"""Google Gemini, generativelanguage.googleapis.com.

Gemini's wire format is its own: `contents` with `parts` instead of
`messages`, `systemInstruction` separately, `functionDeclarations` for tools,
and the model in the URL path. The canonical payload this adapter hands to the
tenant's data boundary is still the OpenAI shape -- that is what gets
minimised, digested and receipted -- and the translation to Gemini's format
happens inside the dispatch callback, so the gate inspects the same text that
leaves the process.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from services.llm import transport
from services.llm.base import (
    BAD_REQUEST, CONFIG, Capabilities, Chunk, Completion, Conversation, LLMError, Provider,
    SYSTEM_SEPARATE, ToolCall, Usage, estimate_cost,
)

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-2.0-flash"
CONTEXT_WINDOW = 1_000_000

#: Gemini rejects a JSON Schema with these keys, which the agent's tool
#: definitions carry. Strip them rather than fail the whole request.
_UNSUPPORTED_SCHEMA_KEYS = ("additionalProperties", "$schema", "default", "maxItems", "minItems", "examples")


class GeminiProvider(Provider):
    id = "gemini"

    # -- declaration --------------------------------------------------------
    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider=self.id,
            model=self.settings.model or DEFAULT_MODEL,
            streaming=True if self.settings.stream_supported is None else bool(self.settings.stream_supported),
            tools=True if self.settings.tools_supported is None else bool(self.settings.tools_supported),
            context_window=self.settings.context_window or CONTEXT_WINDOW,
            system_prompt=SYSTEM_SEPARATE,
            usage_reported=True,
            cost_known=self.settings.price_input_per_mtok is not None or self.settings.price_output_per_mtok is not None,
            endpoint=self._endpoint(),
            notes="Tool schemas are narrowed to the subset Gemini accepts.",
        )

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self.settings.api_key:
            missing.append("PQC_LLM_API_KEY")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}

    def _model(self) -> str:
        return self.settings.model or DEFAULT_MODEL

    def _endpoint(self, stream: bool = False) -> str:
        base = (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")
        verb = "streamGenerateContent?alt=sse" if stream else "generateContent"
        return f"{base}/models/{self._model()}:{verb}"

    def _headers(self) -> Dict[str, str]:
        if not self.settings.api_key:
            raise LLMError(CONFIG, "Gemini needs an API key.", provider=self.id,
                           remedy="Set PQC_LLM_API_KEY to a Google AI Studio key.")
        # The key goes in a header, never in the URL: a URL reaches logs and
        # proxies, and the pinned destination in the Data Control receipt must
        # not contain a credential.
        return {"x-goog-api-key": self.settings.api_key, **self.settings.headers}

    # -- conversation (canonical OpenAI shape; translated at dispatch) -------
    def start(self, system: str, history: List[Dict[str, Any]], message: str,
              *, history_limit: int = 10, chars: int = 2000) -> Conversation:
        conv = Conversation(system=system)
        for item in (history or [])[-history_limit:]:
            role = str((item or {}).get("role") or "")
            content = (item or {}).get("content")
            if role in ("user", "assistant") and isinstance(content, str) and content:
                conv.messages.append({"role": role, "content": content[:chars]})
        conv.messages.append({"role": "user", "content": str(message)[:4000]})
        return conv

    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
        import json
        message: Dict[str, Any] = {"role": "assistant", "content": completion.text or ""}
        if completion.tool_calls:
            message["tool_calls"] = [
                {"id": call.id, "type": "function",
                 "function": {"name": call.name, "arguments": json.dumps(call.arguments, default=str)}}
                for call in completion.tool_calls]
        conv.messages.append(message)

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        for call_id, text in results:
            conv.messages.append({"role": "tool", "tool_call_id": call_id, "content": text})

    # -- requests -----------------------------------------------------------
    def payload_for(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self._model(),
            "messages": ([{"role": "system", "content": conv.system}] if conv.system else []) + conv.messages,
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
        }
        if tools and self.capabilities().tools:
            from services.llm.openai_shape import openai_tools
            payload["tools"] = openai_tools(tools)
            payload["tool_choice"] = "auto"
        return payload

    def complete(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                 org_id: str = "", purpose: str = "assistant",
                 policy_version: Optional[int] = None) -> Completion:
        payload = self.payload_for(conv, tools)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            return transport.post_json(self._endpoint(), to_gemini(clean), headers=self._headers(),
                                       timeout=self.settings.timeout, retries=self.settings.retries,
                                       provider=self.id)

        raw, latency = self._timed(lambda: self._dispatch(payload, invoke, org_id=org_id, purpose=purpose,
                                                          policy_version=policy_version))
        completion = self.parse(raw)
        completion.tools_offered = offered
        completion.latency_ms = latency
        return completion

    def complete_streaming(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                           org_id: str = "", purpose: str = "assistant",
                           policy_version: Optional[int] = None) -> Completion:
        payload = self.payload_for(conv, tools)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            lines = transport.post_lines(self._endpoint(stream=True), to_gemini(clean), headers=self._headers(),
                                         timeout=self.settings.timeout, retries=self.settings.retries,
                                         provider=self.id)
            return self.assemble_stream(lines)

        raw, latency = self._timed(lambda: self._dispatch(payload, invoke, org_id=org_id, purpose=purpose,
                                                          policy_version=policy_version))
        completion = self.parse(raw)
        completion.tools_offered = offered
        completion.latency_ms = latency
        return completion

    def stream(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
               org_id: str = "", purpose: str = "assistant",
               policy_version: Optional[int] = None, chunk_chars: int = 40) -> Iterator[Chunk]:
        import os
        wire = (os.getenv("PQC_LLM_WIRE_STREAM") or "").strip() in {"1", "true", "yes"}
        completion = (self.complete_streaming if wire else self.complete)(
            conv, tools, org_id=org_id, purpose=purpose, policy_version=policy_version)
        text = completion.text or ""
        for index in range(0, len(text), max(1, chunk_chars)):
            yield Chunk(text=text[index:index + chunk_chars])
        yield Chunk(done=True, completion=completion)

    # -- responses ----------------------------------------------------------
    def parse(self, raw: Dict[str, Any]) -> Completion:
        if raw.get("error"):
            raise LLMError(BAD_REQUEST, "Gemini returned an error instead of a completion.", provider=self.id,
                           remedy="Check the model name and that the API key has access to it.")
        candidates = raw.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            blocked = ((raw.get("promptFeedback") or {}).get("blockReason") or "")
            if blocked:
                return Completion(stop_reason="refusal", refusal_category=str(blocked).lower(),
                                  provider=self.id, model=self._model(), raw=raw)
            raise LLMError(BAD_REQUEST, "Gemini returned no candidates.", provider=self.id,
                           remedy="Check the model name and the request limits.")
        candidate = candidates[0] if isinstance(candidates[0], dict) else {}
        parts = ((candidate.get("content") or {}).get("parts") or [])
        text_parts: List[str] = []
        calls: List[ToolCall] = []
        for index, part in enumerate(parts):
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("text"), str):
                text_parts.append(part["text"])
            call = part.get("functionCall")
            if isinstance(call, dict):
                arguments = call.get("args")
                calls.append(ToolCall(id=f"gemini-{index}", name=str(call.get("name") or ""),
                                      arguments=arguments if isinstance(arguments, dict) else {}))
        finish = str(candidate.get("finishReason") or "STOP").upper()
        stop = ("tool_use" if calls else "max_tokens" if finish == "MAX_TOKENS"
                else "refusal" if finish in {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"} else "end_turn")
        meta = raw.get("usageMetadata") if isinstance(raw.get("usageMetadata"), dict) else {}
        usage = estimate_cost(self.settings, Usage(
            input_tokens=_int(meta.get("promptTokenCount")),
            output_tokens=_int(meta.get("candidatesTokenCount")),
            cached_input_tokens=_int(meta.get("cachedContentTokenCount")),
        ))
        return Completion(text="".join(text_parts), tool_calls=calls, stop_reason=stop,
                          refusal_category=finish.lower() if stop == "refusal" else "",
                          usage=usage, provider=self.id,
                          model=str(raw.get("modelVersion") or self._model()), raw=raw)

    def assemble_stream(self, lines: List[str]) -> Dict[str, Any]:
        """Fold Gemini's SSE candidate chunks into one generateContent body."""
        parts: List[Dict[str, Any]] = []
        finish = "STOP"
        meta: Dict[str, Any] = {}
        version = ""
        for event in transport.sse_data(lines):
            version = version or str(event.get("modelVersion") or "")
            if isinstance(event.get("usageMetadata"), dict):
                meta = event["usageMetadata"]
            for candidate in event.get("candidates") or []:
                if not isinstance(candidate, dict):
                    continue
                if candidate.get("finishReason"):
                    finish = str(candidate["finishReason"])
                for part in ((candidate.get("content") or {}).get("parts") or []):
                    if not isinstance(part, dict):
                        continue
                    if isinstance(part.get("text"), str) and parts and isinstance(parts[-1].get("text"), str):
                        parts[-1]["text"] += part["text"]
                    else:
                        parts.append(dict(part))
        body: Dict[str, Any] = {"candidates": [{"content": {"role": "model", "parts": parts},
                                                "finishReason": finish}]}
        if meta:
            body["usageMetadata"] = meta
        if version:
            body["modelVersion"] = version
        return body


def _clean_schema(value: Any) -> Any:
    """Narrow a JSON Schema to the subset Gemini's function declarations accept."""
    if isinstance(value, list):
        return [_clean_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {key: _clean_schema(item) for key, item in value.items() if key not in _UNSUPPORTED_SCHEMA_KEYS}


def to_gemini(clean: Dict[str, Any]) -> Dict[str, Any]:
    """Translate a policy-approved OpenAI-shaped payload into Gemini's format."""
    contents: List[Dict[str, Any]] = []
    system_parts: List[str] = []
    pending: Dict[str, str] = {}
    for message in clean.get("messages") or []:
        role = str(message.get("role") or "")
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        if role == "system":
            if text:
                system_parts.append(text)
            continue
        if role == "tool":
            name = pending.get(str(message.get("tool_call_id") or ""), "tool")
            contents.append({"role": "user", "parts": [
                {"functionResponse": {"name": name, "response": {"result": text}}}]})
            continue
        if role == "assistant":
            parts: List[Dict[str, Any]] = []
            if text:
                parts.append({"text": text})
            for call in message.get("tool_calls") or []:
                function = (call or {}).get("function") or {}
                name = str(function.get("name") or "")
                pending[str(call.get("id") or "")] = name
                import json
                try:
                    arguments = json.loads(function.get("arguments") or "{}")
                except ValueError:
                    arguments = {}
                parts.append({"functionCall": {"name": name,
                                               "args": arguments if isinstance(arguments, dict) else {}}})
            contents.append({"role": "model", "parts": parts or [{"text": ""}]})
            continue
        contents.append({"role": "user", "parts": [{"text": text}]})

    body: Dict[str, Any] = {
        "contents": contents,
        "generationConfig": {"temperature": clean.get("temperature", 0.1),
                             "maxOutputTokens": clean.get("max_tokens", 3000)},
    }
    if system_parts:
        body["systemInstruction"] = {"parts": [{"text": "\n".join(system_parts)}]}
    declarations = []
    for tool in clean.get("tools") or []:
        function = (tool or {}).get("function") or tool
        declarations.append({"name": function.get("name", ""),
                             "description": function.get("description", ""),
                             "parameters": _clean_schema(function.get("parameters")
                                                         or {"type": "object", "properties": {}})})
    if declarations:
        body["tools"] = [{"functionDeclarations": declarations}]
    return body


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
