"""Ollama, local, no API key.

Ollama's /api/chat is close to the OpenAI shape but not the same: no `v1`
prefix, `options` instead of top-level sampling parameters, `stream` defaults
to true so it has to be switched off explicitly, tool results come back as a
`message.tool_calls` array with real objects rather than JSON strings, and the
streaming wire protocol is newline-delimited JSON rather than SSE.

    PQC_LLM_PROVIDER=ollama
    PQC_LLM_BASE_URL=http://127.0.0.1:11434     # the default
    PQC_LLM_MODEL=llama3.1
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from services.llm import transport
from services.llm.base import (
    BAD_REQUEST, Capabilities, Chunk, Completion, Conversation, LLMError, Provider,
    SYSTEM_MESSAGE, ToolCall, Usage, estimate_cost,
)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.1"


class OllamaProvider(Provider):
    id = "ollama"

    # -- declaration --------------------------------------------------------
    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider=self.id,
            model=self.settings.model or DEFAULT_MODEL,
            streaming=True if self.settings.stream_supported is None else bool(self.settings.stream_supported),
            # Tool calling depends on the pulled model, not on Ollama. Declared
            # off unless the operator says the model supports it.
            tools=bool(self.settings.tools_supported),
            context_window=self.settings.context_window,
            system_prompt=SYSTEM_MESSAGE,
            usage_reported=True,
            cost_known=False,
            endpoint=self._endpoint(),
            notes="Local inference: no API key, and no cost to report. "
                  "Set PQC_LLM_TOOLS=1 when the pulled model supports tool calling.",
        )

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not (self.settings.model or DEFAULT_MODEL):
            missing.append("PQC_LLM_MODEL")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing
                else "set " + ", ".join(missing)}

    def _endpoint(self, path: str = "/api/chat") -> str:
        base = (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")
        # Tolerate an operator who pasted the OpenAI-compatible URL.
        if base.endswith("/v1"):
            base = base[:-3]
        return base + path

    # -- conversation -------------------------------------------------------
    def start(self, system: str, history: List[Dict[str, Any]], message: str,
              *, history_limit: int = 10, chars: int = 2000) -> Conversation:
        conv = Conversation(system=system)
        if system:
            conv.messages.append({"role": "system", "content": system})
        for item in (history or [])[-history_limit:]:
            role = str((item or {}).get("role") or "")
            content = (item or {}).get("content")
            if role in ("user", "assistant") and isinstance(content, str) and content:
                conv.messages.append({"role": role, "content": content[:chars]})
        conv.messages.append({"role": "user", "content": str(message)[:4000]})
        return conv

    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
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
            "model": self.settings.model or DEFAULT_MODEL,
            "messages": conv.messages,
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
            return transport.post_json(self._endpoint(), to_ollama(clean, stream=False),
                                       headers=dict(self.settings.headers),
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
            lines = transport.post_lines(self._endpoint(), to_ollama(clean, stream=True),
                                         headers=dict(self.settings.headers),
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
            raise LLMError(BAD_REQUEST, "Ollama returned an error instead of a completion.", provider=self.id,
                           remedy="Check that the model is pulled: ollama pull <model>.")
        message = raw.get("message")
        if not isinstance(message, dict):
            raise LLMError(BAD_REQUEST, "Ollama returned no message.", provider=self.id,
                           remedy="Check the base URL: /api/chat is expected, not the OpenAI-compatible path.")
        calls: List[ToolCall] = []
        for index, item in enumerate(message.get("tool_calls") or []):
            function = (item or {}).get("function") or {}
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments or "{}")
                except ValueError:
                    arguments = {}
            calls.append(ToolCall(id=str(item.get("id") or f"ollama-{index}"),
                                  name=str(function.get("name") or ""),
                                  arguments=arguments if isinstance(arguments, dict) else {}))
        stop = "tool_use" if calls else "max_tokens" if str(raw.get("done_reason") or "") == "length" else "end_turn"
        usage = estimate_cost(self.settings, Usage(
            input_tokens=_int(raw.get("prompt_eval_count")),
            output_tokens=_int(raw.get("eval_count")),
        ))
        return Completion(text=str(message.get("content") or ""), tool_calls=calls, stop_reason=stop,
                          usage=usage, provider=self.id,
                          model=str(raw.get("model") or self.settings.model or DEFAULT_MODEL), raw=raw)

    def assemble_stream(self, lines: List[str]) -> Dict[str, Any]:
        """Fold Ollama's newline-delimited JSON chunks into one /api/chat body."""
        text_parts: List[str] = []
        calls: List[Dict[str, Any]] = []
        body: Dict[str, Any] = {"message": {"role": "assistant", "content": ""}}
        for event in transport.json_lines(lines):
            message = event.get("message") if isinstance(event.get("message"), dict) else {}
            if isinstance(message.get("content"), str):
                text_parts.append(message["content"])
            for call in message.get("tool_calls") or []:
                if isinstance(call, dict):
                    calls.append(call)
            if event.get("done"):
                for key in ("model", "done_reason", "prompt_eval_count", "eval_count"):
                    if key in event:
                        body[key] = event[key]
        body["message"]["content"] = "".join(text_parts)
        if calls:
            body["message"]["tool_calls"] = calls
        return body


def to_ollama(clean: Dict[str, Any], stream: bool) -> Dict[str, Any]:
    """Translate a policy-approved OpenAI-shaped payload into /api/chat's."""
    body: Dict[str, Any] = {
        "model": clean.get("model", DEFAULT_MODEL),
        "messages": [_message(item) for item in clean.get("messages") or []],
        # Ollama streams unless told otherwise, which would make the
        # non-streaming parser see only the first token.
        "stream": bool(stream),
        "options": {"temperature": clean.get("temperature", 0.1),
                    "num_predict": clean.get("max_tokens", 3000)},
    }
    if clean.get("tools"):
        body["tools"] = clean["tools"]
    return body


def _message(item: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"role": str(item.get("role") or "user"),
                           "content": item.get("content") if isinstance(item.get("content"), str) else ""}
    if item.get("tool_calls"):
        out["tool_calls"] = item["tool_calls"]
    return out


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
