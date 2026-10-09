"""Shared implementation for every provider that speaks the OpenAI chat shape.

OpenAI, Azure OpenAI, and the whole openai-compatible family (Groq, OpenRouter,
Together, vLLM, LM Studio, llama.cpp's server, and anything else that
implements /v1/chat/completions) differ only in the URL, the auth header and a
few payload keys. Those differences are the subclass; the request shape,
response parsing, tool round trip and stream assembly are here.

The canonical payload built by `payload_for` is also the payload the tenant's
data boundary inspects, minimises and digests, which is why it is assembled
before `_dispatch` rather than inside the wire callback.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from services.llm import transport
from services.llm.base import (
    BAD_REQUEST, Capabilities, Completion, Conversation, LLMError, Provider,
    SYSTEM_MESSAGE, ToolCall, Usage, estimate_cost,
)


def openai_tools(tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Translate the agent's tool definitions into OpenAI function tools.

    The agent declares tools in Anthropic's shape (`input_schema`); accept
    either, so a contributor can hand this either vocabulary.
    """
    out: List[Dict[str, Any]] = []
    for tool in tools or []:
        if "function" in tool:
            out.append(tool)
            continue
        out.append({"type": "function", "function": {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "parameters": tool.get("input_schema") or tool.get("parameters") or {"type": "object", "properties": {}},
        }})
    return out


class OpenAIShaped(Provider):
    """Base adapter for /v1/chat/completions-compatible endpoints."""

    default_base_url = ""
    default_model = ""
    #: The adapter's own answer. An operator override in Settings wins.
    supports_tools = True
    supports_streaming = True

    def __init__(self, settings) -> None:
        super().__init__(settings)
        if settings.tools_supported is not None:
            self.supports_tools = bool(settings.tools_supported)
        if settings.stream_supported is not None:
            self.supports_streaming = bool(settings.stream_supported)

    # -- subclass hooks -----------------------------------------------------
    def endpoint(self) -> str:
        base = (self.settings.base_url or self.default_base_url).rstrip("/")
        if not base:
            raise LLMError("config", "No base URL is configured for this provider.", provider=self.id,
                           remedy="Set PQC_LLM_BASE_URL.")
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def auth_headers(self) -> Dict[str, str]:
        key = self.settings.api_key
        return {"Authorization": "Bearer " + key} if key else {}

    def wire_payload(self, clean: Dict[str, Any]) -> Dict[str, Any]:
        """Last chance to adjust the policy-approved payload for this endpoint."""
        return clean

    # -- declaration --------------------------------------------------------
    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider=self.id,
            model=self.settings.model or self.default_model,
            streaming=self.supports_streaming,
            tools=self.supports_tools,
            context_window=self.settings.context_window,
            system_prompt=SYSTEM_MESSAGE,
            usage_reported=True,
            cost_known=self.settings.price_input_per_mtok is not None or self.settings.price_output_per_mtok is not None,
            endpoint=self._safe_endpoint(),
        )

    def _safe_endpoint(self) -> str:
        try:
            return self.endpoint()
        except LLMError:
            return ""

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not (self.settings.model or self.default_model):
            missing.append("PQC_LLM_MODEL")
        if not (self.settings.base_url or self.default_base_url):
            missing.append("PQC_LLM_BASE_URL")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}

    # -- conversation -------------------------------------------------------
    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
        message: Dict[str, Any] = {"role": "assistant", "content": completion.text or ""}
        if completion.tool_calls:
            message["tool_calls"] = [
                {"id": call.id, "type": "function",
                 "function": {"name": call.name, "arguments": json.dumps(call.arguments, default=str)}}
                for call in completion.tool_calls
            ]
        conv.messages.append(message)

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        for call_id, text in results:
            conv.messages.append({"role": "tool", "tool_call_id": call_id, "content": text})

    # -- requests -----------------------------------------------------------
    def payload_for(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]],
                    stream: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.settings.model or self.default_model,
            "messages": conv.messages,
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
        }
        if tools and self.supports_tools:
            payload["tools"] = openai_tools(tools)
            payload["tool_choice"] = "auto"
        if stream:
            payload["stream"] = True
            payload["stream_options"] = {"include_usage": True}
        return payload

    def complete(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                 org_id: str = "", purpose: str = "assistant",
                 policy_version: Optional[int] = None) -> Completion:
        # Resolve the destination first: a misconfiguration is not worth a
        # dispatch record, and "set PQC_LLM_BASE_URL" is a better answer than
        # whatever the boundary would say about an unresolvable destination.
        url = self.endpoint()
        payload = self.payload_for(conv, tools)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            return transport.post_json(url, self.wire_payload(clean),
                                       headers={**self.auth_headers(), **self.settings.headers},
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
        """Same turn over the provider's streaming wire protocol."""
        url = self.endpoint()
        payload = self.payload_for(conv, tools, stream=True)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            lines = transport.post_lines(url, {**self.wire_payload(clean), "stream": True},
                                         headers={**self.auth_headers(), **self.settings.headers},
                                         timeout=self.settings.timeout, retries=self.settings.retries,
                                         provider=self.id)
            return self.assemble_stream(lines)

        raw, latency = self._timed(lambda: self._dispatch(payload, invoke, org_id=org_id, purpose=purpose,
                                                          policy_version=policy_version))
        completion = self.parse(raw)
        completion.tools_offered = offered
        completion.latency_ms = latency
        return completion

    # -- responses ----------------------------------------------------------
    def parse(self, raw: Dict[str, Any]) -> Completion:
        choices = raw.get("choices")
        if not isinstance(choices, list) or not choices:
            error = raw.get("error")
            if isinstance(error, dict) and error.get("message"):
                raise LLMError(BAD_REQUEST, "The provider returned an error instead of a completion.",
                               provider=self.id, remedy="Check the model name and the request limits.")
            raise LLMError(BAD_REQUEST, "The provider returned no completion choices.", provider=self.id,
                           remedy="Check that the base URL is an OpenAI-compatible chat-completions endpoint.")
        choice = choices[0] if isinstance(choices[0], dict) else {}
        message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        finish = str(choice.get("finish_reason") or "stop")

        calls: List[ToolCall] = []
        for item in message.get("tool_calls") or []:
            function = (item or {}).get("function") or {}
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except ValueError:
                arguments = {}
            calls.append(ToolCall(id=str(item.get("id") or ""), name=str(function.get("name") or ""),
                                  arguments=arguments if isinstance(arguments, dict) else {}))

        refusal = str(message.get("refusal") or "")
        stop = "tool_use" if calls else "refusal" if refusal else "max_tokens" if finish == "length" else "end_turn"
        usage_raw = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        details = usage_raw.get("prompt_tokens_details") if isinstance(usage_raw.get("prompt_tokens_details"), dict) else {}
        usage = Usage(
            input_tokens=_int(usage_raw.get("prompt_tokens") or usage_raw.get("input_tokens")),
            output_tokens=_int(usage_raw.get("completion_tokens") or usage_raw.get("output_tokens")),
            cached_input_tokens=_int(details.get("cached_tokens")),
        )
        # OpenRouter and some gateways report the billed cost directly.
        reported = usage_raw.get("cost")
        usage = estimate_cost(self.settings, usage, _float(reported))

        return Completion(
            text=_text_of(message),
            tool_calls=calls,
            stop_reason=stop,
            refusal_category="declined" if refusal else "",
            usage=usage,
            provider=self.id,
            model=str(raw.get("model") or self.settings.model or self.default_model),
            raw=raw,
        )

    def assemble_stream(self, lines: List[str]) -> Dict[str, Any]:
        """Fold an SSE delta stream back into one chat-completions response."""
        text_parts: List[str] = []
        calls: Dict[int, Dict[str, Any]] = {}
        finish = "stop"
        usage: Dict[str, Any] = {}
        model = ""
        for event in transport.sse_data(lines):
            if isinstance(event.get("usage"), dict):
                usage = event["usage"]
            model = model or str(event.get("model") or "")
            for choice in event.get("choices") or []:
                if not isinstance(choice, dict):
                    continue
                if choice.get("finish_reason"):
                    finish = str(choice["finish_reason"])
                delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
                if isinstance(delta.get("content"), str):
                    text_parts.append(delta["content"])
                for fragment in delta.get("tool_calls") or []:
                    if not isinstance(fragment, dict):
                        continue
                    index = int(fragment.get("index") or 0)
                    slot = calls.setdefault(index, {"id": "", "type": "function",
                                                    "function": {"name": "", "arguments": ""}})
                    if fragment.get("id"):
                        slot["id"] = str(fragment["id"])
                    function = fragment.get("function") or {}
                    if function.get("name"):
                        slot["function"]["name"] = str(function["name"])
                    if function.get("arguments"):
                        slot["function"]["arguments"] += str(function["arguments"])
        message: Dict[str, Any] = {"role": "assistant", "content": "".join(text_parts)}
        if calls:
            message["tool_calls"] = [calls[key] for key in sorted(calls)]
        body: Dict[str, Any] = {"model": model or self.settings.model,
                                "choices": [{"index": 0, "message": message, "finish_reason": finish}]}
        if usage:
            body["usage"] = usage
        return body

    def stream(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
               org_id: str = "", purpose: str = "assistant",
               policy_version: Optional[int] = None, chunk_chars: int = 40) -> Iterator["Any"]:
        from services.llm.base import Chunk

        completion = (self.complete_streaming if self._wire_stream() else self.complete)(
            conv, tools, org_id=org_id, purpose=purpose, policy_version=policy_version)
        text = completion.text or ""
        for index in range(0, len(text), max(1, chunk_chars)):
            yield Chunk(text=text[index:index + chunk_chars])
        yield Chunk(done=True, completion=completion)

    def _wire_stream(self) -> bool:
        import os
        return self.supports_streaming and (os.getenv("PQC_LLM_WIRE_STREAM") or "").strip() in {"1", "true", "yes"}


def _text_of(message: Dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Some gateways return OpenAI's newer content-part list.
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
