"""Anthropic, api.anthropic.com.

This adapter keeps the behaviour and the model default the agent shipped with:
`claude-opus-5`, adaptive thinking, a cache breakpoint on the static system
prompt, Anthropic-native tool definitions, and no automatic SDK retries. It
speaks the Messages API over the shared transport rather than the SDK, so the
whole provider layer has one mockable HTTP seam; `services/ai_agent.py` still
holds the SDK client for the long-standing Anthropic path, which this adapter
mirrors field for field (see test_llm_providers.py).
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterator, List, Optional, Tuple

from services.llm import transport
from services.llm.base import (
    BAD_REQUEST, Capabilities, Chunk, Completion, Conversation, LLMError, Provider,
    SYSTEM_SEPARATE, ToolCall, Usage, estimate_cost,
)

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
API_VERSION = "2023-06-01"
#: Anthropic's current published context window for the Claude 4/5 families.
CONTEXT_WINDOW = 200_000


class AnthropicProvider(Provider):
    id = "anthropic"
    privacy_provider = "anthropic"

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
            notes="Adaptive thinking and a prompt-cache breakpoint on the static system prefix.",
        )

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self.settings.api_key:
            missing.append("ANTHROPIC_API_KEY")
        if not (self.settings.model or DEFAULT_MODEL):
            missing.append("ANTHROPIC_AGENT_MODEL")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}

    def _endpoint(self) -> str:
        base = (self.settings.base_url or DEFAULT_BASE_URL).rstrip("/")
        return base if base.endswith("/messages") else base + "/messages"

    def _headers(self) -> Dict[str, str]:
        headers = {"anthropic-version": API_VERSION, **self.settings.headers}
        if self.settings.api_key:
            headers["x-api-key"] = self.settings.api_key
        return headers

    # -- conversation -------------------------------------------------------
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
        # Replay the provider's own content array: thinking blocks are signed
        # and must survive the round trip, which rebuilding from text loses.
        blocks = (completion.raw or {}).get("content")
        conv.messages.append({"role": "assistant", "content": blocks if isinstance(blocks, list) else
                              [{"type": "text", "text": completion.text or ""}]})

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        conv.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call_id, "content": text} for call_id, text in results]})

    # -- requests -----------------------------------------------------------
    def payload_for(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]],
                    stream: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.settings.model or DEFAULT_MODEL,
            # Only the static application instructions carry the cache breakpoint.
            "system": [{"type": "text", "text": conv.system, "cache_control": {"type": "ephemeral"}}],
            "messages": conv.messages,
            "max_tokens": self.settings.max_tokens,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": (os.getenv("ANTHROPIC_AGENT_EFFORT") or "high").strip()},
        }
        if tools and self.capabilities().tools:
            payload["tools"] = _anthropic_tools(tools)
            payload["tool_choice"] = {"type": "auto"}
        if stream:
            payload["stream"] = True
        return payload

    def complete(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                 org_id: str = "", purpose: str = "assistant",
                 policy_version: Optional[int] = None) -> Completion:
        payload = self.payload_for(conv, tools)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            return transport.post_json(self._endpoint(), clean, headers=self._headers(),
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
        payload = self.payload_for(conv, tools, stream=True)
        offered = bool(payload.get("tools"))

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            lines = transport.post_lines(self._endpoint(), {**clean, "stream": True}, headers=self._headers(),
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
               policy_version: Optional[int] = None, chunk_chars: int = 30) -> Iterator[Chunk]:
        wire = (os.getenv("MORROW_LLM_WIRE_STREAM") or "").strip() in {"1", "true", "yes"}
        completion = (self.complete_streaming if wire else self.complete)(
            conv, tools, org_id=org_id, purpose=purpose, policy_version=policy_version)
        text = completion.text or ""
        for index in range(0, len(text), max(1, chunk_chars)):
            yield Chunk(text=text[index:index + chunk_chars])
        yield Chunk(done=True, completion=completion)

    # -- responses ----------------------------------------------------------
    def parse(self, raw: Dict[str, Any]) -> Completion:
        if raw.get("type") == "error" or "content" not in raw:
            raise LLMError(BAD_REQUEST, "Anthropic returned an error instead of a message.", provider=self.id,
                           remedy="Check the model name and the request limits.")
        blocks = raw.get("content") or []
        text_parts: List[str] = []
        calls: List[ToolCall] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_use":
                arguments = block.get("input")
                calls.append(ToolCall(id=str(block.get("id") or ""), name=str(block.get("name") or ""),
                                      arguments=arguments if isinstance(arguments, dict) else {}))

        stop_reason = str(raw.get("stop_reason") or "end_turn")
        category = str((raw.get("stop_details") or {}).get("category") or "unspecified") if stop_reason == "refusal" else ""
        stop = {"tool_use": "tool_use", "refusal": "refusal", "max_tokens": "max_tokens"}.get(stop_reason, "end_turn")
        if calls and stop == "end_turn":
            stop = "tool_use"

        usage_raw = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        usage = estimate_cost(self.settings, Usage(
            input_tokens=_int(usage_raw.get("input_tokens")),
            output_tokens=_int(usage_raw.get("output_tokens")),
            cached_input_tokens=_int(usage_raw.get("cache_read_input_tokens")),
        ))
        return Completion(text="".join(text_parts), tool_calls=calls, stop_reason=stop,
                          refusal_category=category, usage=usage, provider=self.id,
                          model=str(raw.get("model") or self.settings.model or DEFAULT_MODEL), raw=raw)

    def assemble_stream(self, lines: List[str]) -> Dict[str, Any]:
        """Fold the Messages streaming events back into one message object."""
        message: Dict[str, Any] = {"type": "message", "content": [], "stop_reason": "end_turn", "usage": {}}
        blocks: Dict[int, Dict[str, Any]] = {}
        partials: Dict[int, str] = {}
        for event in transport.sse_data(lines):
            kind = str(event.get("type") or "")
            if kind == "message_start":
                start = event.get("message") or {}
                message["model"] = start.get("model")
                if isinstance(start.get("usage"), dict):
                    message["usage"].update(start["usage"])
            elif kind == "content_block_start":
                index = int(event.get("index") or 0)
                block = dict(event.get("content_block") or {})
                if block.get("type") == "tool_use":
                    block["input"] = {}
                    partials[index] = ""
                blocks[index] = block
            elif kind == "content_block_delta":
                index = int(event.get("index") or 0)
                delta = event.get("delta") or {}
                block = blocks.setdefault(index, {"type": "text", "text": ""})
                if delta.get("type") == "text_delta":
                    block["text"] = str(block.get("text") or "") + str(delta.get("text") or "")
                elif delta.get("type") == "thinking_delta":
                    block["thinking"] = str(block.get("thinking") or "") + str(delta.get("thinking") or "")
                elif delta.get("type") == "signature_delta":
                    block["signature"] = str(block.get("signature") or "") + str(delta.get("signature") or "")
                elif delta.get("type") == "input_json_delta":
                    partials[index] = partials.get(index, "") + str(delta.get("partial_json") or "")
            elif kind == "content_block_stop":
                index = int(event.get("index") or 0)
                if index in partials:
                    import json
                    try:
                        parsed = json.loads(partials[index] or "{}")
                    except ValueError:
                        parsed = {}
                    blocks[index]["input"] = parsed if isinstance(parsed, dict) else {}
            elif kind == "message_delta":
                delta = event.get("delta") or {}
                if delta.get("stop_reason"):
                    message["stop_reason"] = delta["stop_reason"]
                if delta.get("stop_details"):
                    message["stop_details"] = delta["stop_details"]
                if isinstance(event.get("usage"), dict):
                    message["usage"].update(event["usage"])
        message["content"] = [blocks[key] for key in sorted(blocks)]
        return message


def _anthropic_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Accept either vocabulary and emit Anthropic's `input_schema` form."""
    out: List[Dict[str, Any]] = []
    for tool in tools:
        if "input_schema" in tool:
            out.append(tool)
            continue
        function = tool.get("function") or tool
        out.append({"name": function.get("name", ""), "description": function.get("description", ""),
                    "input_schema": function.get("parameters") or {"type": "object", "properties": {}}})
    return out


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
