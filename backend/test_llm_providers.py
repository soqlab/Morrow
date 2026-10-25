"""Contract tests for the model provider layer (services/llm).

No network, ever. There is exactly one function in the package that opens a
socket -- `services.llm.transport._open` -- and every test here replaces it, so
a test that tried to reach a provider would fail with an AssertionError rather
than silently making a request.

The fixtures are hand-written from each provider's published API shape. They
are deliberately not recorded from live calls: a recorded response would carry
real data into the repository, and the point of a fixture here is the *shape*.

What these guard, concretely:

  * An adapter that sends the wrong URL, header or payload key. Azure's
    deployment-in-the-path and api-version, Gemini's key-in-a-header (never in
    the URL), and Ollama's explicit `stream: false` are each a bug that only
    shows up as a 404 or a one-token answer in production.
  * An adapter that claims a capability it does not implement. `tools=True`
    with the tool definitions dropped makes the agent wait for tool calls that
    never arrive, forever, silently.
  * A credential reaching a log, an error message or a describe() payload.
  * The custom-module loader raising a traceback out of an operator's own file
    instead of a message naming what is wrong.
  * A per-organization override leaking across tenants.
  * MORROW_LLM_DISABLED being overridable by a customer.
  * A provider outage becoming a dead end rather than a built-in answer.
"""

from __future__ import annotations

import io
import json
import sys
import types

import pytest

from services import llm
from services.llm import config, custom, registry, transport
from services.llm.base import (
    AUTH, BAD_REQUEST, CONFIG, CONNECTION, Capabilities, LLMError, Provider,
    RATE_LIMIT, SERVER, Settings, TIMEOUT, Usage,
)

# --------------------------------------------------------------------------- #
# The HTTP boundary
# --------------------------------------------------------------------------- #


class _FakeResponse:
    """Stands in for what urlopen returns: read(), close(), and iteration."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.closed = False

    def read(self, limit: int = -1) -> bytes:
        data, self._body = self._body, b""
        return data if limit < 0 else data[:limit]

    def __iter__(self):
        return iter(io.BytesIO(self._body).readlines())

    def close(self) -> None:
        self.closed = True


class Wire:
    """Records every request the package would have made, and replays answers."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.queue: list = []

    def enqueue(self, *responses) -> "Wire":
        self.queue.extend(responses)
        return self

    def __call__(self, url, body, headers, timeout, method="POST"):
        self.sent.append({"url": url, "headers": dict(headers), "timeout": timeout,
                          "method": method, "body": json.loads(body.decode("utf-8")),
                          "raw": body.decode("utf-8")})
        nxt = self.queue.pop(0) if self.queue else {}
        if isinstance(nxt, Exception):
            raise nxt
        if isinstance(nxt, bytes):
            return _FakeResponse(nxt)
        return _FakeResponse(json.dumps(nxt).encode("utf-8"))

    @property
    def last(self) -> dict:
        assert self.sent, "no request was made"
        return self.sent[-1]


@pytest.fixture()
def wire(monkeypatch):
    """Replace the one socket in the package, and refuse to sleep for a backoff."""
    sent = Wire()
    monkeypatch.setattr(transport, "_open", sent)
    monkeypatch.setattr(transport, "_sleep", lambda _seconds: None)
    return sent


@pytest.fixture()
def no_gate(monkeypatch):
    """Call the wire directly, without the tenant's Data Control boundary.

    The boundary has its own suite (test_ai_data_control.py) and is exercised
    end to end at the bottom of this file. Here it would only obscure what each
    adapter puts on the wire.
    """
    monkeypatch.setattr(Provider, "_dispatch",
                        lambda self, payload, invoke, **kwargs: invoke(payload))


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("MORROW_LLM_PROVIDER", "MORROW_LLM_MODEL", "MORROW_LLM_BASE_URL", "MORROW_LLM_API_KEY",
                 "MORROW_LLM_HEADERS", "MORROW_LLM_API_VERSION", "MORROW_LLM_AZURE_DEPLOYMENT",
                 "MORROW_LLM_CUSTOM_MODULE", "MORROW_LLM_DISABLED", "MORROW_LLM_TOOLS",
                 "MORROW_LLM_STREAM", "MORROW_LLM_WIRE_STREAM", "MORROW_LLM_TEMPERATURE",
                 "MORROW_LLM_MAX_TOKENS", "MORROW_LLM_TIMEOUT", "MORROW_LLM_RETRIES",
                 "MORROW_LLM_PRICE_INPUT_PER_MTOK", "MORROW_LLM_PRICE_OUTPUT_PER_MTOK",
                 "MORROW_LLM_CONTEXT_WINDOW", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                 "OPENAI_AGENT_MODEL", "OPENAI_MODEL", "ANTHROPIC_AGENT_MODEL",
                 "MORROW_AI_LOCAL_URL", "MORROW_AI_LOCAL_MODEL", "MORROW_AI_LOCAL_API_KEY"):
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------- #
# Fixtures: one request/response pair per adapter
# --------------------------------------------------------------------------- #

SYSTEM = "You are post-quantum Scout."
QUESTION = "What is my posture?"
TOOLS = [{"name": "get_org_posture", "description": "Bounded posture sample.",
          "input_schema": {"type": "object", "properties": {}}}]

_OPENAI_ANSWER = {
    "model": "gpt-4o-mini",
    "choices": [{"index": 0, "finish_reason": "stop",
                 "message": {"role": "assistant", "content": "Two critical findings."}}],
    "usage": {"prompt_tokens": 120, "completion_tokens": 18,
              "prompt_tokens_details": {"cached_tokens": 64}},
}
_OPENAI_TOOL_TURN = {
    "model": "gpt-4o-mini",
    "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": None,
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "get_org_posture", "arguments": "{}"}}]}}],
    "usage": {"prompt_tokens": 100, "completion_tokens": 12},
}
_ANTHROPIC_ANSWER = {
    "type": "message", "model": "claude-opus-5", "stop_reason": "end_turn",
    "content": [{"type": "text", "text": "Two critical findings."}],
    "usage": {"input_tokens": 200, "output_tokens": 21, "cache_read_input_tokens": 180},
}
_ANTHROPIC_TOOL_TURN = {
    "type": "message", "model": "claude-opus-5", "stop_reason": "tool_use",
    "content": [{"type": "thinking", "thinking": "", "signature": "sig-abc"},
                {"type": "tool_use", "id": "tu_1", "name": "get_org_posture", "input": {}}],
    "usage": {"input_tokens": 190, "output_tokens": 30},
}
_GEMINI_ANSWER = {
    "modelVersion": "gemini-2.0-flash",
    "candidates": [{"finishReason": "STOP", "content": {"role": "model", "parts": [
        {"text": "Two critical findings."}]}}],
    "usageMetadata": {"promptTokenCount": 150, "candidatesTokenCount": 19,
                      "cachedContentTokenCount": 40},
}
_GEMINI_TOOL_TURN = {
    "candidates": [{"finishReason": "STOP", "content": {"role": "model", "parts": [
        {"functionCall": {"name": "get_org_posture", "args": {}}}]}}],
    "usageMetadata": {"promptTokenCount": 140, "candidatesTokenCount": 8},
}
_OLLAMA_ANSWER = {
    "model": "llama3.1", "done": True, "done_reason": "stop",
    "message": {"role": "assistant", "content": "Two critical findings."},
    "prompt_eval_count": 90, "eval_count": 15,
}
_OLLAMA_TOOL_TURN = {
    "model": "llama3.1", "done": True, "done_reason": "stop",
    "message": {"role": "assistant", "content": "",
                "tool_calls": [{"function": {"name": "get_org_posture", "arguments": {}}}]},
    "prompt_eval_count": 88, "eval_count": 6,
}

#: name -> (settings kwargs, plain answer, tool-asking turn, expected url fragment)
CASES = {
    "anthropic": (dict(api_key="sk-ant-test", model="claude-opus-5"),
                  _ANTHROPIC_ANSWER, _ANTHROPIC_TOOL_TURN, "api.anthropic.com/v1/messages"),
    "openai": (dict(api_key="sk-openai-test", model="gpt-4o-mini"),
               _OPENAI_ANSWER, _OPENAI_TOOL_TURN, "api.openai.com/v1/chat/completions"),
    "azure-openai": (dict(api_key="azure-test-key", base_url="https://r.openai.azure.com",
                          deployment="gpt4o-prod", api_version="2024-10-21"),
                     _OPENAI_ANSWER, _OPENAI_TOOL_TURN,
                     "/openai/deployments/gpt4o-prod/chat/completions?api-version=2024-10-21"),
    "gemini": (dict(api_key="gemini-test-key", model="gemini-2.0-flash"),
               _GEMINI_ANSWER, _GEMINI_TOOL_TURN,
               "/models/gemini-2.0-flash:generateContent"),
    "openai-compatible": (dict(api_key="gsk-test", base_url="https://api.groq.com/openai/v1",
                               model="llama-3.3-70b", tools_supported=True),
                          _OPENAI_ANSWER, _OPENAI_TOOL_TURN,
                          "api.groq.com/openai/v1/chat/completions"),
    "ollama": (dict(base_url="http://127.0.0.1:11434", model="llama3.1", tools_supported=True),
               _OLLAMA_ANSWER, _OLLAMA_TOOL_TURN, "127.0.0.1:11434/api/chat"),
}

NETWORK_PROVIDERS = sorted(CASES)


def make(name: str, **extra) -> Provider:
    kwargs, _, _, _ = CASES[name]
    return registry.build(Settings(provider=name, **{**kwargs, **extra}))


# --------------------------------------------------------------------------- #
# The same request/response suite for every adapter
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_request_goes_to_the_right_place_with_the_right_credential(name, wire, no_gate):
    _, answer, _, fragment = CASES[name]
    provider = make(name)
    wire.enqueue(answer)
    conv = provider.start(SYSTEM, [], QUESTION)
    provider.complete(conv, None)

    assert fragment in wire.last["url"], wire.last["url"]
    # Whatever the auth scheme, the credential must be in a header and nowhere else.
    kwargs = CASES[name][0]
    key = kwargs.get("api_key") or ""
    if key:
        assert key in json.dumps(wire.last["headers"]), "the credential never reached a header"
        assert key not in wire.last["url"], "a key in the URL reaches logs, proxies and receipts"
        assert key not in json.dumps(wire.last["body"]), "a key must not be in the body"
    else:
        assert "Authorization" not in wire.last["headers"], "Ollama needs no credential"
    assert wire.last["method"] == "POST"


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_the_question_and_the_system_prompt_both_reach_the_provider(name, wire, no_gate):
    _, answer, _, _ = CASES[name]
    provider = make(name)
    wire.enqueue(answer)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    raw = wire.last["raw"]
    assert QUESTION in raw
    assert SYSTEM in raw, "dropping the system prompt silently changes the analyst's behaviour"


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_response_parsing_yields_text_and_token_counts(name, wire, no_gate):
    _, answer, _, _ = CASES[name]
    provider = make(name)
    wire.enqueue(answer)
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None)

    assert completion.text == "Two critical findings."
    assert completion.stop_reason == "end_turn"
    assert completion.tool_calls == []
    assert completion.provider == name
    assert completion.usage.input_tokens and completion.usage.output_tokens


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_cost_is_unknown_until_a_price_is_configured(name, wire, no_gate):
    _, answer, _, _ = CASES[name]
    provider = make(name)
    wire.enqueue(answer)
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    # No built-in price table: a guessed number on an operator's screen is worse
    # than "unknown", so this must stay unknown.
    assert completion.usage.cost_usd is None
    assert completion.usage.basis == "unknown"

    priced = make(name, price_input_per_mtok=3.0, price_output_per_mtok=15.0)
    wire.enqueue(answer)
    completion = priced.complete(priced.start(SYSTEM, [], QUESTION), None)
    assert completion.usage.cost_usd > 0
    assert completion.usage.basis == "price_table"


def test_a_gateway_reported_cost_wins_over_the_price_table(wire, no_gate):
    provider = make("openai-compatible", price_input_per_mtok=3.0, price_output_per_mtok=15.0)
    wire.enqueue({**_OPENAI_ANSWER,
                  "usage": {**_OPENAI_ANSWER["usage"], "cost": 0.000412}})
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert completion.usage.cost_usd == 0.000412
    assert completion.usage.basis == "provider_reported"


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_a_tool_round_trip_replays_the_turn_and_the_result(name, wire, no_gate):
    _, answer, tool_turn, _ = CASES[name]
    provider = make(name)
    assert provider.capabilities().tools, f"{name} should offer tools in this configuration"

    wire.enqueue(tool_turn, answer)
    conv = provider.start(SYSTEM, [], QUESTION)
    first = provider.complete(conv, TOOLS)

    assert first.stop_reason == "tool_use"
    assert [call.name for call in first.tool_calls] == ["get_org_posture"]
    assert "get_org_posture" in wire.sent[0]["raw"], "the tool definition must reach the provider"

    provider.add_assistant(conv, first)
    provider.add_tool_results(conv, [(first.tool_calls[0].id, '{"critical":2}')])
    second = provider.complete(conv, TOOLS)

    assert second.text == "Two critical findings."
    # The tool result must be in the second request, or the model answers blind.
    assert '{\\"critical\\":2}' in wire.sent[1]["raw"] or '"critical":2' in wire.sent[1]["raw"]


def test_anthropic_replays_its_signed_thinking_block_unchanged(wire, no_gate):
    """The API replays thinking blocks from the assistant turn; rebuilding that
    turn from extracted text alone drops the signature and the next request 400s."""
    provider = make("anthropic")
    wire.enqueue(_ANTHROPIC_TOOL_TURN, _ANTHROPIC_ANSWER)
    conv = provider.start(SYSTEM, [], QUESTION)
    first = provider.complete(conv, TOOLS)
    provider.add_assistant(conv, first)
    provider.add_tool_results(conv, [("tu_1", "{}")])
    provider.complete(conv, TOOLS)

    replayed = wire.sent[1]["body"]["messages"]
    assistant = next(m for m in replayed if m["role"] == "assistant")
    assert assistant["content"] == _ANTHROPIC_TOOL_TURN["content"]


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_tools_are_not_sent_when_the_provider_cannot_use_them(name, wire, no_gate):
    _, answer, _, _ = CASES[name]
    provider = make(name, tools_supported=False)
    assert provider.capabilities().tools is False
    wire.enqueue(answer)
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), TOOLS)
    assert "get_org_posture" not in wire.last["raw"]
    assert completion.tools_offered is False


# --------------------------------------------------------------------------- #
# Provider-specific request shapes
# --------------------------------------------------------------------------- #

def test_anthropic_keeps_adaptive_thinking_and_the_cache_breakpoint(wire, no_gate):
    provider = make("anthropic")
    wire.enqueue(_ANTHROPIC_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), TOOLS)
    body = wire.last["body"]
    assert body["thinking"] == {"type": "adaptive"}
    assert "budget_tokens" not in json.dumps(body["thinking"])
    assert isinstance(body["system"], list)
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["tools"][0]["input_schema"] == {"type": "object", "properties": {}}
    assert wire.last["headers"]["anthropic-version"] == "2023-06-01"


def test_openai_never_lets_the_provider_retain_the_prompt(wire, no_gate):
    provider = make("openai")
    wire.enqueue(_OPENAI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["body"]["store"] is False


def test_azure_puts_the_deployment_in_the_path_and_the_version_in_the_query(wire, no_gate):
    provider = make("azure-openai")
    wire.enqueue(_OPENAI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["url"] == (
        "https://r.openai.azure.com/openai/deployments/gpt4o-prod/chat/completions"
        "?api-version=2024-10-21")
    assert wire.last["headers"]["api-key"] == "azure-test-key"
    assert "Authorization" not in wire.last["headers"], "Azure uses api-key, not a bearer token"
    # The deployment carries the model on Azure; some api-versions reject an extra one.
    assert "model" not in wire.last["body"]


def test_azure_accepts_a_full_deployment_url_and_only_adds_the_version(wire, no_gate):
    provider = registry.build(Settings(
        provider="azure-openai", api_key="k", api_version="2024-10-21",
        base_url="https://r.openai.azure.com/openai/deployments/d/chat/completions",
        deployment="d"))
    wire.enqueue(_OPENAI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["url"].endswith("/chat/completions?api-version=2024-10-21")
    assert wire.last["url"].count("/chat/completions") == 1


def test_azure_without_a_deployment_fails_with_a_config_error():
    provider = registry.build(Settings(provider="azure-openai", api_key="k",
                                       base_url="https://r.openai.azure.com"))
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == CONFIG
    assert "MORROW_LLM_AZURE_DEPLOYMENT" in caught.value.remedy


def test_gemini_sends_its_own_wire_format_with_the_key_in_a_header(wire, no_gate):
    provider = make("gemini")
    wire.enqueue(_GEMINI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), TOOLS)
    body = wire.last["body"]
    assert body["contents"][0]["parts"][0]["text"] == QUESTION
    assert body["systemInstruction"]["parts"][0]["text"] == SYSTEM
    assert body["generationConfig"]["maxOutputTokens"] >= 256
    assert "messages" not in body, "Gemini takes contents, not messages"
    assert wire.last["headers"]["x-goog-api-key"] == "gemini-test-key"
    assert "key=" not in wire.last["url"], "a key in the URL reaches logs and the signed receipt"
    declarations = body["tools"][0]["functionDeclarations"]
    assert declarations[0]["name"] == "get_org_posture"


def test_gemini_strips_the_schema_keys_it_rejects(wire, no_gate):
    provider = make("gemini")
    wire.enqueue(_GEMINI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), [{
        "name": "search_findings", "description": "",
        "input_schema": {"type": "object", "additionalProperties": False,
                         "properties": {"hosts": {"type": "array", "maxItems": 10,
                                                  "items": {"type": "string"}}},
                         "$schema": "http://json-schema.org/draft-07/schema#"}}])
    schema = wire.last["body"]["tools"][0]["functionDeclarations"][0]["parameters"]
    # Gemini rejects the whole request over any one of these, so a tool with a
    # perfectly ordinary JSON Schema would take the assistant down.
    assert "additionalProperties" not in json.dumps(schema)
    assert "$schema" not in json.dumps(schema)
    assert "maxItems" not in json.dumps(schema)
    assert schema["properties"]["hosts"]["items"] == {"type": "string"}


def test_gemini_reports_a_safety_block_as_a_refusal(wire, no_gate):
    provider = make("gemini")
    wire.enqueue({"promptFeedback": {"blockReason": "SAFETY"}})
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert completion.stop_reason == "refusal"
    assert completion.refusal_category == "safety"


def test_ollama_uses_its_own_api_and_switches_streaming_off(wire, no_gate):
    provider = make("ollama")
    wire.enqueue(_OLLAMA_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["url"] == "http://127.0.0.1:11434/api/chat"
    body = wire.last["body"]
    # Ollama streams unless told otherwise, and the non-streaming parser would
    # then see only the first token.
    assert body["stream"] is False
    assert body["options"]["num_predict"] >= 256
    assert "max_tokens" not in body
    assert body["messages"][0]["role"] == "system"


def test_ollama_tolerates_the_openai_compatible_url_being_pasted_in(wire, no_gate):
    provider = make("ollama", base_url="http://127.0.0.1:11434/v1")
    wire.enqueue(_OLLAMA_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["url"] == "http://127.0.0.1:11434/api/chat"


def test_ollama_tool_arguments_arrive_as_objects_not_json_strings(wire, no_gate):
    provider = make("ollama")
    wire.enqueue(_OLLAMA_TOOL_TURN)
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), TOOLS)
    assert completion.tool_calls[0].arguments == {}
    assert completion.tool_calls[0].id, "a tool call needs an id for the result to match"


def test_a_gateway_gets_its_extra_headers(wire, no_gate):
    provider = make("openai-compatible", headers={"HTTP-Referer": "https://app.example",
                                                  "X-Title": "Morrow"})
    wire.enqueue(_OPENAI_ANSWER)
    provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert wire.last["headers"]["HTTP-Referer"] == "https://app.example"
    assert wire.last["headers"]["X-Title"] == "Morrow"


# --------------------------------------------------------------------------- #
# Streaming assembly
# --------------------------------------------------------------------------- #

def _sse(*events) -> bytes:
    return ("".join(f"data: {json.dumps(event)}\n\n" for event in events) + "data: [DONE]\n\n").encode()


def test_openai_stream_assembles_text_tool_calls_and_usage(wire, no_gate, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_WIRE_STREAM", "1")
    provider = make("openai-compatible")
    wire.enqueue(_sse(
        {"model": "llama-3.3-70b", "choices": [{"index": 0, "delta": {"content": "Two "}}]},
        {"choices": [{"index": 0, "delta": {"content": "critical "}}]},
        {"choices": [{"index": 0, "delta": {"content": "findings."}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "function": {"name": "get_org_posture", "arguments": "{"}}]}}]},
        {"choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "}"}}]}, "finish_reason": "tool_calls"}]},
        {"usage": {"prompt_tokens": 10, "completion_tokens": 4}},
    ))
    chunks = list(provider.stream(provider.start(SYSTEM, [], QUESTION), TOOLS))
    completed = chunks[-1].completion
    assert "".join(chunk.text for chunk in chunks) == "Two critical findings."
    assert completed.tool_calls[0].name == "get_org_posture"
    assert completed.tool_calls[0].id == "call_1"
    assert completed.usage.input_tokens == 10
    assert wire.last["body"]["stream"] is True


def test_anthropic_stream_assembles_text_thinking_and_tool_input(wire, no_gate, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_WIRE_STREAM", "1")
    provider = make("anthropic")
    wire.enqueue(_sse(
        {"type": "message_start", "message": {"model": "claude-opus-5",
                                              "usage": {"input_tokens": 200}}},
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "thinking", "thinking": ""}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "thinking_delta", "thinking": "weighing"}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "signature_delta", "signature": "sig-abc"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 1,
         "delta": {"type": "text_delta", "text": "Two critical findings."}},
        {"type": "content_block_stop", "index": 1},
        {"type": "content_block_start", "index": 2,
         "content_block": {"type": "tool_use", "id": "tu_9", "name": "get_org_posture"}},
        {"type": "content_block_delta", "index": 2,
         "delta": {"type": "input_json_delta", "partial_json": "{\"a\":"}},
        {"type": "content_block_delta", "index": 2,
         "delta": {"type": "input_json_delta", "partial_json": "1}"}},
        {"type": "content_block_stop", "index": 2},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"},
         "usage": {"output_tokens": 44}},
    ))
    chunks = list(provider.stream(provider.start(SYSTEM, [], QUESTION), TOOLS))
    completed = chunks[-1].completion
    assert completed.text == "Two critical findings."
    assert completed.stop_reason == "tool_use"
    assert completed.tool_calls[0].arguments == {"a": 1}
    assert completed.usage.input_tokens == 200 and completed.usage.output_tokens == 44
    # The signed thinking block must survive assembly, or the replay 400s.
    thinking = next(b for b in completed.raw["content"] if b["type"] == "thinking")
    assert thinking["signature"] == "sig-abc"


def test_gemini_stream_assembles_candidate_parts(wire, no_gate, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_WIRE_STREAM", "1")
    provider = make("gemini")
    wire.enqueue(_sse(
        {"modelVersion": "gemini-2.0-flash",
         "candidates": [{"content": {"parts": [{"text": "Two "}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "critical findings."}]}}]},
        {"candidates": [{"finishReason": "STOP", "content": {"parts": []}}],
         "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 3}},
    ))
    chunks = list(provider.stream(provider.start(SYSTEM, [], QUESTION), None))
    assert chunks[-1].completion.text == "Two critical findings."
    assert chunks[-1].completion.usage.input_tokens == 7
    assert "streamGenerateContent?alt=sse" in wire.last["url"]


def test_ollama_stream_is_newline_delimited_json_not_sse(wire, no_gate, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_WIRE_STREAM", "1")
    provider = make("ollama")
    wire.enqueue(b"".join(json.dumps(event).encode() + b"\n" for event in (
        {"message": {"role": "assistant", "content": "Two "}, "done": False},
        {"message": {"role": "assistant", "content": "critical findings."}, "done": False},
        {"message": {"role": "assistant", "content": ""}, "done": True, "model": "llama3.1",
         "done_reason": "stop", "prompt_eval_count": 9, "eval_count": 5},
    )))
    chunks = list(provider.stream(provider.start(SYSTEM, [], QUESTION), None))
    assert chunks[-1].completion.text == "Two critical findings."
    assert chunks[-1].completion.usage.output_tokens == 5
    assert wire.last["body"]["stream"] is True


@pytest.mark.parametrize("name", NETWORK_PROVIDERS)
def test_a_provider_that_cannot_stream_still_streams_one_chunk(name, wire, no_gate):
    """The console must behave the same whatever the provider can do."""
    _, answer, _, _ = CASES[name]
    provider = make(name, stream_supported=False)
    wire.enqueue(answer)
    chunks = list(provider.stream(provider.start(SYSTEM, [], QUESTION), None, chunk_chars=5))
    assert "".join(chunk.text for chunk in chunks) == "Two critical findings."
    assert chunks[-1].done and chunks[-1].completion is not None
    assert len([c for c in chunks if c.text]) > 1, "the text should arrive in pieces"


# --------------------------------------------------------------------------- #
# The capability matrix
# --------------------------------------------------------------------------- #

def test_every_shipped_adapter_declares_a_full_capability_row():
    rows = {row["provider"]: row for row in llm.capability_matrix()}
    assert set(rows) == set(registry.ADAPTERS) | {"custom"}
    for name, adapter in registry.ADAPTERS.items():
        caps = adapter(Settings(provider=name)).capabilities()
        assert isinstance(caps, Capabilities)
        assert caps.provider == name
        assert caps.system_prompt in (llm.SYSTEM_MESSAGE, llm.SYSTEM_SEPARATE, llm.SYSTEM_NONE)
        assert isinstance(caps.tools, bool) and isinstance(caps.streaming, bool)


def test_the_capability_matrix_is_honest_about_tool_calling():
    """These two cover servers that do not implement function calling, so
    claiming tools would make the agent wait for calls that never arrive."""
    assert make("openai-compatible", tools_supported=None).capabilities().tools is False
    assert make("ollama", tools_supported=None).capabilities().tools is False
    # ...and the first-party APIs do support it.
    assert make("anthropic").capabilities().tools is True
    assert make("openai").capabilities().tools is True
    assert make("gemini").capabilities().tools is True


def test_the_builtin_answerer_declares_no_network_and_no_tools():
    builtin = registry.build(Settings(provider="builtin"))
    caps = builtin.capabilities()
    assert caps.network is False and caps.tools is False
    assert caps.streaming is True, "the console sees chunks from every provider"
    assert caps.cost_known is True and caps.endpoint == ""


def test_anthropic_keeps_its_shipped_model_default():
    """A stale model pin is invisible except on the invoice or in a 404."""
    caps = registry.build(Settings(provider="anthropic", api_key="k")).capabilities()
    assert caps.model == "claude-opus-5"
    assert caps.model not in {"claude-sonnet-4-6", "claude-3-5-sonnet", "claude-3-opus"}


@pytest.mark.parametrize("name", sorted(registry.ADAPTERS))
def test_describe_never_contains_a_credential(name):
    provider = registry.build(Settings(provider=name, api_key="sk-super-secret-value",
                                       base_url="https://host/v1", model="m",
                                       headers={"X-Gateway-Token": "tok-secret-value"}))
    described = json.dumps(provider.describe())
    assert "sk-super-secret-value" not in described
    assert "tok-secret-value" not in described
    assert provider.describe()["config"]["api_key_present"] is True
    assert provider.describe()["config"]["extra_header_names"] == ["X-Gateway-Token"]


# --------------------------------------------------------------------------- #
# Transport: errors, retries, backoff
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status, kind, in_remedy", [
    (401, AUTH, "API key"), (403, AUTH, "API key"), (404, "not_found", "model name"),
    (429, RATE_LIMIT, "Retry"), (400, BAD_REQUEST, "request shape"),
    (500, SERVER, "status page"), (503, SERVER, "status page"),
])
def test_each_http_failure_gets_its_own_kind_and_remedy(status, kind, in_remedy):
    error = transport.classify(status, "openai")
    assert error.kind == kind
    assert in_remedy in error.remedy
    assert error.status == status


def test_an_error_message_never_echoes_the_provider_body(wire, no_gate):
    import urllib.error

    class _Err(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("https://api.openai.com", 400, "Bad Request", {},
                             io.BytesIO(b'{"error":{"message":"your prompt said sk-leak-me"}}'))

    provider = make("openai", retries=0)
    wire.enqueue(_Err())
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert "sk-leak-me" not in str(caught.value)
    assert "sk-leak-me" not in caught.value.remedy


def test_retryable_failures_back_off_and_then_succeed(wire, no_gate, monkeypatch):
    waits: list[float] = []
    monkeypatch.setattr(transport, "_sleep", waits.append)
    provider = make("openai", retries=2)
    wire.enqueue(transport.classify(429, "openai"), transport.classify(500, "openai"),
                 _OPENAI_ANSWER)
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert completion.text == "Two critical findings."
    assert len(wire.sent) == 3
    assert waits == [0.5, 1.0], "deterministic backoff, so an operator can reason about latency"


def test_a_bad_key_is_never_retried(wire, no_gate, monkeypatch):
    monkeypatch.setattr(transport, "_sleep", lambda _s: pytest.fail("a 401 must not be retried"))
    provider = make("openai", retries=3)
    wire.enqueue(transport.classify(401, "openai"))
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == AUTH
    assert len(wire.sent) == 1


def test_retries_give_up_and_raise_the_last_typed_error(wire, no_gate):
    provider = make("openai", retries=1)
    wire.enqueue(transport.classify(503, "openai"), transport.classify(503, "openai"))
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == SERVER and caught.value.degradable
    assert len(wire.sent) == 2


def test_a_timeout_is_a_timeout_not_a_connection_failure(wire, no_gate):
    import socket

    provider = make("openai", retries=0)
    wire.enqueue(socket.timeout("timed out"))
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == TIMEOUT
    assert "MORROW_LLM_TIMEOUT" in caught.value.remedy


def test_an_unreachable_host_is_a_connection_failure(wire, no_gate):
    import urllib.error

    provider = make("openai-compatible", retries=0)
    wire.enqueue(urllib.error.URLError("getaddrinfo failed"))
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == CONNECTION
    assert caught.value.degradable


def test_a_redirect_is_refused_rather_than_followed():
    """A 302 would move the request off the destination the tenant approved."""
    with pytest.raises(LLMError) as caught:
        transport._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere")
    assert caught.value.kind == BAD_REQUEST


def test_html_instead_of_json_says_so_rather_than_crashing(wire, no_gate):
    provider = make("openai-compatible", retries=0)
    wire.enqueue(b"<html><body>404 not found</body></html>")
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == BAD_REQUEST
    assert "chat-completions" in caught.value.remedy


def test_a_response_without_choices_is_a_clear_error(wire, no_gate):
    provider = make("openai", retries=0)
    wire.enqueue({"id": "x"})
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None)
    assert caught.value.kind == BAD_REQUEST


# --------------------------------------------------------------------------- #
# Configuration and precedence
# --------------------------------------------------------------------------- #

def test_with_nothing_set_the_builtin_answerer_is_chosen():
    assert config.env_provider() == ("builtin", "default")


def test_an_anthropic_key_alone_keeps_todays_behaviour(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert config.env_provider() == ("anthropic", "default")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-x")
    assert config.env_provider() == ("anthropic", "default"), "Anthropic still wins"


def test_an_openai_key_alone_keeps_todays_behaviour(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-x")
    assert config.env_provider() == ("openai", "default")


def test_an_explicit_provider_beats_a_stray_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "ollama")
    assert config.env_provider() == ("ollama", "environment")


@pytest.mark.parametrize("spelling, expected", [
    ("claude", "anthropic"), ("Azure", "azure-openai"), ("google", "gemini"),
    ("groq", "openai-compatible"), ("LM-Studio", "openai-compatible"),
    ("vllm", "openai-compatible"), ("off", "builtin"), ("none", "builtin"),
])
def test_an_operators_likely_spelling_is_accepted(spelling, expected, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", spelling)
    assert config.env_provider()[0] == expected


def test_legacy_anthropic_variables_are_still_honoured(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("ANTHROPIC_AGENT_MODEL", "claude-opus-5")
    monkeypatch.setenv("ANTHROPIC_AGENT_MAX_TOKENS", "16000")
    monkeypatch.setenv("AGENT_TIMEOUT", "180")
    settings = config.from_environment()
    assert settings.api_key == "sk-ant-x" and settings.model == "claude-opus-5"
    assert settings.max_tokens == 16000 and settings.timeout == 180


def test_numeric_settings_are_clamped_not_trusted(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "openai")
    monkeypatch.setenv("MORROW_LLM_TEMPERATURE", "99")
    monkeypatch.setenv("MORROW_LLM_MAX_TOKENS", "1")
    monkeypatch.setenv("MORROW_LLM_TIMEOUT", "99999")
    monkeypatch.setenv("MORROW_LLM_RETRIES", "not a number")
    settings = config.from_environment()
    assert settings.temperature == 2.0 and settings.max_tokens == 256
    assert settings.timeout == 600 and settings.retries == 2


@pytest.mark.parametrize("raw, expected", [
    ('{"X-Tenant":"acme"}', {"X-Tenant": "acme"}),
    ("X-Tenant=acme,X-Route=eu", {"X-Tenant": "acme", "X-Route": "eu"}),
    ("", {}),
    ("not json and not pairs", {}),
])
def test_extra_headers_parse_both_accepted_forms(raw, expected):
    assert config.parse_headers(raw)[0] == expected


@pytest.mark.parametrize("raw", [
    '{"Host":"evil.example"}', '{"Content-Length":"0"}',
    '{"X-Bad\\r\\nInjected":"v"}', '{"X-Ok":"line1\\r\\nline2"}',
])
def test_headers_that_would_rewrite_the_request_are_refused(raw):
    headers, rejected = config.parse_headers(raw)
    assert headers == {} and rejected


def test_a_rejected_header_is_named_but_its_value_is_not():
    _, rejected = config.parse_headers('{"Host":"super-secret-host.internal"}')
    assert rejected == ["Host"]
    assert "super-secret-host" not in json.dumps(rejected)


# --------------------------------------------------------------------------- #
# The custom-module loader
# --------------------------------------------------------------------------- #

def _install(monkeypatch, name: str, body: str):
    module = types.ModuleType(name)
    module.__dict__["__name__"] = name
    exec(compile(body, name, "exec"), module.__dict__)
    monkeypatch.setitem(sys.modules, name, module)
    return module


_VALID = """
from services.llm.base import Capabilities, Completion, Conversation, Provider, SYSTEM_MESSAGE


class MyProvider(Provider):
    id = "my-provider"

    def capabilities(self):
        return Capabilities(provider="my-provider", model=self.settings.model or "mine",
                            streaming=False, tools=False, context_window=8192,
                            system_prompt=SYSTEM_MESSAGE)

    def complete(self, conv, tools=None, *, org_id="", purpose="assistant", policy_version=None):
        return Completion(text="from my own model", provider="my-provider", model="mine")

    def add_assistant(self, conv, completion):
        conv.messages.append({"role": "assistant", "content": completion.text})

    def add_tool_results(self, conv, results):
        return None
"""


def test_a_valid_custom_module_loads_and_answers(monkeypatch):
    _install(monkeypatch, "pq_test_valid", _VALID)
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "custom")
    monkeypatch.setenv("MORROW_LLM_CUSTOM_MODULE", "pq_test_valid")
    provider, notes = llm.resolve()
    assert provider.id == "my-provider"
    assert provider.capabilities().context_window == 8192
    assert provider.complete(provider.start("s", [], "q")).text == "from my own model"
    assert notes == []


def test_the_factory_form_is_accepted(monkeypatch):
    _install(monkeypatch, "pq_test_factory",
             _VALID + "\n\ndef get_provider(settings):\n    return MyProvider(settings)\n")
    provider = custom.load(Settings(provider="custom", custom_module="pq_test_factory"))
    assert provider.id == "my-provider"


def test_a_class_named_provider_is_accepted(monkeypatch):
    _install(monkeypatch, "pq_test_named", _VALID + "\n\nProvider = MyProvider\n")
    assert custom.load(Settings(provider="custom", custom_module="pq_test_named")).id == "my-provider"


def test_a_missing_module_fails_with_a_message_not_a_traceback():
    with pytest.raises(LLMError) as caught:
        custom.load(Settings(provider="custom", custom_module="no_such_package.no_such_module"))
    assert caught.value.kind == CONFIG
    assert "Could not import" in caught.value.message
    assert "PYTHONPATH" in caught.value.remedy


def test_no_module_named_at_all_says_which_variable_to_set():
    with pytest.raises(LLMError) as caught:
        custom.load(Settings(provider="custom"))
    assert "MORROW_LLM_CUSTOM_MODULE" in caught.value.remedy


@pytest.mark.parametrize("path", ["/etc/passwd", "my-package.mod", "http://x/y", "a..b", "1bad"])
def test_a_value_that_is_not_an_import_path_is_refused(path):
    """Handing anything to importlib would import a package nobody named."""
    with pytest.raises(LLMError) as caught:
        custom.load(Settings(provider="custom", custom_module=path))
    assert "dotted import path" in caught.value.message or "dotted import path" in caught.value.remedy


def test_a_module_with_no_provider_says_what_to_define(monkeypatch):
    _install(monkeypatch, "pq_test_empty", "VALUE = 1\n")
    with pytest.raises(LLMError) as caught:
        custom.load(Settings(provider="custom", custom_module="pq_test_empty"))
    assert "exposes no provider" in caught.value.message
    assert "examples/custom_llm_provider.py" in caught.value.remedy


def test_a_module_with_two_providers_asks_which_one(monkeypatch):
    _install(monkeypatch, "pq_test_two", _VALID + _VALID.replace("MyProvider", "OtherProvider"))
    with pytest.raises(LLMError) as caught:
        custom.load(Settings(provider="custom", custom_module="pq_test_two"))
    assert "defines 2 providers" in caught.value.message


def test_a_module_missing_part_of_the_interface_is_named_precisely(monkeypatch):
    _install(monkeypatch, "pq_test_partial", """
from services.llm.base import Capabilities, Provider


class Half(Provider):
    id = "half"

    def capabilities(self):
        return Capabilities(provider="half", model="m", streaming=False, tools=False,
                            context_window=None)

    def complete(self, conv, tools=None, **kwargs):
        return None
""")
    instance = sys.modules["pq_test_partial"].Half(Settings(provider="custom"))
    object.__setattr__(instance, "add_assistant", None)
    with pytest.raises(LLMError) as caught:
        custom.validate(instance, "pq_test_partial")
    assert "add_assistant()" in caught.value.message


def test_capabilities_returning_the_wrong_type_is_caught():
    class Wrong:
        def capabilities(self):
            return {"provider": "x"}

        start = complete = add_assistant = add_tool_results = lambda *a, **k: None

    with pytest.raises(LLMError) as caught:
        custom.validate(Wrong(), "pq_test_wrong")
    assert "not Capabilities" in caught.value.message


def test_capabilities_that_names_no_model_is_caught():
    class Nameless:
        def capabilities(self):
            return Capabilities(provider="x", model="", streaming=False, tools=False,
                                context_window=None)

        start = complete = add_assistant = add_tool_results = lambda *a, **k: None

    with pytest.raises(LLMError) as caught:
        custom.validate(Nameless(), "pq_test_nameless")
    assert "no model" in caught.value.message, "the console must never misreport what answered"


def test_a_broken_custom_module_degrades_to_the_builtin_answerer(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "custom")
    monkeypatch.setenv("MORROW_LLM_CUSTOM_MODULE", "no_such_package.at_all")
    provider, notes = llm.resolve()
    assert provider.id == "builtin"
    assert any("Could not import" in note for note in notes)


def test_the_shipped_example_satisfies_the_contract():
    """examples/custom_llm_provider.py is what a user copies; it must load."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "examples" / "custom_llm_provider.py"
    assert path.exists(), "the documented example must exist"
    spec = importlib.util.spec_from_file_location("morrow_example_provider", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    instance = module.get_provider(Settings(provider="custom", base_url="https://x/v1",
                                            api_key="k", model="m"))
    custom.validate(instance, "examples/custom_llm_provider.py")
    assert instance.capabilities().tools is False
    assert instance.check()["ready"] is True


def test_an_unknown_provider_name_lists_the_real_ones():
    with pytest.raises(LLMError) as caught:
        registry.build(Settings(provider="gpt5-turbo-max"))
    assert caught.value.kind == CONFIG
    for name in ("anthropic", "ollama", "custom"):
        assert name in caught.value.remedy


def test_a_selected_but_unconfigured_provider_answers_from_rules_and_says_so(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "azure-openai")   # no base URL, no key
    provider, notes = llm.resolve()
    assert provider.id == "builtin"
    assert any("not fully configured" in note for note in notes)
    assert any("MORROW_LLM_BASE_URL" in note for note in notes)


# --------------------------------------------------------------------------- #
# Disabled mode
# --------------------------------------------------------------------------- #

def test_disabled_forces_the_builtin_answerer_whatever_else_is_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    assert llm.disabled() is True
    provider, notes = llm.resolve()
    assert provider.id == "builtin"
    assert any("MORROW_LLM_DISABLED" in note for note in notes)


def test_disabled_is_decided_before_the_organization_is_consulted(monkeypatch):
    """Otherwise a customer could re-enable a model call the operator forbade."""
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    consulted = []
    from services.llm import org_config

    monkeypatch.setattr(org_config, "load", lambda org: consulted.append(org))
    settings, notes = registry.settings_for("org-a")
    assert settings.provider == "builtin"
    assert consulted == [], "the organization's override must not even be read"


def test_describe_reports_the_disabled_state_to_the_console(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    described = llm.describe()
    assert described["disabled"] is True
    assert described["active"]["network"] is False
    assert described["precedence"][0].startswith("MORROW_LLM_DISABLED")


# --------------------------------------------------------------------------- #
# The built-in answerer as a first-class provider
# --------------------------------------------------------------------------- #

def test_the_builtin_answerer_answers_from_the_registered_rules(monkeypatch):
    from services.llm import builtin

    monkeypatch.setattr(builtin, "_answerer",
                        lambda question: {"reply": f"rules say: {question}", "intent": "answer",
                                          "actions": ["open_report"]})
    provider = registry.build(Settings(provider="builtin"))
    completion = provider.complete(provider.start("", [], "what blocks go-live?"))
    assert completion.text == "rules say: what blocks go-live?"
    assert completion.model == "builtin-rules"
    assert completion.usage.cost_usd == 0.0 and completion.usage.basis == "provider_reported"
    assert completion.raw["actions"] == ["open_report"]


def test_the_builtin_answerer_makes_no_request(monkeypatch, wire):
    from services.llm import builtin

    monkeypatch.setattr(builtin, "_answerer", lambda question: {"reply": "local"})
    provider = registry.build(Settings(provider="builtin"))
    provider.complete(provider.start("", [], "q"))
    assert wire.sent == [], "the built-in answerer must never touch the network"


def test_an_unregistered_builtin_says_so_instead_of_answering_emptily(monkeypatch):
    from services.llm import builtin

    monkeypatch.setattr(builtin, "_answerer", None)
    provider = registry.build(Settings(provider="builtin"))
    assert provider.check()["ready"] is False
    assert "MORROW_LLM_PROVIDER" in provider.complete(provider.start("", [], "q")).text


# --------------------------------------------------------------------------- #
# Per-organization override, including isolation
# --------------------------------------------------------------------------- #

@pytest.fixture()
def org_store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "llm-org.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    import importlib

    from services.llm import org_config

    importlib.reload(org_config)
    org_config._ready.clear()
    return org_config


def test_an_organization_can_supply_its_own_provider_and_key(org_store):
    org_store.set_override("org-a", {"provider": "openai-compatible",
                                     "base_url": "https://llm.acme.example/v1",
                                     "model": "acme-7b", "api_key": "acme-secret-key",
                                     "tools_supported": True, "max_tokens": 2048})
    loaded = org_store.load("org-a")
    assert loaded["provider"] == "openai-compatible"
    assert loaded["api_key"] == "acme-secret-key"
    assert loaded["max_tokens"] == 2048


def test_the_key_is_sealed_at_rest_and_never_described(org_store):
    org_store.set_override("org-a", {"provider": "openai-compatible", "model": "m",
                                     "base_url": "https://llm.acme.example/v1",
                                     "api_key": "acme-secret-key",
                                     "headers": {"X-Tenant": "acme-header-secret"}})
    import db_feature_store as store

    with store.feature_conn() as conn:
        row = conn.execute("SELECT key_sealed, headers_sealed FROM llm_org_provider "
                           "WHERE organization_id=?", ("org-a",)).fetchone()
    assert "acme-secret-key" not in row["key_sealed"]
    assert "acme-header-secret" not in row["headers_sealed"]

    described = json.dumps(org_store.describe("org-a"))
    assert "acme-secret-key" not in described
    assert "acme-header-secret" not in described
    assert org_store.describe("org-a")["api_key_present"] is True
    assert org_store.describe("org-a")["extra_header_names"] == ["X-Tenant"]


def test_an_organization_reads_and_writes_only_its_own(org_store):
    org_store.set_override("org-a", {"provider": "ollama", "model": "a-model"})
    org_store.set_override("org-b", {"provider": "gemini", "model": "b-model",
                                     "api_key": "b-key"})
    assert org_store.describe("org-a")["model"] == "a-model"
    assert org_store.describe("org-b")["model"] == "b-model"
    assert org_store.load("org-a").get("api_key") is None, "org-a must not see org-b's key"
    org_store.clear_override("org-a")
    assert org_store.describe("org-a")["configured"] is False
    assert org_store.describe("org-b")["configured"] is True, "clearing one must not touch another"


@pytest.mark.parametrize("org", ["", "*", None])
def test_an_unverified_organization_is_refused(org_store, org):
    with pytest.raises(org_store.OverrideError):
        org_store.describe(org)
    with pytest.raises(org_store.OverrideError):
        org_store.set_override(org, {"provider": "ollama"})
    assert org_store.load(org) is None


def test_an_organization_cannot_name_code_for_this_process_to_import(org_store):
    with pytest.raises(org_store.OverrideError):
        org_store.set_override("org-a", {"provider": "custom"})
    with pytest.raises(org_store.OverrideError):
        org_store.set_override("org-a", {"provider": "ollama",
                                         "custom_module": "attacker.module"})


def test_an_override_that_merely_names_custom_is_ignored_on_merge():
    base = config.from_environment("openai", "environment").with_(api_key="env-key",
                                                                  model="gpt-4o-mini")
    merged = config.merge_org(base, {"provider": "custom",
                                     "custom_module": "attacker.module"})
    assert merged.provider == "openai"
    assert merged.custom_module == ""


def test_changing_the_provider_does_not_carry_the_deployments_key_across():
    """An Anthropic key must not be sent to a Gemini endpoint it was never issued for."""
    base = config.from_environment("anthropic", "environment").with_(
        api_key="sk-ant-deployment", model="claude-opus-5")
    merged = config.merge_org(base, {"provider": "gemini", "model": "gemini-2.0-flash"})
    assert merged.provider == "gemini"
    assert merged.api_key == ""
    assert merged.model == "gemini-2.0-flash"
    assert merged.source == "organization"


def test_the_same_provider_keeps_the_deployments_settings_and_overrides_the_rest():
    base = config.from_environment("openai", "environment").with_(api_key="sk-env",
                                                                  model="gpt-4o-mini")
    merged = config.merge_org(base, {"provider": "openai", "model": "gpt-4o"})
    assert merged.api_key == "sk-env" and merged.model == "gpt-4o"


def test_an_unreadable_override_falls_back_with_a_note(monkeypatch):
    from services.llm import org_config

    def boom(_org):
        raise RuntimeError("feature store down")

    monkeypatch.setattr(org_config, "load", boom)
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "ollama")
    settings, notes = registry.settings_for("org-a")
    assert settings.provider == "ollama"
    assert any("could not be read" in note for note in notes)


@pytest.mark.parametrize("payload", [
    {"provider": "openai-compatible", "headers": {"Host": "evil.example"}},
    {"provider": "openai-compatible", "temperature": "hot"},
    {"provider": "not-a-provider"},
    {"provider": "openai", "unknown_field": 1},
])
def test_a_bad_override_is_rejected_with_a_reason(org_store, payload):
    with pytest.raises(org_store.OverrideError):
        org_store.set_override("org-a", payload)


def test_an_empty_key_field_keeps_the_stored_one(org_store):
    org_store.set_override("org-a", {"provider": "gemini", "model": "m", "api_key": "first-key"})
    org_store.set_override("org-a", {"provider": "gemini", "model": "m2"})
    assert org_store.load("org-a")["api_key"] == "first-key"
    assert org_store.load("org-a")["model"] == "m2"


def test_selecting_the_builtin_answerer_clears_any_destination(org_store):
    org_store.set_override("org-a", {"provider": "gemini", "model": "m", "api_key": "k",
                                     "base_url": "https://x/v1"})
    org_store.set_override("org-a", {"provider": "builtin"})
    described = org_store.describe("org-a")
    assert described["provider"] == "builtin"
    assert described["base_url"] == "" and described["api_key_present"] is False


# --------------------------------------------------------------------------- #
# The data boundary: the tenant's policy, and no secret in any prompt
# --------------------------------------------------------------------------- #

@pytest.fixture()
def gated(tmp_path, monkeypatch):
    """A real Data Control policy approving the brought-your-own destination."""
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "llm-gate.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("MORROW_LLM_BASE_URL", "https://llm.acme.example/v1")
    monkeypatch.setenv("MORROW_LLM_MODEL", "acme-7b")
    monkeypatch.setenv("MORROW_LLM_API_KEY", "acme-wire-key")
    monkeypatch.setenv("MORROW_LLM_TOOLS", "1")
    import importlib

    from services import ai_privacy

    importlib.reload(ai_privacy)
    ai_privacy._ready.clear()
    return ai_privacy


def _approve(privacy, org, **changes):
    conf = {**privacy.default_policy(), "mode": "approved_external", "provider": "byo",
            "workflows": ["assistant"], "free_text": True, **changes}
    version = privacy.policy(org)["version"]
    reviewed = privacy.review(conf, version, org)
    return privacy.change_policy(org, conf, version, reviewed["review_hash"], "customer-admin")


def test_a_brought_your_own_destination_can_be_approved_and_is_pinned(gated):
    approved = _approve(gated, "org-a")
    assert approved["provider"] == "byo"
    assert approved["approved_destination"] == "https://llm.acme.example/v1/chat/completions"
    assert approved["approved_model"] == "acme-7b"


def test_a_dispatch_without_an_approved_policy_never_reaches_the_wire(gated, wire):
    provider, _ = llm.resolve("org-unapproved")
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-unapproved")
    assert caught.value.kind == llm.BLOCKED
    assert wire.sent == [], "no network I/O before the tenant has approved"


def test_an_approved_dispatch_reaches_the_wire_and_is_receipted(gated, wire):
    _approve(gated, "org-a")
    wire.enqueue(_OPENAI_ANSWER)
    provider, _ = llm.resolve("org-a")
    completion = provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-a")
    assert completion.text == "Two critical findings."
    assert len(wire.sent) == 1
    kinds = [receipt["data"]["event_type"] for receipt in gated.events("org-a")]
    assert "request.authorized" in kinds and "request.response_received" in kinds


def test_changing_the_destination_requires_the_customer_to_reapprove(gated, monkeypatch, wire):
    _approve(gated, "org-a")
    monkeypatch.setenv("MORROW_LLM_BASE_URL", "https://somewhere-else.example/v1")
    provider, _ = llm.resolve("org-a")
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-a")
    assert "reapproval" in caught.value.message
    assert wire.sent == []


def test_a_credential_in_the_question_is_blocked_before_any_network_io(gated, wire):
    _approve(gated, "org-a")
    provider, _ = llm.resolve("org-a")
    leaky = "Here is our key: sk-abcdefghijklmnopqrstuvwxyz0123456789 - what should I do?"
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], leaky), None, org_id="org-a")
    assert caught.value.kind == llm.BLOCKED
    assert wire.sent == [], "a credential pattern must stop the call before the socket"


@pytest.mark.parametrize("secret", [
    "-----BEGIN RSA PRIVATE KEY-----",
    "password: hunter2",
    "Authorization: Bearer abcdef123456",
    "AKIAIOSFODNN7EXAMPLE",
    "sk-abcdefghijklmnopqrstuvwxyz",
])
def test_no_prompt_containing_a_secret_ever_leaves(gated, wire, secret):
    _approve(gated, "org-a")
    provider, _ = llm.resolve("org-a")
    with pytest.raises(LLMError):
        provider.complete(provider.start(SYSTEM, [], f"Review this: {secret}"), None,
                          org_id="org-a")
    assert wire.sent == []
    assert all(secret not in json.dumps(sent) for sent in wire.sent)


def test_the_providers_own_credential_is_never_in_the_prompt(gated, wire):
    """The wire key belongs in a header; it must not end up in the body or the receipt."""
    _approve(gated, "org-a")
    wire.enqueue(_OPENAI_ANSWER)
    provider, _ = llm.resolve("org-a")
    provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-a")
    assert "acme-wire-key" not in json.dumps(wire.last["body"])
    assert wire.last["headers"]["Authorization"] == "Bearer acme-wire-key"
    assert all("acme-wire-key" not in json.dumps(receipt) for receipt in gated.events("org-a"))


def test_a_credential_in_the_model_output_withholds_the_response(gated, wire):
    _approve(gated, "org-a")
    wire.enqueue({**_OPENAI_ANSWER, "choices": [{"index": 0, "finish_reason": "stop", "message": {
        "role": "assistant", "content": "Use api_key=sk-abcdefghijklmnopqrstuv to fix it."}}]})
    provider, _ = llm.resolve("org-a")
    with pytest.raises(LLMError) as caught:
        provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-a")
    assert caught.value.kind == llm.BLOCKED
    assert "credential" in caught.value.message.lower()


def test_data_control_strips_every_tool_but_the_read_only_posture_summary(gated, wire):
    """The agent declares many tools; only the allowlisted read tool may be offered."""
    _approve(gated, "org-a")
    wire.enqueue(_OPENAI_ANSWER)
    provider, _ = llm.resolve("org-a")
    provider.complete(provider.start(SYSTEM, [], QUESTION), [
        {"name": "get_org_posture", "description": "", "input_schema": {"type": "object", "properties": {}}},
        {"name": "github_merge_pr", "description": "", "input_schema": {"type": "object", "properties": {}}},
    ], org_id="org-a")
    names = [tool["function"]["name"] for tool in wire.last["body"].get("tools", [])]
    assert names == ["get_org_posture"]
    assert "github_merge_pr" not in wire.last["raw"]


def test_the_organizations_own_provider_is_what_dispatches(gated, org_store, wire, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-deployment")
    org_store.set_override("org-a", {"provider": "openai-compatible", "model": "acme-7b",
                                     "base_url": "https://llm.acme.example/v1",
                                     "api_key": "org-own-key"})
    provider, notes = llm.resolve("org-a")
    assert provider.id == "openai-compatible"
    assert any("own provider" in note for note in notes)
    _approve(gated, "org-a")
    wire.enqueue(_OPENAI_ANSWER)
    provider, _ = llm.resolve("org-a")
    provider.complete(provider.start(SYSTEM, [], QUESTION), None, org_id="org-a")
    assert wire.last["url"].startswith("https://llm.acme.example/v1")
    assert wire.last["headers"]["Authorization"] == "Bearer org-own-key"
    assert "sk-ant-deployment" not in json.dumps(wire.last)


# --------------------------------------------------------------------------- #
# Provider failure degrades to the built-in answerer
# --------------------------------------------------------------------------- #

def _drain(generator):
    import asyncio

    async def run():
        return [chunk async for chunk in generator]

    events = []
    for chunk in asyncio.run(run()):
        for line in chunk.splitlines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    return events


def test_a_provider_outage_answers_from_rules_with_a_visible_note(gated, wire, monkeypatch):
    _approve(gated, "org-a")
    from services import ai_agent
    from services.llm import builtin

    monkeypatch.setattr(builtin, "_answerer",
                        lambda question: {"reply": "Open Administration > Launch readiness."})
    wire.enqueue(transport.classify(503, "openai-compatible"),
                 transport.classify(503, "openai-compatible"),
                 transport.classify(503, "openai-compatible"))
    events = _drain(ai_agent._run_provider(QUESTION, [], "org-a"))
    kinds = [event["type"] for event in events]

    assert "done" in kinds, "a provider outage must not be a dead end"
    assert "".join(e.get("text", "") for e in events if e["type"] == "token") == \
        "Open Administration > Launch readiness."
    notes = [e["text"] for e in events if e["type"] == "notice"]
    assert notes and "unavailable" in notes[0]
    # The answer must name the built-in rules, not the provider that failed.
    final = [e for e in events if e["type"] == "provider"][-1]
    assert final["provider"] == "builtin" and final["network"] is False


def test_a_policy_refusal_is_reported_and_not_routed_around(gated, wire, monkeypatch):
    """Degrading past the customer's own decision would defeat Data Control."""
    from services import ai_agent

    _approve(gated, "org-a")
    provider, _ = llm.resolve("org-a")

    def blocked(*args, **kwargs):
        raise LLMError(llm.BLOCKED, "AI is off for this organization.", provider=provider.id)

    monkeypatch.setattr(type(provider), "complete", blocked)
    monkeypatch.setattr(llm, "resolve", lambda org="": (provider, []))
    monkeypatch.setattr("services.llm.registry.resolve", lambda org="": (provider, []))
    events = _drain(ai_agent._run_provider(QUESTION, [], "org-a"))
    assert [e["type"] for e in events].count("error") == 1
    assert "AI is off" in next(e["text"] for e in events if e["type"] == "error")
    assert "token" not in [e["type"] for e in events]


def test_a_provider_without_tools_says_so_and_still_answers(gated, wire, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_TOOLS", "0")
    _approve(gated, "org-a")
    from services import ai_agent

    wire.enqueue(_OPENAI_ANSWER)
    events = _drain(ai_agent._run_provider(QUESTION, [], "org-a"))
    statuses = " ".join(e.get("text", "") for e in events if e["type"] == "status")
    assert "does not support tool calling" in statuses
    assert "done" in [e["type"] for e in events]
    # The system prompt names the tool; what matters is that none was offered.
    assert "tools" not in wire.last["body"] and "tool_choice" not in wire.last["body"]


def test_the_stream_names_the_model_that_answered(gated, wire):
    _approve(gated, "org-a")
    from services import ai_agent

    wire.enqueue(_OPENAI_ANSWER)
    events = _drain(ai_agent._run_provider(QUESTION, [], "org-a"))
    declared = next(e for e in events if e["type"] == "provider")
    assert declared["provider"] == "openai-compatible"
    assert declared["model"] == "acme-7b"
    usage = next(e for e in events if e["type"] == "usage")
    assert usage["data"]["input_tokens"] == 120
    assert usage["data"]["cost_basis"] == "unknown", "no price configured, so no guess"


def test_disabled_mode_answers_from_rules_before_the_policy_is_read(gated, wire, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    from services import ai_agent
    from services.llm import builtin

    monkeypatch.setattr(builtin, "_answerer", lambda question: {"reply": "Local rules only."})
    # No policy is approved for this organization at all; with a model configured
    # that would raise, and here it must simply answer.
    events = _drain(ai_agent.run_agent_stream(QUESTION, [], "org-never-approved"))
    assert "".join(e.get("text", "") for e in events if e["type"] == "token") == "Local rules only."
    assert any("MORROW_LLM_DISABLED" in e.get("text", "") for e in events if e["type"] == "notice")
    assert wire.sent == []


# --------------------------------------------------------------------------- #
# What the console is told
# --------------------------------------------------------------------------- #

def test_active_provider_is_safe_to_render_and_names_what_is_sent(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("MORROW_LLM_BASE_URL", "https://llm.acme.example/v1")
    monkeypatch.setenv("MORROW_LLM_MODEL", "acme-7b")
    monkeypatch.setenv("MORROW_LLM_API_KEY", "console-secret-key")
    from services import ai_agent

    described = ai_agent.active_provider("")
    rendered = json.dumps(described)
    assert "console-secret-key" not in rendered
    assert described["active"]["provider"] == "openai-compatible"
    assert described["active"]["model"] == "acme-7b"
    assert described["data_sent"]["sent"] and described["data_sent"]["never_sent"]
    assert any("credential" in line.lower() for line in described["data_sent"]["never_sent"])


def test_usage_totals_say_unknown_rather_than_guessing():
    from services.llm import usage

    usage.reset("org-u")
    usage.record("org-u", "ollama", "llama3.1",
                 Usage(input_tokens=10, output_tokens=5, basis="unknown"))
    totals = usage.totals("org-u")
    assert totals["input_tokens"] == 10 and totals["output_tokens"] == 5
    assert totals["cost_usd"] is None and totals["cost_known_for"] == 0
    assert "not billing" in totals["basis"]
    usage.reset("org-u")


def test_a_usage_record_holds_no_prompt_or_completion():
    from services.llm import usage

    usage.reset("org-u")
    usage.record("org-u", "openai", "gpt-4o-mini", Usage(input_tokens=1, output_tokens=1),
                 latency_ms=12)
    entry = usage.recent("org-u", 1)[0]
    assert set(entry) >= {"provider", "model", "input_tokens", "output_tokens", "cost_usd"}
    assert not any("prompt" in key or "content" in key or "text" in key for key in entry)
    usage.reset("org-u")


# --------------------------------------------------------------------------- #
# The two long-standing paths also name what answered
# --------------------------------------------------------------------------- #

def test_the_anthropic_path_names_its_model_and_records_its_tokens(tmp_path, monkeypatch):
    """The default deployment is the one most users see, so the attribution and
    the token ledger have to work there too -- not only on the new adapters."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "legacy.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "sqlite")
    import importlib

    from services import ai_privacy
    from services import ai_agent

    importlib.reload(ai_privacy)
    ai_privacy._ready.clear()
    importlib.reload(ai_agent)

    conf = {**ai_privacy.default_policy(), "mode": "approved_external", "provider": "anthropic",
            "workflows": ["assistant"], "free_text": True}
    reviewed = ai_privacy.review(conf, 0, "org-legacy")
    ai_privacy.change_policy("org-legacy", conf, 0, reviewed["review_hash"], "admin")

    monkeypatch.setattr(ai_agent._CLIENT.messages, "create", lambda **kwargs: _Message({
        "stop_reason": "end_turn", "model": "claude-opus-5",
        "content": [{"type": "text", "text": "Two critical findings."}],
        "usage": {"input_tokens": 300, "output_tokens": 25}}))

    from services.llm import usage as llm_usage

    llm_usage.reset("org-legacy")
    events = _drain(ai_agent._run_claude(QUESTION, [], "org-legacy"))
    declared = next(event for event in events if event["type"] == "provider")
    assert declared["provider"] == "anthropic"
    assert declared["model"] == "claude-opus-5"
    assert declared["tools"] is True and declared["network"] is True

    recorded = llm_usage.recent("org-legacy", 1)[0]
    assert recorded["input_tokens"] == 300 and recorded["output_tokens"] == 25
    assert recorded["cost_usd"] is None, "no price configured, so no guessed figure"
    llm_usage.reset("org-legacy")


class _Message:
    def __init__(self, payload):
        self._payload = payload

    def model_dump(self):
        return self._payload


# --------------------------------------------------------------------------- #
# The operator console's Service health view
# --------------------------------------------------------------------------- #

def test_the_health_check_states_the_provider_without_a_credential(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("MORROW_LLM_BASE_URL", "https://llm.acme.example/v1")
    monkeypatch.setenv("MORROW_LLM_MODEL", "acme-7b")
    monkeypatch.setenv("MORROW_LLM_API_KEY", "health-secret-key")
    monkeypatch.setenv("MORROW_LLM_TOOLS", "1")
    import app

    check = app._ai_provider_health()
    assert check["status"] == "ok"
    assert "openai-compatible / acme-7b" in check["detail"]
    assert "tools yes" in check["detail"] and "streaming yes" in check["detail"]
    assert "health-secret-key" not in json.dumps(check)


def test_the_health_check_calls_a_half_configured_provider_an_error(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "gemini")   # no key
    import app

    check = app._ai_provider_health()
    assert check["status"] == "error"
    assert "gemini is selected but not active" in check["detail"]


def test_the_health_check_treats_the_builtin_answerer_as_a_valid_state(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    import app

    check = app._ai_provider_health()
    assert check["status"] == "configured", "a deliberate off switch is not a fault"
    assert "MORROW_LLM_DISABLED=1" in check["detail"]


# --------------------------------------------------------------------------- #
# The /ai-control/provider endpoints
# --------------------------------------------------------------------------- #

@pytest.fixture()
def api(gated, monkeypatch):
    """The real router, with a harness role check. Tenant comes from request state."""
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient

    from routers.ai_privacy import create_ai_privacy_router

    def require_role(request, allowed_roles, **kwargs):
        if request.headers.get("test-role", "viewer") not in allowed_roles:
            raise HTTPException(403)
        # Harness only. Production uses app._require_role and the verified org_id.
        request.state.org_id = request.headers.get("test-org", "org-a")
        return {"actor_id": "test-admin", "actor_role": request.headers.get("test-role", "viewer")}

    application = FastAPI()
    application.include_router(create_ai_privacy_router(require_role))
    with TestClient(application) as client:
        yield client


ADMIN = {"test-role": "admin", "test-org": "org-a"}
VIEWER = {"test-role": "viewer", "test-org": "org-a"}
OTHER_ADMIN = {"test-role": "admin", "test-org": "org-b"}


def test_the_provider_endpoint_answers_with_everything_the_console_needs(api):
    body = api.get("/ai-control/provider", headers=VIEWER).json()
    assert body["active"]["provider"] == "openai-compatible"
    assert body["active"]["model"] == "acme-7b"
    assert set(body["active"]) >= {"tools", "streaming", "context_window", "endpoint", "network"}
    assert body["capability_matrix"] and body["custom_contract"]["example"].endswith(".py")
    assert body["data_sent"]["never_sent"]
    assert "acme-wire-key" not in api.get("/ai-control/provider", headers=VIEWER).text


def test_only_an_admin_may_set_test_or_clear_the_provider(api):
    assert api.put("/ai-control/provider", headers=VIEWER,
                   json={"provider": "ollama"}).status_code == 403
    assert api.post("/ai-control/provider/test", headers=VIEWER,
                    json={"prompt": "ping"}).status_code == 403
    assert api.delete("/ai-control/provider", headers=VIEWER).status_code == 403
    assert api.get("/ai-control/provider", headers=VIEWER).status_code == 200


def test_setting_a_provider_never_returns_the_key_back(api):
    saved = api.put("/ai-control/provider", headers=ADMIN, json={
        "provider": "openai-compatible", "model": "org-model",
        "base_url": "https://org.example/v1", "api_key": "org-endpoint-secret",
        "headers": {"X-Tenant": "acme"}}).json()
    assert saved["api_key_present"] is True
    assert "org-endpoint-secret" not in json.dumps(saved)
    assert saved["extra_header_names"] == ["X-Tenant"]
    assert "org-endpoint-secret" not in api.get("/ai-control/provider", headers=ADMIN).text


def test_one_organization_cannot_read_or_change_another(api):
    api.put("/ai-control/provider", headers=ADMIN,
            json={"provider": "ollama", "model": "a-model"})
    api.put("/ai-control/provider", headers=OTHER_ADMIN,
            json={"provider": "gemini", "model": "b-model", "api_key": "b-key"})

    mine = api.get("/ai-control/provider", headers=ADMIN).json()["organization_override"]
    theirs = api.get("/ai-control/provider", headers=OTHER_ADMIN).json()["organization_override"]
    assert mine["model"] == "a-model" and theirs["model"] == "b-model"
    assert mine["organization_id"] == "org-a" and theirs["organization_id"] == "org-b"

    # Clearing one must leave the other alone.
    api.delete("/ai-control/provider", headers=ADMIN)
    assert api.get("/ai-control/provider", headers=ADMIN).json()["organization_override"]["configured"] is False
    assert api.get("/ai-control/provider", headers=OTHER_ADMIN).json()["organization_override"]["configured"] is True


def test_an_organization_cannot_select_a_custom_module(api):
    refused = api.put("/ai-control/provider", headers=ADMIN,
                      json={"provider": "custom", "model": "m"})
    assert refused.status_code == 422, refused.text
    forged = api.put("/ai-control/provider", headers=ADMIN,
                     json={"provider": "ollama", "custom_module": "attacker.module"})
    assert forged.status_code == 422, forged.text


def test_a_refused_header_name_is_rejected_with_a_reason(api):
    refused = api.put("/ai-control/provider", headers=ADMIN, json={
        "provider": "openai-compatible", "model": "m", "base_url": "https://x/v1",
        "headers": {"Host": "evil.example"}})
    assert refused.status_code == 422
    assert "Host" in refused.text


def test_a_disabled_deployment_refuses_a_per_organization_override(api, monkeypatch):
    monkeypatch.setenv("MORROW_LLM_DISABLED", "1")
    refused = api.put("/ai-control/provider", headers=ADMIN, json={"provider": "gemini",
                                                                   "api_key": "k"})
    assert refused.status_code == 409
    assert "MORROW_LLM_DISABLED=1" in refused.text
    assert api.get("/ai-control/provider", headers=ADMIN).json()["disabled"] is True


def test_the_test_prompt_proves_the_configuration(api, gated, wire):
    _approve(gated, "org-a")
    wire.enqueue(_OPENAI_ANSWER)
    result = api.post("/ai-control/provider/test", headers=ADMIN,
                      json={"prompt": "Reply with the single word: ready."}).json()
    assert result["ok"] is True
    assert result["reply"] == "Two critical findings."
    assert result["answered_by_model"] == "gpt-4o-mini" or result["model"] == "acme-7b"
    assert result["usage"]["input_tokens"] == 120
    assert "acme-wire-key" not in json.dumps(result)


def test_the_test_prompt_reports_the_typed_error_and_its_remedy(api, gated, wire):
    _approve(gated, "org-a")
    wire.enqueue(transport.classify(401, "openai-compatible"))
    result = api.post("/ai-control/provider/test", headers=ADMIN,
                      json={"prompt": "ping"}).json()
    assert result["ok"] is False
    assert result["error"]["kind"] == AUTH
    assert "API key" in result["error"]["remedy"]
    assert result["reply"] == ""


def test_the_test_prompt_says_when_the_policy_has_not_been_approved(api, wire):
    result = api.post("/ai-control/provider/test", headers=ADMIN, json={"prompt": "ping"}).json()
    assert result["ok"] is False
    assert result["error"]["kind"] == llm.BLOCKED
    assert wire.sent == [], "an unapproved tenant must not reach the wire, even for a test"


@pytest.mark.parametrize("named, expected_url", [
    ("groq", "https://api.groq.com/openai/v1"),
    ("openrouter", "https://openrouter.ai/api/v1"),
    ("together", "https://api.together.xyz/v1"),
    ("lm-studio", "http://127.0.0.1:1234/v1"),
    ("llamacpp", "http://127.0.0.1:8080/v1"),
])
def test_naming_a_gateway_fills_in_its_base_url(named, expected_url, monkeypatch):
    """There is no reason to make an operator look up a URL they just named."""
    monkeypatch.setenv("MORROW_LLM_PROVIDER", named)
    monkeypatch.setenv("MORROW_LLM_MODEL", "some-model")
    settings = config.from_environment()
    assert settings.provider == "openai-compatible"
    assert settings.base_url == expected_url


def test_an_explicit_base_url_always_wins_over_the_implied_one(monkeypatch):
    monkeypatch.setenv("MORROW_LLM_PROVIDER", "groq")
    monkeypatch.setenv("MORROW_LLM_BASE_URL", "https://my-proxy.internal/v1")
    monkeypatch.setenv("MORROW_LLM_MODEL", "some-model")
    assert config.from_environment().base_url == "https://my-proxy.internal/v1"


# --------------------------------------------------------------------------- #
# /agent/chat is never a dead end
# --------------------------------------------------------------------------- #

def test_the_chat_endpoint_falls_back_to_rules_when_the_model_only_errors(tmp_path, monkeypatch):
    """The two long-standing paths report a provider failure as an error event.
    The endpoint must still answer -- with the reason attached -- rather than
    hand the console an empty reply."""
    from fastapi.testclient import TestClient

    from test_assistant_chat import _load_app

    fastapi_app = _load_app(tmp_path, monkeypatch)
    from services import ai_agent
    from services import ai_privacy
    from db import current_organization_id

    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-test-key")
    conf = {**ai_privacy.default_policy(), "mode": "approved_external", "provider": "openai",
            "workflows": ["assistant"], "free_text": True}
    org = current_organization_id()
    reviewed = ai_privacy.review(conf, 0)
    ai_privacy.change_policy(org, conf, 0, reviewed["review_hash"], "test-admin")

    async def only_an_error(message, history, org_id, user_id=None):
        yield "data: " + json.dumps({"type": "error", "text": "Rate limited by the provider."}) + "\n\n"

    monkeypatch.setattr(ai_agent, "run_agent_stream", only_an_error)
    with TestClient(fastapi_app.app) as client:
        body = client.post("/agent/chat", json={"message": "Is RSA quantum safe?",
                                                "question": "Is RSA quantum safe?"}).json()
    assert body["reply"], "an outage must not produce an empty answer"
    assert body["error"] == ""
    assert body["source"] == "rules-fallback"
    assert "Rate limited by the provider." in body["notice"]
    assert body["answered_by"]["provider"] == "builtin"
    assert body["answered_by"]["network"] is False
