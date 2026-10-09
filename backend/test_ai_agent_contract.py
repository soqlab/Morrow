"""Contract tests for the PQC Scout agent's Claude requests.

services/ai_agent.py is the platform's analyst -- 50 tools, a large system prompt,
a multi-round tool-calling loop -- and had no test coverage at all. These tests do
not call the API. They stub the SDK client and assert on the request that would
have gone out, plus the loop's handling of what comes back.

What they are guarding against, concretely:

  * A stale model pin. The agent shipped on claude-sonnet-4-6 long after it was
    superseded, and nothing failed.
  * Losing prompt caching. The tools + system prefix is identical on every turn of
    every conversation; without a cache breakpoint it is re-billed in full each
    time, and the regression is invisible except on the invoice.
  * Reintroducing thinking budget_tokens, which current models reject with a 400.
  * A refusal closing the stream with an empty answer and no explanation.
  * Collapsing the typed SDK errors back into one opaque message, which leaves the
    operator unable to tell a bad key from a rate limit.
"""

import asyncio
import copy
import json

import anthropic
import httpx2
import pytest


@pytest.fixture()
def agent(monkeypatch, tmp_path):
    """Import ai_agent with a key present so the Claude path is active."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    import importlib
    import services.ai_agent as module
    importlib.reload(module)
    monkeypatch.setenv("PQC_SCANNER_DB", str(tmp_path / "agent-privacy.db"))
    monkeypatch.setenv("PQC_MAIN_DB_BACKEND", "sqlite")
    monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "sqlite")
    from services import ai_privacy as privacy
    from db import current_organization_id
    conf = {**privacy.default_policy(), "mode": "approved_external", "provider": "anthropic", "workflows": ["assistant"], "free_text": True}
    for org in {"org-1", current_organization_id()}:
        proposal = privacy.review(conf, 0)
        privacy.change_policy(org, conf, 0, proposal["review_hash"], "test-admin")
    yield module
    # Leave the module reloaded without the test key, so later tests in the same
    # session see the real environment rather than this fixture's.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    importlib.reload(module)


class _FakeMessage:
    """Stands in for the SDK's Message; the loop only needs model_dump()."""

    def __init__(self, payload):
        self._payload = payload

    def model_dump(self):
        return self._payload


def _capture(agent, monkeypatch, responses):
    """Record the kwargs of each messages.create call and replay queued responses."""
    sent = []
    queue = list(responses)

    def _fake_create(**kwargs):
        # Deep copy: the loop appends to the same `messages` list after the call
        # returns, so holding the reference would have these assertions inspect
        # the conversation's final state rather than what this request sent.
        sent.append(copy.deepcopy(kwargs))
        nxt = queue.pop(0) if queue else {"stop_reason": "end_turn", "content": []}
        if isinstance(nxt, Exception):
            raise nxt
        return _FakeMessage(nxt)

    monkeypatch.setattr(agent._CLIENT.messages, "create", _fake_create)
    return sent


def _drain(gen):
    """Run an async generator to completion and return the decoded SSE events."""
    async def _run():
        return [chunk async for chunk in gen]
    chunks = asyncio.run(_run())
    events = []
    for chunk in chunks:
        for line in chunk.splitlines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    return events


def _http_error(cls, status):
    response = httpx2.Response(
        status, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    )
    return cls("boom", response=response, body=None)


# --------------------------------------------------------------------------- #
# Request contract
# --------------------------------------------------------------------------- #

def test_request_uses_a_current_model_with_adaptive_thinking(agent, monkeypatch):
    sent = _capture(agent, monkeypatch, [])
    agent._anthropic_call_sync([{"role": "user", "content": "hi"}], "SYSTEM")

    body = sent[0]
    assert body["model"] == agent._CLAUDE_MODEL
    # Models retired at time of writing. A pin to any of these is the bug this
    # test exists to catch, not a style preference.
    assert body["model"] not in {"claude-sonnet-4-6", "claude-3-5-sonnet", "claude-3-opus"}

    # Adaptive thinking is the only supported on-mode on current models, and the
    # fixed-budget form is rejected with a 400.
    assert body["thinking"] == {"type": "adaptive"}
    assert "budget_tokens" not in json.dumps(body["thinking"])

    # effort belongs inside output_config, not at the top level.
    assert body["output_config"]["effort"] == agent._CLAUDE_EFFORT
    assert "effort" not in body

    assert body["max_tokens"] >= 8000, "4096 truncated multi-tool answers mid-analysis"
    assert body["tools"], "the analyst is useless without its tools"


def test_static_prefix_is_cached_and_volatile_content_sits_after_it(agent, monkeypatch):
    sent = _capture(agent, monkeypatch, [])
    agent._anthropic_call_sync([{"role": "user", "content": "hi"}], "SYSTEM")
    body = sent[0]

    # The system prompt must be a block list to carry cache_control at all; a
    # bare string silently loses caching.
    assert isinstance(body["system"], list)
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["system"][0]["text"] == "SYSTEM"

    # At most 4 breakpoints are allowed per request.
    assert json.dumps(body, default=str).count('"cache_control"') <= 4


def test_cache_prefix_is_byte_stable_across_conversations(agent, monkeypatch):
    """Caching is a prefix match, so any per-request variation in tools or system
    invalidates every cached token behind it."""
    sent = _capture(agent, monkeypatch, [])
    agent._anthropic_call_sync([{"role": "user", "content": "first question"}], "SYSTEM")
    agent._anthropic_call_sync([{"role": "user", "content": "an entirely different one"}], "SYSTEM")

    first, second = sent
    assert json.dumps(first["tools"]) == json.dumps(second["tools"])
    assert json.dumps(first["system"]) == json.dumps(second["system"])
    assert first["messages"] != second["messages"], "the volatile half should differ"


def test_client_no_automatic_retries_and_bounded_timeout(agent):
    """An automatic replay after revocation must not bypass per-dispatch authorization."""
    assert agent._CLIENT is not None
    assert agent._CLIENT.max_retries == 0  # Every new dispatch must reauthorize after revocation.
    assert agent._CLIENT.timeout == float(agent._TIMEOUT)


def test_mid_conversation_policy_change_prevents_replaying_old_content(agent, monkeypatch):
    from services import ai_privacy as privacy
    calls = []
    def first_request(**kwargs):
        calls.append(kwargs)
        current = privacy.policy("org-1")
        conf = {key:current[key] for key in privacy.default_policy()}
        conf["free_text"] = False
        review = privacy.review(conf, current["version"])
        privacy.change_policy("org-1", conf, current["version"], review["review_hash"], "customer-admin")
        return _FakeMessage({"stop_reason":"tool_use", "content":[
            {"type":"thinking","thinking":"earlier private customer text","signature":"provider-sig"},
            {"type":"tool_use","id":"read-1","name":"get_org_posture","input":{}}]})
    monkeypatch.setattr(agent._CLIENT.messages, "create", first_request)
    events = _drain(agent._run_claude("private user question", [], "org-1"))
    assert len(calls) == 1
    assert any(e["type"] == "error" and "Policy changed" in e["text"] for e in events)


# --------------------------------------------------------------------------- #
# Response handling
# --------------------------------------------------------------------------- #

def test_refusal_is_reported_instead_of_closing_the_stream_empty(agent, monkeypatch):
    _capture(agent, monkeypatch, [{
        "stop_reason": "refusal",
        "stop_details": {"type": "refusal", "category": "cyber"},
        "content": [],
    }])

    events = _drain(agent._run_claude("attack something", [], "org-1"))
    kinds = [e["type"] for e in events]

    assert "error" in kinds, "a refusal must not look like a normal completed answer"
    assert "done" not in kinds
    assert any("declined" in e.get("text", "") for e in events if e["type"] == "error")
    assert any("cyber" in e.get("text", "") for e in events if e["type"] == "error")


def test_assistant_turns_are_echoed_back_unchanged(agent, monkeypatch):
    """Thinking blocks must survive the round trip: the API replays them from the
    assistant turn, and rebuilding that turn from extracted text alone drops them."""
    thinking_block = {"type": "thinking", "thinking": "", "signature": "sig-abc"}
    tool_use_block = {"type": "tool_use", "id": "tu_1", "name": "get_org_posture", "input": {}}

    sent = _capture(agent, monkeypatch, [
        {"stop_reason": "tool_use", "content": [thinking_block, tool_use_block]},
        {"stop_reason": "end_turn", "content": [{"type": "text", "text": "Done."}]},
    ])

    events = _drain(agent._run_claude("what is my posture?", [], "org-1"))
    assert "done" in [e["type"] for e in events]

    # Second request carries the first assistant turn plus our tool result.
    replayed = sent[1]["messages"]
    assistant_turn = next(m for m in replayed if m["role"] == "assistant")
    assert assistant_turn["content"] == [thinking_block, tool_use_block]

    tool_turn = replayed[-1]
    assert tool_turn["role"] == "user"
    assert tool_turn["content"][0]["type"] == "tool_result"
    assert tool_turn["content"][0]["tool_use_id"] == "tu_1"


@pytest.mark.parametrize(
    "error, expected",
    [
        (_http_error(anthropic.AuthenticationError, 401), "ANTHROPIC_API_KEY"),
        (_http_error(anthropic.NotFoundError, 404), "ANTHROPIC_AGENT_MODEL"),
        (_http_error(anthropic.RateLimitError, 429), "Rate limited"),
        (_http_error(anthropic.InternalServerError, 500), "500"),
        (anthropic.APIConnectionError(
            request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages")), "reach"),
    ],
)
def test_each_failure_mode_gets_its_own_actionable_message(agent, monkeypatch, error, expected):
    """A single broad handler would tell the operator 'AI call failed' for a bad
    key, a rate limit and an outage alike -- three different remedies."""
    _capture(agent, monkeypatch, [error])

    events = _drain(agent._run_claude("posture?", [], "org-1"))
    errors = [e["text"] for e in events if e["type"] == "error"]

    assert errors, f"{type(error).__name__} produced no error event"
    assert expected in errors[0], f"{type(error).__name__} -> {errors[0]!r}"
    assert "done" not in [e["type"] for e in events]
