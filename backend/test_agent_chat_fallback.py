"""/agent/chat without an AI provider answers with built-in guidance instead of a dead-end error.

The response keeps the original contract (reply, evidence, error) and adds source, ai_configured and a notice.
"""

import json

from fastapi.testclient import TestClient

from test_assistant_chat import _load_app


def _no_provider(monkeypatch):
    from services import ai_agent

    monkeypatch.setattr(ai_agent, "_USE_CLAUDE", False)
    monkeypatch.setattr(ai_agent, "_OPENAI_KEY", "")
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MORROW_AI_LOCAL_URL"):
        monkeypatch.delenv(key, raising=False)
    assert ai_agent.provider_configured() is False


def test_no_provider_serves_rule_based_guidance_with_a_notice(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    _no_provider(monkeypatch)

    async def must_not_stream(*args, **kwargs):  # the AI loop must not run without a provider
        raise AssertionError("agent stream called without a provider")
        yield ""

    from services import ai_agent

    monkeypatch.setattr(ai_agent, "run_agent_stream", must_not_stream)
    with TestClient(fastapi_app.app) as client:
        res = client.post("/agent/chat", json={"message": "Workspace context...\n\nUser request: Is RSA quantum safe?",
                                               "question": "Is RSA quantum safe?", "history": []})
        assert res.status_code == 200, res.text
        body = res.json()
        assert set(body) >= {"reply", "evidence", "error"}
        assert body["error"] == "" and body["evidence"] == {}
        assert "RSA is not quantum-safe" in body["reply"]
        assert body["ai_configured"] is False and body["source"] == "rules"
        assert "AI is off by customer policy" in body["notice"]

        launch = client.post("/agent/chat", json={"message": "What are the exact blockers before this can go live?"}).json()
        assert launch["intent"] == "summarize_status" and "Launch readiness" in launch["reply"] and launch["error"] == ""

        # Old clients that send only message (no question field) still get an answer.
        plain = client.post("/agent/chat", json={"message": "scan a website"}).json()
        assert plain["reply"] and plain["error"] == ""


def test_configured_provider_keeps_the_streamed_contract(tmp_path, monkeypatch):
    fastapi_app = _load_app(tmp_path, monkeypatch)
    from services import ai_agent

    monkeypatch.setattr(ai_agent, "_USE_CLAUDE", True)
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-test-key")
    from services import ai_privacy
    from db import current_organization_id
    conf = {**ai_privacy.default_policy(), "mode":"approved_external", "provider":"openai", "workflows":["assistant"], "free_text":True}
    review = ai_privacy.review(conf, 0)
    ai_privacy.change_policy(current_organization_id(), conf, 0, review["review_hash"], "test-admin")

    async def fake_stream(message, history, org_id, user_id=None):
        yield "data: " + json.dumps({"type": "token", "text": "Hello "}) + "\n\n"
        yield "data: " + json.dumps({"type": "token", "text": "operator"}) + "\n\n"
        yield "data: " + json.dumps({"type": "evidence", "data": {"k": 1}}) + "\n\n"
        yield "data: " + json.dumps({"type": "done"}) + "\n\n"

    monkeypatch.setattr(ai_agent, "run_agent_stream", fake_stream)
    with TestClient(fastapi_app.app) as client:
        body = client.post("/agent/chat", json={"message": "hi"}).json()
    assert body["reply"] == "Hello operator" and body["evidence"] == {"k": 1} and body["error"] == ""
    assert body["ai_configured"] is True and body["source"] == "ai" and "notice" not in body


def test_console_shows_the_notice_and_falls_back_when_the_ai_answer_is_empty():
    import pathlib

    html = (pathlib.Path(__file__).resolve().parent / "static" / "index.html").read_text(encoding="utf-8")
    send = html[html.index("ACTIONS.copilotSend = async"):]
    send = send[:send.index("function capResultDrawer")]
    assert "question: q" in send and "r.data?.notice" in send and "/assistant/chat" in send
    assert "copilotNote" in send
