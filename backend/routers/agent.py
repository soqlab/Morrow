"""HTTP router for the PQC Scout agent (/agent/chat)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from services import ai_agent, ai_privacy
from db import current_organization_id

NO_PROVIDER_NOTICE = ("Built-in guidance (no AI provider configured). Configure a model destination and "
                      "obtain organization-admin approval in Data Control for read-only AI analysis.")


class AgentChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: List[Dict[str, Any]] = Field(default_factory=list)
    # Optional: the user's own words when `message` also carries console context. Used for the built-in
    # (rule-based) answer when no AI provider is configured.
    question: str = Field("", max_length=4000)


def create_agent_router(require_role: Callable, builtin_answer: Optional[Callable[[str], Dict[str, Any]]] = None) -> APIRouter:
    """builtin_answer(question) -> {reply, intent, actions}: rule-based guidance (app._assistant_rule_response)
    served when no AI provider key is configured, instead of an error."""
    router = APIRouter(tags=["Agent"])

    @router.post("/agent/chat")
    async def agent_chat(body: AgentChatRequest, request: Request):
        """
        AI agent endpoint — returns JSON with the full response once complete.

        Only the approved provider and read-only summary tool are available.
        Returns plain-English markdown; non-AI workflows are separate.
        """
        actor = require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="agent.chat",
            resource_type="organization",
            resource_id="",
        )
        org_id = str(getattr(request.state, "org_id", None) or actor.get("org_id") or current_organization_id())
        policy_off = (await run_in_threadpool(ai_privacy.policy, org_id))["mode"] == "off"

        # No provider: answer with built-in guidance and say so, rather than a dead-end error. The
        # reply/evidence/error keys keep their meaning; source, ai_configured and notice are additive.
        if builtin_answer is not None and (policy_off or not ai_agent.provider_configured()):
            guidance = await run_in_threadpool(builtin_answer, body.question or body.message)
            return {"reply": str(guidance.get("reply") or ""), "evidence": {}, "error": "", "source": "rules",
                    "ai_configured": False, "notice": "AI is off by customer policy. Built-in rules only; no model call." if policy_off else NO_PROVIDER_NOTICE, "intent": guidance.get("intent"),
                    "actions": guidance.get("actions") or []}

        # Collect the async generator into a single response
        text_parts: List[str] = []
        evidence: Dict[str, Any] = {}
        error: str = ""
        notice: str = ""
        answered_by: Dict[str, Any] = {}
        usage: Dict[str, Any] = {}

        async for event_str in ai_agent.run_agent_stream(body.message, body.history, org_id):
            # Each yielded string is: "data: {json}\n\n"
            raw = event_str.strip()
            if not raw.startswith("data:"):
                continue
            import json
            try:
                evt = json.loads(raw[5:].strip())
            except Exception:
                continue
            t = evt.get("type", "")
            if t == "token":
                text_parts.append(evt.get("text", ""))
            elif t == "evidence":
                evidence = evt.get("data") or {}
            elif t == "error":
                error = evt.get("text", "")
            elif t == "provider":
                # Which model actually answered. The console states this so a user is
                # never misled about what produced an answer.
                answered_by = {"provider": evt.get("provider"), "model": evt.get("model"),
                               "tools": bool(evt.get("tools")), "streaming": bool(evt.get("streaming")),
                               "network": bool(evt.get("network", True))}
                if evt.get("note"):
                    notice = str(evt["note"])
            elif t == "usage":
                usage = evt.get("data") or {}
            elif t == "notice":
                notice = str(evt.get("text") or "") or notice

        reply = "".join(text_parts)

        # A provider outage must not be a dead end. If the model path produced an
        # error and no text, answer from the built-in rules and say why.
        if error and not reply.strip() and builtin_answer is not None:
            guidance = await run_in_threadpool(builtin_answer, body.question or body.message)
            return {"reply": str(guidance.get("reply") or ""), "evidence": {}, "error": "",
                    "source": "rules-fallback", "ai_configured": True,
                    "notice": f"Built-in guidance (the model was unavailable: {error})",
                    "answered_by": {"provider": "builtin", "model": "builtin-rules",
                                    "tools": False, "streaming": True, "network": False},
                    "intent": guidance.get("intent"), "actions": guidance.get("actions") or []}

        conf = await run_in_threadpool(ai_privacy.policy, org_id)
        if not conf["free_text"]:
            notice = ("Metadata-only AI: your free-text question is withheld; analysis uses a "
                      "bounded organization summary.")
        return {
            "reply": reply,
            "evidence": evidence,
            "error": error,
            "source": "ai",
            "ai_configured": True,
            **({"answered_by": answered_by} if answered_by else {}),
            **({"usage": usage} if usage else {}),
            **({"notice": notice} if notice else {}),
        }

    return router
