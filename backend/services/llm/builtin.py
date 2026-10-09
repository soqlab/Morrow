"""The built-in answerer, as a first-class provider.

"No AI configured" is a mode, not an error path. This adapter answers from the
platform's own rules and database -- the same rule engine behind
/assistant/chat -- so every surface above the provider layer behaves the same
whether a model is configured or not.

It is also the deliberate choice for a deployment that forbids any external
model call: PQC_LLM_DISABLED=1 resolves here and nothing can override it, not
even a per-organization setting.

Nothing in this adapter touches the network, so there is no data boundary to
cross and no Data Control dispatch: the question never leaves the process.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from services.llm.base import (
    Capabilities, Completion, Conversation, Provider, SYSTEM_NONE, Usage,
)

MODEL = "builtin-rules"

#: app.py registers the rule engine here at import time. Kept as a hook rather
#: than an import so this package has no dependency on the application module.
_answerer: Optional[Callable[[str], Dict[str, Any]]] = None


def set_answerer(fn: Optional[Callable[[str], Dict[str, Any]]]) -> None:
    """Register the rule-based answerer: question -> {reply, intent, actions}."""
    global _answerer
    _answerer = fn


def answerer() -> Optional[Callable[[str], Dict[str, Any]]]:
    return _answerer


_UNREGISTERED = (
    "The built-in answerer is not available in this process, and no model provider is "
    "configured. Set PQC_LLM_PROVIDER (see docs/AI_PROVIDERS.md) to point the assistant "
    "at a model, or use the console's non-AI workflows."
)


class BuiltinProvider(Provider):
    id = "builtin"
    #: Never dispatched: there is no destination.
    privacy_provider = "none"

    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider=self.id,
            model=MODEL,
            # The console sees chunks, as it does from every other provider.
            streaming=True,
            tools=False,
            context_window=None,
            system_prompt=SYSTEM_NONE,
            usage_reported=False,
            cost_known=True,          # it is free, and that is known, not guessed
            endpoint="",
            network=False,
            notes="Deterministic rules over this workspace's own data. No request leaves the process.",
        )

    def check(self) -> Dict[str, Any]:
        ready = _answerer is not None
        return {"ready": ready, "missing": [] if ready else ["builtin answerer registration"],
                "detail": "built-in rules, no network" if ready
                else "the rule engine is not registered in this process"}

    # The conversation is just the question: the rules do not use history.
    def start(self, system: str, history: List[Dict[str, Any]], message: str,
              *, history_limit: int = 10, chars: int = 2000) -> Conversation:
        return Conversation(system=system, messages=[{"role": "user", "content": str(message)}])

    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
        conv.messages.append({"role": "assistant", "content": completion.text})

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        # Unreachable: capabilities().tools is False, so no tool is ever offered.
        return None

    def complete(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                 org_id: str = "", purpose: str = "assistant",
                 policy_version: Optional[int] = None) -> Completion:
        question = ""
        for message in reversed(conv.messages):
            if message.get("role") == "user":
                question = str(message.get("content") or "")
                break
        if _answerer is None:
            return Completion(text=_UNREGISTERED, provider=self.id, model=MODEL,
                              usage=Usage(cost_usd=0.0, basis="provider_reported"))
        guidance = _answerer(question) or {}
        return Completion(
            text=str(guidance.get("reply") or ""),
            stop_reason="end_turn",
            usage=Usage(cost_usd=0.0, basis="provider_reported"),
            provider=self.id,
            model=MODEL,
            raw={"intent": guidance.get("intent"), "actions": guidance.get("actions") or []},
        )
