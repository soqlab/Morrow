"""A worked example: bring your own model provider, in code.

Copy this file somewhere on your PYTHONPATH, change the three marked places,
and point the platform at it:

    PQC_LLM_PROVIDER=custom
    PQC_LLM_CUSTOM_MODULE=my_package.my_provider
    PQC_LLM_BASE_URL=https://models.internal.example/v1   # if you want one
    PQC_LLM_MODEL=our-internal-model
    PQC_LLM_API_KEY=...                                   # if you need one

Then prove it works without spending a request on guesswork:

    # configuration only, no network
    python scripts/check-integrations.py --offline --only ai
    # one real call, from the console: Data Control -> Model provider -> Send a test prompt

What the platform asks of you
-----------------------------
Exactly five methods, and a declaration of what you support:

    capabilities()        -> services.llm.base.Capabilities
    start(system, history, message) -> services.llm.base.Conversation
    complete(conv, tools, *, org_id, purpose, policy_version) -> Completion
    add_assistant(conv, completion)
    add_tool_results(conv, results)

Subclassing `services.llm.base.Provider` gives you `start()`, `stream()`,
`check()`, `describe()` and the data-boundary dispatch for free, so in practice
you write `capabilities()`, `complete()`, and the two conversation methods --
and if you declare `tools=False`, the two conversation methods are never
called and can stay as they are below.

Three rules that are not optional
---------------------------------
1. Send your request through `self._dispatch(payload, invoke, ...)`. That is
   the tenant's data boundary: it checks the organization's Data Control
   policy, pins the destination and model, minimises the payload, signs a
   receipt, and scans the response for credential patterns. `payload` must be
   the OpenAI-shaped `{"model", "messages", ...}` dict -- that is what the
   boundary can read and digest -- and `invoke(clean)` translates it to your
   wire format and performs the single HTTP request.
2. Raise `services.llm.base.LLMError(kind, message, remedy=...)` and nothing
   else. `kind` decides what happens next: a retryable or degradable kind
   falls back to the built-in answerer with a visible note, while `BAD_REQUEST`
   surfaces to the operator. Never let a raw exception out; never put a key,
   a header value or any part of the prompt in the message.
3. Tell the truth in `capabilities()`. If you declare `tools=True` and ignore
   the tool definitions, the agent will wait for tool calls that never come.
   Declaring `tools=False` is a supported, tested configuration: the assistant
   answers without tools and says so.

Alternatives to the class below
-------------------------------
The loader accepts any of:

  * `get_provider(settings)` returning a provider instance (use this if you
    want to choose between several implementations at load time),
  * a class named `Provider`,
  * exactly one subclass of `services.llm.base.Provider` defined in the module.

Whatever it finds is validated before anything calls it, and a module that
does not satisfy the contract fails with a message naming what is wrong --
not a traceback.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# The platform runs with `backend/` on sys.path, so these are the import paths
# your module uses too.
from services.llm import transport
from services.llm.base import (
    BAD_REQUEST,
    CONFIG,
    Capabilities,
    Completion,
    Conversation,
    LLMError,
    Provider,
    SYSTEM_MESSAGE,
    ToolCall,
    Usage,
    estimate_cost,
)


class MyProvider(Provider):
    """Talks to an imaginary internal model service."""

    # (1) CHANGE ME -- the name the console shows for what answered.
    id = "my-provider"

    # Which Data Control destination this adapter dispatches through. Leave it
    # as "byo": that is the destination for every provider an operator brings
    # themselves, and it is what the customer approves in the console.
    privacy_provider = "byo"

    # -- declaration --------------------------------------------------------
    def capabilities(self) -> Capabilities:
        return Capabilities(
            provider=self.id,
            model=self.settings.model or "our-internal-model",
            # Say what is true. The agent and the console both read this.
            streaming=False,
            tools=False,
            context_window=32_000,
            system_prompt=SYSTEM_MESSAGE,   # or SYSTEM_SEPARATE, or SYSTEM_NONE
            usage_reported=True,
            cost_known=self.settings.price_input_per_mtok is not None,
            endpoint=self._endpoint(),
            notes="Example adapter from examples/custom_llm_provider.py.",
        )

    def check(self) -> Dict[str, Any]:
        """Configuration readiness. No network call: this runs on every page load."""
        missing: List[str] = []
        if not self.settings.base_url:
            missing.append("PQC_LLM_BASE_URL")
        if not self.settings.api_key:
            missing.append("PQC_LLM_API_KEY")
        return {
            "ready": not missing,
            "missing": missing,
            "detail": "configured" if not missing else "set " + ", ".join(missing),
        }

    def _endpoint(self) -> str:
        base = (self.settings.base_url or "").rstrip("/")
        return (base + "/chat") if base else ""

    # -- the request --------------------------------------------------------
    def complete(
        self,
        conv: Conversation,
        tools: Optional[List[Dict[str, Any]]] = None,
        *,
        org_id: str = "",
        purpose: str = "assistant",
        policy_version: Optional[int] = None,
    ) -> Completion:
        if not self._endpoint():
            raise LLMError(
                CONFIG,
                "No base URL is configured for this provider.",
                provider=self.id,
                remedy="Set PQC_LLM_BASE_URL.",
            )

        # The canonical, policy-visible payload. Keep it in this shape: the data
        # boundary reads `messages` to minimise the content and to digest the
        # request for the signed receipt.
        payload: Dict[str, Any] = {
            "model": self.settings.model or "our-internal-model",
            "messages": conv.messages,
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
        }

        def invoke(clean: Dict[str, Any]) -> Dict[str, Any]:
            # (2) CHANGE ME -- translate the approved payload to your wire
            # format and make exactly one request. Use `transport` so retries,
            # backoff, timeouts, proxy and redirect handling, response-size
            # limits and typed errors all behave like every other provider.
            body = {
                "model": clean["model"],
                "input": [
                    {"speaker": message.get("role"), "utterance": message.get("content")}
                    for message in clean.get("messages", [])
                ],
                "settings": {
                    "temperature": clean.get("temperature", 0.1),
                    "limit": clean.get("max_tokens", 3000),
                },
            }
            return transport.post_json(
                self._endpoint(),
                body,
                headers={"Authorization": "Bearer " + self.settings.api_key,
                         **self.settings.headers},
                timeout=self.settings.timeout,
                retries=self.settings.retries,
                provider=self.id,
            )

        raw, latency_ms = self._timed(
            lambda: self._dispatch(payload, invoke, org_id=org_id, purpose=purpose,
                                   policy_version=policy_version)
        )

        # (3) CHANGE ME -- parse your response into a Completion.
        answer = raw.get("answer")
        if not isinstance(answer, str):
            raise LLMError(
                BAD_REQUEST,
                "The provider response had no answer field.",
                provider=self.id,
                remedy="Check the endpoint path and the response schema.",
            )
        counts = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
        usage = estimate_cost(
            self.settings,
            Usage(input_tokens=_int(counts.get("in")), output_tokens=_int(counts.get("out"))),
        )
        # If you declare tools=True, parse them here into ToolCall(id=..., name=...,
        # arguments={...}) and set stop_reason="tool_use"; the agent runs them and
        # calls add_assistant()/add_tool_results() before the next complete().
        calls: List[ToolCall] = []
        return Completion(
            text=answer,
            tool_calls=calls,
            stop_reason="end_turn",        # or "tool_use" / "refusal" / "max_tokens"
            usage=usage,
            provider=self.id,
            model=str(raw.get("model") or self.settings.model),
            raw=raw,
            latency_ms=latency_ms,
        )

    # -- the tool round trip ------------------------------------------------
    # Only needed when capabilities().tools is True. The agent calls
    # add_assistant() with the turn that asked for tools, runs them, then calls
    # add_tool_results() with (tool_call_id, json_text) pairs -- and the next
    # complete() must replay both so the model sees what it asked for.
    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
        message: Dict[str, Any] = {"role": "assistant", "content": completion.text or ""}
        if completion.tool_calls:
            import json

            message["tool_calls"] = [
                {"id": call.id, "type": "function",
                 "function": {"name": call.name,
                              "arguments": json.dumps(call.arguments, default=str)}}
                for call in completion.tool_calls
            ]
        conv.messages.append(message)

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        for call_id, text in results:
            conv.messages.append({"role": "tool", "tool_call_id": call_id, "content": text})


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_provider(settings):
    """Optional. Present here so this file demonstrates the factory form too."""
    return MyProvider(settings)
