"""The one interface every model provider implements.

Nothing above this module knows which provider is in use. A caller holds a
`Provider`, asks it for `capabilities()`, builds a `Conversation` with
`start()`, and loops on `complete()` until the completion carries no tool
calls. Message encoding is the provider's business: adapters own their wire
format and expose only the normalised shapes in this file.

Every network-backed adapter sends its request through
`services.ai_privacy.dispatch`, which is the tenant's data boundary: it
authorises the call against the organisation's approved Data Control policy,
pins the destination and model, minimises the payload, signs a receipt, and
scans the response for credential patterns before the caller sees it. The
adapter translates the policy-approved canonical payload into provider wire
format *inside* that boundary, so what the gate inspects is what goes out.
"""

from __future__ import annotations

import abc
import json
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, ClassVar, Dict, Iterator, List, Optional, Tuple

# How a provider wants the system prompt delivered.
SYSTEM_SEPARATE = "separate"   # its own top-level field (Anthropic, Gemini)
SYSTEM_MESSAGE = "message"     # a message with role "system" (OpenAI shapes)
SYSTEM_NONE = "none"           # the provider has no notion of one (builtin)

# Error kinds. Callers switch on these instead of parsing messages.
AUTH = "auth"
NOT_FOUND = "not_found"
RATE_LIMIT = "rate_limit"
TIMEOUT = "timeout"
CONNECTION = "connection"
SERVER = "server"
BAD_REQUEST = "bad_request"
REFUSAL = "refusal"
CONFIG = "config"
BLOCKED = "blocked"           # the tenant's data boundary refused the call
KINDS = (AUTH, NOT_FOUND, RATE_LIMIT, TIMEOUT, CONNECTION, SERVER, BAD_REQUEST,
         REFUSAL, CONFIG, BLOCKED)

# Which of these are worth another attempt. A bad key or a rejected model is not.
RETRYABLE = frozenset({RATE_LIMIT, TIMEOUT, CONNECTION, SERVER})

# Error kinds that should degrade to the built-in answerer rather than dead-end.
DEGRADABLE = frozenset({RATE_LIMIT, TIMEOUT, CONNECTION, SERVER, NOT_FOUND, AUTH, CONFIG})


class LLMError(RuntimeError):
    """A typed provider failure.

    `kind` is one of KINDS, `remedy` is the operator-facing next step, and
    `status` is the HTTP status when there was one. The message never contains
    a key, a header value or any part of the prompt.
    """

    def __init__(self, kind: str, message: str, *, provider: str = "", status: Optional[int] = None,
                 remedy: str = "") -> None:
        super().__init__(message)
        self.kind = kind if kind in KINDS else SERVER
        self.message = message
        self.provider = provider
        self.status = status
        self.remedy = remedy

    @property
    def retryable(self) -> bool:
        return self.kind in RETRYABLE

    @property
    def degradable(self) -> bool:
        return self.kind in DEGRADABLE

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "provider": self.provider, "status": self.status,
                "message": self.message, "remedy": self.remedy}

    def operator_text(self) -> str:
        return f"{self.message} {self.remedy}".strip()


@dataclass(frozen=True)
class Capabilities:
    """What this provider, at this model, can actually do.

    Declared rather than guessed: the console shows it, the agent branches on
    `tools` and `streaming`, and the test suite asserts the whole matrix.
    """

    provider: str
    model: str
    streaming: bool
    tools: bool
    context_window: Optional[int]
    system_prompt: str = SYSTEM_MESSAGE
    usage_reported: bool = True          # does the provider return token counts
    cost_known: bool = False             # can a price be applied to those counts
    endpoint: str = ""                   # destination URL, never a credential
    network: bool = True                 # False only for the built-in answerer
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider, "model": self.model, "streaming": self.streaming,
            "tools": self.tools, "context_window": self.context_window,
            "system_prompt": self.system_prompt, "usage_reported": self.usage_reported,
            "cost_known": self.cost_known, "endpoint": self.endpoint,
            "network": self.network, "notes": self.notes,
        }


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Usage:
    """Token counts and cost. `None` means the provider did not say.

    `basis` records how cost was reached, so a number is never mistaken for a
    billed amount: "provider_reported", "price_table" or "unknown".
    """

    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cached_input_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    basis: str = "unknown"

    def as_dict(self) -> Dict[str, Any]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cached_input_tokens": self.cached_input_tokens,
                "cost_usd": self.cost_usd, "cost_basis": self.basis}


@dataclass
class Completion:
    """One provider turn, normalised."""

    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"      # end_turn | tool_use | refusal | max_tokens
    refusal_category: str = ""
    usage: Usage = field(default_factory=Usage)
    provider: str = ""
    model: str = ""
    tools_offered: bool = False        # were tools sent with this request
    raw: Dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0


@dataclass
class Chunk:
    """One streamed piece. `done` arrives once, carrying the full completion."""

    text: str = ""
    status: str = ""
    done: bool = False
    completion: Optional[Completion] = None


class Conversation:
    """Provider-native message accumulator.

    The list in `messages` is in the adapter's own wire shape; callers never
    read it. `add_assistant` and `add_tool_results` are the only ways to grow
    it, and each adapter implements them for its own format.
    """

    def __init__(self, system: str = "", messages: Optional[List[Any]] = None) -> None:
        self.system = system
        self.messages: List[Any] = list(messages or [])

    def __len__(self) -> int:
        return len(self.messages)


@dataclass(frozen=True)
class Settings:
    """Resolved, provider-agnostic configuration. Never logged, never returned.

    `api_key` and `headers` are the only secret-bearing fields; `redacted()`
    is what any surface outside this package is allowed to see.
    """

    provider: str
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 3000
    timeout: int = 60
    retries: int = 2
    headers: Dict[str, str] = field(default_factory=dict)
    api_version: str = ""
    deployment: str = ""
    custom_module: str = ""
    context_window: Optional[int] = None
    price_input_per_mtok: Optional[float] = None
    price_output_per_mtok: Optional[float] = None
    #: Operator override of a declared capability. None keeps the adapter's own
    #: answer; this exists because "OpenAI-compatible" says nothing about
    #: whether a particular server implements tool calling or SSE.
    tools_supported: Optional[bool] = None
    stream_supported: Optional[bool] = None
    source: str = "environment"        # environment | organization | disabled | default
    organization_id: str = ""

    def redacted(self) -> Dict[str, Any]:
        return {
            "provider": self.provider, "model": self.model, "base_url": self.base_url,
            "api_key_present": bool(self.api_key), "temperature": self.temperature,
            "max_tokens": self.max_tokens, "timeout": self.timeout, "retries": self.retries,
            "extra_header_names": sorted(self.headers), "api_version": self.api_version,
            "deployment": self.deployment, "custom_module": self.custom_module,
            "source": self.source,
        }

    def with_(self, **changes: Any) -> "Settings":
        return replace(self, **changes)


def estimate_cost(settings: Settings, usage: Usage, reported_cost: Optional[float] = None) -> Usage:
    """Attach a cost to a usage record, or leave it unknown.

    A cost the provider reported wins. Otherwise a price has to have been
    configured for this model; there is no built-in price table, because a
    stale hard-coded price is worse than "unknown" on an operator's screen.
    """
    if reported_cost is not None:
        return replace(usage, cost_usd=round(float(reported_cost), 6), basis="provider_reported")
    pin, pout = settings.price_input_per_mtok, settings.price_output_per_mtok
    if pin is None and pout is None:
        return replace(usage, cost_usd=None, basis="unknown")
    if usage.input_tokens is None and usage.output_tokens is None:
        return replace(usage, cost_usd=None, basis="unknown")
    total = ((usage.input_tokens or 0) * (pin or 0.0) + (usage.output_tokens or 0) * (pout or 0.0)) / 1_000_000
    return replace(usage, cost_usd=round(total, 6), basis="price_table")


class Provider(abc.ABC):
    """The interface. Eight members, no provider names above it."""

    id: ClassVar[str] = ""
    #: Which Data Control destination this adapter dispatches through. The
    #: policy vocabulary has three network destinations -- "anthropic",
    #: "openai" and "byo" (everything an operator brings themselves).
    privacy_provider: ClassVar[str] = "byo"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- declaration --------------------------------------------------------
    @abc.abstractmethod
    def capabilities(self) -> Capabilities:
        """What this provider supports. Must not touch the network."""

    def check(self) -> Dict[str, Any]:
        """Configuration readiness, without a network call.

        Returns {"ready": bool, "missing": [env var names], "detail": str}.
        """
        # The declared model, not the configured one: an adapter is entitled to
        # its own default, and a custom provider usually has one.
        missing: List[str] = []
        if not str(self.capabilities().model or "").strip():
            missing.append("PQC_LLM_MODEL")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "incomplete configuration"}

    # -- conversation -------------------------------------------------------
    def start(self, system: str, history: List[Dict[str, Any]], message: str,
              *, history_limit: int = 10, chars: int = 2000) -> Conversation:
        """Build a conversation in this provider's wire shape.

        The default is the OpenAI/Ollama shape with the system prompt as the
        first message; adapters that want it separately override this.
        """
        conv = Conversation(system=system)
        if self.capabilities().system_prompt == SYSTEM_MESSAGE and system:
            conv.messages.append({"role": "system", "content": system})
        for item in (history or [])[-history_limit:]:
            role = str((item or {}).get("role") or "")
            content = (item or {}).get("content")
            if role in ("user", "assistant") and isinstance(content, str) and content:
                conv.messages.append({"role": role, "content": content[:chars]})
        conv.messages.append({"role": "user", "content": str(message)[:4000]})
        return conv

    def add_assistant(self, conv: Conversation, completion: Completion) -> None:
        """Append the assistant turn so the next request replays it."""
        raise NotImplementedError

    def add_tool_results(self, conv: Conversation, results: List[Tuple[str, str]]) -> None:
        """Append tool results as (tool_call_id, json_text) pairs."""
        raise NotImplementedError

    # -- completion ---------------------------------------------------------
    @abc.abstractmethod
    def complete(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
                 org_id: str = "", purpose: str = "assistant",
                 policy_version: Optional[int] = None) -> Completion:
        """One turn. Raises LLMError on any failure."""

    def stream(self, conv: Conversation, tools: Optional[List[Dict[str, Any]]] = None, *,
               org_id: str = "", purpose: str = "assistant",
               policy_version: Optional[int] = None, chunk_chars: int = 40) -> Iterator[Chunk]:
        """Yield the turn in pieces.

        The default -- used by every provider that cannot stream, and by every
        provider whose response has to be credential-scanned in full before
        any of it is shown -- is to complete the turn and emit the text as
        chunks, so the console behaves identically either way.
        """
        completion = self.complete(conv, tools, org_id=org_id, purpose=purpose,
                                   policy_version=policy_version)
        text = completion.text or ""
        for index in range(0, len(text), max(1, chunk_chars)):
            yield Chunk(text=text[index:index + chunk_chars])
        yield Chunk(done=True, completion=completion)

    # -- shared plumbing ----------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        """Operator-facing description. Contains no credential."""
        caps = self.capabilities()
        return {**caps.as_dict(), "config": self.settings.redacted(), "check": self.check()}

    def _dispatch(self, payload: Dict[str, Any], invoke: Callable[[Dict[str, Any]], Dict[str, Any]], *,
                  org_id: str, purpose: str, policy_version: Optional[int]) -> Dict[str, Any]:
        """Send `payload` through the tenant's data boundary.

        `payload` is the canonical OpenAI-shaped request: that is what the
        boundary minimises, digests and records. `invoke` receives the cleaned
        copy and is responsible for translating it to this provider's wire
        format and performing the single HTTP request.
        """
        from services import ai_privacy  # late: ai_privacy imports no provider

        try:
            return ai_privacy.dispatch(org_id, purpose, self.privacy_provider, payload, invoke,
                                       expected_version=policy_version)
        except ai_privacy.PrivacyError as exc:
            raise LLMError(BLOCKED, str(exc), provider=self.id,
                           status=getattr(exc, "status", 403),
                           remedy="Review the organization's Data Control policy.") from None

    def _timed(self, fn: Callable[[], Dict[str, Any]]) -> Tuple[Dict[str, Any], int]:
        started = time.monotonic()
        raw = fn()
        return raw, int((time.monotonic() - started) * 1000)


def tool_text(value: Any, limit: int = 8000) -> str:
    """Serialise a tool result for the wire, bounded."""
    return json.dumps(value, default=str)[:limit]
