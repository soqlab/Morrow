"""The model provider layer.

One interface (`base.Provider`), one HTTP boundary (`transport`), one place
that decides which adapter is in use (`registry.resolve`). Nothing above this
package names a provider.

    from services import llm

    provider, notes = llm.resolve(org_id)
    caps = provider.capabilities()
    conv = provider.start(SYSTEM_PROMPT, history, question)
    completion = provider.complete(conv, tools if caps.tools else None,
                                   org_id=org_id, policy_version=version)

Configuration, bring-your-own-model and the data boundary are documented in
docs/AI_PROVIDERS.md.
"""

from __future__ import annotations

from services.llm.base import (  # noqa: F401
    AUTH, BAD_REQUEST, BLOCKED, CONFIG, CONNECTION, NOT_FOUND, RATE_LIMIT, REFUSAL,
    SERVER, TIMEOUT, Capabilities, Chunk, Completion, Conversation, LLMError, Provider,
    Settings, SYSTEM_MESSAGE, SYSTEM_NONE, SYSTEM_SEPARATE, ToolCall, Usage, tool_text,
)
from services.llm.builtin import BuiltinProvider, set_answerer  # noqa: F401
from services.llm.config import (  # noqa: F401
    PROVIDER_IDS, disabled, env_provider, from_environment, normalise,
)
from services.llm.registry import (  # noqa: F401
    ADAPTERS, PRECEDENCE, build, capability_matrix, describe, resolve, settings_for,
)
from services.llm.usage import record as record_usage  # noqa: F401

__all__ = [
    "Provider", "Capabilities", "Completion", "Conversation", "Chunk", "ToolCall", "Usage",
    "Settings", "LLMError", "tool_text", "resolve", "describe", "build", "settings_for",
    "capability_matrix", "ADAPTERS", "PRECEDENCE", "PROVIDER_IDS", "disabled", "env_provider",
    "from_environment", "normalise", "set_answerer", "BuiltinProvider", "record_usage",
    "SYSTEM_MESSAGE", "SYSTEM_NONE", "SYSTEM_SEPARATE",
    "AUTH", "BAD_REQUEST", "BLOCKED", "CONFIG", "CONNECTION", "NOT_FOUND", "RATE_LIMIT",
    "REFUSAL", "SERVER", "TIMEOUT",
]
