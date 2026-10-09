"""Turn resolved configuration into a provider instance.

`resolve(org_id)` is the only function the rest of the platform needs. It
applies the precedence rules in config.py, loads the organization's override
when there is one, builds the adapter, and -- if anything about that is broken
-- returns the built-in answerer with the reason attached, rather than raising
into a request handler.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Type

from services.llm import config
from services.llm.anthropic_api import AnthropicProvider
from services.llm.azure_openai import AzureOpenAIProvider
from services.llm.base import CONFIG, LLMError, Provider, Settings
from services.llm.builtin import BuiltinProvider
from services.llm.gemini import GeminiProvider
from services.llm.ollama import OllamaProvider
from services.llm.openai_api import OpenAIProvider
from services.llm.openai_compatible import OpenAICompatibleProvider

ADAPTERS: Dict[str, Type[Provider]] = {
    AnthropicProvider.id: AnthropicProvider,
    OpenAIProvider.id: OpenAIProvider,
    AzureOpenAIProvider.id: AzureOpenAIProvider,
    GeminiProvider.id: GeminiProvider,
    OpenAICompatibleProvider.id: OpenAICompatibleProvider,
    OllamaProvider.id: OllamaProvider,
    BuiltinProvider.id: BuiltinProvider,
}


def build(settings: Settings) -> Provider:
    """Instantiate the adapter named by `settings.provider`. Raises LLMError."""
    name = config.normalise(settings.provider)
    if name == "custom":
        from services.llm import custom
        return custom.load(settings.with_(provider="custom"))
    adapter = ADAPTERS.get(name)
    if adapter is None:
        raise LLMError(CONFIG, f"Unknown model provider {settings.provider!r}.", provider=name,
                       remedy="PQC_LLM_PROVIDER must be one of: " + ", ".join(sorted(ADAPTERS) + ["custom"]) + ".")
    return adapter(settings.with_(provider=name))


def settings_for(org_id: str = "") -> Tuple[Settings, List[str]]:
    """Resolved settings for this organization, plus any notes worth showing.

    PQC_LLM_DISABLED short-circuits before the organization is consulted, which
    is what makes it impossible to override per tenant.
    """
    notes: List[str] = []
    provider, source = config.env_provider()
    base = config.from_environment(provider, source)
    if source == "disabled":
        notes.append("PQC_LLM_DISABLED=1: the built-in answerer is forced for this deployment "
                     "and cannot be overridden per organization.")
        return base.with_(organization_id=str(org_id or "")), notes
    if not org_id:
        return base.with_(organization_id=""), notes
    override: Optional[Dict[str, Any]] = None
    try:
        from services.llm import org_config
        override = org_config.load(org_id)
    except Exception:
        notes.append("This organization's provider override could not be read; the deployment's "
                     "own settings are in use.")
    if override:
        notes.append("This organization supplies its own provider and credential.")
        return config.merge_org(base, override), notes
    return base.with_(organization_id=str(org_id or "")), notes


def resolve(org_id: str = "") -> Tuple[Provider, List[str]]:
    """The provider to use, and the notes an operator should see.

    Never raises: a misconfiguration degrades to the built-in answerer with the
    reason in the notes, because an assistant that says why it is answering
    from rules is more useful than a 500.
    """
    settings, notes = settings_for(org_id)
    try:
        provider = build(settings)
    except LLMError as exc:
        notes.append(exc.operator_text())
        return BuiltinProvider(Settings(provider="builtin", source="default",
                                        organization_id=str(org_id or ""))), notes
    check = provider.check()
    if not check.get("ready") and provider.id != "builtin":
        notes.append(f"{provider.id} is selected but not fully configured ({check.get('detail')}); "
                     "the built-in answerer answers until it is.")
        return BuiltinProvider(Settings(provider="builtin", source="default",
                                        organization_id=str(org_id or ""))), notes
    return provider, notes


def describe(org_id: str = "") -> Dict[str, Any]:
    """Operator-facing description of the active provider. Contains no credential."""
    from services.llm import usage as usage_log

    provider, notes = resolve(org_id)
    settings, _ = settings_for(org_id)
    selected = config.normalise(settings.provider)
    return {
        "active": provider.describe(),
        "selected": selected,
        "selected_is_active": selected == provider.id,
        "disabled": config.disabled(),
        "precedence": PRECEDENCE,
        "notes": notes,
        "available": sorted(list(ADAPTERS) + ["custom"]),
        "organization_id": str(org_id or ""),
        "usage": {"recent": usage_log.recent(org_id, 10), "totals": usage_log.totals(org_id)},
    }


def capability_matrix() -> List[Dict[str, Any]]:
    """What every shipped adapter supports, at its defaults. No network, no keys."""
    rows: List[Dict[str, Any]] = []
    for name, adapter in sorted(ADAPTERS.items()):
        caps = adapter(Settings(provider=name)).capabilities()
        rows.append({"provider": name, "default_model": caps.model, "tools": caps.tools,
                     "streaming": caps.streaming, "context_window": caps.context_window,
                     "system_prompt": caps.system_prompt, "network": caps.network,
                     "usage_reported": caps.usage_reported, "notes": caps.notes})
    rows.append({"provider": "custom", "default_model": "declared by your module", "tools": "your choice",
                 "streaming": "your choice", "context_window": "your choice",
                 "system_prompt": "your choice", "network": "your choice", "usage_reported": "your choice",
                 "notes": "PQC_LLM_CUSTOM_MODULE=my_package.my_module; see examples/custom_llm_provider.py"})
    return rows


PRECEDENCE = [
    "PQC_LLM_DISABLED=1 forces the built-in answerer and cannot be overridden per organization",
    "the organization's stored provider override",
    "PQC_LLM_PROVIDER",
    "ANTHROPIC_API_KEY if set, else OPENAI_API_KEY, else the built-in answerer",
]
