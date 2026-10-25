"""Where the provider configuration comes from, and in what order.

Precedence, highest first:

  1. MORROW_LLM_DISABLED=1            -- the built-in answerer, always. A
                                      deployment that forbids external model
                                      calls sets this, and nothing below can
                                      override it.
  2. the organization's own override, if one is stored (see org_config.py)
  3. MORROW_LLM_PROVIDER              -- the operator's choice for the deployment
  4. today's behaviour             -- ANTHROPIC_API_KEY if set, else
                                      OPENAI_API_KEY, else the built-in
                                      answerer

Rule 4 is why an existing deployment that sets none of the MORROW_LLM_* variables
behaves exactly as it did before this layer existed.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from services.llm.base import Settings

#: Every adapter this build ships, by the name MORROW_LLM_PROVIDER takes.
PROVIDER_IDS = ("anthropic", "openai", "azure-openai", "gemini", "openai-compatible",
                "ollama", "builtin", "custom")

#: Spellings an operator is likely to try.
ALIASES = {
    "claude": "anthropic", "anthropic-api": "anthropic",
    "openai-api": "openai", "gpt": "openai",
    "azure": "azure-openai", "azureopenai": "azure-openai", "azure_openai": "azure-openai",
    "google": "gemini", "google-gemini": "gemini", "googleai": "gemini",
    "compatible": "openai-compatible", "openai_compatible": "openai-compatible",
    "oai-compatible": "openai-compatible", "local": "openai-compatible",
    "groq": "openai-compatible", "openrouter": "openai-compatible",
    "together": "openai-compatible", "vllm": "openai-compatible",
    "lmstudio": "openai-compatible", "lm-studio": "openai-compatible",
    "llamacpp": "openai-compatible", "llama-cpp": "openai-compatible",
    "none": "builtin", "off": "builtin", "rules": "builtin", "disabled": "builtin",
}

#: Header names an operator may not set: they belong to the transport, and a
#: newline in any value would be request splitting.
_FORBIDDEN_HEADERS = {"host", "content-length", "content-type", "connection",
                      "transfer-encoding", "accept-encoding"}

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _flag(name: str) -> Optional[bool]:
    raw = _env(name).lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return None


def _number(name: str, default: Optional[float], low: float, high: float) -> Optional[float]:
    raw = _env(name)
    if not raw:
        return default
    try:
        return max(low, min(high, float(raw)))
    except ValueError:
        return default


def _integer(name: str, default: Optional[int], low: int, high: int) -> Optional[int]:
    value = _number(name, None if default is None else float(default), float(low), float(high))
    return None if value is None else int(value)


def disabled() -> bool:
    """True when this deployment forbids any external model call."""
    return _flag("MORROW_LLM_DISABLED") is True


def normalise(name: str) -> str:
    """Map an operator's spelling onto a provider id. Unknown names pass through."""
    key = str(name or "").strip().lower().replace(" ", "")
    key = ALIASES.get(key, key)
    return key


def parse_headers(raw: str) -> Tuple[Dict[str, str], List[str]]:
    """Parse MORROW_LLM_HEADERS. Accepts a JSON object or `k=v,k=v`.

    Returns (headers, rejected names). Bad input is dropped with a name, never
    a value, so nothing a gateway token lives in reaches a log.
    """
    text = (raw or "").strip()
    if not text:
        return {}, []
    pairs: Dict[str, Any] = {}
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            return {}, ["<malformed JSON>"]
        if not isinstance(parsed, dict):
            return {}, ["<not a JSON object>"]
        pairs = parsed
    else:
        for item in text.split(","):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            pairs[key.strip()] = value.strip()
    headers: Dict[str, str] = {}
    rejected: List[str] = []
    for key, value in pairs.items():
        name = str(key).strip()
        text_value = "" if value is None else str(value)
        if (not name or name.lower() in _FORBIDDEN_HEADERS
                or any(char in name for char in "\r\n:") or any(char in text_value for char in "\r\n")):
            rejected.append(name or "<empty>")
            continue
        headers[name] = text_value
    return headers, rejected


def env_provider() -> Tuple[str, str]:
    """Which provider the environment selects, and why.

    Returns (provider_id, source) where source is one of "disabled",
    "environment" or "default".
    """
    if disabled():
        return "builtin", "disabled"
    chosen = _env("MORROW_LLM_PROVIDER")
    if chosen:
        return normalise(chosen), "environment"
    # Today's behaviour, preserved for deployments that set none of the above.
    if _env("ANTHROPIC_API_KEY"):
        return "anthropic", "default"
    if _env("OPENAI_API_KEY"):
        return "openai", "default"
    return "builtin", "default"


def _alias_base_url() -> str:
    """The base URL implied by naming a gateway directly.

    MORROW_LLM_PROVIDER=groq resolves to the openai-compatible adapter; there is no
    reason to also make the operator look up the URL. An explicit
    MORROW_LLM_BASE_URL always wins.
    """
    from services.llm.openai_compatible import KNOWN_ENDPOINTS

    raw = _env("MORROW_LLM_PROVIDER").lower().replace(" ", "").replace("_", "-")
    return KNOWN_ENDPOINTS.get(raw, "")


def _legacy(provider: str) -> Dict[str, Any]:
    """Provider-specific variables that predate this layer, still honoured."""
    if provider == "anthropic":
        return {"api_key": _env("ANTHROPIC_API_KEY"),
                "model": _env("ANTHROPIC_AGENT_MODEL"),
                "max_tokens": _integer("ANTHROPIC_AGENT_MAX_TOKENS", None, 256, 200_000),
                "timeout": _integer("AGENT_TIMEOUT", None, 1, 600)}
    if provider == "openai":
        return {"api_key": _env("OPENAI_API_KEY"),
                "model": _env("OPENAI_AGENT_MODEL") or _env("OPENAI_MODEL")}
    if provider in ("openai-compatible", "ollama", "azure-openai", "gemini", "custom"):
        # The customer-hosted destination variables the Data Control page already uses.
        return {"api_key": _env("MORROW_AI_LOCAL_API_KEY"),
                "base_url": _env("MORROW_AI_LOCAL_URL"),
                "model": _env("MORROW_AI_LOCAL_MODEL")}
    return {}


def from_environment(provider: str = "", source: str = "") -> Settings:
    """Resolve Settings for `provider` (or whichever the environment selects)."""
    if not provider:
        provider, source = env_provider()
    source = source or "environment"
    legacy = _legacy(provider)
    headers, _ = parse_headers(_env("MORROW_LLM_HEADERS"))
    return Settings(
        provider=provider,
        model=_env("MORROW_LLM_MODEL") or str(legacy.get("model") or ""),
        base_url=(_env("MORROW_LLM_BASE_URL") or _alias_base_url()
                  or str(legacy.get("base_url") or "")),
        api_key=_env("MORROW_LLM_API_KEY") or str(legacy.get("api_key") or ""),
        temperature=float(_number("MORROW_LLM_TEMPERATURE", 0.1, 0.0, 2.0) or 0.0),
        max_tokens=int(_integer("MORROW_LLM_MAX_TOKENS", legacy.get("max_tokens") or 3000, 256, 200_000) or 3000),
        timeout=int(_integer("MORROW_LLM_TIMEOUT", legacy.get("timeout") or 60, 1, 600) or 60),
        retries=int(_integer("MORROW_LLM_RETRIES", 2, 0, 5) or 0),
        headers=headers,
        api_version=_env("MORROW_LLM_API_VERSION"),
        deployment=_env("MORROW_LLM_AZURE_DEPLOYMENT"),
        custom_module=_env("MORROW_LLM_CUSTOM_MODULE"),
        context_window=_integer("MORROW_LLM_CONTEXT_WINDOW", None, 1024, 10_000_000),
        price_input_per_mtok=_number("MORROW_LLM_PRICE_INPUT_PER_MTOK", None, 0.0, 10_000.0),
        price_output_per_mtok=_number("MORROW_LLM_PRICE_OUTPUT_PER_MTOK", None, 0.0, 10_000.0),
        tools_supported=_flag("MORROW_LLM_TOOLS"),
        stream_supported=_flag("MORROW_LLM_STREAM"),
        source=source,
    )


#: Fields an organization may set for itself. `custom_module` is deliberately
#: absent: loading a tenant-supplied import path would let a customer choose
#: code this process runs.
ORG_FIELDS = ("provider", "model", "base_url", "api_key", "temperature", "max_tokens",
              "timeout", "headers", "api_version", "deployment", "context_window",
              "price_input_per_mtok", "price_output_per_mtok", "tools_supported",
              "stream_supported")


def merge_org(base: Settings, override: Optional[Dict[str, Any]]) -> Settings:
    """Apply an organization's stored override on top of environment Settings.

    A changed provider resets the environment's model, URL, key and deployment,
    because carrying an Anthropic key into, say, a Gemini override would send a
    credential to a destination it was never issued for.
    """
    if not override:
        return base
    provider = normalise(str(override.get("provider") or "")) or base.provider
    if provider == "custom":
        # An organization cannot name code for this process to import.
        provider = base.provider
    start = base if provider == base.provider else Settings(
        provider=provider, temperature=base.temperature, max_tokens=base.max_tokens,
        timeout=base.timeout, retries=base.retries, source=base.source)
    changes: Dict[str, Any] = {"provider": provider, "source": "organization",
                               "organization_id": str(override.get("organization_id") or base.organization_id or "")}
    for field in ORG_FIELDS:
        if field in ("provider",):
            continue
        value = override.get(field)
        if value in (None, ""):
            continue
        changes[field] = value
    if isinstance(changes.get("headers"), str):
        changes["headers"], _ = parse_headers(changes["headers"])
    if not isinstance(changes.get("headers", {}), dict):
        changes.pop("headers", None)
    return start.with_(**changes)
