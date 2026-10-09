"""Bring your own provider, in code.

    PQC_LLM_PROVIDER=custom
    PQC_LLM_CUSTOM_MODULE=my_package.my_module

The module is imported by dotted path and must expose a provider. Three forms
are accepted, checked in this order:

  1. `get_provider(settings)` -- a factory returning a provider instance.
  2. `Provider` -- a class, instantiated with the resolved Settings.
  3. exactly one subclass of `services.llm.base.Provider` defined in the module.

Whatever comes back is validated before anything calls it: it must implement
`capabilities()`, `complete()`, `start()`, `add_assistant()` and
`add_tool_results()`, and `capabilities()` must return a `Capabilities`. Every
failure raises `LLMError(kind="config")` with a message naming what was wrong
and how to fix it -- a traceback out of an operator's own module is not an
error message.

See examples/custom_llm_provider.py for a file to copy.
"""

from __future__ import annotations

import importlib
import inspect
import re
from typing import Any, Dict, List

from services.llm.base import CONFIG, Capabilities, LLMError, Provider, Settings

#: A dotted import path, nothing else. Rejecting anything else keeps a stray
#: value out of importlib, which would otherwise happily import a package the
#: operator did not mean to name.
_MODULE_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")

REQUIRED = ("capabilities", "complete", "start", "add_assistant", "add_tool_results")


def _fail(message: str, remedy: str) -> "LLMError":
    return LLMError(CONFIG, message, provider="custom", remedy=remedy)


def load(settings: Settings) -> Provider:
    """Import and validate the operator's provider. Raises LLMError on any problem."""
    path = (settings.custom_module or "").strip()
    if not path:
        raise _fail("PQC_LLM_PROVIDER=custom needs a module to load.",
                    "Set PQC_LLM_CUSTOM_MODULE=my_package.my_module and see docs/AI_PROVIDERS.md.")
    if not _MODULE_PATH.match(path):
        raise _fail(f"PQC_LLM_CUSTOM_MODULE is not a dotted import path: {path!r}.",
                    "Use a module path such as my_package.my_module -- not a file name or a URL.")
    try:
        module = importlib.import_module(path)
    except ImportError as exc:
        raise _fail(f"Could not import PQC_LLM_CUSTOM_MODULE {path!r}: {exc.__class__.__name__}.",
                    "Make sure the module is on PYTHONPATH and imports cleanly on its own.") from None
    except Exception as exc:
        raise _fail(f"PQC_LLM_CUSTOM_MODULE {path!r} raised {exc.__class__.__name__} while importing.",
                    "Fix the error in your module; it must import without side effects that can fail.") from None

    instance = _instantiate(module, path, settings)
    validate(instance, path)
    return instance


def _instantiate(module: Any, path: str, settings: Settings) -> Any:
    factory = getattr(module, "get_provider", None)
    if callable(factory):
        try:
            return factory(settings)
        except Exception as exc:
            raise _fail(f"{path}.get_provider(settings) raised {exc.__class__.__name__}.",
                        "get_provider must return a provider instance for the given Settings.") from None

    declared = getattr(module, "Provider", None)
    # A module that does `from services.llm.base import Provider` binds that name
    # too; the abstract base is not a provider, and instantiating it raises.
    if (inspect.isclass(declared) and declared is not Provider
            and not inspect.isabstract(declared)):
        return _construct(declared, path, settings)

    subclasses = [value for value in vars(module).values()
                  if inspect.isclass(value) and issubclass(value, Provider) and value is not Provider]
    # A module that imports the adapters would otherwise look like it declares
    # several providers; only classes defined here count.
    local = [cls for cls in subclasses if getattr(cls, "__module__", "") == path]
    if len(local) == 1:
        return _construct(local[0], path, settings)
    if len(local) > 1:
        raise _fail(f"{path} defines {len(local)} providers: " + ", ".join(sorted(cls.__name__ for cls in local)) + ".",
                    "Expose the one to use as `get_provider(settings)` or name the class `Provider`.")
    raise _fail(f"{path} exposes no provider.",
                "Define get_provider(settings), or a class named Provider, or one subclass of "
                "services.llm.base.Provider. Copy examples/custom_llm_provider.py.")


def _construct(cls: Any, path: str, settings: Settings) -> Any:
    try:
        return cls(settings)
    except Exception as exc:
        raise _fail(f"{path}.{cls.__name__}(settings) raised {exc.__class__.__name__}.",
                    "The constructor takes one argument: the resolved Settings.") from None


def validate(instance: Any, path: str = "the custom module") -> None:
    """Check the loaded object against the interface. Raises LLMError."""
    if instance is None:
        raise _fail(f"{path} returned None instead of a provider.",
                    "get_provider(settings) must return a provider instance.")
    missing: List[str] = [name for name in REQUIRED if not callable(getattr(instance, name, None))]
    if missing:
        raise _fail(f"{path} is missing " + ", ".join(f"{name}()" for name in missing) + ".",
                    "Subclass services.llm.base.Provider, or implement the whole interface; "
                    "see examples/custom_llm_provider.py.")
    try:
        caps = instance.capabilities()
    except Exception as exc:
        raise _fail(f"{path}.capabilities() raised {exc.__class__.__name__}.",
                    "capabilities() must return a Capabilities without touching the network.") from None
    if not isinstance(caps, Capabilities):
        raise _fail(f"{path}.capabilities() returned {type(caps).__name__}, not Capabilities.",
                    "Return services.llm.base.Capabilities(provider=..., model=..., streaming=..., "
                    "tools=..., context_window=...).")
    if not str(caps.provider or "").strip():
        raise _fail(f"{path} declares no provider name in capabilities().",
                    "Set Capabilities(provider='my-provider', ...) so the console can name what answered.")
    if not str(caps.model or "").strip():
        raise _fail(f"{path} declares no model in capabilities().",
                    "Set Capabilities(model=...) so the console never misreports what answered.")


def describe_contract() -> Dict[str, Any]:
    """The contract, as data, for the console and the docs."""
    return {
        "env": {"PQC_LLM_PROVIDER": "custom", "PQC_LLM_CUSTOM_MODULE": "my_package.my_module"},
        "accepted_forms": ["get_provider(settings)", "class Provider", "one Provider subclass"],
        "required_methods": list(REQUIRED),
        "example": "examples/custom_llm_provider.py",
    }
