"""
Shared label for modelled, reference, and seed output.

Any response that carries figures the platform did not observe in the
customer's own environment adds a top-level ``model_basis`` object so the
console (and anyone reading the API) can tell a projection from a measurement:

    {
      "kind": "model" | "reference" | "seed",
      "summary": "<one plain sentence of what this is and is not>",
      "assumptions": ["..."],
      "sources": ["..."],
      "as_of": "YYYY-MM"
    }

kind:
  model     -- computed from stated assumptions; a scenario, not a forecast
  reference -- curated guidance or public facts, correct as of ``as_of``
  seed      -- starter records shipped with the product, not customer data
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

MODEL_BASIS_KINDS = ("model", "reference", "seed")


def model_basis(
    kind: str,
    summary: str,
    assumptions: Iterable[str] = (),
    sources: Iterable[str] = (),
    as_of: str = "",
) -> Dict[str, Any]:
    if kind not in MODEL_BASIS_KINDS:
        raise ValueError(f"model_basis kind must be one of {MODEL_BASIS_KINDS}, got {kind!r}")
    return {
        "kind": kind,
        "summary": str(summary),
        "assumptions": [str(a) for a in assumptions],
        "sources": [str(s) for s in sources],
        "as_of": str(as_of),
    }


def assumption_lines(table: Dict[Any, Any], fmt: str = "{key}: {value}") -> List[str]:
    """Flatten a small assumption table into short strings for ``assumptions``."""
    return [fmt.format(key=k, value=v) for k, v in table.items()]
