"""Token and cost records, so an operator can see what the assistant costs.

A bounded in-process ring per organization. It holds counts, not content: no
prompt, no completion, no tool arguments. Nothing here is authoritative
billing -- the provider's own invoice is -- and `cost_basis` says how each
number was reached so an estimate is never read as a charge.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

#: Records kept per organization.
DEPTH = 50

_lock = threading.Lock()
_records: Dict[str, Deque[Dict[str, Any]]] = defaultdict(lambda: deque(maxlen=DEPTH))


def record(org_id: str, provider: str, model: str, usage: Any, *, purpose: str = "assistant",
           latency_ms: int = 0, outcome: str = "ok", tools_used: int = 0) -> Dict[str, Any]:
    entry = {
        "at": time.time(), "provider": provider, "model": model, "purpose": purpose,
        "latency_ms": int(latency_ms or 0), "outcome": outcome, "tool_calls": int(tools_used or 0),
        **(usage.as_dict() if hasattr(usage, "as_dict") else dict(usage or {})),
    }
    with _lock:
        _records[str(org_id or "")].append(entry)
    return entry


def recent(org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
    with _lock:
        items = list(_records.get(str(org_id or ""), ()))
    return items[-max(1, min(DEPTH, limit)):][::-1]


def totals(org_id: str) -> Dict[str, Any]:
    """Summed counts over what is still in the ring, with the window's size."""
    items = recent(org_id, DEPTH)
    known_cost = [item["cost_usd"] for item in items if isinstance(item.get("cost_usd"), (int, float))]
    return {
        "requests": len(items),
        "input_tokens": sum(int(item.get("input_tokens") or 0) for item in items),
        "output_tokens": sum(int(item.get("output_tokens") or 0) for item in items),
        "cost_usd": round(sum(known_cost), 6) if known_cost else None,
        "cost_known_for": len(known_cost),
        "window": f"last {len(items)} request(s) in this process",
        "basis": "not billing; the provider's invoice is authoritative",
    }


def reset(org_id: Optional[str] = None) -> None:
    with _lock:
        if org_id is None:
            _records.clear()
        else:
            _records.pop(str(org_id), None)
