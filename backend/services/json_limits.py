"""JSON from untrusted request bodies, with a cap on nesting depth.

json.loads stops at the interpreter's recursion limit by raising RecursionError, which is not a
ValueError, so a body such as "[[[[..." escaped every handler that expected a parse error. A
document that loads just under that limit is no better: the code that walks it afterwards
(jsonschema validation, json.dumps, recursive flatteners) runs deeper in the stack and hits the
limit there instead. Rejecting anything nested deeper than a fixed, generous bound at load time
removes both failure modes and keeps every later walk shallow.
"""

from __future__ import annotations

import json
from typing import Any

#: Deeper than any CycloneDX BOM or log record in practice, far below the recursion limit.
DEFAULT_MAX_DEPTH = 64


class JSONTooDeep(ValueError):
    """The document nests arrays/objects deeper than the allowed depth."""


def check_depth(obj: Any, max_depth: int = DEFAULT_MAX_DEPTH) -> None:
    """Raise JSONTooDeep if obj nests containers more than max_depth levels (iteratively)."""
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > max_depth:
            raise JSONTooDeep(f"JSON nests deeper than {max_depth} levels")
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))


def loads(data: Any, max_depth: int = DEFAULT_MAX_DEPTH) -> Any:
    """json.loads that raises only ValueError (JSONDecodeError, UnicodeDecodeError, JSONTooDeep)."""
    try:
        obj = json.loads(data)
    except RecursionError:
        raise JSONTooDeep(f"JSON nests deeper than {max_depth} levels") from None
    check_depth(obj, max_depth)
    return obj
