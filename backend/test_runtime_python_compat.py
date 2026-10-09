"""Guard against annotations that work on the dev interpreter but crash the production image.

The Docker image runs Python 3.11 (see backend/Dockerfile). Python 3.14 evaluates annotations
lazily (PEP 649), so a missing `typing` import in an annotation is completely invisible to a
developer running 3.14 — while 3.11 evaluates function and class annotations eagerly at definition
time and raises NameError on import.

That is not a hypothetical: `services/knowledge_base.py` used `Optional[str]` without importing it,
which passed every local test and made the container exit during startup with
`NameError: name 'Optional' is not defined` — the application could not start in its own image.

This test reproduces 3.11's eager evaluation statically, so it fails on any interpreter.
"""
from __future__ import annotations

import ast
import builtins
import pathlib

BUILTIN_NAMES = set(dir(builtins))
SKIP_DIRS = {".venv", "node_modules", "__pycache__", "build", "dist", ".git"}
BACKEND_ROOT = pathlib.Path(__file__).resolve().parent


def _module_files() -> list[pathlib.Path]:
    return [
        path
        for path in sorted(BACKEND_ROOT.rglob("*.py"))
        if not any(part in SKIP_DIRS for part in path.parts)
    ]


def _has_future_annotations(tree: ast.Module) -> bool:
    """True when the module opts into PEP 563, making annotations strings on every version."""
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )


def _binding_lines(tree: ast.Module) -> dict[str, int]:
    """Map each bound name to the earliest line that binds it.

    Position matters. An import placed *after* the function that uses it in an annotation does not
    help: Python 3.11 evaluates the annotation when it reaches the `def`, which is earlier. That is
    precisely how the knowledge_base bug survived review -- the module did import `Optional`, 47
    lines below the function whose signature needed it -- so a check that ignores order misses the
    only real instance in this codebase.
    """
    earliest: dict[str, int] = {}

    def note(name: str, lineno: int) -> None:
        if name not in earliest or lineno < earliest[name]:
            earliest[name] = lineno

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                note((alias.asname or alias.name).split(".")[0], node.lineno)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            note(node.name, node.lineno)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            note(node.id, node.lineno)
    return earliest


def _annotations_of(tree: ast.Module):
    """Yield (annotation_expr, description) for annotations Python 3.11 evaluates on import."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
                if arg.annotation is not None:
                    yield arg.annotation, f"argument {arg.arg!r} of {node.name}()"
            for special in (args.vararg, args.kwarg):
                if special is not None and special.annotation is not None:
                    yield special.annotation, f"argument {special.arg!r} of {node.name}()"
            if node.returns is not None:
                yield node.returns, f"return type of {node.name}()"
        elif isinstance(node, ast.AnnAssign):
            yield node.annotation, "variable annotation"


def test_annotations_do_not_reference_undefined_names():
    problems: list[str] = []

    for path in _module_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        except SyntaxError as exc:  # a parse failure is a separate, louder problem
            problems.append(f"{path.name}: could not parse: {exc}")
            continue
        if _has_future_annotations(tree):
            continue

        bound_at = _binding_lines(tree)
        for annotation, where in _annotations_of(tree):
            for name_node in ast.walk(annotation):
                if not isinstance(name_node, ast.Name):
                    continue
                if name_node.id in BUILTIN_NAMES:
                    continue
                bound_line = bound_at.get(name_node.id)
                if bound_line is not None and bound_line < name_node.lineno:
                    continue
                rel = path.relative_to(BACKEND_ROOT)
                detail = (
                    f"only bound at line {bound_line}, after this use"
                    if bound_line is not None
                    else "not imported or defined"
                )
                problems.append(
                    f"{rel}:{name_node.lineno}: {name_node.id!r} is {detail}, used in the {where}. "
                    f"Python 3.11 (the production image) evaluates this on import and raises "
                    f"NameError. Import it above this line, or add "
                    f"'from __future__ import annotations' to the module."
                )

    assert not problems, "annotations that would break the production image:\n" + "\n".join(problems)
