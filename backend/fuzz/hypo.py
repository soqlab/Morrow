"""Hypothesis settings and strategies shared by backend/test_fuzz_*.py.

Budget: each test names a small example count that keeps the normal pytest run quick and
deterministic (derandomize=True: a pull request sees the same inputs every time). The nightly
workflow sets MORROW_FUZZ_EXAMPLES, which replaces every count and turns derandomization off,
so each night explores new inputs.
"""

from __future__ import annotations

import os
import pathlib
from typing import Callable, List

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st

from fuzz.checks import mutate

CORPUS = pathlib.Path(__file__).resolve().parent / "corpus"
NIGHTLY_EXAMPLES = int(os.environ.get("MORROW_FUZZ_EXAMPLES", "0") or 0)


def fuzz_settings(ci_examples: int) -> Callable:
    return settings(
        max_examples=NIGHTLY_EXAMPLES or ci_examples,
        deadline=None,                       # checks.time_limit bounds each input instead
        derandomize=not NIGHTLY_EXAMPLES,
        database=None if not NIGHTLY_EXAMPLES else settings.default.database,
        suppress_health_check=list(HealthCheck),
        print_blob=True,
    )


def seed_files(target: str, regressions: bool = True) -> List[pathlib.Path]:
    """corpus/<target>/* and, unless regressions=False, corpus/<target>/regressions/*."""
    folder = CORPUS / target
    files = sorted(p for p in (folder.rglob("*") if regressions else folder.glob("*")) if p.is_file())
    if not files:
        raise FileNotFoundError(f"no seed corpus in {folder}")
    return files


def seeds(target: str, regressions: bool = True) -> List[bytes]:
    """Seed inputs for target (regressions included by default: they are good seeds)."""
    return [p.read_bytes() for p in seed_files(target, regressions)]


_OPS = st.lists(st.tuples(st.integers(0, 5), st.integers(0, 1 << 16), st.integers(0, 1 << 16)), max_size=8)


def mutated(seed_list: List[bytes]) -> st.SearchStrategy[bytes]:
    """A seed with up to eight byte-level mutations (overwrite, insert, delete, truncate, and
    16/32-bit length fields set to boundary values)."""
    return st.builds(mutate, st.sampled_from(seed_list), _OPS)


def byte_inputs(target: str, max_size: int = 4096) -> st.SearchStrategy[bytes]:
    return st.one_of(mutated(seeds(target)), st.binary(max_size=max_size))


def json_values(max_leaves: int = 30) -> st.SearchStrategy:
    """Arbitrary JSON values (bounded integers: JSON parsers refuse >4300-digit numbers)."""
    scalars = st.one_of(
        st.none(), st.booleans(), st.integers(-(2 ** 70), 2 ** 70),
        st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=40),
    )
    return st.recursive(
        scalars,
        lambda children: st.one_of(st.lists(children, max_size=5),
                                   st.dictionaries(st.text(max_size=12), children, max_size=5)),
        max_leaves=max_leaves,
    )
