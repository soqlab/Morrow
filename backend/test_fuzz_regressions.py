"""Replay every minimized input in backend/fuzz/corpus/<target>/regressions/ through its check.

A file lands there when a fuzzer (Hypothesis or Atheris) found it crashing or hanging a parser;
the bug is fixed in the same change and this test keeps it fixed. It needs no Hypothesis.
"""

from __future__ import annotations

import pathlib

import pytest

from fuzz import atheris_targets

CORPUS = pathlib.Path(__file__).resolve().parent / "fuzz" / "corpus"
CASES = sorted(p for p in CORPUS.glob("*/regressions/*") if p.is_file())


def test_every_regression_target_has_a_check():
    targets = {p.parent.parent.name for p in CASES}
    assert targets <= set(atheris_targets.TARGETS), targets - set(atheris_targets.TARGETS)
    assert CASES, "no regression inputs found"


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parent.parent.name}/{p.name}")
def test_regression_input(path):
    atheris_targets.TARGETS[path.parent.parent.name](path.read_bytes())
