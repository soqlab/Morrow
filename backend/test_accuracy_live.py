"""Opt-in live run of the public-endpoint accuracy suite (docs/ACCURACY.md).

Skipped unless MORROW_ACCURACY_LIVE=1: it opens real TLS and SSH handshakes to a few hundred
public hosts, so it never runs in the normal suite. The weekly workflow
(.github/workflows/accuracy.yml) calls accuracy/run_accuracy.py directly and only warns; this test
exists so a developer can run the same thing through pytest:

    MORROW_ACCURACY_LIVE=1 python -m pytest -m network test_accuracy_live.py -s
    MORROW_ACCURACY_LIVE=1 MORROW_ACCURACY_ONLY=github.com,www.google.com python -m pytest -m network test_accuracy_live.py -s

The assertion is deliberately loose (F1 floor 0.80 per attribute with at least 10 labelled
endpoints): an endpoint that changed its configuration since it was labelled is not a scanner bug.
"""
from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(os.environ.get("MORROW_ACCURACY_LIVE") != "1",
                       reason="live public-endpoint scan; set MORROW_ACCURACY_LIVE=1"),
]


def test_scanner_accuracy_against_public_endpoints(tmp_path):
    from accuracy import metrics as M
    from accuracy import run_accuracy

    rows = run_accuracy.load_dataset(only=os.environ.get("MORROW_ACCURACY_ONLY", ""))
    assert rows, "no endpoints selected"
    result = run_accuracy.run(rows, workers=int(os.environ.get("MORROW_ACCURACY_WORKERS", "4")))
    print("\n" + M.markdown_table(result["metrics"]))
    for miss in result["misses"]:
        print("MISS", miss)
    weak = [
        (proto, attr, m["f1"])
        for proto, attrs in result["metrics"].items()
        for attr, m in attrs.items()
        if m["n"] >= 10 and m["f1"] is not None and m["f1"] < 0.80
    ]
    assert not weak, weak
