"""Offline tests for the public-endpoint accuracy suite (backend/accuracy, docs/ACCURACY.md).

The live run is network-only (test_accuracy_live.py). These pin the two things that must hold for
its numbers to mean anything, and that can be checked without a network:

  * the scoring arithmetic -- precision, recall and F1 per attribute, with "no answer" counted as a
    miss, never as a pass;
  * the dataset -- every label says how and when it was obtained, by a reference tool that is not
    Morrow, and the dataset stays a few hundred public endpoints.
"""
from __future__ import annotations

import json
import os

import pytest

from accuracy import metrics as M

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "accuracy", "endpoints.jsonl")


def _tls_row(id_, truth, pred):
    base_t = {a: None for a, _ in M.TLS_ATTRIBUTES}
    base_p = {a: None for a, _ in M.TLS_ATTRIBUTES}
    base_t.update(truth)
    base_p.update(pred)
    return {"id": id_, "protocol": "tls", "truth": base_t, "pred": base_p}


def test_binary_precision_recall_and_f1():
    rows = [
        _tls_row("a", {"pq_hybrid": True}, {"pq_hybrid": True}),     # TP
        _tls_row("b", {"pq_hybrid": True}, {"pq_hybrid": False}),    # FN
        _tls_row("c", {"pq_hybrid": False}, {"pq_hybrid": True}),    # FP
        _tls_row("d", {"pq_hybrid": False}, {"pq_hybrid": False}),   # TN
        _tls_row("e", {"pq_hybrid": True}, {"pq_hybrid": True}),     # TP
    ]
    m = M.score(rows)["metrics"]["tls"]["pq_hybrid"]
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 1)
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["f1"] == pytest.approx(2 / 3, abs=1e-4)


def test_no_answer_on_a_positive_is_a_miss_not_a_pass():
    """A scanner that says nothing must not score better than one that answers wrongly."""
    rows = [_tls_row("a", {"pq_hybrid": True}, {"pq_hybrid": None})]
    out = M.score(rows)
    m = out["metrics"]["tls"]["pq_hybrid"]
    assert m["recall"] == 0.0 and m["no_answer"] == 1
    assert out["misses"] == [{"id": "a", "protocol": "tls", "attribute": "pq_hybrid", "label": True, "morrow": None}]


def test_unknown_label_is_excluded_rather_than_guessed():
    rows = [_tls_row("a", {"offers_TLSv1.0": None}, {"offers_TLSv1.0": True})]
    m = M.score(rows)["metrics"]["tls"]["offers_TLSv1.0"]
    assert m["n"] == 0 and m["precision"] is None


def test_value_attribute_precision_counts_only_answers_recall_counts_all():
    rows = [
        _tls_row("a", {"cert_key_type": "EC"}, {"cert_key_type": "EC"}),
        _tls_row("b", {"cert_key_type": "RSA"}, {"cert_key_type": "EC"}),
        _tls_row("c", {"cert_key_type": "RSA"}, {"cert_key_type": None}),
    ]
    m = M.score(rows)["metrics"]["tls"]["cert_key_type"]
    assert m["precision"] == 0.5          # 1 of 2 answers right
    assert m["recall"] == pytest.approx(1 / 3, abs=1e-4)   # 1 of 3 labelled right


def test_signature_names_compare_across_openssl_and_cryptography_spellings():
    assert M.norm_sig("ecdsa-with-SHA256") == M.norm_sig("ECDSA-with-SHA256")
    assert M.norm_sig("rsassaPss") == M.norm_sig("RSASSA-PSS")
    assert M.norm_sig("sha256WithRSAEncryption") != M.norm_sig("sha384WithRSAEncryption")
    assert M.norm_sig("") is None


def test_tls_prediction_maps_scanner_fields():
    facts = {
        "scan_status": "ok",
        "tls_supported_versions": ["TLSv1.2", "TLSv1.3"],
        "tls_support_map": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
        "key_exchange_observed": True, "key_exchange_family": "pq_hybrid",
        "key_type": "EC", "key_bits": 256, "sig_algorithm": "ecdsa-with-SHA256",
        "classical_crypto_dependency": True, "harvest_now_decrypt_later_risk": "high",
    }
    p = M.tls_prediction(facts)
    assert p["offers_TLSv1.0"] is False and p["offers_TLSv1.3"] is True
    assert p["pq_hybrid"] is True
    assert (p["cert_key_type"], p["cert_key_bits"]) == ("EC", 256)
    assert p["cert_quantum_vulnerable"] is True and p["hndl_vulnerable"] is True


def test_tls_prediction_of_a_failed_scan_is_no_answer():
    p = M.tls_prediction({"scan_status": "timeout", "harvest_now_decrypt_later_risk": "unknown",
                          "key_exchange_observed": False})
    assert p["cert_key_type"] is None and p["pq_hybrid"] is None and p["hndl_vulnerable"] is None
    assert p["offers_TLSv1.2"] is None


def test_ssh_prediction_reads_findings():
    res = {"error": None, "pq_ready": False, "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha1"],
           "host_key_algorithms": ["ssh-ed25519"],
           "findings": [{"rule_id": "SSH_CRITICAL_KEX"}, {"rule_id": "SSH_NO_MORROW_KEX"},
                        {"rule_id": "SSH_QUANTUM_VULNERABLE_HOST_KEY"}]}
    p = M.ssh_prediction(res)
    assert p["sha1_kex_offered"] and p["hndl_vulnerable"] and p["hostkey_quantum_vulnerable"]
    assert p["pq_hybrid"] is False
    assert M.ssh_prediction({"error": "timed out"})["pq_hybrid"] is None


def test_markdown_table_lists_every_attribute():
    rows = [_tls_row("a", {"pq_hybrid": True, "cert_key_type": "EC"}, {"pq_hybrid": True, "cert_key_type": "EC"})]
    table = M.markdown_table(M.score(rows)["metrics"])
    assert "`pq_hybrid`" in table and "`cert_key_type`" in table and "100.0%" in table


def test_label_drift_reports_endpoints_that_changed_not_ones_that_did_not():
    def rec(pq, versions, reachable=True):
        return {"id": "tls:x:443", "protocol": "tls", "reachable": reachable,
                "labels": {"pq_hybrid": pq, "tls_versions": versions}}
    v = {"TLSv1.2": True, "TLSv1.3": True}
    assert M.label_drift([rec(False, v)], [rec(False, v)]) == []
    drift = M.label_drift([rec(False, v)], [rec(True, v)])
    assert drift == [{"id": "tls:x:443", "attribute": "pq_hybrid", "was": False, "now": True}]
    assert M.label_drift([rec(False, v)], [rec(None, {}, reachable=False)])[0]["attribute"] == "reachable"


def test_hosts_of_one_site_are_never_scanned_in_parallel():
    from accuracy.run_accuracy import site_key
    assert site_key("rsa2048.badssl.com") == site_key("expired.badssl.com") == "badssl.com"
    assert site_key("www.bbc.co.uk") == "bbc.co.uk"
    assert site_key("www.google.com") != site_key("www.google.de")


def test_only_scanning_host_failures_count_as_environment():
    from accuracy.run_accuracy import environment_failure
    assert environment_failure({"error": "[Errno -3] Temporary failure in name resolution"})
    assert environment_failure({"tls_probe_errors": {"TLSv1.3": "[Errno 101] Network is unreachable"}})
    # A timeout or a TLS alert is a result, not an outage on our side.
    assert not environment_failure({"error": "_ssl.c:999: The handshake operation timed out"})
    assert not environment_failure({"error": "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure"})


def test_rescoring_a_kept_scan_reproduces_its_prediction():
    """--rescan-from rescores from the fields a results file keeps; that must equal scoring the
    original scan, including for files written before tls_support_map was kept."""
    from accuracy.run_accuracy import _KEEP_TLS, scans_from_result
    facts = {"scan_status": "ok", "tls_supported_versions": ["TLSv1.2", "TLSv1.3"],
             "tls_support_map": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
             "tls_probe_errors": {"TLSv1.0": "alert"}, "key_type": "RSA", "key_bits": 2048,
             "key_exchange_observed": True, "key_exchange_family": "classical",
             "harvest_now_decrypt_later_risk": "high", "classical_crypto_dependency": True}
    kept = {k: facts.get(k) for k in _KEEP_TLS if k != "tls_support_map"}
    rescored = scans_from_result({"endpoints": [{"id": "tls:x:443", "morrow": kept}]})["tls:x:443"]
    assert M.tls_prediction(rescored) == M.tls_prediction(facts)


# ── The dataset itself ───────────────────────────────────────────────────────────────────────

def _dataset():
    if not os.path.exists(DATASET):
        pytest.skip("accuracy/endpoints.jsonl not present")
    with open(DATASET, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def test_every_label_records_its_reference_tool_and_date():
    for r in _dataset():
        assert r["label_source"].startswith(("OpenSSL 3.", "OpenSSH_")), r["id"]
        assert "morrow" not in r["label_source"].lower(), r["id"]
        assert r["labelled_at"].endswith("Z") and r["labelled_at"][:2] == "20", r["id"]
        if r["reachable"]:
            assert r["evidence"], r["id"]


def test_openssl_reference_is_new_enough_to_offer_ml_kem():
    """X25519MLKEM768 first shipped in OpenSSL 3.5. An older reference cannot label pq_hybrid."""
    for r in _dataset():
        if r["protocol"] == "tls":
            major, minor = r["label_source"].split()[1].split(".")[:2]
            assert (int(major), int(minor)) >= (3, 5), r["id"]


def test_dataset_is_a_few_hundred_public_endpoints_across_categories():
    rows = [r for r in _dataset() if r["reachable"]]
    assert 200 <= len(rows) <= 500, len(rows)
    cats = {r["category"] for r in rows}
    for needed in ("pq_hybrid", "tls13_classical", "tls12_only", "legacy_tls10_11", "ssh_pq_hybrid"):
        assert needed in cats, needed
    key_types = {r["labels"].get("cert_key_type") for r in rows if r["protocol"] == "tls"}
    assert {"RSA", "EC"} <= key_types
    ids = [r["id"] for r in _dataset()]
    assert len(ids) == len(set(ids))
