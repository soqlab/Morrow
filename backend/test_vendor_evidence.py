"""Vendor evidence packs: only measured data and links, signatures that verify and cannot be replayed
across contexts, the board slide's deadline, the addendum's notice and version, the ZIP, the tickets
(GitHub link length, Jira CSV escaping), opted-out domains and no outbound calls. No network."""

import copy
import csv
import io
import json
import os
import re
import socket
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import board_slide, proof_signing, shelf_life, vendor_check
from services import make_safe as ms
from services import org_rate_limits as _limits
from services import public_check as _check
from services import public_grade as _grade
from services import vendor_evidence as ve

BASE = "https://morrow.test"
NOW = datetime(2026, 11, 19, 9, 30, 0, tzinfo=timezone.utc)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _reset():
    for mod in (_check, _grade, ms):
        mod._TABLES_READY.clear()
    vendor_check._ready = ""
    vendor_check._active.clear()
    proof_signing.reset_cache_for_tests()
    _limits.reset()


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "ve.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_ENABLED", "1")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.setattr(vendor_check, "kick", lambda report_id: False)
    monkeypatch.setattr(_grade, "check", lambda *a, **k: pytest.fail("a stored grade should have been reused"))
    _reset()
    yield
    _reset()


def _grade_result(domain, grade, when, group=None, versions=None, verified=True):
    pq = grade in ("A", "B")
    return {"domain": domain, "scanned_at": when, "cached": False, "grade": grade,
            "key_exchange": {"group": group or ("X25519MLKEM768" if pq else "x25519"), "post_quantum": pq},
            "exposure": {"recorded_traffic_at_risk": not pq, "decrypt_year_low": None if pq else 2035},
            "tls": {"versions": versions if versions is not None else {"1.0": False, "1.1": False, "1.2": True, "1.3": True},
                    "untested": []},
            "certificate": {"verified": verified, "issuer": "CN=Test CA"}, "forward_secrecy": True,
            "rubric_version": _grade.RUBRIC_VERSION, "server_software": "nginx", "summary": "private detail"}


def _registry_result(domain, when, group="x25519"):
    return {"domain": domain, "checked_at": when, "outcome": "ok", "verdict": {"status": "quantum_vulnerable"},
            "observed": {"reachable": True, "scan_status": "ok", "tls_version": "TLSv1.3", "cipher_name": "TLS_AES_128_GCM_SHA256",
                         "key_exchange": group, "key_exchange_family": "ecdh", "key_exchange_observed": True,
                         "certificate_verified": True, "certificate": {"key_type": "EC", "key_bits": 256}}}


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed():
    """Three vendors: payroll (F, RSA), crm (C, two checks and two registry observations), mail (A)."""
    recent = datetime.now(timezone.utc).replace(microsecond=0)
    _grade.store(_grade_result("payroll.example", "F", _iso(recent - timedelta(hours=2)), versions={"1.2": True, "1.3": False}))
    _grade.store(_grade_result("crm.example", "C", _iso(recent - timedelta(days=9))))
    _grade.store(_grade_result("crm.example", "C", _iso(recent - timedelta(hours=1))))
    _grade.store(_grade_result("mail.example", "A", _iso(recent - timedelta(hours=1))))
    _check.record_observation("crm.example", _registry_result("crm.example", _iso(recent - timedelta(days=30)), "secp256r1"))
    _check.record_observation("crm.example", _registry_result("crm.example", _iso(recent - timedelta(days=3))))
    made = vendor_check.create("payroll.example\ncrm.example\nmail.example", start=False)
    vendor_check.run(made["id"])
    return made, vendor_check.read(made["token"], BASE)


# ── only measured data and links ─────────────────────────────────────────────


def test_the_pack_holds_only_measured_data_and_links():
    _, report = seed()
    pack = ve.make_pack(report, "crm.example", BASE, now=NOW)
    doc = pack["envelope"]["document"]
    assert set(doc) == {"format", "domain", "status", "statement", "what_decides_it", "grade_checks",
                        "registry_observations", "registry_record", "deadline", "proposed_target_date", "addendum",
                        "method", "issued_at", "issuer", "signing_context", "signing_keys", "sends_nothing"}
    assert doc["format"] == ve.EVIDENCE_FORMAT and doc["domain"] == "crm.example"
    stored = _grade.history("crm.example", 10, detail=True)
    assert [c["checked_at"] for c in doc["grade_checks"]] == [s["scanned_at"] for s in stored]
    for c in doc["grade_checks"]:
        assert set(c) == {"check_id", "checked_at", "grade", "rubric_version", "key_exchange_group",
                          "post_quantum_key_exchange", "tls_versions_accepted", "tls_versions_refused",
                          "tls_versions_untested", "certificate_verified", "history_url"}
        assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", c["checked_at"])
        assert c["grade"] == "C" and c["key_exchange_group"] == "x25519" and c["rubric_version"] == _grade.RUBRIC_VERSION
        assert c["tls_versions_accepted"] == ["1.2", "1.3"] and c["tls_versions_refused"] == ["1.0", "1.1"]
        assert c["certificate_verified"] is True
        assert c["history_url"] == BASE + "/api/public/history/crm.example?detail=1"
    obs = doc["registry_observations"]
    assert len(obs) == 2 and obs[0]["observed_at"] > obs[1]["observed_at"]
    assert obs[0]["permalink"] == f"{BASE}/r/crm.example/at/{obs[0]['observation_id']}"
    assert obs[0]["key_exchange_group"] == "x25519" and obs[1]["key_exchange_group"] == "secp256r1"
    assert doc["method"]["about_scanner"] == BASE + "/about-scanner" and doc["method"]["method_url"] == ve.METHOD_URL
    assert doc["statement"].startswith("On ") and "crm.example negotiates x25519" in doc["statement"]
    # Nothing from the stored result that the pack does not list: no summaries, no server software.
    text = json.dumps(doc)
    assert "private detail" not in text and "nginx" not in text and "_result" not in text
    allowed = (BASE + "/", ve.METHOD_URL, "https://github.com/soqlab/shelf-life", decrypt_url())
    for url in re.findall(r"https?://[^\s\"',)]+", text):
        assert url.startswith(allowed), url


def decrypt_url():
    from services import decrypt_window

    return decrypt_window.EXPOSURE_SOURCE_URL


def test_the_payroll_pack_reads_its_measured_rsa_and_tls():
    _, report = seed()
    doc = ve.make_pack(report, "payroll.example", BASE, now=NOW)["envelope"]["document"]
    assert doc["what_decides_it"] == "RSA key exchange"
    assert doc["grade_checks"][0]["tls_versions_accepted"] == ["1.2"]
    assert doc["registry_observations"] == [] and doc["registry_record"] is None


# ── signatures ───────────────────────────────────────────────────────────────


def test_the_pack_is_signed_with_both_keys_and_verifies_against_the_published_keys():
    _, report = seed()
    env = ve.make_pack(report, "crm.example", BASE, now=NOW)["envelope"]
    assert env["format"] == ve.ENVELOPE_FORMAT
    assert {s["alg"] for s in env["signatures"]} == set(proof_signing.describe_algorithms())
    assert env["document"]["signing_context"] == "morrow.vendor-evidence.v1"
    assert ve.verify(env)["valid"] is True
    forged = copy.deepcopy(env)
    forged["document"]["grade_checks"][0]["grade"] = "A"
    assert ve.verify(forged)["valid"] is False


def test_a_signature_cannot_be_replayed_across_contexts():
    _, report = seed()
    env = ve.make_pack(report, "crm.example", BASE, now=NOW)["envelope"]
    keys = {k["kid"]: k for k in proof_signing.published_keys()["keys"]}
    message = proof_signing.canonical_bytes(env["document"])
    for sig in env["signatures"]:
        pub = keys[sig["kid"]]["public_key"]
        assert proof_signing.verify_signature(sig["alg"], pub, sig["signature"], message, context=ve.EVIDENCE_CONTEXT)
        assert not proof_signing.verify_signature(sig["alg"], pub, sig["signature"], message, context=ms.PROOF_CONTEXT)
        assert not proof_signing.verify_signature(sig["alg"], pub, sig["signature"], message)
    assert ms.verify_envelope(env)["valid"] is False  # an evidence pack is not a quantum-safe proof

    # And the other way: a real proof's signatures, carried over onto the same bytes, are no evidence.
    proof = ms.sign_document({"format": ve.EVIDENCE_FORMAT, "domain": "crm.example"}, proof_signing.active_key_set())
    assert ms.verify_envelope(dict(proof, document=dict(proof["document"], format=ms.PROOF_FORMAT)))["valid"] is False
    replay = {"format": ve.ENVELOPE_FORMAT, "document": proof["document"], "signatures": proof["signatures"]}
    assert ve.verify(replay)["valid"] is False
    for sig in proof["signatures"]:
        assert not proof_signing.verify_signature(sig["alg"], keys[sig["kid"]]["public_key"], sig["signature"],
                                                  proof_signing.canonical_bytes(proof["document"]), context=ve.EVIDENCE_CONTEXT)


def test_without_a_signing_key_the_pack_is_refused_honestly(monkeypatch):
    _, report = seed()

    def unavailable(create=True):
        raise proof_signing.SigningUnavailable("MORROW_VAULT_MASTER_KEY is not set")

    monkeypatch.setattr(proof_signing, "active_key_set", unavailable)
    with pytest.raises(ve.EvidenceError) as err:
        ve.make_pack(report, "crm.example", BASE, now=NOW)
    assert err.value.status_code == 503 and "cannot sign" in err.value.detail


# ── the deadline ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("data", [None, "", "not-sure", "health", "auth-secrets", "trade-secrets", "personal-data-general"])
def test_the_deadline_matches_the_board_slide_for_the_same_inputs(data):
    slide = board_slide.build("", [], [], [], [], [], data=data, now=NOW)["deadline"]
    mine = ve.deadline_for(data, NOW)
    for key in ("status", "value", "range", "label", "years", "crqc_low", "crqc_likely"):
        assert mine[key] == slide.get(key), key
    assert mine["basis"] == (slide["basis"] or {}).get("text")
    slide_sources = board_slide.build("", [], [], [], [], [], data=data, now=NOW)["sources"]
    assert any(s.startswith(mine["sources"][1].split(", dated")[0]) for s in slide_sources)
    assert mine["kind_of_data"]["assumed"] is (shelf_life.resolve_category(data, [c["id"] for c in shelf_life.public_payload()["categories"]]) is None)


def test_the_target_date_defaults_from_the_deadline_and_can_be_chosen():
    for cat in [c["id"] for c in shelf_life.public_payload()["categories"]]:
        dl = ve.deadline_for(cat, NOW)
        day, why, chosen = ve.target_date("", dl, NOW)
        assert not chosen
        if dl["status"] == "ahead":
            assert day == f"{dl['safe_by_low']}-01-01", cat
        else:
            assert day == (NOW + timedelta(days=ve.PASSED_DEADLINE_DAYS)).date().isoformat(), cat
    dl = ve.deadline_for(None, NOW)
    assert ve.target_date("2027-06-30", dl, NOW)[:3] == ("2027-06-30", "Chosen by you.", True)
    for bad in ("2020-01-01", "tomorrow", "2027-02-30", "2099-01-01"):
        with pytest.raises(ve.EvidenceError):
            ve.target_date(bad, dl, NOW)


# ── the addendum ─────────────────────────────────────────────────────────────


def test_the_addendum_carries_its_notice_and_version_and_claims_no_law():
    t = ve.addendum_template()
    assert t["version"] and re.match(r"^\d{4}-\d\d-\d\d$", t["date"])
    assert t["notice"] == "Template, not legal advice: have your lawyer review it before you use it."
    md = ve.addendum_markdown(["crm.example"], "2027-05-01", BASE)
    assert md.count(t["notice"]) == 2 and md.index(t["notice"]) < md.index("## 1.")
    assert f"Template version {t['version']}, {t['date']}." in md
    assert "X25519MLKEM768" in md and "FIPS 203" in md and "https://doi.org/10.6028/NIST.FIPS.203" in md
    assert "1 May 2027" in md and "crm.example" in md and BASE + "/crm.example" in md
    assert "{" not in md and "}" not in md  # every placeholder filled
    low = md.lower()
    for claim in ve.LEGAL_CLAIMS:
        assert claim not in low
    for word in ("gdpr", "hipaa", "nis2", "dora", "eu law", "united states", "uk law", "governed by the laws", "jurisdiction"):
        assert word not in low, word


def test_the_addendum_file_ships_in_the_image():
    """The root .dockerignore drops every data/ directory; the addendum must be let back in."""
    def keeps(path):
        with open(os.path.join(REPO_ROOT, ".dockerignore"), encoding="utf-8") as fh:
            patterns = [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
        keep, parts = True, path.split("/")
        candidates = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        for pattern in patterns:
            negate = pattern.startswith("!")
            pat = (pattern[1:] if negate else pattern).strip("/")
            rx = "^" + re.escape(pat).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
            if any(re.match(rx, c) for c in candidates):
                keep = negate
        return keep

    assert os.path.exists(ve.ADDENDUM_PATH)
    assert not keeps("backend/data/somewhere-else/x.db")
    assert keeps("backend/data/vendor_addendum.json"), "the image would leave the addendum out"


# ── the ZIP ──────────────────────────────────────────────────────────────────


def test_the_zip_for_one_vendor_has_the_right_files_and_they_verify():
    _, report = seed()
    pack = ve.make_pack(report, "crm.example", BASE, by="2027-05-01", now=NOW)
    zf = zipfile.ZipFile(io.BytesIO(ve.zip_one(pack, now=NOW)))
    assert zf.namelist() == list(ve.FILE_NAMES)
    assert ve.filename("crm.example", NOW) == "morrow-evidence-crm.example-2026-11-19.zip"
    doc = json.loads(zf.read("evidence.json"))
    sigs = json.loads(zf.read("evidence.signatures.json"))
    assert doc == pack["envelope"]["document"]
    assert ve.verify({"document": doc, "signatures": sigs["signatures"]},
                     json.loads(zf.read("morrow-proof-keys.json")))["valid"] is True
    import hashlib
    assert doc["addendum"]["sha256"] == hashlib.sha256(zf.read("addendum.md")).hexdigest()
    page = zf.read("evidence.html").decode("utf-8")
    assert "<script" not in page.lower() and "Template, not legal advice" in page and "prefers-color-scheme:dark" in page
    assert f"/r/crm.example/at/{doc['registry_observations'][0]['observation_id']}" in page
    assert "Subject: Post-quantum key exchange on crm.example" in zf.read("ask-your-vendor.txt").decode("utf-8")
    assert zf.read("ticket.md").decode("utf-8").startswith("# Ask crm.example for post-quantum key exchange")
    assert "Template, not legal advice" in zf.read("addendum.md").decode("utf-8")


def test_the_verifier_in_the_zip_checks_the_pack(tmp_path):
    import subprocess
    import sys

    _, report = seed()
    zf = zipfile.ZipFile(io.BytesIO(ve.zip_one(ve.make_pack(report, "crm.example", BASE, now=NOW), now=NOW)))
    zf.extractall(tmp_path)
    run = subprocess.run([sys.executable, "-I", "verify.py", "evidence.json", "evidence.signatures.json",
                          "morrow-proof-keys.json"], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0 and run.stdout.strip().endswith("verified"), run.stdout + run.stderr
    doc = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    doc["grade_checks"][0]["grade"] = "A"
    (tmp_path / "evidence.json").write_text(json.dumps(doc), encoding="utf-8")
    run = subprocess.run([sys.executable, "-I", "verify.py", "evidence.json", "evidence.signatures.json",
                          "morrow-proof-keys.json"], cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert run.returncode == 1 and "NOT verified" in run.stdout


def test_the_zip_for_all_vendors_is_worst_first_and_skips_the_safe_one():
    _, report = seed()
    out = ve.all_packs(report, BASE, now=NOW)
    assert [p["domain"] for p in out["packs"]] == ["payroll.example", "crm.example"]
    zf = zipfile.ZipFile(io.BytesIO(ve.zip_all(out["packs"], now=NOW)))
    names = zf.namelist()
    assert [n for n in names if "/" not in n] == ["jira.csv", "README.txt"]
    for d in ("payroll.example", "crm.example"):
        assert [n.split("/", 1)[1] for n in names if n.startswith(d + "/")] == list(ve.FILE_NAMES)
    assert not any(n.startswith("mail.example") for n in names)
    assert ve.filename(None, NOW, 2) == "morrow-evidence-2-vendors-2026-11-19.zip"


def test_a_safe_or_ungraded_vendor_gets_no_pack():
    _, report = seed()
    with pytest.raises(ve.EvidenceError) as safe:
        ve.make_pack(report, "mail.example", BASE, now=NOW)
    assert safe.value.status_code == 409
    with pytest.raises(ve.EvidenceError) as missing:
        ve.make_pack(report, "nobody.example", BASE, now=NOW)
    assert missing.value.status_code == 404
    # A newer check that saw post-quantum key exchange wins over the report's older row.
    _grade.store(_grade_result("crm.example", "A", _iso(datetime.now(timezone.utc) + timedelta(minutes=1))))
    with pytest.raises(ve.EvidenceError) as now_safe:
        ve.make_pack(report, "crm.example", BASE, now=NOW)
    assert now_safe.value.status_code == 409 and "nothing to ask for" in now_safe.value.detail


# ── tickets ──────────────────────────────────────────────────────────────────


def test_the_github_link_is_prefilled_and_stays_within_url_limits():
    _, report = seed()
    pack = ve.make_pack(report, "crm.example", BASE, now=NOW)
    url = ve.github_issue_url("acme/security", pack["ticket_title"], pack["ticket_body"])
    parsed = urlparse(url)
    assert parsed.scheme == "https" and parsed.netloc == "github.com" and parsed.path == "/acme/security/issues/new"
    q = parse_qs(parsed.query)
    assert q["title"] == [pack["ticket_title"]] and q["body"] == [pack["ticket_body"]]
    long = ve.github_issue_url("https://github.com/acme/security", "t" * 400, "ünïcode & 😀 " * 3000)
    assert len(long) <= ve.GITHUB_URL_MAX
    body = parse_qs(urlparse(long).query)["body"][0]
    assert body.endswith("The full text is ticket.md in the evidence pack.)") and len(parse_qs(urlparse(long).query)["title"][0]) == 250
    for bad in ("", "acme", "acme/sec/extra", "https://evil.example/acme/sec", "acme/../x y", "-acme/x"):
        with pytest.raises(ve.EvidenceError):
            ve.github_issue_url(bad, "t", "b")


def test_the_jira_csv_escapes_properly():
    _, report = seed()
    packs = ve.all_packs(report, BASE, now=NOW)["packs"]
    packs[0] = dict(packs[0], ticket_title='=HYPERLINK("http://x") "quoted", comma', ticket_body="line one\nline two, \"q\"\n@sum")
    body = ve.jira_csv(packs)
    rows = list(csv.reader(io.StringIO(body)))
    assert rows[0] == ["Summary", "Description", "Issue Type", "Labels", "Due Date"]
    assert rows[1][0] == '\'=HYPERLINK("http://x") "quoted", comma'
    assert rows[1][1] == "line one\nline two, \"q\"\n@sum"
    assert rows[1][2:] == ["Task", "post-quantum", packs[0]["envelope"]["document"]["proposed_target_date"]["date"]]
    assert len(rows) == 3 and rows[2][0].startswith("Ask crm.example")
    assert body.startswith('"Summary","Description"') and "\r\n" in body


# ── opt-outs and outbound calls ──────────────────────────────────────────────


def test_an_opted_out_domain_never_appears(monkeypatch):
    made, report = seed()
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS", "crm.example")
    with pytest.raises(ve.EvidenceError) as err:
        ve.make_pack(report, "crm.example", BASE, now=NOW)
    assert err.value.status_code == 404 and err.value.detail == "That vendor is not in this report."
    out = ve.all_packs(report, BASE, now=NOW)
    assert [p["domain"] for p in out["packs"]] == ["payroll.example"] and out["skipped"] == []
    blob = ve.zip_all(out["packs"], now=NOW)
    zf = zipfile.ZipFile(io.BytesIO(blob))
    for name in zf.namelist():
        assert b"crm.example" not in zf.read(name), name
    assert "crm.example" not in ve.jira_csv(out["packs"])


def test_the_routes_make_no_outbound_calls(monkeypatch):
    import app as application

    made, _ = seed()

    def refuse(*a, **k):
        raise AssertionError("an outbound connection was attempted")

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as client:
        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)
        api = "/api/public/vendors/report/" + made["token"]
        r = client.get(api + "/evidence/crm.example?data=health&by=2027-05-01")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["verified"]["valid"] is True and body["target_date"]["date"] == "2027-05-01"
        assert body["addendum"]["notice"].startswith("Template, not legal advice") and body["files"] == list(ve.FILE_NAMES)
        assert body["deadline"]["kind_of_data"]["category"] == "health-records"
        assert r.headers["cache-control"] == "no-store"
        z = client.get(api + "/evidence/crm.example.zip")
        assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
        assert 'filename="morrow-evidence-crm.example-' in z.headers["content-disposition"]
        assert zipfile.ZipFile(io.BytesIO(z.content)).namelist() == list(ve.FILE_NAMES)
        allz = client.get(api + "/evidence.zip")
        assert allz.status_code == 200 and "morrow-evidence-2-vendors-" in allz.headers["content-disposition"]
        t = client.get(api + "/tickets.csv")
        assert t.status_code == 200 and t.headers["content-type"].startswith("text/csv") and "Ask payroll.example" in t.text
        g = client.get(api + "/evidence/crm.example/github?repo=acme/security", follow_redirects=False)
        assert g.status_code == 303 and g.headers["location"].startswith("https://github.com/acme/security/issues/new?title=")
        assert client.get(api + "/evidence/crm.example/github?repo=nope", follow_redirects=False).status_code == 400
        assert client.get(api + "/evidence/mail.example").status_code == 409
        assert client.get(api + "/evidence/nobody.example").status_code == 404
        assert client.get(api + "/evidence/crm.example?by=2001-01-01").status_code == 400
        assert client.get("/api/public/vendors/report/not-a-real-token/evidence/crm.example").status_code == 404
        client.delete(api, headers={"x-manage-key": made["manage_key"]})
        assert client.get(api + "/evidence/crm.example").status_code == 410
