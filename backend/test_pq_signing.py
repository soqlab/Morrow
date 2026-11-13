"""Post-quantum signing for customers (services/pq_signing*.py, routers/pq_signing.py, tools/morrow_sign).

Runs the real ASGI stack with JWT auth required (the fixture from test_invite_landing, which also
refuses every real network connection). The customer's side is the real morrow-sign code: keys are
made and files signed with it, and its HTTP calls are routed into the same test client.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from test_invite_landing import PASSWORD, api_fixture  # noqa: F401  (api_fixture registers the "api" fixture)

from services import domain_verification as dv
from services import pq_signing as store
from services import pq_signing_format as fmt

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "tools" / "morrow_sign"))
from morrow_sign import cli as sign_cli  # noqa: E402
from morrow_sign import core as sign_core  # noqa: E402

KAT = json.loads((ROOT / "fixtures" / "acvp" / "ml_dsa_65_fips204.json").read_text(encoding="utf-8"))
BUNDLE = ROOT / "static" / "vendor" / "morrow-pq-verify.js"
DOMAIN = "acme.example"
ORG = "org-acme"


# ── NIST ACVP vectors ────────────────────────────────────────────────────────

def test_ml_dsa_65_key_generation_matches_the_nist_acvp_vectors():
    from cryptography.hazmat.primitives.asymmetric import mldsa

    assert KAT["keyGen"]["tests"]
    for case in KAT["keyGen"]["tests"]:
        key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(case["seed"]))
        assert key.public_key().public_bytes_raw().hex().upper() == case["pk"].upper(), case["tcId"]


def test_ml_dsa_65_verification_matches_the_nist_acvp_vectors():
    """External interface, pure ML-DSA, with a context string: exactly how signatures are checked here."""
    outcomes = set()
    for case in KAT["sigVer"]["tests"]:
        message = bytes.fromhex(case["message"])
        context = bytes.fromhex(case["context"])
        ok, _ = fmt.verify_pair(bytes.fromhex(case["pk"]), bytes(32), message, context,
                                bytes.fromhex(case["signature"]), bytes(64))
        assert ok is case["testPassed"], (case["tcId"], case["reason"])
        outcomes.add(ok)
    assert outcomes == {True, False}   # the set has both valid signatures and every kind of tampering


# ── formats ──────────────────────────────────────────────────────────────────

def test_the_statement_bytes_are_fixed_and_the_same_in_the_cli():
    args = (DOMAIN, "mk-" + "0" * 32, "file", "app 1.0.tar.gz", 12, "a" * 128, "2026-11-13T10:00:00Z")
    expected = (b"morrow-signature/1\ndomain acme.example\nkey mk-00000000000000000000000000000000\ntype file\n"
                b"name app 1.0.tar.gz\nsize 12\nsha512 " + b"a" * 128 + b"\nsigned-at 2026-11-13T10:00:00Z\n")
    assert fmt.statement_bytes(*args) == expected
    assert sign_core.statement_bytes(*args) == expected
    entries = [{"path": "index.html", "size": 3, "sha512": "b" * 128}, {"path": "a b/ü.css", "size": 0, "sha512": "c" * 128}]
    assert fmt.manifest_bytes(entries) == sign_core.manifest_bytes(entries)
    assert fmt.parse_manifest(fmt.manifest_bytes(entries), 10) == entries


@pytest.mark.parametrize("name", ["evil\nsize 1", "a‮b", " lead", "", "x" * 256])
def test_names_that_could_forge_a_line_or_mislead_are_refused(tmp_path, name):
    private, _ = sign_core.generate(DOMAIN)
    doc = dict(sign_core.SigningKey(private).sign("file", "ok.bin", 1, "a" * 128), name=name)
    with pytest.raises(fmt.FormatError):
        fmt.parse_signature(doc)


@pytest.mark.parametrize("path", ["/etc/passwd", "../x", "a/../b", "a//b", "a\\b", "a/./b", "dir/"])
def test_manifest_paths_are_relative_and_plain(path):
    with pytest.raises(fmt.FormatError):
        fmt.clean_entries([{"path": path, "size": 1, "sha512": "a" * 128}], 10)


def test_a_public_key_needs_a_proof_of_possession():
    _, public = sign_core.generate(DOMAIN)
    assert fmt.parse_public_key(public)["key"] == public["key"]
    _, other = sign_core.generate(DOMAIN)
    forged = dict(public, proof=other["proof"])
    with pytest.raises(fmt.FormatError, match="proof of possession"):
        fmt.parse_public_key(forged)
    moved = dict(public, domain="other.example")
    with pytest.raises(fmt.FormatError):
        fmt.parse_public_key(moved)


def test_the_key_id_is_derived_from_both_public_keys():
    _, public = sign_core.generate(DOMAIN)
    with pytest.raises(fmt.FormatError, match="key id"):
        fmt.parse_public_key(dict(public, key="mk-" + "1" * 32))


def test_both_signatures_must_verify():
    private, public = sign_core.generate(DOMAIN)
    key = sign_core.SigningKey(private)
    sig = fmt.parse_signature(key.sign("file", "a.bin", 3, "a" * 128))
    ml = fmt.unb64(public["ml_dsa_65"], fmt.ML_DSA_65_PUBLIC_KEY_BYTES, "k")
    ed = fmt.unb64(public["ed25519"], fmt.ED25519_PUBLIC_KEY_BYTES, "k")
    assert fmt.verify_signature(sig, ml, ed) == (True, True)
    other = fmt.parse_signature(key.sign("file", "b.bin", 3, "a" * 128))
    mixed = dict(sig, ed25519=other["ed25519"])
    assert fmt.verify_signature(mixed, ml, ed) == (True, False)
    mixed = dict(sig, ml_dsa_65=other["ml_dsa_65"])
    assert fmt.verify_signature(mixed, ml, ed) == (False, True)


def test_an_encrypted_private_key_needs_its_passphrase():
    private, _ = sign_core.generate(DOMAIN, passphrase="correct horse")
    assert "secret" not in private and "ml_dsa_65_seed" not in json.dumps(private)
    with pytest.raises(sign_core.SignError, match="encrypted"):
        sign_core.SigningKey(private)
    with pytest.raises(sign_core.SignError, match="Wrong passphrase"):
        sign_core.SigningKey(private, "wrong")
    assert sign_core.SigningKey(private, "correct horse").key == private["key"]


# ── the service through the HTTP API ─────────────────────────────────────────

@pytest.fixture(name="signing")
def signing_fixture(api, monkeypatch, tmp_path):
    client, app = api
    monkeypatch.setattr(dv, "_ready", False)
    monkeypatch.setattr(store, "_ready", False)
    dv._cache.clear()
    records = {}
    monkeypatch.setattr(dv, "_txt_values", lambda name: records.get(name, []))

    def verify(org, domain):
        row = dv.add_domain(org, domain)
        records[row["record_name"]] = [row["record_value"]]
        assert dv.verify_domain(org, domain)["status"] == "verified"
        return row

    def bearer(email, org, role="admin"):
        with app._db() as db:
            app._issuer_create_user(db, email, PASSWORD, "", role, org)
        token = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
        return {"Authorization": "Bearer " + token}

    verify(ORG, DOMAIN)
    admin = bearer("admin@acme.example", ORG)
    ns = type("Signing", (), {})()
    ns.client, ns.app, ns.admin, ns.verify, ns.bearer, ns.records, ns.tmp = client, app, admin, verify, bearer, records, tmp_path
    yield ns
    dv._cache.clear()


def make_key(domain=DOMAIN):
    private, public = sign_core.generate(domain)
    return sign_core.SigningKey(private), public


def register(s, public, **extra):
    return s.client.post("/pq-signing/keys", headers=s.admin, json={"public_key": public, **extra})


def upload_key(s):
    res = s.client.post("/pq-signing/upload-keys", headers=s.admin, json={"name": "ci"})
    assert res.status_code == 200, res.text
    return {"Authorization": "Bearer " + res.json()["secret"]}


def sign_bytes(key, name, data, stamp=None):
    return key.sign("file", name, len(data), hashlib.sha512(data).hexdigest(), stamp)


def verdict(s, sig, data=None):
    body = {"signature": sig}
    if data is not None:
        body.update(sha512=hashlib.sha512(data).hexdigest(), size=len(data))
    res = s.client.post("/api/verify", json=body)
    assert res.status_code == 200, res.text
    return res.json()


def test_register_sign_upload_and_verify(signing):
    s = signing
    key, public = make_key()
    res = register(s, public, label="Release key")
    assert res.status_code == 200, res.text
    assert res.json()["key"]["state"]["status"] == "active"
    up = upload_key(s)
    data = b"release bytes"
    sig = sign_bytes(key, "app-1.0.tar.gz", data)
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sig})
    assert res.status_code == 201, res.text
    assert res.json()["verify_url"].endswith(f"/verify/{DOMAIN}?sha512={hashlib.sha512(data).hexdigest()}")
    again = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sig})
    assert again.status_code == 200 and again.json()["created"] is False     # a retried upload is not an error

    result = verdict(s, sig, data)
    assert result["valid"] and result["recorded"], result
    assert [c["check"] for c in result["checks"]] == ["file", "key", "domain", "ml_dsa_65", "ed25519", "key_status"]
    assert not verdict(s, sig, data + b"!")["valid"]

    record = s.client.get(f"/api/verify/{DOMAIN}").json()      # anonymous
    assert record["counts"]["active_keys"] == 1 and record["counts"]["total"] == 1
    assert record["signatures"][0]["document"]["ml_dsa_65"] == sig["ml_dsa_65"]
    assert "uploaded_by" not in record["signatures"][0]
    assert s.client.get(f"/api/verify/{DOMAIN}/lookup?sha512={sig['sha512']}").json()["signatures"]

    console = s.client.get("/pq-signing", headers=s.admin).json()
    assert console["summary"].startswith(f"1 active key for {DOMAIN}; 1 file signed this month; last signature ")
    assert console["upload_keys"][0]["scopes"] == ["sign"]


def test_the_public_pages_and_badge_need_no_account_and_carry_a_strict_policy(signing):
    s = signing
    page = s.client.get(f"/verify/{DOMAIN}")
    assert page.status_code == 200 and "verify.js" in page.text
    assert "script-src 'self';" in page.headers["content-security-policy"]
    assert "unsafe-inline" not in page.headers["content-security-policy"].split("style-src")[0]
    badge = s.client.get(f"/verify/{DOMAIN}/badge.svg")
    assert badge.status_code == 200 and badge.headers["content-type"].startswith("image/svg+xml")
    assert "no active key" in badge.text
    assert s.client.get("/verify").status_code == 200
    assert s.client.get("/api/verify/not a domain").status_code == 400


def test_an_upload_key_can_only_upload(signing):
    s = signing
    up = upload_key(s)
    assert s.client.get("/pq-signing", headers=up).status_code == 403
    assert s.client.post("/scans", headers=up, json={"targets": [DOMAIN]}).status_code == 403
    assert s.client.get("/assets", headers=up).status_code == 403
    _, public = make_key()
    assert s.client.post("/pq-signing/keys", headers=up, json={"public_key": public}).status_code == 403
    # Upload keys are made by a signed-in administrator, never by another API key.
    assert s.client.post("/pq-signing/upload-keys", headers=up, json={}).status_code == 403


def test_keys_only_for_a_domain_the_organization_verified_first_with_the_record_still_published(signing):
    s = signing
    _, public = make_key("other.example")
    res = register(s, public)
    assert res.status_code == 409 and "Verify other.example first" in res.json()["detail"]

    # Another organization verified acme.example later: it cannot register keys for it.
    s.verify("org-late", DOMAIN)
    late = s.bearer("admin@late.example", "org-late")
    _, public = make_key()
    res = s.client.post("/pq-signing/keys", headers=late, json={"public_key": public})
    assert res.status_code == 409 and "verified acme.example first" in res.json()["detail"]

    # The TXT record was taken down: refused, even though the table still says verified.
    s.records.clear()
    res = register(s, public)
    assert res.status_code == 409 and "no longer published" in res.json()["detail"]


def test_a_private_key_file_or_a_tampered_public_key_is_refused(signing):
    s = signing
    private, public = sign_core.generate(DOMAIN)
    assert register(s, private).status_code == 400
    _, other = sign_core.generate(DOMAIN)
    assert register(s, dict(public, proof=other["proof"])).status_code == 400


def test_rotation_retires_the_old_key_and_what_it_signed_stays_valid(signing):
    s = signing
    old, old_pub = make_key()
    assert register(s, old_pub).status_code == 200
    up = upload_key(s)
    data = b"v1"
    sig_v1 = sign_bytes(old, "app-1.tar.gz", data)
    assert s.client.post("/pq-signing/signatures", headers=up, json={"signature": sig_v1}).status_code == 201

    new, new_pub = make_key()
    res = register(s, new_pub, rotates=old.key)
    assert res.status_code == 200, res.text
    assert res.json()["retired"]["state"]["status"] == "retired"

    assert verdict(s, sig_v1, data)["valid"]
    later = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    late_sig = sign_bytes(old, "app-2.tar.gz", b"v2", later)
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": late_sig})
    assert res.status_code == 409 and "retired" in res.json()["detail"]
    result = verdict(s, late_sig, b"v2")
    assert not result["valid"] and result["reason"] == "Signed with a retired key."
    assert s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(new, "app-2.tar.gz", b"v2")}).status_code == 201
    # A retired key cannot come back.
    assert register(s, old_pub).status_code == 409


def test_revocation_keeps_only_what_was_recorded_before_the_compromise(signing):
    s = signing
    key, public = make_key()
    assert register(s, public).status_code == 200
    up = upload_key(s)
    recorded = sign_bytes(key, "early.bin", b"early")
    assert s.client.post("/pq-signing/signatures", headers=up, json={"signature": recorded}).status_code == 201
    unrecorded = sign_bytes(key, "never-uploaded.bin", b"x")
    assert verdict(s, unrecorded, b"x")["valid"]          # valid while the key is trusted, though not on the record
    time.sleep(1.1)                                       # times are kept to the second

    since = (datetime.now(timezone.utc) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{key.key}/revoke", headers=s.admin,
                        json={"note": "laptop stolen", "compromised_since": since})
    assert res.status_code == 400                         # in the future
    res = s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{key.key}/revoke", headers=s.admin, json={"note": ""})
    assert res.status_code == 400                         # a reason is required
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{key.key}/revoke", headers=s.admin,
                        json={"note": "laptop stolen", "compromised_since": now})
    assert res.status_code == 200, res.text
    state = res.json()["key"]["state"]
    assert state["status"] == "revoked" and state["revocation_note"] == "laptop stolen"

    # Recorded on Morrow before the compromise time: still valid.
    rec = verdict(s, recorded, b"early")
    assert rec["valid"] and rec["reason"] == "Valid: recorded before the key was revoked.", rec
    gone = verdict(s, unrecorded, b"x")
    assert not gone["valid"] and gone["reason"] == "The signing key was revoked."
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(key, "after.bin", b"y")})
    assert res.status_code == 409

    # Default: untrusted since registration, so even recorded signatures stop verifying.
    key2, public2 = make_key()
    assert register(s, public2).status_code == 200
    sig2 = sign_bytes(key2, "k2.bin", b"k2")
    assert s.client.post("/pq-signing/signatures", headers=up, json={"signature": sig2}).status_code == 201
    assert s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{key2.key}/revoke", headers=s.admin,
                         json={"note": "unsure"}).status_code == 200
    assert not verdict(s, sig2, b"k2")["valid"]


def test_a_withdrawn_signature_no_longer_verifies_and_stays_on_the_record(signing):
    s = signing
    key, public = make_key()
    assert register(s, public).status_code == 200
    up = upload_key(s)
    sig = sign_bytes(key, "bad-build.zip", b"oops")
    sig_id = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sig}).json()["signature"]["id"]
    assert s.client.post(f"/pq-signing/signatures/{sig_id}/withdraw", headers=s.admin, json={"note": ""}).status_code == 400
    res = s.client.post(f"/pq-signing/signatures/{sig_id}/withdraw", headers=s.admin, json={"note": "wrong commit"})
    assert res.status_code == 200
    assert s.client.post(f"/pq-signing/signatures/{sig_id}/withdraw", headers=s.admin, json={"note": "again"}).status_code == 409
    result = verdict(s, sig, b"oops")
    assert not result["valid"] and "withdrew" in result["reason"]
    listed = s.client.get(f"/api/verify/{DOMAIN}").json()["signatures"][0]
    assert listed["withdrawn"]["note"] == "wrong commit"


def test_uploads_are_checked_before_they_are_kept(signing):
    s = signing
    key, public = make_key()
    assert register(s, public).status_code == 200
    up = upload_key(s)
    sig = sign_bytes(key, "a.bin", b"a")
    bad = dict(sig, name="b.bin")                                # the statement changed, the signature did not
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": bad})
    assert res.status_code == 400 and "does not verify" in res.json()["detail"]
    future = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(key, "f.bin", b"f", future)})
    assert res.status_code == 400 and "future" in res.json()["detail"]
    stranger, _ = make_key()
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(stranger, "s.bin", b"s")})
    assert res.status_code == 404


def test_request_bodies_are_capped(signing):
    s = signing
    up = upload_key(s)
    huge = b'{"signature": "' + b"x" * (5 * 1024 * 1024) + b'"}'
    res = s.client.post("/pq-signing/signatures", headers={**up, "content-type": "application/json"}, content=huge)
    assert res.status_code == 413
    res = s.client.post("/api/verify", headers={"content-type": "application/json"}, content=b'{"a": "' + b"x" * 40000 + b'"}')
    assert res.status_code == 413


def test_the_daily_limit(signing, monkeypatch):
    s = signing
    monkeypatch.setenv("MORROW_PQ_SIGNING_DAILY_LIMIT", "1")
    key, public = make_key()
    assert register(s, public).status_code == 200
    up = upload_key(s)
    assert s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(key, "1", b"1")}).status_code == 201
    res = s.client.post("/pq-signing/signatures", headers=up, json={"signature": sign_bytes(key, "2", b"2")})
    assert res.status_code == 429 and res.headers.get("retry-after")


def test_key_changes_are_journaled_in_the_audit_log(signing):
    from db import list_audit_logs, reset_current_organization_id, set_current_organization_id

    s = signing
    old, old_pub = make_key()
    assert register(s, old_pub).status_code == 200
    new, new_pub = make_key()
    assert register(s, new_pub, rotates=old.key).status_code == 200
    assert s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{new.key}/revoke", headers=s.admin,
                         json={"note": "test"}).status_code == 200
    _, refused = make_key("other.example")
    assert register(s, refused).status_code == 409
    token = set_current_organization_id(ORG)
    try:
        entries = list_audit_logs(limit=500)
    finally:
        reset_current_organization_id(token)
    done = {(e["action"], e["decision"]) for e in entries if str(e["action"]).startswith("pq_signing.key")}
    assert {("pq_signing.key.register", "allow"), ("pq_signing.key.rotate", "allow"),
            ("pq_signing.key.revoke", "allow"), ("pq_signing.key.register", "deny")} <= done


def test_another_organization_cannot_touch_these_keys(signing):
    s = signing
    key, public = make_key()
    assert register(s, public).status_code == 200
    s.verify("org-other", "other.example")
    other = s.bearer("admin@other.example", "org-other")
    res = s.client.post(f"/pq-signing/domains/{DOMAIN}/keys/{key.key}/revoke", headers=other, json={"note": "x"})
    assert res.status_code == 404
    assert s.client.get("/pq-signing", headers=other).json()["keys"] == []


# ── the CLI end to end, against the same server ─────────────────────────────

def _route_cli(s, monkeypatch):
    def request(method, url, body=None, token=""):
        path = url.split("://", 1)[-1].split("/", 1)[1]
        headers = {"Authorization": "Bearer " + token} if token else {}
        res = s.client.request(method, "/" + path, json=body, headers=headers)
        if res.status_code >= 400:
            raise sign_core.SignError(f"Morrow answered {res.status_code}: {res.json().get('detail')}")
        return res.json()
    monkeypatch.setattr(sign_cli, "_request", request)


def test_the_cli_end_to_end(signing, monkeypatch, capsys):
    s = signing
    _route_cli(s, monkeypatch)
    monkeypatch.setenv("MORROW_SIGN_SERVER", "https://morrow.test")
    work = s.tmp / "work"
    work.mkdir()
    assert sign_cli.main(["keygen", "--domain", DOMAIN, "--dir", str(work), "--no-passphrase", "--json"]) == 0
    made = json.loads(capsys.readouterr().out)
    assert sign_cli.main(["register", made["public_key_file"]]) == 2           # no token
    admin_token = s.admin["Authorization"].split(" ", 1)[1]
    monkeypatch.setenv("MORROW_SIGN_TOKEN", admin_token)
    assert sign_cli.main(["register", made["private_key_file"]]) == 2          # never the private key
    assert sign_cli.main(["register", made["public_key_file"], "--label", "CLI key"]) == 0
    monkeypatch.setenv("MORROW_SIGN_UPLOAD_KEY", upload_key(s)["Authorization"].split(" ", 1)[1])

    artifact = work / "app-1.0.tar.gz"
    artifact.write_bytes(os.urandom(4096))
    assert sign_cli.main(["sign", str(artifact), "--key", made["private_key_file"], "--upload"]) == 0
    capsys.readouterr()
    assert sign_cli.main(["verify", str(artifact), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["recorded"] is True
    # Without the .morrow-sig: found on the record by its SHA-512.
    moved = work / "copy.tar.gz"
    shutil.copy(artifact, moved)
    assert sign_cli.main(["verify", str(moved), "--domain", DOMAIN, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["via"] == "public record"
    moved.write_bytes(b"tampered")
    assert sign_cli.main(["verify", str(moved), "--domain", DOMAIN]) == 1
    capsys.readouterr()

    site = work / "public"
    (site / "css").mkdir(parents=True)
    (site / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
    (site / "css" / "site.css").write_text("h1{}", encoding="utf-8")
    (site / ".env").write_text("SECRET=1", encoding="utf-8")                  # dot-files are never listed
    shutil.copy(made["private_key_file"], site / "oops.morrow-key")           # nor key files
    assert sign_cli.main(["sign-site", str(site), "--key", made["private_key_file"], "--upload", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["files"] == 2
    manifest = (site / "morrow-manifest.txt").read_text(encoding="utf-8")
    assert ".env" not in manifest and "morrow-key" not in manifest
    loose = work / "site.css"
    shutil.copy(site / "css" / "site.css", loose)
    assert sign_cli.main(["verify", str(loose), "--domain", DOMAIN, "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] and result["via"] == "site manifest, as css/site.css"
    assert sign_cli.main(["verify", str(artifact), "--public-key", made["public_key_file"]]) == 0


def test_the_signing_tables_are_append_only_and_tenant_isolated():
    from services import postgres_rls

    source = (ROOT / "services" / "pq_signing.py").read_text(encoding="utf-8")
    for table in store.TABLES:
        assert table in postgres_rls.ORG_SCOPED_TABLES
        assert postgres_rls.tenant_column(table) == "org_id"
        assert not re.search(rf"\b(UPDATE|DELETE\s+FROM)\s+{table}\b", source, re.I), table


def test_the_browser_verifier_agrees_with_the_server():
    """The vendored @noble/post-quantum bundle checks the NIST vectors and a morrow-sign signature."""
    node = shutil.which("node")
    if not node or not BUNDLE.exists():
        pytest.skip("node is not installed here")
    private, public = sign_core.generate(DOMAIN)
    sig = sign_core.SigningKey(private).sign("file", "ü app.bin", 7, "d" * 128)
    statement = fmt.statement_bytes(sig["domain"], sig["key"], sig["type"], sig["name"], sig["size"], sig["sha512"],
                                    sig["signed_at"])
    cases = [{"pk": c["pk"], "msg": c["message"], "ctx": c["context"], "sig": c["signature"], "ok": c["testPassed"]}
             for c in KAT["sigVer"]["tests"]]
    script = r"""
const fs = require("fs"), vm = require("vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const ctx = { TextEncoder, Uint8Array, crypto: globalThis.crypto };
ctx.globalThis = ctx; vm.createContext(ctx);
vm.runInContext(fs.readFileSync(input.bundle, "utf8"), ctx);
const hex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)));
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const P = ctx.MorrowPQ, out = { kat: [], hybrid: null };
for (const c of input.cases) out.kat.push(P.mlDsa65Verify(hex(c.sig), hex(c.msg), hex(c.pk), hex(c.ctx)) === c.ok);
const msg = Uint8Array.from(Buffer.from(input.statement, "base64"));
out.hybrid = [P.mlDsa65Verify(b64(input.sig.ml_dsa_65), msg, b64(input.pub.ml_dsa_65), new TextEncoder().encode("morrow-signature/1")),
              P.ed25519Verify(b64(input.sig.ed25519), msg, b64(input.pub.ed25519)),
              P.mlDsa65Verify(b64(input.sig.ml_dsa_65), msg, b64(input.pub.ml_dsa_65), new TextEncoder().encode("other"))];
const h = P.sha512Create(); h.update(new TextEncoder().encode("abc"));
out.sha512 = Buffer.from(h.digest()).toString("hex");
process.stdout.write(JSON.stringify(out));
"""
    payload = json.dumps({"bundle": str(BUNDLE), "cases": cases, "statement": fmt.b64(statement), "sig": sig, "pub": public})
    done = subprocess.run([node, "-e", script], input=payload, capture_output=True, text=True, timeout=120, encoding="utf-8")
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout)
    assert all(out["kat"]) and len(out["kat"]) == len(cases)
    assert out["hybrid"] == [True, True, False]
    assert out["sha512"] == hashlib.sha512(b"abc").hexdigest()
