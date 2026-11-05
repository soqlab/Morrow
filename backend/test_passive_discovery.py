"""Passive TLS discovery: per-format parsing, PQ classification, ingest tokens, isolation, limits."""

import gzip
import json
import os
import tempfile
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app
from db import get_asset, init_db, reset_current_organization_id, set_current_organization_id
from services import passive_discovery as pd
from services import passive_ingest

ORG_A = "00000000-0000-0000-0000-00000000000a"
ORG_B = "00000000-0000-0000-0000-00000000000b"

# ── Real-looking fixture lines ──────────────────────────────────────────────────────────────────

NGINX_JSON_PQ = ('{"time":"2026-11-05T10:00:01+00:00","remote_addr":"203.0.113.7","request":"GET /login?u=x HTTP/2.0",'
                 '"status":200,"ssl_server_name":"portal.example.com","server_port":"443","ssl_protocol":"TLSv1.3",'
                 '"ssl_cipher":"TLS_AES_256_GCM_SHA384","ssl_curve":"X25519MLKEM768"}')
NGINX_KV_CLASSICAL = ('203.0.113.9 - - [05/Nov/2026:10:00:02 +0000] "GET / HTTP/1.1" 200 512 host=api.example.com '
                      'port=443 ssl_protocol=TLSv1.3 ssl_cipher=TLS_AES_128_GCM_SHA256 ssl_curve=X25519')
NGINX_HEX_CURVE = ('{"ssl_server_name":"hex.example.com","server_port":"8443","ssl_protocol":"TLSv1.3",'
                   '"ssl_cipher":"TLS_AES_128_GCM_SHA256","ssl_curve":"0x11ec"}')
NGINX_COMBINED = '203.0.113.7 - - [05/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.5.0"'

ENVOY_JSON_PQ = ('{"start_time":"2026-11-05T10:00:03.120Z","method":"GET","path":"/v1/orders?id=9",'
                 '"response_code":200,"downstream_remote_address":"198.51.100.4:51234",'
                 '"requested_server_name":"orders.example.com","downstream_local_port":"443",'
                 '"downstream_tls_version":"TLSv1.3","downstream_tls_cipher":"TLS_AES_128_GCM_SHA256",'
                 '"downstream_tls_group":"SecP256r1MLKEM768"}')
ENVOY_JSON_TLS12 = ('{"requested_server_name":"legacy.example.com","downstream_local_address":"10.0.0.5:9443",'
                    '"downstream_tls_version":"TLSv1.2","downstream_tls_cipher":"ECDHE-RSA-AES128-GCM-SHA256",'
                    '"downstream_tls_group":"-"}')

HAPROXY_KV = ('<134>Nov  5 10:00:04 lb1 haproxy[2211]: 198.51.100.8:40112 [05/Nov/2026:10:00:04.001] fe_https~ '
              'be_app/app1 0/0/1/2/3 200 845 - - ---- 1/1/0/0/0 0/0 "GET /cart HTTP/1.1" '
              'sni=shop.example.com fp=443 sslv=TLSv1.3 sslc=TLS_AES_256_GCM_SHA384 curve=secp384r1')
HAPROXY_JSON_PQ = ('{"ssl_fc_sni":"pay.example.com","fp":443,"ssl_fc_protocol":"TLSv1.3",'
                   '"ssl_fc_cipher":"TLS_AES_256_GCM_SHA384","ssl_fc_curve":"X25519MLKEM768"}')

ALB_HTTPS = ('https 2026-11-05T10:00:05.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 '
             '10.0.0.1:80 0.086 0.048 0.037 200 200 0 57 "GET https://www.example.com:443/account?id=1 HTTP/1.1" '
             '"curl/8.5.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
             'arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 '
             '"Root=1-58337281-1d84f3d73c47ec4e58577259" "www.example.com" '
             '"arn:aws:acm:us-east-2:123456789012:certificate/12345678-1234-1234-1234-123456789012" 1 '
             '2026-11-05T10:00:04.364000Z "authenticate,forward" "-" "-" "10.0.0.1:80" "200" "-" "-" '
             'TID_1234abcd5678ef90 "-" "-" "-" 10.0.0.9 - -')
ALB_TLS13 = ALB_HTTPS.replace("ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2", "TLS_AES_128_GCM_SHA256 TLSv1.3")
ALB_HTTP = ('http 2026-11-05T10:00:05.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 '
            '10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" '
            '"curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 '
            '"Root=1-58337262-36d228ad5d99923122bbe354" "-" "-" 0 2026-11-05T10:00:04.364000Z "forward" "-" "-" '
            '"10.0.0.1:80" "200" "-" "-" TID_1234abcd5678ef90 "-" "-" "-"')

ZEEK_JSON_PQ = ('{"ts":1762336806.1,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"192.168.1.20","id.orig_p":53842,'
                '"id.resp_h":"93.184.216.34","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256",'
                '"curve":"X25519MLKEM768","server_name":"cdn.example.com","resumed":false,"established":true}')
ZEEK_JSON_UNKNOWN_CODE = ZEEK_JSON_PQ.replace('"X25519MLKEM768"', '"unknown-4588"').replace("cdn.", "edge.")
ZEEK_TSV = [
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tssl",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\testablished",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tbool",
    "1762336807.2\tC1\t192.168.1.21\t53900\t198.51.100.20\t443\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\tsecp256r1\tmail.example.com\tF\tT",
]


# ── Parsers ─────────────────────────────────────────────────────────────────────────────────────

def test_nginx_json_hybrid_group_is_safe_and_nothing_private_is_returned():
    r = pd.parse_batch("nginx", [NGINX_JSON_PQ])
    assert r["parsed"] == 1 and r["unparseable"] == 0
    obs = r["observations"][0]
    assert (obs["host"], obs["port"], obs["tls_version"]) == ("portal.example.com", 443, "TLSv1.3")
    assert obs["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert obs["group"] == "X25519MLKEM768"
    assert obs["key_exchange_family"] == "pq_hybrid"
    assert obs["pq_status"] == "pq_safe_key_exchange"
    assert obs["hndl_risk"] == "low"
    flat = json.dumps(obs)
    for private in ("203.0.113.7", "/login", "u=x"):
        assert private not in flat


def test_nginx_kv_classical_group_is_vulnerable():
    obs = pd.parse_batch("nginx", [NGINX_KV_CLASSICAL])["observations"][0]
    assert (obs["host"], obs["group"]) == ("api.example.com", "x25519")
    assert obs["pq_status"] == "quantum_vulnerable"
    assert obs["hndl_risk"] == "high"


def test_nginx_hex_curve_resolves_through_iana_table():
    obs = pd.parse_batch("nginx", [NGINX_HEX_CURVE])["observations"][0]
    assert obs["group"] == "X25519MLKEM768" and obs["port"] == 8443
    assert obs["pq_status"] == "pq_safe_key_exchange"


def test_nginx_combined_without_tls_fields_is_counted_not_guessed():
    r = pd.parse_batch("nginx", [NGINX_COMBINED, "garbage", '{"broken": '])
    assert r["parsed"] == 0
    assert r["unparseable"] == 3
    assert r["unparseable_by_reason"]["no_tls_fields"] == 2
    assert r["unparseable_by_reason"]["invalid_json"] == 1
    assert all(set(s) == {"index", "reason"} for s in r["unparseable_samples"])


def test_envoy_json_pq_and_tls12_from_local_address():
    r = pd.parse_batch("envoy", [ENVOY_JSON_PQ, ENVOY_JSON_TLS12])
    pq, legacy = r["observations"]
    assert (pq["host"], pq["port"], pq["group"]) == ("orders.example.com", 443, "SecP256r1MLKEM768")
    assert pq["pq_status"] == "pq_safe_key_exchange"
    assert (legacy["host"], legacy["port"]) == ("legacy.example.com", 9443)
    assert legacy["group"] == "" and legacy["group_observed"] is False
    assert legacy["pq_status"] == "quantum_vulnerable"
    assert "pre_tls13_key_exchange_is_classical" in legacy["reasons"]
    assert "198.51.100.4" not in json.dumps(r)


def test_haproxy_syslog_kv_and_json():
    r = pd.parse_batch("haproxy", [HAPROXY_KV, HAPROXY_JSON_PQ])
    kv, js = r["observations"]
    assert (kv["host"], kv["port"], kv["tls_version"], kv["group"]) == ("shop.example.com", 443, "TLSv1.3", "secp384r1")
    assert kv["pq_status"] == "quantum_vulnerable"
    assert js["pq_status"] == "pq_safe_key_exchange"
    assert "/cart" not in json.dumps(r)


def test_alb_has_no_group_and_tls13_stays_unknown():
    r = pd.parse_batch("alb", [ALB_HTTPS, ALB_TLS13, ALB_HTTP, "not an alb line"])
    assert r["parsed"] == 2
    assert r["skipped"] == 1                      # plaintext http: not TLS, not an error
    assert r["unparseable_by_reason"] == {"not_alb_access_log": 1}
    tls12, tls13 = r["observations"]
    assert (tls12["host"], tls12["port"], tls12["cipher"]) == ("www.example.com", 443, "ECDHE-RSA-AES128-GCM-SHA256")
    assert tls12["group_loggable"] is False and tls12["group"] == ""
    assert tls12["pq_status"] == "quantum_vulnerable"
    assert tls13["pq_status"] == "unknown" and "group_not_logged" in tls13["reasons"]
    flat = json.dumps(r)
    assert "192.168.131.39" not in flat and "account" not in flat and "curl" not in flat


def test_zeek_json_tsv_and_unknown_code_point():
    r = pd.parse_batch("zeek", [ZEEK_JSON_PQ, ZEEK_JSON_UNKNOWN_CODE, *ZEEK_TSV])
    assert r["unparseable"] == 0
    pq, decimal, tsv = r["observations"]
    assert (pq["host"], pq["port"], pq["tls_version"]) == ("cdn.example.com", 443, "TLSv1.3")
    assert pq["pq_status"] == "pq_safe_key_exchange"
    assert decimal["group"] == "X25519MLKEM768"   # Zeek "unknown-4588" is decimal 0x11EC
    assert (tsv["host"], tsv["tls_version"], tsv["group"]) == ("mail.example.com", "TLSv1.2", "secp256r1")
    assert tsv["pq_status"] == "quantum_vulnerable"
    assert "192.168.1.2" not in json.dumps(r)


def test_zeek_tsv_without_header_is_not_guessed():
    r = pd.parse_batch("zeek", [ZEEK_TSV[-1]])
    assert r["parsed"] == 0 and r["unparseable_by_reason"] == {"zeek_tsv_without_fields_header": 1}


def test_unregistered_group_code_is_unknown_not_classical():
    obs = pd.parse_batch("nginx", [NGINX_HEX_CURVE.replace("0x11ec", "0x7777")])["observations"][0]
    assert obs["group"] == "unknown-0x7777"
    assert obs["pq_status"] == "unknown"


def test_classification_reuses_scanner_rules():
    import scanner

    for group in ("X25519MLKEM768", "SecP384r1MLKEM1024", "x25519", "secp256r1"):
        assert pd.classify_observation("TLSv1.3", "TLS_AES_128_GCM_SHA256", group, True)["key_exchange_family"] \
            == scanner.classify_key_exchange_group(group)
    weak = pd.classify_observation("TLSv1.2", "ECDHE-RSA-DES-CBC3-SHA", "x25519", True)
    assert weak["hndl_risk"] == "critical" and "weak_cipher" in weak["reasons"]


# ── Endpoint: tokens, ingest, isolation, limits ─────────────────────────────────────────────────

@pytest.fixture()
def client(monkeypatch):
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    tmp_db.close()
    monkeypatch.setenv("MORROW_MAIN_DB_BACKEND", "")
    monkeypatch.setenv("MORROW_SCANNER_DB", tmp_db.name)
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    @asynccontextmanager
    async def _lifespan(_app):
        yield

    fastapi_app.app.router.lifespan_context = _lifespan
    init_db()
    with TestClient(fastapi_app.app) as c:
        yield c
    try:
        os.remove(tmp_db.name)
    except OSError:
        pass


def _admin(org):
    return {"x-user-role": "admin", "x-user-id": "admin-user", "x-org-id": org}


def _token(client, org, fmt=""):
    r = client.post("/v1/runtime/passive/tokens", headers=_admin(org), json={"name": "fluent-bit edge", "default_format": fmt})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["secret"].startswith("mpi_")
    return body["token"]["id"], body["secret"]


def test_token_hashed_at_rest_and_listing_never_shows_secret(client):
    token_id, secret = _token(client, ORG_A)
    listed = client.get("/v1/runtime/passive/tokens", headers=_admin(ORG_A)).json()["items"]
    assert [t["id"] for t in listed] == [token_id]
    assert secret not in json.dumps(listed)
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM passive_ingest_tokens WHERE id = ?", (token_id,)).fetchone()
    assert secret not in json.dumps(dict(row))
    assert len(row["token_hash"]) == 64


def test_token_management_requires_admin(client):
    r = client.post("/v1/runtime/passive/tokens", headers={"x-user-role": "viewer", "x-org-id": ORG_A}, json={"name": "x"})
    assert r.status_code == 403


def test_ingest_requires_valid_token_and_revocation_is_immediate(client):
    body = NGINX_JSON_PQ.encode()
    assert client.post("/v1/runtime/passive/ingest?format=nginx", content=body).status_code == 401
    assert client.post("/v1/runtime/passive/ingest?format=nginx", content=body,
                       headers={"Authorization": "Bearer mpi_000000000000_" + "x" * 43}).status_code == 401
    token_id, secret = _token(client, ORG_A)
    ok = client.post("/v1/runtime/passive/ingest?format=nginx", content=body,
                     headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/x-ndjson"})
    assert ok.status_code == 200, ok.text
    assert client.delete(f"/v1/runtime/passive/tokens/{token_id}", headers=_admin(ORG_A)).json()["token"]["status"] == "revoked"
    again = client.post("/v1/runtime/passive/ingest?format=nginx", content=body, headers={"Authorization": f"Bearer {secret}"})
    assert again.status_code == 401 and "revoked" in again.json()["detail"]


def test_ingest_dedups_merges_inventory_and_is_org_scoped(client):
    _, secret_a = _token(client, ORG_A, fmt="nginx")
    _, secret_b = _token(client, ORG_B, fmt="nginx")
    # Fluent Bit "json" format: an array of records with the tailed line under "log".
    batch = [{"date": 1762336801.0, "log": NGINX_JSON_PQ}] * 3 + [{"date": 1762336802.0, "log": NGINX_KV_CLASSICAL}]
    r = client.post("/v1/runtime/passive/ingest", json=batch,
                    headers={"Authorization": f"Bearer {secret_a}", "x-org-id": ORG_B})   # header cannot redirect
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["parsed"] == 4 and out["endpoints_new"] == 2 and out["assets_upserted"] == 2
    # Second batch: same keys -> counts grow, no new rows, no asset rewrite.
    r2 = client.post("/v1/runtime/passive/ingest", json=batch[:1], headers={"Authorization": f"Bearer {secret_a}"})
    assert r2.json()["endpoints_new"] == 0 and r2.json()["assets_upserted"] == 0

    items_a = client.get("/v1/runtime/passive/endpoints", headers=_admin(ORG_A)).json()["items"]
    by_host = {i["host"]: i for i in items_a}
    assert by_host["portal.example.com"]["observation_count"] == 4
    assert by_host["portal.example.com"]["pq_status"] == "pq_safe_key_exchange"
    assert by_host["portal.example.com"]["source"] == "passive"
    assert by_host["api.example.com"]["pq_status"] == "quantum_vulnerable"
    assert client.get("/v1/runtime/passive/endpoints", headers=_admin(ORG_B)).json()["items"] == []

    tok = set_current_organization_id(ORG_A)
    try:
        asset = get_asset("portal.example.com:443")
    finally:
        reset_current_organization_id(tok)
    assert asset and passive_ingest.PASSIVE_TAG in asset["tags"]
    assert asset["metadata"]["discovery_sources"] == ["passive"]
    assert asset["metadata"]["passive_pq_status"] == "pq_safe_key_exchange"
    tok = set_current_organization_id(ORG_B)
    try:
        assert get_asset("portal.example.com:443") is None
    finally:
        reset_current_organization_id(tok)

    # Org B's token writes only to org B.
    client.post("/v1/runtime/passive/ingest", content=NGINX_KV_CLASSICAL, headers={"Authorization": f"Bearer {secret_b}",
                                                                                    "Content-Type": "text/plain"})
    assert [i["host"] for i in client.get("/v1/runtime/passive/endpoints", headers=_admin(ORG_B)).json()["items"]] == ["api.example.com"]


def test_ingest_vector_ndjson_gzip_and_alb_note(client):
    _, secret = _token(client, ORG_A)
    ndjson = "\n".join(json.dumps({"message": line, "source_type": "file"}) for line in (ALB_HTTPS, ALB_TLS13, ALB_HTTP))
    r = client.post("/v1/runtime/passive/ingest?format=alb", content=gzip.compress(ndjson.encode()),
                    headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/x-ndjson",
                             "Content-Encoding": "gzip"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["parsed"] == 2 and out["skipped"] == 1 and out["group_logged"] is False and "note" in out


def test_ingest_limits(client, monkeypatch):
    _, secret = _token(client, ORG_A, fmt="nginx")
    auth = {"Authorization": f"Bearer {secret}"}
    monkeypatch.setenv("MORROW_PASSIVE_MAX_BODY_BYTES", "2048")
    assert client.post("/v1/runtime/passive/ingest", content=b"x" * 4096, headers=auth).status_code == 413
    monkeypatch.setenv("MORROW_PASSIVE_MAX_BODY_BYTES", str(1024 * 1024))
    monkeypatch.setenv("MORROW_PASSIVE_MAX_DECODED_BYTES", "4096")
    bomb = gzip.compress(b"a" * 200_000)
    assert client.post("/v1/runtime/passive/ingest", content=bomb, headers={**auth, "Content-Encoding": "gzip"}).status_code == 413
    monkeypatch.setenv("MORROW_PASSIVE_MAX_DECODED_BYTES", str(8 * 1024 * 1024))
    monkeypatch.setenv("MORROW_PASSIVE_MAX_LINES", "2")
    assert client.post("/v1/runtime/passive/ingest", json=[NGINX_JSON_PQ] * 3, headers=auth).status_code == 413
    monkeypatch.setenv("MORROW_PASSIVE_MAX_LINES", "5000")
    assert client.post("/v1/runtime/passive/ingest?format=bogus", json=[], headers=auth).status_code == 400
    monkeypatch.setenv("MORROW_PASSIVE_RATE_PER_MINUTE", "2")
    codes = [client.post("/v1/runtime/passive/ingest", json=[NGINX_JSON_PQ], headers=auth).status_code for _ in range(3)]
    assert codes[-1] == 429
