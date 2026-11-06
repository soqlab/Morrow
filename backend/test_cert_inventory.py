"""Certificate-manager and cloud KMS inventory sync (services/cert_inventory).

TESTED AGAINST DOCUMENTED RESPONSES ONLY. Every vendor API is replaced by a fake transport that
answers with fixtures shaped exactly like the vendor's published examples (the URL above each
fixture). Where an example is a single record, more records are made from that same shape so paging
can be exercised. None of this has been run against a live Keyfactor, Venafi, DigiCert, AWS, Azure
or Google account.

The fake sits at services.cert_inventory._transport, below the retry/backoff, redirect, host-pinning
and error-mapping logic, so all of that is exercised for real. Reuses the real-stack fixture from
test_invite_landing (temporary SQLite databases, no network).
"""

import base64
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from test_invite_landing import PASSWORD, api_fixture, make_org  # noqa: F401  (api_fixture registers the "api" fixture)

from services import cert_inventory as ci

ORG = "org-acme"


class FakeVendor:
    """Answers HTTP calls from (method, url regex) -> answer, where answer is (status, body[, headers])
    or a callable(url, headers, data) returning one. Records every call."""

    def __init__(self, routes):
        self.routes = list(routes.items())
        self.calls = []

    def __call__(self, method, url, headers, data):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "data": data})
        for (m, pattern), answer in self.routes:
            if m == method and re.search(pattern, url):
                out = answer(url, headers, data) if callable(answer) else answer
                status, body = out[0], out[1]
                hdrs = out[2] if len(out) > 2 else {}
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                return status, {k.lower(): v for k, v in hdrs.items()}, raw
        raise AssertionError(f"unexpected call {method} {url}")


@pytest.fixture
def env(api, monkeypatch):  # noqa: F811  (pytest fixture injection)
    monkeypatch.setattr(ci, "_ready", False)
    monkeypatch.setattr(ci, "_require_public_host", lambda host: None)
    sleeps = []
    monkeypatch.setattr(ci, "_sleep", sleeps.append)
    monkeypatch.delenv("MORROW_CERT_SOURCES_ALLOW_PRIVATE", raising=False)
    monkeypatch.delenv("MORROW_CODE_HOSTS_ALLOW_PRIVATE", raising=False)
    return api, sleeps


def use(monkeypatch, routes):
    fake = FakeVendor(routes)
    monkeypatch.setattr(ci, "_transport", fake)
    return fake


def assert_read_only(fake):
    """Nothing but reads: GETs, plus the documented read-only POSTs (search, tokens, AWS JSON reads)."""
    for c in fake.calls:
        if c["method"] == "GET":
            continue
        assert c["method"] == "POST", c
        url = c["url"]
        target = c["headers"].get("X-Amz-Target", "")
        assert (url.endswith("/outagedetection/v1/certificatesearch") or url.endswith("/vedauth/authorize/oauth")
                or "/oauth2/v2.0/token" in url or url == "https://oauth2.googleapis.com/token"
                or target in ("TrentService.ListKeys", "TrentService.DescribeKey")), c


# ── Keyfactor Command ───────────────────────────────────────────────────────────────────────────
# Shape: https://software.keyfactor.com/Core-OnPrem/Current/Content/WebAPI/KeyfactorAPI/CertificatesGET.htm

def keyfactor_cert(i, key="RSA", size=2048):
    return {
        "Id": 1000 + i, "Thumbprint": f"{i:040X}", "SerialNumber": f"6100000{i:04d}",
        "IssuedDN": f"CN=app{i}.acme.example, O=Acme", "IssuedCN": f"app{i}.acme.example",
        "ImportDate": "2026-01-02T10:00:00Z", "NotBefore": "2026-01-02T10:00:00Z", "NotAfter": "2027-01-02T10:00:00Z",
        "IssuerDN": "CN=Acme Issuing CA, O=Acme", "PrincipalId": None, "TemplateId": 41, "CertState": 1,
        "KeySizeInBits": size, "KeyType": 1, "KeyTypeString": key,
        "KeyAlgorithm": "RSA (1.2.840.113549.1.1.1)" if key == "RSA" else "ECC (1.2.840.10045.2.1)",
        "RequesterId": 6, "IssuedOU": None, "IssuedEmail": None, "KeyUsage": 160, "SigningAlgorithm": "sha256RSA",
        "CertStateString": "Active", "KeyRecoverable": False, "Curve": None, "TemplateName": "WebServer",
        "OwnerRoleId": 3, "OwnerRoleName": "Web Platform", "RequesterName": "ACME\\svc-pki",
        "Metadata": {"Email-Contact": "web-team@acme.example"} if i % 2 == 0 else {},
        "LocationsCount": [{"Type": "IIS", "Count": 2}, {"Type": "F5-SL-REST", "Count": 1}],
        "Locations": [], "SSLLocations": [], "HasPrivateKey": False, "SubjectAltNameElements": [],
        "CRLDistributionPoints": [], "RevocationEffDate": None, "RevocationReason": None,
    }


def test_keyfactor_pages_classifies_and_uses_documented_headers(env, monkeypatch):
    certs = [keyfactor_cert(i) for i in range(1, 251)] + [keyfactor_cert(251, "ECC", 256)]

    def page(url, headers, data):
        q = dict(re.findall(r"([A-Za-z]+)=([^&]+)", url.split("?", 1)[1]))
        n, size = int(q["PageReturned"]), int(q["ReturnLimit"])
        return 200, certs[(n - 1) * size:n * size], {"x-total-count": str(len(certs))}

    fake = use(monkeypatch, {("GET", r"^https://kf\.acme\.example/KeyfactorAPI/Certificates\?"): page})
    src = ci.add_source(ORG, "keyfactor", {"base_url": "kf.acme.example", "username": "ACME\\svc-morrow",
                                            "password": "S3cret-Pass!"})
    assert src["base_url"] == "https://kf.acme.example/KeyfactorAPI" and src["account"] == "ACME\\svc-morrow"
    result = ci.sync_source(ORG, src["id"])
    assert result["items"] == 251 and result["quantum_vulnerable"] == 251
    pages = [c for c in fake.calls if "ReturnLimit=200" in c["url"]]
    assert [re.search(r"PageReturned=(\d+)", c["url"]).group(1) for c in pages] == ["1", "2"]
    h = fake.calls[0]["headers"]
    assert h["Authorization"] == "Basic " + base64.b64encode(b"ACME\\svc-morrow:S3cret-Pass!").decode()
    assert h["X-Keyfactor-API-Version"] == "1" and h["X-Keyfactor-Requested-With"] == "APIClient"
    items = {i["name"]: i for i in ci.list_inventory(ORG)}
    rsa, ec = items["app2.acme.example"], items["app251.acme.example"]
    assert (rsa["algorithm"], rsa["risk"], rsa["owner"]) == ("RSA-2048", "critical", "web-team@acme.example")
    assert rsa["signature_algorithm"] == "sha256RSA" and rsa["not_after"] == "2027-01-02T10:00:00Z"
    assert items["app1.acme.example"]["owner"] == "Web Platform"
    assert (ec["key_algorithm"], ec["curve"], ec["algorithm"], ec["risk"]) == ("EC", "P-256", "EC P-256", "critical")
    assert_read_only(fake)


# ── Venafi TLS Protect Cloud ────────────────────────────────────────────────────────────────────
# Shape: https://github.com/Venafi/vcert/blob/master/pkg/venafi/cloud/search.go (count, certificates[]
# with id, subjectCN[], serialNumber, fingerprint, validityEnd, applicationIds) plus the documented
# SaaS fields keyStrength, encryptionType, signatureHashAlgorithm, issuerCN.

def venafi_cloud_cert(i):
    return {"id": f"a1b2c3d4-0000-4000-8000-{i:012d}", "companyId": "c0ffee00-0000-4000-8000-000000000001",
            "certificateName": f"api{i}.acme.example", "fingerprint": f"{0xF0000 + i:040X}",
            "serialNumber": f"0A{i:06d}", "subjectCN": [f"api{i}.acme.example"], "subjectDN": f"CN=api{i}.acme.example",
            "issuerCN": ["DigiCert Global G2 TLS RSA SHA256 2020 CA1"], "validityStart": "2026-03-01T00:00:00.000+00:00",
            "validityEnd": "2027-03-01T23:59:59.000+00:00", "keyStrength": 4096 if i == 1 else 2048,
            "encryptionType": "RSA", "signatureAlgorithm": "SHA256_WITH_RSA_ENCRYPTION",
            "signatureHashAlgorithm": "SHA256", "selfSigned": False, "applicationIds": ["app-1"]}


def test_venafi_cloud_searches_by_page_with_api_key(env, monkeypatch):
    certs = [venafi_cloud_cert(i) for i in range(1, 231)]

    def search(url, headers, data):
        paging = json.loads(data)["paging"]
        n, size = paging["pageNumber"], paging["pageSize"]
        return 200, {"count": len(certs), "certificates": certs[n * size:(n + 1) * size]}

    fake = use(monkeypatch, {("POST", r"^https://api\.eu\.venafi\.cloud/outagedetection/v1/certificatesearch$"): search})
    src = ci.add_source(ORG, "venafi_cloud", {"region": "eu", "api_key": "0a1b2c3d-4e5f-6789-abcd-ef0123456789"})
    assert src["account"] == "230 certificates visible"
    assert ci.sync_source(ORG, src["id"])["items"] == 230
    assert all(c["headers"]["tppl-api-key"] == "0a1b2c3d-4e5f-6789-abcd-ef0123456789" for c in fake.calls)
    assert [json.loads(c["data"])["paging"]["pageNumber"] for c in fake.calls[1:]] == [0, 1]
    first = next(i for i in ci.list_inventory(ORG) if i["name"] == "api1.acme.example")
    assert (first["algorithm"], first["risk"], first["issuer"]) == ("RSA-4096", "high", "DigiCert Global G2 TLS RSA SHA256 2020 CA1")
    assert_read_only(fake)


# ── Venafi Trust Protection Platform ────────────────────────────────────────────────────────────
# Shapes: https://docs.venafi.com/Docs/current/TopNav/Content/SDK/AuthSDK/r-SDKa-POST-AuthorizeOAuth.php
#         https://docs.venafi.com/Docs/25.3/TopNav/Content/SDK/WebSDK/r-SDK-GET-Certificates.php

def tpp_cert(i):
    return {"CreatedOn": "2026-02-01T09:22:31.0000000Z", "DN": f"\\VED\\Policy\\Certificates\\Web\\svc{i}.acme.example",
            "Guid": f"{{8b5d6a42-1b2c-4d1e-9f00-{i:012d}}}", "Name": f"svc{i}.acme.example",
            "ParentDn": "\\VED\\Policy\\Certificates\\Web", "SchemaClass": "X509 Server Certificate",
            "X509": {"CN": f"svc{i}.acme.example", "Issuer": "CN=Acme Root CA, O=Acme", "KeyAlgorithm": "RSA",
                     "KeySize": 1024 if i == 3 else 2048, "SANS": {"DNS": [f"svc{i}.acme.example"]},
                     "Serial": f"5B00000{i:05d}", "Subject": f"CN=svc{i}.acme.example, O=Acme",
                     "Thumbprint": f"{0xA0000 + i:040X}", "ValidFrom": "2026-02-01T09:12:31.0000000Z",
                     "ValidTo": "2028-02-01T09:12:31.0000000Z"},
            "_links": [{"Details": f"/vedsdk/certificates/{{8b5d6a42-1b2c-4d1e-9f00-{i:012d}}}"}]}


def test_venafi_tpp_gets_token_then_pages_certificates(env, monkeypatch):
    certs = [tpp_cert(i) for i in range(1, 601)]

    def listing(url, headers, data):
        assert headers["Authorization"] == "Bearer KT2EEVTIjWM/37L78dqJAg=="
        assert "/vedsdk/certificates/?" in url and "OptionalFields=KeyAlgorithm%2CKeySize%2CSubject%2CIssuer" in url
        q = dict(re.findall(r"([A-Za-z]+)=([^&]+)", url.split("?", 1)[1]))
        off, lim = int(q["Offset"]), int(q["Limit"])
        page = certs[off:off + lim]
        return 200, {"Certificates": page, "DataRange": f"{off + 1} - {off + len(page)}", "TotalCount": str(len(certs))}

    fake = use(monkeypatch, {
        ("POST", r"^https://tpp\.acme\.example/vedauth/authorize/oauth$"): (200, {
            "access_token": "KT2EEVTIjWM/37L78dqJAg==", "refresh_token": "", "expires": 1767225600,
            "token_type": "Bearer", "scope": "certificate", "identity": "local:{1d2b3c4e}"}),
        ("GET", r"^https://tpp\.acme\.example/vedsdk/certificates/\?"): listing,
    })
    src = ci.add_source(ORG, "venafi_tpp", {"base_url": "https://tpp.acme.example", "client_id": "morrow-inventory",
                                             "username": "local:morrow-reader", "password": "Passw0rd!"})
    result = ci.sync_source(ORG, src["id"])
    assert result["items"] == 600
    token_call = next(c for c in fake.calls if c["method"] == "POST")
    assert json.loads(token_call["data"]) == {"client_id": "morrow-inventory", "username": "local:morrow-reader",
                                              "password": "Passw0rd!", "scope": "certificate"}
    svc3 = next(i for i in ci.list_inventory(ORG) if i["name"] == "svc3.acme.example")
    assert (svc3["algorithm"], svc3["risk"], svc3["not_after"]) == ("RSA-1024", "critical", "2028-02-01T09:12:31Z")
    assert_read_only(fake)


# ── DigiCert CertCentral ────────────────────────────────────────────────────────────────────────
# Shapes: https://dev.digicert.com/certcentral-apis/services-api/orders/list-orders.html
#         https://dev.digicert.com/md/certcentral-apis/services-api/orders/order-info.md

DIGICERT_THUMB = "AB0123456789C0D1EF234AB56C7890DE12ABC3DE"
DIGICERT_LIST = {
    "orders": [{
        "id": 123456,
        "certificate": {"id": 104, "common_name": "example.com", "dns_names": ["example2.com", "example3.com"],
                        "valid_till": "2027-10-16", "days_remaining": 345, "signature_hash": "sha256"},
        "status": "issued", "is_renewed": False, "date_created": "2018-10-16T17:29:56+00:00",
        "organization": {"id": 112233, "name": "Epigyne Unwieldiness llc"}, "validity_years": 1,
        "disable_renewal_notifications": False, "container": {"id": 14, "name": "DigiCert Inc."},
        "product": {"name_id": "ssl_plus", "name": "Standard SSL", "type": "ssl_certificate"},
        "has_duplicates": False, "product_name_id": "ssl_plus"}],
    "page": {"total": 1, "limit": 0, "offset": 0},
}
DIGICERT_INFO = {
    "id": 123456,
    "certificate": {"id": 104, "thumbprint": DIGICERT_THUMB, "serial_number": "123a56bc78d9e0a1234b567c89d01e23",
                    "common_name": "example.com", "dns_names": ["example2.com", "example3.com"],
                    "date_created": "2018-10-16T17:29:56+00:00", "valid_from": "2026-10-16", "valid_till": "2027-10-16",
                    "days_remaining": 345, "csr": "", "organization": {"id": 112233}, "organization_units": [],
                    "server_platform": {"id": -1, "name": "OTHER"}, "signature_hash": "sha256", "key_size": 2048,
                    "ca_cert": {"id": "f7slk4shv9s2wr3", "name": "DigiCert SHA2 Secure Server CA"}},
    "status": "issued", "user": {"id": 44, "first_name": "Jill", "last_name": "Valentine", "email": "jill.valentine@example.com"},
    "organization": {"id": 112233, "name": "Epigyne Unwieldiness llc"},
}


def digicert_routes():
    return {
        ("GET", r"^https://www\.digicert\.com/services/v2/order/certificate\?"): (200, DIGICERT_LIST),
        ("GET", r"^https://www\.digicert\.com/services/v2/order/certificate/123456$"): (200, DIGICERT_INFO),
    }


def seed_tls_scan(app, host="example.com", sha1=DIGICERT_THUMB):
    import db

    token = db.set_current_organization_id(ORG)
    try:
        db.save_scan_row("scan-tls-1", "complete", datetime.now(timezone.utc), {}, "", [
            {"host": host, "port": 443, "key_type": "RSA", "key_bits": 2048, "cert_sha1": sha1,
             "cert_sha256": "11" * 32}], {})
    finally:
        db.reset_current_organization_id(token)


def test_digicert_lists_orders_reads_details_and_dedups_with_tls_scan(env, monkeypatch):
    (client, app), _ = env
    seed_tls_scan(app)
    fake = use(monkeypatch, digicert_routes())
    src = ci.add_source(ORG, "digicert", {"api_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
    assert src["account"] == "1 issued orders"
    result = ci.sync_source(ORG, src["id"])
    assert result["items"] == 1 and result["linked_to_tls"] == 1
    item = ci.list_inventory(ORG)[0]
    assert (item["asset_key"], item["linked_tls"], item["fingerprint_sha1"]) == ("example.com:443", True, DIGICERT_THUMB)
    assert (item["algorithm"], item["owner"], item["not_after"]) == ("RSA-2048", "jill.valentine@example.com", "2027-10-16T00:00:00Z")
    assert all(c["headers"]["X-DC-DEVKEY"].startswith("AAAA") for c in fake.calls)
    assert "filters%5Bstatus%5D=issued" in fake.calls[-2]["url"]

    import db
    token = db.set_current_organization_id(ORG)
    try:
        asset = db.get_asset("example.com:443")
    finally:
        db.reset_current_organization_id(token)
    entry = asset["metadata"]["cert_inventory"][src["id"]]
    assert entry["provider"] == "digicert" and entry["risk"] == "critical"
    assert {"source:digicert", "inventory:certificate", "quantum-risk:critical"} <= set(asset["tags"])
    assert_read_only(fake)


def test_same_certificate_from_two_managers_is_one_asset(env, monkeypatch):
    cert = keyfactor_cert(7)
    cert["Thumbprint"] = DIGICERT_THUMB
    use(monkeypatch, {**digicert_routes(), ("GET", r"/KeyfactorAPI/Certificates\?"): (200, [cert])})
    a = ci.add_source(ORG, "digicert", {"api_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"})
    b = ci.add_source(ORG, "keyfactor", {"base_url": "https://kf.acme.example/KeyfactorAPI", "token": "eyJhbGciOi.kf"})
    ci.sync_source(ORG, a["id"])
    ci.sync_source(ORG, b["id"])
    keys = {i["asset_key"] for i in ci.list_inventory(ORG)}
    assert keys == {f"cert:{DIGICERT_THUMB}"}
    import db
    token = db.set_current_organization_id(ORG)
    try:
        asset = db.get_asset(f"cert:{DIGICERT_THUMB}")
    finally:
        db.reset_current_organization_id(token)
    assert set(asset["metadata"]["cert_inventory"]) == {a["id"], b["id"]}
    # Removing one source leaves the other's entry on the asset.
    assert ci.remove_source(ORG, a["id"])
    token = db.set_current_organization_id(ORG)
    try:
        asset = db.get_asset(f"cert:{DIGICERT_THUMB}")
    finally:
        db.reset_current_organization_id(token)
    assert set(asset["metadata"]["cert_inventory"]) == {b["id"]} and "source:digicert" not in asset["tags"]


# ── AWS KMS ─────────────────────────────────────────────────────────────────────────────────────
# Shapes: https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeys.html (example response)
#         https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html (example response)

AWS_KEYS = ["0d990263-018e-4e65-a703-eff731de951e", "144be297-0ae1-44ac-9c8f-93cd8c82f841",
            "21184251-b765-428e-b852-2c7353e72571", "214fe92f-5b03-4ae1-b350-db2a45dbe10c",
            "339963f2-e523-49d3-af24-a0fe752aa458", "b776a44b-df37-4438-9be4-a27494e4271a",
            "deaf6c9e-cf2c-46a6-bf6d-0b6d487cffbb"]
SPECS = {AWS_KEYS[1]: "RSA_2048", AWS_KEYS[2]: "ECC_NIST_P384", AWS_KEYS[3]: "ML_DSA_65", AWS_KEYS[4]: "HMAC_256"}


def aws_routes():
    def kms(url, headers, data):
        target = headers["X-Amz-Target"]
        assert headers["Content-Type"] == "application/x-amz-json-1.1"
        assert "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target" in headers["Authorization"]
        body = json.loads(data)
        if target == "TrentService.ListKeys":
            keys = [{"KeyArn": f"arn:aws:kms:us-east-2:111122223333:key/{k}", "KeyId": k} for k in AWS_KEYS]
            if body.get("Limit") == 1:
                return 200, {"Keys": keys[:1], "NextMarker": "m1", "Truncated": True}
            if "Marker" not in body:
                return 200, {"Keys": keys[:4], "NextMarker": "eyJtYXJrZXIiOiI0In0", "Truncated": True}
            assert body["Marker"] == "eyJtYXJrZXIiOiI0In0"
            return 200, {"Keys": keys[4:], "Truncated": False}
        key = body["KeyId"]
        spec = SPECS.get(key, "SYMMETRIC_DEFAULT")
        return 200, {"KeyMetadata": {
            "AWSAccountId": "111122223333", "Arn": f"arn:aws:kms:us-east-2:111122223333:key/{key}",
            "CreationDate": "2025-04-16T16:03:04.060000-07:00", "CustomerMasterKeySpec": spec, "Description": "",
            "Enabled": True, "KeyId": key, "KeyManager": "CUSTOMER", "KeySpec": spec, "KeyState": "Enabled",
            "KeyUsage": "SIGN_VERIFY" if spec in ("RSA_2048", "ECC_NIST_P384", "ML_DSA_65") else "ENCRYPT_DECRYPT",
            "MultiRegion": False, "Origin": "AWS_KMS", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
            "CurrentKeyMaterialId": "0b7fd7ddbac6eef27907413567cad8c810e2883dc8a7534067a82ee1142fc1e6"}}
    return {("POST", r"^https://kms\.us-east-2\.amazonaws\.com/$"): kms}


def test_aws_kms_lists_and_describes_keys_with_signed_json_protocol(env, monkeypatch):
    fake = use(monkeypatch, aws_routes())
    src = ci.add_source(ORG, "aws_kms", {"access_key_id": "AKIAI44QH8DHBEXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG",
                                          "regions": "us-east-2"})
    assert src["account"] == "AKIA…MPLE" and src["settings"]["regions"] == ["us-east-2"]
    result = ci.sync_source(ORG, src["id"])
    assert result["items"] == 7
    by_id = {i["item_key"].rsplit("/", 1)[1]: i for i in ci.list_inventory(ORG)}
    assert (by_id[AWS_KEYS[0]]["algorithm"], by_id[AWS_KEYS[0]]["risk"]) == ("AES-256", "low")
    assert (by_id[AWS_KEYS[1]]["algorithm"], by_id[AWS_KEYS[1]]["risk"]) == ("RSA-2048", "critical")
    assert (by_id[AWS_KEYS[2]]["curve"], by_id[AWS_KEYS[2]]["risk"]) == ("P-384", "high")
    assert (by_id[AWS_KEYS[3]]["algorithm"], by_id[AWS_KEYS[3]]["classification"]["status"]) == ("ML-DSA-65", "compliant")
    assert by_id[AWS_KEYS[4]]["algorithm"] == "HMAC-SHA256"
    assert all(i["asset_key"].startswith("kms:aws_kms:arn:aws:kms:") for i in by_id.values())
    assert_read_only(fake)
    assert "wJalrXUtnFEMI" not in json.dumps(fake.calls[-1]["headers"])


# ── Azure Key Vault ─────────────────────────────────────────────────────────────────────────────
# Shapes: https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys (sample response)
#         https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key (sample response)

AZ_N = ("2HJAE5fU3Cw2Rt9hEuq-F6XjINKGa-zskfISVqopqUy60GOs2eyhxbWbJBeUXNor_gf-tXtNeuqeBgitLeVa640UDvnEjYTKWjCniTxZRaU7ewY8BfTSk"
        "-7KxoDdLsPSpX_MX4rwlAx-_1UGk5t4sQgTbm9T6Fm2oqFd37dsz5-Gj27UP2GTAShfJPFD7MqU_zIgOI0pfqsbNL5xTQVM29K6rX4jSPtylZV3uWJt"
        "koQIQnrIHhk1d0SC0KwlBV3V7R_LVYjiXLyIXsFzSNYgQ68ZjAwt8iL7I8Osa-ehQLM13DVvLASaf7Jnu3sC3CWl3Gyirgded6cfMmswJzY87w")
AZ_NEXT = ("https://myvault.vault.azure.net:443/keys?api-version=7.2&$skiptoken=eyJOZXh0TWFya2VyIjoiMiE5NiFNREF3TURJM0lXdGxlUzlW"
           "VUVSQlZFVkxSVmxCVkZSU1NVSlZWRVZUVkVWVFZDRXdNREF3TWpnaE1qQXhOeTB3TlMwd05GUXdNVG94TVRveE5pNDNNekE0TnpReVdpRS0iLCJUYXJnZXRMb2NhdGlvbiI6MH0&maxresults=1")


def azure_routes(next_link=AZ_NEXT):
    return {
        ("POST", r"^https://login\.microsoftonline\.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2\.0/token$"):
            (200, {"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": "eyJ0eXAiOiJKV1Qi.az"}),
        ("GET", r"^https://myvault\.vault\.azure\.net/keys\?api-version=2025-07-01&maxresults=\d+$"): (200, {
            "value": [{"kid": "https://myvault.vault.azure.net/keys/sdktestkey",
                       "attributes": {"enabled": True, "created": 1493937656, "updated": 1493937656,
                                      "recoveryLevel": "Recoverable+Purgeable"}}],
            "nextLink": next_link}),
        ("GET", r"^https://myvault\.vault\.azure\.net:443/keys\?api-version=7\.2&\$skiptoken="): (200, {
            "value": [{"kid": "https://myvault.vault.azure.net/keys/signing-p256",
                       "attributes": {"enabled": True, "exp": 1830297600, "created": 1493937656, "updated": 1493937656,
                                      "recoveryLevel": "Recoverable+Purgeable"}, "tags": {"owner": "payments@acme.example"}}]}),
        ("GET", r"/keys/sdktestkey\?api-version=2025-07-01$"): (200, {
            "key": {"kid": "https://myvault.vault.azure.net/keys/sdktestkey/78deebed173b48e48f55abf87ed4cf71", "kty": "RSA",
                    "key_ops": ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"], "n": AZ_N, "e": "AQAB"},
            "attributes": {"enabled": True, "created": 1493942451, "updated": 1493942451, "recoveryLevel": "Recoverable+Purgeable"},
            "tags": {"purpose": "unit test", "test name ": "CreateGetDeleteKeyTest"}}),
        ("GET", r"/keys/signing-p256\?api-version=2025-07-01$"): (200, {
            "key": {"kid": "https://myvault.vault.azure.net/keys/signing-p256/1f2e3d", "kty": "EC-HSM", "crv": "P-256",
                    "key_ops": ["sign", "verify"], "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
            "attributes": {"enabled": True, "exp": 1830297600, "created": 1493942451, "updated": 1493942451},
            "tags": {"owner": "payments@acme.example"}}),
    }


AZ_FIELDS = {"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "00000000-1111-2222-3333-444444444444",
             "client_secret": "az-secret-value", "vault_urls": "myvault"}


def test_azure_key_vault_follows_next_link_and_reads_each_key(env, monkeypatch):
    fake = use(monkeypatch, azure_routes())
    src = ci.add_source(ORG, "azure_key_vault", AZ_FIELDS)
    assert src["settings"]["vault_urls"] == ["https://myvault.vault.azure.net"]
    assert ci.sync_source(ORG, src["id"])["items"] == 2
    items = {i["name"]: i for i in ci.list_inventory(ORG)}
    assert (items["sdktestkey"]["algorithm"], items["sdktestkey"]["risk"]) == ("RSA-2048", "critical")
    p256 = items["signing-p256"]
    assert (p256["curve"], p256["owner"], p256["not_after"]) == ("P-256", "payments@acme.example", "2028-01-01T00:00:00Z")
    token = next(c for c in fake.calls if "oauth2" in c["url"])
    assert b"scope=https%3A%2F%2Fvault.azure.net%2F.default" in token["data"]
    assert_read_only(fake)


def test_a_next_link_on_another_host_is_not_followed(env, monkeypatch):
    fake = use(monkeypatch, azure_routes(next_link="https://169.254.169.254/metadata/instance"))
    src = ci.add_source(ORG, "azure_key_vault", AZ_FIELDS)
    with pytest.raises(ci.CertSourceError, match="different host"):
        ci.sync_source(ORG, src["id"])
    assert not any("169.254" in c["url"] for c in fake.calls)
    assert ci.list_sources(ORG)[0]["last_sync_status"] == "error"


# ── Google Cloud KMS ────────────────────────────────────────────────────────────────────────────
# Shapes: https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings/list
#         https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list
#         https://docs.cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm

def service_account():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return {"type": "service_account", "project_id": "acme-prod", "private_key_id": "abc123", "private_key": pem,
            "client_email": "morrow-kms@acme-prod.iam.gserviceaccount.com", "token_uri": "https://evil.example/token"}


def gcp_routes():
    kr = "projects/acme-prod/locations/global/keyRings/app"
    ck = f"{kr}/cryptoKeys"
    versions = {
        "signer": [("RSA_SIGN_PSS_2048_SHA256", "ENABLED"), ("RSA_SIGN_PSS_2048_SHA256", "DESTROYED")],
        "pq-signer": [("PQ_SIGN_ML_DSA_65", "ENABLED")],
        "data": [("GOOGLE_SYMMETRIC_ENCRYPTION", "ENABLED")],
        "ec": [("EC_SIGN_P256_SHA256", "ENABLED")],
        "kem": [("KEM_XWING", "ENABLED")],
    }

    def ver(url, headers, data):
        name = re.search(r"/cryptoKeys/([^/]+)/cryptoKeyVersions", url).group(1)
        return 200, {"cryptoKeyVersions": [
            {"name": f"{ck}/{name}/cryptoKeyVersions/{n + 1}", "state": state, "protectionLevel": "HSM", "algorithm": alg,
             "createTime": "2026-05-01T10:00:00.000000Z", "generateTime": "2026-05-01T10:00:00.000000Z"}
            for n, (alg, state) in enumerate(versions[name])], "totalSize": len(versions[name])}

    def keys(url, headers, data):
        if "pageToken=" not in url:
            return 200, {"cryptoKeys": [{"name": f"{ck}/{k}", "purpose": "ASYMMETRIC_SIGN", "labels": {"owner": "platform"}}
                                        for k in ("signer", "pq-signer")], "nextPageToken": "p2", "totalSize": 5}
        return 200, {"cryptoKeys": [{"name": f"{ck}/{k}", "purpose": "ENCRYPT_DECRYPT"} for k in ("data", "ec", "kem")],
                     "totalSize": 5}

    return {
        ("POST", r"^https://oauth2\.googleapis\.com/token$"): (200, {"access_token": "ya29.gcp", "expires_in": 3599, "token_type": "Bearer"}),
        ("GET", r"/v1/projects/acme-prod/locations\?pageSize="): (200, {"locations": [
            {"name": "projects/acme-prod/locations/global", "locationId": "global", "displayName": "Global"}]}),
        ("GET", r"/locations/global/keyRings\?"): (200, {"keyRings": [{"name": kr, "createTime": "2026-01-01T00:00:00Z"}], "totalSize": 1}),
        ("GET", r"/keyRings/app/cryptoKeys\?"): keys,
        ("GET", r"/cryptoKeyVersions\?"): ver,
    }


def test_gcp_kms_walks_locations_rings_keys_and_versions(env, monkeypatch):
    fake = use(monkeypatch, gcp_routes())
    src = ci.add_source(ORG, "gcp_kms", {"service_account_json": json.dumps(service_account())})
    assert src["account"] == "morrow-kms@acme-prod.iam.gserviceaccount.com" and src["settings"]["project_id"] == "acme-prod"
    assert ci.sync_source(ORG, src["id"])["items"] == 5      # the DESTROYED version is skipped
    items = {i["name"]: i for i in ci.list_inventory(ORG)}
    assert (items["signer/cryptoKeyVersions/1"]["algorithm"], items["signer/cryptoKeyVersions/1"]["owner"]) == ("RSA-2048", "platform")
    assert items["pq-signer/cryptoKeyVersions/1"]["classification"]["status"] == "compliant"
    assert items["data/cryptoKeyVersions/1"]["algorithm"] == "AES-256"
    assert items["ec/cryptoKeyVersions/1"]["risk"] == "critical"
    assert items["kem/cryptoKeyVersions/1"]["classification"]["status"] == "compliant"
    # The token request goes to Google, never to a token_uri taken from the pasted key file.
    assert not any("evil.example" in c["url"] for c in fake.calls)
    assert_read_only(fake)


# ── Rate limits, auth failures, SSRF, sealing, isolation, scheduling ────────────────────────────

def test_rate_limits_back_off_using_retry_after_then_succeed(env, monkeypatch):
    _, sleeps = env
    answers = iter([(429, {"errors": [{"code": "rate_limit"}]}, {"Retry-After": "7"}),
                    (503, {}, {}), (200, DIGICERT_LIST)])
    use(monkeypatch, {("GET", r"/order/certificate\?"): lambda u, h, d: next(answers)})
    src = ci.add_source(ORG, "digicert", {"api_key": "CCCCCCCCCCCCCCCCCCCCCCCCCC"})
    assert src["account"] == "1 issued orders" and sleeps == [7.0, 2.0]


def test_persistent_rate_limiting_gives_up_with_a_clear_message(env, monkeypatch):
    _, sleeps = env
    use(monkeypatch, {("POST", r"certificatesearch"): (429, {}, {"Retry-After": "120"})})
    with pytest.raises(ci.CertSourceError) as err:
        ci.add_source(ORG, "venafi_cloud", {"region": "us", "api_key": "k-0000000000"})
    assert err.value.status_code == 429 and "rate-limiting" in err.value.detail
    assert sleeps == [60.0] * (ci.MAX_ATTEMPTS - 1)


def test_aws_throttling_exception_is_retried(env, monkeypatch):
    _, sleeps = env
    answers = iter([(400, {"__type": "ThrottlingException", "message": "Rate exceeded"}),
                    (200, {"Keys": [], "Truncated": False})])
    use(monkeypatch, {("POST", r"kms\.eu-west-1"): lambda u, h, d: next(answers)})
    ci.add_source(ORG, "aws_kms", {"access_key_id": "AKIAI44QH8DHBEXAMPLE", "secret_access_key": "x" * 40, "regions": "eu-west-1"})
    assert sleeps == [1.0]


@pytest.mark.parametrize("provider,fields,route,answer,needle", [
    ("keyfactor", {"base_url": "https://kf.acme.example/KeyfactorAPI", "username": "svc", "password": "p"},
     ("GET", r"/Certificates\?"), (401, {"Message": "Authorization has been denied for this request."}), "DOMAIN\\user"),
    ("venafi_cloud", {"region": "us", "api_key": "expired-key-000"},
     ("POST", r"certificatesearch"), (401, {"errors": [{"code": 10501, "message": "Invalid api key"}]}), "Preferences > API Keys"),
    ("venafi_tpp", {"base_url": "tpp.acme.example", "client_id": "c", "username": "u", "password": "p"},
     ("POST", r"/vedauth/authorize/oauth$"), (400, {"error": "invalid_grant", "error_description": "Username/password combination not valid"}),
     "Client ID"),
    ("digicert", {"api_key": "revoked-key-0000"},
     ("GET", r"/order/certificate\?"), (401, {"errors": [{"code": "invalid_api_key", "message": "The specified API key is not valid."}]}),
     "X-DC-DEVKEY"),
    ("aws_kms", {"access_key_id": "AKIAI44QH8DHBEXAMPLE", "secret_access_key": "x" * 40, "regions": "us-east-1"},
     ("POST", r"kms\.us-east-1"), (400, {"__type": "UnrecognizedClientException", "message": "The security token included in the request is invalid."}),
     "kms:ListKeys"),
    ("azure_key_vault", AZ_FIELDS, ("POST", r"login\.microsoftonline\.com"),
     (401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided."}), "client secret"),
])
def test_auth_failures_say_what_to_fix(env, monkeypatch, provider, fields, route, answer, needle):
    use(monkeypatch, {route: answer})
    with pytest.raises(ci.CertSourceError) as err:
        ci.add_source(ORG, provider, fields)
    assert err.value.status_code == 400 and needle in err.value.detail
    assert ci.list_sources(ORG) == []            # nothing stored when the check fails


def test_customer_urls_are_guarded_against_internal_addresses(api, monkeypatch):  # noqa: F811
    from services import gateway_network

    monkeypatch.setattr(ci, "_ready", False)
    monkeypatch.delenv("MORROW_CERT_SOURCES_ALLOW_PRIVATE", raising=False)
    monkeypatch.delenv("MORROW_CODE_HOSTS_ALLOW_PRIVATE", raising=False)

    def private(host):
        raise gateway_network.CheckError("Private, special-use, or mixed DNS answers are blocked")
    monkeypatch.setattr(gateway_network, "public_ips", private)
    for bad in ("https://kf.corp-internal.net", "http://kf.acme.example", "https://user:pw@kf.acme.example",
                "https://kf.acme.example:8443", "https://127.0.0.1", "https://kf.acme.example/api?x=1"):
        with pytest.raises(ci.CertSourceError):
            ci.normalize_server_url(bad)
    with pytest.raises(ci.CertSourceError):
        ci.normalize_vault_url("https://169.254.169.254")
    monkeypatch.setenv("MORROW_CERT_SOURCES_ALLOW_PRIVATE", "1")
    assert ci.normalize_server_url("kf.corp-internal.net:8443/KeyfactorAPI") == "https://kf.corp-internal.net:8443/KeyfactorAPI"
    monkeypatch.delenv("MORROW_CERT_SOURCES_ALLOW_PRIVATE")
    monkeypatch.setenv("MORROW_CODE_HOSTS_ALLOW_PRIVATE", "1")
    assert ci.normalize_server_url("tpp.corp-internal.net", keep_path=False) == "https://tpp.corp-internal.net"


def test_host_is_rechecked_before_every_sync(env, monkeypatch):
    use(monkeypatch, {("GET", r"/Certificates\?"): (200, [])})
    src = ci.add_source(ORG, "keyfactor", {"base_url": "kf.acme.example", "token": "tok-123456"})
    checked = []

    def now_private(host):
        checked.append(host)
        raise ci.CertSourceError(400, f"{host}: now resolves to a private address")
    monkeypatch.setattr(ci, "_require_public_host", now_private)
    with pytest.raises(ci.CertSourceError, match="private address"):
        ci.sync_source(ORG, src["id"])
    assert checked == ["kf.acme.example"]


def test_redirects_are_not_followed(env, monkeypatch):
    use(monkeypatch, {("GET", r"/Certificates\?"): (302, b"", {"Location": "https://10.0.0.5/steal"})})
    with pytest.raises(ci.CertSourceError, match="redirect"):
        ci.add_source(ORG, "keyfactor", {"base_url": "kf.acme.example", "token": "tok-123456"})
    # The real transport refuses redirects too: the urllib handler returns None for every 3xx.
    assert ci._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://10.0.0.5/") is None


def test_credentials_are_sealed_and_connections_are_per_organization(env, monkeypatch):
    use(monkeypatch, digicert_routes())
    src = ci.add_source(ORG, "digicert", {"api_key": "DDDD-very-secret-key-0001"})
    from db_feature_store import feature_conn
    with feature_conn() as conn:
        stored = conn.execute("SELECT secret_enc, settings_json FROM org_cert_sources").fetchone()
    assert "very-secret" not in stored["secret_enc"] and "very-secret" not in stored["settings_json"]
    assert "very-secret" not in json.dumps(ci.list_sources(ORG))
    assert ci.list_sources("org-other") == []
    for fn in (ci.test_source, ci.sync_source):
        with pytest.raises(ci.CertSourceError) as err:
            fn("org-other", src["id"])
        assert err.value.status_code == 404
    assert not ci.remove_source("org-other", src["id"]) and ci.list_sources(ORG)


def test_scheduled_sync_is_off_by_default_and_runs_only_when_due(env, monkeypatch):
    fake = use(monkeypatch, digicert_routes())
    off = ci.add_source(ORG, "digicert", {"api_key": "EEEEEEEEEEEEEEEEEEEE"})
    on = ci.add_source(ORG, "digicert", {"api_key": "FFFFFFFFFFFFFFFFFFFF"}, schedule_hours=24)
    assert off["schedule_hours"] == 0 and off["next_sync_at"] is None and on["next_sync_at"]
    assert ci.run_due_syncs()["due"] == 0
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    fake.calls.clear()
    ran = ci.run_due_syncs(now=later)
    assert ran["due"] == 1 and ran["results"] == [{"id": on["id"], "ok": True, "items": 1}]
    assert all(c["headers"]["X-DC-DEVKEY"] == "FFFFFFFFFFFFFFFFFFFF" for c in fake.calls)
    after = {s["id"]: s for s in ci.list_sources(ORG)}
    assert after[on["id"]]["last_sync_status"] == "ok" and after[off["id"]]["last_sync_at"] is None
    ci.set_schedule(ORG, on["id"], 0)
    assert ci.run_due_syncs(now=later + timedelta(days=30))["due"] == 0
    with pytest.raises(ci.CertSourceError):
        ci.set_schedule(ORG, on["id"], 5)


def test_classification_uses_the_platform_table():
    c = lambda **kw: ci.classify(ci._item(**kw))  # noqa: E731
    assert c(key_algorithm="RSA", key_size=3072)["algorithm"] == "RSA-3072"
    assert c(key_algorithm="RSA", key_size=3072)["risk"] == "high"
    assert c(key_algorithm="EC", key_size=384)["algorithm"] == "EC P-384"
    assert c(key_algorithm="Ed25519")["status"] == "quantum_vulnerable"
    weak = c(key_algorithm="ML-DSA", algorithm_detail="ML_DSA_87", signature_algorithm="sha1RSA")
    assert weak["algorithm"] == "ML-DSA-87" and weak["signature"]["algorithm"] == "sha1RSA" and weak["risk"] == "high"
    assert c(key_algorithm="SLH-DSA", algorithm_detail="PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256")["algorithm"] == "SLH-DSA-SHA2-128s"


# ── Routes ──────────────────────────────────────────────────────────────────────────────────────

def bearer(client, app, role="admin"):
    with app._db() as db:
        app._issuer_create_user(db, f"{role}@acme.example", PASSWORD, "", role, ORG)
    token = client.post("/auth/login", json={"email": f"{role}@acme.example", "password": PASSWORD}).json()["access_token"]
    return {"Authorization": "Bearer " + token}


def test_routes_add_test_sync_list_and_never_return_secrets(env, monkeypatch):
    (client, app), _ = env
    make_org(client, ORG, "Acme")
    use(monkeypatch, digicert_routes())
    auth = bearer(client, app)
    providers = client.get("/cert-sources/providers", headers=auth).json()
    assert {p["id"] for p in providers["providers"]} == set(ci.PROVIDERS) and providers["read_only"] is True
    added = client.post("/cert-sources", headers=auth, json={"provider": "digicert", "fields": {"api_key": "route-secret-key-0001"}})
    assert added.status_code == 200, added.text
    sid = added.json()["connection"]["id"]
    assert client.post(f"/cert-sources/{sid}/test", headers=auth).json()["ok"] is True
    synced = client.post(f"/cert-sources/{sid}/sync", headers=auth)
    assert synced.status_code == 200 and synced.json()["items"] == 1
    listed = client.get("/cert-sources", headers=auth)
    assert "route-secret-key-0001" not in listed.text and listed.json()["connections"][0]["last_sync_status"] == "ok"
    inv = client.get("/v1/cert-inventory", headers=auth).json()
    assert inv["count"] == 1 and inv["items"][0]["risk"] == "critical"
    assert client.put(f"/cert-sources/{sid}/schedule", headers=auth, json={"schedule_hours": 24}).json()["connection"]["schedule_hours"] == 24
    assert client.post("/cert-sources/cs_missing/sync", headers=auth).status_code == 404
    assert client.delete(f"/cert-sources/{sid}", headers=auth).json()["removed"] is True
    assert client.get("/cert-inventory", headers=auth).json()["count"] == 0


def test_viewers_can_read_but_not_connect_or_sync(env, monkeypatch):
    (client, app), _ = env
    make_org(client, ORG, "Acme")
    viewer = bearer(client, app, role="viewer")
    assert client.get("/cert-sources", headers=viewer).status_code == 200
    assert client.post("/cert-sources", headers=viewer, json={"provider": "digicert", "fields": {"api_key": "x" * 20}}).status_code == 403
    assert client.post("/cert-sources/cs_x/sync", headers=viewer).status_code == 403


def test_console_copies_are_identical_and_page_ships():
    root = Path(__file__).resolve().parent
    assert (root / "static" / "index.html").read_bytes() == (root.parent / "frontend" / "index.html").read_bytes()
    assert b"/ui/cert-sources.html" in (root / "static" / "index.html").read_bytes()
    page = (root / "static" / "cert-sources.html").read_text(encoding="utf-8")
    assert "/ui/cert-sources.js" in page and "not against live accounts" in page


def test_tls_scanner_records_certificate_fingerprints():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    import scanner

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    facts = scanner._leaf_cert_facts(cert)
    assert facts["cert_sha1"] == cert.fingerprint(hashes.SHA1()).hex().upper()
    assert len(facts["cert_sha256"]) == 64
