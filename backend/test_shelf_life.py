"""Shelf-Life in the harvest clock: the vendored catalogue, its checksum, the public endpoint and the
category / jurisdiction mapping (services/shelf_life.py). No network."""

import hashlib
import json
import os
import shutil

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from fastapi.testclient import TestClient

from services import decrypt_window as _dw
from services import shelf_life as sl

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)


@pytest.fixture(autouse=True)
def fresh():
    sl.reset_cache()
    yield
    sl.reset_cache()


def _copy(tmp_path):
    for name in ("v0.1.json", "v0.1.json.sha256"):
        shutil.copy(os.path.join(sl.DATA_DIR, name), tmp_path / name)
    return tmp_path


# ── the vendored file and its checksum ───────────────────────────────────────


def test_the_vendored_file_matches_its_published_and_pinned_checksum():
    with open(os.path.join(sl.DATA_DIR, "v0.1.json"), "rb") as fh:
        data = fh.read()
    with open(os.path.join(sl.DATA_DIR, "v0.1.json.sha256"), encoding="ascii") as fh:
        published = fh.read().split()[0]
    assert hashlib.sha256(data).hexdigest() == published == sl.EXPECTED_SHA256
    cat = sl.catalogue()
    assert cat is not None and cat["edition"] == "0.1" and len(cat["entries"]) == 51
    assert sl.load_error() is None


def test_the_notice_names_title_author_licence_source_and_changes():
    with open(os.path.join(sl.DATA_DIR, "NOTICE"), encoding="utf-8") as fh:
        notice = fh.read()
    for text in ("Shelf-Life", "SOQLAB and contributors", "CC BY 4.0", "creativecommons.org/licenses/by/4.0",
                 "https://github.com/soqlab/shelf-life", "Changes made: none"):
        assert text in notice


def test_git_keeps_the_catalogue_bytes_exact():
    with open(os.path.join(REPO_ROOT, ".gitattributes"), encoding="utf-8") as fh:
        assert "backend/data/shelf-life/** -text" in fh.read()
    with open(os.path.join(REPO_ROOT, ".dockerignore"), encoding="utf-8") as fh:
        assert "!backend/data/shelf-life/**" in fh.read()


def test_a_changed_byte_is_refused(tmp_path):
    d = _copy(tmp_path)
    data = (d / "v0.1.json").read_bytes()
    (d / "v0.1.json").write_bytes(data.replace(b'"max": 130', b'"max": 131', 1))
    with pytest.raises(sl.CatalogueError, match="does not match"):
        sl.load_catalogue(str(d))


def test_a_regenerated_checksum_file_does_not_launder_a_changed_catalogue(tmp_path):
    d = _copy(tmp_path)
    data = (d / "v0.1.json").read_bytes().replace(b'"max": 130', b'"max": 131', 1)
    (d / "v0.1.json").write_bytes(data)
    (d / "v0.1.json.sha256").write_text(hashlib.sha256(data).hexdigest() + "  v0.1.json\n", encoding="ascii")
    with pytest.raises(sl.CatalogueError, match="pinned"):
        sl.load_catalogue(str(d))


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(sl.CatalogueError, match="cannot read"):
        sl.load_catalogue(str(tmp_path))


def test_a_refused_file_falls_back_and_says_why(monkeypatch, tmp_path, caplog):
    d = _copy(tmp_path)
    (d / "v0.1.json").write_bytes(b"{}")
    monkeypatch.setattr(sl, "DATA_DIR", str(d))
    with caplog.at_level("WARNING"):
        assert sl.catalogue() is None
    assert "falls back" in caplog.text
    body = sl.public_payload()
    assert body["available"] is False and "does not match" in body["reason"]
    assert body["attribution"]["source_url"] == sl.SOURCE_URL
    assert "entries" not in body


# ── mapping ─────────────────────────────────────────────────────────────────


def _entries():
    return {e["id"]: e for e in sl.catalogue()["entries"]}


def test_the_clock_uses_the_conservative_end_of_the_range():
    e = _entries()
    assert sl.slider_years(e["health-records/GB"]) == 100
    assert sl.slider_years(e["health-records/US"]) == 130
    assert sl.slider_years({"recommended_confidentiality_years": {"min": 3, "max": 9, "value": 5}}) == 5
    assert max(sl.slider_years(x) for x in e.values()) == sl.YEARS_MAX == _dw.SHELF_YEARS_MAX


def test_every_catalogue_value_fits_the_dial():
    for e in _entries().values():
        rec = e["recommended_confidentiality_years"]
        assert 0 <= rec["min"] <= rec["max"] <= _dw.SHELF_YEARS_MAX, e["id"]
    h = _dw.harvest(True, False, shelf_years=130, crqc_year=2040)
    assert h["shelf_years"] == 130


def test_short_category_names_resolve():
    ids = [c["id"] for c in sl.catalogue()["categories"]]
    assert sl.resolve_category("health", ids) == "health-records"
    assert sl.resolve_category("health-records", ids) == "health-records"
    assert sl.resolve_category("TAX", ids) == "tax-records"
    assert sl.resolve_category("financial", ids) == "financial-account-payment"
    assert sl.resolve_category("nonsense", ids) is None and sl.resolve_category("", ids) is None
    assert len({sl.short_id(i, ids) for i in ids}) == len(ids)


def test_pick_prefers_the_jurisdiction_then_falls_back_and_says_so():
    e = _entries()
    entry, code = sl.pick(e, "health-records", "GB")
    assert entry["id"] == "health-records/GB" and code == "GB"
    # Canada has no health entry in v0.1: the next in the fallback order that has one.
    entry, code = sl.pick(e, "health-records", "CA")
    assert code == "EU" and entry["id"] == "health-records/EU"
    # Germany falls back to EU law, not to the US.
    entry, code = sl.pick(e, "biometric-data", "DE")
    assert code == "EU"
    # The jurisdiction-neutral entry wins for a category that has nothing else.
    entry, code = sl.pick(e, "auth-secrets", "GB")
    assert code == "INT"
    assert sl.pick(e, "no-such-thing", "GB") == (None, None)


@pytest.mark.parametrize("domain,code", [
    ("nhs.uk", "GB"), ("www.bbc.co.uk", "GB"), ("bund.de", "DE"), ("gouv.fr", "EU"), ("europa.eu", "EU"),
    ("canada.ca", "CA"), ("gov.au", "AU"), ("irs.gov", "US"), ("example.us", "US"), ("army.mil", "US"),
    ("example.com", None), ("example.ch", None), ("example.org", None), ("localhost", None), ("", None),
])
def test_tld_to_jurisdiction(domain, code):
    assert sl.jurisdiction_for_domain(domain) == code


# ── the endpoint ─────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "shelf.db"))
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_endpoint_shape_and_cache(client):
    response = client.get("/api/public/shelf-life")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=3600"
    body = response.json()
    assert body["available"] is True and body["edition"] == "0.1" and body["sha256"] == sl.EXPECTED_SHA256
    assert body["attribution"]["licence"] == "CC BY 4.0" and body["attribution"]["changes"] == "none"
    assert body["years_max"] == 130
    assert len(body["categories"]) == 13 and len(body["entries"]) == 51
    assert {"EU", "GB", "US", "DE", "CA", "AU", "INT"} == {j["code"] for j in body["jurisdictions"]}
    health = next(c for c in body["categories"] if c["id"] == "health-records")
    assert health == {"id": "health-records", "short": "health", "name": "Health and medical records",
                      "label": "Health records", "plural": True}
    gb = next(e for e in body["entries"] if e["id"] == "health-records/GB")
    assert (gb["min"], gb["max"], gb["years"], gb["basis"], gb["confidence"]) == (50, 100, 100, "sector_guidance", "medium")
    assert gb["citations"] and all(c["url"].startswith("https://") for c in gb["citations"])
    assert set(gb) == {"id", "category", "jurisdiction", "min", "max", "value", "open_ended", "basis",
                       "basis_words", "confidence", "years", "citations"}
    assert body["tld_jurisdictions"]["uk"] == "GB"
    # Unverified citations never reach the page.
    raw = {e["id"]: e for e in sl.catalogue()["entries"]}
    for e in body["entries"]:
        verified = [b["url"] for b in raw[e["id"]]["legal_basis"] if b["status"] == "verified" and b.get("url")]
        assert [c["url"] for c in e["citations"]] == verified


def test_endpoint_is_anonymous(monkeypatch, tmp_path):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "shelf.db"))
    import app as application

    monkeypatch.setattr(application, "AUTH_REQUIRED", True)
    monkeypatch.setattr(application, "AUTH_MODE", "jwt")
    with TestClient(application.app) as anonymous:
        assert anonymous.get("/api/public/shelf-life").status_code == 200


def test_endpoint_falls_back_when_the_file_is_refused(client, monkeypatch, tmp_path):
    bad = tmp_path / "bad"
    bad.mkdir()
    monkeypatch.setattr(sl, "DATA_DIR", str(bad))
    sl.reset_cache()
    response = client.get("/api/public/shelf-life")
    assert response.status_code == 200 and response.json()["available"] is False
    assert response.headers["cache-control"] == "public, max-age=300"


# ── the page ─────────────────────────────────────────────────────────────────


def test_the_page_reads_the_catalogue_and_keeps_the_fallback_examples():
    with open(os.path.join(HERE, "static", "instrument.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert '"/api/public/shelf-life"' in js and "SHELF_EXAMPLES" in js
    assert 'param("data")' in js and 'param("jur")' in js and 'param("keep")' in js
    assert "tld_jurisdictions" in js and "Shelf-Life v" in js


def test_about_scanner_credits_the_sources():
    from services import watch

    sources = watch.about_scanner()["sources"]
    shelf = next(s for s in sources if "Shelf-Life" in s["name"])
    assert shelf["url"] == sl.SOURCE_URL and "CC BY 4.0" in shelf["note"]
    json.dumps(sources)
