"""Wall mode and display links (services/display_links.py, routers/display_links.py, static/wall.*).

A display link is a read-only credential for exactly one payload. These tests prove: it opens
nothing else, it is stored only as a hash, revoking and expiry stop it, one organization's link
never shows another's data, the payload has an ETag and answers 304, and the screen shows a stale
state instead of inventing a value.
"""

import hashlib
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

from test_invite_landing import api_fixture, make_org  # noqa: F401  (registers the "api" fixture)
from test_crypto_switch import add_scan, audit_actions, bearer

from services import display_links as dl
from services import postgres_rls

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
NOW = datetime(2026, 11, 16, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
def wall(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    make_org(client, "org-other", "Other")
    add_scan("org-acme", "pay.acme.example:443", "X25519", "s1", "2026-11-10T00:00:00Z")
    add_scan("org-acme", "api.acme.example:443", "X25519MLKEM768", "s1", "2026-11-10T00:00:00Z")
    add_scan("org-other", "a.other.example:443", "X25519", "s9", "2026-11-12T00:00:00Z")
    add_scan("org-other", "b.other.example:443", "X25519", "s9", "2026-11-12T00:00:00Z")
    add_scan("org-other", "c.other.example:443", "X25519", "s9", "2026-11-12T00:00:00Z")
    return {"client": client, "app": app,
            "admin": bearer(app, client, "admin"), "viewer": bearer(app, client, "viewer"),
            "other_admin": bearer(app, client, "admin", org="org-other")}


def make(w, who="admin", **body):
    res = w["client"].post("/display-links", headers=w[who], json=body)
    assert res.status_code == 200, res.text
    return res.json()


def screen(w, token, **headers):
    return w["client"].get("/api/public/wall", headers={"X-Display-Token": token, **headers})


def test_table_is_in_the_rls_plan():
    assert "display_links" in postgres_rls.ORG_SCOPED_TABLES
    assert postgres_rls.tenant_column("display_links") == "org_id"


def test_a_link_shows_the_sentence_and_the_chosen_number_with_private_headers(wall):
    link = make(wall, name="Lobby", metric="not_safe")
    assert link["url"].endswith("/wall#t=" + link["token"]) and "?" not in link["url"]
    res = screen(wall, link["token"])
    assert res.status_code == 200
    body = res.json()
    assert body["number"]["value"] == 1 and body["number"]["label"] == "host not yet quantum-safe"
    assert body["number"]["detail"] == "of 2 scanned"
    assert "pay.acme.example" in body["sentence"] and "1 other endpoint" not in body["sentence"]
    assert body["data_as_of"] == "2026-11-10T00:00:00Z"
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert "noindex" in res.headers["X-Robots-Tag"]
    assert res.headers["Cache-Control"] == "no-store"
    assert res.headers["ETag"]


def test_the_admin_can_switch_the_number(wall):
    link = make(wall, metric="safe_share")
    body = screen(wall, link["token"]).json()
    assert body["number"]["value"] == 50 and body["number"]["unit"] == "%"
    res = wall["client"].patch(f"/display-links/{link['id']}", headers=wall["admin"], json={"metric": "time_to_safe"})
    assert res.status_code == 200
    body = screen(wall, link["token"]).json()
    assert body["metric"] == "time_to_safe" and body["number"]["value"] is None
    assert body["number"]["detail"] == "No fire drill has run yet"
    assert wall["client"].patch(f"/display-links/{link['id']}", headers=wall["admin"], json={"metric": "nope"}).status_code == 400
    assert "display_link.update" in audit_actions()


def test_etag_answers_304_until_the_data_changes(wall):
    link = make(wall)
    first = screen(wall, link["token"])
    tag = first.headers["ETag"]
    again = screen(wall, link["token"], **{"If-None-Match": tag})
    assert again.status_code == 304 and again.headers["ETag"] == tag and not again.content
    add_scan("org-acme", "new.acme.example:443", "X25519", "s2", "2026-11-15T00:00:00Z")
    changed = screen(wall, link["token"], **{"If-None-Match": tag})
    assert changed.status_code == 200 and changed.headers["ETag"] != tag
    assert changed.json()["number"]["value"] == 2


def test_only_the_hash_is_stored(wall):
    link = make(wall)
    from db_feature_store import feature_conn

    with feature_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM display_links").fetchall()]
    assert len(rows) == 1
    row = rows[0]
    assert row["token_hash"] == hashlib.sha256(link["token"].encode()).hexdigest()
    assert link["token"] not in " ".join(str(v) for v in row.values())
    listed = wall["client"].get("/display-links", headers=wall["admin"]).json()["links"]
    assert listed and "token" not in listed[0] and "token_hash" not in listed[0]
    assert link["token"] not in str(listed)


def test_the_token_opens_nothing_else(wall):
    link = make(wall)
    c, tok = wall["client"], link["token"]
    for path in ("/display-links", "/assets", "/fire-drills", "/audit/logs", "/auth/context"):
        as_bearer = c.get(path, headers={"Authorization": "Bearer " + tok})
        as_header = c.get(path, headers={"X-Display-Token": tok})
        assert as_bearer.status_code in (401, 403), (path, as_bearer.status_code)
        assert as_header.status_code in (401, 403), (path, as_header.status_code)
    assert c.post("/display-links", headers={"X-Display-Token": tok}, json={}).status_code in (401, 403)
    assert c.delete(f"/display-links/{link['id']}", headers={"X-Display-Token": tok}).status_code in (401, 403)
    # The payload has the sentence, the number and counts: no host list, owners or findings.
    assert set(screen(wall, tok).json()) == {"sentence", "risk_state", "metric", "number", "data_as_of", "hosts"}


def test_missing_or_wrong_tokens_are_refused(wall):
    c = wall["client"]
    assert c.get("/api/public/wall").status_code == 401
    assert screen(wall, "mwd_" + "x" * 43).status_code == 401
    assert screen(wall, "not a token").status_code == 401


def test_revoked_links_stop_and_both_actions_are_audited(wall):
    link = make(wall, name="Lobby")
    assert screen(wall, link["token"]).status_code == 200
    res = wall["client"].delete(f"/display-links/{link['id']}", headers=wall["admin"])
    assert res.status_code == 200 and res.json()["status"] == "revoked"
    gone = screen(wall, link["token"])
    assert gone.status_code == 401 and "revoked" in gone.json()["detail"]
    actions = audit_actions()
    assert "display_link.create" in actions and "display_link.revoke" in actions
    listed = wall["client"].get("/display-links", headers=wall["admin"]).json()["links"]
    assert listed[0]["status"] == "revoked" and listed[0]["revoked_by"]


def test_links_expire(wall, monkeypatch):
    link = make(wall, expires_in_days=1)
    assert link["expires_at"]
    assert screen(wall, link["token"]).status_code == 200
    later = datetime.now(timezone.utc) + timedelta(days=2)
    monkeypatch.setattr(dl, "_now", lambda: later)
    res = screen(wall, link["token"])
    assert res.status_code == 401 and "expired" in res.json()["detail"]
    assert wall["client"].get("/display-links", headers=wall["admin"]).json()["links"][0]["status"] == "expired"
    assert wall["client"].post("/display-links", headers=wall["admin"], json={"expires_in_days": 3}).status_code == 400


def test_last_used_is_recorded(wall):
    link = make(wall)
    assert wall["client"].get("/display-links", headers=wall["admin"]).json()["links"][0]["last_used_at"] is None
    screen(wall, link["token"])
    used = wall["client"].get("/display-links", headers=wall["admin"]).json()["links"][0]
    assert used["last_used_at"] and used["created_by"]


def test_organizations_are_isolated(wall):
    mine = make(wall)
    theirs = make(wall, who="other_admin")
    assert screen(wall, theirs["token"]).json()["number"]["value"] == 3
    assert screen(wall, mine["token"]).json()["number"]["value"] == 1
    assert "other.example" not in screen(wall, mine["token"]).json()["sentence"]
    c = wall["client"]
    assert [x["id"] for x in c.get("/display-links", headers=wall["admin"]).json()["links"]] == [mine["id"]]
    assert c.delete(f"/display-links/{theirs['id']}", headers=wall["admin"]).status_code == 404
    assert c.patch(f"/display-links/{theirs['id']}", headers=wall["admin"], json={"metric": "safe_share"}).status_code == 404
    assert screen(wall, theirs["token"]).status_code == 200


def test_only_admins_manage_links(wall):
    c = wall["client"]
    assert c.get("/display-links", headers=wall["viewer"]).status_code == 403
    assert c.post("/display-links", headers=wall["viewer"], json={}).status_code == 403


def test_the_wall_page_is_private_and_self_contained(wall):
    res = wall["client"].get("/wall")
    assert res.status_code == 200
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert "noindex" in res.headers["X-Robots-Tag"]
    csp = res.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "connect-src 'self'" in csp and "http" not in csp
    html = res.text
    assert not re.search(r'(src|href)="(https?:)?//', html)
    for name in ("wall.js", "wall.css"):
        with open(os.path.join(STATIC, name), encoding="utf-8") as fh:
            text = fh.read()
        assert not re.search(r"https?://", text.split("*/", 1)[1] if name == "wall.js" else text), name


# ── The pure builder ────────────────────────────────────────────────────────────────────────────


def test_no_scan_means_no_number():
    for metric in dl.NUMBER_IDS:
        body = dl.build([], None, metric, NOW)
        assert body["number"]["value"] is None and body["data_as_of"] is None
        assert "no scan" in body["sentence"].lower()


def test_unread_hosts_are_not_counted_as_safe_or_unsafe():
    facts = [{"asset_key": "a:443", "key_exchange": "X25519MLKEM768", "scan_status": "ok", "scanned_at": "2026-11-01T00:00:00Z"},
             {"asset_key": "b:443", "key_exchange": "", "scan_status": "error", "scanned_at": "2026-11-02T00:00:00Z"}]
    body = dl.build(facts, None, "safe_share", NOW)
    assert body["number"]["value"] == 100 and "1 could not be read" in body["number"]["detail"]
    assert body["data_as_of"] == "2026-11-02T00:00:00Z"


def test_time_to_safe_uses_the_latest_drill():
    drill = {"status": "ok", "time_to_safe_days": 12, "days": {"low": 3.2, "likely": 11.5, "high": 40.0},
             "broken": "X25519", "created_at": "2026-11-14T08:00:00Z"}
    body = dl.build([], drill, "time_to_safe", NOW)
    assert body["number"]["value"] == 12 and "range 4–40 days" in body["number"]["detail"]
    assert body["data_as_of"] == "2026-11-14T08:00:00Z"
    blocked = dl.build([], {"status": "blocked", "time_to_safe_days": None, "created_at": "x"}, "time_to_safe", NOW)
    assert blocked["number"]["value"] is None


def test_the_screen_shows_a_stale_state_and_never_a_made_up_value():
    with open(os.path.join(STATIC, "wall.js"), encoding="utf-8") as fh:
        js = fh.read()
    assert "STALE_MS" in js and "Can't reach Morrow. Last updated" in js
    assert 'dataset.state = "stale"' in js
    # Backs off on errors, up to a ceiling, and sends the ETag back.
    assert "Math.pow(2, failures)" in js and "MAX_MS" in js and "If-None-Match" in js
    # The only request it makes, with the token as a header (never in the query string).
    assert re.findall(r'fetch\("([^"]+)"', js) == ["/api/public/wall"]
    assert '"X-Display-Token": token' in js and "?t=" not in js
    # No value without a server value: an absent number renders as a dash, never a zero.
    assert '"–"' in js and "n.value !== null" in js
    with open(os.path.join(STATIC, "wall.css"), encoding="utf-8") as fh:
        css = fh.read()
    assert "prefers-reduced-motion" in css and '[data-state="stale"]' in css
