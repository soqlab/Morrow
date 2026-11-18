"""Make it safe: Done. One confirmed change at the host's DNS provider, then the watch and the proof.

For a hostname whose DNS is hosted on Cloudflare, the fix is a setting Cloudflare already documents:
its edge offers hybrid post-quantum key agreement (X25519MLKEM768) to visitors of every *proxied*
hostname over TLS 1.3, and a "DNS only" (grey cloud) record sends visitors to the origin instead, so
they get none of it. Done turns that record to Proxied, through Cloudflare's API v4, with a token the
person pastes for this one action.

Sources (checked 2026-11-18; the same list is in data/make_safe_recipes.json under ``one_click``):

- Post-quantum in Cloudflare products: visitor key agreement X25519MLKEM768 "for any proxied hostname
  or HTTPS application behind Cloudflare".
  https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-cloudflare-products/
- Post-quantum cryptography: "Cloudflare post-quantum key agreements are only supported in protocols
  based on TLS 1.3 (including HTTP/3)." https://developers.cloudflare.com/ssl/post-quantum-cryptography/
- Proxy status: proxied records answer with Cloudflare anycast addresses instead of the origin's; only
  A, AAAA and CNAME records can be proxied; proxied records have a TTL of Auto (300 s).
  https://developers.cloudflare.com/dns/proxy-status/
- TLS 1.3 setting: PATCH the ``tls_1_3`` zone setting, values on, zrt, off.
  https://developers.cloudflare.com/ssl/edge-certificates/additional-options/tls-13/
- API: GET /zones?name= (Zone Read), GET /zones/{zone}/dns_records?name.exact= (DNS Read or Write),
  PATCH /zones/{zone}/dns_records/{id} (DNS Write), GET and PATCH /zones/{zone}/settings/{setting}
  (Zone Settings Read / Write).
  https://developers.cloudflare.com/api/resources/zones/methods/list/
  https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
  https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/
  https://developers.cloudflare.com/api/resources/zones/subresources/settings/methods/get/
- Token template URLs: /profile/api-tokens?permissionGroupKeys=[{"key":..,"type":..}]&accountId=*&zoneId=all&name=..
  https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/

The rules this module keeps:

- **The token is never kept.** It is an argument of one function call, sent only to
  api.cloudflare.com in an Authorization header, and dropped when the request ends. It is not
  written to the database, the audit log, a log line or an error message; ``_scrub`` removes it from
  anything Cloudflare's own answer might echo.
- **Ownership is the token's access.** The zone must be one the token can read and must contain the
  hostname, or nothing happens.
- **A preview, then exactly that change.** ``preview`` reads and changes nothing; it stores what it
  saw (record ids and their current state, never the token) under a preview id. ``apply`` re-reads
  every record, refuses if anything moved since the preview, and then changes only the one setting
  the preview named. ``undo`` puts back the state the apply recorded, for ``UNDO_SECONDS``.
- **Honest failures.** A token without a permission, a zone that does not contain the host, a record
  Cloudflare cannot proxy: each says which and what to do next.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)

API = "https://api.cloudflare.com/client/v4"
TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1 << 20
#: A preview is good for this long; after it, Done reads the zone again.
PREVIEW_SECONDS = 15 * 60
#: Undo is offered for this long after the change.
UNDO_SECONDS = 24 * 3600
#: Record types Cloudflare can proxy (https://developers.cloudflare.com/dns/proxy-status/).
PROXIABLE_TYPES = ("A", "AAAA", "CNAME")
#: Cloudflare API tokens are opaque strings of URL-safe characters. Anything else is refused unread.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.]{20,200}$")
_ID_RE = re.compile(r"^[a-f0-9]{32}$")

KIND_PROXY = "proxy_record"
KIND_TLS13 = "tls_1_3_on"

#: The token a person creates: the least that does the job. TLS 1.3 needs one more permission, asked
#: for only when that is the change.
TOKEN_NAME = "Morrow Done"
TOKEN_PERMISSIONS = ({"key": "zone", "type": "read"}, {"key": "dns", "type": "edit"})
TLS_TOKEN_PERMISSIONS = TOKEN_PERMISSIONS + ({"key": "zone_settings", "type": "edit"},)
CHECKED_ON = "2026-11-18"

_TABLES_LOCK = threading.Lock()
_TABLES_READY: set = set()


class DoneError(Exception):
    """A refusal with a next step. ``detail`` never contains the token."""

    def __init__(self, status_code: int, error: str, detail: str, next_step: str = "",
                 extra: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.status_code = status_code
        self.error = error
        self.detail = detail
        self.next_step = next_step
        self.extra = extra or {}
        self.retry_after = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"error": self.error, "detail": self.detail}
        if self.next_step:
            out["next_step"] = self.next_step
        out.update(self.extra)
        return out


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> Optional[datetime]:
    try:
        out = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return out if out.tzinfo else out.replace(tzinfo=timezone.utc)


def enabled() -> bool:
    return str(os.getenv("MORROW_MAKE_SAFE_DONE_ENABLED", "1")).strip().lower() not in ("0", "false", "no", "off")


def token_url(permissions: Tuple[Dict[str, str], ...] = TOKEN_PERMISSIONS) -> str:
    """Cloudflare's own token form, pre-filled (template URL format from the docs cited above)."""
    keys = json.dumps(list(permissions), separators=(",", ":"))
    return ("https://dash.cloudflare.com/profile/api-tokens?"
            + urlencode({"permissionGroupKeys": keys, "accountId": "*", "zoneId": "all", "name": TOKEN_NAME},
                        quote_via=quote))


def token_template(zone_hint: str = "", tls: bool = False) -> Dict[str, Any]:
    perms = ["Zone > Zone > Read", "Zone > DNS > Edit"] + (["Zone > Zone Settings > Edit"] if tls else [])
    return {
        "name": TOKEN_NAME,
        "permissions": perms,
        "zone_resources": f"Include > Specific zone > {zone_hint}" if zone_hint else "Include > Specific zone > your zone",
        "ttl": "Optional: set an end date a day from now. Morrow does not keep the token, so it needs no longer.",
        "url": token_url(TLS_TOKEN_PERMISSIONS if tls else TOKEN_PERMISSIONS),
    }


def check_token(token: Any) -> str:
    text = str(token or "").strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not _TOKEN_RE.match(text):
        raise DoneError(400, "token_invalid", "That does not look like a Cloudflare API token.",
                        "Create one with the link below and paste the whole token. It is shown once, after you "
                        "press Create Token.")
    return text


def _scrub(text: Any, token: str) -> str:
    out = str(text or "")
    if token:
        out = out.replace(token, "[token]")
    return out[:300]


# ── The Cloudflare API (replaced in tests) ───────────────────────────────────


def _urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, bytes]:
    """One HTTPS request to api.cloudflare.com. Never logs headers; never follows a redirect."""
    import urllib.error
    import urllib.request

    if not url.startswith(API + "/"):
        raise ValueError("only api.cloudflare.com")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D401
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with opener.open(req, timeout=TIMEOUT_SECONDS) as resp:  # nosec B310  # fixed https://api.cloudflare.com prefix, checked above
            return resp.status, resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        try:
            data = exc.read(MAX_RESPONSE_BYTES)
        except Exception:
            data = b""
        return exc.code, data


#: tests replace this with recorded responses
transport: Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, bytes]] = _urllib_transport


class _CF:
    """The calls Done makes, holding the token only for the life of one request."""

    def __init__(self, token: str):
        self._token = token

    def call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, Any]]:
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json",
                   "User-Agent": "Morrow-MakeSafe-Done/1 (+https://morrow.soqlab.com/check-acceptable-use)"}
        raw = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
        try:
            status, data = transport(method, API + path, headers, raw)
        except Exception as exc:  # the exception text is ours (urllib), never the headers
            logger.warning("make-safe done: Cloudflare API unreachable (%s)", exc.__class__.__name__)
            raise DoneError(502, "provider_unreachable", "Cloudflare's API did not answer.",
                            "Nothing was changed. Try again in a minute.") from None
        try:
            parsed = json.loads(data.decode("utf-8")) if data else {}
        except (ValueError, UnicodeDecodeError):
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        return status, parsed

    def errors(self, body: Dict[str, Any]) -> str:
        msgs = [_scrub(e.get("message"), self._token) for e in (body.get("errors") or []) if isinstance(e, dict)]
        return "; ".join(m for m in msgs if m)[:300]


def _auth_failure(status: int, body: Dict[str, Any], cf: _CF, step: str, permission: str, zone: str = "",
                  tls: bool = False) -> Optional[DoneError]:
    """The honest refusal for a 400/401/403 from Cloudflare, or None when the call succeeded."""
    if status not in (400, 401, 403):
        return None
    said = cf.errors(body)
    codes = {int(e.get("code") or 0) for e in (body.get("errors") or []) if isinstance(e, dict)}
    if status == 401 or codes & {1000, 6003, 6111, 9103, 9106}:
        return DoneError(401, "token_invalid", "Cloudflare did not accept that token.",
                         "Check it was pasted whole, has not expired and was not rolled. Then paste it again.",
                         {"provider_said": said, "token_template": token_template(zone, tls)})
    if status == 403:
        return DoneError(403, "token_scope", f"The token is missing a permission: {permission}. Cloudflare refused to {step}.",
                         f"Edit the token in Cloudflare (My Profile > API Tokens), add {permission} for "
                         f"{zone or 'the zone'}, and paste it again. Nothing was changed.",
                         {"provider_said": said, "missing_permission": permission,
                          "token_template": token_template(zone, tls)})
    return None


def _ok(status: int, body: Dict[str, Any]) -> bool:
    return 200 <= status < 300 and bool(body.get("success", True))


# ── Reading the zone ─────────────────────────────────────────────────────────


def _candidates(host: str) -> List[str]:
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))][:6]


def find_zone(cf: _CF, host: str) -> Dict[str, Any]:
    """The token's zone that contains host: the longest matching zone name. Refuses otherwise."""
    for name in _candidates(host):
        status, body = cf.call("GET", "/zones?" + urlencode({"name": name, "per_page": 5}))
        fail = _auth_failure(status, body, cf, "list zones", "Zone > Zone > Read", name)
        if fail:
            raise fail
        if not _ok(status, body):
            raise DoneError(502, "provider_error", "Cloudflare answered with an error: " + (cf.errors(body) or f"HTTP {status}"),
                            "Nothing was changed. Try again in a minute.")
        for zone in body.get("result") or []:
            zname = str(zone.get("name") or "").lower().rstrip(".")
            if zname and (host == zname or host.endswith("." + zname)) and _ID_RE.match(str(zone.get("id") or "")):
                if str(zone.get("status") or "active") not in ("active",):
                    raise DoneError(409, "zone_not_active",
                                    f"The zone {zname} is {zone.get('status')} on Cloudflare, not active, so a proxied "
                                    "record would not be served by Cloudflare yet.",
                                    "Finish adding the zone in Cloudflare (its nameservers must be Cloudflare's), "
                                    "then press Done again.")
                return {"id": str(zone["id"]), "name": zname}
    status, body = cf.call("GET", "/zones?per_page=50")
    seen = [str(z.get("name") or "") for z in (body.get("result") or [])] if _ok(status, body) else []
    if not seen:
        raise DoneError(403, "token_scope", f"The token cannot see any zone, so it cannot reach {host}.",
                        "Give the token Zone > Zone > Read and Zone > DNS > Edit for the zone that holds "
                        f"{host}, and paste it again. Nothing was changed.",
                        {"missing_permission": "Zone > Zone > Read", "token_template": token_template()})
    raise DoneError(403, "wrong_zone",
                    f"This token opens {len(seen)} zone{'s' if len(seen) != 1 else ''}, and none of them contains {host}. "
                    "Morrow only changes a hostname inside a zone the token proves you control.",
                    f"Create a token for the zone that holds {host} and paste that one. Nothing was changed.",
                    {"token_template": token_template()})


def read_records(cf: _CF, zone: Dict[str, Any], host: str) -> List[Dict[str, Any]]:
    status, body = cf.call("GET", f"/zones/{zone['id']}/dns_records?" + urlencode({"name.exact": host, "per_page": 100}))
    fail = _auth_failure(status, body, cf, "read the DNS records", "Zone > DNS > Edit", zone["name"])
    if fail:
        raise fail
    if not _ok(status, body):
        raise DoneError(502, "provider_error", "Cloudflare answered with an error: " + (cf.errors(body) or f"HTTP {status}"),
                        "Nothing was changed. Try again in a minute.")
    out = []
    for r in body.get("result") or []:
        if str(r.get("type") or "") in PROXIABLE_TYPES and str(r.get("name") or "").lower().rstrip(".") == host:
            out.append({"id": str(r.get("id") or ""), "type": str(r["type"]), "name": host,
                        "content": str(r.get("content") or "")[:255], "proxied": bool(r.get("proxied")),
                        "proxiable": r.get("proxiable", True) is not False, "ttl": int(r.get("ttl") or 1)})
    return [r for r in out if _ID_RE.match(r["id"])]


def read_tls13(cf: _CF, zone: Dict[str, Any]) -> Optional[str]:
    """The zone's TLS 1.3 setting, or None when the token may not read it (it needs no such right)."""
    status, body = cf.call("GET", f"/zones/{zone['id']}/settings/tls_1_3")
    if not _ok(status, body):
        return None
    value = str((body.get("result") or {}).get("value") or "")
    return value if value in ("on", "off", "zrt") else None


# ── Tables (no organisation column: a hostname's own public action, like make_safe_watches) ──


def _db_identity() -> str:
    return (f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}|"
            f"{os.getenv('DATABASE_URL', '')[:12]}")


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with _TABLES_LOCK:
        if identity in _TABLES_READY:
            return
        with feature_conn() as conn:
            # One row per preview; the same row records the apply and the undo. Never a token.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS make_safe_done_changes (
                    id          TEXT PRIMARY KEY,
                    domain      TEXT NOT NULL,
                    provider    TEXT NOT NULL,
                    zone_id     TEXT NOT NULL,
                    zone_name   TEXT NOT NULL,
                    kind        TEXT NOT NULL,
                    before_json TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    applied_at  TEXT NOT NULL DEFAULT '',
                    undone_at   TEXT NOT NULL DEFAULT ''
                )
                """)
            # The audit trail: what was asked, what Cloudflare did, from which (hashed) address.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS make_safe_done_log (
                    id         TEXT PRIMARY KEY,
                    at         TEXT NOT NULL,
                    domain     TEXT NOT NULL,
                    action     TEXT NOT NULL,
                    outcome    TEXT NOT NULL,
                    change_id  TEXT NOT NULL DEFAULT '',
                    zone_name  TEXT NOT NULL DEFAULT '',
                    detail     TEXT NOT NULL DEFAULT '',
                    ip_hash    TEXT NOT NULL DEFAULT ''
                )
                """)
            conn.commit()
        _TABLES_READY.add(identity)


def audit(domain: str, action: str, outcome: str, ip_hash: str = "", change_id: str = "", zone_name: str = "",
          detail: str = "", token: str = "") -> None:
    try:
        init_tables()
        with feature_conn() as conn:
            conn.execute("INSERT INTO make_safe_done_log (id, at, domain, action, outcome, change_id, zone_name, detail, "
                         "ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (secrets.token_hex(16), now_utc().strftime("%Y-%m-%dT%H:%M:%S.%fZ"), domain, action, outcome, change_id, zone_name,
                          _scrub(detail, token), ip_hash))
            conn.commit()
    except Exception as exc:
        logger.warning("make-safe done: audit write failed (%s)", exc.__class__.__name__)


def audit_log(domain: str, limit: int = 50) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute("SELECT at, action, outcome, change_id, zone_name, detail FROM make_safe_done_log "
                            "WHERE domain = ? ORDER BY at DESC LIMIT ?", (domain, int(limit))).fetchall()
    return [dict(r) for r in rows]


def _save(row: Dict[str, Any]) -> None:
    init_tables()
    with feature_conn() as conn:
        conn.execute("DELETE FROM make_safe_done_changes WHERE id = ?", (row["id"],))
        conn.execute("INSERT INTO make_safe_done_changes (id, domain, provider, zone_id, zone_name, kind, before_json, "
                     "status, created_at, applied_at, undone_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (row["id"], row["domain"], row["provider"], row["zone_id"], row["zone_name"], row["kind"],
                      json.dumps(row["before"], separators=(",", ":"), sort_keys=True), row["status"],
                      row["created_at"], row.get("applied_at") or "", row.get("undone_at") or ""))
        # Old previews nobody confirmed carry nothing worth keeping.
        cutoff = iso(now_utc() - timedelta(days=2))
        conn.execute("DELETE FROM make_safe_done_changes WHERE status = 'previewed' AND created_at < ?", (cutoff,))
        conn.commit()


def _load(change_id: str) -> Optional[Dict[str, Any]]:
    if not re.match(r"^[a-f0-9]{32}$", str(change_id or "")):
        return None
    init_tables()
    with feature_conn() as conn:
        row = conn.execute("SELECT id, domain, provider, zone_id, zone_name, kind, before_json, status, created_at, "
                           "applied_at, undone_at FROM make_safe_done_changes WHERE id = ?", (change_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    out["before"] = json.loads(out.pop("before_json") or "{}")
    return out


# ── Preview, apply, undo ─────────────────────────────────────────────────────


def _describe(kind: str, zone: Dict[str, Any], records: List[Dict[str, Any]]) -> Dict[str, Any]:
    if kind == KIND_PROXY:
        lines = [f"{r['name']} {r['type']} {r['content']}: from DNS only to Proxied" for r in records]
        return {
            "kind": kind,
            "title": f"{records[0]['name']} from DNS only to Proxied",
            "lines": lines,
            "records": [{"type": r["type"], "name": r["name"], "content": r["content"], "from": "DNS only",
                         "to": "Proxied"} for r in records],
            "nothing_else": "Nothing else. No other record, setting or zone is touched.",
            "consequences": [
                f"Visitors reach {records[0]['name']} through Cloudflare: its DNS answers become Cloudflare's "
                f"addresses instead of {', '.join(r['content'] for r in records[:3])}.",
                "Visitors see the certificate Cloudflare serves for the hostname (its Universal SSL certificate, "
                "or yours if you uploaded one), not the one on your server.",
                "Cloudflare connects to your server for each request. Under SSL/TLS > Overview, Full (strict) "
                "keeps that leg verified. Only HTTP and HTTPS on Cloudflare's supported ports are proxied.",
                "Caching, request size limits and Cloudflare's security features now apply to this hostname.",
            ] + ([f"The CNAME points at {r['content']}. Some hosting platforms do not support running behind "
                  "Cloudflare's proxy: check theirs before you confirm." for r in records if r["type"] == "CNAME"][:1]),
            "propagation": "Resolvers that cached the old answer keep it until its TTL runs out: "
                           + ", ".join(sorted({_ttl(r["ttl"]) for r in records})) + ".",
        }
    return {
        "kind": kind,
        "title": f"TLS 1.3 for the zone {zone['name']}: from Off to On",
        "lines": [f"Zone {zone['name']}: SSL/TLS > Edge Certificates > TLS 1.3 from Off to On"],
        "records": [],
        "nothing_else": "Nothing else. Records, certificates and other settings stay as they are.",
        "consequences": [
            "Cloudflare offers post-quantum key agreement only over TLS 1.3, so this is the switch that lets "
            "visitors negotiate X25519MLKEM768.",
            f"Applies to every proxied hostname in {zone['name']}. Clients that only speak TLS 1.2 still connect.",
        ],
        "propagation": "Cloudflare applies zone settings within seconds.",
    }


def _ttl(ttl: int) -> str:
    t = int(ttl or 1)
    if t == 1:
        return "Auto (5 minutes)"
    if t >= 7200 and t % 3600 == 0:
        return f"{t // 3600} hours"
    if t >= 120:
        return f"{round(t / 60)} minutes"
    return f"{t} seconds"


def preview(domain: str, token: Any, ip_hash: str = "") -> Dict[str, Any]:
    """What Done would change for domain, read with the token. Changes nothing at Cloudflare."""
    tok = check_token(token)
    cf = _CF(tok)
    try:
        zone = find_zone(cf, domain)
        records = read_records(cf, zone, domain)
        if not records:
            raise DoneError(404, "no_record",
                            f"The zone {zone['name']} has no A, AAAA or CNAME record named exactly {domain}. It may be "
                            "answered by a wildcard record or by another service, so there is no single record to proxy.",
                            "Follow the step-by-step recipe below instead. Nothing was changed.")
        stuck = [r for r in records if not r["proxiable"]]
        if stuck:
            raise DoneError(409, "not_proxiable",
                            f"Cloudflare says the {stuck[0]['type']} record for {domain} cannot be proxied "
                            f"({stuck[0]['content']}).",
                            "Point the record at an address Cloudflare can proxy, or follow the recipe for the "
                            "server that answers it. Nothing was changed.")
        tls = read_tls13(cf, zone)
        grey = [r for r in records if not r["proxied"]]
        note = ""
        if grey:
            kind, before = KIND_PROXY, {"records": [{"id": r["id"], "proxied": False, "type": r["type"],
                                                     "content": r["content"], "ttl": r["ttl"]} for r in grey]}
            if tls == "off":
                note = ("TLS 1.3 is also off for this zone, and Cloudflare offers post-quantum key agreement only over "
                        "TLS 1.3. After this change, Done offers that one next.")
            elif tls is None:
                note = ("Morrow could not read the zone's TLS 1.3 setting with this token (it is on by default). "
                        "If the check after the change still sees a classical key exchange, that is the setting to look at.")
            change = _describe(kind, zone, grey)
        elif tls == "off":
            kind, before = KIND_TLS13, {"tls_1_3": "off"}
            change = _describe(kind, zone, [])
        else:
            audit(domain, "preview", "nothing_to_change", ip_hash, zone_name=zone["name"], token=tok)
            return {"domain": domain, "provider": "cloudflare", "zone": zone["name"], "nothing_to_change": True,
                    "detail": f"{domain} is already Proxied" + (" and TLS 1.3 is on" if tls in ("on", "zrt") else "")
                              + ". Cloudflare should already offer X25519MLKEM768, so the next step is a fresh check.",
                    "token_kept": False}
    except DoneError as exc:
        audit(domain, "preview", exc.error, ip_hash, detail=exc.detail, token=tok)
        raise
    row = {"id": secrets.token_hex(16), "domain": domain, "provider": "cloudflare", "zone_id": zone["id"],
           "zone_name": zone["name"], "kind": kind, "before": before, "status": "previewed",
           "created_at": iso(now_utc())}
    _save(row)
    audit(domain, "preview", "ok", ip_hash, row["id"], zone["name"], change["title"], token=tok)
    out = {"domain": domain, "provider": "cloudflare", "zone": zone["name"], "preview_id": row["id"],
           "expires_in": PREVIEW_SECONDS, "change": change, "note": note, "token_kept": False,
           "undo_window_hours": UNDO_SECONDS // 3600}
    if kind == KIND_TLS13:
        out["needs_permission"] = "Zone > Zone Settings > Edit"
        out["token_template"] = token_template(zone["name"], tls=True)
    return out


def _patch_proxied(cf: _CF, zone: Dict[str, Any], record_id: str, value: bool) -> Dict[str, Any]:
    status, body = cf.call("PATCH", f"/zones/{zone['id']}/dns_records/{record_id}", {"proxied": bool(value)})
    fail = _auth_failure(status, body, cf, "change the DNS record", "Zone > DNS > Edit", zone["name"])
    if fail:
        raise fail
    if not _ok(status, body) or bool((body.get("result") or {}).get("proxied")) is not bool(value):
        raise DoneError(502, "provider_error", "Cloudflare did not make the change: " + (cf.errors(body) or f"HTTP {status}"),
                        "Nothing else was changed. Try again, or switch the record by hand under DNS > Records.")
    return body.get("result") or {}


def _patch_tls13(cf: _CF, zone: Dict[str, Any], value: str) -> None:
    status, body = cf.call("PATCH", f"/zones/{zone['id']}/settings/tls_1_3", {"value": value})
    fail = _auth_failure(status, body, cf, "change the TLS 1.3 setting", "Zone > Zone Settings > Edit", zone["name"],
                         tls=True)
    if fail:
        raise fail
    if not _ok(status, body) or str((body.get("result") or {}).get("value") or "") != value:
        raise DoneError(502, "provider_error", "Cloudflare did not make the change: " + (cf.errors(body) or f"HTTP {status}"),
                        "Nothing else was changed. Try again, or switch it under SSL/TLS > Edge Certificates.")


def _zone_of(cf: _CF, row: Dict[str, Any]) -> Dict[str, Any]:
    zone = find_zone(cf, row["domain"])
    if zone["id"] != row["zone_id"]:
        raise DoneError(403, "wrong_zone", "This token opens a different zone from the one previewed.",
                        "Use the same token you previewed with. Nothing was changed.")
    return zone


def apply(domain: str, preview_id: Any, token: Any, ip_hash: str = "") -> Dict[str, Any]:
    """Make exactly the previewed change, after checking nothing moved since the preview."""
    tok = check_token(token)
    row = _load(str(preview_id or ""))
    if not row or row["domain"] != domain:
        raise DoneError(404, "no_preview", "There is no preview with that id for this domain.",
                        "Press Done again to see what would change. Nothing was changed.")
    if row["status"] != "previewed":
        raise DoneError(409, "already_" + row["status"], f"That change was already {row['status']}.",
                        "Press Done again for a fresh preview.")
    created = _parse(row["created_at"]) or now_utc()
    if (now_utc() - created).total_seconds() > PREVIEW_SECONDS:
        raise DoneError(410, "preview_expired", "That preview is more than 15 minutes old.",
                        "Press Done again: Morrow reads the zone afresh before any change. Nothing was changed.")
    cf = _CF(tok)
    try:
        zone = _zone_of(cf, row)
        if row["kind"] == KIND_PROXY:
            current = {r["id"]: r for r in read_records(cf, zone, domain)}
            wanted = row["before"]["records"]
            for r in wanted:
                now_r = current.get(r["id"])
                if not now_r or now_r["proxied"] is not False or now_r["content"] != r["content"]:
                    raise DoneError(409, "changed_since_preview",
                                    f"The {r['type']} record for {domain} changed after the preview.",
                                    "Press Done again for a fresh preview. Nothing was changed.")
            done: List[str] = []
            try:
                for r in wanted:
                    _patch_proxied(cf, zone, r["id"], True)
                    done.append(r["id"])
            except DoneError:
                for rid in done:  # put back what this request changed before the failure
                    try:
                        _patch_proxied(cf, zone, rid, False)
                    except DoneError:
                        pass
                raise
        else:
            if read_tls13(cf, zone) not in ("off", None):
                raise DoneError(409, "changed_since_preview", "TLS 1.3 is no longer off for this zone.",
                                "Press Done again for a fresh preview. Nothing was changed.")
            _patch_tls13(cf, zone, "on")
    except DoneError as exc:
        audit(domain, "apply", exc.error, ip_hash, row["id"], row["zone_name"], exc.detail, token=tok)
        raise
    now = now_utc()
    row.update(status="applied", applied_at=iso(now))
    _save(row)
    audit(domain, "apply", "ok", ip_hash, row["id"], row["zone_name"],
          "proxied " + ", ".join(f"{r['type']} {r['content']}" for r in row["before"]["records"])
          if row["kind"] == KIND_PROXY else "TLS 1.3 on", token=tok)
    ttls = [int(r.get("ttl") or 1) for r in row["before"].get("records") or []]
    return {"domain": domain, "applied": True, "change_id": row["id"], "kind": row["kind"], "zone": row["zone_name"],
            "applied_at": row["applied_at"], "undo_until": iso(now + timedelta(seconds=UNDO_SECONDS)),
            "propagation_seconds": max([300 if t == 1 else t for t in ttls] or [30]), "token_kept": False}


def undo(domain: str, change_id: Any, token: Any, ip_hash: str = "") -> Dict[str, Any]:
    """Put back the state an apply recorded, for records Done changed and nobody changed since."""
    tok = check_token(token)
    row = _load(str(change_id or ""))
    if not row or row["domain"] != domain or row["status"] not in ("applied", "undone"):
        raise DoneError(404, "no_change", "There is no change with that id for this domain.", "")
    if row["status"] == "undone":
        raise DoneError(409, "already_undone", "That change was already undone.", "")
    applied = _parse(row["applied_at"]) or now_utc()
    if (now_utc() - applied).total_seconds() > UNDO_SECONDS:
        raise DoneError(410, "undo_expired", "Undo is offered for 24 hours after the change.",
                        "Switch it back by hand in Cloudflare: DNS > Records, or SSL/TLS > Edge Certificates.")
    cf = _CF(tok)
    skipped: List[str] = []
    try:
        zone = _zone_of(cf, row)
        if row["kind"] == KIND_PROXY:
            current = {r["id"]: r for r in read_records(cf, zone, domain)}
            for r in row["before"]["records"]:
                now_r = current.get(r["id"])
                if not now_r or now_r["proxied"] is not True:
                    skipped.append(f"{r['type']} {r['content']}")
                    continue
                _patch_proxied(cf, zone, r["id"], False)
        else:
            _patch_tls13(cf, zone, "off")
    except DoneError as exc:
        audit(domain, "undo", exc.error, ip_hash, row["id"], row["zone_name"], exc.detail, token=tok)
        raise
    row.update(status="undone", undone_at=iso(now_utc()))
    _save(row)
    audit(domain, "undo", "ok", ip_hash, row["id"], row["zone_name"],
          ("skipped " + ", ".join(skipped)) if skipped else "", token=tok)
    return {"domain": domain, "undone": True, "change_id": row["id"], "skipped": skipped,
            "detail": ("Put back: " + ("TLS 1.3 is off again." if row["kind"] == KIND_TLS13
                                       else f"{domain} is DNS only again.")
                       + (f" Left alone, because they had changed since: {', '.join(skipped)}." if skipped else "")),
            "token_kept": False}


# ── What the plan says (services/make_safe.plan) ─────────────────────────────


def offer(host: str, detected: Dict[str, Any], safe: bool) -> Optional[Dict[str, Any]]:
    """The one-click offer for a host that is not safe, when its DNS or its edge is Cloudflare."""
    if safe or not enabled():
        return None
    dns = detected.get("dns") or {}
    ns = [str(n).lower() for n in dns.get("ns") or []]
    on_cf_dns = any(n.endswith(".ns.cloudflare.com") for n in ns)
    proxied = detected.get("stack") == "cloudflare"
    if not (on_cf_dns or proxied):
        return None
    if not proxied and detected.get("stack") not in (None, "", "unknown"):
        from services import make_safe

        if make_safe._kind(str(detected.get("stack"))) in ("cdn", "cloud_lb"):
            # Another edge already answers for the host; putting Cloudflare in front of it is not one
            # documented change, so the recipe for that edge stays the fix.
            return None
    if proxied:
        why = (f"{host} is served through Cloudflare but still negotiates a classical key exchange. The usual cause "
               "is TLS 1.3 switched off for the zone; Done reads the zone and changes only what is needed.")
    else:
        why = (f"{host}'s DNS is on Cloudflare ({', '.join(ns[:2])}) but the record is DNS only, so visitors reach "
               "your own server and get none of the post-quantum key agreement Cloudflare offers on proxied hostnames.")
    zone_hint = str(dns.get("ns_zone") or "")
    return {"provider": "cloudflare", "name": "Cloudflare", "why": why, "proxied": proxied, "nameservers": ns[:4],
            "token_template": token_template(zone_hint), "token_kept": False, "checked_on": CHECKED_ON,
            "undo_window_hours": UNDO_SECONDS // 3600}
