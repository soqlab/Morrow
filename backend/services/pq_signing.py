"""Post-quantum signing for customers: public keys on verified domains, a public record of signatures.

The customer holds the private keys. ``morrow-sign`` (tools/morrow_sign) makes an ML-DSA-65 +
Ed25519 key pair on the customer's machine, signs release files or a manifest of a site's files,
and writes a detached ``.morrow-sig`` file. Morrow only ever receives public keys, signatures and
hashes, never a private key and never the signed file. The byte formats are in
services/pq_signing_format.py.

What this module keeps (every table carries the tenant in ``org_id``; services/postgres_rls.py
lists them all):

  pq_signing_keys           one row per registered public key, never changed after it is written
  pq_signing_key_events     registered / retired / revoked, appended; a key's state is read from these
  pq_signatures             the public record of signatures, appended
  pq_signature_entries      the file list of a signed manifest (path, size, sha512), appended
  pq_signature_revocations  a publisher withdrawing one signature, appended

Nothing here updates or deletes a row of these tables: a change of state is a new row, so the
history a visitor is shown cannot be rewritten afterwards (test_pq_signing checks the SQL).

The rules:

  * A key is accepted only for a domain the organization has verified (DNS TXT, the same check as
    services/domain_verification), only when the TXT record is still published at that moment, and
    only when no other organization verified that domain first. The public key file must carry a
    proof of possession: both private keys signing the registration statement.
  * Rotating registers the new key and retires the old one in the same step.
  * Retired: the key signs nothing new. A signature dated before the retirement still verifies.
  * Revoked (the key may be in someone else's hands): from the moment the customer names, nothing
    signed with the key verifies, except signatures already on Morrow's public record from before
    that moment. A signature date is written by whoever holds the key, so it proves nothing once the
    key is compromised; the time Morrow recorded the signature does.
  * A signature on the record can be withdrawn by the publisher; a withdrawn signature no longer
    verifies, and the withdrawal and its reason are shown.

Public reads (/verify/<domain>, /api/verify/...) are cross-tenant by nature, a stranger reading
another organization's public record, so they run in a named platform scope
(services/tenant_scope.platform_scope), as services/team_join.resolve does.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import INTEGRITY_ERRORS, atomic, feature_conn
from services import pq_signing_format as fmt

MAX_ACTIVE_KEYS_PER_DOMAIN = 10
MAX_MANIFEST_ENTRIES = 10000
MAX_NOTE = 500
MAX_LABEL = 80
#: How far ahead of this server's clock a signature date may be (clock skew on the signer's machine).
FUTURE_SKEW = timedelta(minutes=10)
PUBLIC_LIST_DEFAULT = 50
PUBLIC_LIST_MAX = 200

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS pq_signing_keys (
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        key_id TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        ml_dsa_65 TEXT NOT NULL,
        ed25519 TEXT NOT NULL,
        proof_ml_dsa_65 TEXT NOT NULL,
        proof_ed25519 TEXT NOT NULL,
        rotates TEXT NOT NULL DEFAULT '',
        registered_at TEXT NOT NULL,
        registered_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (domain, key_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pq_signing_keys_org ON pq_signing_keys(org_id, domain)",
    """
    CREATE TABLE IF NOT EXISTS pq_signing_key_events (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        key_id TEXT NOT NULL,
        event TEXT NOT NULL,
        effective_at TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_pq_key_events_once ON pq_signing_key_events(domain, key_id, event)",
    """
    CREATE TABLE IF NOT EXISTS pq_signatures (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        key_id TEXT NOT NULL,
        subject_type TEXT NOT NULL,
        name TEXT NOT NULL,
        size BIGINT NOT NULL,
        sha512 TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        ml_dsa_65 TEXT NOT NULL,
        ed25519 TEXT NOT NULL,
        sig_digest TEXT NOT NULL,
        entry_count INTEGER NOT NULL DEFAULT 0,
        uploaded_by TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_pq_signatures_digest ON pq_signatures(domain, sig_digest)",
    "CREATE INDEX IF NOT EXISTS idx_pq_signatures_recent ON pq_signatures(domain, recorded_at)",
    "CREATE INDEX IF NOT EXISTS idx_pq_signatures_hash ON pq_signatures(domain, sha512)",
    "CREATE INDEX IF NOT EXISTS idx_pq_signatures_org ON pq_signatures(org_id, recorded_at)",
    """
    CREATE TABLE IF NOT EXISTS pq_signature_entries (
        signature_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        path TEXT NOT NULL,
        size BIGINT NOT NULL,
        sha512 TEXT NOT NULL,
        PRIMARY KEY (signature_id, position)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pq_signature_entries_hash ON pq_signature_entries(sha512)",
    """
    CREATE TABLE IF NOT EXISTS pq_signature_revocations (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        domain TEXT NOT NULL,
        signature_id TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        revoked_at TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_pq_signature_revocations_once ON pq_signature_revocations(signature_id)",
)

#: Every table above, for services/postgres_rls.py and the tests.
TABLES = ("pq_signing_keys", "pq_signing_key_events", "pq_signatures", "pq_signature_entries",
          "pq_signature_revocations")

_ready = False
_ready_lock = threading.Lock()


class SigningError(Exception):
    def __init__(self, status_code: int, detail: str, code: str = ""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code


# ── setup ────────────────────────────────────────────────────────────────────

def _now_dt() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return _iso(_now_dt())


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _init() -> None:
    global _ready
    if _ready:
        return
    with _ready_lock:
        if _ready:
            return
        with feature_conn() as conn:
            for ddl in SCHEMA:
                conn.execute(ddl)
            conn.commit()
        _ready = True


def init_tables() -> None:
    """Create this module's tables now (registered with register_deferred_schema in app.py)."""
    global _ready
    _ready = False
    _init()


def daily_upload_limit() -> int:
    try:
        return max(1, int(os.getenv("MORROW_PQ_SIGNING_DAILY_LIMIT", "2000")))
    except ValueError:
        return 2000


def _scope(reason: str):
    from services import tenant_scope

    return tenant_scope.platform_scope(f"post-quantum signing: {reason}")


def _clip(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


# ── domains ──────────────────────────────────────────────────────────────────

def _normalize(domain: Any) -> str:
    from services import domain_verification as dv

    try:
        return dv.normalize_domain(domain)
    except dv.DomainError as exc:
        raise SigningError(exc.status_code, exc.detail, "invalid_domain") from None


def _org_verified(conn: Any, org_id: str, domain: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM org_verified_domains WHERE org_id = ? AND domain = ? AND status = 'verified'",
        (org_id, domain)).fetchone() is not None


def dns_record_present(org_id: str, domain: str) -> bool:
    """The organization's verification TXT record, looked up now. SigningError(503) when DNS can't answer."""
    from services import domain_verification as dv

    dv._init()
    with feature_conn() as conn:
        row = conn.execute("SELECT token FROM org_verified_domains WHERE org_id = ? AND domain = ?",
                           (org_id, domain)).fetchone()
    if not row:
        return False
    try:
        values = dv._txt_values(f"{dv.RECORD_PREFIX}.{domain}")
    except dv.DomainError:
        raise SigningError(503, "We couldn't look up the domain's DNS record just now. Try again in a minute.",
                           "dns_unavailable") from None
    return f"{dv.VALUE_PREFIX}{row['token']}" in values


def _require_domain(org_id: str, domain: str, actor: str = "") -> None:
    """Refuse unless this organization verified the domain, first, and the TXT record is still there."""
    from services import domain_verification as dv

    dv._init()
    with feature_conn() as conn:
        mine = _org_verified(conn, org_id, domain)
    if not mine:
        raise SigningError(409, f"Verify {domain} first, under Domains: Morrow accepts a signing key only for a "
                                "domain your organization has shown it controls.", "domain_not_verified")
    # Whether another organization verified the domain earlier is a cross-tenant question.
    from services import tenant_scope

    with tenant_scope.platform_scope("post-quantum signing: did another organization verify this domain first",
                                     actor=str(actor or "")), feature_conn() as conn:
        rows = conn.execute(
            "SELECT org_id FROM org_verified_domains WHERE domain = ? AND status = 'verified' "
            "ORDER BY verified_at, org_id", (domain,)).fetchall()
    if rows and str(rows[0]["org_id"]) != org_id:
        raise SigningError(409, f"Another organization verified {domain} first, so signing keys for it belong to "
                                "that organization. Contact support if this is your domain.", "domain_claimed")
    if not dns_record_present(org_id, domain):
        raise SigningError(409, f"The DNS record that verified {domain} is no longer published. Publish it again "
                                "and check the domain, then register the key.", "dns_record_missing")


# ── keys ─────────────────────────────────────────────────────────────────────

def _event_id() -> str:
    return "kev_" + secrets.token_hex(10)


def _key_state(key: Dict[str, Any], events: List[Dict[str, Any]], domain_verified: bool) -> Dict[str, Any]:
    retired = next((e for e in events if e["event"] == "retired"), None)
    revoked = next((e for e in events if e["event"] == "revoked"), None)
    status = "revoked" if revoked else "retired" if retired else "active"
    return {
        "status": status,
        "usable": status == "active" and domain_verified,
        "domain_verified": domain_verified,
        "retired_at": retired["effective_at"] if retired else None,
        "revoked_at": revoked["created_at"] if revoked else None,
        "compromised_since": revoked["effective_at"] if revoked else None,
        "revocation_note": revoked["note"] if revoked else "",
    }


def _key_row(r: Any) -> Dict[str, Any]:
    return {
        "org_id": r["org_id"], "domain": r["domain"], "key_id": r["key_id"], "label": r["label"],
        "ml_dsa_65": r["ml_dsa_65"], "ed25519": r["ed25519"], "rotates": r["rotates"] or "",
        "registered_at": r["registered_at"], "registered_by": r["registered_by"],
        "proof": {"ml_dsa_65": r["proof_ml_dsa_65"], "ed25519": r["proof_ed25519"]},
    }


def _event_row(r: Any) -> Dict[str, Any]:
    return {"event": r["event"], "effective_at": r["effective_at"], "note": r["note"], "created_at": r["created_at"],
            "actor": r["actor"]}


_KEY_COLUMNS = ("org_id, domain, key_id, label, ml_dsa_65, ed25519, proof_ml_dsa_65, proof_ed25519, rotates, "
                "registered_at, registered_by")


def _keys_with_state(conn: Any, where: str, params: tuple) -> List[Dict[str, Any]]:
    keys = [_key_row(r) for r in conn.execute(
        f"SELECT {_KEY_COLUMNS} FROM pq_signing_keys WHERE {where} ORDER BY registered_at DESC, key_id",  # nosec B608: the column list and WHERE text are module constants; values are bound
        params).fetchall()]
    if not keys:
        return []
    events: Dict[tuple, List[Dict[str, Any]]] = {}
    verified: Dict[tuple, bool] = {}
    for key in keys:
        ident = (key["domain"], key["key_id"])
        if ident not in events:
            events[ident] = [_event_row(r) for r in conn.execute(
                "SELECT event, effective_at, note, created_at, actor FROM pq_signing_key_events "
                "WHERE domain = ? AND key_id = ? ORDER BY created_at, id", ident).fetchall()]
        owner = (key["org_id"], key["domain"])
        if owner not in verified:
            verified[owner] = _org_verified(conn, *owner)
        key["events"] = events[ident]
        key["state"] = _key_state(key, events[ident], verified[owner])
    return keys


def list_keys(org_id: str) -> List[Dict[str, Any]]:
    from services import domain_verification as dv

    _init()
    dv._init()
    with feature_conn() as conn:
        return _keys_with_state(conn, "org_id = ?", (org_id,))


def _get_key(conn: Any, org_id: str, domain: str, kid: str) -> Optional[Dict[str, Any]]:
    keys = _keys_with_state(conn, "org_id = ? AND domain = ? AND key_id = ?", (org_id, domain, kid))
    return keys[0] if keys else None


def _append_event(conn: Any, org_id: str, domain: str, kid: str, event: str, effective_at: str, note: str,
                  actor: str) -> None:
    conn.execute(
        "INSERT INTO pq_signing_key_events (id, org_id, domain, key_id, event, effective_at, note, created_at, actor) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (_event_id(), org_id, domain, kid, event, effective_at, _clip(note, MAX_NOTE), _now(), _clip(actor, 160)))


def register_key(org_id: str, public_key: Any, *, label: str = "", rotates: str = "", actor: str = "") -> Dict[str, Any]:
    """Register a public key file for its domain. Returns the key, with the retired one when rotating."""
    from services import domain_verification as dv

    try:
        parsed = fmt.parse_public_key(public_key)
    except fmt.FormatError as exc:
        raise SigningError(400, str(exc), "invalid_public_key") from None
    domain = _normalize(parsed["domain"])
    if domain != parsed["domain"]:
        raise SigningError(400, "The domain in the key file is not written in its normal form.", "invalid_public_key")
    _init()
    dv._init()
    _require_domain(org_id, domain, actor)
    kid = parsed["key"]
    rotates = str(rotates or "").strip()
    now = _now()
    with feature_conn() as conn:
        existing = conn.execute("SELECT org_id FROM pq_signing_keys WHERE domain = ? AND key_id = ?",
                                (domain, kid)).fetchone()
        if existing:
            raise SigningError(409, "This key is already registered for this domain. A retired or revoked key "
                                    "cannot be registered again: make a new one with morrow-sign keygen.",
                               "key_exists")
        if rotates:
            old = _get_key(conn, org_id, domain, rotates)
            if not old:
                raise SigningError(404, f"There is no key {rotates} for {domain} to rotate.", "key_not_found")
            if old["state"]["status"] != "active":
                raise SigningError(409, f"Key {rotates} is already {old['state']['status']}.", "key_not_active")
        else:
            active = [k for k in _keys_with_state(conn, "org_id = ? AND domain = ?", (org_id, domain))
                      if k["state"]["status"] == "active"]
            if len(active) >= MAX_ACTIVE_KEYS_PER_DOMAIN:
                raise SigningError(409, f"{domain} has {len(active)} active keys, the most allowed. Rotate or retire "
                                        "one first.", "too_many_keys")
        try:
            with atomic(conn):
                conn.execute(
                    f"INSERT INTO pq_signing_keys ({_KEY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",  # nosec B608: the column list and WHERE text are module constants; values are bound
                    (org_id, domain, kid, _clip(label, MAX_LABEL), fmt.b64(parsed["ml_dsa_65"]),
                     fmt.b64(parsed["ed25519"]), parsed["proof"]["ml_dsa_65"], parsed["proof"]["ed25519"], rotates,
                     now, _clip(actor, 160)))
        except INTEGRITY_ERRORS:
            raise SigningError(409, "This key is already registered for this domain.", "key_exists") from None
        _append_event(conn, org_id, domain, kid, "registered", now,
                      f"replaces {rotates}" if rotates else "", actor)
        if rotates:
            _append_event(conn, org_id, domain, rotates, "retired", now, f"rotated to {kid}", actor)
        conn.commit()
        key = _get_key(conn, org_id, domain, kid)
        retired = _get_key(conn, org_id, domain, rotates) if rotates else None
    return {"key": key, "retired": retired}


def retire_key(org_id: str, domain: Any, kid: str, *, note: str = "", actor: str = "") -> Dict[str, Any]:
    name = _normalize(domain)
    _init()
    with feature_conn() as conn:
        key = _get_key(conn, org_id, name, str(kid or ""))
        if not key:
            raise SigningError(404, f"There is no key {kid} for {name}.", "key_not_found")
        if key["state"]["status"] != "active":
            raise SigningError(409, f"This key is already {key['state']['status']}.", "key_not_active")
        _append_event(conn, org_id, name, key["key_id"], "retired", _now(), note, actor)
        conn.commit()
        return _get_key(conn, org_id, name, key["key_id"])


def revoke_key(org_id: str, domain: Any, kid: str, *, compromised_since: Any = None, note: str = "",
               actor: str = "") -> Dict[str, Any]:
    """Revoke a key that may be in someone else's hands.

    compromised_since: from when the key can no longer be trusted. Signatures recorded on Morrow
    before it keep verifying; none after it, and no unrecorded one, does. Default: the moment the
    key was registered, so nothing it signed verifies any more.
    """
    name = _normalize(domain)
    _init()
    if not _clip(note, MAX_NOTE):
        raise SigningError(400, "Say why the key is revoked. Visitors see this note.", "note_required")
    with feature_conn() as conn:
        key = _get_key(conn, org_id, name, str(kid or ""))
        if not key:
            raise SigningError(404, f"There is no key {kid} for {name}.", "key_not_found")
        if key["state"]["status"] == "revoked":
            raise SigningError(409, "This key is already revoked.", "key_revoked")
        registered = _parse_time(key["registered_at"])
        now = _now_dt()
        if compromised_since in (None, ""):
            since = registered or now
        else:
            since = _parse_time(compromised_since)
            if since is None:
                raise SigningError(400, "compromised_since must be a date and time, like 2026-11-01T00:00:00Z.",
                                   "invalid_time")
        if since > now:
            raise SigningError(400, "compromised_since cannot be in the future.", "invalid_time")
        if registered and since < registered:
            since = registered
        _append_event(conn, org_id, name, key["key_id"], "revoked", _iso(since), note, actor)
        conn.commit()
        return _get_key(conn, org_id, name, key["key_id"])


# ── signatures ───────────────────────────────────────────────────────────────

_SIG_COLUMNS = ("id, org_id, domain, key_id, subject_type, name, size, sha512, signed_at, recorded_at, ml_dsa_65, "
                "ed25519, sig_digest, entry_count, uploaded_by")


def _sig_row(r: Any) -> Dict[str, Any]:
    return {
        "id": r["id"], "domain": r["domain"], "key": r["key_id"], "type": r["subject_type"], "name": r["name"],
        "size": int(r["size"]), "sha512": r["sha512"], "signed_at": r["signed_at"], "recorded_at": r["recorded_at"],
        "ml_dsa_65": r["ml_dsa_65"], "ed25519": r["ed25519"], "entry_count": int(r["entry_count"] or 0),
        "uploaded_by": r["uploaded_by"],
    }


def _attach_revocations(conn: Any, sigs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for sig in sigs:
        row = conn.execute("SELECT note, revoked_at FROM pq_signature_revocations WHERE signature_id = ?",
                           (sig["id"],)).fetchone()
        sig["withdrawn"] = {"at": row["revoked_at"], "note": row["note"]} if row else None
    return sigs


def record_signature(org_id: str, document: Any, *, entries: Any = None, actor: str = "") -> Dict[str, Any]:
    """Put one signature on the public record. Checked against the registered key before it is kept.

    Returns {"signature": ..., "created": bool}; a signature that is already recorded is returned as
    it is (an upload retried by CI is not an error).
    """
    try:
        sig = fmt.parse_signature(document)
    except fmt.FormatError as exc:
        raise SigningError(400, str(exc), "invalid_signature") from None
    clean_entries: List[Dict[str, Any]] = []
    if entries not in (None, []):
        if sig["type"] != "manifest":
            raise SigningError(400, "Only a manifest signature carries a file list.", "invalid_signature")
        try:
            clean_entries = fmt.clean_entries(entries, MAX_MANIFEST_ENTRIES)
        except fmt.FormatError as exc:
            raise SigningError(400, str(exc), "invalid_manifest") from None
        rebuilt = fmt.manifest_bytes(clean_entries)
        if hashlib.sha512(rebuilt).hexdigest() != sig["sha512"] or len(rebuilt) != sig["size"]:
            raise SigningError(400, "The file list does not rebuild the signed manifest: its hash or size differs.",
                               "manifest_mismatch")
    signed_at = _parse_time(sig["signed_at"])
    if signed_at is None or signed_at > _now_dt() + FUTURE_SKEW:
        raise SigningError(400, "The signature is dated in the future. Check the signing machine's clock.",
                           "signed_in_future")
    _init()
    from services import domain_verification as dv

    dv._init()
    digest = fmt.signature_digest(sig)
    with feature_conn() as conn:
        key = _get_key(conn, org_id, sig["domain"], sig["key"])
        if not key:
            raise SigningError(404, f"Key {sig['key']} is not registered for {sig['domain']} in this organization.",
                               "key_not_found")
        if not key["state"]["domain_verified"]:
            raise SigningError(409, f"{sig['domain']} is no longer a verified domain of this organization.",
                               "domain_not_verified")
        if key["state"]["status"] != "active":
            raise SigningError(409, f"Key {sig['key']} is {key['state']['status']}: it signs nothing new.",
                               "key_not_active")
        ml_ok, ed_ok = fmt.verify_signature(sig, fmt.unb64(key["ml_dsa_65"], fmt.ML_DSA_65_PUBLIC_KEY_BYTES, "key"),
                                            fmt.unb64(key["ed25519"], fmt.ED25519_PUBLIC_KEY_BYTES, "key"))
        if not (ml_ok and ed_ok):
            failed = " and ".join(n for n, ok in (("ML-DSA-65", ml_ok), ("Ed25519", ed_ok)) if not ok)
            raise SigningError(400, f"The {failed} signature does not verify against key {sig['key']}.",
                               "bad_signature")
        existing = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? AND sig_digest = ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
                                (sig["domain"], digest)).fetchone()
        if existing:
            return {"signature": _attach_revocations(conn, [_sig_row(existing)])[0], "created": False}
        since = _iso(_now_dt() - timedelta(days=1))
        count = conn.execute("SELECT COUNT(*) AS n FROM pq_signatures WHERE org_id = ? AND recorded_at >= ?",
                             (org_id, since)).fetchone()
        if int(count["n"] or 0) >= daily_upload_limit():
            raise SigningError(429, f"This organization recorded {daily_upload_limit()} signatures in the last 24 "
                                    "hours, the most allowed. Try again later or ask support to raise the limit.",
                               "daily_limit")
        sig_id = "sig_" + secrets.token_hex(10)
        try:
            with atomic(conn):
                conn.execute(
                    f"INSERT INTO pq_signatures ({_SIG_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",  # nosec B608: the column list and WHERE text are module constants; values are bound
                    (sig_id, org_id, sig["domain"], sig["key"], sig["type"], sig["name"], sig["size"], sig["sha512"],
                     sig["signed_at"], _now(), fmt.b64(sig["ml_dsa_65"]), fmt.b64(sig["ed25519"]), digest,
                     len(clean_entries), _clip(actor, 160)))
        except INTEGRITY_ERRORS:
            row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? AND sig_digest = ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
                               (sig["domain"], digest)).fetchone()
            if row:
                return {"signature": _attach_revocations(conn, [_sig_row(row)])[0], "created": False}
            raise
        for position, entry in enumerate(clean_entries):
            conn.execute(
                "INSERT INTO pq_signature_entries (signature_id, org_id, position, path, size, sha512) "
                "VALUES (?, ?, ?, ?, ?, ?)", (sig_id, org_id, position, entry["path"], entry["size"], entry["sha512"]))
        conn.commit()
        row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE id = ?", (sig_id,)).fetchone()  # nosec B608: the column list and WHERE text are module constants; values are bound
        return {"signature": _attach_revocations(conn, [_sig_row(row)])[0], "created": True}


def withdraw_signature(org_id: str, sig_id: str, *, note: str = "", actor: str = "") -> Dict[str, Any]:
    if not _clip(note, MAX_NOTE):
        raise SigningError(400, "Say why the signature is withdrawn. Visitors see this note.", "note_required")
    _init()
    with feature_conn() as conn:
        row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE id = ? AND org_id = ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
                           (str(sig_id or ""), org_id)).fetchone()
        if not row:
            raise SigningError(404, "There is no such signature in this organization.", "signature_not_found")
        try:
            with atomic(conn):
                conn.execute(
                    "INSERT INTO pq_signature_revocations (id, org_id, domain, signature_id, note, revoked_at, actor) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ("srv_" + secrets.token_hex(10), org_id, row["domain"], row["id"], _clip(note, MAX_NOTE), _now(),
                     _clip(actor, 160)))
        except INTEGRITY_ERRORS:
            raise SigningError(409, "This signature is already withdrawn.", "already_withdrawn") from None
        conn.commit()
        return _attach_revocations(conn, [_sig_row(row)])[0]


def org_signatures(org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE org_id = ? ORDER BY recorded_at DESC, id "  # nosec B608: the column list and WHERE text are module constants; values are bound
                            "LIMIT ?", (org_id, max(1, min(int(limit), 500)))).fetchall()
        return _attach_revocations(conn, [_sig_row(r) for r in rows])


def org_withdrawals(org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT r.signature_id, r.domain, r.note, r.revoked_at, r.actor, s.name FROM pq_signature_revocations r "
            "LEFT JOIN pq_signatures s ON s.id = r.signature_id WHERE r.org_id = ? ORDER BY r.revoked_at DESC LIMIT ?",
            (org_id, max(1, min(int(limit), 500)))).fetchall()
    return [{"signature_id": r["signature_id"], "domain": r["domain"], "name": r["name"] or "", "note": r["note"],
             "at": r["revoked_at"], "actor": r["actor"]} for r in rows]


def org_counts(org_id: str) -> Dict[str, Any]:
    _init()
    month_start = _now_dt().replace(day=1, hour=0, minute=0, second=0)
    with feature_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS n, MAX(recorded_at) AS last FROM pq_signatures WHERE org_id = ?",
                             (org_id,)).fetchone()
        month = conn.execute("SELECT COUNT(*) AS n FROM pq_signatures WHERE org_id = ? AND recorded_at >= ?",
                             (org_id, _iso(month_start))).fetchone()
    return {"total": int(total["n"] or 0), "this_month": int(month["n"] or 0), "last_recorded_at": total["last"],
            "month_start": _iso(month_start)}


# ── the public record ───────────────────────────────────────────────────────

def _public_key(key: Dict[str, Any]) -> Dict[str, Any]:
    """A key as strangers see it: who in the organization made each change stays private."""
    out = {k: key[k] for k in ("domain", "key_id", "label", "ml_dsa_65", "ed25519", "rotates", "registered_at",
                               "state", "proof")}
    out["events"] = [{k: e[k] for k in ("event", "effective_at", "note", "created_at")} for e in key["events"]]
    return out


def _public_sig(sig: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in sig.items() if k != "uploaded_by"}
    out["document"] = {"format": fmt.SIGNATURE_FORMAT, **{k: sig[k] for k in (
        "domain", "key", "type", "name", "size", "sha512", "signed_at", "ml_dsa_65", "ed25519")}}
    return out


def public_domain(domain: Any, limit: int = PUBLIC_LIST_DEFAULT) -> Dict[str, Any]:
    """What /verify/<domain> shows: every key with its history, and the latest signatures."""
    from services import domain_verification as dv

    name = _normalize(domain)
    limit = max(1, min(int(limit or PUBLIC_LIST_DEFAULT), PUBLIC_LIST_MAX))
    _init()
    dv._init()
    month_start = _iso(_now_dt().replace(day=1, hour=0, minute=0, second=0))
    with _scope("public record of a domain"), feature_conn() as conn:
        keys = _keys_with_state(conn, "domain = ?", (name,))
        sigs = [_sig_row(r) for r in conn.execute(
            f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? ORDER BY recorded_at DESC, id LIMIT ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
            (name, limit)).fetchall()]
        _attach_revocations(conn, sigs)
        totals = conn.execute("SELECT COUNT(*) AS n, MAX(recorded_at) AS last FROM pq_signatures WHERE domain = ?",
                              (name,)).fetchone()
        month = conn.execute("SELECT COUNT(*) AS n FROM pq_signatures WHERE domain = ? AND recorded_at >= ?",
                             (name, month_start)).fetchone()
    return {
        "domain": name,
        "keys": [_public_key(k) for k in keys],
        "signatures": [_public_sig(s) for s in sigs],
        "counts": {"total": int(totals["n"] or 0), "this_month": int(month["n"] or 0),
                   "last_recorded_at": totals["last"], "active_keys": sum(1 for k in keys if k["state"]["usable"]),
                   "month_start": month_start},
        "generated_at": _now(),
    }


def public_signature(domain: Any, sig_id: str) -> Dict[str, Any]:
    name = _normalize(domain)
    _init()
    with _scope("one public signature"), feature_conn() as conn:
        row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? AND id = ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
                           (name, str(sig_id or ""))).fetchone()
        if not row:
            raise SigningError(404, "There is no such signature on this domain's record.", "signature_not_found")
        sig = _attach_revocations(conn, [_sig_row(row)])[0]
        entries = [{"path": r["path"], "size": int(r["size"]), "sha512": r["sha512"]} for r in conn.execute(
            "SELECT path, size, sha512 FROM pq_signature_entries WHERE signature_id = ? ORDER BY position",
            (sig["id"],)).fetchall()]
    out = _public_sig(sig)
    out["entries"] = entries
    return out


def lookup(domain: Any, sha512: Any, limit: int = 20) -> Dict[str, Any]:
    """Signatures on this domain's record for a file with this SHA-512: signed directly, or listed in a
    signed manifest."""
    name = _normalize(domain)
    digest = str(sha512 or "").strip().lower()
    if not fmt.is_sha512(digest):
        raise SigningError(400, "sha512 must be 128 hex characters.", "invalid_hash")
    _init()
    with _scope("find a file's signature on a domain's record"), feature_conn() as conn:
        direct = [_sig_row(r) for r in conn.execute(
            f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? AND sha512 = ? ORDER BY recorded_at DESC "  # nosec B608: the column list and WHERE text are module constants; values are bound
            "LIMIT ?", (name, digest, limit)).fetchall()]
        listed = conn.execute(
            "SELECT e.signature_id, e.path FROM pq_signature_entries e JOIN pq_signatures s ON s.id = e.signature_id "
            "WHERE e.sha512 = ? AND s.domain = ? ORDER BY s.recorded_at DESC LIMIT ?", (digest, name, limit)).fetchall()
        in_manifests = []
        for r in listed:
            row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE id = ?", (r["signature_id"],)).fetchone()  # nosec B608: the column list and WHERE text are module constants; values are bound
            if row:
                sig = _sig_row(row)
                sig["path"] = r["path"]
                in_manifests.append(sig)
        _attach_revocations(conn, direct + in_manifests)
    return {"domain": name, "sha512": digest, "signatures": [_public_sig(s) for s in direct],
            "in_manifests": [dict(_public_sig(s), path=s["path"]) for s in in_manifests]}


def assess(sig: Dict[str, Any], key: Optional[Dict[str, Any]], record: Optional[Dict[str, Any]],
           file_sha512: Optional[str] = None, file_size: Optional[int] = None) -> Dict[str, Any]:
    """The verdict on one parsed signature, from the public key record and the signature record.

    The same rules run in the browser (static/verify.js) and in morrow-sign verify. Each check is
    reported, so a failure says which one failed.
    """
    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def verdict(valid: bool, reason: str) -> Dict[str, Any]:
        return {"valid": valid, "reason": reason, "checks": checks,
                "recorded": bool(record), "recorded_at": record["recorded_at"] if record else None,
                "signature_id": record["id"] if record else None}

    if file_sha512 is not None:
        if not check("file", file_sha512 == sig["sha512"] and (file_size is None or file_size == sig["size"]),
                     "The file's SHA-512 and size match the signature." if file_sha512 == sig["sha512"]
                     else "The file's SHA-512 differs from the signed one: this is not the file that was signed."):
            return verdict(False, "This file is not the one that was signed.")
    if not check("key", key is not None, "The key is on the domain's public record." if key
                 else f"{sig['domain']} has no key {sig['key']} on its public record."):
        return verdict(False, "The signing key is not registered for this domain.")
    state = key["state"]
    if not check("domain", state["domain_verified"], "The key's owner still controls the domain (DNS verified)."
                 if state["domain_verified"] else "The organization that registered this key no longer has the domain verified."):
        return verdict(False, "The key's owner no longer has this domain verified.")
    ml_ok, ed_ok = fmt.verify_signature(sig, fmt.unb64(key["ml_dsa_65"], fmt.ML_DSA_65_PUBLIC_KEY_BYTES, "key"),
                                        fmt.unb64(key["ed25519"], fmt.ED25519_PUBLIC_KEY_BYTES, "key"))
    check("ml_dsa_65", ml_ok, "ML-DSA-65 (FIPS 204) signature verifies." if ml_ok else "ML-DSA-65 signature does not verify.")
    check("ed25519", ed_ok, "Ed25519 signature verifies." if ed_ok else "Ed25519 signature does not verify.")
    if not (ml_ok and ed_ok):
        return verdict(False, "The signature does not verify: both ML-DSA-65 and Ed25519 must.")
    if record and record.get("withdrawn"):
        check("withdrawn", False, f"Withdrawn by the publisher on {record['withdrawn']['at']}: {record['withdrawn']['note']}")
        return verdict(False, "The publisher withdrew this signature.")
    status = state["status"]
    if status == "revoked":
        since = state["compromised_since"]
        ok = bool(record) and str(record["recorded_at"]) < str(since)
        check("key_status", ok, (f"The key was revoked; this signature was recorded on {record['recorded_at']}, before "
                                 f"the key stopped being trusted ({since}).") if ok else
              f"The key was revoked: nothing it signed is trusted unless Morrow recorded it before {since}.")
        return verdict(ok, "Valid: recorded before the key was revoked." if ok else "The signing key was revoked.")
    if status == "retired":
        ok = str(sig["signed_at"]) <= str(state["retired_at"])
        check("key_status", ok, f"Signed before the key was retired on {state['retired_at']}." if ok else
              f"Signed after the key was retired on {state['retired_at']}.")
        return verdict(ok, "Valid: signed before the key was retired." if ok else "Signed with a retired key.")
    check("key_status", True, "The key is active.")
    return verdict(True, "Valid post-quantum signature." if record else
                   "Valid post-quantum signature. It is not on Morrow's public record.")


def verify_document(document: Any, file_sha512: Optional[str] = None, file_size: Optional[int] = None) -> Dict[str, Any]:
    """POST /api/verify: the verdict on a signature file, against the public record."""
    try:
        sig = fmt.parse_signature(document)
    except fmt.FormatError as exc:
        raise SigningError(400, str(exc), "invalid_signature") from None
    if file_sha512 is not None and not fmt.is_sha512(file_sha512):
        raise SigningError(400, "sha512 must be 128 lowercase hex characters.", "invalid_hash")
    from services import domain_verification as dv

    _init()
    dv._init()
    with _scope("check a signature against a domain's public record"), feature_conn() as conn:
        keys = _keys_with_state(conn, "domain = ? AND key_id = ?", (sig["domain"], sig["key"]))
        row = conn.execute(f"SELECT {_SIG_COLUMNS} FROM pq_signatures WHERE domain = ? AND sig_digest = ?",  # nosec B608: the column list and WHERE text are module constants; values are bound
                           (sig["domain"], fmt.signature_digest(sig))).fetchone()
        record = _attach_revocations(conn, [_sig_row(row)])[0] if row else None
    result = assess(sig, keys[0] if keys else None, record, file_sha512, file_size)
    result["domain"] = sig["domain"]
    result["key"] = sig["key"]
    result["name"] = sig["name"]
    result["signed_at"] = sig["signed_at"]
    return result


def summary_sentence(keys: List[Dict[str, Any]], counts: Dict[str, Any], now: Optional[datetime] = None) -> str:
    """The console's answer first: keys, signatures this month, the last one."""
    active = [k for k in keys if k["state"]["usable"]]
    domains = sorted({k["domain"] for k in active})
    if not keys:
        return "No signing keys yet."
    where = f"for {domains[0]}" if len(domains) == 1 else f"across {len(domains)} domains" if domains else ""
    parts = [f"{len(active)} active key{'' if len(active) == 1 else 's'}" + (f" {where}" if where else "")]
    n = counts.get("this_month", 0)
    parts.append(f"{n} file{'' if n == 1 else 's'} signed this month")
    last = _parse_time(counts.get("last_recorded_at"))
    parts.append(f"last signature {ago(last, now)}" if last else "no signature recorded yet")
    return "; ".join(parts) + "."


def ago(when: datetime, now: Optional[datetime] = None) -> str:
    seconds = max(0, int(((now or _now_dt()) - when).total_seconds()))
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{round(seconds / 60)} minutes ago"
    if seconds < 129600:
        hours = round(seconds / 3600)
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    days = round(seconds / 86400)
    return f"{days} day{'' if days == 1 else 's'} ago"
