"""Gateway control plane. Desired configuration is never treated as runtime evidence."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from contextlib import contextmanager
from urllib.parse import urlsplit

from db_feature_store import feature_conn, postgres_enabled
from services import gateway_network as network
from vault_crypto import decrypt_secret, encrypt_secret


class GatewayError(ValueError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def init_tables():
    with feature_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS gateway_sites (
                id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                hostname TEXT NOT NULL, revision INTEGER NOT NULL, data TEXT NOT NULL,
                UNIQUE(organization_id, hostname)
            );
            CREATE TABLE IF NOT EXISTS gateway_history (
                id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, site_id TEXT NOT NULL,
                version INTEGER NOT NULL, policy TEXT NOT NULL, actor TEXT NOT NULL,
                reason TEXT NOT NULL, created_at REAL NOT NULL,
                UNIQUE(organization_id, site_id, version)
            );
        """)
        conn.commit()


@contextmanager
def connection(org):
    if not org or org == "*":
        raise GatewayError("An authenticated organization is required", 403)
    init_tables()
    with feature_conn() as conn:
        if postgres_enabled():
            conn.execute("SELECT set_config('app.current_organization_id', ?, true)", (org,))
        yield conn


def _read(conn, org, site_id):
    row = conn.execute("SELECT revision, data FROM gateway_sites WHERE id=? AND organization_id=?", (site_id, org)).fetchone()
    if not row:
        raise GatewayError("Gateway site not found", 404)
    value = json.loads(row["data"])
    value["revision"] = int(row["revision"])
    return value


def _save(conn, org, value):
    revision = value["revision"]
    changed = conn.execute("UPDATE gateway_sites SET data=?, revision=revision+1 WHERE id=? AND organization_id=? AND revision=?",
                           (canonical(value), value["id"], org, revision))
    if changed.rowcount != 1:
        raise GatewayError("Site changed during this operation; refresh and retry")
    value["revision"] += 1


def _fresh(value, seconds):
    age = time.time() - float(value or 0)
    return 0 <= age <= seconds


def _owned(site):
    if not _fresh(site.get("ownership_verified_at"), 86400):
        raise GatewayError("Verify both domain and origin ownership before this operation")


def public(site):
    result = {k: v for k, v in site.items() if k not in {"sealed_key"}}
    result["key_configured"] = bool(site.get("sealed_key"))
    proof = site.get("runtime") or {}
    current = _fresh(proof.get("checked_at"), 300) and proof.get("config_hash") == digest(site["policy"]) and proof.get("mode") == site["policy"]["mode"]
    owned = _fresh(site.get("ownership_verified_at"), 86400)
    if not current or not _fresh((site.get("statistics") or {}).get("checked_at"), 300):
        result.pop("statistics", None)
    result["coverage"] = {
        "ownership": "verified" if owned else "verification_required",
        "routing": "signed_gateway_response_verified" if current else "unknown",
        "certificate": "verified" if current else "unknown",
        "filtering": (proof.get("mode", "unknown") if current and owned and proof.get("waf_self_test") is True else "unknown"),
        "desired_mode": site["policy"]["mode"],
        "visitor_pq": "unknown", "origin_pq": "unknown", "origin_bypass": "not_verified",
        "availability": "not_independently_verified",
        "basis": "HTTPS challenge to this hostname and signed customer-managed gateway observation; not an independent security certification",
    }
    result["dns_records"] = [{"type": "TXT", "name": "_airlock-gateway." + host, "value": site["challenge"]}
                             for host in (site["hostname"], urlsplit(site["policy"]["origin_url"]).hostname)]
    return result


def list_sites(org):
    with connection(org) as conn:
        rows = conn.execute("SELECT id FROM gateway_sites WHERE organization_id=? ORDER BY hostname", (org,)).fetchall()
        return [public(_read(conn, org, row["id"])) for row in rows]


def get_site(org, site_id):
    with connection(org) as conn:
        return public(_read(conn, org, site_id))


def _history(conn, org, site, actor, reason):
    conn.execute("INSERT INTO gateway_history (id,organization_id,site_id,version,policy,actor,reason,created_at) VALUES (?,?,?,?,?,?,?,?)",
                 (uuid.uuid4().hex, org, site["id"], site["policy"]["version"], canonical(site["policy"]), actor, reason, time.time()))


def create_site(org, website, origin, actor):
    host = urlsplit(network.origin_url(website)).hostname
    upstream = network.origin_url(origin)
    if host == urlsplit(upstream).hostname:
        raise GatewayError("Use a separate origin hostname to prevent a proxy routing loop", 422)
    with connection(org) as conn:
        if conn.execute("SELECT COUNT(*) FROM gateway_sites WHERE organization_id=?", (org,)).fetchone()[0] >= 50:
            raise GatewayError("Organization gateway limit reached", 429)
        if conn.execute("SELECT id FROM gateway_sites WHERE organization_id=? AND hostname=?", (org, host)).fetchone():
            raise GatewayError("This hostname is already in your workspace")
        site_id = uuid.uuid4().hex
        site = {"id": site_id, "hostname": host, "revision": 1, "created_at": time.time(),
                "challenge": "airlock-verification=" + secrets.token_urlsafe(32), "ownership_verified_at": None,
                "policy": {"site_id": site_id, "hostname": host, "origin_url": upstream, "version": 1,
                           "mode": "observe", "exceptions": [], "retention_hours": 24, "max_body_bytes": 1048576},
                "compatibility": None, "runtime": None}
        conn.execute("INSERT INTO gateway_sites (id,organization_id,hostname,revision,data) VALUES (?,?,?,?,?)",
                     (site_id, org, host, 1, canonical(site)))
        _history(conn, org, site, actor, "Initial observe-only configuration")
        conn.commit()
    return public(site)


def history(org, site_id):
    with connection(org) as conn:
        _read(conn, org, site_id)
        rows = conn.execute("SELECT version,policy,actor,reason,created_at FROM gateway_history WHERE organization_id=? AND site_id=? ORDER BY version DESC LIMIT 100", (org, site_id)).fetchall()
        return [{**dict(row), "policy": json.loads(row["policy"])} for row in rows]


def _snapshot(org, site_id, operation):
    # Persist a cooldown before network I/O; concurrent requests cannot start an unbounded scan.
    with connection(org) as conn:
        site = _read(conn, org, site_id)
        if _fresh(site.get("last_" + operation), 10):
            raise GatewayError("Please wait before repeating this check", 429)
        site["last_" + operation] = time.time()
        _save(conn, org, site)
        conn.commit()
        return site


def _store_snapshot(org, site):
    with connection(org) as conn:
        _save(conn, org, site)
        conn.commit()
    return public(site)


def verify_ownership(org, site_id):
    site = _snapshot(org, site_id, "ownership_check")
    hosts = [site["hostname"], urlsplit(site["policy"]["origin_url"]).hostname]
    checks = {host: site["challenge"] in network.txt_values("_airlock-gateway." + host) for host in hosts}
    site["ownership_checks"] = checks
    site["ownership_verified_at"] = time.time() if all(checks.values()) else None
    return _store_snapshot(org, site)


def compatibility(org, site_id, cases, approval, actor):
    if not approval:
        raise GatewayError("Customer approval is required to send compatibility-check requests", 422)
    site = _snapshot(org, site_id, "compatibility_check")
    _owned(site)
    results = []
    for case in cases:
        try:
            response = network.request(site["hostname"], case["path"], method="HEAD")
            results.append({"name": case["name"], "status": "passed" if response["status"] == case["expected_status"] else "failed",
                            "http_status": response["status"], "latency_ms": response["latency_ms"]})
        except network.CheckError as exc:
            results.append({"name": case["name"], "status": "failed", "error": str(exc)})
    site["compatibility"] = {"checked_at": time.time(), "actor": actor, "results": results,
                             "passed": bool(results) and all(r["status"] == "passed" for r in results),
                             "scope": "HEAD reachability only. Does not verify login, forms, uploads, or WebSocket behavior."}
    site["journey_review"] = None
    return _store_snapshot(org, site)


def review_journeys(org, site_id, checks, actor):
    with connection(org) as conn:
        site = _read(conn, org, site_id)
        _owned(site)
        site["journey_review"] = {"actor": actor, "checked_at": time.time(), "checks": checks,
                                  "basis": "Customer-attested application tests; not platform-executed"}
        _save(conn, org, site)
        conn.commit()
    return public(site)


def _enforcement_reviews(site):
    _owned(site)
    checks = site.get("compatibility") or {}
    review = site.get("journey_review") or {}
    if not checks.get("passed") or not _fresh(checks.get("checked_at"), 86400):
        raise GatewayError("Run passing compatibility checks before enforcement")
    if not _fresh(review.get("checked_at"), 86400) or any(c["result"] == "failed" for c in review.get("checks", [])) or len(review.get("checks", [])) != 4:
        raise GatewayError("Review login, forms, uploads, and WebSocket tests (or explain non-applicability)")


def _can_enforce(site):
    _enforcement_reviews(site)
    runtime = site.get("runtime") or {}
    if not _fresh(runtime.get("checked_at"), 300) or runtime.get("config_hash") != digest(site["policy"]) or runtime.get("mode") != "observe" or runtime.get("waf_self_test") is not True:
        raise GatewayError("Verify the running observe-mode gateway before enabling blocking")


def change_policy(org, site_id, updates, actor, reason, expected_version, rollback_version=None):
    with connection(org) as conn:
        site = _read(conn, org, site_id)
        if site["policy"]["version"] != expected_version:
            raise GatewayError("Policy changed; reload before editing")
        old = site["policy"]
        if rollback_version is not None:
            row = conn.execute("SELECT policy FROM gateway_history WHERE organization_id=? AND site_id=? AND version=?", (org, site_id, rollback_version)).fetchone()
            if not row:
                raise GatewayError("Policy version not found", 404)
            updates = json.loads(row["policy"])
        proposed = {**old, **updates, "version": old["version"] + 1}
        if proposed["mode"] == "enforce" and old["mode"] != "enforce":
            _can_enforce(site)
        site["policy"] = proposed
        site["runtime"] = None
        site.pop("statistics", None)
        _history(conn, org, site, actor, reason)
        _save(conn, org, site)
        conn.commit()
    return public(site)


def bootstrap(org, site_id):
    with connection(org) as conn:
        site = _read(conn, org, site_id)
        _owned(site)
        key = secrets.token_hex(32)
        try:
            site["sealed_key"] = encrypt_secret(key)
        except Exception as exc:
            raise GatewayError("Configure the vault master key before provisioning a gateway", 503) from exc
        site["runtime"] = None
        site.pop("statistics", None)
        _save(conn, org, site)
        conn.commit()
    return {"site": public(site), "secret": key, "policy": site["policy"],
            "warning": "Save the secret once on the gateway. Re-provisioning revokes old observations and requires updating every replica."}


def _key(site):
    try:
        return decrypt_secret(site["sealed_key"])
    except Exception as exc:
        raise GatewayError("Provision the gateway credential first; vault key must be available", 409) from exc


def _challenge(site):
    nonce = secrets.token_hex(24)
    response = network.request(site["hostname"], "/__airlock/challenge?nonce=" + nonce)
    try:
        envelope = json.loads(response["body"])
        if not isinstance(envelope, dict):
            raise ValueError()
        raw = base64.b64decode(envelope["payload"], validate=True)
        expected = hmac.new(_key(site).encode(), raw, hashlib.sha256).hexdigest()
        if response["status"] != 200 or not hmac.compare_digest(expected, envelope["signature"]):
            raise ValueError()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError()
        if payload["nonce"] != nonce or payload["site_id"] != site["id"] or not _fresh(payload["time"], 60):
            raise ValueError()
        if (payload.get("mode") not in ("observe", "enforce")
                or not isinstance(payload.get("config_hash"), str) or not re.fullmatch(r"[a-f0-9]{64}", payload["config_hash"])
                or not isinstance(payload.get("instance"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", payload["instance"])
                or type(payload.get("waf_self_test")) is not bool):
            raise ValueError()
        return payload
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        raise GatewayError("No valid fresh gateway response at this hostname; routing is not verified") from exc


def _statistics(data, proof):
    if (not isinstance(data, dict) or data.get("config_hash") != proof["config_hash"]
            or not isinstance(data.get("instance"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", data["instance"])):
        raise GatewayError("Statistics do not match the observed gateway policy; verify replica rollout")
    def count(value):
        if type(value) is not int or not 0 <= value <= 10000:
            raise ValueError("Invalid bounded counter")
        return value
    result = {key: count(data.get(key, 0)) for key in ("requests", "blocked", "matched", "upstream_errors")}
    rules = data.get("rule_counts", {})
    if not isinstance(rules, dict) or len(rules) > 1000:
        raise ValueError("Invalid rule counters")
    result["rule_counts"] = {}
    for key, value in list(rules.items())[:100]:
        if not re.fullmatch(r"[0-9]{1,7}", key):
            raise ValueError("Invalid rule ID")
        result["rule_counts"][key] = count(value)
    return {**result, "checked_at": time.time(), "instance": data["instance"], "config_hash": data["config_hash"],
            "scope": "One responding gateway process; bounded rolling window, not fleet-wide or lifetime totals"}


def probe(org, site_id, apply=False):
    site = _snapshot(org, site_id, "runtime_check")
    _owned(site)
    try:
        proof = _challenge(site)
        if apply:
            if site["policy"]["mode"] == "enforce":
                _enforcement_reviews(site)
            response = network.request(site["hostname"], "/__airlock/policy", method="PUT",
                                       headers={"Authorization": "Bearer " + _key(site), "Content-Type": "application/json"},
                                       body=canonical(site["policy"]).encode())
            if response["status"] != 200:
                raise GatewayError("Gateway rejected configuration; previous runtime policy remains active")
            proof = _challenge(site)
        site["runtime"] = {"checked_at": time.time(), "config_hash": proof["config_hash"], "mode": proof["mode"],
                           "instance": proof["instance"], "waf_self_test": proof.get("waf_self_test") is True}
        site.pop("runtime_error", None)
        # Private metadata is retrieved only after authenticating the gateway's challenge.
        site.pop("statistics", None)
        response = network.request(site["hostname"], "/__airlock/statistics", headers={"Authorization": "Bearer " + _key(site)})
        if response["status"] == 200:
            data = json.loads(response["body"])
            # Allowlist numeric aggregates only; never trust gateway-provided arbitrary log fields.
            site["statistics"] = _statistics(data, proof)
    except (network.CheckError, GatewayError, ValueError, KeyError, TypeError, OverflowError) as exc:
        site["runtime"] = None
        site.pop("statistics", None)
        site["runtime_error"] = str(exc) if isinstance(exc, (network.CheckError, GatewayError)) else "Invalid gateway observation"
    return _store_snapshot(org, site)


def purge(org, site_id):
    site = _snapshot(org, site_id, "purge")
    _owned(site)
    _challenge(site)
    response = network.request(site["hostname"], "/__airlock/statistics", method="DELETE", headers={"Authorization": "Bearer " + _key(site)})
    if response["status"] != 204:
        raise GatewayError("Gateway did not confirm deletion")
    site.pop("statistics", None)
    site["last_purged_at"] = time.time()
    return _store_snapshot(org, site)
