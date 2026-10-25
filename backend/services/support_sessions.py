"""Vendor support "view as customer" sessions.

A platform operator (owner, operator or support role) opens a customer's console read-only to see
what the customer sees. The design keeps four promises:

  1. Consent and accountability. Every session carries a reason (and optional ticket), a hard time
     limit of 5-60 minutes, and is written to BOTH the platform admin events and the customer's own
     tenant audit log at start, exchange, revoke and expiry. Every request made with the session is
     journaled against its id (platform_support_requests) and, through the normal role check, also
     lands in the tenant audit log under the actor "support:<session id>".
  2. Customer control. Each organization has an "Allow vendor support access" setting (default off).
     When it is off, support sessions cannot be created, including by platform owners.
  3. No token in a URL. Creation returns a one-time launch code (/ui/#support=<code>). The console
     exchanges it once, within 60 seconds, at POST /auth/support-session/exchange for a short-lived
     signed token that lives only in that tab's sessionStorage. Only a hash of the code is stored.
  4. Read-only with hard limits, enforced in ONE place: handle_request(), called by the auth
     middleware for every request that presents a support token, before any other authentication.

Enforcement model: allow-list, with a deny list layered on top
----------------------------------------------------------------
The route table has ~360 GET routes (and grows). A deny list fails open: any new GET route that
returns secrets is reachable by support until someone remembers to list it. An allow-list fails
closed: a new route is refused in a support view until it is reviewed and added here. The console's
read surface is a stable, enumerable set of route templates, so an allow-list is feasible, and it is
the choice made here. The deny list below is still checked FIRST, as defence in depth: it documents
the categories that must never be allowed and a unit test asserts no allow-list entry matches it.

Rules, in order:
  * the token must verify (signature, issuer, audience, expiry) and carry typ=support_view and a sid;
  * the session must exist, not be revoked, and not be expired (status cached <= 5 s per replica;
    a revoke on this replica takes effect immediately);
  * x-org-id, when sent, must equal the session organization, and so must any {organization_id}
    path parameter or organization_id / org_id / org query parameter;
  * method must be GET or HEAD. The single exception is POST /support-session/end, which can only end
    the presenting session itself;
  * the path must not match DENY_* and must match ALLOWED_GET_ROUTES.

Tokens are signed with the built-in issuer's key (MORROW_AUTH_JWT_SECRET) with role "viewer" and a
subject that can never match an organization member, so the normal role checks treat support as a
viewer. The token is never accepted by the ordinary JWT path because this check runs first.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from db_feature_store import feature_conn
from services import route_paths as _route_paths

logger = logging.getLogger(__name__)

TOKEN_TYPE = "support_view"
MIN_MINUTES, MAX_MINUTES, DEFAULT_MINUTES = 5, 60, 30
MIN_REASON = 10
CODE_TTL_SECONDS = 60
SAFE_METHODS = frozenset({"GET", "HEAD"})
END_PATH = "/support-session/end"
LAUNCH_PREFIX = "/ui/#support="
ALLOWED_CREATE_ROLES = frozenset({"owner", "operator", "support"})

_SID_RE = re.compile(r"^ss_[0-9a-f]{24}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

# ── Route policy ─────────────────────────────────────────────────────────────

#: Never reachable with a support token, whatever the allow-list says. Checked first.
DENY_PREFIXES: Tuple[str, ...] = (
    "/platform", "/admin", "/vendor-admin",           # vendor operations: support must not escalate
    "/vault",                                          # stored credentials and /reveal
    "/auth",                                           # credential management (four reads are allowed below)
    "/integrations/settings", "/integrations/slack/settings", "/integrations/secret-backend",
    "/integrations/cloudflare",                        # API tokens, and live calls to Cloudflare
    "/integrations/webhooks", "/integrations/webhook-events", "/webhooks", "/push/webhooks",
    "/push/subscriptions", "/cbom/webhook/setup",      # webhook secrets, signing keys and delivery payloads
    "/notifications/config", "/tickets/config",        # SMTP / Jira / ServiceNow credentials
    "/compliance-ledger", "/badge", "/trust-passport", "/vendor-attestation", "/api/vendor-attestation",
    "/vendor-attestations/invites",                    # signing and shareable bearer links
    "/airlock/install.sh", "/airlock/install.ps1",     # installers embed enrolment material
    "/cicd-gate/generate-script", "/cicd-gate/generate-yaml",
    "/jobs",                                           # raw job results are not tenant-scoped by id
    "/telemetry/stream",                               # unbounded stream
    "/docs", "/openapi.json", "/redoc",
)
#: Bulk exports and downloads that could exfiltrate a tenant's data in one call.
DENY_EXACT_TEMPLATES: Tuple[str, ...] = (
    "/organizations",                                  # cross-tenant list
    "/organizations/{organization_id}/export",         # GDPR export
    "/audit/logs/export.csv", "/compliance/export.csv", "/cbom", "/cbom.csv",
    "/scans/{scan_id}/export.csv", "/scans/{scan_id}/cbom.json",
    "/blast-radius/export", "/canaries/{canary_id}/export", "/readiness/e2e/export",
    "/security-intents/bundle", "/security-truth/policy-bundle", "/org/quantum-readiness-report.html",
    "/evidence/assets/{asset_key:path}", "/evidence/remediations/{remediation_id}",
    "/evidence/repos/{repo:path}", "/assets/{asset_key:path}/evidence",
    "/validation-jobs/{validation_job_id}/evidence",
    "/remediations/{remediation_id}/pr-readiness-check",  # calls GitHub with stored credentials
)
#: Any path containing one of these words is refused (secrets, reveal, exports, downloads, keys).
DENY_WORDS: Tuple[str, ...] = (
    "reveal", "secret", "credential", "password", "token", "api-key", "apikey", "export", "download",
    "bundle", "audit-package",
)
DENY_SUFFIXES: Tuple[str, ...] = (".csv", ".ndjson", ".zip", ".json", ".sh", ".ps1", ".html", ".xml", ".pdf")

#: Reads a support view may make. Templates use the route table's own syntax, without /v1.
ALLOWED_GET_ROUTES: Tuple[str, ...] = (
    # Console bootstrap and the support banner
    "/auth/config", "/auth/context", "/auth/memberships", "/auth/access-policy",
    "/announcements/active", "/support-session/current", "/health", "/healthz", "/status",
    "/org/support-access", "/org/support-access/history",
    # Posture, risk and reporting
    "/executive-dashboard", "/actuarial/individual", "/board-risk", "/board-risk/leaderboard",
    "/board-risk/regulatory", "/board-risk/weather", "/heatmap", "/fix-next", "/timeline/data", "/search",
    "/metrics/trends", "/metrics/scan/{scan_id}/overview", "/migration-tasks", "/migration-velocity",
    "/crypto-agility", "/crypto-mesh", "/crypto-mesh/profiles", "/dark-matter/map", "/security-graph",
    "/peer-benchmark", "/peer-benchmark/sectors", "/roi-calculator/effort-catalog", "/roi-calculator/sectors",
    "/fips-pq/report", "/hybrid-cert/libraries", "/pq-codegen/targets", "/providers/capabilities",
    "/providers/{provider}/playbook", "/org/compliance-report",
    "/org/{organization_id}/agility-leaderboard", "/org/{organization_id}/crypto-weather",
    "/org/{organization_id}/drift-analytics", "/org/{organization_id}/flight-recorder",
    "/org/{organization_id}/metrics", "/org/{organization_id}/policy", "/org/{organization_id}/qri",
    "/org/{organization_id}/quantum-migrations", "/org/{organization_id}/readiness",
    "/org/{organization_id}/regulatory-alignment", "/org/{organization_id}/vendor-attestations",
    "/organizations/{organization_id}/members",
    # Quantum risk
    "/hndl/dashboard", "/hndl/timeline", "/hndl-canaries", "/qday/countdown", "/qday-forecast",
    "/qday-forecast/milestones", "/qday-forecast/threat-actors", "/q-intel/feed", "/q-intel/model",
    "/quantum-sim/graph", "/blast-radius/graph", "/blast-radius/custom-edges", "/contagion/graph",
    "/canaries", "/canaries/dashboard", "/canaries/tiers", "/canaries/{canary_id}/hit-log",
    "/qtisn/dashboard", "/qtisn/history", "/qtisn/membership",
    # Inventory and scans
    "/assets", "/assets/{asset_key_str}", "/assets/{asset_key_str}/history", "/collections",
    "/collections/{collection_id}", "/tags", "/baselines", "/repositories", "/repositories/{name}",
    "/repos/{repo:path}/gate", "/scans", "/scans/{scan_id}", "/scans/{scan_id}/results",
    "/scans/{scan_id}/diff", "/scans/{scan_id}/migration-plan", "/scans/{scan_id}/compliance/{framework}",
    "/scan-schedules", "/scan-schedules/{schedule_id}", "/schedules", "/schedules/{schedule_id}",
    "/binary/scans", "/binary/scans/{scan_id}", "/mobile-iot/scans", "/mobile-iot/scans/{scan_id}",
    "/mobile-iot/stats", "/sbom/imports", "/sbom/imports/{import_id}/components", "/sast/rules",
    "/dep-scan/signatures", "/cbom/webhook/ingests", "/cicd-gate/scans", "/observatory/dashboard",
    "/observatory/history/{asset_key}", "/kms/history", "/runtime/assets", "/runtime/traffic/observations",
    "/runtime/traffic/topology", "/gateway/sites", "/gateway/sites/{site_id}", "/gateway/sites/{site_id}/history",
    "/airlock/architecture", "/airlock/enterprise-readiness", "/airlock/flight-recorder",
    "/airlock/onboarding-status", "/airlock/policy",
    # Remediation, governance and compliance
    "/remediations", "/remediations/{remediation_id}", "/remediations/{remediation_id}/flight-recorder",
    "/remediations/{remediation_id}/pr-readiness", "/remediations/{remediation_id}/validations",
    "/remediations/branches/cleanup/status", "/remediation-feed", "/work/remediation-feed",
    "/validation/sandbox-profile", "/validation-jobs/{validation_job_id}",
    "/playbooks", "/playbooks/recommend", "/playbooks/progress/assets", "/playbooks/{playbook_id}",
    "/playbooks/{playbook_id}/progress", "/autopilot/dashboard", "/autopilot/tasks",
    "/autonomous-mesh/blueprint", "/autonomous-mesh/capability-truth", "/drift/status", "/drift/events",
    "/drift-prevention/plan", "/emergency-response/types", "/policies", "/policies/active",
    "/policies/templates", "/policies/results/history", "/policies/{policy_id}",
    "/governance/certificates", "/governance/shadow-it", "/crypto-governance/certs",
    "/crypto-governance/shadow-it", "/security-intents", "/security-intents/stored",
    "/security-intents/stored/{intent_id}", "/security-intents/{intent_id}",
    "/compliance/frameworks", "/compliance-mapping", "/compliance-mapping/frameworks",
    "/api/v1/compliance/gate", "/evidence/frameworks", "/regulatory/frameworks",
    "/regulatory/frameworks/{framework_id}", "/regulatory/filings", "/regulatory/filings/{filing_id}",
    "/maturity/domains", "/maturity/assessments", "/maturity/assessments/{assessment_id}",
    "/zk-compliance/proofs", "/zk-compliance/standards", "/sla/status", "/sla/breaches", "/sla/config",
    "/readiness/e2e",
    # Vendors, integrations (read-only views without credentials), developer portal, knowledge
    "/vendor-scorecard", "/vendor-scorecard/summary", "/vendor-scorecard/{vendor_id}",
    "/vendor-assessments", "/vendor-assessments/template", "/vendor-assessments/{assessment_id}",
    "/vendor-assessments/{vendor_name}/history", "/integrations/findings", "/integrations/findings/{finding_id}",
    "/integrations/rules", "/integrations/jira/template", "/integrations/github/pr-events",
    "/integrations/github/status-publishes", "/integrations/github-app/status", "/tickets",
    "/notifications/log", "/push/log", "/digest/config", "/digest/snapshots", "/telemetry/events",
    "/telemetry/kpis", "/telemetry/stats", "/sovereign-copilot/redaction-policy", "/feedback",
    "/dev/findings", "/dev/requests", "/dev/stats", "/dev/teams",
    "/kb/articles", "/kb/articles/{slug}", "/kb/search",
)

_ORG_QUERY_PARAMS = ("organization_id", "org_id", "org")


def _template_regex(template: str) -> "re.Pattern[str]":
    out, pos, names = ["^"], 0, []
    for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_]*)(:path)?\}", template):
        out.append(re.escape(template[pos:match.start()]))
        name = match.group(1)
        group = name if name not in names else f"{name}_{len(names)}"
        names.append(group)
        out.append(f"(?P<{group}>.+)" if match.group(2) else f"(?P<{group}>[^/]+)")
        pos = match.end()
    out.append(re.escape(template[pos:]) + "$")
    return re.compile("".join(out))


_ALLOWED_RE = [(t, _template_regex(t)) for t in ALLOWED_GET_ROUTES]
_DENY_EXACT_RE = [(t, _template_regex(t)) for t in DENY_EXACT_TEMPLATES]


def normalize_path(path: str) -> str:
    """The canonical route this request reaches. See services/route_paths.py.

    Case is preserved so ALLOWED_GET_ROUTES templates still match; denied_reason() lowercases for
    its own comparisons. Every /v1 prefix is stripped, not just the first, together with duplicate
    and trailing slashes, ``.``/``..`` segments and percent-encoded separators.
    """
    return _route_paths.canonical_path(path)


def denied_reason(route: str) -> str:
    """Why a normalized path is on the deny list, or "" when it is not."""
    lower = route.lower()
    if lower == "/auth" or lower.startswith("/auth/"):
        return "" if lower in {"/auth/config", "/auth/context", "/auth/memberships", "/auth/access-policy"} \
            else "credential management is not available in a support view"
    for prefix in DENY_PREFIXES:
        if prefix == "/auth":
            continue
        if lower == prefix or lower.startswith(prefix + "/") or (prefix.endswith((".sh", ".ps1")) and lower.startswith(prefix)):
            return "this area holds vendor controls, credentials or secrets and is never available in a support view"
    for template, rx in _DENY_EXACT_RE:
        if rx.match(route):
            return "exports and downloads are not available in a support view"
    if any(lower.endswith(s) for s in DENY_SUFFIXES):
        return "file downloads are not available in a support view"
    if any(word in lower for word in DENY_WORDS):
        return "secrets, credentials and exports are not available in a support view"
    return ""


def route_decision(method: str, path: str, org_id: str, query: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    """(allowed, detail). Pure function of the request; the session checks happen before this."""
    verb = str(method or "GET").upper()
    route = normalize_path(path)
    if verb not in SAFE_METHODS:
        if verb == "POST" and route == END_PATH:
            return True, ""
        return False, f"Support view is read-only: {verb} requests are not allowed."
    reason = denied_reason(route)
    if reason:
        return False, f"Support view: {reason}."
    for key in _ORG_QUERY_PARAMS:
        value = str((query or {}).get(key) or "").strip()
        if value and value != org_id:
            return False, "Support view is limited to the organization the session was opened for."
    for template, rx in _ALLOWED_RE:
        match = rx.match(route)
        if not match:
            continue
        params = match.groupdict()
        scoped = [v for k, v in params.items() if k.split("_")[0] == "organization" or k in {"org_id"}]
        if any(v != org_id for v in scoped):
            return False, "Support view is limited to the organization the session was opened for."
        return True, template
    return False, "Support view: this page or endpoint is not on the support read-only allow-list."


# ── Time and storage helpers ─────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cache_seconds() -> float:
    try:
        value = float(os.getenv("MORROW_SUPPORT_SESSION_CACHE_SECONDS", "5") or 5)
    except ValueError:
        value = 5.0
    return max(0.0, min(value, 5.0))  # never longer than 5 seconds


def _db_identity() -> str:
    return f"{os.getenv('MORROW_FEATURE_STORE_BACKEND', '')}|{os.getenv('MORROW_SCANNER_DB', '')}"


_TABLES_READY: set = set()
_LOCK = threading.Lock()
_SESSION_CACHE: Dict[str, Tuple[float, str, Optional[Dict[str, Any]]]] = {}


def init_tables() -> None:
    identity = _db_identity()
    if identity in _TABLES_READY:
        return
    with feature_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS platform_support_sessions (
                id               TEXT PRIMARY KEY,
                organization_id  TEXT NOT NULL,
                operator_id      TEXT NOT NULL DEFAULT '',
                operator_role    TEXT NOT NULL DEFAULT '',
                operator_display TEXT NOT NULL DEFAULT '',
                reason           TEXT NOT NULL DEFAULT '',
                ticket_ref       TEXT NOT NULL DEFAULT '',
                break_glass      INTEGER NOT NULL DEFAULT 0,
                minutes          INTEGER NOT NULL DEFAULT 30,
                created_at       TEXT NOT NULL,
                expires_at       TEXT NOT NULL,
                exchanged_at     TEXT NOT NULL DEFAULT '',
                revoked_at       TEXT NOT NULL DEFAULT '',
                revoked_by       TEXT NOT NULL DEFAULT '',
                revoke_reason    TEXT NOT NULL DEFAULT '',
                last_used_at     TEXT NOT NULL DEFAULT '',
                request_count    INTEGER NOT NULL DEFAULT 0,
                ended_recorded   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_platform_support_sessions_org ON platform_support_sessions(organization_id);
            CREATE INDEX IF NOT EXISTS idx_platform_support_sessions_expires ON platform_support_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS platform_support_codes (
                code_hash   TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                used_at     TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS platform_support_requests (
                id              TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL,
                organization_id TEXT NOT NULL DEFAULT '',
                method          TEXT NOT NULL DEFAULT '',
                path            TEXT NOT NULL DEFAULT '',
                status_code     INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_platform_support_requests_session ON platform_support_requests(session_id);
            CREATE TABLE IF NOT EXISTS platform_support_access (
                organization_id TEXT PRIMARY KEY,
                allowed         INTEGER NOT NULL DEFAULT 0,
                updated_by      TEXT NOT NULL DEFAULT '',
                updated_at      TEXT NOT NULL DEFAULT ''
            );
            """
        )
        conn.commit()
    _TABLES_READY.add(identity)


_SESSION_COLUMNS = (
    "id, organization_id, operator_id, operator_role, operator_display, reason, ticket_ref, break_glass, minutes, "
    "created_at, expires_at, exchanged_at, revoked_at, revoked_by, revoke_reason, last_used_at, request_count, ended_recorded"
)


def session_status(row: Dict[str, Any], now: Optional[datetime] = None) -> str:
    if str(row.get("revoked_at") or ""):
        return "revoked"
    expires = _parse(row.get("expires_at"))
    if not expires or (now or _now()) >= expires:
        return "expired"
    return "active"


def public_session(row: Dict[str, Any]) -> Dict[str, Any]:
    item = {k: row.get(k) for k in (
        "id", "organization_id", "operator_id", "operator_role", "operator_display", "reason", "ticket_ref",
        "minutes", "created_at", "expires_at", "exchanged_at", "revoked_at", "revoked_by", "revoke_reason",
        "last_used_at", "request_count")}
    item["break_glass"] = bool(int(row.get("break_glass") or 0))
    item["request_count"] = int(row.get("request_count") or 0)
    item["status"] = session_status(row)
    expires = _parse(row.get("expires_at"))
    item["seconds_remaining"] = max(0, int((expires - _now()).total_seconds())) if expires and item["status"] == "active" else 0
    return item


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    sid = str(session_id or "").strip()
    if not _SID_RE.match(sid):
        return None
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(f"SELECT {_SESSION_COLUMNS} FROM platform_support_sessions WHERE id = ?", (sid,)).fetchone()
    return dict(row) if row else None


def cached_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Session row, re-read at most every MORROW_SUPPORT_SESSION_CACHE_SECONDS (capped at 5)."""
    identity = _db_identity()
    now = time.monotonic()
    with _LOCK:
        hit = _SESSION_CACHE.get(session_id)
    if hit and hit[1] == identity and now - hit[0] < _cache_seconds():
        return hit[2]
    row = get_session(session_id)
    with _LOCK:
        if len(_SESSION_CACHE) > 2000:
            _SESSION_CACHE.clear()
        _SESSION_CACHE[session_id] = (now, identity, row)
    return row


def _forget(session_id: str) -> None:
    with _LOCK:
        _SESSION_CACHE.pop(session_id, None)


def list_sessions(organization_id: str = "", active: Optional[bool] = None, limit: int = 200) -> List[Dict[str, Any]]:
    init_tables()
    clauses, params = [], []
    now = _iso(_now())
    if organization_id:
        clauses.append("organization_id = ?")
        params.append(str(organization_id))
    if active is True:
        clauses.append("revoked_at = '' AND expires_at > ?")
        params.append(now)
    elif active is False:
        clauses.append("(revoked_at <> '' OR expires_at <= ?)")
        params.append(now)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(int(limit or 200), 1000)))
    with feature_conn() as conn:
        rows = conn.execute(
            f"SELECT {_SESSION_COLUMNS} FROM platform_support_sessions{where} ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [public_session(dict(r)) for r in rows]


# ── Customer setting ─────────────────────────────────────────────────────────


def support_access(organization_id: str) -> Dict[str, Any]:
    init_tables()
    with feature_conn() as conn:
        row = conn.execute(
            "SELECT organization_id, allowed, updated_by, updated_at FROM platform_support_access WHERE organization_id = ?",
            (str(organization_id),),
        ).fetchone()
    if not row:
        return {"organization_id": organization_id, "allowed": False, "updated_by": "", "updated_at": "", "default": True}
    item = dict(row)
    item["allowed"] = bool(int(item.get("allowed") or 0))
    item["default"] = False
    return item


def set_support_access(organization_id: str, allowed: bool, updated_by: str) -> Dict[str, Any]:
    init_tables()
    now = _iso(_now())
    with feature_conn() as conn:
        cur = conn.execute(
            "UPDATE platform_support_access SET allowed = ?, updated_by = ?, updated_at = ? WHERE organization_id = ?",
            (1 if allowed else 0, str(updated_by or "")[:160], now, str(organization_id)),
        )
        if int(cur.rowcount or 0) == 0:
            conn.execute(
                "INSERT INTO platform_support_access (organization_id, allowed, updated_by, updated_at) VALUES (?, ?, ?, ?)",
                (str(organization_id), 1 if allowed else 0, str(updated_by or "")[:160], now),
            )
        conn.commit()
    return support_access(organization_id)


# ── Audit (both logs) ────────────────────────────────────────────────────────

_PLATFORM_EVENT_WRITER: Dict[str, Optional[Callable[..., None]]] = {"fn": None}


def configure(platform_event_writer: Callable[..., None]) -> None:
    """app.py passes its platform admin event writer: (organization_id, action, reason=, details=)."""
    _PLATFORM_EVENT_WRITER["fn"] = platform_event_writer


def audit(session: Dict[str, Any], event: str, *, actor_id: str = "", reason: str = "",
          severity: str = "info", extra: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """Write one support-session lifecycle event to the platform admin events AND the tenant audit log."""
    org = str(session.get("organization_id") or "")
    created, ended = _parse(session.get("created_at")), _parse(session.get("revoked_at")) or _parse(session.get("expires_at"))
    details = {
        "support_session_id": session.get("id"),
        "operator": session.get("operator_id"),
        "operator_display": session.get("operator_display") or session.get("operator_id"),
        "operator_role": session.get("operator_role"),
        "ticket_ref": session.get("ticket_ref") or "",
        "minutes": int(session.get("minutes") or 0),
        "created_at": session.get("created_at"),
        "expires_at": session.get("expires_at"),
        "break_glass": bool(int(session.get("break_glass") or 0)),
        "severity": severity,
        "access": "read-only",
    }
    if event in {"revoked", "expired"} and created and ended:
        details["duration_seconds"] = max(0, int((min(ended, _now()) - created).total_seconds()))
        details["request_count"] = int(session.get("request_count") or 0)
    details.update(extra or {})
    text = reason or str(session.get("reason") or "")
    written = {"platform": False, "tenant": False}
    writer = _PLATFORM_EVENT_WRITER["fn"]
    if writer:
        from services import platform_operators as _operators

        token = None
        if not _operators.CURRENT_OPERATOR.get():
            token = _operators.CURRENT_OPERATOR.set({"actor_id": actor_id or str(session.get("operator_id") or "support"),
                                                     "actor_role": str(session.get("operator_role") or "support")})
        try:
            writer(org, f"support_session.{event}", reason=text[:500], details=details)
            written["platform"] = True
        except Exception as exc:
            logger.warning("[support-sessions] platform event failed: %s", exc.__class__.__name__)
        finally:
            if token is not None:
                _operators.CURRENT_OPERATOR.reset(token)
    try:
        from db import append_audit_log, reset_current_organization_id, set_current_organization_id

        org_token = set_current_organization_id(org)
        try:
            append_audit_log(
                actor_id=(actor_id or f"vendor-support:{session.get('operator_display') or session.get('operator_id')}")[:160],
                actor_role="vendor_support",
                action=f"support_session.{event}",
                resource_type="support_session",
                resource_id=str(session.get("id") or ""),
                decision="allow",
                reason=text[:500],
                details=details,
            )
            written["tenant"] = True
        finally:
            reset_current_organization_id(org_token)
    except Exception as exc:
        logger.warning("[support-sessions] tenant audit failed: %s", exc.__class__.__name__)
    return written


def finalize_expired(organization_id: str = "") -> int:
    """Record the expiry of sessions that ran out without a revoke. Idempotent across replicas."""
    init_tables()
    now = _iso(_now())
    clause, params = "", [now]
    if organization_id:
        clause, params = " AND organization_id = ?", [now, str(organization_id)]
    with feature_conn() as conn:
        rows = conn.execute(
            f"SELECT {_SESSION_COLUMNS} FROM platform_support_sessions "
            "WHERE revoked_at = '' AND ended_recorded = 0 AND expires_at <= ?" + clause + " LIMIT 100",
            tuple(params),
        ).fetchall()
        claimed = []
        for row in rows:
            cur = conn.execute("UPDATE platform_support_sessions SET ended_recorded = 1 WHERE id = ? AND ended_recorded = 0",
                               (row["id"],))
            if int(cur.rowcount or 0) == 1:
                claimed.append(dict(row))
        conn.commit()
    for row in claimed:
        audit(row, "expired", reason="Support session reached its time limit.")
    return len(claimed)


# ── Lifecycle ────────────────────────────────────────────────────────────────


class SupportSessionError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _hash_code(code: str) -> str:
    return hashlib.sha256(("support-launch:" + str(code)).encode("utf-8")).hexdigest()


def _signing_key() -> str:
    from services import auth_issuer

    secret = str(getattr(auth_issuer, "_SECRET", "") or "").strip()
    if not secret:
        raise SupportSessionError(503, "Support sessions need a token signing key: set MORROW_AUTH_JWT_SECRET on the server.")
    return secret


def create_session(*, organization_id: str, operator_id: str, operator_role: str, operator_display: str,
                   reason: str, minutes: int, ticket_ref: str = "", break_glass: bool = False) -> Dict[str, Any]:
    if break_glass or not support_access(organization_id)["allowed"]:
        raise SupportSessionError(403, "Support access requires customer consent; no override is permitted.")
    text = str(reason or "").strip()
    if len(text) < MIN_REASON:
        raise SupportSessionError(400, f"reason must be at least {MIN_REASON} characters.")
    mins = int(minutes or DEFAULT_MINUTES)
    if not MIN_MINUTES <= mins <= MAX_MINUTES:
        raise SupportSessionError(400, f"minutes must be between {MIN_MINUTES} and {MAX_MINUTES}.")
    _signing_key()
    init_tables()
    now = _now()
    sid = "ss_" + secrets.token_hex(12)
    code = secrets.token_urlsafe(32)
    row = {
        "id": sid, "organization_id": str(organization_id), "operator_id": str(operator_id or "")[:160],
        "operator_role": str(operator_role or "")[:32], "operator_display": str(operator_display or operator_id or "")[:160],
        "reason": text[:500], "ticket_ref": str(ticket_ref or "").strip()[:80], "break_glass": 1 if break_glass else 0,
        "minutes": mins, "created_at": _iso(now), "expires_at": _iso(now + timedelta(minutes=mins)),
        "exchanged_at": "", "revoked_at": "", "revoked_by": "", "revoke_reason": "", "last_used_at": "",
        "request_count": 0, "ended_recorded": 0,
    }
    with feature_conn() as conn:
        conn.execute(
            f"INSERT INTO platform_support_sessions ({_SESSION_COLUMNS}) VALUES ({', '.join(['?'] * 18)})",
            tuple(row[c.strip()] for c in _SESSION_COLUMNS.split(",")),
        )
        conn.execute(
            "INSERT INTO platform_support_codes (code_hash, session_id, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, '')",
            (_hash_code(code), sid, _iso(now), _iso(now + timedelta(seconds=CODE_TTL_SECONDS))),
        )
        conn.commit()
    return {"session": public_session(row), "row": row, "code": code, "launch_url": LAUNCH_PREFIX + code,
            "launch_code_expires_in": CODE_TTL_SECONDS}


def mint_token(row: Dict[str, Any]) -> str:
    import jwt
    from services import auth_issuer

    now = int(time.time())
    expires = _parse(row.get("expires_at"))
    exp = int(expires.timestamp()) if expires else now
    display = str(row.get("operator_display") or row.get("operator_id") or "support")
    payload = {
        "typ": TOKEN_TYPE,
        "sid": row["id"],
        "sub": f"support:{row['id']}",
        "act": {"operator": str(row.get("operator_id") or ""), "display": display},
        "role": "viewer",
        "org_id": row["organization_id"],
        "name": f"Vendor support ({display})",
        "iss": auth_issuer._ISSUER,
        "aud": auth_issuer._AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _signing_key(), algorithm="HS256")


def exchange_code(code: str) -> Dict[str, Any]:
    raw = str(code or "").strip()
    if not _CODE_RE.match(raw):
        raise SupportSessionError(400, "Invalid support launch code.")
    init_tables()
    now = _now()
    digest = _hash_code(raw)
    with feature_conn() as conn:
        found = conn.execute(
            "SELECT code_hash, session_id, expires_at, used_at FROM platform_support_codes WHERE code_hash = ?", (digest,)
        ).fetchone()
        if not found:
            raise SupportSessionError(404, "Support launch code not found.")
        if str(found["used_at"] or ""):
            raise SupportSessionError(409, "This support launch link has already been used. Start a new session.")
        expires = _parse(found["expires_at"])
        if not expires or now >= expires:
            raise SupportSessionError(410, "This support launch link has expired (links are valid for 60 seconds).")
        claimed = conn.execute("UPDATE platform_support_codes SET used_at = ? WHERE code_hash = ? AND used_at = ''",
                               (_iso(now), digest))
        if int(claimed.rowcount or 0) != 1:
            conn.rollback()
            raise SupportSessionError(409, "This support launch link has already been used. Start a new session.")
        conn.execute("UPDATE platform_support_sessions SET exchanged_at = ? WHERE id = ?", (_iso(now), found["session_id"]))
        conn.commit()
    row = get_session(found["session_id"])
    if not row or session_status(row) != "active":
        raise SupportSessionError(410, "This support session is no longer active.")
    _forget(row["id"])
    token = mint_token(row)
    audit(row, "exchanged", reason=str(row.get("reason") or ""), extra={"note": "Support console opened (launch link used)."})
    return {"access_token": token, "token_type": "Bearer", "session": public_session(row)}


def revoke_session(session_id: str, *, revoked_by: str, reason: str, organization_id: str = "") -> Dict[str, Any]:
    row = get_session(session_id)
    if not row or (organization_id and row["organization_id"] != organization_id):
        raise SupportSessionError(404, "Support session not found.")
    if str(row.get("revoked_at") or ""):
        return public_session(row)
    if session_status(row) == "expired":
        finalize_expired(row["organization_id"])
        return public_session(get_session(session_id) or row)
    now = _iso(_now())
    with feature_conn() as conn:
        cur = conn.execute(
            "UPDATE platform_support_sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ?, ended_recorded = 1 "
            "WHERE id = ? AND revoked_at = ''",
            (now, str(revoked_by or "")[:160], str(reason or "")[:500], row["id"]),
        )
        conn.commit()
    _forget(row["id"])
    updated = get_session(row["id"]) or row
    if int(cur.rowcount or 0) == 1:
        audit(updated, "revoked", actor_id=str(revoked_by or ""), reason=str(reason or "Support session ended."),
              extra={"revoked_by": revoked_by})
    return public_session(updated)


def record_request(session_id: str, organization_id: str, method: str, path: str, status_code: int) -> None:
    try:
        init_tables()
        now = _iso(_now())
        with feature_conn() as conn:
            conn.execute(
                "INSERT INTO platform_support_requests (id, session_id, organization_id, method, path, status_code, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (uuid.uuid4().hex, session_id, organization_id, str(method)[:10], str(path)[:300], int(status_code), now),
            )
            conn.execute(
                "UPDATE platform_support_sessions SET request_count = request_count + 1, last_used_at = ? WHERE id = ?",
                (now, session_id),
            )
            conn.commit()
    except Exception as exc:  # the journal must never break the request it describes
        logger.warning("[support-sessions] request journal failed: %s", exc.__class__.__name__)


def list_requests(session_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT id, session_id, organization_id, method, path, status_code, created_at FROM platform_support_requests "
            "WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
            (str(session_id), max(1, min(int(limit or 200), 1000))),
        ).fetchall()
    return [dict(r) for r in rows]


CUSTOMER_REQUESTS_PER_SESSION = 500


def customer_request_history(organization_id: str, session_ids: List[str],
                             per_session: int = CUSTOMER_REQUESTS_PER_SESSION) -> Dict[str, Dict[str, Any]]:
    """Pages viewed per session for the customer's own history: path and time only, oldest first.

    Strictly org-scoped: rows must belong to one of session_ids AND to organization_id, so a session id
    from another organization returns nothing. {session_id: {"requests": [{path, at}], "total": n}}."""
    org = str(organization_id or "")
    ids = [str(s) for s in dict.fromkeys(session_ids or []) if s][:200]
    out: Dict[str, Dict[str, Any]] = {sid: {"requests": [], "total": 0} for sid in ids}
    if not org or not ids:
        return out
    init_tables()
    marks = ", ".join("?" for _ in ids)
    with feature_conn() as conn:
        totals = conn.execute(
            f"SELECT session_id, COUNT(*) FROM platform_support_requests WHERE organization_id = ? AND session_id IN ({marks}) "
            "GROUP BY session_id", (org, *ids)).fetchall()
        rows = conn.execute(
            f"SELECT session_id, path, created_at FROM platform_support_requests WHERE organization_id = ? AND session_id IN ({marks}) "
            "ORDER BY created_at ASC, id ASC", (org, *ids)).fetchall()
    for sid, total in totals:
        out[str(sid)]["total"] = int(total or 0)
    limit = max(1, int(per_session))
    for sid, path, created_at in rows:
        bucket = out[str(sid)]["requests"]
        if len(bucket) < limit:
            bucket.append({"path": str(path), "at": created_at})
    return out


# ── Request enforcement ──────────────────────────────────────────────────────


def _unverified_payload(bearer: str) -> Dict[str, Any]:
    import base64

    parts = str(bearer or "").split(".")
    if len(parts) != 3 or len(bearer) > 4096:
        return {}
    try:
        raw = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def looks_like_support_token(bearer: str) -> bool:
    """Cheap routing test (no trust): the token claims to be a support token. Verification follows."""
    return bool(bearer) and _unverified_payload(bearer).get("typ") == TOKEN_TYPE


def authorize(bearer: str, method: str, path: str, header_org: str = "",
              query: Optional[Dict[str, str]] = None) -> Tuple[Optional[Dict[str, Any]], str, int]:
    """(claims, error, status) for a request carrying a support token."""
    import jwt
    from services import auth_issuer

    try:
        secret = _signing_key()
    except SupportSessionError as exc:
        return None, exc.detail, 401
    try:
        claims = jwt.decode(bearer, secret, algorithms=["HS256"], audience=auth_issuer._AUDIENCE, issuer=auth_issuer._ISSUER)
    except jwt.ExpiredSignatureError:
        try:
            stale = jwt.decode(bearer, secret, algorithms=["HS256"], audience=auth_issuer._AUDIENCE,
                               issuer=auth_issuer._ISSUER, options={"verify_exp": False})
            if _SID_RE.match(str(stale.get("sid") or "")):
                row = cached_session(str(stale["sid"]))
                if row:
                    finalize_expired(row["organization_id"])
        except Exception:
            pass
        return None, "Support session has ended: its time limit was reached.", 401
    except Exception:
        return None, "Invalid support session token.", 401
    sid = str(claims.get("sid") or "")
    if claims.get("typ") != TOKEN_TYPE or not _SID_RE.match(sid):
        return None, "Invalid support session token.", 401
    row = cached_session(sid)
    if not row:
        return None, "Support session not found.", 401
    org = str(row["organization_id"])
    if str(claims.get("org_id") or "") != org:
        return None, "Support session token does not match its session.", 401
    from db import set_current_organization_id, reset_current_organization_id
    org_token = set_current_organization_id(org)
    try:
        if not support_access(org)["allowed"]:
            return None, "Support session has ended: customer consent revoked.", 401
    finally:
        reset_current_organization_id(org_token)
    status = session_status(row)
    if status == "revoked":
        return None, "Support session has ended: it was revoked.", 401
    if status == "expired":
        finalize_expired(org)
        return None, "Support session has ended: its time limit was reached.", 401
    if str(header_org or "").strip() and str(header_org).strip() != org:
        return None, "Support session is limited to its own organization (x-org-id does not match).", 403
    allowed, detail = route_decision(method, path, org, query)
    if not allowed:
        return None, detail, 403
    display = str(row.get("operator_display") or row.get("operator_id") or "")
    return {
        "typ": TOKEN_TYPE,
        "sid": sid,
        "sub": f"support:{sid}",
        "user_id": f"support:{sid}",
        "role": "viewer",
        "org_id": org,
        "organization_id": org,
        "act": {"operator": row.get("operator_id"), "display": display},
        "name": f"Vendor support ({display})",
        "auth_method": "support_session",
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
    }, "", 200


async def handle_request(request: Any, call_next: Callable[..., Any], bearer: str) -> Any:
    """The single enforcement point for support tokens, called by the auth middleware."""
    from starlette.concurrency import run_in_threadpool
    from starlette.responses import JSONResponse

    path = request.url.path
    query = {k: v for k, v in request.query_params.items() if k in _ORG_QUERY_PARAMS}
    claims, error, status = await run_in_threadpool(
        authorize, bearer, request.method, path, request.headers.get("x-org-id", ""), query
    )
    sid = str(_unverified_payload(bearer).get("sid") or "")
    if not claims:
        if status == 403 and _SID_RE.match(sid):
            row = await run_in_threadpool(cached_session, sid)
            if row:
                await run_in_threadpool(record_request, sid, row["organization_id"], request.method, normalize_path(path), 403)
        headers = {"x-support-session": "ended"} if status == 401 else {"x-support-session": "denied"}
        return JSONResponse(status_code=status, content={"detail": error, "support_session": True}, headers=headers)
    request.state.auth_claims = claims
    request.state.authenticated = True
    request.state.support_session_id = claims["sid"]
    response = await call_next(request)
    await run_in_threadpool(record_request, claims["sid"], claims["org_id"], request.method,
                            normalize_path(path), int(getattr(response, "status_code", 0) or 0))
    response.headers["x-support-session"] = "read-only"
    return response


def history_from_audit(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fold tenant audit rows for support sessions into one line per session for the customer."""
    by_id: Dict[str, Dict[str, Any]] = {}
    for entry in sorted(entries, key=lambda e: str(e.get("created_at") or "")):
        details = entry.get("details") if isinstance(entry.get("details"), dict) else None
        if details is None:
            try:
                details = json.loads(entry.get("details_json") or "{}")
            except Exception:
                details = {}
        sid = str(entry.get("resource_id") or details.get("support_session_id") or "")
        if not sid:
            continue
        item = by_id.setdefault(sid, {"id": sid, "events": []})
        event = str(entry.get("action") or "").replace("support_session.", "")
        item["events"].append({"event": event, "at": entry.get("created_at")})
        item["operator"] = details.get("operator_display") or details.get("operator") or item.get("operator")
        item["reason"] = entry.get("reason") if event == "started" else item.get("reason") or entry.get("reason")
        item["ticket_ref"] = details.get("ticket_ref") or item.get("ticket_ref") or ""
        item["break_glass"] = bool(details.get("break_glass")) or bool(item.get("break_glass"))
        item["minutes"] = details.get("minutes") or item.get("minutes")
        item["expires_at"] = details.get("expires_at") or item.get("expires_at")
        if event == "started":
            item["started_at"] = entry.get("created_at")
        if event in {"revoked", "expired"}:
            item["ended_at"] = entry.get("created_at")
            item["ended_by"] = event
            if details.get("duration_seconds") is not None:
                item["duration_seconds"] = details.get("duration_seconds")
            if details.get("request_count") is not None:
                item["request_count"] = details.get("request_count")
    out = list(by_id.values())
    for item in out:
        if not item.get("ended_at"):
            expires = _parse(item.get("expires_at"))
            item["status"] = "active" if expires and _now() < expires else "ended"
        else:
            item["status"] = item["ended_by"]
    out.sort(key=lambda x: str(x.get("started_at") or ""), reverse=True)
    return out
