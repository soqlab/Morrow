"""
Scheduled Digest Reports + post-quantum Trust Badge

Digest:  Weekly/monthly report card summarising migration delta, new vulns,
         deadline countdown, and maturity score changes.
         Delivered to Slack / Teams / PagerDuty via fire_alert().

Badge:   SVG badge at /badge/{org_token} showing current post-quantum maturity.
         Token = SHA-256(org_id + secret_salt)[:16] stored in the DB.

Tables created here:
  digest_config  — per-org schedule (frequency, channels, last_sent_at)
  digest_snapshots — historical snapshots for delta calculation
  badge_tokens     — org_id → public token mapping
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── DB ─────────────────────────────────────────────────────────────────────────

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "morrow.db")


def _db() -> sqlite3.Connection:
    return sqlite3.connect(_DB_PATH, check_same_thread=False)


def _ensure_tables() -> None:
    with closing(_db()) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS digest_config (
            org_id          TEXT PRIMARY KEY,
            frequency       TEXT NOT NULL DEFAULT 'weekly',
            slack_webhook   TEXT NOT NULL DEFAULT '',
            teams_webhook   TEXT NOT NULL DEFAULT '',
            pd_routing_key  TEXT NOT NULL DEFAULT '',
            enabled         INTEGER NOT NULL DEFAULT 1,
            last_sent_at    TEXT,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS digest_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id          TEXT NOT NULL,
            snapshot_type   TEXT NOT NULL DEFAULT 'auto',
            migration_pct   REAL NOT NULL DEFAULT 0,
            total_assets    INTEGER NOT NULL DEFAULT 0,
            high_risk       INTEGER NOT NULL DEFAULT 0,
            maturity_level  INTEGER,
            maturity_label  TEXT,
            taken_at        TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS badge_tokens (
            token           TEXT PRIMARY KEY,
            org_id          TEXT NOT NULL UNIQUE,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );
        """)
        conn.commit()


# ── Digest config ──────────────────────────────────────────────────────────────

def set_digest_config(
    org_id: str,
    frequency: str = "weekly",
    slack_webhook: str = "",
    teams_webhook: str = "",
    pd_routing_key: str = "",
    enabled: bool = True,
) -> Dict[str, Any]:
    _ensure_tables()
    freq = frequency if frequency in ("daily", "weekly", "monthly") else "weekly"
    with closing(_db()) as conn:
        conn.execute("""
            INSERT INTO digest_config (org_id, frequency, slack_webhook, teams_webhook, pd_routing_key, enabled)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(org_id) DO UPDATE SET
                frequency=excluded.frequency,
                slack_webhook=excluded.slack_webhook,
                teams_webhook=excluded.teams_webhook,
                pd_routing_key=excluded.pd_routing_key,
                enabled=excluded.enabled
        """, (org_id, freq, slack_webhook, teams_webhook, pd_routing_key, 1 if enabled else 0))
        conn.commit()
    return get_digest_config(org_id)


def get_digest_config(org_id: str) -> Dict[str, Any]:
    """The stored config INCLUDING the outbound credentials. Server-side senders only.

    Anything that answers a request must go through redact_digest_config() first.
    """
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM digest_config WHERE org_id=?", (org_id,)).fetchone()
    if not row:
        return {"org_id": org_id, "configured": False}
    d = dict(row)
    d["configured"] = True
    return d


#: Fields in digest_config that are bearer credentials. A Slack incoming-webhook URL is a bearer
#: token in a URL: whoever holds it can post into the customer's channel. A PagerDuty routing key
#: raises incidents. A Teams webhook is the same shape as Slack's.
SECRET_FIELDS = ("slack_webhook", "teams_webhook", "pd_routing_key")


def _hint(value: str) -> str:
    """A recognisable, unusable remnant: enough to tell two webhooks apart, not enough to use one."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    tail = raw[-4:] if len(raw) > 8 else ""
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        host = rest.split("/", 1)[0]
        return f"{scheme}://{host}/…{tail}"
    return f"…{tail}" if tail else "…"


def redact_digest_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """The config as an API may return it: every credential replaced by a hint.

    Read-back of these values serves nobody. The console writes them and needs to show whether one
    is set and which one; the value itself only ever travels outward from the server. Returning
    them made GET /digest/config a credential-disclosure endpoint for every reader of it -- a
    read-only customer "viewer" seat and, because the route is on the vendor support allow-list, a
    support operator "viewing as" the customer. services/support_sessions.py already bars
    /integrations/slack/settings and /notifications/config for exactly this reason; this makes
    /digest/config consistent with that rule instead of an exception to it.
    """
    out = dict(config or {})
    for field in SECRET_FIELDS:
        if field not in out:
            continue
        value = str(out.pop(field) or "")
        out[f"{field}_configured"] = bool(value.strip())
        out[f"{field}_hint"] = _hint(value)
    out["secrets_redacted"] = True
    return out


# ── Snapshot management ────────────────────────────────────────────────────────

def save_snapshot(
    org_id: str,
    migration_pct: float,
    total_assets: int,
    high_risk: int,
    maturity_level: Optional[int] = None,
    maturity_label: str = "",
    snapshot_type: str = "auto",
) -> int:
    _ensure_tables()
    with closing(_db()) as conn:
        cur = conn.execute("""
            INSERT INTO digest_snapshots
              (org_id, snapshot_type, migration_pct, total_assets, high_risk, maturity_level, maturity_label)
            VALUES (?,?,?,?,?,?,?)
        """, (org_id, snapshot_type, migration_pct, total_assets, high_risk, maturity_level, maturity_label))
        conn.commit()
        return cur.lastrowid


def get_last_snapshot(org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM digest_snapshots WHERE org_id=? ORDER BY id DESC LIMIT 1", (org_id,)
        ).fetchone()
    return dict(row) if row else None


def get_previous_snapshot(org_id: str) -> Optional[Dict[str, Any]]:
    """Second-to-last snapshot (for computing deltas)."""
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM digest_snapshots WHERE org_id=? ORDER BY id DESC LIMIT 2", (org_id,)
        ).fetchall()
    if len(rows) >= 2:
        return dict(rows[1])
    return None


# ── Digest generation ──────────────────────────────────────────────────────────

def build_digest(
    org_id: str,
    org_name: str,
    migration_pct: float,
    total_assets: int,
    high_risk: int,
    maturity_level: Optional[int],
    maturity_label: str,
    nearest_deadline_name: str,
    days_until_deadline: Optional[int],
    q_day_prob: float,
    canary_triggered_30d: int,
    active_alerts: int,
) -> Dict[str, Any]:
    """
    Build the digest payload.  Saves a new snapshot and computes deltas vs previous.
    """
    prev = get_last_snapshot(org_id)
    save_snapshot(org_id, migration_pct, total_assets, high_risk, maturity_level, maturity_label)

    mig_delta   = round(migration_pct - (prev["migration_pct"] if prev else migration_pct), 1)
    asset_delta = total_assets - (prev["total_assets"] if prev else total_assets)
    risk_delta  = high_risk    - (prev["high_risk"]    if prev else high_risk)
    mat_delta   = (maturity_level or 0) - (prev.get("maturity_level") or 0 if prev else 0)

    period_label = "since last report" if prev else "initial snapshot"

    summary_lines = [
        f"Post-quantum migration: {migration_pct}% ({'+' if mig_delta>=0 else ''}{mig_delta}% {period_label})",
        f"Total assets: {total_assets} ({'+' if asset_delta>=0 else ''}{asset_delta} new)",
        f"High-risk assets: {high_risk} ({'+' if risk_delta>=0 else ''}{risk_delta} change)",
        f"Maturity: {maturity_label or 'L'+str(maturity_level) if maturity_level else 'Not assessed'}"
          + (f" ({'+' if mat_delta>=0 else ''}{mat_delta} levels)" if mat_delta != 0 else ""),
        f"Q-Day probability (RSA-2048): {round(q_day_prob,2)}%",
        f"Nearest deadline: {nearest_deadline_name or 'None'} "
          + (f"({days_until_deadline}d remaining)" if days_until_deadline is not None else ""),
    ]
    if canary_triggered_30d:
        summary_lines.append(f"⚠ Canary triggered {canary_triggered_30d}× in the last 30 days")
    if active_alerts:
        summary_lines.append(f"⚠ {active_alerts} active observatory alert(s)")

    status = "RED" if (mig_delta < -5 or risk_delta > 5 or canary_triggered_30d > 0) else \
             "AMBER" if (mig_delta < 0 or risk_delta > 0 or active_alerts > 0) else "GREEN"

    facts = [
        {"name": "Migration %",     "value": f"{migration_pct}% ({mig_delta:+.1f}%)"},
        {"name": "High-Risk Assets","value": str(high_risk)},
        {"name": "Maturity",        "value": maturity_label or "—"},
        {"name": "Q-Day Risk",      "value": f"{round(q_day_prob,2)}%"},
        {"name": "Nearest Deadline","value": f"{nearest_deadline_name or '—'} ({days_until_deadline}d)" if days_until_deadline else nearest_deadline_name or "—"},
        {"name": "Status",          "value": status},
    ]

    return {
        "org_id": org_id,
        "org_name": org_name,
        "status": status,
        "summary": "\n".join(summary_lines),
        "facts": facts,
        "migration_pct": migration_pct,
        "mig_delta": mig_delta,
        "total_assets": total_assets,
        "high_risk": high_risk,
        "maturity_level": maturity_level,
        "maturity_label": maturity_label,
        "q_day_prob": q_day_prob,
        "canary_triggered_30d": canary_triggered_30d,
        "active_alerts": active_alerts,
        "nearest_deadline_name": nearest_deadline_name,
        "days_until_deadline": days_until_deadline,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def send_digest(
    digest: Dict[str, Any],
    slack_webhook: str = "",
    teams_webhook: str = "",
    pd_routing_key: str = "",
) -> Dict[str, Any]:
    """Fire the digest to all configured channels."""
    try:
        from services.alerting import fire_alert
    except ImportError:
        return {"ok": False, "error": "alerting service unavailable"}

    status = digest.get("status", "AMBER")
    severity_map = {"RED": "critical", "AMBER": "warning", "GREEN": "info"}

    result = fire_alert(
        event_type="digest",
        title=f"Post-Quantum Weekly Digest — {digest.get('org_name','Your Org')} — {status}",
        summary=digest.get("summary", ""),
        severity=severity_map.get(status, "info"),
        facts=digest.get("facts", []),
        details=digest,
        dedup_key=f"pq-digest-{digest.get('org_id','')}",
        slack_webhook=slack_webhook,
        teams_webhook=teams_webhook,
        pagerduty_routing_key=pd_routing_key,
    )

    # Update last_sent_at
    try:
        with closing(_db()) as conn:
            conn.execute("UPDATE digest_config SET last_sent_at=? WHERE org_id=?",
                         (datetime.now(timezone.utc).isoformat(), digest.get("org_id","")))
            conn.commit()
    except Exception:
        pass

    return result


def list_snapshots(org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    _ensure_tables()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM digest_snapshots WHERE org_id=? ORDER BY id DESC LIMIT ?", (org_id, limit)
        ).fetchall()
    return [dict(r) for r in rows]


# ── post-quantum Trust Badge ────────────────────────────────────────────────────────────

def _get_or_create_badge_token(org_id: str) -> str:
    _ensure_tables()
    with closing(_db()) as conn:
        row = conn.execute("SELECT token FROM badge_tokens WHERE org_id=?", (org_id,)).fetchone()
        if row:
            return row[0]
        token = secrets.token_hex(16)
        conn.execute("INSERT OR IGNORE INTO badge_tokens (token, org_id) VALUES (?,?)", (token, org_id))
        conn.commit()
    return token


def get_badge_token(org_id: str) -> Dict[str, Any]:
    """Return the org's public badge token (creates one if needed)."""
    token = _get_or_create_badge_token(org_id)
    return {"org_id": org_id, "token": token}


def resolve_badge_token(token: str) -> Optional[str]:
    """Return org_id for a given token, or None."""
    _ensure_tables()
    with closing(_db()) as conn:
        row = conn.execute("SELECT org_id FROM badge_tokens WHERE token=?", (token,)).fetchone()
    return row[0] if row else None


_MATURITY_COLORS = {
    None: ("#6b7280", "#374151"),   # grey  — unknown
    0:    ("#ef4444", "#7f1d1d"),   # red   — Initial
    1:    ("#f97316", "#7c2d12"),   # orange — Aware
    2:    ("#eab308", "#713f12"),   # yellow — Defined
    3:    ("#3b82f6", "#1e3a5f"),   # blue  — Managed
    4:    ("#8b5cf6", "#4c1d95"),   # purple — Optimised
    5:    ("#22c55e", "#14532d"),   # green — Leading
}

_LEVEL_LABELS = {
    None: "Unknown", 0: "Initial", 1: "Aware",
    2: "Defined", 3: "Managed", 4: "Optimised", 5: "Leading",
}


def generate_badge_svg(
    maturity_level: Optional[int],
    migration_pct: float,
    org_name: str = "Morrow",
) -> str:
    """
    Generate an SVG badge similar to shields.io style.

    Left panel: "Post-Quantum Ready"
    Right panel: maturity level label + color
    Sub-bar: migration % as a thin progress bar
    """
    level = maturity_level if maturity_level is not None else None
    fg_color, bg_color = _MATURITY_COLORS.get(level, _MATURITY_COLORS[None])
    level_label = _LEVEL_LABELS.get(level, "Unknown")
    label = "Post-Quantum Maturity"
    value = f"L{level} · {level_label}" if level is not None else "Not Assessed"

    # Dimensions
    label_w = 96
    value_w = 112
    total_w = label_w + value_w
    h = 28
    bar_h = 4
    total_h = h + bar_h
    rx = 4

    # Migration bar fill
    bar_fill_w = max(4, int(migration_pct / 100 * total_w))
    bar_color = "#22c55e" if migration_pct >= 75 else "#f59e0b" if migration_pct >= 40 else "#ef4444"

    # Truncate org name for display
    (org_name[:18] + "…") if len(org_name) > 20 else org_name

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" role="img" aria-label="{label}: {value}">
  <title>{label}: {value} — {org_name}</title>
  <defs>
    <linearGradient id="bg_l" x2="0" y2="1">
      <stop offset="0" stop-color="#555" stop-opacity=".15"/>
      <stop offset="1" stop-opacity=".15"/>
    </linearGradient>
    <linearGradient id="bg_r" x2="0" y2="1">
      <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
      <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r"><rect width="{total_w}" height="{h}" rx="{rx}"/></clipPath>
  </defs>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="{h}" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="{h}" fill="{bg_color}"/>
    <rect width="{label_w}" height="{h}" fill="url(#bg_l)"/>
    <rect x="{label_w}" width="{value_w}" height="{h}" fill="url(#bg_r)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="10">
    <text x="{label_w//2+1}" y="19" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_w//2}" y="18">{label}</text>
    <text x="{label_w + value_w//2+1}" y="19" fill="#010101" fill-opacity=".3" font-weight="bold">{value}</text>
    <text x="{label_w + value_w//2}" y="18" font-weight="bold">{value}</text>
  </g>
  <rect width="{total_w}" height="{h}" fill="none" stroke="rgba(0,0,0,.2)" stroke-width="1" rx="{rx}"/>
  <!-- Migration progress bar -->
  <rect y="{h}" width="{total_w}" height="{bar_h}" fill="#1f2937"/>
  <rect y="{h}" width="{bar_fill_w}" height="{bar_h}" fill="{bar_color}" opacity="0.9"/>
  <text x="{total_w//2}" y="{h+bar_h-1}" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="7" fill="rgba(255,255,255,.6)">{migration_pct:.0f}% post-quantum-ready</text>
</svg>"""
    return svg
