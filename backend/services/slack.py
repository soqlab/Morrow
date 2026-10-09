"""
Slack alert notifications for PQC Scanner.

Sends a formatted message to a Slack incoming webhook URL when a scan
finishes with findings above the configured severity threshold.

Config (stored via set_integration_setting or env fallback):
  Key "slack_webhook_url"  — Incoming Webhook URL from Slack App settings
  Key "slack_min_severity" — minimum severity to alert: critical|high|medium (default: high)
  Key "slack_channel"      — optional channel override (e.g. #security)

Env fallback:
  SLACK_WEBHOOK_URL        — used when no DB setting exists
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_EMOJI = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
_SEVERITY_COLOR = {"critical": "#EF4444", "high": "#F97316", "medium": "#F59E0B",
                   "low": "#22C55E", "info": "#94A3B8"}


def _webhook_url() -> str:
    try:
        from db import get_integration_setting
        url = get_integration_setting("slack_webhook_url", "").strip()
    except Exception:
        url = ""
    return url or os.getenv("SLACK_WEBHOOK_URL", "").strip()


def _min_severity() -> int:
    try:
        from db import get_integration_setting
        sev = get_integration_setting("slack_min_severity", "high").strip().lower()
    except Exception:
        sev = "high"
    return _SEVERITY_ORDER.get(sev, 3)


def _post(webhook_url: str, payload: Dict[str, Any]) -> bool:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def notify_scan_complete(
    scan_id: str,
    targets: List[str],
    results: List[Dict[str, Any]],
    org_id: str = "",
    app_url: str = "",
) -> bool:
    """
    Send a Slack notification for a completed scan.

    Returns True if the message was sent, False if skipped or failed.
    """
    webhook_url = _webhook_url()
    if not webhook_url:
        return False

    min_sev = _min_severity()
    threshold_name = next((k for k, v in _SEVERITY_ORDER.items() if v == min_sev), "high")

    # Collect findings above threshold
    critical_hosts: List[Dict[str, Any]] = []
    total_findings = 0
    for r in results:
        if r.get("error"):
            continue
        host_findings = [
            f for f in (r.get("findings") or [])
            if _SEVERITY_ORDER.get((f.get("severity") or "").lower(), 0) >= min_sev
        ]
        if host_findings:
            critical_hosts.append({
                "host": f"{r.get('host', '?')}:{r.get('port', 443)}",
                "risk_level": r.get("quantum_risk_level") or r.get("risk_level", "unknown"),
                "risk_score": r.get("quantum_risk_score") or 0,
                "findings": host_findings,
            })
            total_findings += len(host_findings)

    if not critical_hosts:
        return False  # Nothing above threshold — no alert needed

    # Pick worst severity across all findings
    worst_sev = "low"
    for h in critical_hosts:
        for f in h["findings"]:
            sev = (f.get("severity") or "").lower()
            if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(worst_sev, 0):
                worst_sev = sev

    emoji = _SEVERITY_EMOJI.get(worst_sev, "🔴")
    color = _SEVERITY_COLOR.get(worst_sev, "#EF4444")

    # Header text
    hosts_scanned = len([r for r in results if not r.get("error")])
    header = f"{emoji} *PQC Scanner — {worst_sev.upper()} findings detected*"
    summary = (
        f"Scan of *{hosts_scanned}* host{'s' if hosts_scanned != 1 else ''}  "
        f"| *{total_findings}* finding{'s' if total_findings != 1 else ''} ≥ {threshold_name}  "
        f"| *{len(critical_hosts)}* host{'s' if len(critical_hosts) != 1 else ''} affected"
    )
    if org_id:
        summary += f"  | Org: {org_id}"

    # Build attachment fields (top 5 affected hosts)
    fields = []
    for h in critical_hosts[:5]:
        top = h["findings"][0]
        sev_tag = (top.get("severity") or "").upper()
        fields.append({
            "title": f"{h['host']}  (risk {h['risk_score']}/100)",
            "value": f"[{sev_tag}] {top.get('title', '')}",
            "short": False,
        })
    if len(critical_hosts) > 5:
        fields.append({
            "title": "…and more",
            "value": f"{len(critical_hosts) - 5} additional hosts have findings.",
            "short": False,
        })

    # Action buttons (deep link to scan)
    actions = []
    if app_url and scan_id:
        actions.append({
            "type": "button",
            "text": "View Scan",
            "url": f"{app_url.rstrip('/')}/ui/?scan={scan_id}",
            "style": "danger" if worst_sev == "critical" else "primary",
        })

    payload: Dict[str, Any] = {
        "text": header,
        "attachments": [
            {
                "color": color,
                "text": summary,
                "fields": fields,
                "footer": "PQC Scanner",
                "ts": None,
                **({"actions": actions} if actions else {}),
            }
        ],
    }

    return _post(webhook_url, payload)


def test_slack_webhook(webhook_url: str) -> bool:
    """Send a test message to verify a webhook URL works."""
    return _post(webhook_url, {
        "text": "✅ *PQC Scanner* — Slack notifications are configured correctly.",
        "attachments": [{
            "color": "#22C55E",
            "text": "This is a test message. Real alerts will appear here when scans detect critical or high findings.",
            "footer": "PQC Scanner",
        }],
    })
