"""
Multi-Channel Alerting — Microsoft Teams + PagerDuty

Extends the existing Slack alerting to support Teams Adaptive Cards
and PagerDuty Events API v2. All channels fire from the same trigger
points: canary triggers, observatory drift events, Q-Day threshold
crossings, and regulatory deadline warnings.

Teams:    Incoming Webhook — posts an Adaptive Card to a Teams channel
PagerDuty: Events API v2  — creates/resolves incidents in PagerDuty
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ── Teams ─────────────────────────────────────────────────────────────────────

def send_teams_alert(
    webhook_url: str,
    title: str,
    summary: str,
    severity: str = "warning",
    facts: Optional[list] = None,
    action_url: str = "",
    action_label: str = "View in Morrow",
) -> Dict[str, Any]:
    """
    Post an Adaptive Card to a Microsoft Teams channel via Incoming Webhook.

    severity: "critical" | "warning" | "info"
    facts: list of {"name": str, "value": str} pairs shown in the card
    """
    color_map = {"critical": "attention", "warning": "warning", "info": "good"}
    accent = color_map.get(severity, "warning")

    # Teams Adaptive Card payload
    card_body: list = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": title,
            "color": accent,
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": summary,
            "wrap": True,
            "spacing": "Small",
        },
    ]

    if facts:
        card_body.append({
            "type": "FactSet",
            "facts": [{"title": f.get("name", ""), "value": str(f.get("value", ""))} for f in facts[:10]],
            "spacing": "Medium",
        })

    card_body.append({
        "type": "TextBlock",
        "text": f"Sent by Morrow · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "size": "Small",
        "color": "Accent",
        "spacing": "Medium",
        "isSubtle": True,
    })

    actions = []
    if action_url:
        actions.append({
            "type": "Action.OpenUrl",
            "title": action_label,
            "url": action_url,
        })

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": card_body,
                    "actions": actions,
                    "msteams": {"width": "Full"},
                },
            }
        ],
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
        return {"ok": True, "status": resp.status, "body": body[:200]}
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}", "status": e.code}
    except Exception as ex:
        return {"ok": False, "error": str(ex)[:200]}


def test_teams_webhook(webhook_url: str) -> Dict[str, Any]:
    return send_teams_alert(
        webhook_url,
        title="Morrow — Test Alert",
        summary="Your Microsoft Teams integration is working correctly.",
        severity="info",
        facts=[{"name": "Status", "value": "Connected"}, {"name": "Time", "value": datetime.now(timezone.utc).isoformat()}],
    )


# ── PagerDuty ─────────────────────────────────────────────────────────────────

_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


def send_pagerduty_alert(
    routing_key: str,
    summary: str,
    severity: str = "warning",
    source: str = "Morrow",
    dedup_key: str = "",
    details: Optional[Dict[str, Any]] = None,
    component: str = "morrow",
    group: str = "cryptography",
    class_: str = "quantum_vulnerability",
    links: Optional[list] = None,
) -> Dict[str, Any]:
    """
    Trigger a PagerDuty incident via Events API v2.

    severity: "critical" | "error" | "warning" | "info"
    dedup_key: if set, PagerDuty deduplicates alerts with the same key
    """
    pd_severity_map = {
        "critical": "critical",
        "high":     "error",
        "warning":  "warning",
        "info":     "info",
        "medium":   "warning",
        "low":      "info",
    }

    payload: Dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary[:1024],
            "source": source,
            "severity": pd_severity_map.get(severity, "warning"),
            "component": component,
            "group": group,
            "class": class_,
            "custom_details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

    if dedup_key:
        payload["dedup_key"] = dedup_key

    if links:
        payload["links"] = [{"href": lk.get("url", ""), "text": lk.get("label", "")} for lk in links[:5]]

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            _PD_EVENTS_URL,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
        return {"ok": True, "status": resp.status, "dedup_key": body.get("dedup_key", ""),
                "message": body.get("message", ""), "body": body}
    except urllib.error.HTTPError as e:
        body_text = ""
        try: body_text = e.read().decode()[:200]
        except Exception: pass
        return {"ok": False, "error": f"HTTP {e.code}: {e.reason}", "status": e.code, "body": body_text}
    except Exception as ex:
        return {"ok": False, "error": str(ex)[:200]}


def resolve_pagerduty_incident(routing_key: str, dedup_key: str) -> Dict[str, Any]:
    """Resolve an existing PagerDuty incident by dedup key."""
    payload = {
        "routing_key": routing_key,
        "dedup_key": dedup_key,
        "event_action": "resolve",
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            _PD_EVENTS_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
        return {"ok": True, "resolved": True, "body": body}
    except Exception as ex:
        return {"ok": False, "error": str(ex)[:200]}


def test_pagerduty(routing_key: str) -> Dict[str, Any]:
    return send_pagerduty_alert(
        routing_key=routing_key,
        summary="Morrow — Integration Test Alert",
        severity="info",
        dedup_key="morrow-test",
        details={"test": True, "source": "Morrow integration test"},
    )


# ── Unified multi-channel fire ────────────────────────────────────────────────

def fire_alert(
    event_type: str,
    title: str,
    summary: str,
    severity: str,
    facts: Optional[list] = None,
    details: Optional[Dict[str, Any]] = None,
    dedup_key: str = "",
    slack_webhook: str = "",
    teams_webhook: str = "",
    pagerduty_routing_key: str = "",
    action_url: str = "",
) -> Dict[str, Any]:
    """
    Fire an alert to all configured channels simultaneously.
    Returns per-channel results.
    """
    results: Dict[str, Any] = {"event_type": event_type, "channels": {}}

    if slack_webhook:
        try:
            # Build a minimal Slack message
            import urllib.request as _ur
            import json as _json
            _blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": title}},
                {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            ]
            if facts:
                fields = [{"type": "mrkdwn", "text": f"*{f['name']}*\n{f['value']}"} for f in facts[:10]]
                _blocks.append({"type": "section", "fields": fields[:10]})
            _payload = _json.dumps({"text": title, "blocks": _blocks}).encode()
            _req = _ur.Request(slack_webhook, data=_payload, headers={"Content-Type": "application/json"})
            with _ur.urlopen(_req, timeout=8) as r:
                results["channels"]["slack"] = {"ok": True, "status": r.status}
        except Exception as ex:
            results["channels"]["slack"] = {"ok": False, "error": str(ex)[:100]}

    if teams_webhook:
        results["channels"]["teams"] = send_teams_alert(
            teams_webhook, title=title, summary=summary, severity=severity,
            facts=facts, action_url=action_url,
        )

    if pagerduty_routing_key:
        results["channels"]["pagerduty"] = send_pagerduty_alert(
            routing_key=pagerduty_routing_key,
            summary=f"{title} — {summary}",
            severity=severity,
            dedup_key=dedup_key or f"pq-{event_type}",
            details=details or {},
        )

    results["fired_at"] = datetime.now(timezone.utc).isoformat()
    results["channels_fired"] = len(results["channels"])
    return results
