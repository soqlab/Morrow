from __future__ import annotations

import hashlib
import hmac
import json
import random
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib import request, error as urlerror
from vault_db import get_credential


from db import (
    load_scan_row,
    list_webhooks,
    record_webhook_event,
    bump_webhook_attempt,
    update_webhook_event,
    get_baseline,
    claim_due_webhook_events,
    get_integration_setting,
    # Sprint 8 rules
    list_event_rules,
    should_fire_event_rule,
)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hmac_sig(secret: str, body: bytes) -> str:
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def webhook_transport_kind(url: str) -> str:
    parsed = str(url or "").strip().lower()
    if "hooks.slack.com/" in parsed:
        return "slack"
    if "discord.com/api/webhooks/" in parsed or "discordapp.com/api/webhooks/" in parsed:
        return "discord"
    return "generic"


def webhook_requires_credential(webhook: Dict[str, Any]) -> bool:
    return webhook_transport_kind(str((webhook or {}).get("url") or "")) == "generic"


def _event_envelope(event_type: str, dedupe_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(payload or {})
    payload.setdefault("asset_key", "")
    if "finding_summary" not in payload:
        severity = "critical" if event_type in ("cert.expired",) else str(payload.get("severity") or payload.get("max_severity") or "")
        finding_ids = payload.get("finding_ids") or payload.get("new_finding_ids") or []
        total = len(finding_ids) if isinstance(finding_ids, list) else 0
        payload["finding_summary"] = {
            "severity": severity,
            "counts": {severity: total} if severity and total else {},
            "total": total,
        }
    return {
        "schema_version": "1.0",
        "event_type": event_type,
        "event_id": dedupe_key,
        "ts": int(time.time()),
        "ts_iso": _utc_now_iso(),
        "data": payload,
    }


def _notification_text(event_type: str, payload: Dict[str, Any]) -> str:
    remediation_ids = payload.get("remediation_ids") or []
    rid = str(payload.get("remediation_id") or "").strip()
    if not rid and isinstance(remediation_ids, list) and remediation_ids:
        rid = ",".join(str(x) for x in remediation_ids[:5])
    asset_key = str(payload.get("asset_key") or "").strip()
    repository = str(payload.get("repository") or "").strip()
    file_path = str(payload.get("file_path") or "").strip()
    pr_url = str(payload.get("pr_url") or "").strip()
    exit_code = payload.get("exit_code")

    if event_type == "validation.failed":
        return (
            f"[post-quantum] validation failed for remediation #{rid or '?'} "
            f"asset={asset_key or '-'} repo={repository or '-'} file={file_path or '-'} "
            f"exit={exit_code if exit_code is not None else '?'}"
        )
    if event_type == "remediation.merged":
        return (
            f"[post-quantum] remediation merged #{rid or '?'} "
            f"asset={asset_key or '-'} repo={repository or '-'} file={file_path or '-'} "
            f"{pr_url or ''}"
        ).strip()
    if event_type == "remediation.drifted":
        return (
            f"[post-quantum] drift detected for remediation #{rid or '?'} "
            f"asset={asset_key or '-'} repo={repository or '-'} file={file_path or '-'} "
            f"{pr_url or ''}"
        ).strip()
    if event_type == "remediation.drift_followup_created":
        followup_id = str(payload.get("followup_remediation_id") or "").strip()
        return (
            f"[post-quantum] drift follow-up created parent=#{rid or '?'} followup=#{followup_id or '?'} "
            f"asset={asset_key or '-'} repo={repository or '-'} file={file_path or '-'}"
        ).strip()
    if event_type == "remediation.drift_acknowledged":
        actor_id = str(payload.get("actor_id") or "").strip()
        return (
            f"[post-quantum] drift acknowledged for remediation #{rid or '?'} "
            f"asset={asset_key or '-'} by={actor_id or '-'}"
        ).strip()
    return f"[post-quantum] {event_type}: {json.dumps(payload, sort_keys=True)[:400]}"


def _delivery_payload(webhook: Dict[str, Any], event_type: str, dedupe_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    transport = webhook_transport_kind(str((webhook or {}).get("url") or ""))
    if transport == "slack":
        return {"text": _notification_text(event_type, payload)}
    if transport == "discord":
        return {"content": _notification_text(event_type, payload)}
    return _event_envelope(event_type, dedupe_key, payload)


def _extract_rule_ids(result: dict) -> List[str]:
    out: List[str] = []
    for f in (result.get("findings") or []):
        rid = (f or {}).get("rule_id")
        if rid:
            out.append(str(rid))
    return out


def _as_int(v: Any) -> Optional[int]:
    try:
        if v is None or str(v) == "":
            return None
        return int(v)
    except Exception:
        return None


def _cert_bucket(days_until_expiry: Optional[int]) -> str:
    """Return stable state buckets for cert expiry noise control."""
    if days_until_expiry is None:
        return "unknown"
    if days_until_expiry <= 0:
        return "expired"
    if days_until_expiry <= 1:
        return "expiring_1"
    if days_until_expiry <= 7:
        return "expiring_7"
    if days_until_expiry <= 30:
        return "expiring_30"
    return "ok"


def build_events_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Build canonical internal events for a completed scan.

    Point 1 bugfix included: treat each scan result as the facts dict (support legacy wrappers too).

    Note: Sprint 8 rules engine controls *routing* (delivery), not generation.
    """
    scan = load_scan_row(scan_id)
    if not scan:
        return []

    results = scan.get("results") or []
    summary = scan.get("summary") or {}
    status = scan.get("status") or ""
    error_text = scan.get("error_text") or ""

    # UI-configurable threshold (default 30) – stored in DB integrations_settings
    try:
        expiring_soon_days = int(get_integration_setting("cert_expiring_soon_days", "30"))
    except Exception:
        expiring_soon_days = 30
    expiring_soon_days = max(1, min(36500, expiring_soon_days))

    events: List[Dict[str, Any]] = []

    # Always emit scan.completed
    events.append({
        "event_type": "scan.completed",
        "dedupe_key": _sha256_hex(f"scan.completed:{scan_id}"),
        "payload": {
            "scan_id": scan_id,
            "asset_key": "",
            "status": status,
            "summary": summary,
            "finding_summary": {
                "severity": "",
                "counts": {},
                "total": sum(len((r or {}).get("findings") or []) for r in results if isinstance(r, dict)),
            },
        },
    })

    if str(status).lower() == "failed":
        events.append({
            "event_type": "scan.failed",
            "dedupe_key": _sha256_hex(f"scan.failed:{scan_id}"),
            "payload": {"scan_id": scan_id, "status": status, "summary": summary, "error_text": error_text},
        })

    for r in results:
        host = str((r or {}).get("host") or "")
        port = int((r or {}).get("port") or 443)
        ak = f"{host}:{port}"

        rule_ids = set(_extract_rule_ids(r or {}))

        # ✅ Point 1 fix: scanner returns a flat facts dict; also support {"facts":{...}}.
        facts = None
        if isinstance(r, dict):
            facts = r.get("facts")
            if not isinstance(facts, dict) or not facts:
                facts = r
        if not isinstance(facts, dict):
            facts = {}

        du_int = _as_int(facts.get("days_until_expiry"))
        not_after = str(facts.get("not_after") or "")
        verify_reason = str(facts.get("verify_reason") or "")

        # cert.expired
        expired = False
        if du_int is not None and du_int < 0:
            expired = True
        if verify_reason == "expired":
            expired = True
        if "CERT_EXPIRED" in rule_ids or "VERIFY_EXPIRED" in rule_ids:
            expired = True

        if expired:
            # Important: do NOT include days_until_expiry in fingerprint (it changes daily).
            bucket = _cert_bucket(du_int)
            fp = f"{not_after}:{bucket}:{verify_reason}"
            events.append({
                "event_type": "cert.expired",
                "dedupe_key": _sha256_hex(f"cert.expired:{ak}:{fp}"),
                "payload": {
                    "scan_id": scan_id,
                    "asset_key": ak,
                    "host": host,
                    "port": port,
                    "days_until_expiry": du_int,
                    "not_after": not_after,
                    "verify_reason": verify_reason,
                    "facts": facts,
                    "finding_ids": sorted(rule_ids),
                    "state": bucket,
                },
            })

        # cert.expiring_soon
        expiring_soon = False
        if du_int is not None and 0 <= du_int <= expiring_soon_days:
            expiring_soon = True
        if "CERT_EXPIRING_SOON" in rule_ids:
            expiring_soon = True

        if expiring_soon:
            bucket = _cert_bucket(du_int)
            fp = f"{not_after}:{bucket}:{expiring_soon_days}"
            events.append({
                "event_type": "cert.expiring_soon",
                "dedupe_key": _sha256_hex(f"cert.expiring_soon:{ak}:{fp}"),
                "payload": {
                    "scan_id": scan_id,
                    "asset_key": ak,
                    "host": host,
                    "port": port,
                    "days_until_expiry": du_int,
                    "not_after": not_after,
                    "threshold_days": expiring_soon_days,
                    "facts": facts,
                    "finding_ids": sorted(rule_ids),
                    "state": bucket,
                },
            })

        # pq.not_ready
        if "MORROW_RSA_ENDPOINT" in rule_ids or "MORROW_EC_ENDPOINT" in rule_ids:
            sigs = sorted([x for x in ("MORROW_RSA_ENDPOINT", "MORROW_EC_ENDPOINT") if x in rule_ids])
            fp = ",".join(sigs)
            events.append({
                "event_type": "pq.not_ready",
                "dedupe_key": _sha256_hex(f"pq.not_ready:{ak}:{fp}"),
                "payload": {"scan_id": scan_id, "asset_key": ak, "host": host, "port": port, "signals": sigs, "finding_ids": sorted(rule_ids)},
            })

        # scan.regression
        base = get_baseline(ak)
        if base and base.get("baseline_scan_id"):
            base_scan = load_scan_row(str(base["baseline_scan_id"]))
            base_rules: set[str] = set()
            if base_scan:
                for br in (base_scan.get("results") or []):
                    if f"{br.get('host')}:{int(br.get('port') or 443)}" == ak:
                        base_rules = set(_extract_rule_ids(br))
                        break
            new_rules = sorted(rule_ids - base_rules)
            if new_rules:
                fp = ",".join(new_rules)
                events.append({
                    "event_type": "scan.regression",
                    "dedupe_key": _sha256_hex(f"scan.regression:{ak}:{fp}"),
                    "payload": {
                        "scan_id": scan_id,
                        "asset_key": ak,
                        "host": host,
                        "port": port,
                        "baseline_scan_id": base["baseline_scan_id"],
                        "new_finding_ids": new_rules,
                    },
                })

    return events


# -----------------------------
# Sprint 8 Rules + Point 3 Noise Control
# -----------------------------


def _severity_rank(s: str) -> int:
    m = {
        "": 0,
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }
    return m.get(str(s or "").strip().lower(), 0)


def _event_matches_rule(event_type: str, payload: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    # Event types
    types = rule.get("event_types") or ["*"]
    if "*" not in types and event_type not in types:
        return False

    # Min severity (only if payload provides severity)
    min_sev = str(rule.get("min_severity") or "").strip()
    if min_sev:
        sev = payload.get("severity") or payload.get("max_severity") or ""
        if _severity_rank(str(sev)) < _severity_rank(min_sev):
            return False

    # Rule IDs filter (finding_ids / new_finding_ids)
    want_rule_ids = set(rule.get("rule_ids") or [])
    if want_rule_ids:
        got = set(payload.get("finding_ids") or [])
        got |= set(payload.get("new_finding_ids") or [])
        if got.isdisjoint(want_rule_ids):
            return False

    # Quantum score min (if present)
    qmin = float(rule.get("quantum_score_min") if rule.get("quantum_score_min") is not None else -1)
    if qmin >= 0:
        q = payload.get("quantum_risk_score")
        if q is None:
            q = (payload.get("facts") or {}).get("quantum_risk_score")
        try:
            if q is None or float(q) < qmin:
                return False
        except Exception:
            return False

    # Optional metadata filters (only enforced if event payload contains them)
    meta = payload.get("asset") or payload.get("asset_meta") or {}
    if isinstance(meta, dict):
        for k, rk in (
            ("environment", "environments"),
            ("team", "teams"),
            ("criticality", "criticalities"),
        ):
            allowed = set(rule.get(rk) or [])
            if allowed:
                v = str(meta.get(k) or "")
                if v and v not in allowed:
                    return False

        tags_allowed = set(rule.get("tags") or [])
        if tags_allowed:
            tags = meta.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            if isinstance(tags, list):
                if set(tags).isdisjoint(tags_allowed):
                    return False

    return True


def _effective_fire_mode(event_type: str, rule: Dict[str, Any]) -> str:
    # Point 3: if a rule hasn't been updated with fire_mode yet,
    # default cert/pq/regression style events to state_change to reduce noise.
    mode = str(rule.get("fire_mode") or "").strip().lower()
    if not mode or mode == "always":
        if event_type.startswith("cert."):
            return "state_change"
        if event_type in ("scan.regression", "pq.not_ready"):
            return "state_change"
        return "always"
    return mode


def _rule_fingerprint(event_type: str, payload: Dict[str, Any], rule: Dict[str, Any]) -> str:
    # Stable, rule-scoped fingerprint for Point 3.
    # (Rule ID is stored separately in DB; we keep fingerprint small and deterministic.)

    if event_type.startswith("cert."):
        ak = str(payload.get("asset_key") or "")
        not_after = str(payload.get("not_after") or "")
        state = str(payload.get("state") or _cert_bucket(_as_int(payload.get("days_until_expiry"))))
        # Include threshold_days so changing threshold creates a new fingerprint.
        th = str(payload.get("threshold_days") or "")
        return _sha256_hex(f"{event_type}:{ak}:{not_after}:{state}:{th}")

    # For scan.completed/failed, include scan_id (always unique per scan)
    if event_type.startswith("scan."):
        sid = str(payload.get("scan_id") or "")
        ak = str(payload.get("asset_key") or "")
        return _sha256_hex(f"{event_type}:{sid}:{ak}")

    # Generic fallback: use event_type + asset_key + dedupe hints
    ak = str(payload.get("asset_key") or "")
    return _sha256_hex(f"{event_type}:{ak}:{json.dumps(payload, sort_keys=True)[:500]}")


def _post_json(
    url: str,
    body: bytes,
    event_type: str,
    secret: str = "",
    timeout_s: int = 10,
    max_read_bytes: int = 2048,
) -> tuple[int, str]:
    """POST JSON and return (http_status, response_excerpt).

    Notes:
    - For 2xx responses, we still read up to max_read_bytes so we can capture a snippet for debugging.
    - For non-2xx responses urllib raises HTTPError; callers should handle it and can still read the body.
    """
    headers = {"Content-Type": "application/json", "X-Morrow-Event": event_type}
    if secret:
        headers["X-Morrow-Signature"] = _hmac_sig(secret, body)
    req = request.Request(url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout_s) as resp:
        code = int(getattr(resp, "status", 200) or 200)
        excerpt = ""
        try:
            raw = resp.read(max(0, int(max_read_bytes)))
            if raw:
                excerpt = raw.decode("utf-8", "ignore")[: int(max_read_bytes)]
        except Exception:
            excerpt = ""
        return code, excerpt


def _read_http_error_excerpt(e: urlerror.HTTPError, max_read_bytes: int = 2048) -> str:
    try:
        raw = e.read(max(0, int(max_read_bytes)))
        if raw:
            return raw.decode("utf-8", "ignore")[: int(max_read_bytes)]
    except Exception:
        pass
    return ""


def _backoff_seconds(attempts: int, base: float = 5.0, cap: float = 3600.0, jitter: float = 0.2) -> float:
    """Exponential backoff with jitter.

    attempts is the *current* attempt count after increment.
    """
    try:
        a = max(1, int(attempts))
    except Exception:
        a = 1
    delay = min(float(cap), float(base) * (2.0 ** (a - 1)))
    # +/- jitter%
    if jitter and jitter > 0:
        delay *= (1.0 + random.uniform(-float(jitter), float(jitter)))
    return max(1.0, delay)


def drain_webhook_delivery_queue(limit: int = 200, max_attempts: int = 5) -> Dict[str, Any]:
    """Drain the webhook delivery queue.

    Implements:
    - per-webhook rate limiting (rate_limit_per_minute)
    - backoff + jitter using next_attempt_at
    - better error capture: http_status + response body excerpt

    Returns a small stats object (safe to show in UI).
    """
    hooks = {int(h["id"]): h for h in list_webhooks() if h.get("enabled")}
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # Multi-worker safe claim/lease
    try:
        import os as _os
        import socket as _socket
        worker_id = f"{_socket.gethostname()}:{_os.getpid()}"
    except Exception:
        worker_id = "worker"
        _os = None  # type: ignore
    try:
        lease_seconds = int((_os.getenv("MORROW_WEBHOOK_LEASE_SECONDS", "600") if _os else "600"))
    except Exception:
        lease_seconds = 600

    due = claim_due_webhook_events(
        limit=int(limit or 200),
        max_attempts=int(max_attempts or 5),
        now_iso=now_iso,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )

    # Track per-webhook send spacing
    last_sent_ts: Dict[int, float] = {}

    attempted = 0
    sent = 0
    failed = 0
    skipped = 0

    for ev in due:
        wid = int(ev.get("webhook_id") or 0)
        wh = hooks.get(wid)
        if not wh:
            skipped += 1
            continue

        # ✅ STRICT MODE: never send unsigned webhooks (no Vault credential)
        if wh.get("enabled") and webhook_requires_credential(wh) and not wh.get("credential_id"):
            row_id = int(ev.get("id") or 0)
            update_webhook_event(
                row_id,
                status="failed",
                http_status=0,
                error_text="STRICT BLOCK: missing credential_id (Vault required)",
                response_excerpt="",
                next_attempt_at="",
            )
            skipped += 1
            continue

        et = str(ev.get("event_type") or "")
        payload = ev.get("payload") or {}

        # per-webhook rate limit
        try:
            rpm = int(wh.get("rate_limit_per_minute") or 60)
        except Exception:
            rpm = 60
        min_interval = (60.0 / float(rpm)) if rpm > 0 else 0.0
        if min_interval > 0:
            last = last_sent_ts.get(wid)
            if last is not None:
                wait = min_interval - (time.time() - last)
                if wait > 0:
                    time.sleep(min(wait, 2.0))  # don’t sleep too long in one chunk

        body = json.dumps(payload).encode("utf-8")

        # Timeout can be configured per webhook
        try:
            timeout_s = int(wh.get("timeout_seconds") or 10)
        except Exception:
            timeout_s = 10
        timeout_s = max(1, min(120, timeout_s))

        attempted += 1
        row_id = int(ev.get("id") or 0)
        try:
            bump_webhook_attempt(row_id)
            code, excerpt = _post_json(
                str(wh.get("url") or ""),
                body,
                et,
                secret=_resolve_webhook_secret(wh),
                timeout_s=timeout_s,
            )
            update_webhook_event(
                row_id,
                status="sent",
                http_status=code,
                error_text="",
                response_excerpt=excerpt,
                next_attempt_at="",
            )
            sent += 1
            last_sent_ts[wid] = time.time()
        except urlerror.HTTPError as e:
            code = int(getattr(e, "code", 0) or 0)
            excerpt = _read_http_error_excerpt(e)
            # Schedule next attempt (backoff)
            attempts_now = int((ev.get("attempts") or 0)) + 1
            delay = _backoff_seconds(attempts_now)
            next_ts = time.time() + delay
            next_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_ts))
            update_webhook_event(
                row_id,
                status="failed",
                http_status=code,
                error_text=str(e),
                response_excerpt=excerpt,
                next_attempt_at=next_iso,
            )
            failed += 1
        except Exception as e:
            attempts_now = int((ev.get("attempts") or 0)) + 1
            delay = _backoff_seconds(attempts_now)
            next_ts = time.time() + delay
            next_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(next_ts))
            update_webhook_event(
                row_id,
                status="failed",
                http_status=0,
                error_text=str(e),
                response_excerpt="",
                next_attempt_at=next_iso,
            )
            failed += 1

    return {
        "due": len(due),
        "attempted": attempted,
        "sent": sent,
        "failed": failed,
        "skipped": skipped,
    }


def _enqueue_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    hooks_all = [h for h in list_webhooks() if h.get("enabled")]
    hooks_by_id = {int(h["id"]): h for h in hooks_all}
    if not hooks_all or not events:
        return {"attempted": 0, "sent": 0, "hooks": len(hooks_all), "events": len(events)}

    rules = [r for r in list_event_rules(limit=500) if r.get("enabled")]

    attempted = 0
    sent = 0

    record_suppressed = str(get_integration_setting("record_suppressed_events", "0") or "0").strip() == "1"

    for ev in events:
        et = str(ev.get("event_type") or "")
        payload_data = ev.get("payload") or {}

        # --- Route destinations ---
        destinations: List[Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = []
        if rules:
            for rule in rules:
                if not _event_matches_rule(et, payload_data, rule):
                    continue
                wh_ids = [int(x) for x in (rule.get("webhook_ids") or []) if str(x).isdigit() or isinstance(x, int)]
                for wid in wh_ids:
                    wh = hooks_by_id.get(int(wid))
                    if wh:
                        destinations.append((wh, rule))
        else:
            # Legacy allow-list fallback
            for wh in hooks_all:
                allowed = wh.get("events")
                if allowed is None:
                    allowed = ["*"]
                if "*" not in allowed and et not in allowed:
                    continue
                destinations.append((wh, None))

        if not destinations:
            continue

        for wh, rule in destinations:
            if wh.get("enabled") and webhook_requires_credential(wh) and not (wh.get("credential_id") or wh.get("has_secret")):
                print(f"[webhook] STRICT BLOCK: missing credential_id for id={wh.get('id')} name={wh.get('name')}")
                continue

            dedupe_key = str(ev.get("dedupe_key") or "")
            webhook_payload = _delivery_payload(wh, et, dedupe_key, payload_data)

            # --- Point 3: suppression / cooldown per RULE ---
            if rule is not None:
                rid = int(rule.get("id") or 0)
                cooldown = int(rule.get("cooldown_minutes") or 0)
                mode = _effective_fire_mode(et, rule)

                fp = _rule_fingerprint(et, payload_data, rule)

                if not should_fire_event_rule(rid, fp, cooldown_minutes=cooldown, fire_mode=mode):
                    if record_suppressed:
                        record_webhook_event(
                            webhook_id=int(wh["id"]),
                            event_type=et,
                            dedupe_key=_sha256_hex(f"suppressed:{rid}:{fp}:{wh['id']}"),
                            payload=webhook_payload,
                            status="suppressed",
                            max_attempts=0,
                        )
                    continue

            # Record event (dedupe per webhook)
            row_id = record_webhook_event(
                webhook_id=int(wh["id"]),
                event_type=et,
                dedupe_key=dedupe_key,
                payload=webhook_payload,
                status="queued",
                max_attempts=5,
            )
            if row_id is None:
                continue

            # Sprint 8.3: make delivery truly asynchronous.
            # At scan-completion time we only enqueue; a dedicated Celery task drains the queue.
            attempted += 1
            sent += 0

    return {"attempted": attempted, "queued": attempted, "sent": sent, "hooks": len(hooks_all), "events": len(events), "rules": len(rules)}


def deliver_events_for_scan(scan_id: str) -> Dict[str, Any]:
    """Enqueue scan-derived events for asynchronous delivery."""
    return _enqueue_events(build_events_for_scan(scan_id))


def emit_platform_event(event_type: str, payload: Dict[str, Any], dedupe_key: str = "") -> Dict[str, Any]:
    event_type = str(event_type or "").strip()
    if not event_type:
        return {"attempted": 0, "queued": 0, "sent": 0, "hooks": 0, "events": 0, "rules": 0}
    dedupe = str(dedupe_key or "").strip() or _sha256_hex(
        f"{event_type}:{json.dumps(payload or {}, sort_keys=True, separators=(',', ':'))}"
    )
    return _enqueue_events([{"event_type": event_type, "dedupe_key": dedupe, "payload": payload or {}}])

def test_rules_for_scan(scan_id: str | None = None) -> dict:
    """
    Used by /integrations/rules/test.
    Returns which rules would route which events for a given scan.
    Minimal but stable: matches by event_type + optional simple conditions if present.
    """
    # Lazy import to avoid circular imports / optional functions
    from db import list_event_rules

    # If scan_id not provided, use latest scan if your DB has it; otherwise require scan_id.
    if not scan_id:
        # Fallback: return empty (UI will still work, and API won’t crash)
        return {"ok": True, "scan_id": None, "matches": []}

    events = build_events_for_scan(scan_id) or []
    rules = list_event_rules(limit=500) or []

    matches: list[dict] = []
    for ev in events:
        ev_type = (ev.get("event_type") or "").strip()
        payload = ev.get("payload") or {}
        data = payload.get("data") or payload  # tolerate either shape
        facts = (data.get("facts") if isinstance(data, dict) else None) or {}
        asset_key = (data.get("asset_key") if isinstance(data, dict) else None) or facts.get("asset_key") or ""

        for r in rules:
            if not r or not r.get("enabled", True):
                continue

            # Match event type
            ev_types = r.get("event_types") or r.get("event_types_json") or []
            if isinstance(ev_types, str):
                try:
                    ev_types = json.loads(ev_types)
                except Exception:
                    ev_types = [ev_types]
            if ev_type not in ev_types and "*" not in ev_types:
                continue

            # Optional: very lightweight condition support (safe defaults)
            conds = r.get("conditions") or r.get("conditions_json") or []
            if isinstance(conds, str):
                try:
                    conds = json.loads(conds)
                except Exception:
                    conds = []

            ok = True
            for c in conds:
                if not isinstance(c, dict):
                    continue
                field = c.get("field")
                op = c.get("op")
                val = c.get("value")

                # Support common fields (extend later)
                if field in ("asset_key", "host", "port", "days_until_expiry", "quantum_risk_score", "severity", "finding_rule_id"):
                    # Pull from facts first, then from data
                    cur = facts.get(field)
                    if cur is None and isinstance(data, dict):
                        cur = data.get(field)

                    # Very simple operators
                    try:
                        if op == "==" and cur != val:
                            ok = False
                        elif op == "!=" and cur == val:
                            ok = False
                        elif op == ">=" and float(cur) < float(val):
                            ok = False
                        elif op == "<=" and float(cur) > float(val):
                            ok = False
                        elif op == "in" and cur not in (val or []):
                            ok = False
                    except Exception:
                        # If condition can’t be evaluated, treat as not matched
                        ok = False

                if not ok:
                    break

            if not ok:
                continue

            matches.append({
                "rule_id": r.get("id"),
                "rule_name": r.get("name"),
                "event_type": ev_type,
                "asset_key": asset_key,
                "webhook_ids": r.get("webhook_ids") or [],
            })

    return {"ok": True, "scan_id": scan_id, "matches": matches}


def deliver_test_ping(webhook_id: int) -> dict:
    hooks = {int(h["id"]): h for h in list_webhooks(include_secret=True) if h.get("enabled")}
    wh = hooks.get(int(webhook_id))
    if not wh:
        raise KeyError("webhook not found")
    if webhook_requires_credential(wh) and not wh.get("credential_id"):
        raise PermissionError("webhook requires credential_id")

    nonce = str(uuid.uuid4())
    et = "test.ping"
    dedupe_key = _sha256_hex(f"test.ping:{webhook_id}:{nonce}")
    payload = _delivery_payload(wh, et, dedupe_key, {"message": "pong", "nonce": nonce})

    row_id = record_webhook_event(
        webhook_id=int(webhook_id),
        event_type=et,
        dedupe_key=dedupe_key,
        payload=payload,
        status="queued",
        max_attempts=5,
    )
    if row_id is None:
        return {"ok": False, "reason": "deduped"}

    body = json.dumps(payload).encode("utf-8")
    try:
        bump_webhook_attempt(row_id)
        code, excerpt = _post_json(str(wh.get("url") or ""), body, et, secret=_resolve_webhook_secret(wh), timeout_s=int(wh.get("timeout_seconds") or 10))
        update_webhook_event(row_id, status="sent", http_status=code, error_text="", response_excerpt=excerpt, next_attempt_at="")
        return {"ok": True, "row_id": row_id, "http_status": code, "response_excerpt": excerpt}
    except urlerror.HTTPError as e:
        code = int(getattr(e, "code", 0) or 0)
        excerpt = _read_http_error_excerpt(e)
        update_webhook_event(row_id, status="failed", http_status=code, error_text=str(e), response_excerpt=excerpt)
        return {"ok": False, "row_id": row_id, "http_status": code, "response_excerpt": excerpt, "error": str(e)}
    except Exception as e:
        update_webhook_event(row_id, status="failed", http_status=0, error_text=str(e), response_excerpt="")
        return {"ok": False, "row_id": row_id, "error": str(e)}


def retry_pending_deliveries(limit: int = 50, max_attempts: int = 5) -> Dict[str, Any]:
    # Synchronous debugging endpoint used by the UI.
    # The production path uses Celery (drain_webhook_delivery_queue), but this is still handy for a "Retry now" button.
    stats = drain_webhook_delivery_queue(limit=int(limit or 50), max_attempts=int(max_attempts or 5))
    stats["forced"] = True
    return stats


def _resolve_webhook_secret(wh: dict) -> str:
    cid = wh.get("credential_id")
    if not cid:
        # Vault-only mode: no credential_id means no secret available
        return ""
    cred = get_credential(int(cid), reveal=True)
    return str((cred or {}).get("secret") or "")
