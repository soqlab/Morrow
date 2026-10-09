"""
Real-Time Crypto Telemetry

Maintains an in-memory event bus that collects live events from all scanner
subsystems. Consumers (SSE clients) receive a stream of newline-delimited
JSON events without polling.

Event types:
  scan_complete   — a host was scanned; includes host, risk_level, algorithm
  canary_trip     — a canary endpoint was triggered
  finding_new     — a new high/critical finding was detected
  hndl_alert      — a harvest-now-decrypt-later beacon was seen
  alert_fired     — a Slack / Teams / PagerDuty alert was sent
  maturity_change — organization maturity level changed
  digest_sent     — a scheduled digest was delivered
  system_info     — heartbeat / stats update

Usage (SSE endpoint in app.py):
    from services.realtime_telemetry import push_event, event_stream

    @app.get("/v1/telemetry/stream")
    async def telemetry_stream(request: Request):
        return StreamingResponse(event_stream(request, org_id), media_type="text/event-stream")

    # From any scanner subsystem:
    push_event("scan_complete", {"host": "...", "risk_level": "high"}, org_id)
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List


# ── In-memory event store ──────────────────────────────────────────────────────

_MAX_HISTORY = 500          # events kept in ring buffer
_HEARTBEAT_INTERVAL = 15   # seconds between SSE keepalive pings

_event_lock = threading.Lock()
_event_history: deque = deque(maxlen=_MAX_HISTORY)
_event_id_counter = 0

# Per-org subscriber queues: org_id → list of asyncio.Queue
_subscribers: Dict[str, List[asyncio.Queue]] = {}
_sub_lock = threading.Lock()

# Counters
_counters: Dict[str, Dict[str, int]] = {}  # org_id → {event_type: count}
_counter_lock = threading.Lock()


# ── Event model ────────────────────────────────────────────────────────────────

def _make_event(event_type: str, data: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    global _event_id_counter
    with _event_lock:
        _event_id_counter += 1
        eid = _event_id_counter
    return {
        "id":         eid,
        "type":       event_type,
        "org_id":     org_id,
        "data":       data,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }


def _sse_format(event: Dict[str, Any]) -> str:
    """Format an event as an SSE message."""
    return (
        f"id: {event['id']}\n"
        f"event: {event['type']}\n"
        f"data: {json.dumps(event)}\n\n"
    )


# ── Public push API ────────────────────────────────────────────────────────────

def push_event(event_type: str, data: Dict[str, Any], org_id: str = "default") -> Dict[str, Any]:
    """
    Publish an event to all SSE subscribers for this org and append to history.

    Safe to call from sync code (scanner workers, Celery tasks, etc.).
    """
    event = _make_event(event_type, data, org_id)

    with _event_lock:
        _event_history.append(event)

    with _counter_lock:
        org_c = _counters.setdefault(org_id, {})
        org_c[event_type] = org_c.get(event_type, 0) + 1

    # Fan-out to all subscribers: try to push into each asyncio Queue.
    # Queues live in an event loop thread; use call_soon_threadsafe.
    with _sub_lock:
        queues = list(_subscribers.get(org_id, []) + _subscribers.get("*", []))

    for q_info in queues:
        loop: asyncio.AbstractEventLoop = q_info["loop"]
        q:    asyncio.Queue             = q_info["queue"]
        try:
            loop.call_soon_threadsafe(q.put_nowait, event)
        except Exception:
            pass

    return event


def push_scan_complete(
    host: str,
    port: int,
    risk_level: str,
    algorithm: str,
    key_bits: int,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("scan_complete", {
        "host":      host,
        "port":      port,
        "risk_level":risk_level,
        "algorithm": algorithm,
        "key_bits":  key_bits,
    }, org_id)


def push_canary_trip(
    canary_id: str,
    triggered_by: str,
    severity: str,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("canary_trip", {
        "canary_id":    canary_id,
        "triggered_by": triggered_by,
        "severity":     severity,
    }, org_id)


def push_finding(
    host: str,
    finding_type: str,
    severity: str,
    description: str,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("finding_new", {
        "host":        host,
        "type":        finding_type,
        "severity":    severity,
        "description": description,
    }, org_id)


def push_hndl_alert(
    source_ip: str,
    protocol: str,
    classification: str,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("hndl_alert", {
        "source_ip":      source_ip,
        "protocol":       protocol,
        "classification": classification,
    }, org_id)


def push_alert_fired(
    channel: str,
    event_type: str,
    severity: str,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("alert_fired", {
        "channel":    channel,
        "event_type": event_type,
        "severity":   severity,
    }, org_id)


def push_maturity_change(
    old_level: int,
    new_level: int,
    label: str,
    org_id: str = "default",
) -> Dict[str, Any]:
    return push_event("maturity_change", {
        "old_level": old_level,
        "new_level": new_level,
        "label":     label,
    }, org_id)


# ── History & stats ────────────────────────────────────────────────────────────

def get_recent_events(
    org_id: str = "default",
    limit: int = 50,
    event_type: str = "",
    since_id: int = 0,
) -> List[Dict[str, Any]]:
    """Return recent events from the ring buffer, filtered by org and type."""
    with _event_lock:
        events = list(_event_history)

    filtered = [
        e for e in events
        if (e["org_id"] == org_id or org_id == "*")
        and (not event_type or e["type"] == event_type)
        and e["id"] > since_id
    ]
    return filtered[-limit:]


def get_event_stats(org_id: str = "default") -> Dict[str, Any]:
    """Return per-type event counts and last-event timestamps."""
    with _counter_lock:
        org_counts = dict(_counters.get(org_id, {}))

    with _event_lock:
        events = [e for e in _event_history if e["org_id"] == org_id]

    last_by_type: Dict[str, str] = {}
    for e in events:
        last_by_type[e["type"]] = e["timestamp"]

    total = sum(org_counts.values())
    return {
        "org_id":       org_id,
        "total_events": total,
        "by_type":      org_counts,
        "last_seen":    last_by_type,
        "buffer_size":  len(_event_history),
    }


def get_live_kpis(org_id: str = "default") -> Dict[str, Any]:
    """
    Compute live KPIs from recent events for the real-time dashboard panel:
    - scans in last hour
    - canary trips in last 24h
    - critical findings in last 24h
    - HNDL alerts in last 24h
    """
    now = time.time()
    hour_ago = now - 3600
    day_ago  = now - 86400

    with _event_lock:
        events = list(_event_history)

    def _ts(e: Dict) -> float:
        try:
            dt = datetime.fromisoformat(e["timestamp"])
            return dt.timestamp()
        except Exception:
            return 0.0

    def _match(e: Dict, etype: str, since: float) -> bool:
        return e["org_id"] == org_id and e["type"] == etype and _ts(e) >= since

    scans_1h       = sum(1 for e in events if _match(e, "scan_complete", hour_ago))
    canary_24h     = sum(1 for e in events if _match(e, "canary_trip", day_ago))
    findings_24h   = sum(1 for e in events if _match(e, "finding_new", day_ago)
                         and e.get("data", {}).get("severity") in ("critical", "high"))
    hndl_24h       = sum(1 for e in events if _match(e, "hndl_alert", day_ago))
    alerts_24h     = sum(1 for e in events if _match(e, "alert_fired", day_ago))

    # Most recent scan
    scan_events    = [e for e in events if _match(e, "scan_complete", 0)]
    last_scan_host = scan_events[-1]["data"].get("host", "") if scan_events else ""
    last_scan_risk = scan_events[-1]["data"].get("risk_level", "") if scan_events else ""

    return {
        "org_id":          org_id,
        "scans_last_hour": scans_1h,
        "canary_trips_24h":canary_24h,
        "critical_findings_24h": findings_24h,
        "hndl_alerts_24h": hndl_24h,
        "alerts_fired_24h":alerts_24h,
        "last_scan_host":  last_scan_host,
        "last_scan_risk":  last_scan_risk,
        "computed_at":     datetime.now(timezone.utc).isoformat(),
    }


# ── SSE async generator ────────────────────────────────────────────────────────

async def event_stream(
    request: Any,   # starlette.requests.Request
    org_id: str = "default",
    last_event_id: int = 0,
) -> AsyncIterator[bytes]:
    """
    Async generator for Server-Sent Events.
    Yields missed history events first, then live events.

    Usage in FastAPI:
        from fastapi.responses import StreamingResponse
        return StreamingResponse(event_stream(request, org_id), media_type="text/event-stream")
    """
    loop = asyncio.get_event_loop()
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    q_info = {"loop": loop, "queue": queue}

    with _sub_lock:
        _subscribers.setdefault(org_id, []).append(q_info)
        _subscribers.setdefault("*", [])  # platform-admin wildcard

    try:
        # 1. Replay history since last_event_id
        missed = get_recent_events(org_id, limit=100, since_id=last_event_id)
        for evt in missed:
            yield _sse_format(evt).encode()

        # 2. Stream live events
        last_heartbeat = time.monotonic()
        while True:
            if await request.is_disconnected():
                break

            now_mono = time.monotonic()
            if now_mono - last_heartbeat >= _HEARTBEAT_INTERVAL:
                yield b": heartbeat\n\n"
                last_heartbeat = now_mono

            try:
                event = await asyncio.wait_for(queue.get(), timeout=5.0)
                yield _sse_format(event).encode()
            except asyncio.TimeoutError:
                continue
    finally:
        with _sub_lock:
            org_list = _subscribers.get(org_id, [])
            if q_info in org_list:
                org_list.remove(q_info)


# ── Emit system-info heartbeat (call from background task) ─────────────────────

def emit_system_heartbeat(org_id: str = "default") -> Dict[str, Any]:
    """Push a system_info event with current KPIs — call from a periodic task."""
    kpis = get_live_kpis(org_id)
    return push_event("system_info", kpis, org_id)
