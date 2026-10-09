"""
Scheduled Scan Engine

Allows organizations to define recurring scan targets with configurable
intervals. The FastAPI startup hook runs a background coroutine that
checks for due scans every 5 minutes and executes them automatically.

Scan results are written to the scans table and a telemetry event is
pushed so the War Room / Notification Center sees them in real-time.

Pure stdlib — no APScheduler, Celery, or external dependencies.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("pqc.scheduler")

# ── In-memory schedule registry (backed by DB) ──────────────────────────────
_LOOP_TASK: Optional[asyncio.Task] = None  # set by start_scheduler()


# ── DB helpers ────────────────────────────────────────────────────────────────

def _ensure_table(db_conn) -> None:
    """Create the scan_schedules table if it doesn't exist."""
    db_conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL,
            name        TEXT NOT NULL,
            targets     TEXT NOT NULL,        -- JSON array of "host:port" strings
            interval_hours INTEGER NOT NULL DEFAULT 24,
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL,
            last_run_at TEXT,
            next_run_at TEXT NOT NULL,
            last_status TEXT,                 -- "ok" | "error" | "running"
            last_error  TEXT,
            run_count   INTEGER NOT NULL DEFAULT 0
        )
    """)
    db_conn.commit()


def _row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    # Parse targets JSON
    try:
        d["targets"] = json.loads(d.get("targets") or "[]")
    except Exception:
        d["targets"] = []
    d["enabled"] = bool(d.get("enabled", 1))
    return d


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_schedule(
    db_conn,
    org_id: str,
    name: str,
    targets: List[str],
    interval_hours: int = 24,
    enabled: bool = True,
) -> Dict[str, Any]:
    import uuid
    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(hours=interval_hours)).isoformat()
    sid = str(uuid.uuid4())
    _ensure_table(db_conn)
    db_conn.execute(
        """INSERT INTO scan_schedules
           (id, org_id, name, targets, interval_hours, enabled, created_at, next_run_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (sid, org_id, name, json.dumps(targets), interval_hours,
         1 if enabled else 0, now.isoformat(), next_run),
    )
    db_conn.commit()
    return get_schedule(db_conn, sid, org_id)


def list_schedules(db_conn, org_id: str) -> List[Dict[str, Any]]:
    _ensure_table(db_conn)
    rows = db_conn.execute(
        "SELECT * FROM scan_schedules WHERE org_id=? ORDER BY created_at DESC", (org_id,)
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_schedule(db_conn, schedule_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    _ensure_table(db_conn)
    row = db_conn.execute(
        "SELECT * FROM scan_schedules WHERE id=? AND org_id=?", (schedule_id, org_id)
    ).fetchone()
    return _row_to_dict(row) if row else None


def update_schedule(
    db_conn,
    schedule_id: str,
    org_id: str,
    name: Optional[str] = None,
    targets: Optional[List[str]] = None,
    interval_hours: Optional[int] = None,
    enabled: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    _ensure_table(db_conn)
    existing = get_schedule(db_conn, schedule_id, org_id)
    if not existing:
        return None
    new_name = name if name is not None else existing["name"]
    new_targets = targets if targets is not None else existing["targets"]
    new_interval = interval_hours if interval_hours is not None else existing["interval_hours"]
    new_enabled = enabled if enabled is not None else existing["enabled"]
    # Recalculate next_run if interval changed
    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(hours=new_interval)).isoformat()
    db_conn.execute(
        """UPDATE scan_schedules
           SET name=?, targets=?, interval_hours=?, enabled=?, next_run_at=?
           WHERE id=? AND org_id=?""",
        (new_name, json.dumps(new_targets), new_interval,
         1 if new_enabled else 0, next_run, schedule_id, org_id),
    )
    db_conn.commit()
    return get_schedule(db_conn, schedule_id, org_id)


def delete_schedule(db_conn, schedule_id: str, org_id: str) -> bool:
    _ensure_table(db_conn)
    cur = db_conn.execute(
        "DELETE FROM scan_schedules WHERE id=? AND org_id=?", (schedule_id, org_id)
    )
    db_conn.commit()
    return cur.rowcount > 0


def get_due_schedules(db_conn) -> List[Dict[str, Any]]:
    """Return all enabled schedules whose next_run_at <= now."""
    _ensure_table(db_conn)
    now = datetime.now(timezone.utc).isoformat()
    rows = db_conn.execute(
        """SELECT * FROM scan_schedules
           WHERE enabled=1 AND next_run_at <= ? AND (last_status IS NULL OR last_status != 'running')
           ORDER BY next_run_at ASC""",
        (now,)
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def mark_running(db_conn, schedule_id: str) -> None:
    _ensure_table(db_conn)
    db_conn.execute(
        "UPDATE scan_schedules SET last_status='running' WHERE id=?", (schedule_id,)
    )
    db_conn.commit()


def mark_complete(db_conn, schedule_id: str, status: str, error: str = "") -> None:
    """After a scheduled scan completes, update last_run and compute next_run."""
    _ensure_table(db_conn)
    row = db_conn.execute(
        "SELECT interval_hours, run_count FROM scan_schedules WHERE id=?", (schedule_id,)
    ).fetchone()
    if not row:
        return
    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(hours=row["interval_hours"])).isoformat()
    db_conn.execute(
        """UPDATE scan_schedules
           SET last_run_at=?, next_run_at=?, last_status=?, last_error=?, run_count=run_count+1
           WHERE id=?""",
        (now.isoformat(), next_run, status, error[:500] if error else "", schedule_id),
    )
    db_conn.commit()


# ── Background scheduler loop ─────────────────────────────────────────────────

async def _scheduler_loop(get_db_fn, run_scan_fn, push_event_fn) -> None:
    """
    Background coroutine.  Wakes every 5 minutes, finds due schedules,
    runs them via run_scan_fn, and pushes telemetry events.

    get_db_fn()        — returns a DB connection context manager
    run_scan_fn(host, port, org_id) — calls the scanner, returns result dict
    push_event_fn(org_id, type, data) — pushes a telemetry event
    """
    log.info("Scan scheduler started — checking every 5 minutes")
    while True:
        try:
            await asyncio.sleep(300)  # check every 5 minutes
            with get_db_fn() as db:
                due = get_due_schedules(db)

            for schedule in due:
                sid = schedule["id"]
                org_id = schedule["org_id"]
                targets = schedule.get("targets") or []
                log.info(f"[scheduler] Running schedule {sid!r} for org {org_id!r}: {targets}")

                with get_db_fn() as db:
                    mark_running(db, sid)

                errors = []
                scan_results = []
                for target in targets[:20]:  # safety cap
                    try:
                        host_port = target.rsplit(":", 1)
                        host = host_port[0]
                        port = int(host_port[1]) if len(host_port) > 1 else 443
                        result = await asyncio.get_event_loop().run_in_executor(
                            None, run_scan_fn, host, port, org_id
                        )
                        if result:
                            scan_results.append(result)
                            await push_event_fn(org_id, "scan_complete", {
                                "host": host,
                                "port": port,
                                "risk_level": result.get("risk_level", "unknown"),
                                "algorithm": result.get("algorithm", ""),
                                "source": "scheduler",
                                "schedule_id": sid,
                                "schedule_name": schedule["name"],
                            })
                    except Exception as e:
                        errors.append(f"{target}: {e}")
                        log.warning(f"[scheduler] Error scanning {target}: {e}")

                final_status = "error" if errors and not scan_results else "ok"
                with get_db_fn() as db:
                    mark_complete(db, sid, final_status, "; ".join(errors))

                log.info(f"[scheduler] Schedule {sid!r} done — {len(scan_results)} scans, {len(errors)} errors")

        except asyncio.CancelledError:
            log.info("Scan scheduler stopped")
            break
        except Exception as e:
            log.error(f"[scheduler] Loop error: {e}")
            await asyncio.sleep(60)  # back off on unexpected error


def start_scheduler(get_db_fn, run_scan_fn, push_event_fn) -> asyncio.Task:
    """Start the background scheduler. Call from FastAPI startup event."""
    global _LOOP_TASK
    loop = asyncio.get_event_loop()
    _LOOP_TASK = loop.create_task(
        _scheduler_loop(get_db_fn, run_scan_fn, push_event_fn)
    )
    return _LOOP_TASK


def stop_scheduler() -> None:
    global _LOOP_TASK
    if _LOOP_TASK and not _LOOP_TASK.done():
        _LOOP_TASK.cancel()
        _LOOP_TASK = None
