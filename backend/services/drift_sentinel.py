"""Crypto Drift Sentinel — hourly snapshot diffing, fires telemetry on regression."""
import asyncio
import hashlib
import json
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

_sentinel_task: Optional[asyncio.Task] = None
_INTERVAL = 3600  # seconds between snapshots


def _table_sql():
    return """
    CREATE TABLE IF NOT EXISTS drift_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS drift_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        delta_json TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    """


def init_tables(db) -> None:
    for stmt in _table_sql().strip().split(";"):
        s = stmt.strip()
        if s:
            db.execute(s)
    db.commit()


def _take_snapshot(db, org_id: str) -> dict:
    # `assets` carries ownership and criticality, not crypto facts: it has no
    # algorithm, risk_level or port column, so this query raised on every call
    # and drift never had a snapshot to compare. The observed cryptography lives
    # in scan_results, keyed as "host:port".
    rows = db.execute(
        """SELECT asset_key, key_type, risk_level
           FROM scan_results
           WHERE organization_id=?
           GROUP BY asset_key
           HAVING scanned_at = MAX(scanned_at)
           ORDER BY asset_key""",
        (org_id,),
    ).fetchall()
    items = []
    for r in rows:
        key = str(r[0] or "")
        host, sep, port = key.rpartition(":")
        try:
            port_n = int(port) if sep else 0
        except ValueError:
            port_n = 0
        items.append({"key": key, "algorithm": r[1] or "", "risk": r[2] or "", "port": port_n})
    return {"org_id": org_id, "assets": items, "count": len(items)}


def _snapshot_hash(snap: dict) -> str:
    return hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest()


def _diff_snapshots(old: dict, new: dict) -> list[dict]:
    diffs = []
    old_map = {a["key"]: a for a in old.get("assets", [])}
    new_map = {a["key"]: a for a in new.get("assets", [])}

    for key, na in new_map.items():
        if key not in old_map:
            diffs.append({"type": "new_asset", "asset": key, "detail": na})
        else:
            oa = old_map[key]
            if na.get("risk") != oa.get("risk"):
                diffs.append({
                    "type": "risk_change",
                    "asset": key,
                    "from": oa.get("risk"),
                    "to": na.get("risk"),
                })
            if na.get("algorithm") != oa.get("algorithm"):
                diffs.append({
                    "type": "algorithm_change",
                    "asset": key,
                    "from": oa.get("algorithm"),
                    "to": na.get("algorithm"),
                })

    for key in old_map:
        if key not in new_map:
            diffs.append({"type": "asset_removed", "asset": key})

    return diffs


def store_snapshot(db, org_id: str, snap: dict) -> str:
    h = _snapshot_hash(snap)
    db.execute(
        "INSERT INTO drift_snapshots (org_id, snapshot_hash, snapshot_json, created_at) VALUES (?,?,?,?)",
        (org_id, h, json.dumps(snap), int(time.time())),
    )
    db.commit()
    return h


def get_last_snapshot(db, org_id: str) -> Optional[dict]:
    row = db.execute(
        "SELECT snapshot_json FROM drift_snapshots WHERE org_id=? ORDER BY created_at DESC LIMIT 1",
        (org_id,),
    ).fetchone()
    return json.loads(row[0]) if row else None


def store_drift_event(db, org_id: str, event_type: str, description: str, delta: list) -> None:
    db.execute(
        "INSERT INTO drift_events (org_id, event_type, description, delta_json, created_at) VALUES (?,?,?,?,?)",
        (org_id, event_type, description, json.dumps(delta), int(time.time())),
    )
    db.commit()


def list_drift_events(db, org_id: str, limit: int = 50) -> list[dict]:
    rows = db.execute(
        "SELECT id, event_type, description, delta_json, created_at FROM drift_events "
        "WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
        (org_id, limit),
    ).fetchall()
    return [
        {"id": r[0], "event_type": r[1], "description": r[2],
         "delta": json.loads(r[3]), "created_at": r[4]}
        for r in rows
    ]


def get_drift_status(db, org_id: str) -> dict:
    last = db.execute(
        "SELECT created_at, snapshot_hash FROM drift_snapshots WHERE org_id=? ORDER BY created_at DESC LIMIT 1",
        (org_id,),
    ).fetchone()
    recent_events = db.execute(
        "SELECT COUNT(*) FROM drift_events WHERE org_id=? AND created_at > ?",
        (org_id, int(time.time()) - 86400),
    ).fetchone()[0]
    return {
        "status": "drift_detected" if recent_events > 0 else "clean",
        "last_snapshot_at": last[0] if last else None,
        "last_snapshot_hash": last[1] if last else None,
        "drift_events_24h": recent_events,
    }


async def _sentinel_loop(get_db, push_telemetry) -> None:
    await asyncio.sleep(10)  # short delay on startup
    while True:
        try:
            with get_db() as db:
                init_tables(db)
                orgs = db.execute("SELECT DISTINCT organization_id FROM assets").fetchall()
                for (org_id,) in orgs:
                    try:
                        snap = _take_snapshot(db, org_id)
                        prev = get_last_snapshot(db, org_id)
                        store_snapshot(db, org_id, snap)
                        if prev:
                            diffs = _diff_snapshots(prev, snap)
                            regressions = [d for d in diffs if d.get("type") in ("risk_change", "algorithm_change")]
                            if regressions:
                                desc = f"{len(regressions)} regression(s) detected"
                                store_drift_event(db, org_id, "regression", desc, regressions)
                                await push_telemetry(
                                    org_id=org_id,
                                    event_type="drift_regression",
                                    data={"description": desc, "regressions": regressions[:5]},
                                )
                                logger.warning("[Drift Sentinel] %s — %s", org_id, desc)
                    except Exception as e:
                        logger.debug("[Drift Sentinel] org %s error: %s", org_id, e)
        except Exception as e:
            logger.debug("[Drift Sentinel] loop error: %s", e)
        await asyncio.sleep(_INTERVAL)


def start_sentinel(get_db, push_telemetry) -> None:
    global _sentinel_task
    if _sentinel_task is None or _sentinel_task.done():
        _sentinel_task = asyncio.create_task(_sentinel_loop(get_db, push_telemetry))
        logger.info("[Drift Sentinel] started — interval %ds", _INTERVAL)


def stop_sentinel() -> None:
    global _sentinel_task
    if _sentinel_task and not _sentinel_task.done():
        _sentinel_task.cancel()
        logger.info("[Drift Sentinel] stopped")
