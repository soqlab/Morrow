"""Deferred writer for routine audit entries.

Every authorized request records an audit entry. That entry is a read-modify-write of a hash
chain -- read the newest entry_hash for the tenant, hash this entry onto it, insert, commit -- so
a read of a dashboard paid for an extra transaction, and at 50 concurrent readers the audit write
was a measurable share of the request (docs/LOAD_TEST_REPORT.md section 10.5).

Routine entries are now queued in memory and written by one background thread in batches, the way
the request journal already is. What that must not change:

  * **Ordering and the chain.** One writer drains the queue in submission order and appends each
    entry through the same db.append_audit_log, which holds the per-tenant chain lock. The chain
    is built exactly as it was, in the order the requests happened.
  * **Failing closed.** A deferred entry is only accepted while the writer is healthy and the
    queue has room. The moment a flush fails, or the queue fills, every caller that asked for a
    guaranteed record writes synchronously again and raises if that write fails -- which is what
    `required=True` has always meant. `degraded()` says which mode the process is in.
  * **Being readable.** Anything that reads or verifies the audit log flushes the queue first, so
    an entry is never missing from a list that should contain it.

High-severity entries -- a denial, a break-glass use, an operator action -- are never queued. They
go straight to storage and fail closed on the spot. Only a `decision="allow"` record of a read is
deferred, and only ever by a few hundred milliseconds.
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

FLUSH_INTERVAL_SECONDS = 0.25
#: Above this, callers write synchronously instead of queueing. Bounds memory and means a stuck
#: database turns into slow-but-correct requests, never into lost audit entries.
QUEUE_MAX = 5000

_lock = threading.Lock()
_flush_lock = threading.Lock()
_pending: List[Tuple[str, Dict[str, Any]]] = []
_writer: Dict[str, Any] = {"thread": None}
_wakeup = threading.Event()
_health: Dict[str, Any] = {"healthy": True, "last_error": "", "last_error_at": 0.0,
                           "written": 0, "failed": 0, "queued": 0, "synchronous": 0}


def enabled() -> bool:
    """Deferred writing can be switched off; then every entry is written on the request."""
    return str(os.getenv("MORROW_AUDIT_DEFERRED_WRITES", "1") or "1").strip().lower() in {"1", "true", "yes", "on"}


def degraded() -> bool:
    """True when the writer has failed and every entry must be written synchronously."""
    with _lock:
        return not _health["healthy"]


def state() -> Dict[str, Any]:
    with _lock:
        return {**_health, "pending": len(_pending), "enabled": enabled(),
                "flush_interval_seconds": FLUSH_INTERVAL_SECONDS, "queue_max": QUEUE_MAX}


def _mark_failure(exc: BaseException) -> None:
    with _lock:
        _health["healthy"] = False
        _health["last_error"] = exc.__class__.__name__
        _health["last_error_at"] = time.time()
        _health["failed"] += 1
    logger.error("audit queue write failed (%s); audit writes are synchronous until it succeeds",
                 exc.__class__.__name__)


def _mark_success(n: int) -> None:
    with _lock:
        _health["healthy"] = True
        _health["written"] += n


def _ensure_writer() -> None:
    thread = _writer["thread"]
    if thread is not None and thread.is_alive():
        return
    with _lock:
        thread = _writer["thread"]
        if thread is not None and thread.is_alive():
            return
        thread = threading.Thread(target=_loop, name="audit-log-writer", daemon=True)
        _writer["thread"] = thread
        thread.start()


def _loop() -> None:
    while True:
        _wakeup.wait(FLUSH_INTERVAL_SECONDS)
        _wakeup.clear()
        try:
            flush()
        except Exception:  # never let the writer thread die; flush() records the failure
            pass


def submit(org_id: str, entry: Dict[str, Any]) -> bool:
    """Queue one routine audit entry. False means "write it yourself, now".

    The caller is told to write synchronously when deferred writing is off, when the last flush
    failed, or when the queue is full -- so a caller that must not lose the entry never silently
    hands it to a writer that cannot write.
    """
    if not enabled():
        return False
    with _lock:
        if not _health["healthy"] or len(_pending) >= QUEUE_MAX:
            _health["synchronous"] += 1
            return False
        _pending.append((str(org_id or ""), dict(entry)))
        _health["queued"] += 1
    _ensure_writer()
    return True


def flush() -> int:
    """Write every queued entry now, in order. Returns how many were written.

    A batch that fails is put back at the front of the queue and the writer is marked unhealthy,
    so nothing is dropped and every caller goes back to writing synchronously until it recovers.
    """
    with _flush_lock:
        with _lock:
            if not _pending:
                return 0
            batch, _pending[:] = list(_pending), []
        from db import append_audit_log, reset_current_organization_id, set_current_organization_id
        written = 0
        try:
            for index, (org_id, entry) in enumerate(batch):
                token = set_current_organization_id(org_id)
                try:
                    append_audit_log(**entry)
                except Exception:
                    # Keep this entry and everything after it, in order, for the next attempt.
                    with _lock:
                        _pending[:0] = batch[index:]
                    raise
                finally:
                    reset_current_organization_id(token)
                written += 1
        except Exception as exc:
            _mark_failure(exc)
            if written:
                _mark_success(written)
                with _lock:
                    _health["healthy"] = False
            return written
        _mark_success(written)
        return written


def drain(timeout: float = 5.0) -> int:
    """Flush, retrying briefly, for shutdown and for readers that must see everything."""
    deadline = time.monotonic() + max(0.0, timeout)
    total = 0
    while True:
        total += flush()
        with _lock:
            remaining = len(_pending)
        if not remaining or time.monotonic() >= deadline:
            return total
        time.sleep(0.05)


atexit.register(drain)
