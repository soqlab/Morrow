from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional


_SENTRY_READY = False
logger = logging.getLogger("morrow.observability")


def _ensure_sentry() -> bool:
    global _SENTRY_READY
    dsn = str(os.getenv("SENTRY_DSN") or "").strip()
    if not dsn:
        return False
    if _SENTRY_READY:
        return True
    try:
        import sentry_sdk  # type: ignore

        sentry_sdk.init(
            dsn=dsn,
            environment=str(os.getenv("MORROW_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "").strip() or None,
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0") or 0),
        )
        _SENTRY_READY = True
        return True
    except Exception as exc:
        logger.warning("sentry initialization failed: %s", exc)
        return False


def capture_exception(exc: BaseException, context: Optional[Dict[str, Any]] = None) -> None:
    """Capture unexpected exceptions without making Sentry a hard runtime dependency."""
    context = context or {}
    if _ensure_sentry():
        try:
            import sentry_sdk  # type: ignore

            with sentry_sdk.push_scope() as scope:
                for key, value in context.items():
                    scope.set_extra(str(key), value)
                sentry_sdk.capture_exception(exc)
            return
        except Exception as sentry_exc:
            logger.warning("sentry capture failed: %s", sentry_exc)

    # Cloud Error Reporting can ingest structured exception logs from stdout/stderr.
    logger.exception("captured exception", extra=context)
