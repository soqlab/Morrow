"""Paste anything (services/paste_anything.py): the home page's one input, for more than a domain.

  POST /api/public/paste    {"content": "<text, or base64 of a file>", "encoding": "text"|"base64",
                             "name": "<file name, optional>", "as": "<a kind, when the first answer asked>"}

Unauthenticated, under /api/public (so app._auth_public_path and the public CORS policy apply: a
cross-site page cannot send it, because JSON needs a preflight that is refused). The body is read as
a stream with a hard cap and never logged; the answer is never cached. Errors are
``{"error", "detail"}`` with 400, 413, 415, 422 (a private key: refused, with the warning), 429 (with
Retry-After) or 503.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

PREFIX = "/api/public"
_NO_STORE = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}


def _ip_of(deps: Any, request: Request) -> str:
    getter = getattr(deps, "client_ip", None)
    if callable(getter):
        try:
            return str(getter(request) or "")
        except Exception:
            pass
    return str(request.client.host if request.client else "")


def _error(exc: Any) -> JSONResponse:
    headers = dict(_NO_STORE)
    if getattr(exc, "retry_after", None):
        headers["Retry-After"] = str(int(max(1, exc.retry_after)))
    return JSONResponse(exc.as_dict(), status_code=exc.status_code, headers=headers)


def create_paste_router(deps: Any) -> APIRouter:
    """deps: client_ip(request) -> str."""
    router = APIRouter(prefix=PREFIX, tags=["public-paste"])

    @router.post("/paste")
    async def paste(request: Request):
        from services import json_limits
        from services import paste_anything as pa
        from services import pcap_tls

        ctype = str(request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return JSONResponse({"error": "bad_request", "detail": "Send JSON: {\"content\": \"...\"}."},
                                status_code=415, headers=_NO_STORE)
        limit = pa.MAX_BODY_BYTES
        declared = request.headers.get("content-length")
        too_big = pa.PasteError(413, "too_large", f"That is larger than {pa.MAX_INPUT_BYTES // (1024 * 1024)} MB, "
                                "the most Morrow reads.")
        if declared and declared.isdigit() and int(declared) > limit:
            return _error(too_big)
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > limit:
                return _error(too_big)
            chunks.append(chunk)
        body = b"".join(chunks)
        chunks.clear()
        try:
            payload = json_limits.loads(body, max_depth=4)
        except ValueError:
            return _error(pa.PasteError(400, "bad_request", "Send JSON: {\"content\": \"...\"}."))
        del body
        try:
            data, name, forced = pa.decode_request(payload)
            del payload
            capture = forced == "capture" or pcap_tls.is_capture(data)
            pa.charge(_ip_of(deps, request), capture=capture)
            result = await run_in_threadpool(pa.analyze, data, name, forced)
        except pa.PasteError as exc:
            return _error(exc)
        except Exception as exc:
            # Never echo the input and never log it: only the exception's class is logged.
            logger.warning("paste: unreadable input (%s)", exc.__class__.__name__)
            return _error(pa.PasteError(400, "unreadable", "Morrow could not read that."))
        return JSONResponse(result, headers=_NO_STORE)

    return router
