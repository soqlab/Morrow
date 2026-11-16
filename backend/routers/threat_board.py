"""The quantum threat board's data (services/threat_board.py). The page itself is /threat (routers/instrument.py).

  GET /api/public/threat                 the board: headline, the estimate and why, every verified entry
  GET /api/public/threat/dataset.json    the exact dataset file (check it against its pinned SHA-256)
  GET /api/public/threat/schema.json     the JSON Schema the dataset is validated against
  GET /api/public/threat.atom            Atom feed: one entry per edition of the dataset

Unauthenticated (the /api/public prefix is public in app._auth_public_path), read-only, and it
contacts nothing: every answer is the reviewed file on disk.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from services import threat_board as _tb

_CACHE = "public, max-age=3600"


def _unavailable(exc: Exception) -> JSONResponse:
    return JSONResponse({"error": "threat_board_unavailable", "detail": str(exc)}, status_code=503,
                        headers={"Cache-Control": "no-store"})


def create_threat_board_router() -> APIRouter:
    router = APIRouter(prefix="/api/public", tags=["public-threat-board"])

    @router.get("/threat")
    def public_threat():
        try:
            return JSONResponse(_tb.board(), headers={"Cache-Control": _CACHE})
        except _tb.DatasetError as exc:
            return _unavailable(exc)

    @router.get("/threat/dataset.json")
    def public_threat_dataset():
        try:
            body = _tb.raw_dataset()
        except _tb.DatasetError as exc:
            return _unavailable(exc)
        return Response(body, media_type="application/json; charset=utf-8",
                        headers={"Cache-Control": _CACHE, "X-Content-SHA256": _tb.sha256_of(body)})

    @router.get("/threat/schema.json")
    def public_threat_schema():
        try:
            with open(os.path.join(_tb.DATA_DIR, _tb.SCHEMA_FILE), "rb") as fh:
                body = fh.read()
        except OSError as exc:
            return _unavailable(exc)
        return Response(body, media_type="application/schema+json", headers={"Cache-Control": _CACHE})

    @router.get("/threat.atom")
    def public_threat_atom(request: Request):
        from services.public_config import public_base_url

        try:
            body = _tb.atom((public_base_url() or str(request.base_url)).rstrip("/"))
        except _tb.DatasetError as exc:
            return _unavailable(exc)
        return Response(body, media_type="application/atom+xml; charset=utf-8", headers={"Cache-Control": _CACHE})

    return router
