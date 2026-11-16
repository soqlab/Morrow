"""Board slide in one click (/board-slide...). Logic and rendering in services/board_slide.py.

Any signed-in member of the organization (viewer, analyst, operator, admin, owner) can read the
slide and download it. Everything is read for the caller's own organization only. Each download
is one audit entry (action ``board_slide.export``, the format as the resource id); the slide's
content is never written to the log. Support sessions cannot download it ("export" in the path).
"""

from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response

from db import current_organization_id
from services import board_slide

RequireRole = Callable[..., Dict[str, Any]]

MEMBERS = ["viewer", "analyst", "operator", "admin", "owner"]


def _org(request: Request) -> str:
    return str(getattr(request.state, "org_id", "") or current_organization_id())


def create_board_slide_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter(tags=["Board slide"])

    @router.get("/board-slide")
    def api_board_slide(request: Request, data: str = Query("", max_length=60), jur: str = Query("", max_length=8)):
        """What the slide says, with its sources, as JSON."""
        require_role(request, allowed_roles=MEMBERS, action="board_slide.read", resource_type="board_slide",
                     resource_id=_org(request))
        return board_slide.gather(_org(request), data or None, jur or None)

    def _export(request: Request, fmt: str, data: str, jur: str) -> Response:
        require_role(request, allowed_roles=MEMBERS, action="board_slide.export", resource_type="board_slide",
                     resource_id=fmt)
        org = _org(request)
        content = board_slide.gather(org, data or None, jur or None)
        body = board_slide.render(content, fmt)
        return Response(content=body, media_type=board_slide.FORMATS[fmt], headers={
            "Content-Disposition": f'attachment; filename="{board_slide.filename(content, fmt)}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        })

    @router.get("/board-slide/export.pptx")
    def api_board_slide_pptx(request: Request, data: str = Query("", max_length=60), jur: str = Query("", max_length=8)):
        return _export(request, "pptx", data, jur)

    @router.get("/board-slide/export.pdf")
    def api_board_slide_pdf(request: Request, data: str = Query("", max_length=60), jur: str = Query("", max_length=8)):
        return _export(request, "pdf", data, jur)

    return router
