"""Trial requests: the retired public form, and the operator queue that still reads the old rows.

Public (unauthenticated, rate limited) -- retired
  POST /trial-request                    410 Gone: accounts sign in with a passkey at /ui/
  POST /api/trial-request                410 Gone, the same answer

  The form asked for an email address and answered by emailing a link, which is the one kind of
  sign-in Morrow no longer offers. Nothing is recorded and nothing is sent. The page addresses
  (GET /trial, GET /trial-request) redirect to /ui/ from app.py.

Operator (platform key / operator session, like the rest of /platform/*)
  GET    /platform/trial-requests                 the queue of past requests, pending first
  GET    /platform/trial-requests/counts          for the navigation badge
  POST   /platform/trial-requests/{id}/approve    creates the organization and the invitation
  POST   /platform/trial-requests/{id}/decline    records the decision, keeps the row

The table and its rows are kept: requests made before the form was retired can still be read and
decided by an operator.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from services import platform_operators as _operators
from services import trial_requests as _trials

logger = logging.getLogger(__name__)

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES

#: Nothing here may be cached: a queue is operational.
_NO_STORE = {"Cache-Control": "no-store"}

#: Where a person who wants an account goes now.
SIGN_IN_PATH = "/ui/"

#: The whole answer of a retired public route.
RETIRED = {
    "detail": "Account requests by email have ended. Morrow signs you in with a passkey: "
              "open /ui/ to sign in or to use a setup link.",
    "sign_in": SIGN_IN_PATH,
    "recorded": False,
}


class ApproveBody(BaseModel):
    organization_name: str = Field("", max_length=160)
    plan_type: str = Field("trial", max_length=40)
    role: str = Field(_trials.DEFAULT_TRIAL_ROLE, max_length=40)
    expires_hours: int = Field(168, ge=1, le=720)
    note: str = Field("", max_length=1000)


class DeclineBody(BaseModel):
    note: str = Field("", max_length=1000)
    spam: bool = False


def create_trial_requests_router(deps: Any) -> APIRouter:
    """deps: limiter, public_rate, client_ip(request), require_platform_admin(request, roles)."""

    router = APIRouter()

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    # ── Public: retired ──────────────────────────────────────────────────────

    def _gone() -> JSONResponse:
        return JSONResponse(RETIRED, status_code=410, headers={**_NO_STORE, "Link": f'<{SIGN_IN_PATH}>; rel="alternate"'})

    @router.post("/trial-request", include_in_schema=False)
    @deps.limiter.limit(deps.public_rate)
    def trial_request_form(request: Request) -> JSONResponse:
        return _gone()

    @router.post("/api/trial-request")
    @deps.limiter.limit(deps.public_rate)
    def trial_request_json(request: Request) -> JSONResponse:
        return _gone()

    # ── Operator ─────────────────────────────────────────────────────────────

    @router.get("/platform/trial-requests")
    def platform_trial_requests(request: Request, status: str = "", limit: int = 200) -> JSONResponse:
        guard(request, READ)
        wanted = str(status or "").strip().lower()
        if wanted and wanted not in _trials.STATUSES:
            return JSONResponse(
                {"detail": f"status must be one of {', '.join(_trials.STATUSES)}."},
                status_code=400, headers=_NO_STORE)
        return JSONResponse({"requests": _trials.list_requests(wanted, limit),
                             "counts": _trials.counts()}, headers=_NO_STORE)

    @router.get("/platform/trial-requests/counts")
    def platform_trial_request_counts(request: Request) -> JSONResponse:
        guard(request, READ)
        return JSONResponse(_trials.counts(), headers=_NO_STORE)

    @router.post("/platform/trial-requests/{request_id}/approve")
    def platform_approve_trial(request_id: str, body: ApproveBody, request: Request) -> JSONResponse:
        actor = guard(request, WRITE)
        operator = str(actor.get("operator") or actor.get("subject") or actor.get("key_id") or
                       "operator")
        try:
            decided = _trials.approve(
                request_id, operator, organization_name=body.organization_name,
                plan_type=body.plan_type, role=body.role, expires_hours=body.expires_hours,
                note=body.note)
        except _trials.TrialRequestError as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=_NO_STORE)
        # The token is in this response and nowhere else -- not in the row, not in the audit log.
        # If it is lost, the invitation is revoked and reissued rather than recovered.
        return JSONResponse({"request": decided, "detail":
                             "Organization created and invitation issued. The invitation link is "
                             "shown once; send it, or email it from the Invitations view."},
                            headers=_NO_STORE)

    @router.post("/platform/trial-requests/{request_id}/decline")
    def platform_decline_trial(request_id: str, body: DeclineBody, request: Request) -> JSONResponse:
        actor = guard(request, WRITE)
        operator = str(actor.get("operator") or actor.get("subject") or actor.get("key_id") or
                       "operator")
        try:
            decided = _trials.decline(request_id, operator, note=body.note, spam=body.spam)
        except _trials.TrialRequestError as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=_NO_STORE)
        return JSONResponse({"request": decided}, headers=_NO_STORE)

    return router

