"""Trial requests: the public form, and the operator queue that turns one into an account.

Public (unauthenticated, rate limited)
  POST /trial-request                    the form on /pilot posts here; returns an HTML page
  POST /api/trial-request                the same thing for a JSON client

Operator (platform key / operator session, like the rest of /platform/*)
  GET    /platform/trial-requests                 the queue, pending first
  GET    /platform/trial-requests/counts          for the navigation badge
  POST   /platform/trial-requests/{id}/approve    creates the organization and the invitation
  POST   /platform/trial-requests/{id}/decline    records the decision, keeps the row

Why the public route answers with HTML
--------------------------------------
The form on /pilot is a plain ``<form method="post">`` with no JavaScript, because the thing a
stranger does once should not depend on a script loading. That means the response has to be a page
a browser can show: a success page, or the same form again with the reason it was refused. JSON
clients get the same logic through /api/trial-request.
"""

from __future__ import annotations

import html
import logging
import time
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from services import platform_operators as _operators
from services import trial_requests as _trials

logger = logging.getLogger(__name__)

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES

#: Nothing here may be cached: a submission result is per-submitter and a queue is operational.
_NO_STORE = {"Cache-Control": "no-store"}


class TrialRequestBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    name: str = Field("", max_length=120)
    company: str = Field("", max_length=160)
    domain: str = Field("", max_length=253)
    use_case: str = Field("", max_length=2000)


class ApproveBody(BaseModel):
    organization_name: str = Field("", max_length=160)
    plan_type: str = Field("trial", max_length=40)
    role: str = Field(_trials.DEFAULT_TRIAL_ROLE, max_length=40)
    expires_hours: int = Field(168, ge=1, le=720)
    note: str = Field("", max_length=1000)


class DeclineBody(BaseModel):
    note: str = Field("", max_length=1000)
    spam: bool = False


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, heading: str, body: str, *, status_code: int = 200) -> HTMLResponse:
    """A small self-contained page in the public document style.

    It loads public.css only and carries no inline style or script, so it is safe under any of the
    policies in app.py and readable if the stylesheet never arrives.
    """
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)} | Airlock Command</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta name="robots" content="noindex, follow">
<link rel="stylesheet" href="/ui/public.css?v=7">
</head>
<body class="public-document">
<main class="doc-shell">
  <header class="topbar">
    <a class="brand" href="/launch"><span class="brand-mark" aria-hidden="true"></span><span>Airlock Command</span></a>
    <nav class="nav" aria-label="Public navigation"><a href="/">Platform</a><a href="/check">Free check</a><a href="/pricing">Pricing</a><a href="/support">Contact</a></nav>
  </header>
  <section class="doc-section">
    <h1>{_esc(heading)}</h1>
    {body}
  </section>
  <footer>
    <span>Airlock Command</span>
    <nav><a href="/terms">Terms</a> / <a href="/privacy">Privacy</a> / <a href="/support">Support</a></nav>
  </footer>
</main>
</body>
</html>
"""
    return HTMLResponse(document, status_code=status_code, headers=_NO_STORE)


def create_trial_requests_router(deps: Any) -> APIRouter:
    """deps: limiter, public_rate, client_ip(request), require_platform_admin(request, roles)."""

    router = APIRouter()

    def _ip(request: Request) -> str:
        try:
            return str(deps.client_ip(request) or "")
        except Exception:
            return ""

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    def _record(email: Any, name: Any, company: Any, domain: Any, use_case: Any,
                honeypot: Any, request: Request) -> Dict[str, Any]:
        """Shared by both public routes. Raises TrialRequestError for anything refusable."""
        if str(honeypot or "").strip():
            # A field that is hidden from people and attractive to scripts. Answer as though it
            # worked: telling a bot which signal caught it is how the next version avoids it.
            logger.info("trial request: honeypot filled, discarded")
            return {"id": "", "status": "pending", "duplicate": False, "discarded": True}
        return _trials.submit(email=email, name=name, company=company, domain=domain,
                              use_case=use_case, client_ip=_ip(request))

    # ── Public ───────────────────────────────────────────────────────────────

    @router.post("/trial-request", include_in_schema=False)
    @deps.limiter.limit(deps.public_rate)
    def trial_request_form(
        request: Request,
        email: str = Form(""),
        name: str = Form(""),
        company: str = Form(""),
        domain: str = Form(""),
        use_case: str = Form(""),
        # Named to look worth filling in. Real submitters never see it.
        website: str = Form(""),
    ) -> HTMLResponse:
        try:
            result = _record(email, name, company, domain, use_case, website, request)
        except _trials.TrialRequestError as exc:
            return _page(
                "Check that again", "We could not record that request",
                f'<p class="notice">{_esc(exc.detail)}</p>'
                '<p><a class="btn" href="/pilot#trial">Back to the form</a></p>',
                status_code=exc.status_code)
        logger.info("trial request submitted id=%s", result.get("id") or "-")
        return _page(
            "Request received", "Request received",
            "<p>Thank you &mdash; your request is in the queue and a person reads it. If it is "
            "approved you will get a single-use invitation link by email, which creates your "
            "organization when you accept it.</p>"
            "<p>There is no automatic approval, and that is deliberate: an account here can scan "
            "hosts, so a person checks every request. Expect a reply within two working days.</p>"
            "<p>In the meantime the <a href=\"/check\">free readiness check</a> needs no account "
            "at all, and will tell you what your public TLS endpoint negotiates today.</p>"
            '<p><a class="btn" href="/check">Run the free check</a></p>')

    @router.post("/api/trial-request")
    @deps.limiter.limit(deps.public_rate)
    def trial_request_json(request: Request, body: TrialRequestBody) -> JSONResponse:
        try:
            result = _record(body.email, body.name, body.company, body.domain, body.use_case,
                             "", request)
        except _trials.TrialRequestError as exc:
            return JSONResponse({"detail": exc.detail, "field": exc.field, "recorded": False},
                                status_code=exc.status_code, headers=_NO_STORE)
        return JSONResponse(
            {"recorded": True, "id": result.get("id", ""), "status": result.get("status"),
             "duplicate": bool(result.get("duplicate")),
             "detail": "A person reviews every request. Approval is not automatic."},
            headers=_NO_STORE)

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


def intake_health() -> Dict[str, Any]:
    """Is the route from a stranger to an account actually open? Used by the launch checks.

    A public site with no intake is the failure this module exists to prevent, and it is invisible:
    everything works, nobody can sign up, and the only symptom is silence.
    """
    counts = _trials.counts()
    return {
        "intake_open": True,
        "pending": counts.get(_trials.STATUS_PENDING, 0),
        "total": counts.get("total", 0),
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
