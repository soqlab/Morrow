"""Operator sign-in routes for the vendor admin portal: SSO, sessions, MFA. Logic lives in
services/operator_auth.py; this module only maps it to HTTP and writes the audit trail.

Public (no credential):
    GET  /platform/auth-config            what the sign-in screen should offer (no secrets)
    GET  /vendor-admin/sso/start          redirect to the identity provider (PKCE, state, nonce)
    GET  /vendor-admin/sso/callback       finish sign-in, set the session cookies
    POST /platform/session/logout         end the cookie session (CSRF-checked while it is valid)

Authenticated (session cookie or operator key):
    GET  /platform/mfa/status
    POST /platform/mfa/enroll/start       secret, otpauth URI and a locally rendered QR code
    POST /platform/mfa/enroll/confirm     first code; returns 10 single-use recovery codes
    POST /platform/mfa/verify             TOTP or recovery code; elevates the session / step-up
    POST /platform/mfa/recovery-codes/regenerate   (needs a fresh TOTP code)
    GET  /platform/mfa/operators          owner: enrolment state of every identity
    POST /platform/mfa/reset              owner + step-up: reset another operator's MFA, with reason
    GET  /platform/operator-sessions      console sessions
    POST /platform/operator-sessions/{session_ref}/revoke
"""

from __future__ import annotations

import hmac
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from services import operator_auth as _auth
from services import platform_operators as _operators

logger = logging.getLogger(__name__)

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES
OWNER = _operators.OWNER_ROLES
_PORTAL = "/vendor-admin/"


class CodeRequest(BaseModel):
    code: str = Field("", max_length=16)
    recovery_code: str = Field("", max_length=32)


class MfaResetRequest(BaseModel):
    identity: str = Field(..., min_length=5, max_length=340)
    reason: str = Field(..., min_length=3, max_length=500)


class SessionRevokeRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


def _no_store(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})


def _redirect_uri(request: Request) -> str:
    configured = _auth.oidc_settings()["redirect_uri"]
    if configured:
        return configured
    return str(request.base_url).rstrip("/") + _auth.SSO_CALLBACK_PATH


def _clear_cookies(response: Any, request: Request) -> None:
    secure = _auth.cookie_secure(request)
    for name in (_auth.SESSION_COOKIE, _auth.CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=secure, httponly=name == _auth.SESSION_COOKIE, samesite="strict")


def create_operator_auth_router(deps: Any) -> APIRouter:
    """deps: require_platform_admin(request, roles), record_event(org, action, reason=, details=)."""
    router = APIRouter()

    def guard(request: Request, roles=None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    def record(action: str, reason: str = "", details: Optional[Dict[str, Any]] = None, actor: Optional[Dict[str, Any]] = None) -> None:
        token = _operators.CURRENT_OPERATOR.set(actor) if actor is not None else None
        try:
            deps.record_event("", action, reason=reason, details=details or {})
        except Exception as exc:
            logger.warning("[operator-auth] audit write failed for %s: %s", action, exc.__class__.__name__)
        finally:
            if token is not None:
                _operators.CURRENT_OPERATOR.reset(token)

    def fail(exc: _auth.OperatorAuthError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.detail())

    def client_ip(request: Request) -> str:
        return str(getattr(request.client, "host", "") or "")

    # ── Public ───────────────────────────────────────────────────────────────

    @router.get("/platform/auth-config")
    def platform_auth_config():
        return _no_store(_auth.public_auth_config())

    @router.get("/vendor-admin/sso/start")
    def sso_start(request: Request):
        try:
            url, state = _auth.start_sso(_redirect_uri(request))
        except _auth.OperatorAuthError as exc:
            return RedirectResponse(f"{_PORTAL}?sso_error={exc.code}", status_code=303)
        except Exception as exc:  # discovery unreachable
            logger.warning("[operator-auth] SSO start failed: %s", exc.__class__.__name__)
            return RedirectResponse(f"{_PORTAL}?sso_error=sso_unavailable", status_code=303)
        response = RedirectResponse(url, status_code=302)
        # Lax, not Strict: the callback is a top-level navigation from the identity provider's site.
        response.set_cookie(_auth.SSO_STATE_COOKIE, state, max_age=_auth.STATE_TTL_SECONDS, path="/vendor-admin/sso",
                            secure=_auth.cookie_secure(request), httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.get("/vendor-admin/sso/callback")
    def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        bound = str(request.cookies.get(_auth.SSO_STATE_COOKIE) or "")
        ip = client_ip(request)

        def denied(exc: _auth.OperatorAuthError, email: str = "") -> RedirectResponse:
            record("platform.operator_sign_in_denied", exc.code, {
                "auth_method": "sso", "severity": "medium", "code": exc.code, "email": email, "ip": ip,
            }, actor={"actor_id": email or "unknown-sso-user", "actor_role": "", "auth_method": "sso", "email": email})
            response = RedirectResponse(f"{_PORTAL}?sso_error={exc.code}", status_code=303)
            if exc.code != "sso_state_mismatch":  # a forged callback must not cancel the real sign-in in progress
                response.delete_cookie(_auth.SSO_STATE_COOKIE, path="/vendor-admin/sso")
            return response

        if error:
            return denied(_auth.OperatorAuthError(401, "sso_idp_error", "The identity provider returned an error."))
        try:
            result = _auth.complete_sso(code, state, bound, _redirect_uri(request))
        except _auth.OperatorAuthError as exc:
            email = ""
            return denied(exc, email)
        except Exception as exc:
            logger.warning("[operator-auth] SSO callback failed: %s", exc.__class__.__name__)
            return denied(_auth.OperatorAuthError(502, "sso_unavailable", "The identity provider could not be reached."))
        raw, row = _auth.create_session(result["email"], result["role"], "sso", email=result["email"],
                                        subject=result["subject"], ip=ip, user_agent=request.headers.get("user-agent", ""))
        actor = {"actor_id": result["email"], "actor_role": result["role"], "ceiling_role": result["role"],
                 "credential_source": "operator_session", "auth_method": "sso", "email": result["email"]}
        record("platform.operator_signed_in", "", {"auth_method": "sso", "session_ref": row["ref"], "ip": ip,
                                                    "mfa_required": _auth.mfa_required()}, actor=actor)
        response = RedirectResponse(_PORTAL + "#/dashboard", status_code=303)
        secure = _auth.cookie_secure(request)
        max_age = _auth.session_absolute_seconds()
        response.set_cookie(_auth.SESSION_COOKIE, raw, max_age=max_age, path="/", secure=secure, httponly=True, samesite="strict")
        response.set_cookie(_auth.CSRF_COOKIE, _auth.csrf_token_for(raw), max_age=max_age, path="/", secure=secure,
                            httponly=False, samesite="strict")
        response.delete_cookie(_auth.SSO_STATE_COOKIE, path="/vendor-admin/sso")
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.post("/platform/session/logout")
    def session_logout(request: Request):
        raw = _auth.session_cookie(request)
        ended = False
        if raw:
            row, _state = _auth.load_session(raw, touch=False)
            if row:
                sent = str(request.headers.get(_auth.CSRF_HEADER) or "")
                # compare_digest, like every other secret comparison in this module and in
                # operator_auth.require_session_actor. `!=` on a token leaks its prefix through
                # timing, and this is the one write a signed-out-by-CSRF attacker would want.
                if not sent or not hmac.compare_digest(sent.encode(), _auth.csrf_token_for(raw).encode()):
                    raise HTTPException(status_code=403, detail={"code": "csrf_failed", "message": "Missing or invalid CSRF token."})
                ended = _auth.revoke_session_raw(raw, row["operator"], "signed out")
                record("platform.operator_signed_out", "", {"auth_method": row["auth_method"], "session_ref": row["ref"]},
                       actor={"actor_id": row["operator"], "actor_role": row["role"], "auth_method": row["auth_method"],
                              "email": row["email"], "credential_source": "operator_session"})
        response = _no_store({"ok": True, "session_ended": ended})
        _clear_cookies(response, request)
        return response

    # ── MFA ──────────────────────────────────────────────────────────────────

    def account_label(actor: Dict[str, Any]) -> str:
        return str(actor.get("email") or actor.get("actor_id") or "operator")

    @router.get("/platform/mfa/status")
    def mfa_status(request: Request):
        actor = guard(request)
        identity = _auth.identity_for(actor)
        status = _auth.mfa_status(identity) if identity else {"enrolled": False, "required": _auth.mfa_required()}
        return _no_store({"api_version": "v1", "auth_method": actor.get("auth_method") or "", "can_enrol": bool(identity),
                          "elevated": bool(actor.get("mfa_elevated")), **status})

    @router.post("/platform/mfa/enrolment-approvals")
    def mfa_approve_enrolment(body: MfaResetRequest, request: Request):
        """An owner lets one named identity enrol an authenticator: single use, one hour.

        Without this, MFA was trust-on-first-use. The enrolment endpoints are necessarily exempt
        from the elevation gate, so a stolen operator key or a hijacked session could enrol its own
        authenticator before the real holder did, and MFA then defended the attacker's access.
        """
        actor = guard(request, OWNER)
        _auth.require_step_up(actor, "approve an MFA enrolment for another operator")
        identity = body.identity.strip()
        if not identity.startswith(("sso:", "key:")):
            raise HTTPException(status_code=400, detail="identity must look like sso:<email> or key:<operator name>.")
        granted = _auth.grant_enrolment_approval(identity, actor["actor_id"], body.reason)
        record("platform.mfa_enrolment_approved", body.reason,
               {"target_identity": identity, "expires_at": granted["expires_at"], "severity": "high"})
        return _no_store({"api_version": "v1", "ok": True, **granted,
                          "note": "The account can enrol once, within the hour. Nothing else changed."})

    @router.post("/platform/mfa/enroll/start")
    def mfa_enroll_start(request: Request):
        actor = guard(request)
        try:
            payload = _auth.begin_enrolment(_auth.identity_for(actor), account_label(actor))
        except _auth.OperatorAuthError as exc:
            record("platform.mfa_enrolment_refused", exc.code,
                   {"auth_method": actor.get("auth_method"), "code": exc.code, "ip": client_ip(request),
                    "severity": "high" if exc.code == "mfa_enrolment_approval_required" else "medium"})
            raise fail(exc) from None
        record("platform.mfa_enrolment_started", "",
               {"auth_method": actor.get("auth_method"), "approved_by": payload.get("approved_by") or "",
                "first_enrolment": bool(payload.get("first_enrolment")), "ip": client_ip(request),
                "severity": "high"})
        return _no_store({"api_version": "v1", **payload,
                          "note": "Scan the QR code or type the secret into an authenticator app, then confirm with a code."})

    def elevate(request: Request, actor: Dict[str, Any]) -> None:
        if actor.get("credential_source") == "operator_session":
            _auth.mark_session_mfa(_auth.session_cookie(request))

    def audited_verify(request: Request, actor: Dict[str, Any], body: CodeRequest, confirm: bool) -> Dict[str, Any]:
        identity = _auth.identity_for(actor)
        try:
            result = _auth.verify_mfa(identity, body.code, "" if confirm else body.recovery_code, confirm_pending=confirm)
        except _auth.OperatorAuthError as exc:
            record("platform.mfa_rate_limited" if exc.code == "mfa_rate_limited" else "platform.mfa_failed", exc.code, {
                "auth_method": actor.get("auth_method"), "severity": "high" if exc.code == "mfa_rate_limited" else "medium",
                "code": exc.code, "ip": client_ip(request), "enrolment": confirm,
            })
            raise fail(exc) from None
        elevate(request, actor)
        return result

    @router.post("/platform/mfa/enroll/confirm")
    def mfa_enroll_confirm(body: CodeRequest, request: Request):
        actor = guard(request)
        result = audited_verify(request, actor, body, confirm=True)
        # High severity and surfaced as a notification: an authenticator appearing on an operator
        # account is either a routine onboarding or the moment an intruder made their access
        # durable, and the two look identical in the log unless someone is told.
        record("platform.mfa_enrolled", "", {"auth_method": actor.get("auth_method"), "severity": "high",
                                             "identity": _auth.identity_for(actor), "ip": client_ip(request)})
        return _no_store({"api_version": "v1", "ok": True, "enrolled": True, "recovery_codes": result.get("recovery_codes", []),
                          "note": "Store these recovery codes somewhere safe. Each works once and they are not shown again."})

    @router.post("/platform/mfa/verify")
    def mfa_verify(body: CodeRequest, request: Request):
        actor = guard(request)
        result = audited_verify(request, actor, body, confirm=False)
        record("platform.mfa_verified", "", {"auth_method": actor.get("auth_method"), "method": result.get("method"),
                                             "recovery_codes_remaining": result.get("recovery_codes_remaining")})
        return _no_store({"api_version": "v1", "ok": True, "method": result.get("method"),
                          "recovery_codes_remaining": result.get("recovery_codes_remaining"),
                          "step_up_seconds": _auth.step_up_seconds()})

    @router.post("/platform/mfa/recovery-codes/regenerate")
    def mfa_regenerate(body: CodeRequest, request: Request):
        actor = guard(request)
        if not body.code:
            raise HTTPException(status_code=400, detail={"code": "mfa_code_required", "message": "Enter a current authenticator code."})
        audited_verify(request, actor, CodeRequest(code=body.code), confirm=False)
        try:
            codes = _auth.regenerate_recovery_codes(_auth.identity_for(actor))
        except _auth.OperatorAuthError as exc:
            raise fail(exc) from None
        record("platform.mfa_recovery_codes_regenerated", "", {"auth_method": actor.get("auth_method")})
        return _no_store({"api_version": "v1", "ok": True, "recovery_codes": codes,
                          "note": "The previous recovery codes no longer work."})

    @router.get("/platform/mfa/operators")
    def mfa_operators(request: Request):
        guard(request, OWNER)
        return _no_store({"api_version": "v1", "items": _auth.list_mfa_identities(), "required": _auth.mfa_required()})

    @router.post("/platform/mfa/reset")
    def mfa_reset(body: MfaResetRequest, request: Request):
        actor = guard(request, OWNER)
        _auth.require_step_up(actor, "reset another operator's MFA")
        identity = body.identity.strip()
        if not identity.startswith(("sso:", "key:")):
            raise HTTPException(status_code=400, detail="identity must look like sso:<email> or key:<operator name>.")
        if identity == _auth.identity_for(actor):
            raise HTTPException(status_code=400, detail="Ask another owner to reset your own MFA.")
        removed = _auth.reset_mfa(identity)
        if not removed:
            raise HTTPException(status_code=404, detail="No MFA enrolment for that identity.")
        sessions = _auth.revoke_operator_sessions(identity.split(":", 1)[1], actor["actor_id"], "MFA reset") if identity.startswith("sso:") else 0
        record("platform.mfa_reset", body.reason, {"target_identity": identity, "sessions_revoked": sessions, "severity": "high"})
        return _no_store({"api_version": "v1", "ok": True, "identity": identity, "sessions_revoked": sessions})

    # ── Operator sessions ────────────────────────────────────────────────────

    @router.get("/platform/operator-sessions")
    def operator_sessions(request: Request, include_inactive: bool = False):
        guard(request)
        return _no_store({"api_version": "v1", "items": _auth.list_sessions(include_inactive=bool(include_inactive)),
                          "idle_timeout_seconds": _auth.session_idle_seconds(),
                          "absolute_timeout_seconds": _auth.session_absolute_seconds()})

    @router.post("/platform/operator-sessions/{session_ref}/revoke")
    def revoke_operator_session(session_ref: str, body: SessionRevokeRequest, request: Request):
        actor = guard(request, WRITE)
        result = _auth.revoke_session_by_ref(session_ref, actor["actor_id"], body.reason)
        if not result:
            raise HTTPException(status_code=404, detail="Operator session not found.")
        record("platform.operator_session_revoked", body.reason, {"session_ref": session_ref, "operator": result["operator"],
                                                                  "session_auth_method": result["auth_method"]})
        return _no_store({"ok": True, **result})

    return router


def install_operator_auth(app: Any, deps: Any) -> None:
    """Include the router, and put the /vendor-admin/sso routes ahead of the /vendor-admin static mount."""
    router = create_operator_auth_router(deps)
    app.include_router(router)
    routes = app.router.routes
    # FastAPI either copies the routes (older releases) or appends one wrapper that keeps
    # `original_router` (0.14x). Move whichever entries belong to this router to the front, because
    # Starlette matches in order and the StaticFiles mount at /vendor-admin would swallow the SSO paths.
    ours = [r for r in routes
            if getattr(r, "original_router", None) is router
            or str(getattr(r, "path", "")).startswith("/vendor-admin/sso/")]
    for route in ours:
        routes.remove(route)
    for index, route in enumerate(ours):
        routes.insert(index, route)
