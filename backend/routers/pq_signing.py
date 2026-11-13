"""Post-quantum signing for customers (services/pq_signing.py): the console API and the public record.

Signed in (the organization comes from the credential):

  GET    /pq-signing                                    viewer and up: keys, signatures, withdrawals, the summary
  POST   /pq-signing/keys                               admin: register a public key file (rotate with "rotates")
  POST   /pq-signing/domains/{domain}/keys/{key}/retire admin: the key signs nothing new
  POST   /pq-signing/domains/{domain}/keys/{key}/revoke admin: the key may be in someone else's hands
  POST   /pq-signing/signatures                         an API key with the "sign" scope, or operator and up
  POST   /pq-signing/signatures/{id}/withdraw           admin: take one signature back, with a reason
  GET    /pq-signing/upload-keys                        admin: the organization's signing upload keys
  POST   /pq-signing/upload-keys                        admin, signed in (not with an API key): the secret, once
  DELETE /pq-signing/upload-keys/{id}                   admin: revoke one

Public, no account (app._auth_public_path asks :func:`is_public_path`):

  GET  /verify, /verify/{domain}            the verify page (static/verify.html): keys, signatures, drop a file
  GET  /verify/{domain}/badge.svg           the badge a customer puts next to their downloads
  GET  /api/verify/{domain}                 keys with their history and the latest signatures, as JSON
  GET  /api/verify/{domain}/signatures/{id} one signature, with a manifest's file list
  GET  /api/verify/{domain}/lookup?sha512=  signatures for a file with this SHA-512
  POST /api/verify                          {"signature": <.morrow-sig>, "sha512"?: hex, "size"?: n}: the verdict

Every request body is read with a size cap before it is parsed, every route is rate limited per
client address, and nothing here accepts a private key or a file: only public keys, signatures and
hashes. Key registration, rotation, retirement, revocation, withdrawals and upload keys are
written to the tenant audit log.
"""

from __future__ import annotations

import html
import json
import os
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response

from services import pq_signing as store
from services import route_paths as _route_paths

READ_ROLES = ["viewer", "analyst", "operator", "admin", "owner"]
UPLOAD_ROLES = ["operator", "admin", "owner"]
ADMIN_ROLES = ["admin", "owner"]

#: Request body caps. A public key file is ~6 KB; a signature file ~7 KB; a manifest upload carries
#: up to store.MAX_MANIFEST_ENTRIES lines of about 250 bytes each.
MAX_KEY_BODY = 32 * 1024
MAX_SMALL_BODY = 32 * 1024
MAX_UPLOAD_BODY = 4 * 1024 * 1024

UPLOAD_KEY_PREFIX = "morrow-sign: "
UPLOAD_KEY_DAYS = 365

#: The policy for the verify page: this origin only, nothing inline (static/verify.html has none).
PAGE_CSP = ("default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; "
            "object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; worker-src 'none'")
BADGE_CSP = "default-src 'none'; style-src 'unsafe-inline'"

PUBLIC_PREFIXES = ("/verify", "/api/verify")


def is_public_path(path: str) -> bool:
    return _route_paths.has_prefix(path, PUBLIC_PREFIXES)


def _http(exc: store.SigningError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)


async def _json_body(request: Request, limit: int) -> Dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"The request body is larger than {limit} bytes.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=f"The request body is larger than {limit} bytes.")
        chunks.append(chunk)
    try:
        body = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="The request body must be JSON.") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="The request body must be a JSON object.")
    return body


def _text(body: Dict[str, Any], name: str, limit: int) -> str:
    value = body.get(name)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{name} must be text.")
    return value.strip()[:limit]


def _actor_label(request: Request) -> str:
    claims = getattr(request.state, "auth_claims", {}) or {}
    return str(claims.get("email") or claims.get("sub") or request.headers.get("x-user-id") or "unknown")[:160]


def _is_api_key(request: Request) -> bool:
    claims = getattr(request.state, "auth_claims", {}) or {}
    return str(claims.get("auth_method") or "") == "api_key"


def badge_svg(domain: str, active_keys: int) -> str:
    """A flat 20px badge. Plain text in system fonts, so it renders the same everywhere it is embedded."""
    left = "post-quantum signed"
    right = f"{domain}" if active_keys else f"{domain}: no active key"
    lw = 8 + int(len(left) * 6.4)
    rw = 10 + int(len(right) * 6.6)
    width = lw + rw
    fill = "#0f7a45" if active_keys else "#8f5200"
    e = html.escape
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" '
            f'aria-label="{e(left)}: {e(right)}"><title>{e(left)}: {e(right)}. Verify on Morrow.</title>'
            f'<rect width="{lw}" height="20" fill="#0c1014"/><rect x="{lw}" width="{rw}" height="20" fill="{fill}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="6" y="14">{e(left)}</text><text x="{lw + 6}" y="14">{e(right)}</text></g></svg>')


def create_pq_signing_router(
    require_role: Callable[..., Dict[str, Any]],
    audit_event: Callable[..., None],
    org_of: Callable[[Request], str],
    static_dir: str,
    public_base: Optional[Callable[[Request], str]] = None,
    limiter: Optional[Any] = None,
) -> APIRouter:
    router = APIRouter()

    def _limit(rule: str):
        return limiter.limit(rule) if limiter is not None else (lambda fn: fn)

    def _base(request: Request) -> str:
        base = ""
        if public_base is not None:
            try:
                base = str(public_base(request) or "")
            except Exception:
                base = ""
        return (base or str(request.base_url)).rstrip("/")

    def _deny(request: Request, action: str, resource_id: str, exc: store.SigningError) -> HTTPException:
        audit_event(request, action=action, resource_type="pq_signing_key", resource_id=resource_id[:160],
                    decision="deny", reason=exc.detail[:200])
        return _http(exc)

    # ── console ──────────────────────────────────────────────────────────────

    @router.get("/pq-signing")
    def api_pq_signing(request: Request):
        """Everything the console's Signing view shows, with the answer-first sentence."""
        org = org_of(request)
        actor = require_role(request, READ_ROLES, action="pq_signing.read", resource_type="pq_signing",
                             resource_id=org)
        from services import domain_verification as dv

        keys = store.list_keys(org)
        counts = store.org_counts(org)
        domains = dv.list_domains(org)
        upload_keys = _upload_keys(org) if str(actor.get("actor_role", "")).lower() in ADMIN_ROLES else None
        base = _base(request)
        return JSONResponse({
            "api_version": "v1",
            "summary": store.summary_sentence(keys, counts),
            "counts": counts,
            "keys": keys,
            "signatures": store.org_signatures(org),
            "withdrawals": store.org_withdrawals(org),
            "domains": [{"domain": d["domain"], "verified": d["status"] == "verified"} for d in domains],
            "upload_keys": upload_keys,
            "can_admin": str(actor.get("actor_role", "")).lower() in ADMIN_ROLES,
            "public_base": base,
            "daily_limit": store.daily_upload_limit(),
        }, headers={"Cache-Control": "no-store"})

    @router.post("/pq-signing/keys")
    @_limit("20/minute")
    async def api_register_key(request: Request):
        """Register a public key file made by morrow-sign keygen. {"public_key": {...}, "label"?, "rotates"?}"""
        body = await _json_body(request, MAX_KEY_BODY)
        rotates = _text(body, "rotates", 40)
        action = "pq_signing.key.rotate" if rotates else "pq_signing.key.register"
        public_key = body.get("public_key")
        kid = str(public_key.get("key") or "")[:40] if isinstance(public_key, dict) else ""
        require_role(request, ADMIN_ROLES, action=action, resource_type="pq_signing_key", resource_id=kid)
        org = org_of(request)
        try:
            result = await run_in_threadpool(store.register_key, org, public_key, label=_text(body, "label", 80),
                                             rotates=rotates, actor=_actor_label(request))
        except store.SigningError as exc:
            raise _deny(request, action, kid, exc) from None
        key = result["key"]
        audit_event(request, action=action, resource_type="pq_signing_key", resource_id=key["key_id"], required=True,
                    details={"domain": key["domain"], "key_id": key["key_id"], "label": key["label"],
                             "rotates": rotates or None, "ml_dsa_65_public_key_sha256": _sha256(key["ml_dsa_65"]),
                             "ed25519_public_key": key["ed25519"]})
        return {"api_version": "v1", **result}

    @router.post("/pq-signing/domains/{domain}/keys/{key_id}/retire")
    @_limit("20/minute")
    async def api_retire_key(domain: str, key_id: str, request: Request):
        body = await _json_body(request, MAX_SMALL_BODY)
        require_role(request, ADMIN_ROLES, action="pq_signing.key.retire", resource_type="pq_signing_key",
                     resource_id=key_id[:40])
        try:
            key = await run_in_threadpool(store.retire_key, org_of(request), domain, key_id,
                                          note=_text(body, "note", store.MAX_NOTE), actor=_actor_label(request))
        except store.SigningError as exc:
            raise _deny(request, "pq_signing.key.retire", key_id, exc) from None
        audit_event(request, action="pq_signing.key.retire", resource_type="pq_signing_key", resource_id=key["key_id"],
                    required=True, details={"domain": key["domain"], "retired_at": key["state"]["retired_at"],
                                            "note": _text(body, "note", store.MAX_NOTE)})
        return {"api_version": "v1", "key": key}

    @router.post("/pq-signing/domains/{domain}/keys/{key_id}/revoke")
    @_limit("20/minute")
    async def api_revoke_key(domain: str, key_id: str, request: Request):
        """{"note": why, "compromised_since"?: ISO time}. Default: since the key was registered."""
        body = await _json_body(request, MAX_SMALL_BODY)
        require_role(request, ADMIN_ROLES, action="pq_signing.key.revoke", resource_type="pq_signing_key",
                     resource_id=key_id[:40])
        try:
            key = await run_in_threadpool(store.revoke_key, org_of(request), domain, key_id,
                                          compromised_since=_text(body, "compromised_since", 40) or None,
                                          note=_text(body, "note", store.MAX_NOTE), actor=_actor_label(request))
        except store.SigningError as exc:
            raise _deny(request, "pq_signing.key.revoke", key_id, exc) from None
        audit_event(request, action="pq_signing.key.revoke", resource_type="pq_signing_key", resource_id=key["key_id"],
                    required=True, details={"domain": key["domain"], "compromised_since": key["state"]["compromised_since"],
                                            "note": key["state"]["revocation_note"]})
        return {"api_version": "v1", "key": key}

    @router.post("/pq-signing/signatures")
    @_limit("120/minute")
    async def api_upload_signature(request: Request):
        """Put a signature on the public record: {"signature": <.morrow-sig>, "entries"?: [manifest lines]}.

        The signed file never comes here: only the signature, its hash, and for a site manifest the
        list of paths, sizes and hashes it covers.
        """
        body = await _json_body(request, MAX_UPLOAD_BODY)
        require_role(request, UPLOAD_ROLES, action="pq_signing.signature.upload", resource_type="pq_signature",
                     resource_id="")
        try:
            result = await run_in_threadpool(store.record_signature, org_of(request), body.get("signature"),
                                             entries=body.get("entries"), actor=_actor_label(request))
        except store.SigningError as exc:
            headers = {"Retry-After": "3600"} if exc.status_code == 429 else None
            raise HTTPException(status_code=exc.status_code, detail=exc.detail, headers=headers) from None
        sig = result["signature"]
        domain = sig["domain"]
        return JSONResponse({"api_version": "v1", "created": result["created"], "signature": sig,
                             "verify_url": f"{_base(request)}/verify/{domain}?sha512={sig['sha512']}"},
                            status_code=201 if result["created"] else 200)

    @router.post("/pq-signing/signatures/{sig_id}/withdraw")
    @_limit("20/minute")
    async def api_withdraw_signature(sig_id: str, request: Request):
        body = await _json_body(request, MAX_SMALL_BODY)
        require_role(request, ADMIN_ROLES, action="pq_signing.signature.withdraw", resource_type="pq_signature",
                     resource_id=sig_id[:40])
        note = _text(body, "note", store.MAX_NOTE)
        try:
            sig = await run_in_threadpool(store.withdraw_signature, org_of(request), sig_id, note=note,
                                          actor=_actor_label(request))
        except store.SigningError as exc:
            raise _http(exc) from None
        audit_event(request, action="pq_signing.signature.withdraw", resource_type="pq_signature",
                    resource_id=sig["id"], required=True,
                    details={"domain": sig["domain"], "name": sig["name"], "sha512": sig["sha512"], "note": note})
        return {"api_version": "v1", "signature": sig}

    def _upload_keys(org: str):
        from services import api_keys

        return [k for k in api_keys.list_keys(org) if k.get("scopes") == ["sign"]]

    @router.get("/pq-signing/upload-keys")
    def api_list_upload_keys(request: Request):
        org = org_of(request)
        require_role(request, ADMIN_ROLES, action="pq_signing.upload_key.list", resource_type="api_key", resource_id=org)
        return {"api_version": "v1", "items": _upload_keys(org)}

    @router.post("/pq-signing/upload-keys")
    @_limit("10/minute")
    async def api_create_upload_key(request: Request):
        """An API key that can only upload signatures. {"name": "..."}. The secret is shown once."""
        body = await _json_body(request, MAX_SMALL_BODY)
        require_role(request, ADMIN_ROLES, action="pq_signing.upload_key.create", resource_type="api_key")
        if _is_api_key(request):
            raise HTTPException(status_code=403, detail="Create upload keys while signed in to the console, not with an API key.")
        from services import api_keys

        name = _text(body, "name", 60) or "release pipeline"
        org = org_of(request)
        try:
            key, secret = await run_in_threadpool(api_keys.create_key, org, UPLOAD_KEY_PREFIX + name, ["sign"],
                                                  UPLOAD_KEY_DAYS, _actor_label(request))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        audit_event(request, action="pq_signing.upload_key.create", resource_type="api_key", resource_id=key["id"],
                    required=True, details={"name": key["name"], "prefix": key["prefix"], "scopes": key["scopes"],
                                            "expires_at": key["expires_at"]})
        return {"api_version": "v1", "key": key, "secret": secret,
                "note": "Copy the key now: it is not stored and cannot be shown again. Keep it in your CI secrets "
                        "as MORROW_SIGN_UPLOAD_KEY."}

    @router.delete("/pq-signing/upload-keys/{key_id}")
    @_limit("20/minute")
    def api_revoke_upload_key(key_id: str, request: Request):
        org = org_of(request)
        require_role(request, ADMIN_ROLES, action="pq_signing.upload_key.revoke", resource_type="api_key",
                     resource_id=key_id[:40])
        from services import api_keys

        if not any(k["id"] == key_id for k in _upload_keys(org)):
            raise HTTPException(status_code=404, detail="There is no such upload key in this organization.")
        key = api_keys.revoke_key(key_id, _actor_label(request), "revoked from the Signing view")
        audit_event(request, action="pq_signing.upload_key.revoke", resource_type="api_key", resource_id=key_id,
                    required=True, details={"name": (key or {}).get("name", "")})
        return {"api_version": "v1", "key": key}

    # ── public ───────────────────────────────────────────────────────────────

    def _page() -> FileResponse:
        path = os.path.join(static_dir, "verify.html")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="verify.html not found")
        return FileResponse(path, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": "no-cache", "Content-Security-Policy": PAGE_CSP})

    @router.get("/verify", include_in_schema=False)
    @_limit("120/minute")
    def public_verify_home(request: Request):
        return _page()

    @router.get("/verify/{domain}", include_in_schema=False)
    @_limit("120/minute")
    def public_verify_page(domain: str, request: Request):
        return _page()

    @router.get("/verify/{domain}/badge.svg", include_in_schema=False)
    @_limit("240/minute")
    async def public_verify_badge(domain: str, request: Request):
        try:
            record = await run_in_threadpool(store.public_domain, domain, 1)
        except store.SigningError as exc:
            raise _http(exc) from None
        return Response(badge_svg(record["domain"], record["counts"]["active_keys"]), media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=300", "Content-Security-Policy": BADGE_CSP,
                                 "Cross-Origin-Resource-Policy": "cross-origin"})

    @router.get("/api/verify/{domain}")
    @_limit("60/minute")
    async def public_verify_record(domain: str, request: Request,
                                   limit: int = Query(store.PUBLIC_LIST_DEFAULT, ge=1, le=store.PUBLIC_LIST_MAX)):
        try:
            record = await run_in_threadpool(store.public_domain, domain, limit)
        except store.SigningError as exc:
            raise _http(exc) from None
        record["badge"] = {"image": f"{_base(request)}/verify/{record['domain']}/badge.svg",
                           "link": f"{_base(request)}/verify/{record['domain']}"}
        return JSONResponse(record, headers={"Cache-Control": "public, max-age=30"})

    @router.get("/api/verify/{domain}/signatures/{sig_id}")
    @_limit("60/minute")
    async def public_verify_signature(domain: str, sig_id: str, request: Request):
        try:
            sig = await run_in_threadpool(store.public_signature, domain, sig_id)
        except store.SigningError as exc:
            raise _http(exc) from None
        return JSONResponse(sig, headers={"Cache-Control": "public, max-age=30"})

    @router.get("/api/verify/{domain}/lookup")
    @_limit("60/minute")
    async def public_verify_lookup(domain: str, request: Request, sha512: str = Query(..., max_length=128)):
        try:
            found = await run_in_threadpool(store.lookup, domain, sha512)
        except store.SigningError as exc:
            raise _http(exc) from None
        return JSONResponse(found, headers={"Cache-Control": "no-store"})

    @router.post("/api/verify")
    @_limit("30/minute")
    async def public_verify_document(request: Request):
        """The verdict on a signature file. Send the file's SHA-512 (and size) to check the file too."""
        body = await _json_body(request, MAX_SMALL_BODY)
        digest = body.get("sha512")
        size = body.get("size")
        if digest is not None and not isinstance(digest, str):
            raise HTTPException(status_code=400, detail="sha512 must be text.")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise HTTPException(status_code=400, detail="size must be a whole number of bytes.")
        try:
            result = await run_in_threadpool(store.verify_document, body.get("signature"),
                                             digest.strip().lower() if isinstance(digest, str) else None, size)
        except store.SigningError as exc:
            raise _http(exc) from None
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    return router


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(str(text or "").encode("ascii")).hexdigest()
