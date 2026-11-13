"""Watch mode and domain claims over HTTP (services/watch.py holds the rules).

Signed in (any role watches; an admin or owner claims, because a claim speaks for the organization):
  GET    /instrument/watch                       your watched domains, what changed, your channels
  GET    /instrument/watch/{domain}              are you watching it, its last answer, its changes
  PUT    /instrument/watch/{domain}              watch it
  DELETE /instrument/watch/{domain}              stop watching it
  POST   /instrument/watch-push                  {endpoint, keys:{p256dh, auth}} this browser's push subscription
  DELETE /instrument/watch-push                  {endpoint}
  POST   /instrument/watch-channels              {kind: slack_webhook|generic_webhook, target}
  DELETE /instrument/watch-channels/{id}
  POST   /instrument/watch-test                  one test message to every channel you have
  POST   /instrument/watch-feed                  a new private feed address (the old one stops)
  DELETE /instrument/watch-feed
  GET    /instrument/claims/{domain}             your organization's claim: the DNS record, the state
  POST   /instrument/claims/{domain}             start a claim: the DNS TXT record to publish
  POST   /instrument/claims/{domain}/check       look the record up now and claim
  DELETE /instrument/claims/{domain}             give the claim up
  POST   /instrument/claims/{domain}/opt-out     the owner asks Morrow never to check it again

Public (under /api/public, so the auth gate lets them through):
  GET /api/public/claim/{domain}                 claimed or not, since when, the owner's public reply
  GET /api/public/scanner                       what the checker sends, when, and how to opt out
  GET /api/public/push-key                       the VAPID public key, or why push is off
  GET /api/public/watch-feed/{token}.atom        a private feed: the random token is the credential
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from services import watch as _watch

_NO_STORE = {"Cache-Control": "no-store"}
ANY_ROLE = ["viewer", "analyst", "admin", "owner"]
ADMIN = ["admin", "owner"]


class PushBody(BaseModel):
    endpoint: str = Field(default="", max_length=2048)
    keys: Dict[str, str] = Field(default_factory=dict)


class EndpointBody(BaseModel):
    endpoint: str = Field(default="", max_length=2048)


class ChannelBody(BaseModel):
    kind: str = Field(default="", max_length=40)
    target: str = Field(default="", max_length=2048)


def _err(exc: _watch.WatchError) -> JSONResponse:
    return JSONResponse({"detail": exc.detail, "error": exc.code}, status_code=exc.status_code, headers=_NO_STORE)


def create_watch_router(deps: Any) -> APIRouter:
    """deps: require_role(request, roles, action, resource_type, resource_id) -> actor dict,
    org_id() -> str, audit(request, action, resource_type, resource_id, details) -> None."""
    router = APIRouter(include_in_schema=False)

    def who(request: Request, roles, action: str, rtype: str, rid: str = ""):
        actor = deps.require_role(request, roles, action=action, resource_type=rtype, resource_id=rid) or {}
        return deps.org_id(), str(actor.get("actor_id") or "")

    def audit(request: Request, action: str, rtype: str, rid: str, details: Optional[Dict[str, Any]] = None) -> None:
        fn = getattr(deps, "audit", None)
        if callable(fn):
            try:
                fn(request, action=action, resource_type=rtype, resource_id=rid, details=details or {})
            except Exception:
                pass

    async def call(fn, *args):
        try:
            return JSONResponse(await run_in_threadpool(fn, *args), headers=_NO_STORE)
        except _watch.WatchError as exc:
            return _err(exc)

    # ── watching ──
    @router.get("/instrument/watch")
    async def watch_overview(request: Request):
        org, user = who(request, ANY_ROLE, "read", "domain_watch", "*")
        return await call(_watch.overview, org, user)

    @router.get("/instrument/watch/{domain}")
    async def watch_one(request: Request, domain: str):
        org, user = who(request, ANY_ROLE, "read", "domain_watch", domain)
        return await call(_watch.watching, org, user, domain)

    @router.put("/instrument/watch/{domain}")
    async def watch_start(request: Request, domain: str):
        org, user = who(request, ANY_ROLE, "create", "domain_watch", domain)
        resp = await call(_watch.watch, org, user, domain)
        if resp.status_code == 200:
            audit(request, "watch.started", "domain_watch", domain)
        return resp

    @router.delete("/instrument/watch/{domain}")
    async def watch_stop(request: Request, domain: str):
        org, user = who(request, ANY_ROLE, "delete", "domain_watch", domain)
        try:
            removed = await run_in_threadpool(_watch.unwatch, org, user, domain)
        except _watch.WatchError as exc:
            return _err(exc)
        audit(request, "watch.stopped", "domain_watch", domain)
        return JSONResponse({"removed": removed}, headers=_NO_STORE)

    # ── channels ──
    @router.post("/instrument/watch-push")
    async def push_add(request: Request, body: PushBody):
        org, user = who(request, ANY_ROLE, "create", "watch_push", "")
        return await call(_watch.add_push, org, user, {"endpoint": body.endpoint, "keys": body.keys})

    @router.delete("/instrument/watch-push")
    async def push_remove(request: Request, body: EndpointBody):
        org, user = who(request, ANY_ROLE, "delete", "watch_push", "")
        return JSONResponse({"removed": await run_in_threadpool(_watch.remove_push, org, user, body.endpoint)}, headers=_NO_STORE)

    @router.post("/instrument/watch-channels")
    async def channel_add(request: Request, body: ChannelBody):
        org, user = who(request, ANY_ROLE, "create", "watch_channel", "")
        resp = await call(_watch.add_channel, org, user, body.kind, body.target)
        if resp.status_code == 200:
            audit(request, "watch.channel_added", "watch_channel", body.kind)
        return resp

    @router.delete("/instrument/watch-channels/{channel_id}")
    async def channel_remove(request: Request, channel_id: str):
        org, user = who(request, ANY_ROLE, "delete", "watch_channel", channel_id)
        removed = await run_in_threadpool(_watch.remove_channel, org, user, channel_id)
        return JSONResponse({"removed": removed}, status_code=200 if removed else 404, headers=_NO_STORE)

    @router.post("/instrument/watch-test")
    async def channel_test(request: Request):
        org, user = who(request, ANY_ROLE, "create", "watch_test", "")
        return await call(_watch.test_channels, org, user)

    @router.post("/instrument/watch-feed")
    async def feed_new(request: Request):
        org, user = who(request, ANY_ROLE, "create", "watch_feed", "")
        resp = await call(_watch.new_feed, org, user)
        audit(request, "watch.feed_rotated", "watch_feed", "")
        return resp

    @router.delete("/instrument/watch-feed")
    async def feed_drop(request: Request):
        org, user = who(request, ANY_ROLE, "delete", "watch_feed", "")
        return JSONResponse({"removed": await run_in_threadpool(_watch.drop_feed, org, user)}, headers=_NO_STORE)

    # ── claims ──
    @router.get("/instrument/claims/{domain}")
    async def claim_get(request: Request, domain: str):
        org, _ = who(request, ANY_ROLE, "read", "domain_claim", domain)
        return await call(_watch.claim_status, org, domain)

    @router.post("/instrument/claims/{domain}")
    async def claim_start(request: Request, domain: str):
        org, _ = who(request, ADMIN, "create", "domain_claim", domain)
        return await call(_watch.start_claim, org, domain)

    @router.post("/instrument/claims/{domain}/check")
    async def claim_check(request: Request, domain: str):
        org, user = who(request, ADMIN, "update", "domain_claim", domain)
        resp = await call(_watch.claim, org, user, domain)
        if resp.status_code == 200:
            audit(request, "domain.claimed", "domain_claim", domain)
        return resp

    @router.delete("/instrument/claims/{domain}")
    async def claim_release(request: Request, domain: str):
        org, _ = who(request, ADMIN, "delete", "domain_claim", domain)
        try:
            removed = await run_in_threadpool(_watch.release, org, domain)
        except _watch.WatchError as exc:
            return _err(exc)
        audit(request, "domain.claim_released", "domain_claim", domain)
        return JSONResponse({"removed": removed}, headers=_NO_STORE)

    @router.post("/instrument/claims/{domain}/opt-out")
    async def claim_opt_out(request: Request, domain: str):
        org, user = who(request, ADMIN, "update", "domain_claim", domain)
        from services import public_check

        try:
            name = await run_in_threadpool(_watch.require_claim, org, domain)
            out = await run_in_threadpool(public_check.add_optout, name, "owner request: DNS-verified claim in Morrow",
                                          f"claim:{org}:{user}"[:200])
        except _watch.WatchError as exc:
            return _err(exc)
        except public_check.PublicCheckError as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=_NO_STORE)
        audit(request, "domain.opted_out_by_owner", "domain_claim", name)
        return JSONResponse({"domain": out.get("domain", name), "opted_out": True}, headers=_NO_STORE)

    # ── public ──
    @router.get("/api/public/claim/{domain}")
    async def public_claim(domain: str):
        return await call(_watch.public_claim, domain)

    @router.get("/api/public/scanner")
    async def scanner_facts(host: str = "example.com"):
        from services import public_grade

        try:
            name = public_grade.normalize(host)
        except public_grade.GradeError:
            name = "example.com"
        return JSONResponse(await run_in_threadpool(_watch.about_scanner, name), headers={"Cache-Control": "public, max-age=300"})

    @router.get("/api/public/push-key")
    async def push_key():
        from services import web_push

        st = web_push.status()
        return JSONResponse({"enabled": st["enabled"], "public_key": st["public_key"], "reason": st["reason"]},
                            headers={"Cache-Control": "public, max-age=300"})

    @router.get("/api/public/watch-feed/{token}.atom")
    async def private_feed(token: str):
        body = await run_in_threadpool(_watch.feed_atom, token)
        if body is None:
            return JSONResponse({"detail": "No feed at this address. Make a new one on /watching."}, status_code=404,
                                headers=_NO_STORE)
        return Response(body, media_type="application/atom+xml; charset=utf-8",
                        headers={"Cache-Control": "private, no-store", "X-Robots-Tag": "noindex"})

    return router
