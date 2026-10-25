"""The public, unauthenticated post-quantum readiness checker.

Pages (no account, no tenant)
  GET  /check                               the form (static/check.html)
  GET  /check/{domain}                      301 to /r/{domain}, the permanent record

The registry: the permanent record (server-rendered, services/registry_page.py)
  GET  /r/{domain}                          the record; 404 with a noindex page when there is none
  GET  /r/{domain}/at/{id}                  one past observation, immutable and citable
  GET  /r/{domain}/badge.svg                the embeddable badge
  GET  /r/{domain}/export.json              the JSON export, from the record rather than the cache
  GET  /r/{domain}/cbom.json                the CBOM, from the record rather than the cache

API (public, unauthenticated, rate limited)
  GET  /api/public-check/config             the guardrails and their current values
  POST /api/public-check {domain}           runs the check, or serves the cache
  GET  /api/public-check/{domain}           the cached result only; 404 when there is none
  GET  /api/public-check/{domain}/export.json   the JSON export of a cached result
  GET  /api/public-check/{domain}/cbom.json     a CycloneDX 1.6 CBOM for the checked endpoint

Operator (platform key / operator session, like the rest of /platform/*)
  GET    /platform/public-check/log         the check log, for an abuse investigation
  GET    /platform/public-check/opt-outs    the opt-out list
  POST   /platform/public-check/opt-outs    add a domain (and drop its cached result)
  DELETE /platform/public-check/opt-outs/{domain}

Why GET never checks anything
-----------------------------
Only POST contacts a target. A GET -- a permalink someone shared, a crawler, a link preview, the
endpoint smoke test -- reads the cache and nothing else. That makes the permalink safe to share at
any volume: a popular result is served from one check, and no amount of link traffic turns into
connections to someone else's server.

Rate limits apply twice over: the slowapi per-IP limiter on these routes (so even cache reads
cannot be used to hammer the API), and inside services/public_check.py the per-IP, per-domain and
global check budgets, which only an actual check spends.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Iterable, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from services import platform_operators as _operators
from services import public_check as _check
from services import public_config as _public_config
from services import registry_page as _registry

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES

#: A cached result is a public fact about a public endpoint, and the permalink is meant to be
#: shared, so a short shared-cache window is appropriate. Nothing here is per-visitor.
_RESULT_CACHE_CONTROL = "public, max-age=60"
_PAGE_CACHE_CONTROL = "public, max-age=0, must-revalidate"
#: A record page is the same for everyone and changes only when the endpoint's cryptography does,
#: which the ETag already detects. stale-while-revalidate lets a shared cache answer instantly and
#: refresh behind the request -- the difference between serving a catalogue and straining under it.
_RECORD_CACHE_CONTROL = "public, max-age=300, stale-while-revalidate=86400"
#: Sent on every /r response that is not the current record of a real observation. /r/{anything} is
#: unbounded crawl space, so a page with nothing to show must never be indexable. The pages carry a
#: robots meta tag as well; the header is what a client can check without parsing HTML, and what a
#: deployment check can therefore verify.
_NOINDEX_HEADER = {"X-Robots-Tag": "noindex, follow"}


class CheckRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=400)
    #: Asks for a fresh check instead of the cache. It still spends the per-domain budget, so it
    #: cannot be used to re-check one host repeatedly.
    refresh: bool = False


class OptOutRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=400)
    reason: str = Field("", max_length=500)


def _error(exc: _check.PublicCheckError) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if exc.retry_after:
        headers["Retry-After"] = str(int(max(1, exc.retry_after)))
    return JSONResponse(
        {"detail": exc.detail, "outcome": exc.outcome, "domain_checked": False},
        status_code=exc.status_code, headers=headers)


def create_public_check_router(deps: Any) -> APIRouter:
    """deps: static_dir, limiter, public_check_rate, client_ip(request),
    require_platform_admin(request, roles), record_event(...)."""
    router = APIRouter()

    def _ip(request: Request) -> str:
        getter = getattr(deps, "client_ip", None)
        if callable(getter):
            try:
                return str(getter(request) or "")
            except Exception:
                pass
        return str(request.client.host if request.client else "")

    def _page() -> FileResponse:
        path = os.path.join(deps.static_dir, "check.html")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="check.html not found")
        return FileResponse(path, media_type="text/html; charset=utf-8",
                            headers={"Cache-Control": _PAGE_CACHE_CONTROL})

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    # ── Pages ────────────────────────────────────────────────────────────────

    @router.get("/check", include_in_schema=False)
    def public_check_page() -> FileResponse:
        return _page()

    @router.get("/check/{domain}", include_in_schema=False)
    def public_check_permalink_page(domain: str) -> Response:
        # The old permalink. It pointed at a cache that expires in an hour and is pruned after a
        # week, so a link shared on Monday was broken by the following Monday. The record at
        # /r/{domain} is the permanent one, and two URLs for one record would split its search
        # ranking and make the ETag meaningless -- so this redirects rather than rendering.
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError:
            return RedirectResponse("/check", status_code=302)
        return RedirectResponse(f"/r/{host}", status_code=301)

    # ── Registry: the permanent record ───────────────────────────────────────
    #
    # None of these routes carries @deps.limiter.limit(deps.public_check_rate), and that is
    # deliberate rather than an omission. That budget (30/minute by default) exists to stop the
    # API being used to hammer the checker; a record page is meant to be crawled, shared and
    # embedded, and applying the checker's budget to it would throttle exactly the traffic the
    # registry exists to attract -- a search engine indexing a catalogue would collect 429s.
    # They are still covered by the limiter's per-IP default (MORROW_RATE_LIMIT_DEFAULT, 300/minute)
    # and by the request-count middleware, and none of them can start a check, so the worst a
    # flood achieves is reading cached HTML.

    def _origin(request: Request) -> str:
        """The address to build absolute URLs from.

        MORROW_PUBLIC_BASE_URL when the deployment sets it, because that is the host people type and
        the one a canonical link and a badge URL have to name. request.base_url is the fallback,
        and behind a proxy it is only right if forwarded headers are honoured -- which is why the
        configured value wins.
        """
        return _public_config.public_base_url() or str(request.base_url).rstrip("/")

    def _refuse_page(request: Request, host: str, covered: str) -> HTMLResponse:
        return HTMLResponse(
            _registry.render_refused(host, covered, _origin(request)),
            status_code=403,
            headers={"Cache-Control": "no-store", **_NOINDEX_HEADER})

    def _record_etag(entry: Dict[str, Any]) -> str:
        """An ETag over everything the page shows, not only the cryptography.

        content_hash alone is wrong here: re-checking an unchanged endpoint moves "last confirmed"
        and can move the observation count without changing the cryptography, so an ETag built from
        content_hash alone would answer 304 and leave the visitor looking at a stale date. The
        observation id is in here too, so viewing the current record straight after a change cannot
        be served from a cache keyed on the previous one.
        """
        basis = "|".join(str(entry.get(key) or "") for key in
                         ("content_hash", "last_observed_at", "observations", "observation_id"))
        return f'"{hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]}"'

    def _canonical_redirect(host: str, domain: str, suffix: str = "") -> Optional[RedirectResponse]:
        """301 to the normalised spelling, so /r/Example.COM is not a second URL for one record."""
        if host == domain:
            return None
        return RedirectResponse(f"/r/{host}{suffix}", status_code=301)

    @router.get("/r/{domain}", include_in_schema=False)
    def registry_record(request: Request, domain: str) -> Response:
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError:
            # Not a hostname this service will accept, so by definition there is no record. The
            # missing page says so in HTML, because this route is reached by people and crawlers
            # following links, not by API clients who want JSON.
            return HTMLResponse(
                _registry.render_missing(str(domain)[:253], _origin(request)),
                status_code=404,
                headers={"Cache-Control": "no-store", **_NOINDEX_HEADER})
        moved = _canonical_redirect(host, domain)
        if moved is not None:
            return moved

        covered = _check.opted_out(host)
        if covered:
            return _refuse_page(request, host, covered)

        entry = _check.registry_entry(host)
        if entry is None:
            # 404, and noindex inside the page: /r/{anything} is unbounded crawl space, and a
            # crawler offered 200s for arbitrary strings will mine the namespace indefinitely.
            return HTMLResponse(_registry.render_missing(host, _origin(request)),
                                status_code=404,
                                headers={"Cache-Control": "public, max-age=60",
                                         **_NOINDEX_HEADER})

        etag = _record_etag(entry)
        if (request.headers.get("if-none-match") or "").strip() == etag:
            return Response(status_code=304, headers={"ETag": etag,
                                                      "Cache-Control": _RECORD_CACHE_CONTROL})
        html = _registry.render_record(entry, _check.registry_history(host), _origin(request))
        return HTMLResponse(html, headers={"ETag": etag, "Cache-Control": _RECORD_CACHE_CONTROL})

    @router.get("/r/{domain}/at/{observation_id}", include_in_schema=False)
    def registry_observation_page(request: Request, domain: str, observation_id: int) -> Response:
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError as exc:
            return _error(exc)
        moved = _canonical_redirect(host, domain, f"/at/{int(observation_id)}")
        if moved is not None:
            return moved
        covered = _check.opted_out(host)
        if covered:
            return _refuse_page(request, host, covered)
        entry = _check.registry_entry(host)
        observation = _check.registry_observation(host, int(observation_id))
        if entry is None or observation is None:
            return HTMLResponse(_registry.render_missing(host, _origin(request)),
                                status_code=404,
                                headers={"Cache-Control": "no-store", **_NOINDEX_HEADER})
        html = _registry.render_record(entry, _check.registry_history(host), _origin(request),
                                       observation=observation)
        # A past observation never changes, so it can be cached hard.
        return HTMLResponse(html, headers={"Cache-Control": "public, max-age=86400",
                                           **_NOINDEX_HEADER})

    @router.get("/r/{domain}/badge.svg", include_in_schema=False)
    def registry_badge(request: Request, domain: str) -> Response:
        """The embeddable badge. Renders from stored data; it can never start a check.

        An opted-out domain and a domain nobody has checked both get the neutral grey badge with
        status 200 -- see services/registry_page.badge_svg for why a 403 would be the wrong answer
        here even though it is the right one on every other route.
        """
        posture: Optional[str] = None
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError:
            host = ""
        if host and not _check.opted_out(host):
            entry = _check.registry_entry(host)
            if entry is not None:
                posture = str(entry.get("posture") or "")
        svg = _registry.badge_svg(posture)
        headers = {
            "Cache-Control": "public, max-age=3600, s-maxage=86400",
            "ETag": f'"{hashlib.sha256(svg.encode("utf-8")).hexdigest()[:32]}"',
            # README images are proxied (GitHub's Camo); nothing here may vary per viewer.
            "Access-Control-Allow-Origin": "*",
        }
        if (request.headers.get("if-none-match") or "").strip() == headers["ETag"]:
            return Response(status_code=304, headers=headers)
        return Response(svg, media_type="image/svg+xml", headers=headers)

    @router.get("/r/{domain}/export.json", include_in_schema=False)
    def registry_export(request: Request, domain: str) -> Response:
        return _registry_download(request, domain, _check.export_json, "export")

    @router.get("/r/{domain}/cbom.json", include_in_schema=False)
    def registry_cbom(request: Request, domain: str) -> Response:
        return _registry_download(request, domain, _check.export_cbom, "cbom")

    def _registry_download(request: Request, domain: str, builder: Any, kind: str) -> Response:
        """The exports, served from the permanent record rather than the cache.

        The equivalents under /api/public-check read the cache, so a download link went dead with
        the cache entry. These read the record, which is the point of having one.
        """
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError as exc:
            return _error(exc)
        refusal = _refuse_if_opted_out(host)
        if refusal is not None:
            return refusal
        entry = _check.registry_entry(host)
        if entry is None:
            return JSONResponse(
                {"detail": f"No record for {host}. Run the check from /check to create one.",
                 "outcome": "no_record", "domain": host},
                status_code=404, headers={"Cache-Control": "no-store"})
        payload = builder(entry["result"])
        return JSONResponse(payload, headers={
            "Cache-Control": _RECORD_CACHE_CONTROL,
            "Content-Disposition": f'attachment; filename="{host}-{kind}.json"',
        })

    # ── Public API ───────────────────────────────────────────────────────────

    def _refuse_if_opted_out(host: str) -> Optional[JSONResponse]:
        """An opted-out domain is refused on every read route, not only the HTML one.

        Adding an opt-out deletes the cached result, so these routes usually have nothing to serve
        anyway. "Usually" is not a guarantee: a domain added through MORROW_PUBLIC_CHECK_OPTOUT_DOMAINS
        deletes nothing, and a cached result from before the opt-out would then still have been
        downloadable as JSON and as a CBOM while the page itself answered 403. The guard is cheap
        and the promise made to a domain owner is unconditional, so it is made on every route.
        """
        covered = _check.opted_out(host)
        if not covered:
            return None
        return _error(_check.PublicCheckError(
            403, f"{covered} has asked not to be checked by this service.", "refused_optout"))

    @router.get("/api/public-check/config")
    @deps.limiter.limit(deps.public_check_rate)
    def public_check_config(request: Request) -> JSONResponse:
        """Everything the page needs to state its own boundaries, read from live settings."""
        return JSONResponse({
            "guardrails": _check.settings_public(),
            "queue": _check.queue_depth(),
            "acceptable_use": acceptable_use(),
            "deadlines": _check.published_deadlines(),
            "limits": list(_check._LIMITS),
            "what_a_full_assessment_adds": list(_check._FULL_ASSESSMENT_ADDS),
        }, headers={"Cache-Control": "public, max-age=300"})

    @router.post("/api/public-check")
    @deps.limiter.limit(deps.public_check_rate)
    async def public_check_run(request: Request, body: CheckRequest):
        """The only route that contacts anything. Everything else reads the cache."""
        client_ip = _ip(request)
        try:
            result = await run_in_threadpool(
                _check.run_check, body.domain, client_ip, bool(body.refresh))
        except _check.PublicCheckError as exc:
            return _error(exc)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @router.get("/api/public-check/{domain}")
    @deps.limiter.limit(deps.public_check_rate)
    def public_check_cached(request: Request, domain: str):
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError as exc:
            return _error(exc)
        refusal = _refuse_if_opted_out(host)
        if refusal is not None:
            return refusal
        result = _check.cached_result(host)
        if result is None:
            return JSONResponse(
                {"detail": f"No cached result for {host}. Run the check from /check to produce one.",
                 "outcome": "no_cached_result", "domain": host},
                status_code=404, headers={"Cache-Control": "no-store"})
        return JSONResponse(result, headers={"Cache-Control": _RESULT_CACHE_CONTROL})

    @router.get("/api/public-check/{domain}/export.json")
    @deps.limiter.limit(deps.public_check_rate)
    def public_check_export(request: Request, domain: str):
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError as exc:
            return _error(exc)
        refusal = _refuse_if_opted_out(host)
        if refusal is not None:
            return refusal
        result = _check.cached_result(host)
        if result is None:
            return JSONResponse({"detail": f"No cached result for {host}.",
                                 "outcome": "no_cached_result"}, status_code=404,
                                headers={"Cache-Control": "no-store"})
        return JSONResponse(_check.export_json(result), headers={
            "Cache-Control": _RESULT_CACHE_CONTROL,
            "Content-Disposition": f'attachment; filename="pq-check-{host}.json"'})

    @router.get("/api/public-check/{domain}/cbom.json")
    @deps.limiter.limit(deps.public_check_rate)
    def public_check_cbom(request: Request, domain: str):
        try:
            host = _check.normalize_domain(domain)
        except _check.PublicCheckError as exc:
            return _error(exc)
        refusal = _refuse_if_opted_out(host)
        if refusal is not None:
            return refusal
        result = _check.cached_result(host)
        if result is None:
            return JSONResponse({"detail": f"No cached result for {host}.",
                                 "outcome": "no_cached_result"}, status_code=404,
                                headers={"Cache-Control": "no-store"})
        return JSONResponse(_check.export_cbom(result), headers={
            "Cache-Control": _RESULT_CACHE_CONTROL,
            "Content-Disposition": f'attachment; filename="pq-check-{host}-cbom.json"'})

    # ── Operator surface ─────────────────────────────────────────────────────

    @router.get("/platform/public-check/log")
    def platform_public_check_log(request: Request, limit: int = 100, domain: str = ""):
        guard(request, READ)
        host = ""
        if domain:
            try:
                host = _check.normalize_domain(domain)
            except _check.PublicCheckError as exc:
                raise HTTPException(status_code=400, detail=exc.detail) from None
        return {"entries": _check.recent_log(limit=limit, domain=host),
                "retention_days": _check.log_retention_days(),
                "note": "Requester addresses are stored only as a salted hash. "
                        "Two rows with the same hash came from the same address."}

    @router.get("/platform/public-check/opt-outs")
    def platform_public_check_optouts(request: Request):
        guard(request, READ)
        return {"opt_outs": _check.list_optouts(),
                "configured": sorted(_check._optout_set()),
                "abuse_contact": _check.abuse_contact()}

    @router.post("/platform/public-check/opt-outs")
    def platform_public_check_optout_add(request: Request, body: OptOutRequest):
        actor = guard(request, WRITE)
        try:
            out = _check.add_optout(body.domain, body.reason,
                                    str((actor or {}).get("actor_id") or ""))
        except _check.PublicCheckError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
        record = getattr(deps, "record_event", None)
        if callable(record):
            try:
                record("public_check_optout_added", {"domain": out["domain"]})
            except Exception:
                pass
        return out

    @router.delete("/platform/public-check/opt-outs/{domain}")
    def platform_public_check_optout_remove(request: Request, domain: str):
        guard(request, WRITE)
        try:
            return _check.remove_optout(domain)
        except _check.PublicCheckError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None

    return router


def acceptable_use() -> Dict[str, Any]:
    """The acceptable-use statement, served to the page so it cannot drift from the code.

    It is on the result page itself, not in the terms: someone pointing this at a host they do not
    own needs to read it before they press the button, not after they agree to a contract.
    """
    return {
        "summary": ("This tool reads public Certificate Transparency data for a domain and makes one "
                    "TLS handshake to it on port 443. That is the same kind of contact a browser or "
                    "SSL Labs makes, and nothing more."),
        "does": [
            "Reads public Certificate Transparency logs. The target is not contacted for this.",
            f"Makes at most two connections to the hostname you typed, on port {_check.PORT}: one "
            "ordinary TLS handshake, and one that offers post-quantum key-exchange groups.",
            "Caches the answer and serves the cache, so a popular domain is checked once rather "
            "than once per visitor.",
            "Logs the domain, the time, a salted hash of your address and the outcome, so abuse "
            "can be investigated.",
        ],
        "does_not": [
            "No port scanning. One port, 443.",
            "No subdomain discovery or enumeration.",
            "No vulnerability probing, no exploit attempts, no authentication attempts.",
            "No crawling and no HTTP request to the target.",
            "No private, loopback, link-local, carrier-grade NAT or reserved address, ever.",
            "No result is stored against any customer account, and no customer data is read.",
        ],
        "rules": [
            "Check hosts you own, or hosts whose configuration is public information you have a "
            "legitimate reason to read. Do not use this as a step in attacking anyone.",
            "Do not automate it. The rate limits are enforced, and the cached result is the same "
            "answer as a fresh one.",
            "If you operate a domain and do not want it checked here, write to the address below "
            "and it will be refused before anything is resolved or connected to.",
        ],
        "abuse_contact": _check.abuse_contact(),
        "opt_out_contact": _check.abuse_contact(),
        # The published documents, so an API or command-line caller can find them without reading
        # the page. The statement above remains the authority on what the running code does; these
        # pages are the longer form of it, and they say so.
        "documents": {
            "terms": "/public-check/terms",
            "acceptable_use": "/public-check/acceptable-use",
            "privacy": "/public-check/privacy",
            "abuse_and_opt_out": "/abuse",
            "scanner_identity": "/scanner",
        },
        "self_hoster_note": ("If you run your own copy of this service, the responsibility for what "
                             "it contacts is yours, under your own jurisdiction's rules."),
    }
