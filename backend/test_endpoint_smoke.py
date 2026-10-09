"""Every GET endpoint must answer without a server error.

63% of the API had no test touching it, and that is where every defect this
codebase turned up was hiding: a feature that had never worked, with nothing to
notice. The red team simulation, 22 of the AI analyst's tools, the SLA board,
drift snapshots and the audit package export were all in untested surface.

This is deliberately shallow. It proves nothing about correctness -- only that a
route does not blow up when called. That is a low bar, and it is exactly the bar
every one of those bugs failed: they were 500s or silently-empty responses, not
subtle logic errors.

Two things it does not do:
  * POST/PUT/DELETE, which mutate. Those need per-endpoint fixtures.
  * Assert on response bodies. A separate concern, and a moving one.
"""

import os
import re

import pytest

ORG = "00000000-0000-0000-0000-000000000001"

# Endpoints that reach the network, a broker, or stream indefinitely on GET.
# Probing these measures the internet, not the application. Matched after the
# /v1 prefix is stripped so an alias cannot slip past.
EXTERNAL_OR_STREAMING = (
    "/observatory/run", "/scan", "/qday/live", "/q-intel/refresh",
    "/runtime-handshake", "/cloud-discovery", "/integrations/cloudflare",
    "/telemetry/stream", "/agent", "/assistant", "/sovereign-copilot",
)

# A 503 that names an unconfigured optional dependency is correct behaviour, not
# a defect: the server is telling the operator exactly what to set. Anything
# else in the 5xx range is a bug.
ALLOWED_UNCONFIGURED = (
    "/auth/github/connect", "/auth/saml/login", "/auth/saml/metadata",
    "/jobs/{job_id}", "/vault/credentials",
    "/vault/credentials/{cred_id}", "/vault/credentials/{cred_id}/reveal",
)

PATH_PARAMS = {
    "organization_id": ORG, "org_id": ORG, "token": "x", "scan_id": "x", "id": "1",
    "asset_key": "example.com:443", "remediation_id": "1", "name": "x", "key": "x",
    "schedule_id": "1", "webhook_id": "1", "framework": "nist", "path": "x",
    "invite_id": "1", "job_id": "1", "vendor": "x", "host": "example.com",
    "filename": "x", "domain": "example.com",
}


def _strip_v1(path: str) -> str:
    return re.sub(r"^/v1", "", path) or "/"


def _fill(path: str) -> str:
    return re.sub(r"\{([a-zA-Z_]+)(?::[^}]+)?\}",
                  lambda m: PATH_PARAMS.get(m.group(1), "1"), path)


@pytest.fixture(scope="module")
def probe():
    os.environ.setdefault("PQC_AUTH_MODE", "header")
    os.environ.setdefault("PQC_DEFAULT_ROLE", "admin")
    import app as application
    from fastapi.testclient import TestClient

    # Everything mutated here is module-level state on a shared import, so each
    # value is captured and restored. Leaving _PLATFORM_ADMIN_KEY set to the
    # probe's key made unrelated platform-auth tests pass or fail depending on
    # file order -- the kind of breakage a smoke test has no business causing.
    was_key = application._PLATFORM_ADMIN_KEY
    was_enabled = getattr(application.limiter, "enabled", True)
    was_max = application.RATE_LIMIT_MAX_REQUESTS

    application._PLATFORM_ADMIN_KEY = "smoke-key"
    # There are two limiters and both must be lifted, or the probe answers 429
    # for most routes and the suite passes while proving almost nothing:
    #   * slowapi, via the per-route decorators
    #   * a per-organization counter in the request middleware
    application.limiter.enabled = False
    application.RATE_LIMIT_MAX_REQUESTS = 10_000_000

    # A suspended organization answers 403 to everything, so a probe run that
    # tripped a lifecycle endpoint would leave this file failing for reasons
    # unrelated to the code under test. Start from a known-active org.
    try:
        import db as _db_mod
        with _db_mod.get_connection() as _conn:
            _conn.execute(
                "UPDATE organizations SET subscription_status='active' WHERE id=?", (ORG,)
            )
            _conn.commit()
    except Exception:
        pass

    headers = {
        "x-org-id": ORG, "x-platform-key": "smoke-key",
        "x-platform-admin-role": "owner", "x-actor-role": "admin",
        "x-user-id": "smoke@test",
    }
    with TestClient(application, raise_server_exceptions=False) if False else TestClient(
        application.app, raise_server_exceptions=False
    ) as client:
        yield application, client, headers

    application._PLATFORM_ADMIN_KEY = was_key
    application.limiter.enabled = was_enabled
    application.RATE_LIMIT_MAX_REQUESTS = was_max
    # Restoring the limit is not enough: the sliding window keeps a timestamp per
    # request, and this probe adds well over a thousand. Left in place, the very
    # next test to call the API gets a 429 and fails for a reason that has
    # nothing to do with it. Drain the window and the observation log too.
    application._requests_by_org.clear()
    application._RATE_LIMIT_OBSERVATIONS.clear()


def _get_routes(application):
    paths = set()
    for route in application.app.routes:
        methods = getattr(route, "methods", None) or set()
        if "GET" not in methods:
            continue
        path = route.path
        if path.startswith(("/ui", "/vendor-admin")):
            continue
        if any(_strip_v1(path).startswith(s) for s in EXTERNAL_OR_STREAMING):
            continue
        paths.add(path)
    return sorted(paths)


def test_no_get_endpoint_returns_a_server_error(probe):
    application, client, headers = probe
    failures = []

    for path in _get_routes(application):
        try:
            response = client.get(_fill(path), headers=headers)
        except Exception as exc:  # a route that raises before returning
            failures.append(f"{path}  raised {type(exc).__name__}: {str(exc)[:120]}")
            continue
        if response.status_code < 500:
            continue
        if _strip_v1(path) in ALLOWED_UNCONFIGURED and response.status_code == 503:
            continue
        try:
            detail = str(response.json())[:160]
        except Exception:
            detail = response.text[:160]
        failures.append(f"[{response.status_code}] {path}\n        {detail}")

    assert not failures, (
        "GET endpoints returning a server error. A 500 here is a route that cannot "
        "run at all -- usually a call signature or schema mismatch that no other "
        "test covers:\n\n  " + "\n  ".join(failures)
    )


def test_the_probe_covers_a_meaningful_share_of_the_api(probe):
    """A smoke test that quietly stops finding routes would pass forever."""
    application, _, _ = probe
    assert len(_get_routes(application)) > 300


def test_most_endpoints_answer_successfully(probe):
    """Guards the fixture itself: if auth or the limiter regressed, everything
    would answer 401 or 429 and the suite above would pass vacuously."""
    application, client, headers = probe
    routes = _get_routes(application)
    ok = sum(1 for p in routes if client.get(_fill(p), headers=headers).status_code == 200)
    assert ok > len(routes) * 0.6, (
        f"only {ok}/{len(routes)} endpoints returned 200; the probe is probably "
        "being rejected rather than exercising the API"
    )


def test_unconfigured_dependencies_explain_themselves(probe):
    """A 503 is only acceptable when it tells the operator what to configure."""
    application, client, headers = probe
    for path in ALLOWED_UNCONFIGURED:
        response = client.get(_fill(path), headers=headers)
        if response.status_code != 503:
            continue
        body = response.text.lower()
        assert any(word in body for word in ("configure", "not configured", "set ", "requires")), (
            f"{path} returned 503 without saying what to configure: {response.text[:120]}"
        )


# --------------------------------------------------------------------------- #
# Write surface
# --------------------------------------------------------------------------- #
# POST/PUT/PATCH/DELETE cannot be probed with valid payloads without a fixture
# per endpoint. They can be probed with an *invalid* one: a malformed request
# must be rejected, never crash the route. An empty body also cannot mutate
# anything, so this is safe to run across the whole write surface.
#
# It found two endpoints returning 500 for a missing assessment, because the
# service raises ValueError where the route expected a falsy return.

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Reaches the network or a broker, or exists to destroy state.
#
# The suspend and org-delete routes matter more than the rest: the probe runs as
# the very organization they act on, so calling them suspends the caller. Every
# subsequent request then answers 403 "subscription is suspended" -- 143 of them
# on the first run -- and the probe quietly stops exercising anything while still
# reporting no server errors.
WRITE_SKIP = EXTERNAL_OR_STREAMING + (
    "/demo/lab/seed", "/platform/retention/run", "/platform/traffic/clear",
    "/crypto-kill-switch", "/emergency-response",
    "/platform/customers/{organization_id}/suspend", "/admin/orgs/{org_id}",
)


def _write_routes(application):
    out = set()
    for route in application.app.routes:
        methods = getattr(route, "methods", None) or set()
        # app.routes also holds included routers, which carry no .path.
        path = getattr(route, "path", None)
        if not path or not methods:
            continue
        if path.startswith(("/ui", "/vendor-admin")):
            continue
        if any(_strip_v1(path).startswith(s) for s in WRITE_SKIP):
            continue
        for method in WRITE_METHODS:
            if method in methods:
                out.add((method, path))
    return sorted(out)


def test_no_mutating_endpoint_crashes_on_a_malformed_body(probe):
    application, client, headers = probe
    failures = []

    for method, path in _write_routes(application):
        try:
            response = client.request(method, _fill(path), headers=headers, json={})
        except Exception as exc:
            failures.append(f"{method} {path}  raised {type(exc).__name__}: {str(exc)[:120]}")
            continue
        if response.status_code < 500:
            continue
        try:
            detail = str(response.json())[:160]
        except Exception:
            detail = response.text[:160]
        failures.append(f"[{response.status_code}] {method} {path}\n        {detail}")

    assert not failures, (
        "Mutating endpoints returning a server error for a malformed body. A "
        "rejected request should be 4xx; a 500 means the input reached code that "
        "could not handle it:\n\n  " + "\n  ".join(failures)
    )


def test_the_write_probe_covers_a_meaningful_share_of_the_api(probe):
    application, _, _ = probe
    assert len(_write_routes(application)) > 250


def test_the_public_checker_routes_answer_without_a_server_error(probe):
    """Named explicitly, because the enumerating probes above cannot reach them.

    FastAPI holds the routes of an included APIRouter inside a lazy _IncludedRouter container
    rather than flattening them into app.routes, so _get_routes and _write_routes see none of the
    router-mounted surface. These are the public checker's GET routes; every one of them reads the
    cache and nothing else, so probing them reaches no network.
    """
    _, client, headers = probe
    for path in ("/check", "/check/example.com", "/api/public-check/config",
                 "/api/public-check/example.com",
                 "/api/public-check/example.com/export.json",
                 "/api/public-check/example.com/cbom.json",
                 # The registry's read surface. /r/{domain} answers 404 with a page when there is
                 # no record and the badge answers 200 with the neutral badge, both from stored
                 # data only, so probing them reaches no network either.
                 "/r/example.com", "/r/example.com/badge.svg",
                 "/r/example.com/export.json", "/r/example.com/cbom.json"):
        response = client.get(path, headers=headers)
        assert response.status_code < 500, f"{path} answered {response.status_code}"
        assert response.status_code in {200, 404}, f"{path} answered {response.status_code}"

    # The one mutating route, with a body it must reject rather than crash on.
    for body in ({}, {"domain": ""}, {"domain": "127.0.0.1"}, {"domain": "*.example.com"}):
        response = client.post("/api/public-check", headers=headers, json=body)
        assert response.status_code < 500, f"{body} crashed the route"
        assert response.status_code in {400, 403, 422, 429, 503}


def test_a_missing_vendor_assessment_is_reported_as_not_found(probe):
    """Regression: services.vendor_workflow raises ValueError for an unknown
    assessment, but send/respond/score were written as though it returned None,
    so the 404 branch was unreachable and every one answered 500."""
    _, client, headers = probe
    for path in ("/vendor-assessments/does-not-exist/send",
                 "/vendor-assessments/does-not-exist/score"):
        response = client.post(path, headers=headers, json={})
        assert response.status_code == 404, (
            f"{path} answered {response.status_code}, expected 404: {response.text[:120]}"
        )
