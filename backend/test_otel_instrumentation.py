"""OpenTelemetry instrumentation must attach, and instrumented requests must still work.

Two failure modes have both happened here, and neither announced itself:

1. Silently absent. The instrumentation was attached inside `try: ... except ImportError: pass`.
   opentelemetry-instrumentation 0.48b0 imports pkg_resources, which current environments no longer
   provide, so the import raised ModuleNotFoundError and per-request tracing was simply off — an
   operator who configured an OTLP endpoint got the SDK tracer and no HTTP spans, with nothing
   logged. The `pass` is now a warning, and this test asserts the instrumentation is present.

2. Present but incompatible. Instrumentation 0.50b0 reads `scope["route"].path`, which on FastAPI
   0.141 is an `_IncludedRouter` with no `.path`, so *every* instrumented request raised
   AttributeError. That surfaced as ~40 unrelated-looking test failures across the suite; one
   request through the middleware stack identifies it directly.

The instrumentation attaches at import regardless of OTEL_EXPORTER_OTLP_ENDPOINT (only the exporter
is gated on it), so no endpoint is configured here and no trace export is attempted.
"""

from fastapi.testclient import TestClient


def test_fastapi_instrumentation_is_attached():
    import app

    assert getattr(app.app, "_is_instrumented_by_opentelemetry", False), (
        "OpenTelemetry FastAPI instrumentation did not attach, so per-request tracing is disabled. "
        "Check the pqc.otel warning at import time — most likely the "
        "opentelemetry-instrumentation-fastapi dependency failed to import."
    )


def test_requests_succeed_through_the_instrumented_middleware_stack():
    """Catches instrumentation that is installed but incompatible with the FastAPI version."""
    import app

    app.app.router.on_startup.clear()
    app.app.router.on_shutdown.clear()
    with TestClient(app.app) as client:
        # A public route and a routed API path: the route-details lookup that broke on FastAPI 0.141
        # runs per request and depends on how the route was registered.
        assert client.get("/status").status_code == 200
        assert client.get("/healthz").status_code == 200
        response = client.get("/assets", headers={"x-user-id": "admin", "x-user-role": "admin"})
        assert response.status_code == 200, response.text


def test_instrumentation_version_tracks_fastapi():
    """The instrumentation reads FastAPI internals, so a stale pairing breaks every request.

    Asserted as a floor rather than an exact pin: 0.50b0 and earlier are known incompatible with
    FastAPI 0.141.
    """
    from importlib import metadata

    raw = metadata.version("opentelemetry-instrumentation-fastapi")
    # Versions look like "0.65b0"; compare on the numeric minor component.
    minor = int(raw.split(".")[1].split("b")[0])
    assert minor >= 51, (
        f"opentelemetry-instrumentation-fastapi {raw} predates FastAPI 0.141 support and will raise "
        f"AttributeError('_IncludedRouter' object has no attribute 'path') on every request"
    )
