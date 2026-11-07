"""Real-service end-to-end tests: a running Morrow backend and real nginx, Envoy, Prometheus,
strongSwan, Fluent Bit and Vector containers (deploy/e2e/compose.yml).

Every test here is skipped unless MORROW_E2E_BASE_URL names the backend of that stack, so the normal
unit suite never needs the services. The CI job is .github/workflows/e2e-real.yml; the manual
walkthrough is docs/DEMO_RUNBOOK.md.

The tests talk to the backend over HTTP only, as a customer would, and drive the containers through
the docker CLI (reload nginx, switch the traffic generator to failing clients, start the shippers).
Each session works in a fresh organization, which first proves control of the e2e DNS zone through
the product's own domain-verification flow (a real TXT record served by the dnsmasq container).
"""
from __future__ import annotations

import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

BASE_URL = (os.environ.get("MORROW_E2E_BASE_URL") or "").rstrip("/")
REPO = Path(__file__).resolve().parents[2]
E2E_DIR = REPO / "deploy" / "e2e"
STATE = E2E_DIR / "state"
COMPOSE = ["docker", "compose", "-f", str(E2E_DIR / "compose.yml")]
ZONE = "e2e.morrow.test"
CLASSIC_GROUPS = "ssl_ecdh_curve X25519:prime256v1;\n"
HYBRID_GROUPS = "ssl_ecdh_curve X25519MLKEM768:X25519;\n"


def pytest_collection_modifyitems(config, items):
    here = Path(__file__).parent
    skip = pytest.mark.skip(reason="MORROW_E2E_BASE_URL not set (needs the deploy/e2e stack)")
    for item in items:
        if here in Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.real_services)
            if not BASE_URL:
                item.add_marker(skip)


def run(args, check: bool = True, timeout: int = 180, env: Optional[Dict[str, str]] = None) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, **(env or {})})
    if check and proc.returncode != 0:
        raise AssertionError(f"{' '.join(args)} failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return proc.stdout


def compose(*args: str, env: Optional[Dict[str, str]] = None, timeout: int = 900) -> str:
    return run([*COMPOSE, *args], env=env, timeout=timeout)


def container(service: str) -> str:
    """The container compose names for a service of the morrow-e2e project. Plain `docker` calls on
    it are much cheaper than `docker compose` ones, which load and inspect the whole project."""
    return f"morrow-e2e-{service}-1"


def wait_for(fn: Callable[[], Any], timeout: float, interval: float = 2.0, what: str = "condition") -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}; last value: {last!r}")


def _write(path: Path, text: str) -> None:
    """LF only: the containers read these files, and the carriage return that Windows text mode
    adds left the traffic generator reading a mode that never equalled "fail"."""
    path.write_bytes(text.encode("utf-8"))


def set_nginx_groups(text: str) -> None:
    _write(STATE / "nginx-groups.conf", text)
    run(["docker", "exec", container("nginx"), "nginx", "-s", "reload"], timeout=300)
    time.sleep(1.0)


def set_traffic_mode(mode: str) -> None:
    _write(STATE / "traffic_mode", mode + "\n")


class Api:
    def __init__(self, base: str, org: str):
        import httpx

        self.org = org
        self.http = httpx.Client(base_url=base, timeout=httpx.Timeout(360.0, connect=10.0))

    def headers(self, role: str = "admin", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        return {"x-user-role": role, "x-user-id": f"e2e-{role}", "x-org-id": self.org, **(extra or {})}

    def call(self, method: str, path: str, expect: Optional[int] = 200, role: str = "admin", **kw) -> Any:
        headers = kw.pop("headers", None)
        r = self.http.request(method, path, headers=headers if headers is not None else self.headers(role), **kw)
        if expect is not None:
            assert r.status_code == expect, f"{method} {path} -> {r.status_code}: {r.text[:2000]}"
        try:
            return r.json()
        except ValueError:
            return r.text

    def get(self, path: str, **kw) -> Any:
        return self.call("GET", path, **kw)

    def post(self, path: str, **kw) -> Any:
        return self.call("POST", path, **kw)

    def scan(self, *targets: str, timeout: float = 600) -> Dict[str, Any]:
        """POST /scans, wait for it to complete, return GET /scans/{id}/results."""
        started = self.post("/scans", json={"targets": list(targets)})
        scan_id = started["id"]

        def done():
            s = self.get(f"/scans/{scan_id}")
            return s if s.get("status") in ("completed", "failed") else None

        scan = wait_for(done, timeout, what=f"scan {scan_id}")
        assert scan["status"] == "completed", scan
        return self.get(f"/scans/{scan_id}/results")


@pytest.fixture(scope="session")
def api() -> Api:
    # MORROW_E2E_ORG pins the organization (the runbook uses it to look at the same data in the
    # console afterwards); by default every session gets a fresh one.
    client = Api(BASE_URL, os.environ.get("MORROW_E2E_ORG") or str(uuid.uuid4()))
    wait_for(lambda: _healthy(client), 900, what="backend /healthz")
    return client


def _healthy(client: Api) -> bool:
    try:
        return client.http.get("/healthz", timeout=60).status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="session")
def verified_zone(api: Api) -> str:
    """The session's organization proves it controls e2e.morrow.test: add the domain, publish the
    TXT record it was given on the stack's DNS server, verify. Scans are refused until then."""
    added = api.post("/domains", json={"domain": ZONE}, role="operator")["domain"]
    assert added["record_name"] == f"_morrow-verify.{ZONE}"
    conf = (f"local=/{ZONE}/\nlog-queries\n"
            f"txt-record={added['record_name']},\"{added['record_value']}\"\n")
    _write(STATE / "dnsmasq.conf", conf)
    run(["docker", "restart", container("dns")], timeout=300)
    verified = wait_for(lambda: api.post(f"/domains/{ZONE}/verify", role="operator")["domain"].get("verified_now"),
                        300, interval=5, what="TXT record verification")
    assert verified is True
    return ZONE


@pytest.fixture(scope="session", autouse=True)
def _baseline_state():
    """Every session starts from the same state: nginx classical-only, traffic from modern clients."""
    if not BASE_URL:
        yield
        return
    set_traffic_mode("normal")
    set_nginx_groups(CLASSIC_GROUPS)
    yield
    # Best effort: a slow docker exec here must not turn into a failure (or, under a strict xfail,
    # a hidden one) of whichever test happened to run last. The next session resets the state anyway.
    set_traffic_mode("normal")
    try:
        set_nginx_groups(CLASSIC_GROUPS)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not reset nginx to classical groups: {exc}")
