"""Redis-backed rate limiting against a real Redis server.

Skipped unless PQC_TEST_REDIS_URL points at a disposable Redis (use a DB index nothing else needs):

    docker run -d --name pqc-test-redis -p 56379:6379 redis:7-alpine
    PQC_TEST_REDIS_URL=redis://127.0.0.1:56379/1 python -m pytest -q test_redis_integration.py

Covers services/org_rate_limits.py (the per-organization sliding windows): window correctness against the
in-process implementation, one shared counter across separate processes, atomicity under concurrency,
Retry-After, key expiry, and falling back to in-process counters when Redis goes away. Also the fixed-window
per-organization counter in app.py's rate_limit middleware (TTL on every key).
"""

import os
import random
import subprocess
import sys
import threading
import time
import uuid

import pytest

REDIS_URL = os.getenv("PQC_TEST_REDIS_URL", "").strip()
pytestmark = pytest.mark.skipif(not REDIS_URL, reason="set PQC_TEST_REDIS_URL to run against a real Redis")

BACKEND = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def rl(monkeypatch):
    import redis

    from services import org_rate_limits

    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    org_rate_limits.reset()
    # The module's own client uses 1 s socket timeouts; a loaded CI machine can exceed that and the limiter then
    # (correctly) falls back to memory for a few seconds. Pre-seed a client with more headroom for the test.
    org_rate_limits._redis.update(client=redis.Redis.from_url(REDIS_URL, socket_connect_timeout=5, socket_timeout=5),
                                  url=REDIS_URL, script=None, script_client=None)
    client = redis.Redis.from_url(REDIS_URL)
    created = []

    def org():
        name = f"it-{uuid.uuid4().hex[:10]}"
        created.append(name)
        return name

    yield org_rate_limits, client, org
    for name in created:
        client.delete(f"pqc:orglimit:api:{name}", f"pqc:orglimit:scan:{name}")
    org_rate_limits.reset()
    org_rate_limits._clock = time.time
    org_rate_limits._redis.update(client=None, url=None, script=None, script_client=None)


def _at(module, monkeypatch, t):
    monkeypatch.setattr(module, "_clock", lambda: t)


def test_sliding_window_matches_the_in_process_window(rl, monkeypatch):
    module, _, org = rl
    name = org()
    rng = random.Random(7)
    t = 1_700_000_000.0
    for _ in range(400):
        t += rng.choice([0.0, 0.25, 1.0, 3.0, 7.5, 20.0])
        _at(module, monkeypatch, t)
        redis_result = module.hit("api", name, 5, 30.0)
        memory = module._hit_memory("api", name, 5, 30.0, t)
        assert redis_result["backend"] == "redis"
        assert (redis_result["allowed"], redis_result["remaining"]) == memory[:2]
        assert redis_result["retry_after"] == pytest.approx(memory[2], abs=1e-6)


def test_boundary_and_retry_after(rl, monkeypatch):
    module, client, org = rl
    name = org()
    for t in (1000.0, 1010.0, 1020.0):
        _at(module, monkeypatch, t)
        assert module.hit("api", name, 3, 60.0)["allowed"]
    _at(module, monkeypatch, 1030.5)
    denied = module.hit("api", name, 3, 60.0)
    assert denied == {"allowed": False, "remaining": 0, "retry_after": pytest.approx(29.5), "backend": "redis"}
    assert client.zcard(f"pqc:orglimit:api:{name}") == 3  # a rejected request never takes a slot
    _at(module, monkeypatch, 1059.999)
    assert not module.hit("api", name, 3, 60.0)["allowed"]
    _at(module, monkeypatch, 1060.0)  # the 1000.0 entry is exactly one window old: expired
    assert module.hit("api", name, 3, 60.0)["allowed"]
    _at(module, monkeypatch, 1060.0)
    assert module.hit("api", name, 3, 60.0)["retry_after"] == pytest.approx(10.0)


def test_keys_expire_and_do_not_accumulate(rl):
    module, client, org = rl
    names = [org() for _ in range(25)]
    for name in names:
        started = time.monotonic()
        assert module.hit("api", name, 2, 1.0)["backend"] == "redis"
        ttl = client.pttl(f"pqc:orglimit:api:{name}")
        # TTL() rounds down to zero during the final second. A descheduled test
        # may even observe expiry; neither is an unbounded/persistent key (-1).
        assert ttl == -2 or 0 <= ttl <= 2000
        if ttl == -2:
            assert time.monotonic() - started >= 1.0
    time.sleep(2.2)
    assert all(not client.exists(f"pqc:orglimit:api:{name}") for name in names)
    # A busy key stays bounded by the limit, however many requests arrive.
    busy = org()
    for _ in range(200):
        module.hit("api", busy, 7, 60.0)
    assert client.zcard(f"pqc:orglimit:api:{busy}") == 7


def test_concurrent_threads_cannot_share_the_last_slot(rl):
    module, client, org = rl
    name = org()
    results, barrier = [], threading.Barrier(40)

    def worker():
        barrier.wait()
        results.append(module.hit("api", name, 10, 60.0))

    threads = [threading.Thread(target=worker) for _ in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(r["backend"] == "redis" for r in results)
    assert sum(1 for r in results if r["allowed"]) == 10
    assert client.zcard(f"pqc:orglimit:api:{name}") == 10


_WORKER = r"""
import json, os, sys, threading
sys.path.insert(0, os.environ["PQC_BACKEND_DIR"])
from services import org_rate_limits as o
import redis
client = redis.Redis.from_url(os.environ["REDIS_URL"], socket_connect_timeout=10, socket_timeout=10)
client.ping()
# This case tests cross-process atomicity, not the production outage timeout.
o._redis.update(client=client, url=os.environ["REDIS_URL"], script=None, script_client=None)
org, limit, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
start = float(sys.argv[4])
import time
while time.time() < start:
    time.sleep(0.005)
out = []
def go():
    out.append(o.hit("api", org, limit, 300.0))
ts = [threading.Thread(target=go) for _ in range(n)]
[t.start() for t in ts]
[t.join() for t in ts]
print(json.dumps({"allowed": sum(1 for r in out if r["allowed"]), "backends": sorted({r["backend"] for r in out})}))
"""


def test_two_processes_share_one_counter(rl):
    """Two separate interpreters (as two API replicas would be), limit N, 2N requests split evenly: exactly N pass."""
    import json

    _, client, org = rl
    name, limit = org(), 12
    env = {**os.environ, "REDIS_URL": REDIS_URL, "PQC_BACKEND_DIR": BACKEND}
    env.pop("CELERY_BROKER_URL", None)
    start = time.time() + 4.0
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, name, str(limit), str(limit), str(start)],
                              cwd=BACKEND, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for _ in range(2)]
    outputs = []
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=120)
        assert proc.returncode == 0, stderr
        outputs.append(json.loads(stdout.strip().splitlines()[-1]))
    assert all(o["backends"] == ["redis"] for o in outputs)
    assert sum(o["allowed"] for o in outputs) == limit
    assert client.zcard(f"pqc:orglimit:api:{name}") == limit


def test_redis_going_away_falls_back_without_errors(rl, monkeypatch):
    module, client, org = rl
    name = org()
    assert module.hit("api", name, 2, 60.0)["backend"] == "redis"
    # Dropping this process's connections mid-run: redis-py reconnects, the shared counter carries on.
    module._redis["client"].connection_pool.disconnect()
    assert module.hit("api", name, 2, 60.0) == {"allowed": True, "remaining": 0, "retry_after": 0.0, "backend": "redis"}
    # Redis unreachable: the in-process window answers, nothing raises, and only the first call pays the timeout.
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    started = time.monotonic()
    first = module.hit("api", name, 2, 60.0)
    assert first["backend"] == "memory" and first["allowed"]
    results = [module.hit("api", name, 2, 60.0) for _ in range(20)]
    assert time.monotonic() - started < 5.0
    assert all(r["backend"] == "memory" for r in results)
    assert [r["allowed"] for r in results[:2]] == [True, False]
    # Redis back (and the retry backoff over): the shared counter is used again.
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    module._redis["down_until"] = 0.0
    assert module.hit("api", name, 2, 60.0)["backend"] == "redis"


def test_middleware_429_carries_accurate_retry_after(rl, monkeypatch):
    """The HTTP response a limited organization gets: Retry-After is the ceiling of the real wait."""
    import asyncio

    from starlette.requests import Request
    from starlette.responses import PlainTextResponse

    module, _, org = rl
    name = org()
    monkeypatch.setattr(module, "enabled", lambda: True)
    monkeypatch.setattr(module, "overrides_stale", lambda: False)
    monkeypatch.setattr(module, "billing_limits_active", lambda: False)
    monkeypatch.setattr(module, "limits_for", lambda org_id, plan=(None, None): (2, 0))
    monkeypatch.setattr(module.request_identity, "resolve", lambda request, mode: {"authenticated": True, "organization_id": name})

    async def call_next(_request):
        return PlainTextResponse("ok")

    async def run_sync(fn, *args):
        return fn(*args)

    def request():
        return Request({"type": "http", "method": "GET", "path": "/assets", "headers": [], "query_string": b"",
                        "client": ("192.0.2.1", 1), "server": ("testserver", 80), "scheme": "http", "root_path": ""})

    async def send(t):
        _at(module, monkeypatch, t)
        return await module.enforce(request(), call_next, auth_mode="jwt", run_in_threadpool=run_sync)

    assert asyncio.run(send(5000.0)).status_code == 200
    assert asyncio.run(send(5000.4)).status_code == 200
    limited = asyncio.run(send(5017.3))
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "43"  # 5000.0 + 60 - 5017.3 = 42.7 s, rounded up
    assert asyncio.run(send(5060.0)).status_code == 200


def test_app_per_org_counter_is_shared_and_expires(monkeypatch):
    """app.py rate_limit middleware: the Redis fixed-window counter decides, carries a TTL, and a Redis outage
    falls back to the in-process counter without failing the request."""
    import redis
    from fastapi.testclient import TestClient

    import app

    client = redis.Redis.from_url(REDIS_URL)
    org_id = f"it-{uuid.uuid4().hex[:10]}"
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    monkeypatch.setattr(app, "_REDIS_RATE_CLIENT", None)
    monkeypatch.setattr(app, "RATE_LIMIT_MAX_REQUESTS", 3)
    monkeypatch.setattr(app, "_extract_org_id_from_request", lambda request: org_id)
    monkeypatch.setattr(app.limiter, "enabled", False)
    app._REDIS_RATE_DOWN_UNTIL[0] = 0.0
    http = TestClient(app.app)
    try:
        # Not /health: probe and static paths deliberately skip per-request accounting now, so they
        # never reach the per-organization counter this test is about.
        codes = [http.get("/qday/countdown").status_code for _ in range(5)]
        keys = client.keys(f"pqc:rate:{org_id}:*")
        # A window boundary can fall between requests; each window still admits at most 3.
        assert codes.count(429) >= 1 and len(keys) in (1, 2)
        assert all(0 < client.ttl(k) <= app.RATE_LIMIT_WINDOW_SECONDS + 5 for k in keys)
        # The counter is Redis's, not this process's: another replica's requests count against it.
        for k in keys:
            client.set(k, 0, keepttl=True)
        assert http.get("/qday/countdown").status_code != 429
        monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
        monkeypatch.setattr(app, "_REDIS_RATE_CLIENT", None)
        assert http.get("/qday/countdown").status_code != 429
        assert app._REDIS_RATE_DOWN_UNTIL[0] > time.monotonic()
    finally:
        app._REDIS_RATE_DOWN_UNTIL[0] = 0.0
        for k in client.keys(f"pqc:rate:{org_id}:*"):
            client.delete(k)
        http.close()
