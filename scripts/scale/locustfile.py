"""Many signed-in console users at once (Locust). Dev-only: locust is in scripts/scale/requirements-load.txt.

Each virtual user signs in through POST /auth/login with one of the accounts load_users.py made
(round robin, so users are spread over its organizations) and then opens console views: each task
loads every endpoint one view of backend/static/index.html loads, one after another, the way
bench.py lists them. Requests are named "<view> <path>", so the stats group by view.

    locust -f scripts/scale/locustfile.py --headless -u 100 -r 10 -t 5m \
        --host http://127.0.0.1:8000 --csv out/run-100   # MORROW_LOAD_USERS=users.json

Environment:
  MORROW_LOAD_USERS   path of the JSON list load_users.py wrote (required)
  MORROW_LOAD_THINK   "min,max" seconds between views (default 2,6: a person reading a page)
"""
from __future__ import annotations

import itertools
import json
import os
import threading

from locust import HttpUser, between, events

_USERS = json.loads(open(os.environ["MORROW_LOAD_USERS"], encoding="utf-8").read())
_NEXT = itertools.count()
_LOCK = threading.Lock()
_THINK = [float(x) for x in os.environ.get("MORROW_LOAD_THINK", "2,6").split(",")]

# view -> the endpoints it loads (bench.py ENDPOINTS; {scan} is filled from /scans).
VIEWS = {
    "overview": ["/executive-dashboard", "/qday/countdown", "/board-risk/weather", "/telemetry/kpis",
                 "/observatory/dashboard", "/crypto-agility", "/migration-velocity", "/hndl/dashboard",
                 "/board-risk", "/compliance-mapping", "/hndl-canaries"],
    "inventory": ["/assets", "/tags", "/collections", "/repositories", "/baselines",
                  "/governance/certificates", "/blast-radius/graph"],
    "findings": ["/scans?limit=25", "/scans/{scan}/results", "/fix-next", "/heatmap"],
    "cbom": ["/cbom", "/cbom.csv", "/sbom/imports", "/cbom/webhook/ingests"],
    "hndl": ["/hndl/timeline", "/dark-matter/map", "/q-intel/model"],
    "remediation": ["/remediations", "/remediation-feed", "/migration-tasks"],
    "reports": ["/board-risk/leaderboard", "/board-risk/regulatory"],
    "search": ["/search?q=svc00012", "/search?q=rsa"],
}
# How often each view is opened relative to the others.
WEIGHTS = {"overview": 4, "inventory": 3, "findings": 3, "cbom": 1, "hndl": 1, "remediation": 2, "reports": 1,
           "search": 3}


class ConsoleUser(HttpUser):
    wait_time = between(_THINK[0], _THINK[-1])

    def on_start(self):
        with _LOCK:
            account = _USERS[next(_NEXT) % len(_USERS)]
        res = self.client.post("/auth/login", json={"email": account["email"], "password": account["password"]},
                               name="auth /auth/login")
        res.raise_for_status()
        self.client.headers["Authorization"] = "Bearer " + res.json()["access_token"]
        self.scan_id = ""

    def open_view(self, view: str):
        for path in VIEWS[view]:
            if "{scan}" in path:
                if not self.scan_id:
                    continue
                url = path.replace("{scan}", self.scan_id)
            else:
                url = path
            with self.client.get(url, name="%s %s" % (view, path), catch_response=True) as res:
                if res.status_code != 200:
                    res.failure("HTTP %d" % res.status_code)
                elif path.startswith("/scans?"):
                    try:
                        body = res.json()
                        items = body if isinstance(body, list) else (body.get("items") or body.get("scans") or [])
                        self.scan_id = str((items[0] or {}).get("id") or "") if items else ""
                    except Exception:
                        pass


def _make_task(view: str):
    def run(self):
        self.open_view(view)
    run.__name__ = "view_" + view
    return run


ConsoleUser.tasks = {_make_task(v): w for v, w in WEIGHTS.items()}


@events.quitting.add_listener
def _summary(environment, **_):
    """Per-view p95 and error rate, printed at the end (the CSVs have every request)."""
    stats = environment.stats
    groups = {}
    for entry in stats.entries.values():
        view = entry.name.split(" ", 1)[0]
        g = groups.setdefault(view, {"n": 0, "fail": 0, "entries": []})
        g["n"] += entry.num_requests
        g["fail"] += entry.num_failures
        g["entries"].append(entry)
    print("%-12s %8s %8s %8s %8s" % ("view", "requests", "errors%", "p50 ms", "p95 ms"))
    for view, g in sorted(groups.items()):
        merged = None
        for e in g["entries"]:
            if merged is None:
                from locust.stats import StatsEntry
                merged = StatsEntry(stats, view, "")
            merged.extend(e)
        p50 = merged.get_response_time_percentile(0.5) if merged else 0
        p95 = merged.get_response_time_percentile(0.95) if merged else 0
        print("%-12s %8d %8.2f %8.0f %8.0f" % (view, g["n"], 100.0 * g["fail"] / max(1, g["n"]), p50, p95))
