"""The rollout's Prometheus client, against a real HTTP server. The other rollout tests replace it."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from services import pq_rollout


class _Prometheus(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        _Prometheus.seen.append((self.path, self.headers.get("Authorization")))
        body = json.dumps({"status": "success", "data": {"resultType": "vector",
                           "result": [{"metric": {}, "value": [0, "0.004"]}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def prometheus(monkeypatch):
    monkeypatch.setenv("MORROW_CODE_HOSTS_ALLOW_PRIVATE", "1")  # a company install's own Prometheus
    _Prometheus.seen = []
    server = HTTPServer(("127.0.0.1", 0), _Prometheus)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_queries_a_real_prometheus(prometheus):
    result = pq_rollout._prometheus_get(prometheus, 'sum(rate(tls_handshake_errors{pq="hybrid"}[5m]))', "tok")
    assert result["data"]["result"][0]["value"][1] == "0.004"
    path, auth = _Prometheus.seen[0]
    assert path.startswith("/api/v1/query?query=sum%28rate")
    assert auth == "Bearer tok"


def test_unreachable_prometheus_is_a_metrics_error(monkeypatch):
    monkeypatch.setenv("MORROW_CODE_HOSTS_ALLOW_PRIVATE", "1")
    with pytest.raises(pq_rollout.MetricsError):
        pq_rollout._prometheus_get("http://127.0.0.1:9", "up", "")
