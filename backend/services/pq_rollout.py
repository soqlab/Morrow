"""Gradual post-quantum rollout with automatic rollback.

For a load balancer or service mesh with weighted routing, Morrow generates staged configurations
that send 1%, 10%, 50% and then 100% of traffic to a hybrid post-quantum TLS listener or cluster:

  envoy     weighted_clusters on the route, plus the hybrid-PQ upstream cluster
  istio     VirtualService weights over two DestinationRule subsets
  nginx     stream split_clients between the classic and the hybrid-PQ listener
  haproxy   server weights in a TCP backend over the two listeners

A stage advances only when its health gates pass for a minimum soak time: the handshake failure
rate and the HTTP error rate of the post-quantum side, read from the customer's Prometheus, compared
with the classic side (the baseline). If a gate fails Morrow immediately produces the rollback
configuration (and opens it as a pull request when a code host is connected), marks the rollout
rolled back with the reason and the failing metric, and notifies through the organization's alert
webhooks.

Morrow never changes a live system: each stage is a pull request or a configuration the customer
applies. An org admin approves the rollout; in "manual" mode an admin also approves every stage, in
"automatic" mode Morrow opens the next stage's pull request on its own once the gates pass, and a
person still merges it.
"""

from __future__ import annotations

import json
import math
import re
import secrets
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from db_feature_store import feature_conn

PLATFORMS = {
    "envoy":   {"name": "Envoy", "ext": "yaml", "mechanism": "route weighted_clusters"},
    "istio":   {"name": "Istio", "ext": "yaml", "mechanism": "VirtualService weights + DestinationRule subsets"},
    "nginx":   {"name": "nginx", "ext": "conf", "mechanism": "stream split_clients"},
    "haproxy": {"name": "HAProxy", "ext": "cfg", "mechanism": "backend server weights"},
}
DEFAULT_STAGES = [1, 10, 50, 100]
GATES = {
    "handshake_failure_rate": {"label": "TLS handshake failure rate", "default_max_delta": 0.01,
                               "reason": "old clients failed the new handshake"},
    "http_error_rate": {"label": "HTTP error rate", "default_max_delta": 0.005,
                        "reason": "HTTP errors rose behind the post-quantum listener"},
}

_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_GROUP = re.compile(r"^[A-Za-z0-9_]{2,40}$")
_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,250}$")
_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._/-]{0,61}[A-Za-z0-9])?$")


class RolloutError(Exception):
    def __init__(self, status_code: int, detail: Any):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── Spec validation ─────────────────────────────────────────────────────────────────────────────

def _endpoint(value: Any, field: str) -> Tuple[str, int]:
    text = str(value or "").strip()
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit() or not _HOST.match(host) or not 0 < int(port) < 65536:
        raise RolloutError(400, f"{field} must be host:port, like 10.0.0.12:8443 or pq.internal:443.")
    return host, int(port)


def normalize_spec(platform: str, spec: Dict[str, Any], default_groups: Optional[List[str]] = None) -> Dict[str, Any]:
    """Every value that ends up inside a generated configuration is checked against a strict pattern,
    so a field can never smuggle in another directive."""
    platform = str(platform or "").strip().lower()
    if platform not in PLATFORMS:
        raise RolloutError(400, f"Choose one of: {', '.join(PLATFORMS)}.")
    spec = dict(spec or {})
    service = str(spec.get("service") or "").strip().lower()
    if not _NAME.match(service):
        raise RolloutError(400, "service must be a lowercase DNS label (letters, digits, dashes).")
    host = str(spec.get("host") or "").strip().lower()
    if not _HOST.match(host) or "." not in host:
        raise RolloutError(400, "host must be the public hostname clients connect to.")
    groups = [str(g).strip() for g in (spec.get("pq_groups") or default_groups or ["X25519MLKEM768", "X25519"]) if str(g).strip()]
    if not groups or len(groups) > 6 or not all(_GROUP.match(g) for g in groups):
        raise RolloutError(400, "pq_groups must be TLS group names like X25519MLKEM768.")
    out: Dict[str, Any] = {"service": service, "host": host, "pq_groups": groups}
    if platform == "istio":
        namespace = str(spec.get("namespace") or "default").strip().lower()
        if not _NAME.match(namespace):
            raise RolloutError(400, "namespace must be a Kubernetes namespace name.")
        label_key = str(spec.get("subset_label") or "morrow.io/tls-profile").strip()
        if not _LABEL.match(label_key):
            raise RolloutError(400, "subset_label must be a Kubernetes label key.")
        out.update(namespace=namespace, subset_label=label_key)
    else:
        out["classic_upstream"] = "%s:%d" % _endpoint(spec.get("classic_upstream"), "classic_upstream")
        out["pq_upstream"] = "%s:%d" % _endpoint(spec.get("pq_upstream"), "pq_upstream")
        listen = int(spec.get("listen_port") or 443)
        if not 0 < listen < 65536:
            raise RolloutError(400, "listen_port must be a TCP port.")
        out["listen_port"] = listen
    if platform == "envoy":
        for field, default in (("classic_cluster", f"{service}-classic"), ("pq_cluster", f"{service}-pq-hybrid")):
            value = str(spec.get(field) or default).strip()
            if not re.match(r"^[A-Za-z0-9_.-]{1,100}$", value):
                raise RolloutError(400, f"{field} must be an Envoy cluster name.")
            out[field] = value
    return out


def normalize_stages(stages: Any) -> List[int]:
    values = [int(s) for s in (stages or DEFAULT_STAGES)]
    if not values or len(values) > 10 or values != sorted(set(values)) or values[0] < 1 or values[-1] != 100:
        raise RolloutError(400, "stages must be increasing percentages between 1 and 100 that end at 100, like 1, 10, 50, 100.")
    return values


# ── Configuration rendering ─────────────────────────────────────────────────────────────────────

def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-/]*", text) and text.lower() not in ("true", "false", "yes", "no", "null", "on", "off", "y", "n"):
        return text
    return json.dumps(text)


def _yaml(value: Any, indent: int = 0) -> List[str]:
    """A small YAML emitter for dicts, lists and scalars (block style, JSON-quoted strings when needed).
    Kept here so the backend does not need PyYAML at runtime."""
    pad = "  " * indent
    lines: List[str] = []
    if isinstance(value, dict):
        for key, val in value.items():
            k = _yaml_scalar(key)
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{k}:")
                lines.extend(_yaml(val, indent + 1 if isinstance(val, dict) else indent))
            else:
                lines.append(f"{pad}{k}: {_yaml_scalar(val) if not isinstance(val, (dict, list)) else ('{}' if isinstance(val, dict) else '[]')}")
    elif isinstance(value, list):
        for val in value:
            if isinstance(val, dict) and val:
                sub = _yaml(val, indent + 1)
                lines.append(f"{pad}- {sub[0].strip()}")
                lines.extend(sub[1:])
            elif isinstance(val, list) and val:
                lines.append(f"{pad}-")
                lines.extend(_yaml(val, indent + 1))
            else:
                lines.append(f"{pad}- {_yaml_scalar(val)}")
    else:
        lines.append(pad + _yaml_scalar(value))
    return lines


def _header(name: str, platform: str, weight: int, spec: Dict[str, Any], rollback: bool) -> List[str]:
    what = ("ROLLBACK: all traffic back to the classic listener." if rollback
            else f"Stage: {weight}% of new connections to the hybrid post-quantum side ({':'.join(spec['pq_groups'])}).")
    return [f"# Morrow staged post-quantum rollout: {name}", f"# {what}",
            f"# Platform: {PLATFORMS[platform]['name']} ({PLATFORMS[platform]['mechanism']}). Service {spec['service']}, host {spec['host']}.",
            "# Proposed by Morrow for review. Nothing has been applied to a live system."]


def render_config(platform: str, spec: Dict[str, Any], weight: int, name: str = "", rollback: bool = False) -> str:
    """The configuration that sends `weight` percent of traffic to the hybrid post-quantum side."""
    weight = max(0, min(100, int(weight)))
    classic = 100 - weight
    name = re.sub(r"[\r\n]+", " ", str(name or spec["service"]))[:120]
    head = _header(name, platform, weight, spec, rollback)
    if platform == "envoy":
        pq_host, pq_port = spec["pq_upstream"].rsplit(":", 1)
        doc = {
            "route_config": {
                "name": f"{spec['service']}-routes",
                "virtual_hosts": [{
                    "name": spec["service"], "domains": [spec["host"]],
                    "routes": [{"match": {"prefix": "/"}, "route": {"weighted_clusters": {"clusters": [
                        {"name": spec["classic_cluster"], "weight": classic},
                        {"name": spec["pq_cluster"], "weight": weight},
                    ]}}}],
                }],
            },
            "clusters": [{
                "name": spec["pq_cluster"], "type": "STRICT_DNS", "connect_timeout": "5s",
                "load_assignment": {"cluster_name": spec["pq_cluster"], "endpoints": [{"lb_endpoints": [
                    {"endpoint": {"address": {"socket_address": {"address": pq_host, "port_value": int(pq_port)}}}}]}]},
                "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                    "sni": spec["host"],
                    "common_tls_context": {"tls_params": {"tls_minimum_protocol_version": "TLSv1_3",
                                                          "ecdh_curves": list(spec["pq_groups"])}}}},
            }],
        }
        return "\n".join(head + ["# Merge route_config into the listener's HTTP connection manager and add the cluster."] + _yaml(doc)) + "\n"
    if platform == "istio":
        fqdn = f"{spec['service']}.{spec['namespace']}.svc.cluster.local"
        labels = {"app.kubernetes.io/managed-by": "morrow"}
        vs = {"apiVersion": "networking.istio.io/v1beta1", "kind": "VirtualService",
              "metadata": {"name": f"{spec['service']}-pq-rollout", "namespace": spec["namespace"], "labels": labels},
              "spec": {"hosts": [spec["host"], fqdn], "http": [{"route": [
                  {"destination": {"host": fqdn, "subset": "classic"}, "weight": classic},
                  {"destination": {"host": fqdn, "subset": "pq-hybrid"}, "weight": weight}]}]}}
        dr = {"apiVersion": "networking.istio.io/v1beta1", "kind": "DestinationRule",
              "metadata": {"name": f"{spec['service']}-pq-rollout", "namespace": spec["namespace"], "labels": labels},
              "spec": {"host": fqdn, "trafficPolicy": {"tls": {"mode": "ISTIO_MUTUAL"}}, "subsets": [
                  {"name": "classic", "labels": {spec["subset_label"]: "classic"}},
                  {"name": "pq-hybrid", "labels": {spec["subset_label"]: "pq-hybrid"}}]}}
        note = [f"# Workloads labelled {spec['subset_label']}=pq-hybrid must terminate TLS with {':'.join(spec['pq_groups'])}",
                "# (meshConfig.tlsDefaults.ecdhCurves on Istio 1.23+, or the gateway's TLS settings)."]
        return "\n".join(head + note + _yaml(vs) + ["---"] + _yaml(dr)) + "\n"
    svc = re.sub(r"[^a-z0-9]", "_", spec["service"])
    if platform == "nginx":
        split = []
        if 0 < weight < 100:
            split.append(f"    {weight}%    pq_hybrid_{svc};")
        split.append(f"    *       {'pq_hybrid' if weight == 100 else 'classic'}_{svc};")
        lines = head + [
            "# Place inside the top-level stream { } context. Clients are split by address, so each client",
            "# keeps the same side for the whole stage.",
            f'split_clients "${{remote_addr}}" $morrow_tls_backend_{svc} {{', *split, "}",
            "", f"upstream classic_{svc} {{", f"    server {spec['classic_upstream']};", "}",
            "", f"upstream pq_hybrid_{svc} {{", f"    server {spec['pq_upstream']};", "}",
            "", "server {", f"    listen {spec['listen_port']};", f"    proxy_pass $morrow_tls_backend_{svc};", "}",
            "", f"# The hybrid listener at {spec['pq_upstream']} terminates TLS with:",
            f"#     ssl_ecdh_curve {':'.join(spec['pq_groups'])};",
        ]
        return "\n".join(lines) + "\n"
    lines = head + [
        "# TCP pass-through: clients are balanced by source address onto the classic or the hybrid listener.",
        f"frontend fe_{svc}_tls", "    mode tcp", f"    bind :{spec['listen_port']}", f"    default_backend be_{svc}_tls",
        "", f"backend be_{svc}_tls", "    mode tcp", "    balance source",
        f"    server classic {spec['classic_upstream']} weight {classic} check",
        f"    server pq_hybrid {spec['pq_upstream']} weight {weight} check",
        "", f"# The hybrid listener at {spec['pq_upstream']} terminates TLS with:",
        f"#     bind :443 ssl crt /etc/haproxy/certs/{spec['service']}.pem curves {':'.join(spec['pq_groups'])}",
    ]
    return "\n".join(lines) + "\n"


def config_path(platform: str, spec: Dict[str, Any]) -> str:
    return f"morrow/pq-rollout/{platform}-{spec['service']}.{PLATFORMS[platform]['ext']}"


def preview(platform: str, spec: Dict[str, Any], stages: Any = None, name: str = "",
            default_groups: Optional[List[str]] = None) -> Dict[str, Any]:
    clean = normalize_spec(platform, spec, default_groups)
    steps = normalize_stages(stages)
    return {"platform": platform, "spec": clean, "stages": steps, "file_path": config_path(platform, clean),
            "configs": [{"weight": w, "config": render_config(platform, clean, w, name)} for w in steps],
            "rollback": render_config(platform, clean, 0, name, rollback=True)}


# ── Metrics (customer Prometheus) ───────────────────────────────────────────────────────────────

class MetricsError(Exception):
    pass


def normalize_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    from services import code_hosts, gateway_network

    metrics = dict(metrics or {})
    url = str(metrics.get("prometheus_url") or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise RolloutError(400, "prometheus_url must be the https:// address of your Prometheus, without credentials or a query.")
    if not code_hosts.private_servers_allowed():
        if parts.port not in (None, 443):
            raise RolloutError(400, "Only HTTPS on the standard port is supported for the metrics source.")
        try:
            gateway_network.hostname(parts.hostname)
        except gateway_network.CheckError as exc:
            raise RolloutError(400, f"prometheus_url: {exc}.") from None
    path = parts.path.rstrip("/")
    if path and not _PATH.match(path):
        raise RolloutError(400, "prometheus_url has an invalid path.")
    port = f":{parts.port}" if parts.port not in (None, 443) else ""
    queries: Dict[str, Any] = {}
    for gate in GATES:
        q = (metrics.get("queries") or {}).get(gate)
        if isinstance(q, dict):
            pq, base = str(q.get("pq") or "").strip(), str(q.get("baseline") or "").strip()
            if not pq or not base or len(pq) > 2000 or len(base) > 2000:
                raise RolloutError(400, f"queries.{gate} needs both a pq and a baseline PromQL query.")
            queries[gate] = {"pq": pq, "baseline": base}
        else:
            text = str(q or "").strip()
            if "$variant" not in text or len(text) > 2000:
                raise RolloutError(400, f"queries.{gate} must be PromQL containing $variant (replaced by the classic or "
                                        "post-quantum label value), or an object with pq and baseline queries.")
            queries[gate] = text
    thresholds = {}
    for gate, info in GATES.items():
        value = float((metrics.get("max_delta") or {}).get(gate, info["default_max_delta"]))
        if not 0 <= value <= 1:
            raise RolloutError(400, f"max_delta.{gate} must be a rate between 0 and 1.")
        thresholds[gate] = value
    labels = {"pq": str(metrics.get("pq_label") or "pq-hybrid"), "baseline": str(metrics.get("baseline_label") or "classic")}
    if not all(re.match(r"^[A-Za-z0-9_.:-]{1,80}$", v) for v in labels.values()):
        raise RolloutError(400, "pq_label and baseline_label must be plain label values.")
    return {"prometheus_url": f"https://{parts.hostname.lower()}{port}{path}", "queries": queries,
            "max_delta": thresholds, "labels": labels}


def _prometheus_get(base_url: str, query: str, token: str) -> Dict[str, Any]:
    """GET /api/v1/query against the customer's Prometheus. Public servers go through the DNS-pinned
    SSRF guard (services/gateway_network); a company-network install that allows private servers
    (MORROW_CODE_HOSTS_ALLOW_PRIVATE) connects directly."""
    from services import code_hosts, gateway_network

    parts = urllib.parse.urlsplit(base_url)
    suffix = "/api/v1/query?" + urllib.parse.urlencode({"query": query})
    path = parts.path.rstrip("/") + suffix
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if code_hosts.private_servers_allowed():
        import urllib.request

        req = urllib.request.Request(base_url.rstrip("/") + suffix, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, body = resp.status, resp.read(262144)
        except Exception as exc:
            raise MetricsError(f"Prometheus could not be reached ({exc.__class__.__name__}).") from None
    else:
        try:
            got = gateway_network.request(parts.hostname or "", path, headers=headers, limit=262144)
        except gateway_network.CheckError as exc:
            raise MetricsError(f"Prometheus could not be reached: {exc}.") from None
        status, body = got["status"], got["body"]
    if status != 200:
        raise MetricsError(f"Prometheus answered {status}.")
    try:
        return json.loads(body)
    except ValueError:
        raise MetricsError("Prometheus returned something that is not JSON.") from None


def _value(payload: Dict[str, Any]) -> Optional[float]:
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise MetricsError(str((payload or {}).get("error") or "Prometheus query failed.")[:200])
    data = payload.get("data") or {}
    result = data.get("result")
    values: List[float] = []
    if data.get("resultType") == "scalar" and isinstance(result, list) and len(result) == 2:
        values.append(float(result[1]))
    elif isinstance(result, list):
        for series in result:
            try:
                values.append(float((series.get("value") or [0, "nan"])[1]))
            except (TypeError, ValueError):
                continue
    values = [v for v in values if not math.isnan(v) and not math.isinf(v)]
    return sum(values) if values else None


def evaluate_gates(metrics: Dict[str, Any], token: str, fetch: Optional[Callable[[str, str, str], Dict[str, Any]]] = None) -> Dict[str, Any]:
    """{"result": "pass" | "fail" | "inconclusive", "gates": [...]} comparing the post-quantum side with the classic baseline."""
    fetch = fetch or _prometheus_get
    gates: List[Dict[str, Any]] = []
    for gate, info in GATES.items():
        q = metrics["queries"][gate]
        if isinstance(q, dict):
            pq_query, base_query = q["pq"], q["baseline"]
        else:
            pq_query = q.replace("$variant", metrics["labels"]["pq"])
            base_query = q.replace("$variant", metrics["labels"]["baseline"])
        entry: Dict[str, Any] = {"gate": gate, "label": info["label"], "max_delta": metrics["max_delta"][gate]}
        try:
            pq_value = _value(fetch(metrics["prometheus_url"], pq_query, token))
            base_value = _value(fetch(metrics["prometheus_url"], base_query, token))
        except MetricsError as exc:
            entry.update(result="inconclusive", detail=str(exc))
            gates.append(entry)
            continue
        entry.update(pq=pq_value, baseline=base_value)
        if pq_value is None or base_value is None:
            entry.update(result="inconclusive", detail="No data yet for one side.")
        else:
            delta = pq_value - base_value
            entry["delta"] = round(delta, 6)
            entry["result"] = "fail" if delta > metrics["max_delta"][gate] else "pass"
        gates.append(entry)
    results = {g["result"] for g in gates}
    overall = "fail" if "fail" in results else "inconclusive" if "inconclusive" in results else "pass"
    return {"result": overall, "gates": gates, "checked_at": _iso(_now_dt())}


# ── Storage ─────────────────────────────────────────────────────────────────────────────────────

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS pq_rollouts (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL, platform TEXT NOT NULL,
        status TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'manual', dry_run INTEGER NOT NULL DEFAULT 1,
        spec_json TEXT NOT NULL, stages_json TEXT NOT NULL, stage_index INTEGER NOT NULL DEFAULT -1,
        stage_state TEXT NOT NULL DEFAULT '', soak_minutes INTEGER NOT NULL DEFAULT 30,
        metrics_json TEXT NOT NULL, token_enc TEXT NOT NULL DEFAULT '', baseline_json TEXT NOT NULL DEFAULT '{}',
        last_gate_json TEXT NOT NULL DEFAULT '{}', repository TEXT NOT NULL DEFAULT '', file_path TEXT NOT NULL DEFAULT '',
        connection_id TEXT NOT NULL DEFAULT '', base_branch TEXT NOT NULL DEFAULT '', pr_url TEXT NOT NULL DEFAULT '',
        pr_number TEXT NOT NULL DEFAULT '', rollback_reason TEXT NOT NULL DEFAULT '', rollback_metric TEXT NOT NULL DEFAULT '',
        rollback_pr_url TEXT NOT NULL DEFAULT '', events_json TEXT NOT NULL DEFAULT '[]',
        approved_by TEXT NOT NULL DEFAULT '', approved_at TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '',
        soak_started_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_pq_rollouts_org ON pq_rollouts(org_id, created_at)",
)
_lock = threading.Lock()
_ready_for = ""


def _init() -> None:
    global _ready_for
    from db_feature_store import dialect, _sqlite_path

    marker = f"{dialect()}:{_sqlite_path() if dialect() == 'sqlite' else ''}"
    if _ready_for == marker:
        return
    with _lock:
        with feature_conn() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.commit()
        _ready_for = marker


_JSON_COLS = {"spec_json": "spec", "stages_json": "stages", "metrics_json": "metrics", "baseline_json": "baseline",
              "last_gate_json": "last_gate", "events_json": "events"}


def _row(row: Any) -> Dict[str, Any]:
    d = dict(row)
    for col, key in _JSON_COLS.items():
        d[key] = json.loads(d.pop(col, "") or ("[]" if key in ("stages", "events") else "{}"))
    d["dry_run"] = bool(int(d.get("dry_run") or 0))
    d["has_token"] = bool(d.pop("token_enc", ""))
    stages = d["stages"]
    idx = int(d["stage_index"]) if d.get("stage_index") is not None else -1
    d["stage_index"] = idx
    d["current_weight"] = stages[idx] if 0 <= idx < len(stages) else 0
    d["next_weight"] = stages[idx + 1] if idx + 1 < len(stages) else None
    return d


def _load(conn, org_id: str, rollout_id: str) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM pq_rollouts WHERE org_id = ? AND id = ?", (org_id, rollout_id)).fetchone()
    if not row:
        raise RolloutError(404, "Rollout not found.")
    return _row(row)


def _token(org_id: str, rollout_id: str) -> str:
    from vault_crypto import decrypt_secret

    with feature_conn() as conn:
        row = conn.execute("SELECT token_enc FROM pq_rollouts WHERE org_id = ? AND id = ?", (org_id, rollout_id)).fetchone()
    sealed = str((row or {"token_enc": ""})["token_enc"] or "")
    return decrypt_secret(sealed) if sealed else ""


def _update(org_id: str, rollout: Dict[str, Any], actor: str, action: str, details: Dict[str, Any], **fields: Any) -> Dict[str, Any]:
    events = list(rollout.get("events") or [])[-199:]
    events.append({"at": _iso(_now_dt()), "actor": actor, "action": action, **details})
    fields["events_json"] = json.dumps(events)
    fields["updated_at"] = _iso(_now_dt())
    for key in list(fields):
        if key in ("baseline", "last_gate"):
            fields[f"{key}_json"] = json.dumps(fields.pop(key))
    cols = ", ".join(f"{k} = ?" for k in fields)
    with feature_conn() as conn:
        conn.execute(f"UPDATE pq_rollouts SET {cols} WHERE org_id = ? AND id = ?", (*fields.values(), org_id, rollout["id"]))
        conn.commit()
        return _load(conn, org_id, rollout["id"])


def _journal(actor: Dict[str, str], action: str, rollout_id: str, details: Dict[str, Any]) -> None:
    from db import append_audit_log

    append_audit_log(str(actor.get("actor_id") or ""), str(actor.get("actor_role") or ""), action, "pq_rollout",
                     rollout_id, decision="allow", details=details)


def _notify(event_type: str, payload: Dict[str, Any]) -> None:
    try:
        from events import emit_platform_event

        emit_platform_event(event_type, payload)
    except Exception:
        pass


# ── Lifecycle ───────────────────────────────────────────────────────────────────────────────────

def create_rollout(org_id: str, actor: Dict[str, str], *, name: str, platform: str, spec: Dict[str, Any], metrics: Dict[str, Any],
                   token: str = "", stages: Any = None, soak_minutes: int = 30, mode: str = "manual", dry_run: bool = True,
                   repository: str = "", connection_id: str = "", base_branch: str = "",
                   default_groups: Optional[List[str]] = None) -> Dict[str, Any]:
    from vault_crypto import encrypt_secret

    _init()
    mode = str(mode or "manual").strip().lower()
    if mode not in ("manual", "automatic"):
        raise RolloutError(400, "mode must be manual or automatic.")
    plan = preview(platform, spec, stages, name, default_groups)
    clean_metrics = normalize_metrics(metrics)
    soak = int(soak_minutes if soak_minutes is not None else 30)
    if not 1 <= soak <= 10080:
        raise RolloutError(400, "soak_minutes must be between 1 and 10080 (a week).")
    secret = str(token or "").strip()
    if secret and (len(secret) > 4000 or any(c.isspace() for c in secret)):
        raise RolloutError(400, "Paste the metrics token exactly as issued, without spaces.")
    rollout_id = "pqr_" + secrets.token_hex(8)
    now = _iso(_now_dt())
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO pq_rollouts (id, org_id, name, platform, status, mode, dry_run, spec_json, stages_json, soak_minutes, "
            "metrics_json, token_enc, repository, file_path, connection_id, base_branch, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (rollout_id, org_id, re.sub(r"\s+", " ", str(name or plan["spec"]["service"]))[:120], plan["platform"], mode,
             1 if dry_run else 0, json.dumps(plan["spec"]), json.dumps(plan["stages"]), soak, json.dumps(clean_metrics),
             encrypt_secret(secret) if secret else "", str(repository or "")[:200], plan["file_path"],
             str(connection_id or "")[:64], str(base_branch or "")[:200], str(actor.get("actor_id") or ""), now, now))
        conn.commit()
        rollout = _load(conn, org_id, rollout_id)
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "created",
                      {"platform": plan["platform"], "stages": plan["stages"], "mode": mode, "dry_run": bool(dry_run)})
    _journal(actor, "pq_rollout.created", rollout_id, {"platform": plan["platform"], "service": plan["spec"]["service"],
                                                       "stages": plan["stages"], "mode": mode, "dry_run": bool(dry_run)})
    return rollout


def get_rollout(org_id: str, rollout_id: str, with_configs: bool = False) -> Dict[str, Any]:
    _init()
    with feature_conn() as conn:
        rollout = _load(conn, org_id, rollout_id)
    if with_configs:
        rollout["configs"] = [{"weight": w, "config": render_config(rollout["platform"], rollout["spec"], w, rollout["name"])}
                              for w in rollout["stages"]]
        rollout["rollback_config"] = render_config(rollout["platform"], rollout["spec"], 0, rollout["name"], rollback=True)
    return rollout


def list_rollouts(org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute("SELECT * FROM pq_rollouts WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
                            (org_id, max(1, min(int(limit or 100), 500)))).fetchall()
    out = []
    for r in rows:
        d = _row(r)
        d.pop("events", None)
        out.append(d)
    return out


def summary(org_id: str) -> Dict[str, Any]:
    """'40 migrated, 2 rolled back: old clients failed the new handshake'."""
    items = list_rollouts(org_id, limit=500)
    counts: Dict[str, int] = {}
    reasons: Dict[str, int] = {}
    for r in items:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        if r["status"] == "rolled_back" and r["rollback_reason"]:
            reasons[r["rollback_reason"]] = reasons.get(r["rollback_reason"], 0) + 1
    migrated, rolled = counts.get("completed", 0), counts.get("rolled_back", 0)
    in_flight = sum(counts.get(s, 0) for s in ("approved", "in_progress"))
    text = f"{migrated} migrated, {rolled} rolled back"
    if reasons:
        text += ": " + "; ".join(f"{reason}" + (f" ({n})" if n > 1 else "")
                                 for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]))
    if in_flight:
        text += f". {in_flight} in progress"
    return {"text": text, "migrated": migrated, "rolled_back": rolled, "in_progress": in_flight, "by_status": counts,
            "rollback_reasons": reasons, "total": len(items)}


def _require(rollout: Dict[str, Any], *statuses: str) -> None:
    if rollout["status"] not in statuses:
        raise RolloutError(409, f"The rollout is {rollout['status']}; this step needs it to be {' or '.join(statuses)}.")


def approve(org_id: str, rollout_id: str, actor: Dict[str, str], fetch=None) -> Dict[str, Any]:
    """An admin approves the plan. The baseline (classic-side rates) is recorded for the record."""
    rollout = get_rollout(org_id, rollout_id)
    _require(rollout, "draft")
    baseline: Dict[str, Any] = {}
    try:
        check = evaluate_gates(rollout["metrics"], _token(org_id, rollout_id), fetch)
        baseline = {g["gate"]: g.get("baseline") for g in check["gates"]}
        baseline["checked_at"] = check["checked_at"]
    except Exception as exc:  # a baseline that cannot be read now is read again at every gate check
        baseline = {"error": str(exc)[:200]}
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "approved", {"mode": rollout["mode"]},
                      status="approved", approved_by=str(actor.get("actor_id") or ""), approved_at=_iso(_now_dt()),
                      baseline=baseline)
    _journal(actor, "pq_rollout.approved", rollout_id, {"mode": rollout["mode"], "dry_run": rollout["dry_run"], "baseline": baseline})
    return rollout


def _pr_body(rollout: Dict[str, Any], weight: int, rollback: bool, reason: str = "") -> str:
    if rollback:
        return (f"**Rollback** of the post-quantum rollout **{rollout['name']}**: all traffic goes back to the classic listener.\n\n"
                f"Reason: {reason}\n\nMerge this promptly. Nothing has been applied to a live system by Morrow.")
    stages = ", ".join(f"{w}%" for w in rollout["stages"])
    return (f"Stage **{weight}%** of the post-quantum rollout **{rollout['name']}** ({PLATFORMS[rollout['platform']]['name']}, "
            f"service `{rollout['spec']['service']}`). Stages: {stages}.\n\n"
            f"After this merges Morrow watches the handshake failure rate and the HTTP error rate of the hybrid side against "
            f"the classic side for {rollout['soak_minutes']} minutes. If either rises past its gate Morrow proposes the rollback "
            "immediately.\n\nNothing has been applied to a live system. Review, test, and merge when ready.")


def _open(org_id: str, rollout: Dict[str, Any], weight: int, rollback: bool, reason: str, open_request) -> Dict[str, Any]:
    """Open the stage (or rollback) change, or in dry-run return it without opening anything."""
    from services import code_hosts

    content = render_config(rollout["platform"], rollout["spec"], weight, rollout["name"], rollback=rollback)
    title = (f"Roll back post-quantum rollout: {rollout['name']}" if rollback
             else f"Post-quantum rollout {rollout['name']}: {weight}% to hybrid TLS")[:200]
    out = {"weight": weight, "file_path": rollout["file_path"], "config": content, "title": title}
    if rollout["dry_run"] or not rollout["repository"]:
        out["outcome"] = "dry_run" if rollout["dry_run"] else "apply_manually"
        return out
    try:
        opened = (open_request or code_hosts.open_change_request)(
            org_id, rollout["repository"], {rollout["file_path"]: content}, title, _pr_body(rollout, weight, rollback, reason),
            base_branch=rollout["base_branch"], connection_id=rollout["connection_id"])
    except code_hosts.CodeHostError as exc:
        out.update(outcome="failed", error=str(exc.detail)[:300])
        return out
    out.update(outcome="pr_open", pr_url=str(opened.get("url") or ""), pr_number=str(opened.get("number") or ""),
               connection_id=str(opened.get("connection_id") or rollout["connection_id"] or ""))
    return out


def advance(org_id: str, rollout_id: str, actor: Dict[str, str], open_request=None, automatic: bool = False) -> Dict[str, Any]:
    """Propose the next stage. An admin calls this (or Morrow does, in automatic mode, after the gates pass)."""
    rollout = get_rollout(org_id, rollout_id)
    if automatic:
        _require(rollout, "in_progress")
    else:
        _require(rollout, "approved", "in_progress")
        if rollout["status"] == "in_progress" and rollout["stage_state"] != "awaiting_approval":
            raise RolloutError(409, f"The current stage is {rollout['stage_state'] or 'not ready'}; it advances once its gates pass.")
    idx = rollout["stage_index"] + 1
    if idx >= len(rollout["stages"]):
        raise RolloutError(409, "Every stage has been proposed.")
    weight = rollout["stages"][idx]
    opened = _open(org_id, rollout, weight, False, "", open_request)
    if opened["outcome"] == "failed":
        _journal(actor, "pq_rollout.stage_open_failed", rollout_id, {"weight": weight, "error": opened["error"]})
        raise RolloutError(502, opened["error"])
    stage_state = "pending_merge" if opened["outcome"] == "pr_open" else "awaiting_apply"
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "stage_proposed",
                      {"weight": weight, "outcome": opened["outcome"], "pr_url": opened.get("pr_url", ""), "automatic": automatic},
                      status="in_progress", stage_index=idx, stage_state=stage_state, soak_started_at="",
                      pr_url=opened.get("pr_url", ""), pr_number=opened.get("pr_number", ""),
                      connection_id=opened.get("connection_id", rollout["connection_id"]))
    _journal(actor, "pq_rollout.stage_proposed", rollout_id, {"weight": weight, "outcome": opened["outcome"],
                                                              "pr_url": opened.get("pr_url", ""), "automatic": automatic})
    rollout["proposed"] = opened
    return rollout


def mark_applied(org_id: str, rollout_id: str, actor: Dict[str, str]) -> Dict[str, Any]:
    """An admin confirms the stage's configuration is live (merged and deployed, or applied by hand). The soak starts."""
    rollout = get_rollout(org_id, rollout_id)
    _require(rollout, "in_progress")
    if rollout["stage_state"] not in ("pending_merge", "awaiting_apply"):
        raise RolloutError(409, "The current stage is already live.")
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "stage_live", {"weight": rollout["current_weight"]},
                      stage_state="soaking", soak_started_at=_iso(_now_dt()))
    _journal(actor, "pq_rollout.stage_live", rollout_id, {"weight": rollout["current_weight"], "confirmed_by": "admin"})
    return rollout


def rollback(org_id: str, rollout_id: str, actor: Dict[str, str], *, reason: str, metric: str = "",
             open_request=None, gate: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rollout = get_rollout(org_id, rollout_id)
    _require(rollout, "approved", "in_progress")
    opened = _open(org_id, rollout, 0, True, reason, open_request)
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "rolled_back",
                      {"reason": reason, "metric": metric, "outcome": opened["outcome"], "pr_url": opened.get("pr_url", "")},
                      status="rolled_back", stage_state="rolled_back", rollback_reason=str(reason)[:300],
                      rollback_metric=str(metric)[:300], rollback_pr_url=opened.get("pr_url", ""),
                      **({"last_gate": gate} if gate else {}))
    _journal(actor, "pq_rollout.rolled_back", rollout_id, {"reason": reason, "metric": metric, "outcome": opened["outcome"],
                                                           "pr_url": opened.get("pr_url", ""), "weight_at_failure": rollout["current_weight"]})
    _notify("pq_rollout.rolled_back", {"rollout_id": rollout_id, "name": rollout["name"], "platform": rollout["platform"],
                                       "reason": reason, "metric": metric, "weight_at_failure": rollout["current_weight"],
                                       "rollback_pr_url": opened.get("pr_url", ""), "severity": "high"})
    rollout["rollback"] = opened
    return rollout


def cancel(org_id: str, rollout_id: str, actor: Dict[str, str]) -> Dict[str, Any]:
    rollout = get_rollout(org_id, rollout_id)
    _require(rollout, "draft", "approved")
    rollout = _update(org_id, rollout, str(actor.get("actor_id") or ""), "cancelled", {}, status="cancelled")
    _journal(actor, "pq_rollout.cancelled", rollout_id, {})
    return rollout


def evaluate(org_id: str, rollout_id: str, actor: Dict[str, str], *, fetch=None, request_state=None,
             open_request=None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """One tick: notice a merged stage, check the gates, roll back on failure, advance after the soak."""
    from services import code_hosts

    now = now or _now_dt()
    rollout = get_rollout(org_id, rollout_id)
    _require(rollout, "in_progress")
    actor_id = str(actor.get("actor_id") or "")
    if rollout["stage_state"] == "pending_merge" and rollout["pr_number"]:
        try:
            st = (request_state or code_hosts.change_request_state)(org_id, rollout["repository"], rollout["pr_number"],
                                                                     connection_id=rollout["connection_id"])
        except code_hosts.CodeHostError as exc:
            rollout["tick"] = {"result": "waiting", "detail": str(exc.detail)[:200]}
            return rollout
        if st.get("state") == "merged":
            rollout = _update(org_id, rollout, actor_id, "stage_live", {"weight": rollout["current_weight"], "pr_url": rollout["pr_url"]},
                              stage_state="soaking", soak_started_at=_iso(now))
            _journal(actor, "pq_rollout.stage_live", rollout_id, {"weight": rollout["current_weight"], "confirmed_by": "merge"})
        elif st.get("state") == "closed":
            # Closed without merging: the stage never went live. Step back so an admin can propose it again.
            first = rollout["stage_index"] <= 0
            rollout = _update(org_id, rollout, actor_id, "stage_pr_closed", {"weight": rollout["current_weight"]},
                              status="approved" if first else "in_progress", stage_state="" if first else "awaiting_approval",
                              stage_index=rollout["stage_index"] - 1, pr_url="", pr_number="")
            _journal(actor, "pq_rollout.stage_pr_closed", rollout_id, {"weight": rollout["next_weight"]})
            rollout["tick"] = {"result": "pr_closed"}
            return rollout
        else:
            rollout["tick"] = {"result": "waiting", "detail": "The stage's pull request is not merged yet."}
            return rollout
    if rollout["stage_state"] != "soaking":
        rollout["tick"] = {"result": "waiting", "detail": f"Stage is {rollout['stage_state']}."}
        return rollout
    gate = evaluate_gates(rollout["metrics"], _token(org_id, rollout_id), fetch)
    if gate["result"] == "fail":
        failing = [g for g in gate["gates"] if g["result"] == "fail"]
        reason = "; ".join(GATES[g["gate"]]["reason"] for g in failing)
        metric = "; ".join(f"{g['label']} {g['pq']:.4f} on the post-quantum side vs {g['baseline']:.4f} baseline "
                           f"(allowed +{g['max_delta']:.4f})" for g in failing)
        rollout = rollback(org_id, rollout_id, actor, reason=reason, metric=metric, open_request=open_request, gate=gate)
        rollout["tick"] = {"result": "rolled_back", "gate": gate}
        return rollout
    started = _parse(rollout["soak_started_at"]) or now
    soaked = now - started >= timedelta(minutes=int(rollout["soak_minutes"]))
    if gate["result"] == "inconclusive" or not soaked:
        rollout = _update(org_id, rollout, actor_id, "gate_checked", {"result": gate["result"], "soaked": soaked}, last_gate=gate)
        rollout["tick"] = {"result": "soaking", "gate": gate,
                           "detail": "No data yet; the stage keeps soaking." if gate["result"] == "inconclusive" else "Gates pass; soak continues."}
        return rollout
    _journal(actor, "pq_rollout.stage_passed", rollout_id, {"weight": rollout["current_weight"], "gate": gate})
    if rollout["stage_index"] + 1 >= len(rollout["stages"]):
        rollout = _update(org_id, rollout, actor_id, "completed", {"weight": rollout["current_weight"]},
                          status="completed", stage_state="completed", last_gate=gate)
        _journal(actor, "pq_rollout.completed", rollout_id, {})
        _notify("pq_rollout.completed", {"rollout_id": rollout_id, "name": rollout["name"], "platform": rollout["platform"]})
        rollout["tick"] = {"result": "completed", "gate": gate}
        return rollout
    rollout = _update(org_id, rollout, actor_id, "stage_passed", {"weight": rollout["current_weight"]},
                      stage_state="awaiting_approval", last_gate=gate)
    if rollout["mode"] == "automatic":
        rollout = advance(org_id, rollout_id, {"actor_id": "morrow:automatic", "actor_role": "system"}, open_request=open_request,
                          automatic=True)
        rollout["tick"] = {"result": "advanced", "gate": gate}
        return rollout
    rollout["tick"] = {"result": "awaiting_approval", "gate": gate}
    return rollout
