from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_HOST_PORT_RE = re.compile(r"\b([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::(\d{1,5}))?\b")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_host(host: str) -> str:
    host = str(host or "").strip().lower()
    if "://" in host:
        parsed = urlparse(host)
        host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    host = host.strip(". ")
    if not host or not _HOST_RE.match(host):
        return ""
    return host


def normalize_runtime_record(record: Dict[str, Any]) -> Dict[str, Any]:
    url = str(record.get("url") or record.get("request_url") or "").strip()
    parsed = urlparse(url) if url else None
    host = _clean_host(record.get("host") or record.get("hostname") or record.get("server_name") or (parsed.hostname if parsed else ""))
    if not host:
        return {"ok": False, "error": "missing_or_invalid_host", "raw": record}

    try:
        port = int(record.get("port") or (parsed.port if parsed else 0) or 443)
    except Exception:
        port = 443
    if port <= 0 or port > 65535:
        port = 443

    protocol = str(record.get("protocol") or record.get("scheme") or (parsed.scheme if parsed else "https") or "https").strip().lower()
    if protocol not in {"http", "https", "grpc", "tcp", "tls"}:
        protocol = "https"
    path = str(record.get("path") or (parsed.path if parsed else "") or "").strip() or "/"
    try:
        count = int(record.get("count") or record.get("observed_count") or 1)
    except Exception:
        count = 1
    count = max(1, count)
    timestamp = str(record.get("timestamp") or record.get("observed_at") or record.get("last_seen") or _now_iso()).strip()

    out = {
        "ok": True,
        "source": str(record.get("source") or "").strip().lower(),
        "provider": str(record.get("provider") or "").strip().lower(),
        "asset_key": f"{host}:{port}",
        "host": host,
        "port": port,
        "protocol": protocol,
        "method": str(record.get("method") or "").strip().upper(),
        "path": path[:512],
        "server_name": str(record.get("server_name") or host).strip().lower(),
        "tls_version": str(record.get("tls_version") or record.get("ssl_protocol") or "").strip(),
        "cipher": str(record.get("cipher") or record.get("ssl_cipher") or "").strip(),
        "status_code": int(record.get("status_code") or record.get("status") or 0) if str(record.get("status_code") or record.get("status") or "0").isdigit() else 0,
        "observed_count": count,
        "observed_at": timestamp,
        "metadata": record.get("metadata") if isinstance(record.get("metadata"), dict) else {},
        "raw": record,
    }
    return out


def _record_from_json_log(obj: Dict[str, Any], source: str, provider: str, log_format: str) -> Dict[str, Any]:
    cf_host = obj.get("ClientRequestHost") or obj.get("EdgeRequestHost") or obj.get("host")
    cf_uri = obj.get("ClientRequestURI") or obj.get("path") or obj.get("request_path")
    envoy_authority = obj.get("authority") or obj.get(":authority") or obj.get("request_host")
    envoy_path = obj.get("path") or obj.get(":path")
    alb_host = obj.get("host") or obj.get("domain_name") or obj.get("hostname")
    url = obj.get("url") or obj.get("request_url") or obj.get("ClientRequestURL") or ""
    host = cf_host or envoy_authority or alb_host or obj.get("server_name") or ""
    path = cf_uri or envoy_path or obj.get("uri") or obj.get("request") or ""
    if not url and host and path:
        scheme = "https" if str(obj.get("ssl_protocol") or obj.get("tls_version") or "").strip() else "https"
        url = f"{scheme}://{host}{path if str(path).startswith('/') else '/' + str(path)}"
    return {
        "source": source,
        "provider": provider,
        "url": url,
        "host": host,
        "port": obj.get("port") or obj.get("server_port") or obj.get("target_port") or 443,
        "protocol": obj.get("scheme") or obj.get("protocol") or obj.get("type") or "https",
        "method": obj.get("ClientRequestMethod") or obj.get("method") or obj.get("request_method") or "",
        "path": path,
        "server_name": obj.get("server_name") or host,
        "tls_version": obj.get("ClientSSLProtocol") or obj.get("tls_version") or obj.get("ssl_protocol") or obj.get("tls.protocol") or "",
        "cipher": obj.get("ClientSSLCipher") or obj.get("cipher") or obj.get("ssl_cipher") or obj.get("tls.cipher") or "",
        "status_code": obj.get("EdgeResponseStatus") or obj.get("status") or obj.get("status_code") or obj.get("response_code") or 0,
        "count": obj.get("count") or obj.get("observed_count") or 1,
        "timestamp": obj.get("timestamp") or obj.get("datetime") or obj.get("StartTime") or obj.get("time") or "",
        "metadata": {"log_format": log_format, "parsed_from": "json_log"},
    }


def parse_runtime_log_line(line: str, source: str = "runtime-log", provider: str = "unknown", log_format: str = "auto") -> Dict[str, Any]:
    raw = str(line or "").strip()
    clean_source = str(source or "runtime-log").strip().lower() or "runtime-log"
    clean_provider = str(provider or "unknown").strip().lower() or "unknown"
    clean_format = str(log_format or "auto").strip().lower() or "auto"
    if not raw:
        return {"ok": False, "error": "empty_log_line", "raw": {"line": line}}
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return normalize_runtime_record(_record_from_json_log(obj, clean_source, clean_provider, clean_format))
    except Exception:
        pass

    url_match = _URL_RE.search(raw)
    url = url_match.group(0) if url_match else ""
    host = ""
    port = 443
    if not url:
        hp = _HOST_PORT_RE.search(raw)
        if hp:
            host = hp.group(1)
            if hp.group(2):
                try:
                    port = int(hp.group(2))
                except Exception:
                    port = 443
    method_match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", raw, flags=re.I)
    tls_match = re.search(r"\b(TLSv?1\.[0-3])\b", raw, flags=re.I)
    status_match = re.search(r"\b([1-5]\d\d)\b", raw)
    record = {
        "source": clean_source,
        "provider": clean_provider,
        "url": url,
        "host": host,
        "port": port,
        "protocol": "https",
        "method": method_match.group(1).upper() if method_match else "",
        "tls_version": tls_match.group(1) if tls_match else "",
        "status_code": int(status_match.group(1)) if status_match else 0,
        "count": 1,
        "metadata": {"log_format": clean_format, "parsed_from": "text_log", "raw_line_sample": raw[:512]},
    }
    return normalize_runtime_record(record)


def parse_runtime_log_lines(lines: List[str], source: str = "runtime-log", provider: str = "unknown", log_format: str = "auto") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    parsed = [parse_runtime_log_line(line, source=source, provider=provider, log_format=log_format) for line in lines or []]
    valid = [item for item in parsed if item.get("ok")]
    invalid = [item for item in parsed if not item.get("ok")]
    return valid, invalid


def summarize_runtime_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_asset: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not rec.get("ok"):
            continue
        asset = rec["asset_key"]
        item = by_asset.setdefault(
            asset,
            {
                "asset_key": asset,
                "host": rec.get("host") or "",
                "port": int(rec.get("port") or 0),
                "sources": set(),
                "providers": set(),
                "protocols": set(),
                "tls_versions": set(),
                "paths_sample": [],
                "observed_count": 0,
                "first_seen": rec.get("observed_at") or "",
                "last_seen": rec.get("observed_at") or "",
            },
        )
        for key, target in (("source", "sources"), ("provider", "providers"), ("protocol", "protocols"), ("tls_version", "tls_versions")):
            value = str(rec.get(key) or "").strip()
            if value:
                item[target].add(value)
        path = str(rec.get("path") or "").strip()
        if path and path not in item["paths_sample"] and len(item["paths_sample"]) < 8:
            item["paths_sample"].append(path)
        item["observed_count"] += int(rec.get("observed_count") or 1)
        ts = str(rec.get("observed_at") or "")
        if ts:
            if not item["first_seen"] or ts < item["first_seen"]:
                item["first_seen"] = ts
            if not item["last_seen"] or ts > item["last_seen"]:
                item["last_seen"] = ts
    assets = []
    for item in by_asset.values():
        clean = dict(item)
        for key in ("sources", "providers", "protocols", "tls_versions"):
            clean[key] = sorted(item[key])
        assets.append(clean)
    assets.sort(key=lambda x: (-int(x.get("observed_count") or 0), x.get("asset_key") or ""))
    return {"asset_count": len(assets), "assets": assets}
