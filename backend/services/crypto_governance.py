from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional


def _parse_datetime(value: Any) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc)
        except Exception:
            return None
    candidates = [raw, raw.replace("Z", "+00:00")]
    for candidate in candidates:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def certificate_expiry_value(latest: Dict[str, Any]) -> str:
    keys = [
        "cert_not_after",
        "certificate_not_after",
        "not_after",
        "notAfter",
        "cert_expires_at",
        "certificate_expires_at",
        "expires_at",
        "valid_to",
        "cert_valid_to",
        "cert_expiry",
    ]
    for key in keys:
        value = latest.get(key)
        if str(value or "").strip():
            return str(value).strip()
    cert = latest.get("certificate") if isinstance(latest.get("certificate"), dict) else {}
    for key in keys:
        value = cert.get(key)
        if str(value or "").strip():
            return str(value).strip()
    return ""


def classify_certificate(latest: Dict[str, Any], *, warning_days: int = 30, now: Optional[datetime] = None) -> Dict[str, Any]:
    now_dt = now or datetime.now(timezone.utc)
    raw_expiry = certificate_expiry_value(latest)
    expires_at = _parse_datetime(raw_expiry)
    issuer = str(latest.get("cert_issuer") or latest.get("issuer") or "").strip()
    subject = str(latest.get("cert_subject") or latest.get("subject") or "").strip()
    if not expires_at:
        return {
            "status": "unknown",
            "severity": "unknown",
            "expires_at": raw_expiry,
            "days_remaining": None,
            "issuer": issuer,
            "subject": subject,
            "message": "certificate expiration was not present in the latest scan evidence",
        }
    days_remaining = int((expires_at - now_dt).total_seconds() // 86400)
    if days_remaining < 0:
        status = "expired"
        severity = "critical"
        message = "certificate is expired"
    elif days_remaining <= int(warning_days):
        status = "expiring_soon"
        severity = "high" if days_remaining <= 7 else "medium"
        message = f"certificate expires within {warning_days} days"
    else:
        status = "healthy"
        severity = "info"
        message = "certificate is outside the warning window"
    return {
        "status": status,
        "severity": severity,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "days_remaining": days_remaining,
        "issuer": issuer,
        "subject": subject,
        "message": message,
    }


def build_certificate_lifecycle_report(
    *,
    assets: List[Dict[str, Any]],
    latest_for_asset: Any,
    warning_days: int = 30,
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {"expired": 0, "expiring_soon": 0, "healthy": 0, "unknown": 0}
    for asset in assets:
        key = str(asset.get("asset_key") or "").strip()
        if not key:
            continue
        latest = latest_for_asset(key) or {}
        cert = classify_certificate(latest, warning_days=warning_days)
        counts[cert["status"]] = counts.get(cert["status"], 0) + 1
        items.append({
            "asset_key": key,
            "owner": str(asset.get("owner") or "").strip(),
            "team": str(asset.get("team") or "").strip(),
            "repository_id": int(asset.get("repository_id") or 0),
            "repository": str(asset.get("repository_name") or "").strip(),
            "scan_id": str(latest.get("scan_id") or "").strip(),
            "scanned_at": str(latest.get("scanned_at") or "").strip(),
            **cert,
        })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "unknown": 3, "info": 4}
    items.sort(key=lambda item: (severity_order.get(str(item.get("severity") or "unknown"), 9), item.get("days_remaining") if item.get("days_remaining") is not None else 99999, str(item.get("asset_key") or "")))
    return {"warning_days": int(warning_days), "summary": counts, "items": items}


def build_shadow_it_report(*, assets: List[Dict[str, Any]], runtime_assets: List[Dict[str, Any]], latest_for_asset: Any) -> Dict[str, Any]:
    asset_by_key = {str(asset.get("asset_key") or "").strip(): asset for asset in assets if str(asset.get("asset_key") or "").strip()}
    items: List[Dict[str, Any]] = []
    counts = {"runtime_observed": len(runtime_assets), "unknown_assets": 0, "unmanaged_assets": 0, "unscanned_runtime_assets": 0}
    for runtime in runtime_assets:
        key = str(runtime.get("asset_key") or "").strip()
        if not key:
            continue
        asset = asset_by_key.get(key) or {}
        latest = latest_for_asset(key) or {}
        owner_missing = not str(asset.get("owner") or "").strip()
        repo_missing = not int(asset.get("repository_id") or 0)
        no_scan = not bool(latest)
        unknown_asset = not bool(asset)
        unmanaged = unknown_asset or owner_missing or repo_missing or no_scan
        if unknown_asset:
            counts["unknown_assets"] += 1
        if unmanaged:
            counts["unmanaged_assets"] += 1
        if no_scan:
            counts["unscanned_runtime_assets"] += 1
        if unmanaged:
            blockers = []
            if unknown_asset:
                blockers.append("not in asset inventory")
            if owner_missing:
                blockers.append("missing owner")
            if repo_missing:
                blockers.append("missing repository link")
            if no_scan:
                blockers.append("no scan evidence")
            items.append({
                "asset_key": key,
                "status": "unmanaged_runtime_endpoint" if not unknown_asset else "unknown_runtime_endpoint",
                "blockers": blockers,
                "observed_count": int(runtime.get("observed_count") or 0),
                "first_seen": str(runtime.get("first_seen") or ""),
                "last_seen": str(runtime.get("last_seen") or ""),
                "sources": runtime.get("sources") or [],
                "providers": runtime.get("providers") or [],
                "protocols": runtime.get("protocols") or [],
                "tls_versions": runtime.get("tls_versions") or [],
                "owner": str(asset.get("owner") or "").strip(),
                "team": str(asset.get("team") or "").strip(),
                "repository_id": int(asset.get("repository_id") or 0),
                "latest_scan_id": str(latest.get("scan_id") or "").strip(),
            })
    items.sort(key=lambda item: (-int(item.get("observed_count") or 0), str(item.get("asset_key") or "")))
    return {"summary": counts, "items": items}
