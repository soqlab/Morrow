"""Operator alert routing API: channels, test sends and the delivery log.

Reads need a platform admin read role (owner, operator, support, auditor); changes and test sends
need a write role (owner, operator). Every change carries a reason and is recorded as a platform
admin event. Secrets are never returned: a channel answers with target_hint only.

Delivery logic lives in services/alert_routing.py.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Union

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from services import alert_routing as _ar
from services import platform_mail as _mail
from services import platform_operators as _operators

READ = _operators.READ_ROLES
WRITE = _operators.WRITE_ROLES


class QuietHours(BaseModel):
    start: str = Field(..., max_length=5)
    end: str = Field(..., max_length=5)
    timezone: str = Field("UTC", max_length=64)
    allow_critical: bool = True


class ChannelCreateRequest(BaseModel):
    kind: str = Field(..., pattern="^(slack_webhook|email|pagerduty|generic_webhook)$")
    name: str = Field(..., min_length=1, max_length=80)
    target: Union[str, List[str]] = Field(...)
    enabled: bool = True
    min_severity: str = Field("warn", pattern="^(critical|warn|info)$")
    kinds: Optional[List[str]] = Field(None, max_length=20)
    quiet_hours: Optional[QuietHours] = None
    reason: str = Field(..., min_length=3, max_length=500)


class ChannelUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    target: Optional[Union[str, List[str]]] = None
    enabled: Optional[bool] = None
    min_severity: Optional[str] = Field(None, pattern="^(critical|warn|info)$")
    kinds: Optional[List[str]] = Field(None, max_length=20)
    quiet_hours: Optional[QuietHours] = None
    clear_quiet_hours: bool = False
    reason: str = Field(..., min_length=3, max_length=500)


class TestSendRequest(BaseModel):
    reason: str = Field("", max_length=500)


def _no_store(payload: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers={"Cache-Control": "no-store"})


def _dump(model: Any) -> Dict[str, Any]:
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


def _target_length_ok(target: Any) -> None:
    if isinstance(target, list):
        if len(target) > _ar.MAX_EMAIL_RECIPIENTS or any(len(str(t)) > 320 for t in target):
            raise HTTPException(status_code=400, detail="Too many or too long recipient addresses.")
    elif target is not None and len(str(target)) > 4096:
        raise HTTPException(status_code=400, detail="The target is too long.")


def _incident_details(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Audit-event fields for the PagerDuty incidents a delete or a disable resolved (or could not)."""
    return {"incidents_open": summary.get("open", 0), "incidents_resolved": summary.get("resolved", 0),
            "incidents_failed": summary.get("failed", 0), "incidents_retrying": summary.get("retrying", 0),
            "incidents_in_digest": summary.get("digest_items", 0)}


def _incident_body(summary: Dict[str, Any]) -> Dict[str, Any]:
    """What the caller is told about those incidents: counts, and one entry per incident with its outcome."""
    return {"open": summary.get("open", 0), "resolved": summary.get("resolved", 0), "failed": summary.get("failed", 0),
            "retrying": summary.get("retrying", 0), "in_digest": summary.get("digest_items", 0),
            "items": [{"notification_id": i["notification_id"], "title": i["title"], "resolved": i["ok"],
                       "http_status": i["http_status"], "error": i["error"]} for i in summary.get("items", [])]}


def create_alert_routing_router(deps: Any) -> APIRouter:
    """deps: require_platform_admin(request, roles), record_event(org, action, reason, details), base_url(request)."""
    router = APIRouter()

    def guard(request: Request, roles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        return deps.require_platform_admin(request, set(roles) if roles else None)

    def record(action: str, reason: str, details: Dict[str, Any]) -> None:
        deps.record_event("", action, reason=reason, details=details)

    def fail(exc: _ar.AlertRoutingError) -> HTTPException:
        return HTTPException(status_code=exc.status_code, detail=exc.detail)

    @router.get("/platform/alert-channels")
    def platform_alert_channels(request: Request):
        guard(request, READ)
        try:
            items = [_ar.public_channel(c) for c in _ar.list_channels()]
            dispatcher = _ar.job_state()
        except _ar.AlertRoutingError as exc:
            raise fail(exc) from None
        return _no_store({
            "api_version": "v1", "generated_at": _ar.iso(_ar.now_utc()), "items": items,
            "channel_kinds": list(_ar.CHANNEL_KINDS), "notification_kinds": list(_ar.NOTIFICATION_KINDS),
            "notification_kind_labels": dict(_ar.NOTIFICATION_KIND_LABELS),
            "email_configured": _mail.configured(), "secret_storage_configured": _ar.vault_configured(),
            "settings": _ar.public_settings(), "dispatcher": dispatcher,
        })

    @router.post("/platform/alert-channels")
    def platform_create_alert_channel(req: ChannelCreateRequest, request: Request):
        actor = guard(request, WRITE)
        _target_length_ok(req.target)
        data = _dump(req)
        try:
            channel = _ar.create_channel(data, actor.get("actor_id") or "")
        except _ar.AlertRoutingError as exc:
            raise fail(exc) from None
        public = _ar.public_channel(channel)
        record("platform.alert_channel_created", req.reason, {
            "channel_id": public["id"], "kind": public["kind"], "name": public["name"], "min_severity": public["min_severity"],
            "kinds": public["kinds"], "enabled": public["enabled"]})
        return _no_store({"ok": True, "channel": public})

    @router.put("/platform/alert-channels/{channel_id}")
    def platform_update_alert_channel(channel_id: str, req: ChannelUpdateRequest, request: Request):
        actor = guard(request, WRITE)
        _target_length_ok(req.target)
        data = {k: v for k, v in _dump(req).items() if k not in ("reason", "clear_quiet_hours", "quiet_hours")}
        fields_set = getattr(req, "model_fields_set", None) or getattr(req, "__fields_set__", set())
        if req.clear_quiet_hours:
            data["quiet_hours"] = None
        elif "quiet_hours" in fields_set and req.quiet_hours is not None:
            data["quiet_hours"] = _dump(req.quiet_hours)
        if "kinds" not in fields_set:
            data.pop("kinds", None)
        elif data.get("kinds") is None:
            data["kinds"] = []
        resolved: Dict[str, Any] = {}
        try:
            channel, changed = _ar.update_channel(channel_id, data, actor.get("actor_id") or "", resolved)
        except _ar.AlertRoutingError as exc:
            raise fail(exc) from None
        public = _ar.public_channel(channel)
        details = {"channel_id": public["id"], "kind": public["kind"], "changed": changed, "enabled": public["enabled"]}
        if resolved.get("open"):
            details.update(_incident_details(resolved))
        record("platform.alert_channel_updated", req.reason, details)
        body = {"ok": True, "channel": public, "changed": changed}
        if resolved.get("open"):
            body["incidents"] = _incident_body(resolved)
            body["note"] = _ar.resolve_note(resolved)
        return _no_store(body)

    @router.delete("/platform/alert-channels/{channel_id}")
    def platform_delete_alert_channel(channel_id: str, request: Request,
                                      reason: str = Query(..., min_length=3, max_length=500)):
        guard(request, WRITE)
        try:
            result = _ar.delete_channel(channel_id)
        except _ar.AlertRoutingError as exc:
            raise fail(exc) from None
        channel = result["channel"]
        incidents = result["incidents"]
        record("platform.alert_channel_deleted", reason, {"channel_id": channel["id"], "kind": channel["kind"], "name": channel["name"],
                                                          "open_items": result["open_items"], **_incident_details(incidents)})
        return _no_store({"ok": True, "channel_id": channel["id"], "note": _ar.resolve_note(incidents),
                          "incidents": _incident_body(incidents)})

    @router.post("/platform/alert-channels/{channel_id}/test")
    async def platform_test_alert_channel(channel_id: str, request: Request, req: Optional[TestSendRequest] = None):
        guard(request, WRITE)
        base = deps.base_url(request)
        try:
            result = await run_in_threadpool(_ar.test_send, channel_id, base)
        except _ar.AlertRoutingError as exc:
            raise fail(exc) from None
        record("platform.alert_channel_tested", (req.reason if req else "") or "test send", {
            "channel_id": result["channel"]["id"], "kind": result["channel"]["kind"], "ok": result["ok"],
            "http_status": result["http_status"]})
        return _no_store({"api_version": "v1", **result})

    @router.get("/platform/alert-deliveries")
    def platform_alert_deliveries(request: Request, channel_id: str = Query("", max_length=32),
                                  status: str = Query("", pattern="^(|sent|failed|suppressed)$"),
                                  event: str = Query("", pattern="^(|trigger|renotify|resolve|digest|test|rate_limited|config_error)$"),
                                  limit: int = Query(100, ge=1, le=500)):
        guard(request, READ)
        items = _ar.list_deliveries(channel_id.strip().lower(), int(limit), status, event)
        return _no_store({"api_version": "v1", "generated_at": _ar.iso(_ar.now_utc()), "items": items})

    return router
