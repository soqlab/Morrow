"""Crypto kill switch (/crypto-switch/...) and gradual post-quantum rollouts (/pq-rollouts/...).

Logic lives in services/crypto_switch.py and services/pq_rollout.py. Every route is role-checked
through the console's require_role; every step that changes state needs an org admin. Viewers can
watch the live status.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from db import current_organization_id, latest_scan_facts_for_org, latest_scan_results_for_assets, list_assets
from services import crypto_switch, pq_rollout

RequireRole = Callable[..., Dict[str, Any]]

VIEW = ["viewer", "analyst", "operator", "admin"]
OPERATE = ["operator", "admin"]
ADMIN = ["admin"]


class PreflightRequest(BaseModel):
    broken: str = Field(..., min_length=1, max_length=80)
    fallback: str = Field("", max_length=80)


class IncidentRequest(BaseModel):
    broken: str = Field(..., min_length=1, max_length=80)
    fallback: str = Field("", max_length=80)
    reason: str = Field("", max_length=2000)
    dry_run: bool = True
    batch_size: int = Field(10, ge=1, le=200)
    repository: str = Field("", max_length=200)
    connection_id: str = Field("", max_length=64)
    base_branch: str = Field("", max_length=200)


class NoteRequest(BaseModel):
    note: str = Field("", max_length=500)


class BatchRequest(BaseModel):
    batch: Optional[int] = Field(None, ge=1, le=10000)


class RolloutPreviewRequest(BaseModel):
    name: str = Field("", max_length=120)
    platform: str = Field(..., max_length=20)
    spec: Dict[str, Any] = Field(default_factory=dict)
    stages: Optional[List[int]] = None


class RolloutRequest(RolloutPreviewRequest):
    metrics: Dict[str, Any] = Field(default_factory=dict)
    metrics_token: str = Field("", max_length=4000)
    soak_minutes: int = Field(30, ge=1, le=10080)
    mode: str = Field("manual", max_length=20)
    dry_run: bool = True
    repository: str = Field("", max_length=200)
    connection_id: str = Field("", max_length=64)
    base_branch: str = Field("", max_length=200)


class RollbackRequest(BaseModel):
    reason: str = Field("Rolled back by an administrator", min_length=1, max_length=300)


def _org(request: Request) -> str:
    return str(getattr(request.state, "org_id", "") or current_organization_id())


def _mesh_profiles() -> List[Dict[str, Any]]:
    try:
        from services.advanced_pq_controls import list_crypto_mesh_profiles

        return list_crypto_mesh_profiles(limit=1)
    except Exception:
        return []


def _mesh_groups() -> Optional[List[str]]:
    """The hybrid groups the org's crypto-mesh profile prefers (built on its emergency_algorithm)."""
    for row in _mesh_profiles():
        groups = ((row.get("profile") or {}).get("primary_profile") or {}).get("tls_groups")
        if groups:
            return [str(g) for g in groups]
    return None


def create_crypto_switch_router(require_role: RequireRole, load_policy: Callable[[str], Dict[str, Any]],
                                request_rescan: Optional[Callable[[List[str]], str]] = None) -> APIRouter:
    router = APIRouter(tags=["Crypto kill switch", "Post-quantum rollout"])

    def guard(request: Request, roles: List[str], action: str, rtype: str, rid: str = "") -> Dict[str, Any]:
        return require_role(request, allowed_roles=roles, action=action, resource_type=rtype, resource_id=rid or _org(request))

    def run(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (crypto_switch.SwitchError, pq_rollout.RolloutError) as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None

    # ── Kill switch ──────────────────────────────────────────────────────────────────────────

    @router.get("/crypto-switch/algorithms")
    def api_switch_algorithms(request: Request):
        guard(request, VIEW, "crypto_switch.algorithms", "organization")
        return {"api_version": "v1", **crypto_switch.catalogue()}

    @router.post("/crypto-switch/preflight")
    def api_switch_preflight(body: PreflightRequest, request: Request):
        org_id = _org(request)
        guard(request, OPERATE, "crypto_switch.preflight", "organization")
        fallback = body.fallback or crypto_switch.default_fallback(body.broken, _mesh_profiles())
        facts = latest_scan_facts_for_org(limit=5000)
        assets = list_assets(limit=5000)
        plan = crypto_switch.build_plan(body.broken, fallback, facts, assets, policy=load_policy(org_id))
        plan["items"] = [{k: v for k, v in i.items() if k != "change_content"} for i in plan["items"][:200]]
        return {"api_version": "v1", "dry_run": True, **plan}

    @router.post("/crypto-switch/incidents")
    def api_switch_declare(body: IncidentRequest, request: Request):
        org_id = _org(request)
        actor = guard(request, ADMIN, "crypto_switch.declare", "organization")
        fallback = body.fallback or crypto_switch.default_fallback(body.broken, _mesh_profiles())
        return run(crypto_switch.create_incident, org_id, actor, body.broken, fallback,
                   facts=latest_scan_facts_for_org(limit=5000), assets=list_assets(limit=5000), policy=load_policy(org_id),
                   reason=body.reason, dry_run=body.dry_run, batch_size=body.batch_size, repository=body.repository,
                   connection_id=body.connection_id, base_branch=body.base_branch)

    @router.get("/crypto-switch/incidents")
    def api_switch_list(request: Request, limit: int = Query(50, ge=1, le=500)):
        guard(request, VIEW, "crypto_switch.list", "organization")
        return {"api_version": "v1", "items": crypto_switch.list_incidents(_org(request), limit=limit)}

    @router.get("/crypto-switch/incidents/{incident_id}")
    def api_switch_status(incident_id: str, request: Request, changes: bool = Query(False)):
        guard(request, VIEW, "crypto_switch.status", "crypto_switch_incident", incident_id)
        return run(crypto_switch.incident_status, _org(request), incident_id, with_changes=changes)

    @router.post("/crypto-switch/incidents/{incident_id}/approve")
    def api_switch_approve(incident_id: str, body: NoteRequest, request: Request):
        actor = guard(request, ADMIN, "crypto_switch.approve", "crypto_switch_incident", incident_id)
        return run(crypto_switch.approve_incident, _org(request), incident_id, actor, body.note)

    @router.post("/crypto-switch/incidents/{incident_id}/go-live")
    def api_switch_go_live(incident_id: str, request: Request):
        actor = guard(request, ADMIN, "crypto_switch.go_live", "crypto_switch_incident", incident_id)
        return run(crypto_switch.go_live, _org(request), incident_id, actor)

    @router.post("/crypto-switch/incidents/{incident_id}/execute")
    def api_switch_execute(incident_id: str, body: BatchRequest, request: Request):
        actor = guard(request, ADMIN, "crypto_switch.execute_batch", "crypto_switch_incident", incident_id)
        return run(crypto_switch.execute_batch, _org(request), incident_id, actor, body.batch)

    @router.post("/crypto-switch/incidents/{incident_id}/refresh")
    def api_switch_refresh(incident_id: str, request: Request):
        actor = guard(request, OPERATE, "crypto_switch.refresh", "crypto_switch_incident", incident_id)
        return run(crypto_switch.refresh_incident, _org(request), incident_id, actor,
                   latest_facts=latest_scan_results_for_assets, request_rescan=request_rescan)

    @router.post("/crypto-switch/incidents/{incident_id}/cancel")
    def api_switch_cancel(incident_id: str, body: NoteRequest, request: Request):
        actor = guard(request, ADMIN, "crypto_switch.cancel", "crypto_switch_incident", incident_id)
        return run(crypto_switch.cancel_incident, _org(request), incident_id, actor, body.note)

    # ── Gradual rollout ──────────────────────────────────────────────────────────────────────

    @router.get("/pq-rollouts/platforms")
    def api_rollout_platforms(request: Request):
        guard(request, VIEW, "pq_rollout.platforms", "organization")
        return {"api_version": "v1", "platforms": [{"id": k, **v} for k, v in pq_rollout.PLATFORMS.items()],
                "default_stages": pq_rollout.DEFAULT_STAGES,
                "gates": [{"id": k, "label": v["label"], "default_max_delta": v["default_max_delta"]} for k, v in pq_rollout.GATES.items()],
                "default_pq_groups": _mesh_groups() or ["X25519MLKEM768", "X25519"]}

    @router.post("/pq-rollouts/preview")
    def api_rollout_preview(body: RolloutPreviewRequest, request: Request):
        guard(request, OPERATE, "pq_rollout.preview", "organization")
        return run(pq_rollout.preview, body.platform, body.spec, body.stages, body.name, _mesh_groups())

    @router.post("/pq-rollouts")
    def api_rollout_create(body: RolloutRequest, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.create", "organization")
        return run(pq_rollout.create_rollout, _org(request), actor, name=body.name, platform=body.platform, spec=body.spec,
                   metrics=body.metrics, token=body.metrics_token, stages=body.stages, soak_minutes=body.soak_minutes,
                   mode=body.mode, dry_run=body.dry_run, repository=body.repository, connection_id=body.connection_id,
                   base_branch=body.base_branch, default_groups=_mesh_groups())

    @router.get("/pq-rollouts")
    def api_rollout_list(request: Request, limit: int = Query(100, ge=1, le=500)):
        guard(request, VIEW, "pq_rollout.list", "organization")
        org_id = _org(request)
        return {"api_version": "v1", "summary": pq_rollout.summary(org_id), "items": pq_rollout.list_rollouts(org_id, limit=limit)}

    @router.get("/pq-rollouts/summary")
    def api_rollout_summary(request: Request):
        guard(request, VIEW, "pq_rollout.summary", "organization")
        return pq_rollout.summary(_org(request))

    @router.get("/pq-rollouts/{rollout_id}")
    def api_rollout_get(rollout_id: str, request: Request, configs: bool = Query(False)):
        guard(request, VIEW, "pq_rollout.get", "pq_rollout", rollout_id)
        return run(pq_rollout.get_rollout, _org(request), rollout_id, with_configs=configs)

    @router.post("/pq-rollouts/{rollout_id}/approve")
    def api_rollout_approve(rollout_id: str, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.approve", "pq_rollout", rollout_id)
        return run(pq_rollout.approve, _org(request), rollout_id, actor)

    @router.post("/pq-rollouts/{rollout_id}/advance")
    def api_rollout_advance(rollout_id: str, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.advance", "pq_rollout", rollout_id)
        return run(pq_rollout.advance, _org(request), rollout_id, actor)

    @router.post("/pq-rollouts/{rollout_id}/mark-applied")
    def api_rollout_applied(rollout_id: str, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.mark_applied", "pq_rollout", rollout_id)
        return run(pq_rollout.mark_applied, _org(request), rollout_id, actor)

    @router.post("/pq-rollouts/{rollout_id}/evaluate")
    def api_rollout_evaluate(rollout_id: str, request: Request):
        actor = guard(request, OPERATE, "pq_rollout.evaluate", "pq_rollout", rollout_id)
        return run(pq_rollout.evaluate, _org(request), rollout_id, actor)

    @router.post("/pq-rollouts/{rollout_id}/rollback")
    def api_rollout_rollback(rollout_id: str, body: RollbackRequest, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.rollback", "pq_rollout", rollout_id)
        return run(pq_rollout.rollback, _org(request), rollout_id, actor, reason=body.reason, metric="manual")

    @router.post("/pq-rollouts/{rollout_id}/cancel")
    def api_rollout_cancel(rollout_id: str, request: Request):
        actor = guard(request, ADMIN, "pq_rollout.cancel", "pq_rollout", rollout_id)
        return run(pq_rollout.cancel, _org(request), rollout_id, actor)

    return router
