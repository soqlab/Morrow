from __future__ import annotations

from typing import Any, Callable, Dict

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from db import current_organization_id, list_assets, list_audit_logs, list_remediations, list_repositories
from services.security_intent import (
    build_security_graph,
    evaluate_security_intent,
    score_vendor_attestation,
    validate_security_truth,
)
from services.security_intent_store import (
    active_security_intent_bundle,
    create_security_intent,
    get_security_intent,
    list_security_intents,
    set_security_intent_status,
)
from services.advanced_pq_controls import (
    build_crypto_mesh_profile,
    create_hndl_canary_token,
    generate_vendor_private_proof,
    list_crypto_mesh_profiles,
    list_hndl_canaries,
    record_hndl_canary_hit,
    save_crypto_mesh_profile,
    verify_vendor_private_proof,
)


RequireRole = Callable[..., Dict[str, Any]]


class IntentEvaluateRequest(BaseModel):
    intent: str = Field(..., min_length=3, max_length=4000)
    name: str = Field("Security intent", max_length=180)
    save: bool = False


class SecurityTruthRequest(BaseModel):
    change: str = Field(..., min_length=1, max_length=120000)
    intent: str = Field("", max_length=4000)
    source: str = Field("manual", max_length=80)


class VendorAttestationScoreRequest(BaseModel):
    attestation: Dict[str, Any] = Field(default_factory=dict)
    dependent_assets: int = Field(0, ge=0, le=100000)


class MeshProfileRequest(BaseModel):
    name: str = Field("Default crypto agility mesh", max_length=180)
    intent: str = Field("", max_length=4000)
    emergency_algorithm: str = Field("", max_length=120)
    save: bool = False


class CanaryCreateRequest(BaseModel):
    label: str = Field("HNDL canary", max_length=180)
    scope: str = Field("", max_length=300)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CanaryHitRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=4000)
    source: str = Field("", max_length=300)
    event: Dict[str, Any] = Field(default_factory=dict)


class PrivateProofRequest(BaseModel):
    vendor_name: str = Field(..., min_length=1, max_length=180)
    scan_summary: Dict[str, Any] = Field(default_factory=dict)
    claims: Dict[str, Any] = Field(default_factory=dict)


class PrivateProofVerifyRequest(BaseModel):
    proof: Dict[str, Any] = Field(default_factory=dict)


def create_security_intent_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter(tags=["Security Intent"])

    @router.post("/security-intents/evaluate")
    def api_evaluate_security_intent(body: IntentEvaluateRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_intent.evaluate",
            resource_type="organization",
            resource_id=org_id,
        )
        evaluation = evaluate_security_intent(
            body.intent,
            assets=list_assets(limit=2000),
            repositories=list_repositories(limit=1000),
            remediations=list_remediations(limit=1000),
            audit_events=list_audit_logs(limit=200),
        )
        if body.save:
            actor_id = str(getattr(request.state, "actor_id", "") or request.headers.get("x-user-id") or "")
            saved = create_security_intent(body.name, body.intent, evaluation, created_by=actor_id)
            return {"ok": True, "saved": saved, "evaluation": evaluation}
        return evaluation

    @router.get("/security-intents")
    def api_list_security_intents(
        request: Request,
        status: str = Query("", max_length=32),
        limit: int = Query(200, ge=1, le=1000),
    ):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_intent.list",
            resource_type="organization",
            resource_id=org_id,
        )
        return {"api_version": "v1", "items": list_security_intents(status=status, limit=int(limit))}

    @router.post("/security-intents/{intent_id}/publish")
    def api_publish_security_intent(intent_id: int, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["admin"],
            action="security_intent.publish",
            resource_type="security_intent",
            resource_id=str(intent_id),
        )
        row = set_security_intent_status(int(intent_id), "published")
        if not row:
            raise HTTPException(status_code=404, detail="security intent not found")
        return {"ok": True, "organization_id": org_id, "item": row}

    @router.post("/security-intents/{intent_id}/disable")
    def api_disable_security_intent(intent_id: int, request: Request):
        require_role(
            request,
            allowed_roles=["admin"],
            action="security_intent.disable",
            resource_type="security_intent",
            resource_id=str(intent_id),
        )
        row = set_security_intent_status(int(intent_id), "disabled")
        if not row:
            raise HTTPException(status_code=404, detail="security intent not found")
        return {"ok": True, "item": row}

    @router.get("/security-intents/{intent_id}")
    def api_get_security_intent(intent_id: int, request: Request):
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_intent.get",
            resource_type="security_intent",
            resource_id=str(intent_id),
        )
        row = get_security_intent(int(intent_id))
        if not row:
            raise HTTPException(status_code=404, detail="security intent not found")
        return row

    @router.get("/security-truth/policy-bundle")
    def api_security_truth_policy_bundle(request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_truth.policy_bundle",
            resource_type="organization",
            resource_id=org_id,
        )
        bundle = active_security_intent_bundle()
        bundle["organization_id"] = org_id
        bundle["ci_integration"] = {
            "endpoint": "/v1/security-truth/validate",
            "method": "POST",
            "required_headers": ["Authorization or x-user-role in local/dev", "Content-Type: application/json"],
            "decision_contract": "decision == 'allow' may proceed; decision == 'block' must fail CI or require exception.",
        }
        return bundle

    @router.get("/security-graph")
    def api_security_graph(request: Request, limit: int = Query(1000, ge=1, le=5000)):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_graph.read",
            resource_type="organization",
            resource_id=org_id,
        )
        return build_security_graph(
            assets=list_assets(limit=int(limit)),
            repositories=list_repositories(limit=int(limit)),
            remediations=list_remediations(limit=int(limit)),
        )

    @router.post("/security-truth/validate")
    def api_security_truth_validate(body: SecurityTruthRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="security_truth.validate",
            resource_type="organization",
            resource_id=org_id,
        )
        result = validate_security_truth(body.change, intent=body.intent)
        result["source"] = body.source
        return result

    @router.post("/vendor-attestations/score")
    def api_vendor_attestation_score(body: VendorAttestationScoreRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="vendor_attestation.score",
            resource_type="organization",
            resource_id=org_id,
        )
        return score_vendor_attestation(body.attestation, dependent_assets=int(body.dependent_assets or 0))

    @router.get("/drift-prevention/plan")
    def api_drift_prevention_plan(request: Request, limit: int = Query(1000, ge=1, le=5000)):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="drift_prevention.plan",
            resource_type="organization",
            resource_id=org_id,
        )
        drifted = list_remediations(drift_status="drifted", limit=int(limit))
        failed = list_remediations(drift_status="check_failed", limit=int(limit))
        open_work = list_remediations(limit=int(limit))
        return {
            "api_version": "v1",
            "organization_id": org_id,
            "summary": {
                "drifted": len(drifted),
                "check_failed": len(failed),
                "open_remediation_cards": len([r for r in open_work if str(r.get("status") or "").lower() not in {"verified_closed", "rejected"}]),
            },
            "controls": [
                "Run scheduled drift checks for verified remediations.",
                "Create follow-up remediation when protected content changes.",
                "Require Security Truth validation before risky infrastructure changes merge.",
                "Escalate repeated drift to admin/vendor review.",
            ],
            "drifted_items": drifted[:50],
            "check_failed_items": failed[:50],
        }

    @router.post("/crypto-mesh/profiles")
    def api_crypto_mesh_profile(body: MeshProfileRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="crypto_mesh.profile",
            resource_type="organization",
            resource_id=org_id,
        )
        profile = build_crypto_mesh_profile(body.name, intent=body.intent, emergency_algorithm=body.emergency_algorithm)
        if body.save:
            return {"ok": True, "saved": save_crypto_mesh_profile(body.name, profile), "profile": profile}
        return profile

    @router.get("/crypto-mesh/profiles")
    def api_list_crypto_mesh_profiles(request: Request, limit: int = Query(100, ge=1, le=500)):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="crypto_mesh.list",
            resource_type="organization",
            resource_id=org_id,
        )
        return {"api_version": "v1", "organization_id": org_id, "items": list_crypto_mesh_profiles(limit=int(limit))}

    @router.post("/hndl-canaries")
    def api_create_hndl_canary(body: CanaryCreateRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="hndl_canary.create",
            resource_type="organization",
            resource_id=org_id,
        )
        return create_hndl_canary_token(body.label, scope=body.scope, metadata=body.metadata)

    @router.get("/hndl-canaries")
    def api_list_hndl_canaries(request: Request, limit: int = Query(100, ge=1, le=500)):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="hndl_canary.list",
            resource_type="organization",
            resource_id=org_id,
        )
        return list_hndl_canaries(limit=int(limit))

    @router.post("/hndl-canaries/hit")
    def api_hndl_canary_hit(body: CanaryHitRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="hndl_canary.hit",
            resource_type="organization",
            resource_id=org_id,
        )
        return record_hndl_canary_hit(body.token, source=body.source, event=body.event)

    @router.post("/vendor-private-proofs")
    def api_vendor_private_proof(body: PrivateProofRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["operator", "admin"],
            action="vendor_private_proof.create",
            resource_type="organization",
            resource_id=org_id,
        )
        return generate_vendor_private_proof(body.vendor_name, body.scan_summary, claims=body.claims)

    @router.post("/vendor-private-proofs/verify")
    def api_vendor_private_proof_verify(body: PrivateProofVerifyRequest, request: Request):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or "*")
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="vendor_private_proof.verify",
            resource_type="organization",
            resource_id=org_id,
        )
        return verify_vendor_private_proof(body.proof)

    return router
