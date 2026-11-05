"""Migration proofs, their public keys, and audit-journal verification."""
from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Request

from db import current_organization_id
from services import audit_chain, migration_proof, proof_signing


def create_migration_proof_router(require_role: Callable[..., Any]) -> APIRouter:
    router = APIRouter()

    @router.post("/remediations/{remediation_id}/migration-proof")
    def api_issue_migration_proof(remediation_id: int, request: Request):
        require_role(request, allowed_roles=["operator", "admin", "owner"], action="remediation.migration_proof",
                     resource_type="remediation", resource_id=str(remediation_id))
        base = str(request.base_url).rstrip("/")
        issuer = {"product": "Morrow", "software_version": str(getattr(request.app, "version", "") or ""),
                  "keys_url": base + proof_signing.WELL_KNOWN_PATH}
        try:
            proof = migration_proof.build_proof(int(remediation_id), issuer=issuer)
        except migration_proof.ProofRefused as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail)
        return {
            "api_version": "v1",
            "kind": "migration_proof",
            "proof": proof,
            "verify": {
                "offline": "python scripts/verify_migration_proof.py proof.json --keys morrow-proof-keys.json",
                "keys_url": issuer["keys_url"],
                "journal_export": base + "/audit/journal/export",
            },
        }

    @router.get(proof_signing.WELL_KNOWN_PATH, include_in_schema=True)
    def api_proof_keys():
        try:
            return proof_signing.published_keys()
        except Exception:
            raise HTTPException(status_code=503, detail="proof signing keys are unavailable")

    @router.get("/audit/journal/verify")
    def api_verify_audit_journal(request: Request):
        require_role(request, allowed_roles=["admin", "owner"], action="audit.verify",
                     resource_type="audit_log", resource_id="*")
        return {"api_version": "v1", "kind": "audit_journal_verification",
                **audit_chain.verify_chain(current_organization_id())}

    @router.get("/audit/journal/export")
    def api_export_audit_journal(request: Request):
        require_role(request, allowed_roles=["admin", "owner"], action="audit.export",
                     resource_type="audit_log", resource_id="*")
        return audit_chain.export_chain(current_organization_id())

    return router
