from typing import Any, Callable, Dict
import sys

from fastapi import APIRouter, Query, Request

from db import current_organization_id, list_assets, list_runtime_observed_assets
from services.crypto_governance import build_certificate_lifecycle_report, build_shadow_it_report


RequireRole = Callable[..., Dict[str, Any]]


def _app_attr(name: str) -> Any:
    app_module = sys.modules.get("app")
    if app_module is None or not hasattr(app_module, name):
        raise RuntimeError(f"{name} unavailable")
    return getattr(app_module, name)


def _default_org_id() -> str:
    app_module = sys.modules.get("app")
    return str(getattr(app_module, "DEFAULT_ORG_ID", "default-org") if app_module else "default-org")


def create_governance_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter()

    @router.get("/governance/certificates")
    @router.get("/v1/governance/certificates")
    def api_certificate_lifecycle(
        request: Request,
        warning_days: int = Query(30, ge=1, le=365),
        asset_limit: int = Query(5000, ge=1, le=20000),
    ):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="governance.certificates", resource_type="organization", resource_id=org_id)
        assets = list_assets(limit=int(asset_limit))
        report = build_certificate_lifecycle_report(
            assets=assets,
            latest_for_asset=_app_attr("_latest_full_scan_result_lookup")(),
            warning_days=int(warning_days),
        )
        return {"api_version": "v1", "organization_id": org_id, **report}

    @router.get("/governance/shadow-it")
    @router.get("/v1/governance/shadow-it")
    def api_shadow_it(
        request: Request,
        asset_limit: int = Query(5000, ge=1, le=20000),
        runtime_limit: int = Query(1000, ge=1, le=5000),
    ):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="governance.shadow_it", resource_type="organization", resource_id=org_id)
        assets = list_assets(limit=int(asset_limit))
        runtime_assets = list_runtime_observed_assets(limit=int(runtime_limit))
        report = build_shadow_it_report(
            assets=assets,
            runtime_assets=runtime_assets,
            latest_for_asset=_app_attr("_latest_full_scan_result_lookup")(),
        )
        return {"api_version": "v1", "organization_id": org_id, **report}

    return router
