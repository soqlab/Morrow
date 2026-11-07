from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
import sys

from fastapi import APIRouter, HTTPException, Query, Request

from db import (asset_latest_evidence, asset_scan_latest_ready, backfill_progress, certificate_lifecycle_rows,
                current_organization_id, list_assets, list_runtime_observed_assets)
from services.crypto_governance import (build_certificate_lifecycle_report,
                                        build_certificate_lifecycle_report_from_rows, build_shadow_it_report)


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
        limit: int = Query(200, ge=1, le=5000),
        cursor: Optional[str] = Query(None, max_length=2048),
        asset_limit: Optional[int] = Query(None, ge=1, le=20000),
    ):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="governance.certificates", resource_type="organization", resource_id=org_id)
        # `asset_limit` is the old name of the page size, kept for existing callers.
        page_size = min(int(asset_limit or limit), 5000)
        if not asset_scan_latest_ready():
            # The one-time backfill of an upgraded database is still running (see
            # db.start_background_backfills): answer as before it existed, for the newest assets.
            assets = list_assets(limit=page_size)
            report = build_certificate_lifecycle_report(
                assets=assets,
                latest_for_asset=_app_attr("_latest_full_scan_result_lookup")(
                    fallback_keys=[a.get("asset_key") or "" for a in assets]),
                warning_days=int(warning_days),
            )
            return {"api_version": "v1", "organization_id": org_id, **report, "next_cursor": None,
                    "backfill": backfill_progress()}
        # The summary covers the whole inventory and `items` is one page of it, most urgent first,
        # both from asset_scan_latest in SQL; `next_cursor` fetches the next page. This used to
        # parse the newest 100 scans' full results (4-18 s and 95 MB at 100,000 assets) for the
        # newest 5,000 assets only, and then returned all 5,000.
        now = datetime.now(timezone.utc)
        try:
            data = certificate_lifecycle_rows(int(warning_days), now, page_size, cursor)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid cursor") from None
        report = build_certificate_lifecycle_report_from_rows(data, warning_days=int(warning_days), now=now)
        return {"api_version": "v1", "organization_id": org_id, **report, "next_cursor": data.get("next_cursor")}

    @router.get("/governance/shadow-it")
    @router.get("/v1/governance/shadow-it")
    def api_shadow_it(
        request: Request,
        asset_limit: int = Query(5000, ge=1, le=20000),
        runtime_limit: int = Query(1000, ge=1, le=5000),
    ):
        org_id = str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()
        require_role(request, allowed_roles=["viewer", "operator", "admin"], action="governance.shadow_it", resource_type="organization", resource_id=org_id)
        runtime_assets = list_runtime_observed_assets(limit=int(runtime_limit))
        keys = [str(r.get("asset_key") or "").strip() for r in runtime_assets if str(r.get("asset_key") or "").strip()]
        # Only the runtime endpoints are judged, so only their inventory rows and scan evidence are
        # read. Reading the newest `asset_limit` assets instead called every runtime endpoint outside
        # them "not in asset inventory" once the inventory was larger than that.
        assets = list_assets(limit=max(int(asset_limit), len(keys)), asset_keys=keys, _max_limit=20000) if keys else []
        evidence = asset_latest_evidence(keys)
        report = build_shadow_it_report(
            assets=assets,
            runtime_assets=runtime_assets,
            latest_for_asset=lambda key: evidence.get(str(key or "").strip()) or {},
        )
        return {"api_version": "v1", "organization_id": org_id, **report}

    return router
