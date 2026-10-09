from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from db import upsert_asset, set_asset_metadata
from vault_db import get_credential


def _load_service_account(credential_id: int) -> tuple[Dict[str, Any], str]:
    cred = get_credential(int(credential_id), reveal=True)
    if not cred:
        raise ValueError("credential not found")
    secret = cred.get("secret") or ""
    info = json.loads(secret)
    meta = cred.get("meta_json") or {}
    project_id = (
        meta.get("project_id")
        or meta.get("project")
        or info.get("project_id")
        or meta.get("gcp_project_id")
    )
    if not project_id:
        raise ValueError("project_id missing in service account or meta_json")
    return info, project_id


def sync_gcp_assets(
    credential_id: int,
    project_id: Optional[str] = None,
    asset_types: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Discover GCP resources via Cloud Asset Inventory and upsert them into the asset inventory.
    Returns a summary dict so callers can surface status in the UI/API.
    """
    try:
        from google.cloud import asset_v1
        from google.oauth2 import service_account
    except Exception as e:
        return {"ok": False, "error": f"google-cloud-asset missing: {e}"}

    try:
        info, proj = _load_service_account(credential_id)
        if project_id:
            proj = project_id
    except Exception as e:
        return {"ok": False, "error": str(e)}

    creds = service_account.Credentials.from_service_account_info(info)
    client = asset_v1.AssetServiceClient(credentials=creds)

    scope = f"projects/{proj}"
    atypes = asset_types or [
        "compute.googleapis.com/Instance",
        "compute.googleapis.com/ForwardingRule",  # load balancer frontends
        "compute.googleapis.com/TargetHttpsProxy",
    ]

    req = asset_v1.SearchAllResourcesRequest(scope=scope, asset_types=atypes, page_size=500)

    discovered = 0
    tagged = 0
    errors: List[str] = []
    labels_used = 0

    try:
        for res in client.search_all_resources(request=req):
            discovered += 1
            name = getattr(res, "display_name", None) or getattr(res, "name", "") or ""
            full_name = getattr(res, "name", "") or ""
            labels = dict(getattr(res, "labels", {}) or {})
            metadata = {
                "gcp_full_resource_name": full_name,
                "project_id": proj,
                "location": getattr(res, "location", ""),
                "asset_type": getattr(res, "asset_type", ""),
                "labels": labels,
            }

            tags: List[str] = ["source:gcp"]
            # Preserve network context as tags where obvious
            if "env" in labels:
                tags.append(f"env:{labels['env']}")
            if "team" in labels:
                tags.append(f"team:{labels['team']}")

            try:
                upsert_asset(
                    asset_key_str=name or full_name,
                    owner="",
                    team=labels.get("team", ""),
                    environment=labels.get("env", ""),
                    criticality=labels.get("criticality", ""),
                    confidentiality_lifetime="",
                    notes="",
                    tags=tags,
                    metadata=metadata,
                )
                set_asset_metadata(name or full_name, metadata)
                tagged += 1
                if labels:
                    labels_used += 1
            except Exception as e:  # pragma: no cover - defensive
                errors.append(str(e))
                continue
    except Exception as e:
        errors.append(str(e))

    return {
        "ok": len(errors) == 0,
        "project_id": proj,
        "discovered": discovered,
        "upserted": tagged,
        "labels_applied": labels_used,
        "errors": errors,
    }

