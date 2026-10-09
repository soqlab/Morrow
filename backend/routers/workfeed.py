from typing import Any, Callable, Dict, List
import sys

from fastapi import APIRouter, Query, Request

from db import (
    current_organization_id,
    get_latest_validation_job_for_remediation,
    list_migration_tasks,
    list_remediations,
)
from services.remediation_feed import (
    build_migration_task_card,
    build_remediation_card,
    filter_cards,
    summarize_feed,
)


RequireRole = Callable[..., Dict[str, Any]]


def _default_org_id() -> str:
    app_module = sys.modules.get("app")
    return str(getattr(app_module, "DEFAULT_ORG_ID", "default-org") if app_module else "default-org")


def _active_org_id(request: Request) -> str:
    return str(getattr(request.state, "org_id", current_organization_id()) or _default_org_id()).strip() or _default_org_id()


def create_workfeed_router(require_role: RequireRole) -> APIRouter:
    router = APIRouter()

    @router.get("/work/remediation-feed")
    @router.get("/v1/work/remediation-feed")
    def api_remediation_feed(
        request: Request,
        limit: int = Query(200, ge=1, le=1000),
        include_closed: bool = Query(False),
        asset_key: str = Query("", max_length=256),
        repository: str = Query("", max_length=256),
        kind: str = Query("", max_length=64),
    ):
        org_id = _active_org_id(request)
        require_role(
            request,
            allowed_roles=["viewer", "operator", "admin"],
            action="work.remediation_feed",
            resource_type="organization",
            resource_id=org_id,
        )

        remediation_cards: List[Dict[str, Any]] = []
        for remediation in list_remediations(limit=int(limit)):
            validation = get_latest_validation_job_for_remediation(int(remediation.get("id") or 0), passed_only=False)
            remediation_cards.append(build_remediation_card(remediation, validation))

        migration_cards = [build_migration_task_card(task) for task in list_migration_tasks(limit=int(limit))]
        cards = filter_cards(
            [*remediation_cards, *migration_cards],
            include_closed=bool(include_closed),
            asset_key=asset_key,
            repository=repository,
            kind=kind,
        )
        cards = sorted(cards, key=lambda item: (int(item.get("priority") or 0), str(item.get("updated_at") or "")), reverse=True)
        cards = cards[: int(limit)]

        return {
            "api_version": "v1",
            "organization_id": org_id,
            "summary": summarize_feed(cards),
            "cards": cards,
        }

    return router
