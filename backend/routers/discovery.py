"""Discovery sources: IKEv2/IPsec VPN scanning and CBOM (CBOMkit) import.

POST /v1/scan/ike          scan IKEv2 responders (ike_scanner.scan_ike)
POST /v1/cbom/import       import a CycloneDX 1.6 CBOM, e.g. CBOMkit output (services/sbom_import.import_cbom)
GET  /v1/crypto-inventory  the organization's deduplicated cryptographic inventory

The factory takes app.py's helpers as arguments, as the other routers do, so this module holds no
copy of the auth, scope or database plumbing.
"""
from __future__ import annotations

import contextvars
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile as StarletteUploadFile

from services import sbom_import

#: IKE scans running at once across the whole process. Each scan sends up to
#: ike_scanner._MAX_PROBES paced datagrams; this bounds the total outbound IKE traffic.
_IKE_CONCURRENCY = threading.BoundedSemaphore(2)
_IKE_SCAN_TIMEOUT = 300  # seconds per target, worst case for a responder that answers slowly

_CBOM_SOURCES = ("cbomkit", "cbom")
_INVENTORY_SOURCES = ("cbomkit", "cbom", "sbom")
_INVENTORY_TYPES = ("algorithm", "protocol", "certificate", "related-crypto-material", "library")


class IkeScanRequest(BaseModel):
    targets: List[str] = Field(..., min_length=1, max_length=10)
    probe_ikev1: bool = True


def _scan_one(scan: Callable[..., dict], host: str, port: int, probe_ikev1: bool) -> dict:
    with _IKE_CONCURRENCY:
        return scan(host, port, probe_ikev1=probe_ikev1)


def create_discovery_router(
    require_role: Callable[..., Any],
    refuse_unverified_targets: Callable[[Request, List[str]], None],
    org_of: Callable[[Request], str],
    db: Callable[[], Any],
    ensure_tables: Callable[[Any], None],
    limiter: Optional[Any] = None,
) -> APIRouter:
    router = APIRouter()

    def _limit(rule: str):
        if limiter is None:
            return lambda fn: fn
        return limiter.limit(rule)

    @router.post("/v1/scan/ike")
    @router.post("/scan/ike")
    @_limit("6/minute")
    def api_scan_ike(req: IkeScanRequest, request: Request):
        """Scan IKEv2 (IPsec VPN) responders: accepted transforms, RFC 9370 / ML-KEM key exchange."""
        require_role(request, allowed_roles=["viewer", "operator", "admin"],
                     action="scan.ike", resource_type="scan", resource_id="")
        from ike_scanner import parse_target, scan_ike

        targets = [t.strip() for t in req.targets[:10] if t and t.strip()]
        refuse_unverified_targets(request, targets)
        results = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            for t in targets:
                try:
                    host, port = parse_target(t)
                except ValueError:
                    results.append({"host": t, "error": "invalid target", "findings": []})
                    continue
                if not host or not 0 < port < 65536:
                    results.append({"host": t, "error": "invalid target", "findings": []})
                    continue
                # Each task carries this request's context, so the scanner knows whose scan it is.
                futures[pool.submit(contextvars.copy_context().run, _scan_one, scan_ike, host, port,
                                    req.probe_ikev1)] = t
            for fut, target in futures.items():
                try:
                    results.append(fut.result(timeout=_IKE_SCAN_TIMEOUT))
                except Exception as exc:
                    results.append({"host": target, "error": str(exc), "findings": []})
        return {"targets": len(results), "results": results}

    @router.post("/v1/cbom/import")
    @router.post("/cbom/import")
    @_limit("20/minute")
    async def api_cbom_import(
        request: Request,
        source: str = Query("cbomkit", description="cbomkit (default) or cbom"),
        filename: str = Query("", max_length=255, description="name to record for a JSON-body upload"),
    ):
        """Import a CycloneDX 1.6 CBOM (CBOMkit output) into the organization's crypto inventory.

        Accepts the document as a multipart upload (field "file") or as the raw JSON request body.
        """
        require_role(request, ["analyst", "admin", "owner"], action="cbom.import", resource_type="sbom")
        if source not in _CBOM_SOURCES:
            raise HTTPException(status_code=400, detail=f"source must be one of {', '.join(_CBOM_SOURCES)}")
        org_id = org_of(request)
        cap = sbom_import.MAX_IMPORT_BYTES
        try:
            declared = int(request.headers.get("content-length") or 0)
        except ValueError:
            declared = 0
        if declared > cap + 64 * 1024:  # allow for multipart framing
            raise HTTPException(status_code=413, detail=f"Upload exceeds the {cap}-byte import limit.")
        ctype = (request.headers.get("content-type") or "").lower()
        if ctype.startswith("multipart/form-data"):
            form = await request.form(max_files=1, max_fields=4)
            upload = form.get("file")
            if not isinstance(upload, (UploadFile, StarletteUploadFile)):
                raise HTTPException(status_code=400, detail="multipart upload needs a \"file\" field")
            name = upload.filename or "cbom.json"
            # Read one byte past the limit so an oversized file is refused, not truncated.
            data = await upload.read(cap + 1)
        else:
            name = filename or "cbom.json"
            chunks, total = [], 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > cap:
                    raise HTTPException(status_code=413, detail=f"Upload exceeds the {cap}-byte import limit.")
                chunks.append(chunk)
            data = b"".join(chunks)
        with db() as conn:
            ensure_tables(conn)
            try:
                return sbom_import.import_cbom(conn, org_id, name, data, source=source)
            except sbom_import.ImportTooLarge as exc:
                raise HTTPException(status_code=413, detail=str(exc))
            except sbom_import.SchemaInvalid as exc:
                raise HTTPException(status_code=422, detail={"message": str(exc), "errors": exc.errors})
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/v1/crypto-inventory")
    @router.get("/crypto-inventory")
    def api_crypto_inventory(
        request: Request,
        source: str = Query("", description="cbomkit, cbom or sbom"),
        asset_type: str = Query("", description="algorithm, protocol, certificate, related-crypto-material, library"),
        limit: int = Query(500, ge=1, le=5000),
    ):
        require_role(request, ["viewer", "analyst", "admin", "owner"], action="sbom.read", resource_type="sbom")
        if source and source not in _INVENTORY_SOURCES:
            raise HTTPException(status_code=400, detail=f"source must be one of {', '.join(_INVENTORY_SOURCES)}")
        if asset_type and asset_type not in _INVENTORY_TYPES:
            raise HTTPException(status_code=400, detail=f"asset_type must be one of {', '.join(_INVENTORY_TYPES)}")
        with db() as conn:
            ensure_tables(conn)
            assets = sbom_import.list_inventory(conn, org_of(request), source=source,
                                                asset_type=asset_type, limit=limit)
        return {"assets": assets, "count": len(assets)}

    return router
