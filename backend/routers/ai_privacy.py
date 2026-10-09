"""Customer controls, not platform-owner impersonation. All endpoints are tenant scoped."""
from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Literal
import zipfile

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from db import current_organization_id
from services import ai_privacy as privacy
from services.ai_data_filter import canonical, minimize


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Policy(Strict):
    mode: Literal["off", "customer_hosted", "approved_external"]
    # "byo" is the destination the provider layer resolves: Azure OpenAI, Gemini,
    # any OpenAI-compatible endpoint, Ollama, or an operator's own module.
    provider: Literal["none", "local", "openai", "anthropic", "byo"]
    workflows: list[Literal["assistant", "intent", "remediation", "metadata_analysis"]] = Field(default_factory=list, max_length=4)
    free_text: bool = False
    receipt_retention_days: int = Field(default=90, ge=1, le=365)


class Proposal(Strict):
    policy: Policy
    expected_version: int = Field(ge=0)


class Approval(Proposal):
    review_hash: str = Field(min_length=64, max_length=64)


class Preview(Strict):
    purpose: Literal["metadata_analysis"] = "metadata_analysis"
    metadata: dict = Field(default_factory=dict)


class ProviderOverride(Strict):
    """This organization's own model provider. No "custom": a tenant must not be
    able to name a Python module for this process to import."""

    provider: Literal["anthropic", "openai", "azure-openai", "gemini",
                      "openai-compatible", "ollama", "builtin"]
    model: str = Field("", max_length=512)
    base_url: str = Field("", max_length=512)
    api_version: str = Field("", max_length=64)
    deployment: str = Field("", max_length=256)
    # Write-only. An empty value leaves whatever is already sealed in place, so
    # the model can be changed without the key being handed back out to re-submit.
    api_key: str = Field("", max_length=4096)
    headers: dict = Field(default_factory=dict)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(None, ge=256, le=200000)
    timeout: int | None = Field(None, ge=1, le=600)
    context_window: int | None = Field(None, ge=1024, le=10000000)
    price_input_per_mtok: float | None = Field(None, ge=0.0, le=10000.0)
    price_output_per_mtok: float | None = Field(None, ge=0.0, le=10000.0)
    tools_supported: bool | None = None
    stream_supported: bool | None = None


class ProviderTest(Strict):
    prompt: str = Field("Reply with the single word: ready.", min_length=1, max_length=500)


class Evidence(Strict):
    expected_version: int = Field(ge=1)
    metadata: dict


def metadata_payload(metadata):
    if len(canonical(metadata)) > 200000:
        raise privacy.PrivacyError("Metadata too large", 413)
    clean = minimize(metadata)
    if not clean:
        raise privacy.PrivacyError("No supported cryptographic metadata supplied", 422)
    return {"messages": [
        {"role": "system", "content": "Analyze approved cryptographic metadata. State missing evidence. Do not execute actions."},
        {"role": "user", "content": canonical(clean)}], "max_tokens": 2000}


class BoundedRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()
        async def handle(request):
            # Bound chunked input before FastAPI parses JSON; Content-Length is not trusted.
            if request.method in {"POST", "PUT"}:
                parts, length = [], 0
                async for chunk in request.stream():
                    length += len(chunk)
                    if length > 262144:
                        raise HTTPException(413, "Data Control input exceeds 256 KiB")
                    parts.append(chunk)
                request._body = b"".join(parts)
            return await original(request)
        return handle


def _forced_builtin() -> bool:
    """True when the deployment forbids every external model call."""
    from services.llm import config as llm_config
    return llm_config.disabled()


def create_ai_privacy_router(require_role):
    router = APIRouter(prefix="/ai-control", tags=["Customer data control"], route_class=BoundedRoute)

    def invoke(request, response, action, fn, *args, admin=False):
        response.headers["Cache-Control"] = "no-store"
        actor = require_role(request, allowed_roles=["admin"] if admin else ["viewer", "operator", "admin"],
                             action="ai_privacy." + action, resource_type="organization", resource_id="")
        org = str(getattr(request.state, "org_id", None) or current_organization_id())
        actor_token = privacy.ACTOR.set(str(actor["actor_id"]))
        try:
            return fn(org, *args, **({"actor": actor["actor_id"]} if action in {"approve", "stop", "provider_set", "provider_clear"} else {}))
        except privacy.PrivacyError as exc:
            raise HTTPException(exc.status, str(exc)) from None
        except Exception:
            raise HTTPException(503, "Data Control storage or approved model is unavailable; no fallback was attempted") from None
        finally:
            privacy.ACTOR.reset(actor_token)

    @router.get("/status")
    def status(request: Request, response: Response):
        return invoke(request, response, "read", privacy.status)

    @router.post("/policy/review")
    def review(body: Proposal, request: Request, response: Response):
        return invoke(request, response, "review", lambda org: privacy.review(body.policy.model_dump(), body.expected_version), admin=True)

    @router.put("/policy")
    def approve(body: Approval, request: Request, response: Response):
        return invoke(request, response, "approve", privacy.change_policy, body.policy.model_dump(), body.expected_version, body.review_hash, admin=True)

    @router.post("/stop")
    def stop(request: Request, response: Response):
        return invoke(request, response, "stop", privacy.stop, admin=True)

    @router.post("/preview")
    def preview(body: Preview, request: Request, response: Response):
        return invoke(request, response, "preview", lambda org: privacy.preview_completion(org, body.purpose, metadata_payload(body.metadata)))

    @router.get("/events")
    def events(request: Request, response: Response, limit: int = Query(100, ge=1, le=1000), before: float | None = None):
        def read(org):
            items = privacy.events(org, limit, before)
            return {"items": items, "next_before": items[-1]["data"]["created_at"] if len(items) == limit else None,
                    "scope": "Signed gateway observations; not proof of provider deletion, training behavior or complete network coverage"}
        return invoke(request, response, "events", read)

    @router.get("/export")
    def export(request: Request, response: Response, before: float | None = None):
        def bundle(org):
            s = privacy.status(org)
            items = privacy.events(org, 1000, before)
            return {"receipts": items, "public_key": s["public_key"], "policy": s["policy"],
                    "next_before": items[-1]["data"]["created_at"] if len(items) == 1000 else None,
                    "verification": "Pin the public key through a trusted channel; signatures attest these records, not absence of other transfers."}
        result = invoke(request, response, "export", bundle)
        return Response(json.dumps(result), media_type="application/json", headers={"Cache-Control": "no-store", "Content-Disposition": "attachment; filename=ai-processing-receipts.json"})

    @router.post("/analyze-metadata")
    def analyze(body: Evidence, request: Request, response: Response):
        def call(org):
            conf = privacy.authorize(org, "metadata_analysis")
            if conf["version"] != body.expected_version:
                raise privacy.PrivacyError("Policy changed since the customer-side review; review again", 409)
            result = privacy.openai_completion(org, "metadata_analysis", metadata_payload(body.metadata), expected_version=body.expected_version)
            return {"result": result, "policy_version": conf["version"], "receipts_url": "/ai-control/events"}
        return invoke(request, response, "analyze", call)

    # ── Model provider ───────────────────────────────────────────────────────
    # Which model would answer, what it can do, and a way to prove it works.
    # Everything here is tenant scoped: a customer reads and sets only their own.

    @router.get("/provider")
    def provider_status(request: Request, response: Response):
        def read(org):
            from services import ai_agent
            from services.llm import capability_matrix, custom, org_config
            return {**ai_agent.active_provider(org),
                    "organization_override": org_config.describe(org),
                    "capability_matrix": capability_matrix(),
                    "custom_contract": custom.describe_contract(),
                    "scope": "Configuration as this process resolved it. Reachability is only "
                             "proven by a test prompt."}
        return invoke(request, response, "provider_read", read)

    @router.put("/provider")
    def provider_set(body: ProviderOverride, request: Request, response: Response):
        def write(org, actor=""):
            from services.llm import org_config
            if _forced_builtin():
                raise privacy.PrivacyError(
                    "This deployment makes no external model calls (PQC_LLM_DISABLED=1). "
                    "An organization setting cannot override that.", 409)
            try:
                return org_config.set_override(org, body.model_dump(exclude_none=True), actor=actor)
            except org_config.OverrideError as exc:
                raise privacy.PrivacyError(str(exc), getattr(exc, "status", 422)) from None
        return invoke(request, response, "provider_set", write, admin=True)

    @router.delete("/provider")
    def provider_clear(request: Request, response: Response):
        def clear(org, actor=""):
            from services.llm import org_config
            return org_config.clear_override(org)
        return invoke(request, response, "provider_clear", clear, admin=True)

    @router.post("/provider/test")
    def provider_test(body: ProviderTest, request: Request, response: Response):
        """Send one short prompt through the whole path and report what happened.

        It crosses the same data boundary as a real question: the organization's
        Data Control policy must permit the assistant workflow, the destination is
        the pinned one, and a receipt is written.
        """
        def run(org):
            from services import llm
            from services.llm import usage as llm_usage

            instance, notes = llm.resolve(org)
            caps = instance.capabilities()
            result = {"provider": caps.provider, "model": caps.model, "tools": caps.tools,
                      "streaming": caps.streaming, "network": caps.network,
                      "endpoint": caps.endpoint, "notes": notes,
                      "prompt": body.prompt}
            conv = instance.start("You are a configuration self-test. Answer in under 10 words.",
                                  [], body.prompt)
            try:
                completion = instance.complete(conv, None, org_id=org, purpose="assistant")
            except llm.LLMError as exc:
                llm_usage.record(org, caps.provider, caps.model, {}, purpose="provider_test",
                                 outcome=exc.kind)
                return {**result, "ok": False, "reply": "", "error": exc.as_dict()}
            llm_usage.record(org, completion.provider or caps.provider, completion.model or caps.model,
                             completion.usage, purpose="provider_test",
                             latency_ms=completion.latency_ms, outcome="ok")
            return {**result, "ok": True, "reply": completion.text,
                    "answered_by_model": completion.model or caps.model,
                    "usage": completion.usage.as_dict(), "latency_ms": completion.latency_ms,
                    "stop_reason": completion.stop_reason}
        return invoke(request, response, "provider_test", run, admin=True)

    @router.get("/customer-kit")
    def kit(request: Request, response: Response):
        invoke(request, response, "kit", lambda org: None)
        root = Path(__file__).resolve().parents[1]
        files = {"ai_data_filter.py": root / "services/ai_data_filter.py",
                 "customer_data_gate.py": root / "customer_data_control/customer_data_gate.py",
                 "verify_ai_receipts.py": root / "customer_data_control/verify_ai_receipts.py",
                 "README.md": root / "customer_data_control/README.md"}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, path in files.items():
                archive.writestr(name, path.read_bytes())
        return Response(buffer.getvalue(), media_type="application/zip", headers={"Cache-Control": "no-store", "Content-Disposition": "attachment; filename=customer-data-control.zip"})

    return router
