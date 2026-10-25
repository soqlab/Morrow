"""Tenant-scoped AI authorization and signed metadata receipts. Fail closed before network I/O."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.request
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

import db_feature_store as store
from services.ai_data_filter import canonical, sanitize_payload, SECRET
from vault_crypto import decrypt_secret, encrypt_secret

_schema_lock = threading.Lock()
_ready = set()
WORKFLOWS = {"assistant", "intent", "remediation", "metadata_analysis"}
# Destinations an organization may approve under "approved_external". "byo" is the one the
# provider layer resolves (Azure, Gemini, any OpenAI-compatible endpoint, Ollama, a custom
# module); its url and model are pinned into the approved policy like any other.
APPROVED_EXTERNAL = {"openai", "anthropic", "byo"}
# A key pasted into a base URL would be copied verbatim into the signed receipt and
# into every operator screen that shows the pinned destination.
_SECRET_IN_URL = re.compile(r"(?:api[_-]?key|access[_-]?token|apikey|key|token|secret|password)=", re.I)
READ_TOOLS = {"get_org_posture"}
ACTOR = ContextVar("ai_data_control_actor", default="unknown")


class PrivacyError(ValueError):
    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status


def init_tables():
    identity = (store.dialect(), store._feature_dsn() if store.postgres_enabled() else store._sqlite_path())
    with _schema_lock:
        if identity in _ready:
            return
        with store.feature_conn() as conn:
            present = False
            if store.postgres_enabled():
                row = conn.execute("SELECT to_regclass('public.ai_privacy_policy'),to_regclass('public.ai_privacy_events'),to_regclass('public.ai_privacy_jobs')").fetchone()
                present = all(row[i] for i in range(3))
            if not present:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS ai_privacy_policy (
                        organization_id TEXT PRIMARY KEY, version INTEGER NOT NULL, config TEXT NOT NULL,
                        key_sealed TEXT NOT NULL, public_key TEXT NOT NULL, head_hash TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS ai_privacy_events (
                        id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
                        event_type TEXT NOT NULL, receipt TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_ai_privacy_events_org_time ON ai_privacy_events(organization_id,created_at);
                    CREATE TABLE IF NOT EXISTS ai_privacy_jobs (
                        id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
                        status TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_ai_privacy_jobs_org ON ai_privacy_jobs(organization_id,status);
                """)
                conn.commit()
        _ready.add(identity)


@contextmanager
def connection(org, write=False):
    if not org or org == "*":
        raise PrivacyError("A verified organization is required")
    init_tables()
    with store.feature_conn() as conn:
        if store.postgres_enabled():
            conn.execute("SELECT set_config('app.current_organization_id',?,true)", (org,))
        elif write:
            conn.execute("BEGIN IMMEDIATE")
        yield conn


def default_policy():
    return {"mode": "off", "provider": "none", "workflows": [], "free_text": False, "receipt_retention_days": 90}


def _row(conn, org, lock=False):
    suffix = " FOR UPDATE" if lock and store.postgres_enabled() else ""
    return conn.execute("SELECT * FROM ai_privacy_policy WHERE organization_id=?" + suffix, (org,)).fetchone()


def policy(org):
    with connection(org) as conn:
        row = _row(conn, org)
    return {"organization_id": org, "version": int(row["version"]) if row else 0,
            **(json.loads(row["config"]) if row else default_policy())}


def _byo_destination(org=None):
    """The destination the provider layer resolves for this deployment or tenant.

    "byo" is the Data Control destination for every provider an operator brings
    themselves -- Azure OpenAI, Gemini, any OpenAI-compatible endpoint, Ollama,
    or their own module. The url and model land in the approved policy exactly
    as the first-party destinations do, so changing either still forces the
    customer to review and reapprove. See docs/AI_PROVIDERS.md.
    """
    try:
        from services.llm import registry as llm_registry
        provider, _ = llm_registry.resolve(str(org or "") if org and org != "*" else "")
        caps = provider.capabilities()
        if not caps.network or not caps.endpoint:
            return {"url": "", "configured": False, "model": caps.model or "", "provider": provider.id}
        parsed = urlsplit(caps.endpoint)
        if parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
            return {"url": "", "configured": False, "model": caps.model or "", "provider": provider.id}
        return {"url": caps.endpoint, "configured": bool(caps.model) and provider.check().get("ready", False),
                "model": caps.model or "", "provider": provider.id}
    except Exception:
        return {"url": "", "configured": False, "model": "", "provider": ""}


def destinations(org=None):
    local = os.getenv("MORROW_AI_LOCAL_URL", "").strip()
    try:
        parsed = urlsplit(local)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            local = ""
    except ValueError:
        local = ""
    return {
        "openai": {"url": "https://api.openai.com/v1/chat/completions", "configured": bool(os.getenv("OPENAI_API_KEY", "").strip()),
                   "model": os.getenv("OPENAI_AGENT_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-4o-mini"},
        "anthropic": {"url": "https://api.anthropic.com/v1/messages", "configured": bool(os.getenv("ANTHROPIC_API_KEY", "").strip()),
                      "model": os.getenv("ANTHROPIC_AGENT_MODEL") or "claude-opus-5"},
        "local": {"url": local, "configured": bool(local and os.getenv("MORROW_AI_LOCAL_MODEL")),
                  "model": os.getenv("MORROW_AI_LOCAL_MODEL", "")},
        "byo": _byo_destination(org),
    }


def _destination(provider, org=None):
    destination = destinations(org).get(provider)
    if not destination or not destination["configured"]:
        raise PrivacyError("The approved model destination is not configured; no fallback is permitted", 503)
    parsed = urlsplit(destination["url"])
    # Azure OpenAI puts the required api-version in the query string, so a query is
    # part of the contract for a brought-your-own destination; credentials in the
    # URL are still refused, for every provider.
    allow_query = provider == "byo"
    if parsed.username or parsed.password or parsed.fragment or not parsed.hostname or (parsed.query and not allow_query):
        raise PrivacyError("Invalid configured model destination", 503)
    if provider == "byo":
        if parsed.scheme not in {"http", "https"}:
            raise PrivacyError("A brought-your-own model destination must be HTTP or HTTPS", 503)
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise PrivacyError("A brought-your-own model destination requires HTTPS, except on loopback", 503)
        if _SECRET_IN_URL.search(destination["url"]):
            raise PrivacyError("A model destination must not carry a credential in its URL", 503)
    if provider == "local":
        if os.getenv("MORROW_AI_DEPLOYMENT_LOCATION") != "customer":
            raise PrivacyError("Customer-hosted mode requires an operator-configured customer deployment", 409)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
            raise PrivacyError("Customer model requires HTTPS, except on loopback", 503)
    return destination


def review(config, expected_version, org=None):
    if set(config) != set(default_policy()):
        raise PrivacyError("Unsupported policy fields", 422)
    mode, provider = config["mode"], config["provider"]
    if mode not in {"off", "customer_hosted", "approved_external"} or type(config["free_text"]) is not bool:
        raise PrivacyError("Invalid AI mode or text permission", 422)
    if not isinstance(config["workflows"], list) or not set(config["workflows"]).issubset(WORKFLOWS):
        raise PrivacyError("Unsupported workflow", 422)
    if type(config["receipt_retention_days"]) is not int or not 1 <= config["receipt_retention_days"] <= 365:
        raise PrivacyError("Receipt retention must be 1-365 days", 422)
    if (mode == "off" and provider != "none") or (mode == "customer_hosted" and provider != "local") or (mode == "approved_external" and provider not in APPROVED_EXTERNAL):
        raise PrivacyError("Mode and destination do not match", 422)
    clean = {**config, "workflows": sorted(set(config["workflows"]))}
    destination = _destination(provider, org) if mode != "off" else {"url": "none", "model": "none"}
    bound = {"config": clean, "expected_version": expected_version, "destination": destination["url"], "model": destination["model"]}
    return {**bound, "review_hash": hashlib.sha256(canonical(bound).encode()).hexdigest(),
            "notice": "Free text may include code, identifiers or personal data; credential-pattern checks are not complete DLP." if clean["free_text"] else "Only allowlisted cryptographic metadata; arbitrary text and identifiers withheld."}


def _ensure(conn, org):
    row = _row(conn, org, lock=True)
    if row:
        return row
    private = Ed25519PrivateKey.generate()
    secret = base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    conn.execute("INSERT INTO ai_privacy_policy (organization_id,version,config,key_sealed,public_key,head_hash) VALUES (?,0,?,?,?,'') ON CONFLICT (organization_id) DO NOTHING",
                 (org, canonical(default_policy()), encrypt_secret(secret), public))
    return _row(conn, org, lock=True)


def _private(row):
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(decrypt_secret(row["key_sealed"])))


def _event(conn, org, row, kind, **fields):
    last = conn.execute("SELECT MAX(created_at) FROM ai_privacy_events WHERE organization_id=?", (org,)).fetchone()[0]
    created = max(time.time(), float(last or 0) + 0.000001)
    data = {"id": uuid.uuid4().hex, "organization_id": org, "created_at": created, "event_type": kind,
            "policy_version": int(row["version"]), "previous_hash": row["head_hash"], **fields}
    signature = base64.b64encode(_private(row).sign(canonical(data).encode())).decode()
    receipt = {"data": data, "signature": signature, "public_key": row["public_key"], "algorithm": "Ed25519"}
    head = hashlib.sha256(canonical(receipt).encode()).hexdigest()
    conn.execute("INSERT INTO ai_privacy_events (id,organization_id,created_at,event_type,receipt) VALUES (?,?,?,?,?)",
                 (data["id"], org, data["created_at"], kind, canonical(receipt)))
    conn.execute("UPDATE ai_privacy_policy SET head_hash=? WHERE organization_id=?", (head, org))
    return receipt


def change_policy(org, config, version, review_hash, actor):
    proposal = review(config, version, org)
    if not hmac.compare_digest(str(review_hash), proposal["review_hash"]):
        raise PrivacyError("Review the current destination, model and data policy before approving", 409)
    # Pin the deployment target too; an environment change requires customer reapproval.
    approved = {**proposal["config"], "approved_destination": proposal["destination"], "approved_model": proposal["model"]}
    with connection(org, write=True) as conn:
        row = _ensure(conn, org)
        if int(row["version"]) != version:
            raise PrivacyError("Policy changed; review it again", 409)
        conn.execute("UPDATE ai_privacy_policy SET version=version+1,config=? WHERE organization_id=?", (canonical(approved), org))
        conn.execute("UPDATE ai_privacy_jobs SET status='cancelled' WHERE organization_id=? AND status='queued'", (org,))
        row = _row(conn, org, lock=True)
        _event(conn, org, row, "policy.approved", actor=str(actor)[:128], mode=config["mode"], provider=config["provider"],
               free_text=config["free_text"], workflows=proposal["config"]["workflows"], destination=proposal["destination"], model=proposal["model"])
        conn.commit()
    return policy(org)


def stop(org, actor):
    # Revocation must succeed even if a receipt signing key is unavailable.
    with connection(org, write=True) as conn:
        row = _row(conn, org, lock=True)
        if not row:
            return {"policy": {"organization_id": org, "version": 0, **default_policy()}, "cancelled": 0, "receipt_recorded": False, "already_off": True}
        conf = json.loads(row["config"])
        conf.update(mode="off", provider="none", workflows=[])
        conn.execute("UPDATE ai_privacy_policy SET version=version+1,config=? WHERE organization_id=?", (canonical(conf), org))
        cancelled = conn.execute("UPDATE ai_privacy_jobs SET status='cancelled' WHERE organization_id=? AND status='queued'", (org,)).rowcount
        conn.commit()
    recorded = True
    try:
        with connection(org, write=True) as conn:
            row = _row(conn, org, lock=True)
            _event(conn, org, row, "ai.stopped", actor=str(actor)[:128], cancelled=cancelled)
            conn.commit()
    except Exception:
        recorded = False
    return {"policy": policy(org), "cancelled": cancelled, "receipt_recorded": recorded,
            "notice": "Queued/new dispatch blocked. Requests already dispatching or transmitted cannot be recalled."}


def authorize(org, purpose, provider=None):
    conf = policy(org)
    if conf["mode"] == "off":
        raise PrivacyError("AI is off for this organization. An organization admin must approve a Data Control policy.")
    if purpose not in conf["workflows"]:
        raise PrivacyError("This AI workflow is not approved")
    if provider and conf["provider"] != provider:
        raise PrivacyError("This provider is not approved; fallback is prohibited")
    dest = _destination(conf["provider"], org)
    if dest["url"] != conf.get("approved_destination") or dest["model"] != conf.get("approved_model"):
        raise PrivacyError("Model destination changed; customer reapproval is required", 409)
    return conf


def _clean(payload, conf):
    clean = sanitize_payload(payload, conf["free_text"])
    clean["model"] = conf["approved_model"]
    if conf["provider"] == "openai":
        clean["store"] = False
    tools = clean.get("tools", [])
    clean_tools = [t for t in tools if (t.get("name") or t.get("function", {}).get("name")) in READ_TOOLS]
    if clean_tools:
        clean["tools"] = clean_tools
    else:
        clean.pop("tools", None)
        clean.pop("tool_choice", None)
    return clean


def preview(org, purpose, payload, expected_version=None):
    conf = authorize(org, purpose)
    if expected_version is not None and conf["version"] != expected_version:
        raise PrivacyError("Policy changed since approval; review again", 409)
    try:
        clean = _clean(payload, conf)
    except ValueError as exc:
        raise PrivacyError(str(exc), 422) from None
    return {"policy_version": conf["version"], "destination": conf["approved_destination"], "payload": clean,
            "sent": False, "scope": "This preview input reached this platform. For local-only review use the customer-side filter."}


def receipt_valid(receipt, trusted_public_key):
    try:
        if receipt["public_key"] != trusted_public_key:
            return False
        Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted_public_key, validate=True)).verify(
            base64.b64decode(receipt["signature"], validate=True), canonical(receipt["data"]).encode())
        return True
    except Exception:
        return False


def events(org, limit=100, before=None):
    conf = policy(org)
    cutoff = time.time() - conf["receipt_retention_days"] * 86400
    with connection(org) as conn:
        rows = conn.execute("SELECT receipt FROM ai_privacy_events WHERE organization_id=? AND created_at>=? AND created_at<? ORDER BY created_at DESC,id DESC LIMIT ?",
                            (org, cutoff, before or time.time() + 1, min(1000, max(1, limit)))).fetchall()
    return [json.loads(row["receipt"]) for row in rows]


def status(org):
    conf = policy(org)
    with connection(org) as conn:
        row = _row(conn, org)
        latest = conn.execute("SELECT created_at FROM ai_privacy_events WHERE organization_id=? AND event_type='request.authorized' ORDER BY created_at DESC LIMIT 1", (org,)).fetchone()
    last = float(latest[0]) if latest else None
    return {"policy": conf, "destinations": destinations(org), "public_key": row["public_key"] if row else None,
            "last_enforcement_check": last, "observation": "recent_dispatch" if last and time.time() - last < 300 else "unknown_or_stale",
            "boundary_location": os.getenv("MORROW_AI_DEPLOYMENT_LOCATION", "platform"),
            "boundary_location_basis": "operator-declared, not remotely attested",
            "provider_retention": "not_verified", "provider_training": "not_verified", "network_bypass_prevention": "deployment_firewall_required",
            "scope": "Only calls through this application gateway; not other software, CDN traffic or provider internals."}


def dispatch(org, purpose, provider, payload, invoke, expected_version=None):
    try:
        conf = authorize(org, purpose, provider)
        if expected_version is not None and conf["version"] != expected_version:
            raise PrivacyError("Policy changed since approval; review again", 409)
        clean = _clean(payload, conf)
    except (PrivacyError, ValueError) as exc:
        try:
            with connection(org, write=True) as conn:
                row = _ensure(conn, org)
                _event(conn, org, row, "request.blocked", purpose=purpose, actor=str(ACTOR.get())[:128], reason="policy_or_content_rejected")
                conn.commit()
        except Exception:
            pass  # A failed denial receipt never permits network I/O.
        raise PrivacyError(str(exc), getattr(exc, "status", 422)) from None
    job = uuid.uuid4().hex
    with connection(org, write=True) as conn:
        row = _row(conn, org, lock=True)
        if row is None or int(row["version"]) != conf["version"]:
            raise PrivacyError("Policy changed before dispatch", 409)
        conn.execute("INSERT INTO ai_privacy_jobs (id,organization_id,policy_version,status,created_at) VALUES (?,?,?,'queued',?)",
                     (job, org, conf["version"], time.time()))
        conn.commit()
    # This transaction is the dispatch boundary; a stop cancels queued jobs and all later rounds.
    with connection(org, write=True) as conn:
        row = _row(conn, org, lock=True)
        current = conn.execute("SELECT status FROM ai_privacy_jobs WHERE id=? AND organization_id=?", (job, org)).fetchone()
        if int(row["version"]) != conf["version"] or not current or current[0] != "queued":
            raise PrivacyError("Request cancelled by policy change", 409)
        active = conn.execute("SELECT COUNT(*) FROM ai_privacy_jobs WHERE organization_id=? AND status='dispatching' AND created_at>?", (org, time.time() - 600)).fetchone()[0]
        if active >= 2:
            conn.execute("UPDATE ai_privacy_jobs SET status='capacity_rejected' WHERE id=? AND organization_id=?", (job, org))
            conn.commit()
            raise PrivacyError("Two AI requests are already running for this organization", 429)
        signing_secret = _private(row).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        digest_key = hmac.new(signing_secret, b"Post-quantum AI payload digest v1", hashlib.sha256).digest()
        request_digest = hmac.new(digest_key, canonical(clean).encode(), hashlib.sha256).hexdigest()
        _event(conn, org, row, "request.authorized", job_id=job, purpose=purpose, provider=provider,
               actor=str(ACTOR.get())[:128],
               destination=conf["approved_destination"], model=clean["model"], request_digest=request_digest,
               digest_algorithm="HMAC-SHA256", bytes=len(canonical(clean).encode()), free_text=conf["free_text"])
        conn.execute("UPDATE ai_privacy_jobs SET status='dispatching' WHERE id=? AND organization_id=?", (job, org))
        conn.commit()
    outcome = "failed_or_delivery_unknown"
    try:
        response = invoke(clean)
        if SECRET.search(canonical(response)):
            outcome = "output_blocked"
            raise PrivacyError("Potential credential in model output; response withheld", 502)
        outcome = "response_received"
    finally:
        with connection(org, write=True) as conn:
            row = _row(conn, org, lock=True)
            _event(conn, org, row, "request." + outcome, job_id=job, authorized_policy_version=conf["version"])
            conn.execute("UPDATE ai_privacy_jobs SET status=? WHERE id=? AND organization_id=?", (outcome, job, org))
            conn.commit()
    return response


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise PrivacyError("Model redirects are not approved", 502)


def _completion_payload(conf, payload):
    if conf["provider"] != "anthropic":
        return payload
    # Preview and dispatch share the same translation, including the output limit.
    return {"model": conf["approved_model"],
            "system": "\n".join(str(m["content"]) for m in payload["messages"] if m["role"] == "system"),
            "max_tokens": min(4000, max(1, int(payload.get("max_tokens", 4000)))),
            "messages": [m for m in payload["messages"] if m["role"] != "system"]}


def preview_completion(org, purpose, payload):
    conf = authorize(org, purpose)
    return preview(org, purpose, _completion_payload(conf, payload), expected_version=conf["version"])


def openai_completion(org, purpose, payload, timeout=60, expected_version=None):
    conf = authorize(org, purpose)
    if expected_version is not None and conf["version"] != expected_version:
        raise PrivacyError("Policy changed since approval; review again", 409)
    provider = conf["provider"]
    if provider == "anthropic":
        # Legacy code-generation/intent callers use the OpenAI response shape, without tools.
        import anthropic
        request = _completion_payload(conf, payload)
        def call(clean):
            with anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], base_url="https://api.anthropic.com", timeout=min(180, max(1, timeout)), max_retries=0,
                                     http_client=anthropic.DefaultHttpxClient(trust_env=False, follow_redirects=False)) as client:
                return client.messages.create(**clean).model_dump()
        response = dispatch(org, purpose, provider, request, call, expected_version=conf["version"])
        return {"choices": [{"message": {"content": "".join(b.get("text", "") for b in response.get("content", []) if b.get("type") == "text")}}]}
    if provider == "byo":
        # The provider layer owns the wire format for everything an operator brings
        # themselves. It dispatches through this module, so the boundary, the receipt
        # and the output credential scan are identical. Provider-specific response
        # hints (OpenAI's response_format, for one) are not forwarded; callers that
        # want JSON keep their deterministic fallback. See docs/AI_PROVIDERS.md.
        from services.llm import base as llm_base, registry as llm_registry
        instance, _notes = llm_registry.resolve(org)
        if not instance.capabilities().network:
            raise PrivacyError("The approved model destination is not configured; no fallback is permitted", 503)
        conversation = llm_base.Conversation(system="", messages=list(payload.get("messages") or []))
        try:
            completion = instance.complete(conversation, None, org_id=org, purpose=purpose,
                                           policy_version=conf["version"])
        except llm_base.LLMError as exc:
            raise PrivacyError(exc.operator_text(), 502 if exc.kind != "blocked" else (exc.status or 403)) from None
        return {"choices": [{"message": {"content": completion.text},
                             "finish_reason": completion.stop_reason}],
                "model": completion.model, "usage": completion.usage.as_dict()}
    destination = _destination(provider)
    def call(clean):
        headers = {"Content-Type": "application/json"}
        key = os.getenv("OPENAI_API_KEY") if provider == "openai" else os.getenv("MORROW_AI_LOCAL_API_KEY")
        if key:
            headers["Authorization"] = "Bearer " + key
        req = urllib.request.Request(destination["url"], data=canonical(clean).encode(), headers=headers, method="POST")
        # No inherited proxy may receive the model credential or bypass the pinned destination.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(req, timeout=min(180, max(1, timeout))) as res:
            raw = res.read(2000001)
            if len(raw) > 2000000:
                raise PrivacyError("Model response exceeds the boundary limit", 502)
            return json.loads(raw)
    return dispatch(org, purpose, provider, payload, call, expected_version=conf["version"])


def prune(org):
    conf = policy(org)
    with connection(org, write=True) as conn:
        cutoff = time.time() - conf["receipt_retention_days"] * 86400
        conn.execute("DELETE FROM ai_privacy_events WHERE id IN (SELECT id FROM ai_privacy_events WHERE organization_id=? AND created_at<? ORDER BY created_at LIMIT 5000)", (org, cutoff))
        conn.execute("DELETE FROM ai_privacy_jobs WHERE id IN (SELECT id FROM ai_privacy_jobs WHERE organization_id=? AND created_at<? LIMIT 5000)", (org, cutoff))
        conn.commit()
