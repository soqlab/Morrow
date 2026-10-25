"""SAML 2.0 SSO support for Morrow.

Activated when all three env vars are set:
  PQC_SAML_SP_ENTITY_ID      e.g., https://pqc.yourco.com
  PQC_SAML_IDP_METADATA_URL  e.g., https://sso.yourco.com/saml/metadata
  PQC_SAML_SP_ACS_URL        e.g., https://pqc.yourco.com/auth/saml/acs

Optional:
  PQC_SAML_ROLE_ATTRIBUTE    SAML attribute name that maps to PQC roles (default: role)
  PQC_SAML_NAMEID_AS_ACTOR   1 = use NameID as actor_id (default: 1)
  PQC_SAML_SESSION_HOURS     JWT session duration after SAML login (default: 8)

How it works:
  1. User visits /auth/saml/login -> redirected to IdP
  2. IdP posts assertion to /auth/saml/acs
  3. ACS validates assertion, issues a short-lived JWT signed with PQC_VAULT_MASTER_KEY
  4. Frontend receives the JWT and stores it for subsequent API calls
  5. Existing JWT middleware validates all subsequent requests
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

SAML_ENABLED = bool(
    os.getenv("PQC_SAML_SP_ENTITY_ID", "").strip()
    and os.getenv("PQC_SAML_IDP_METADATA_URL", "").strip()
    and os.getenv("PQC_SAML_SP_ACS_URL", "").strip()
)

SP_ENTITY_ID       = os.getenv("PQC_SAML_SP_ENTITY_ID", "").strip()
IDP_METADATA_URL   = os.getenv("PQC_SAML_IDP_METADATA_URL", "").strip()
SP_ACS_URL         = os.getenv("PQC_SAML_SP_ACS_URL", "").strip()
ROLE_ATTRIBUTE     = os.getenv("PQC_SAML_ROLE_ATTRIBUTE", "role").strip() or "role"
NAMEID_AS_ACTOR    = os.getenv("PQC_SAML_NAMEID_AS_ACTOR", "1").strip() in {"1", "true", "yes"}
SESSION_HOURS      = max(1, min(72, int(os.getenv("PQC_SAML_SESSION_HOURS", "8") or "8")))


def _saml_settings() -> Dict[str, Any]:
    """Build python3-saml settings dict from environment variables."""
    return {
        "strict": True,
        "debug": os.getenv("PQC_SAML_DEBUG", "0").strip() in {"1", "true"},
        "sp": {
            "entityId": SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": SP_ACS_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": IDP_METADATA_URL,
            "singleSignOnService": {
                "url": IDP_METADATA_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": "",  # Loaded from metadata URL at runtime
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameIdEncrypted": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm":    "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def _load_idp_metadata() -> Optional[str]:
    """Fetch and return IdP metadata XML, or None on failure."""
    import urllib.request
    try:
        with urllib.request.urlopen(IDP_METADATA_URL, timeout=10) as resp:
            return resp.read().decode("utf-8")
    except Exception:
        return None


def _auth_with_metadata(request_data: Dict[str, Any]):
    """Return a python3-saml OneLogin_Saml2_Auth instance loaded with live IdP metadata."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

    settings = _saml_settings()
    metadata_xml = _load_idp_metadata()
    if metadata_xml:
        try:
            idp_data = OneLogin_Saml2_IdPMetadataParser.parse(metadata_xml)
            settings["idp"] = idp_data.get("idp", settings["idp"])
        except Exception:
            pass

    return OneLogin_Saml2_Auth(request_data, old_settings=settings)


def _prepare_request(request) -> Dict[str, Any]:
    """Convert a FastAPI Request into the dict python3-saml expects."""
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", request.url.hostname),
        "server_port": request.url.port or (443 if request.url.scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},  # populated by ACS handler after reading body
    }


def _issue_jwt(actor_id: str, actor_role: str, org_id: str) -> str:
    """Issue a short-lived JWT signed with PQC_VAULT_MASTER_KEY."""
    import hmac as _hmac
    import hashlib as _hashlib

    key = os.getenv("PQC_VAULT_MASTER_KEY", "").strip().encode()
    if not key:
        raise RuntimeError("PQC_VAULT_MASTER_KEY is required for SAML JWT issuance")

    now = int(time.time())
    header  = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": actor_id,
        "role": actor_role,
        "org_id": org_id,
        "iat": now,
        "exp": now + SESSION_HOURS * 3600,
        "iss": SP_ENTITY_ID,
    }).encode()).rstrip(b"=").decode()

    signing_input = f"{header}.{payload}".encode()
    sig = _hmac.new(key, signing_input, _hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig_b64}"


def get_saml_login_url(request) -> Tuple[bool, str]:
    """Return (ok, redirect_url) for starting a SAML login flow."""
    if not SAML_ENABLED:
        return False, "SAML SSO is not configured"
    try:
        req_data = _prepare_request(request)
        auth = _auth_with_metadata(req_data)
        return True, auth.login()
    except Exception as exc:
        return False, str(exc)


def process_saml_acs(request, post_body: bytes) -> Tuple[bool, Dict[str, Any]]:
    """Process a SAML ACS (Assertion Consumer Service) POST.

    Returns (ok, result) where result contains jwt, actor_id, actor_role, org_id on success,
    or error on failure.
    """
    if not SAML_ENABLED:
        return False, {"error": "SAML SSO is not configured"}
    try:
        import urllib.parse

        post_data = dict(urllib.parse.parse_qsl(post_body.decode("utf-8", "ignore")))
        req_data = _prepare_request(request)
        req_data["post_data"] = post_data

        auth = _auth_with_metadata(req_data)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            return False, {"error": f"SAML assertion errors: {errors}", "reason": auth.get_last_error_reason()}

        if not auth.is_authenticated():
            return False, {"error": "SAML authentication failed"}

        name_id = auth.get_nameid() or ""
        attrs   = auth.get_attributes() or {}

        # Resolve actor_id
        actor_id = name_id if NAMEID_AS_ACTOR else str(
            attrs.get("email", [name_id])[0] or
            attrs.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", [name_id])[0] or
            name_id
        )

        # Resolve role
        raw_roles = attrs.get(ROLE_ATTRIBUTE, []) or attrs.get("groups", []) or []
        actor_role = "viewer"
        for r in (raw_roles if isinstance(raw_roles, list) else [raw_roles]):
            r_lower = str(r or "").strip().lower()
            if r_lower == "admin":
                actor_role = "admin"
                break
            if r_lower == "operator" and actor_role == "viewer":
                actor_role = "operator"

        # Resolve org_id
        org_raw = attrs.get("org_id", attrs.get("organization_id", []))
        org_id  = str(org_raw[0] if isinstance(org_raw, list) and org_raw else org_raw or "").strip()
        if not org_id:
            from db import DEFAULT_ORG_ID
            org_id = DEFAULT_ORG_ID

        jwt = _issue_jwt(actor_id, actor_role, org_id)
        return True, {
            "jwt": jwt,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "org_id": org_id,
            "session_expires_in_hours": SESSION_HOURS,
        }

    except Exception as exc:
        return False, {"error": str(exc)}


def saml_metadata_xml() -> Tuple[bool, str]:
    """Return the SP metadata XML for IdP registration."""
    if not SAML_ENABLED:
        return False, "SAML SSO is not configured"
    try:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        settings_obj = OneLogin_Saml2_Settings(settings=_saml_settings(), sp_validation_only=True)
        return True, settings_obj.get_sp_metadata()
    except Exception as exc:
        return False, str(exc)
