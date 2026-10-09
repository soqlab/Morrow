"""Platform operator credentials: who is calling the vendor admin API, and with what ceiling.

Two kinds of credential authenticate /platform/*:

  * Named operators (preferred). PQC_PLATFORM_OPERATORS is a JSON list of
    {"name": "alice", "role": "operator", "key_sha256": "<64 hex>"}. Only the SHA-256
    of each key is configured, so the environment never holds a usable secret for
    them. The role is bound to the key: the caller cannot raise it, and a request
    without an x-platform-admin-role header runs with exactly that role. The header
    may still narrow it (an owner can look at the portal as an auditor).

  * The legacy shared key, PQC_PLATFORM_ADMIN_KEY. It keeps working so existing
    scripts and the go-live gate are not broken. Its ceiling is
    PQC_PLATFORM_ADMIN_KEY_ROLE (owner when unset, which is what it has always been).
    Because anyone holding a shared key is anonymous, a request that does not say
    which role it wants gets the least-privileged role (auditor) rather than the
    ceiling; write calls must ask for owner/operator explicitly. Unknown role names
    are rejected with 400 instead of silently becoming owner.

Every admin audit event records the resolved operator name (see CURRENT_OPERATOR).

Generate a named operator credential with:

    python -m services.platform_operators --name alice --role operator
"""

from __future__ import annotations

import argparse
import contextvars
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

ROLE_ORDER = ("owner", "operator", "support", "auditor")
ROLE_RANK = {"auditor": 1, "support": 2, "operator": 3, "owner": 4}
ROLE_ALIASES = {
    "platform_admin": "owner",
    "admin": "owner",
    "owner": "owner",
    "operator": "operator",
    "support": "support",
    "auditor": "auditor",
    "viewer": "auditor",
    "read_only": "auditor",
    "readonly": "auditor",
}
READ_ROLES = frozenset(ROLE_RANK)
WRITE_ROLES = frozenset({"owner", "operator"})
OWNER_ROLES = frozenset({"owner"})
LEAST_PRIVILEGED_ROLE = "auditor"
LEGACY_OPERATOR_NAME = "platform-admin"

#: The operator resolved by the current request's platform-admin guard. The guard runs inside the
#: endpoint, in the same context as the audit write that follows it, so the audit trail can name the
#: operator without every call site passing it along.
CURRENT_OPERATOR: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "pqc_platform_operator", default=None
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,79}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CLAIMED_USER_RE = re.compile(r"[^A-Za-z0-9._@+-]")
_CACHE: Dict[str, Any] = {"raw": None, "operators": [], "errors": []}


class RoleError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def normalize_role(value: Any) -> Optional[str]:
    return ROLE_ALIASES.get(str(value or "").strip().lower())


def legacy_key_role() -> str:
    raw = str(os.getenv("PQC_PLATFORM_ADMIN_KEY_ROLE") or "").strip()
    if not raw:
        return "owner"
    role = normalize_role(raw)
    if not role:
        # Fail closed: a typo must not leave the shared key with more power than intended.
        logger.warning("[platform-operators] PQC_PLATFORM_ADMIN_KEY_ROLE is not a known role; using auditor")
        return LEAST_PRIVILEGED_ROLE
    return role


def load_operators() -> List[Dict[str, str]]:
    raw = os.getenv("PQC_PLATFORM_OPERATORS", "") or ""
    if raw == _CACHE["raw"]:
        return _CACHE["operators"]
    operators: List[Dict[str, str]] = []
    errors: List[str] = []
    text = raw.strip()
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = []
            errors.append("PQC_PLATFORM_OPERATORS is not valid JSON; no named operators loaded.")
        if not isinstance(data, list):
            errors.append("PQC_PLATFORM_OPERATORS must be a JSON list.")
            data = []
        seen = set()
        for index, entry in enumerate(data):
            if not isinstance(entry, dict):
                errors.append(f"Operator entry {index} is not an object.")
                continue
            name = str(entry.get("name") or "").strip()
            role = normalize_role(entry.get("role"))
            digest = str(entry.get("key_sha256") or "").strip().lower()
            if not _NAME_RE.match(name):
                errors.append(f"Operator entry {index} has an invalid name.")
                continue
            if not role:
                errors.append(f"Operator '{name}' has an unknown role.")
                continue
            if not _HEX64_RE.match(digest):
                errors.append(f"Operator '{name}' needs key_sha256 as 64 lowercase hex characters.")
                continue
            if name.lower() in seen:
                errors.append(f"Operator '{name}' is listed more than once.")
                continue
            seen.add(name.lower())
            operators.append({"name": name, "role": role, "key_sha256": digest})
    for message in errors:
        logger.warning("[platform-operators] %s", message)
    _CACHE.update(raw=raw, operators=operators, errors=errors)
    return operators


def configuration_errors() -> List[str]:
    load_operators()
    return list(_CACHE["errors"])


def credentials_configured(legacy_key: str) -> bool:
    return bool(legacy_key) or bool(load_operators())


def resolve_credential(provided: str, legacy_key: str) -> Optional[Dict[str, Any]]:
    """Return the credential a presented key belongs to, or None. Constant time per configured key."""
    provided = str(provided or "").strip()
    if not provided:
        return None
    try:
        provided_bytes = provided.encode("utf-8")
    except Exception:
        return None
    digest = hashlib.sha256(provided_bytes).hexdigest().encode("ascii")
    match: Optional[Dict[str, str]] = None
    for operator in load_operators():
        # Compare against every entry, so timing does not reveal the position of a match.
        if hmac.compare_digest(digest, operator["key_sha256"].encode("ascii")) and match is None:
            match = operator
    legacy_ok = False
    if legacy_key:
        try:
            legacy_ok = hmac.compare_digest(provided_bytes, str(legacy_key).encode("utf-8"))
        except Exception:
            legacy_ok = False
    if match:
        return {"name": match["name"], "ceiling_role": match["role"], "bound": True, "source": "named_operator"}
    if legacy_ok:
        return {
            "name": LEGACY_OPERATOR_NAME,
            "ceiling_role": legacy_key_role(),
            "bound": False,
            "source": "legacy_shared_key",
        }
    return None


def effective_role(credential: Dict[str, Any], requested: Any) -> str:
    """Resolve the role for this request. Raises RoleError(400|403)."""
    raw = str(requested or "").strip().lower()
    ceiling = str(credential.get("ceiling_role") or LEAST_PRIVILEGED_ROLE)
    if raw:
        role = ROLE_ALIASES.get(raw)
        if not role:
            raise RoleError(400, "Unknown platform admin role. Use owner, operator, support, or auditor.")
    else:
        role = ceiling if credential.get("bound") else LEAST_PRIVILEGED_ROLE
    if ROLE_RANK[role] > ROLE_RANK.get(ceiling, 0):
        raise RoleError(403, f"Platform admin role '{role}' exceeds this credential's '{ceiling}' role.")
    return role


def allowed_roles_for(ceiling: str) -> List[str]:
    top = ROLE_RANK.get(str(ceiling or ""), 0)
    return [role for role in ROLE_ORDER if ROLE_RANK[role] <= top]


def sanitize_claimed_user(value: Any) -> str:
    return _CLAIMED_USER_RE.sub("", str(value or ""))[:120]


def public_operator_list() -> List[Dict[str, str]]:
    return [{"name": op["name"], "role": op["role"]} for op in load_operators()]


def new_operator_entry(name: str, role: str) -> Tuple[str, Dict[str, str]]:
    normalized = normalize_role(role)
    if not normalized:
        raise ValueError("role must be owner, operator, support, or auditor")
    if not _NAME_RE.match(str(name or "")):
        raise ValueError("name may contain letters, digits and . _ @ + - (max 80)")
    key = secrets.token_urlsafe(48)
    return key, {"name": name, "role": normalized, "key_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest()}


def _main() -> None:  # pragma: no cover - operator tooling
    parser = argparse.ArgumentParser(description="Create a named platform operator credential.")
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", required=True, choices=list(ROLE_ORDER))
    args = parser.parse_args()
    key, entry = new_operator_entry(args.name, args.role)
    print("Give this key to the operator through a secret manager; it is not stored anywhere:")
    print(key)
    print("Add this entry to the PQC_PLATFORM_OPERATORS JSON list:")
    print(json.dumps(entry))


if __name__ == "__main__":  # pragma: no cover
    _main()
