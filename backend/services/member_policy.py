"""Who may change whose role, and who may remove whom, inside one organization.

The organization's owner is the account that signed up and created it (services/signup.py,
morrow_org_owners). In an organization with a recorded owner:

  * Only the owner may change the role of an admin, make someone an admin (by a role change, by
    adding a member or by an invitation with an admin role) or remove/deactivate an admin.
  * Other admins keep managing members who are not admins (viewer, operator, analyst and so on).
  * Nobody changes their own role, and the owner can't be removed or have their role changed from
    inside the organization at all: they hand ownership to another admin first
    (POST /auth/organization/owner/transfer). An ownerless organization can't happen that way.

An organization without a recorded owner (made before owners were recorded, or by a platform
operator) keeps the old rules for managing admins, except that nobody changes their own role. A
platform operator can record its owner (PUT /platform/customers/{id}/owner).

Platform operators are outside these rules: they act through /platform routes, with an MFA step-up
whenever the change touches an admin or the owner.

This module only decides. The routes in app.py and routers/ look the people up, journal and audit a
refusal (member_change.refused, decision deny) and answer 403 with the detail given here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

#: Roles that administer the organization. Changing them, granting them or removing someone who has
#: one needs the owner.
PRIVILEGED_ROLES = frozenset({"admin", "owner", "org_admin", "platform_admin"})

ROLE = "role"        # change an existing member's role
REMOVE = "remove"    # remove, suspend or deactivate a member
GRANT = "grant"      # add a member or invite someone with a role


@dataclass(frozen=True)
class Refusal:
    reason: str
    detail: str


def last_admin() -> Refusal:
    """Refusal for deactivating or removing yourself when nobody else is an active admin."""
    return Refusal("last_admin", "You're the only active admin of this organization, so you can't deactivate or "
                                 "remove yourself. Make someone else an admin first.")


def privileged(role: object) -> bool:
    return str(role or "").strip().lower() in PRIVILEGED_ROLES


def _ids(values: Iterable[object]) -> set:
    return {str(v).strip() for v in values if str(v or "").strip()}


def check(*, owner_id: str, caller_ids: Iterable[object], target_ids: Iterable[object] = (),
          target_roles: Iterable[object] = (), action: str, new_role: str = "") -> Optional[Refusal]:
    """None when the caller (an admin of the organization) may make this change, else the Refusal.

    `caller_ids` and `target_ids` are every identifier the person is known by here (account id,
    email), because older routes name people by email and newer ones by account id.
    """
    owner_id = str(owner_id or "").strip()
    callers, targets = _ids(caller_ids), _ids(target_ids)
    is_owner = bool(owner_id) and owner_id in callers
    target_is_owner = bool(owner_id) and owner_id in targets
    target_privileged = target_is_owner or any(privileged(r) for r in target_roles)
    self_target = bool(callers & targets)

    if action == ROLE:
        if self_target:
            if is_owner:
                return Refusal("own_role", "You can't change your own role. You own this organization: "
                                           "transfer ownership to another admin first.")
            return Refusal("own_role", "You can't change your own role. Ask another admin.")
        if target_is_owner:
            return Refusal("owner_protected", "The organization's owner keeps the admin role. "
                                              "Only the owner can hand ownership to someone else.")
        if owner_id and (target_privileged or privileged(new_role)) and not is_owner:
            return Refusal("owner_required", "Only the organization's owner can change an admin's role "
                                             "or make someone an admin.")
        return None
    if action == REMOVE:
        if target_is_owner:
            return Refusal("owner_protected", "The organization's owner can't be removed. "
                                              "The owner can transfer ownership to another admin first.")
        if owner_id and target_privileged and not is_owner:
            return Refusal("owner_required", "Only the organization's owner can remove an admin.")
        return None
    if action == GRANT:
        if owner_id and privileged(new_role) and not is_owner:
            return Refusal("owner_required", "Only the organization's owner can make someone an admin.")
        return None
    raise ValueError(f"unknown member action {action!r}")
