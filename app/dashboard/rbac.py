"""Role-based access control — pure, testable policy functions.

Roles are derived from an OIDC claim (default ``groups``) issued by the central
IdP. Zone need-to-know (ABAC) is derived from a ``zones`` claim. Keeping these
as pure functions means the policy is unit-tested without a live IdP or DB.
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    ADMIN = "admin"


# Highest privilege first — a user with several groups gets the strongest role.
_PRIORITY = [Role.ADMIN, Role.AUDITOR, Role.ANALYST, Role.VIEWER]


def role_from_claims(claims: dict, role_claim: str = "groups") -> Role:
    raw = claims.get(role_claim) or []
    if isinstance(raw, str):
        raw = [raw]
    vals = {str(x).lower() for x in raw}
    for role in _PRIORITY:
        # Accept either bare ("admin") or namespaced ("audit-admin") group names.
        if role.value in vals or f"audit-{role.value}" in vals:
            return role
    return Role.VIEWER


def zones_from_claims(claims: dict, zones_claim: str = "zones") -> list[str]:
    raw = claims.get(zones_claim) or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(z) for z in raw]


def can_view_raw_findings(role: Role) -> bool:
    return role in (Role.ANALYST, Role.AUDITOR, Role.ADMIN)


def can_export(role: Role) -> bool:
    # Bulk export is the highest-risk action — auditors and admins only.
    return role in (Role.AUDITOR, Role.ADMIN)


def can_view_audit(role: Role) -> bool:
    return role in (Role.AUDITOR, Role.ADMIN)


def zone_filter(role: Role, user_zones: list[str]) -> list[str] | None:
    """Which zones may this user see raw rows for?

    Returns ``None`` for "all zones", or an explicit list to restrict to.
    Analysts are confined to their assigned zones (need-to-know); auditors and
    admins see all.
    """
    if role is Role.ANALYST:
        return list(user_zones)
    return None
