"""Unit tests for RBAC policy (pure functions, no IdP/DB needed)."""
from app.dashboard.rbac import (
    Role,
    can_export,
    can_view_audit,
    can_view_raw_findings,
    role_from_claims,
    zone_filter,
    zones_from_claims,
)


def test_role_priority_picks_strongest():
    assert role_from_claims({"groups": ["viewer", "admin"]}) is Role.ADMIN
    assert role_from_claims({"groups": ["audit-auditor"]}) is Role.AUDITOR
    assert role_from_claims({"groups": "analyst"}) is Role.ANALYST


def test_role_defaults_to_viewer():
    assert role_from_claims({}) is Role.VIEWER
    assert role_from_claims({"groups": ["unrelated"]}) is Role.VIEWER


def test_capability_matrix():
    assert not can_view_raw_findings(Role.VIEWER)
    assert can_view_raw_findings(Role.ANALYST)
    assert can_export(Role.AUDITOR)
    assert not can_export(Role.ANALYST)
    assert can_view_audit(Role.ADMIN)
    assert not can_view_audit(Role.ANALYST)


def test_zone_need_to_know():
    # Analysts are confined to their assigned zones; others see all (None).
    assert zone_filter(Role.ANALYST, ["dmz"]) == ["dmz"]
    assert zone_filter(Role.AUDITOR, ["dmz"]) is None
    assert zone_filter(Role.ADMIN, []) is None


def test_zones_from_claims():
    assert zones_from_claims({"zones": "dmz"}) == ["dmz"]
    assert zones_from_claims({"zones": ["core", "edge"]}) == ["core", "edge"]
    assert zones_from_claims({}) == []
