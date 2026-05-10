"""Tests for the RBAC permission registry."""

from app.services.auth.permissions import BUILTIN_ROLE_PERMISSIONS, PERMISSIONS


def test_permission_registry_contains_specified_phase_1_permissions() -> None:
    """The permission registry includes the documented Phase 1 permission set."""
    assert {
        "findings:read",
        "findings:export",
        "targets:manage",
        "intel:manage",
        "users:manage",
        "roles:manage",
        "audit:read",
        "reports:export",
        "scanners:manage",
    }.issubset(PERMISSIONS)


def test_builtin_roles_only_use_registered_permissions() -> None:
    """Seeded built-in roles cannot drift from the central permission registry."""
    for permissions in BUILTIN_ROLE_PERMISSIONS.values():
        assert set(permissions).issubset(PERMISSIONS)
