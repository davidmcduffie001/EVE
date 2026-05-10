"""Central RBAC permission registry."""

PERMISSIONS: frozenset[str] = frozenset(
    {
        "findings:read",
        "findings:export",
        "targets:manage",
        "intel:manage",
        "users:manage",
        "roles:manage",
        "audit:read",
        "reports:export",
        "scanners:manage",
        "executions:create",
        "executions:approve",
        "credentials:manage",
    }
)

BUILTIN_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "Admin": sorted(PERMISSIONS),
    "Analyst": [
        "findings:read",
        "findings:export",
        "reports:export",
    ],
    "Read-Only": [
        "findings:read",
        "audit:read",
    ],
}
