"""Request-level tests for the findings API."""

from uuid import uuid4

import anyio
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.main import create_app
from app.models.base import Base, Finding, Role, Scan, ScannerIntegration, Target, User
from app.services.auth.security import PasswordHasher


@pytest.fixture
def findings_client() -> TestClient:
    """Create a test app with one readable finding."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")

    async def seed() -> None:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        async with sessionmaker() as session:
            analyst_role = Role(
                id=uuid4(),
                name="Analyst",
                is_system_role=False,
                permissions=["findings:read"],
            )
            scanner_role = Role(
                id=uuid4(),
                name="Scanner Admin",
                is_system_role=False,
                permissions=["scanners:manage"],
            )
            analyst = User(
                id=uuid4(),
                email="analyst@example.test",
                display_name="Analyst User",
                role_id=analyst_role.id,
                password_hash=PasswordHasher().hash_password("correct-password"),
            )
            scanner_admin = User(
                id=uuid4(),
                email="scanner-admin@example.test",
                display_name="Scanner Admin",
                role_id=scanner_role.id,
                password_hash=PasswordHasher().hash_password("correct-password"),
            )
            integration = ScannerIntegration(
                id=uuid4(),
                name="Lab OpenVAS",
                scanner_type="greenbone",
                edition_required="ce",
                enabled=True,
                encrypted_credentials_ref="v1:test",
                created_by=analyst.id,
            )
            scan = Scan(
                id=uuid4(),
                scanner_integration_id=integration.id,
                scanner_type="greenbone",
                scanner_scan_id="task-1",
                status="succeeded",
            )
            target = Target(
                id=uuid4(),
                locator="192.0.2.10",
                locator_type="ip",
                tags={},
                in_authorized_scope=True,
            )
            finding = Finding(
                id=uuid4(),
                scan_id=scan.id,
                target_id=target.id,
                scanner_finding_id="result-1",
                dedupe_key="a" * 64,
                severity="high",
                status="open",
                title="Apache httpd Unsupported Version Detection",
                description="Remote Apache httpd is unsupported.",
                port=443,
                protocol="tcp",
                service_name="https",
                confidence="confirmed",
                tool_specific_data={"cve_ids": ["CVE-2025-0001"]},
            )
            session.add_all(
                [
                    analyst_role,
                    scanner_role,
                    analyst,
                    scanner_admin,
                    integration,
                    scan,
                    target,
                    finding,
                ]
            )
            await session.commit()

    anyio.run(seed)
    settings = Settings(auth_secret_key="test-signing-key", cookie_secure=False)  # noqa: S106
    with TestClient(create_app(settings=settings, sessionmaker=sessionmaker)) as client:
        yield client

    anyio.run(sessionmaker.kw["bind"].dispose)


def _login(client: TestClient, email: str = "analyst@example.test") -> None:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == 200


def test_findings_reader_can_list_findings(findings_client: TestClient) -> None:
    """Users with findings:read can view normalized scanner findings."""
    _login(findings_client)

    response = findings_client.get("/findings")

    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["title"] == "Apache httpd Unsupported Version Detection"
    assert response.json()["items"][0]["target_locator"] == "192.0.2.10"
    assert response.json()["items"][0]["scanner_type"] == "greenbone"
    assert response.json()["items"][0]["severity"] == "high"
    assert response.json()["items"][0]["port"] == 443
    assert response.json()["items"][0]["protocol"] == "tcp"
    assert response.json()["items"][0]["cve_ids"] == ["CVE-2025-0001"]


def test_findings_list_requires_findings_read_permission(findings_client: TestClient) -> None:
    """Users without findings:read cannot view findings."""
    _login(findings_client, "scanner-admin@example.test")

    response = findings_client.get("/findings")

    assert response.status_code == 403
