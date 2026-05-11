"""Tests for Greenbone/OpenVAS scanner sync normalization."""

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.database import create_sessionmaker
from app.models.base import Base, Finding, Role, Scan, ScannerIntegration, Target, User
from app.services.auth.security import PasswordHasher
from app.services.scanners.greenbone import (
    GreenboneGmpClient,
    GreenboneResult,
    GreenboneTask,
    GreenboneTlsEndpoint,
    _parse_greenbone_endpoint,
    sync_greenbone_integration,
    sync_greenbone_scan_results,
)


def test_greenbone_client_parses_tasks_and_results_from_gmp_xml() -> None:
    """Greenbone XML responses are normalized into task and result records."""
    task_xml = """
    <get_tasks_response status="200" status_text="OK">
      <task id="task-1">
        <name>Weekly Edge Scan</name>
        <status>Done</status>
        <last_report>
          <report id="report-1"/>
        </last_report>
      </task>
    </get_tasks_response>
    """
    result_xml = """
    <get_results_response status="200" status_text="OK">
      <result id="result-1">
        <name>Apache httpd Unsupported Version Detection</name>
        <description>Remote Apache httpd is unsupported.</description>
        <host>192.0.2.10</host>
        <port>443/tcp</port>
        <threat>High</threat>
        <severity>8.1</severity>
        <nvt oid="1.3.6.1.4.1.25623.1.0.123456">
          <name>Apache httpd Unsupported Version Detection</name>
          <cve>CVE-2025-0001, CVE-2025-0002</cve>
        </nvt>
      </result>
    </get_results_response>
    """

    assert GreenboneGmpClient.parse_tasks(task_xml) == [
        GreenboneTask(
            task_id="task-1",
            name="Weekly Edge Scan",
            status="Done",
            report_id="report-1",
        )
    ]
    assert GreenboneGmpClient.parse_results(result_xml) == [
        GreenboneResult(
            result_id="result-1",
            host="192.0.2.10",
            title="Apache httpd Unsupported Version Detection",
            description="Remote Apache httpd is unsupported.",
            severity="high",
            port=443,
            protocol="tcp",
            service_name=None,
            cve_ids=["CVE-2025-0001", "CVE-2025-0002"],
            tool_specific_data={
                "nvt_oid": "1.3.6.1.4.1.25623.1.0.123456",
                "threat": "High",
                "severity_score": "8.1",
            },
        )
    ]


def test_greenbone_endpoint_parser_requires_remote_gmp_endpoint() -> None:
    """EVE only supports remotely reachable Greenbone GMP endpoints."""
    assert _parse_greenbone_endpoint("unix:///run/gvmd/gvmd.sock") is None
    assert _parse_greenbone_endpoint("/run/gvmd/gvmd.sock") is None
    assert _parse_greenbone_endpoint("tls://127.0.0.1:9390") == GreenboneTlsEndpoint(
        hostname="127.0.0.1",
        port=9390,
    )


@pytest.mark.asyncio
async def test_greenbone_sync_persists_scan_target_and_finding() -> None:
    """Greenbone task results create canonical scan, target, and finding rows."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Scanner Admin", permissions=["scanners:manage"])
        user = User(
            id=uuid4(),
            email="scanner-admin@example.test",
            display_name="Scanner Admin",
            role_id=role.id,
            password_hash=PasswordHasher().hash_password("correct-password"),
        )
        integration = ScannerIntegration(
            id=uuid4(),
            name="Lab OpenVAS",
            scanner_type="greenbone",
            edition_required="ce",
            enabled=True,
            encrypted_credentials_ref="v1:test",
            created_by=user.id,
        )
        session.add_all([role, user, integration])
        await session.commit()

        summary = await sync_greenbone_scan_results(
            session=session,
            integration=integration,
            tasks=[
                GreenboneTask(
                    task_id="task-1",
                    name="Weekly Edge Scan",
                    status="Done",
                    report_id="report-1",
                )
            ],
            results_by_task={
                "task-1": [
                    GreenboneResult(
                        result_id="result-1",
                        host="192.0.2.10",
                        title="Apache httpd Unsupported Version Detection",
                        description="Remote Apache httpd is unsupported.",
                        severity="high",
                        port=443,
                        protocol="tcp",
                        service_name=None,
                        cve_ids=["CVE-2025-0001"],
                        tool_specific_data={"nvt_oid": "1.3.6.1.4.1.25623.1.0.123456"},
                    )
                ]
            },
        )
        await session.commit()

        scans = (await session.scalars(select(Scan))).all()
        targets = (await session.scalars(select(Target))).all()
        findings = (await session.scalars(select(Finding))).all()

    await sessionmaker.kw["bind"].dispose()

    assert summary.scans_imported == 1
    assert summary.findings_imported == 1
    assert len(scans) == 1
    assert scans[0].scanner_scan_id == "task-1"
    assert scans[0].status == "succeeded"
    assert len(targets) == 1
    assert targets[0].locator == "192.0.2.10"
    assert targets[0].locator_type == "ip"
    assert len(findings) == 1
    assert findings[0].scanner_finding_id == "result-1"
    assert findings[0].severity == "high"
    assert findings[0].port == 443
    assert findings[0].protocol == "tcp"


@pytest.mark.asyncio
async def test_greenbone_sync_entrypoint_fetches_tasks_and_results() -> None:
    """The Greenbone sync entrypoint coordinates task/result fetches before persistence."""
    sessionmaker = create_sessionmaker("sqlite+aiosqlite:///:memory:")
    async with sessionmaker.kw["bind"].begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    class FakeGreenboneClient:
        def __init__(self) -> None:
            self.fetched_results_for: list[str] = []

        async def fetch_tasks(self) -> list[GreenboneTask]:
            return [
                GreenboneTask(
                    task_id="task-1",
                    name="Weekly Edge Scan",
                    status="Done",
                    report_id="report-1",
                )
            ]

        async def fetch_results(self, task: GreenboneTask) -> list[GreenboneResult]:
            self.fetched_results_for.append(task.task_id)
            return [
                GreenboneResult(
                    result_id="result-1",
                    host="192.0.2.10",
                    title="Apache httpd Unsupported Version Detection",
                    description="Remote Apache httpd is unsupported.",
                    severity="high",
                    port=443,
                    protocol="tcp",
                    service_name=None,
                    cve_ids=[],
                    tool_specific_data={},
                )
            ]

    async with sessionmaker() as session:
        role = Role(id=uuid4(), name="Scanner Admin", permissions=["scanners:manage"])
        user = User(
            id=uuid4(),
            email="scanner-admin@example.test",
            display_name="Scanner Admin",
            role_id=role.id,
            password_hash=PasswordHasher().hash_password("correct-password"),
        )
        integration = ScannerIntegration(
            id=uuid4(),
            name="Lab OpenVAS",
            scanner_type="greenbone",
            edition_required="ce",
            enabled=True,
            encrypted_credentials_ref="v1:test",
            created_by=user.id,
        )
        session.add_all([role, user, integration])
        await session.commit()

        client = FakeGreenboneClient()
        summary = await sync_greenbone_integration(
            session=session,
            integration=integration,
            client=client,
        )
        await session.commit()
        finding_count = len((await session.scalars(select(Finding))).all())

    await sessionmaker.kw["bind"].dispose()

    assert client.fetched_results_for == ["task-1"]
    assert summary.scans_imported == 1
    assert summary.findings_imported == 1
    assert finding_count == 1


def test_greenbone_sync_skips_results_without_hosts() -> None:
    """Results without a host cannot be mapped to an EVE target."""
    assert GreenboneGmpClient.parse_results(
        """
        <get_results_response status="200" status_text="OK">
          <result id="result-1">
            <name>Log Message</name>
            <description>No host here.</description>
          </result>
        </get_results_response>
        """
    ) == []
