"""Greenbone/OpenVAS scanner connectivity helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

import anyio
from defusedxml import ElementTree
from gvm.connections import TLSConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import Finding, Scan, ScannerIntegration, Target, utc_now
from app.services.scanners.dedupe import compute_finding_dedupe_key


@dataclass(frozen=True)
class GreenboneConnectivityResult:
    """Safe connectivity status for a Greenbone GMP endpoint."""

    ok: bool
    reason: str
    error: str | None = None


@dataclass(frozen=True)
class GreenboneTask:
    """Greenbone task summary selected for import."""

    task_id: str
    name: str
    status: str
    report_id: str | None


@dataclass(frozen=True)
class GreenboneResult:
    """Normalized Greenbone result before database persistence."""

    result_id: str
    host: str
    title: str
    description: str
    severity: str
    port: int | None
    protocol: str | None
    service_name: str | None
    cve_ids: list[str]
    tool_specific_data: dict[str, Any]


@dataclass(frozen=True)
class GreenboneSyncSummary:
    """Counts from an OpenVAS/Greenbone result import."""

    scans_imported: int
    findings_imported: int
    results_skipped: int


class GreenboneGmpClient:
    """Small GMP client wrapper for task and result retrieval."""

    def __init__(self, *, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password

    async def fetch_tasks(self) -> list[GreenboneTask]:
        """Fetch Greenbone tasks over GMP."""
        return await anyio.to_thread.run_sync(self._fetch_tasks_sync)

    async def fetch_results(self, task: GreenboneTask) -> list[GreenboneResult]:
        """Fetch Greenbone results for a task's latest report."""
        return await anyio.to_thread.run_sync(self._fetch_results_sync, task)

    @staticmethod
    def parse_tasks(xml: str) -> list[GreenboneTask]:
        """Parse a GMP get_tasks response into task summaries."""
        root = ElementTree.fromstring(xml)
        tasks: list[GreenboneTask] = []
        for task in root.findall(".//task"):
            task_id = task.attrib.get("id", "").strip()
            if not task_id:
                continue
            tasks.append(
                GreenboneTask(
                    task_id=task_id,
                    name=_element_text(task, "name") or task_id,
                    status=_element_text(task, "status") or "Unknown",
                    report_id=_latest_report_id(task),
                )
            )
        return tasks

    @staticmethod
    def parse_results(xml: str) -> list[GreenboneResult]:
        """Parse a GMP get_results response into normalized result records."""
        root = ElementTree.fromstring(xml)
        results: list[GreenboneResult] = []
        for result in root.findall(".//result"):
            host = _element_text(result, "host")
            if not host:
                continue
            port, protocol = _parse_port(_element_text(result, "port"))
            threat = _element_text(result, "threat")
            severity_score = _element_text(result, "severity")
            nvt = result.find("nvt")
            nvt_name = _element_text(nvt, "name") if nvt is not None else None
            title = _element_text(result, "name") or nvt_name or "Untitled Greenbone result"
            cve_ids = _parse_cve_ids(_element_text(nvt, "cve") if nvt is not None else None)
            results.append(
                GreenboneResult(
                    result_id=result.attrib.get("id", "").strip(),
                    host=host,
                    title=title,
                    description=_element_text(result, "description") or title,
                    severity=_normalize_greenbone_severity(threat, severity_score),
                    port=port,
                    protocol=protocol,
                    service_name=None,
                    cve_ids=cve_ids,
                    tool_specific_data={
                        "nvt_oid": nvt.attrib.get("oid", "").strip() if nvt is not None else "",
                        "threat": threat,
                        "severity_score": severity_score,
                    },
                )
            )
        return results

    def _fetch_tasks_sync(self) -> list[GreenboneTask]:
        endpoint = _parse_greenbone_endpoint(self.base_url)
        if endpoint is None:
            raise ValueError("Greenbone GMP endpoint is invalid")
        connection = TLSConnection(hostname=endpoint[0], port=endpoint[1], timeout=60)
        transform = EtreeCheckCommandTransform()
        with GMP(connection=connection, transform=transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.get_tasks(filter_string="rows=1000 sort-reverse=modified")
        return self.parse_tasks(ElementTree.tostring(response, encoding="unicode"))

    def _fetch_results_sync(self, task: GreenboneTask) -> list[GreenboneResult]:
        if task.report_id is None:
            return []
        endpoint = _parse_greenbone_endpoint(self.base_url)
        if endpoint is None:
            raise ValueError("Greenbone GMP endpoint is invalid")
        connection = TLSConnection(hostname=endpoint[0], port=endpoint[1], timeout=60)
        transform = EtreeCheckCommandTransform()
        with GMP(connection=connection, transform=transform) as gmp:
            gmp.authenticate(self.username, self.password)
            response = gmp.get_results(
                filter_string=f"report_id={task.report_id} rows=1000 sort-reverse=severity"
            )
        return self.parse_results(ElementTree.tostring(response, encoding="unicode"))


async def test_greenbone_connectivity(
    *,
    base_url: str,
    username: str,
    password: str,
) -> GreenboneConnectivityResult:
    """Verify a Greenbone GMP endpoint with a short authenticated request."""
    endpoint = _parse_greenbone_endpoint(base_url)
    if endpoint is None:
        return GreenboneConnectivityResult(
            ok=False,
            reason="invalid_endpoint",
            error="Greenbone GMP endpoint is invalid",
        )

    return await anyio.to_thread.run_sync(
        _test_greenbone_connectivity_sync,
        endpoint[0],
        endpoint[1],
        username,
        password,
    )


def _parse_greenbone_endpoint(base_url: str) -> tuple[str, int] | None:
    candidate = base_url.strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"tls://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"tls", "gmp"}:
        return None
    if not parsed.hostname:
        return None
    return parsed.hostname, parsed.port or 9390


def _test_greenbone_connectivity_sync(
    hostname: str,
    port: int,
    username: str,
    password: str,
) -> GreenboneConnectivityResult:
    connection = TLSConnection(hostname=hostname, port=port, timeout=10)
    transform = EtreeCheckCommandTransform()
    try:
        with GMP(connection=connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            gmp.get_version()
    except TimeoutError:
        return GreenboneConnectivityResult(
            ok=False,
            reason="timeout",
            error="Greenbone GMP connection timed out",
        )
    except OSError:
        return GreenboneConnectivityResult(
            ok=False,
            reason="connect_error",
            error="Unable to connect to Greenbone GMP endpoint",
        )
    except GvmError:
        return GreenboneConnectivityResult(
            ok=False,
            reason="gmp_error",
            error="Greenbone GMP authentication or request failed",
        )
    return GreenboneConnectivityResult(ok=True, reason="gmp_version_ok")


async def sync_greenbone_scan_results(
    *,
    session: AsyncSession,
    integration: ScannerIntegration,
    tasks: list[GreenboneTask],
    results_by_task: dict[str, list[GreenboneResult]],
) -> GreenboneSyncSummary:
    """Persist normalized Greenbone scan results into EVE scan and finding tables."""
    scans_imported = 0
    findings_imported = 0
    skipped = 0
    now = utc_now()

    for task in tasks:
        scan = await _get_or_create_scan(
            session=session,
            integration=integration,
            task=task,
            imported_at=now,
        )
        scans_imported += 1
        for result in results_by_task.get(task.task_id, []):
            if not result.host:
                skipped += 1
                continue
            target = await _get_or_create_target(session=session, locator=result.host)
            dedupe_key = compute_finding_dedupe_key(
                scanner_type=integration.scanner_type,
                target_locator=target.locator,
                scanner_finding_id=result.result_id,
                cve_ids=result.cve_ids,
                port=result.port,
                protocol=result.protocol,
                service_name=result.service_name,
                title=result.title,
            )
            existing = await session.scalar(
                select(Finding).where(Finding.dedupe_key == dedupe_key).limit(1)
            )
            if existing is not None:
                existing.last_seen_at = now
                existing.scan_id = scan.id
                existing.target_id = target.id
                continue
            finding = Finding(
                scan_id=scan.id,
                target_id=target.id,
                scanner_finding_id=result.result_id,
                dedupe_key=dedupe_key,
                severity=result.severity,
                title=result.title,
                description=result.description,
                port=result.port,
                protocol=result.protocol,
                service_name=result.service_name,
                confidence="confirmed",
                tool_specific_data={
                    **result.tool_specific_data,
                    "cve_ids": result.cve_ids,
                    "greenbone_task_id": task.task_id,
                    "greenbone_task_name": task.name,
                },
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(finding)
            findings_imported += 1
    return GreenboneSyncSummary(
        scans_imported=scans_imported,
        findings_imported=findings_imported,
        results_skipped=skipped,
    )


async def sync_greenbone_integration(
    *,
    session: AsyncSession,
    integration: ScannerIntegration,
    client: GreenboneGmpClient,
) -> GreenboneSyncSummary:
    """Fetch Greenbone tasks and results, then persist them into EVE tables."""
    tasks = await client.fetch_tasks()
    results_by_task: dict[str, list[GreenboneResult]] = {}
    for task in tasks:
        results_by_task[task.task_id] = await client.fetch_results(task)
    return await sync_greenbone_scan_results(
        session=session,
        integration=integration,
        tasks=tasks,
        results_by_task=results_by_task,
    )


async def _get_or_create_scan(
    *,
    session: AsyncSession,
    integration: ScannerIntegration,
    task: GreenboneTask,
    imported_at: datetime,
) -> Scan:
    scan = await session.scalar(
        select(Scan)
        .where(Scan.scanner_integration_id == integration.id)
        .where(Scan.scanner_scan_id == task.task_id)
        .limit(1)
    )
    if scan is not None:
        scan.status = _scan_status_from_greenbone_task(task.status)
        scan.completed_at = imported_at
        return scan
    scan = Scan(
        scanner_integration_id=integration.id,
        scanner_type=integration.scanner_type,
        scanner_scan_id=task.task_id,
        status=_scan_status_from_greenbone_task(task.status),
        started_at=None,
        completed_at=imported_at,
        raw_output_ref=task.report_id,
    )
    session.add(scan)
    await session.flush()
    return scan


async def _get_or_create_target(*, session: AsyncSession, locator: str) -> Target:
    existing = await session.scalar(select(Target).where(Target.locator == locator).limit(1))
    if existing is not None:
        return existing
    target = Target(
        locator=locator,
        locator_type=_locator_type(locator),
        tags={},
        in_authorized_scope=False,
    )
    session.add(target)
    await session.flush()
    return target


def _element_text(element: ElementTree.Element | None, path: str) -> str:
    if element is None:
        return ""
    child = element.find(path)
    return (child.text or "").strip() if child is not None else ""


def _latest_report_id(task: ElementTree.Element) -> str | None:
    report = task.find("last_report/report")
    if report is None:
        return None
    return report.attrib.get("id", "").strip() or None


def _parse_port(value: str) -> tuple[int | None, str | None]:
    if not value:
        return None, None
    raw_port, _, raw_protocol = value.partition("/")
    try:
        return int(raw_port), raw_protocol.lower() or None
    except ValueError:
        return None, raw_protocol.lower() or None


def _parse_cve_ids(value: str | None) -> list[str]:
    if not value:
        return []
    cves = []
    for part in value.replace(";", ",").split(","):
        candidate = part.strip().upper()
        if candidate.startswith("CVE-"):
            cves.append(candidate)
    return sorted(set(cves))


def _normalize_greenbone_severity(threat: str, severity_score: str) -> str:
    threat_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "log": "info",
        "false positive": "info",
    }
    mapped = threat_map.get(threat.strip().lower())
    if mapped:
        return mapped
    try:
        score = float(severity_score)
    except ValueError:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _scan_status_from_greenbone_task(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in {"done", "stopped"}:
        return "succeeded"
    if normalized in {"running", "requested"}:
        return "running"
    if normalized in {"queued", "new"}:
        return "queued"
    if normalized in {"interrupted", "error"}:
        return "failed"
    return "succeeded"


def _locator_type(locator: str) -> str:
    try:
        parsed_ip = ip_address(locator)
    except ValueError:
        try:
            ip_network(locator, strict=False)
        except ValueError:
            if "://" in locator:
                return "url"
            return "domain"
        return "cidr"
    return "ip" if parsed_ip.version in {4, 6} else "host"
