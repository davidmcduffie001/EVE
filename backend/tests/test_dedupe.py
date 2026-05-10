"""Tests for scanner finding deduplication keys."""

from app.services.scanners.dedupe import compute_finding_dedupe_key


def test_dedupe_key_is_stable_for_equivalent_finding_input() -> None:
    """Equivalent finding identity fields produce the same stable key."""
    first = compute_finding_dedupe_key(
        scanner_type="nessus",
        target_locator="WEB-01.EXAMPLE.COM",
        scanner_finding_id=" 19506 ",
        cve_ids=["CVE-2024-0002", "CVE-2024-0001"],
        port=443,
        protocol="TCP",
        service_name="HTTPS",
        title="TLS Certificate Cannot Be Trusted",
    )
    second = compute_finding_dedupe_key(
        scanner_type="NESSUS",
        target_locator="web-01.example.com",
        scanner_finding_id="19506",
        cve_ids=["CVE-2024-0001", "CVE-2024-0002"],
        port=443,
        protocol="tcp",
        service_name="https",
        title=" tls   certificate cannot be trusted ",
    )

    assert first == second
    assert len(first) == 64


def test_dedupe_key_changes_when_target_changes() -> None:
    """The same scanner finding on a different target is a distinct finding."""
    first = compute_finding_dedupe_key(
        scanner_type="nessus",
        target_locator="web-01.example.com",
        scanner_finding_id="19506",
        cve_ids=[],
        port=443,
        protocol="tcp",
        service_name="https",
        title="TLS Certificate Cannot Be Trusted",
    )
    second = compute_finding_dedupe_key(
        scanner_type="nessus",
        target_locator="web-02.example.com",
        scanner_finding_id="19506",
        cve_ids=[],
        port=443,
        protocol="tcp",
        service_name="https",
        title="TLS Certificate Cannot Be Trusted",
    )

    assert first != second
