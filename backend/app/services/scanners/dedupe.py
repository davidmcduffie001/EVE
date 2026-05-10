"""Stable deduplication keys for normalized scanner findings."""

from __future__ import annotations

import hashlib
import re


def _normalize_text(value: object) -> str:
    """Normalize text-like values for deterministic key generation."""
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def compute_finding_dedupe_key(
    *,
    scanner_type: str,
    target_locator: str,
    scanner_finding_id: str | None,
    cve_ids: list[str],
    port: int | None,
    protocol: str | None,
    service_name: str | None,
    title: str,
) -> str:
    """Compute a stable SHA-256 identity key for a scanner finding."""
    normalized_cves = ",".join(sorted(_normalize_text(cve_id).upper() for cve_id in cve_ids))
    parts = [
        _normalize_text(scanner_type),
        _normalize_text(target_locator),
        _normalize_text(scanner_finding_id),
        normalized_cves,
        "" if port is None else str(port),
        _normalize_text(protocol),
        _normalize_text(service_name),
        _normalize_text(title),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
