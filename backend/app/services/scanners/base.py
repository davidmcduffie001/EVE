"""Base scanner connector protocol for Phase 1 integrations."""

from abc import ABC, abstractmethod
from typing import Any


class ScannerConnector(ABC):
    """Interface implemented by scanner connectors such as Nessus."""

    @abstractmethod
    async def authenticate(self) -> None:
        """Authenticate with the upstream scanner without exposing credentials."""

    @abstractmethod
    async def fetch_scans(self) -> list[dict[str, Any]]:
        """Fetch scanner-native scan summaries."""

    @abstractmethod
    async def fetch_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch scanner-native findings for a scan."""

    @abstractmethod
    def normalize(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Normalize a scanner-native finding into EVE's canonical shape."""

    @abstractmethod
    async def sync(self) -> None:
        """Run an end-to-end scanner synchronization."""
