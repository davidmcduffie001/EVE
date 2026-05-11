"""Greenbone/OpenVAS scanner connectivity helpers."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import anyio
from gvm.connections import TLSConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform


@dataclass(frozen=True)
class GreenboneConnectivityResult:
    """Safe connectivity status for a Greenbone GMP endpoint."""

    ok: bool
    reason: str
    error: str | None = None


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
