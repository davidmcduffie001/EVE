"""TOTP helpers for user-managed MFA enrollment."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_totp_secret() -> str:
    """Create a base32 TOTP secret suitable for authenticator apps."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_totp_uri(*, secret: str, account_name: str, issuer: str = "EVE") -> str:
    """Build an otpauth URI for TOTP enrollment."""
    label = f"{issuer}:{account_name}"
    return (
        f"otpauth://totp/{quote(label)}"
        f"?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def generate_totp_code(secret: str, *, for_time: int | None = None) -> str:
    """Generate the six-digit TOTP code for a secret at a point in time."""
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    counter = int((time.time() if for_time is None else for_time) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp_code(
    secret: str,
    code: str,
    *,
    at_time: int | None = None,
    window: int = 1,
) -> bool:
    """Return whether a user-provided TOTP code is valid within the allowed window."""
    normalized_code = code.strip().replace(" ", "")
    if len(normalized_code) != 6 or not normalized_code.isdigit():
        return False
    current_time = int(time.time() if at_time is None else at_time)
    for step in range(-window, window + 1):
        candidate = generate_totp_code(secret, for_time=current_time + (step * 30))
        if hmac.compare_digest(candidate, normalized_code):
            return True
    return False
