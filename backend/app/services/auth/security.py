"""Local authentication security helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.config import Settings

PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 720_000
SALT_BYTES = 16
JOSE_HMAC_SHA256_ALGORITHM = "HS256"


class InvalidTokenError(ValueError):
    """Raised when a signed token cannot be trusted."""


@dataclass(frozen=True)
class AccessTokenClaims:
    """Verified access-token claims used by authenticated API dependencies."""

    subject: str
    role_name: str
    token_type: str
    expires_at: datetime
    issued_at: datetime


@dataclass(frozen=True)
class MfaChallengeClaims:
    """Verified MFA challenge-token claims."""

    subject: str
    token_type: str
    expires_at: datetime
    issued_at: datetime


class PasswordHasher:
    """Password hashing and verification using stdlib PBKDF2-HMAC-SHA256."""

    def hash_password(self, password: str) -> str:
        """Hash a plaintext password with a random salt."""
        salt = secrets.token_bytes(SALT_BYTES)
        derived_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return "$".join(
            [
                PBKDF2_ALGORITHM,
                str(PBKDF2_ITERATIONS),
                _base64url_encode(salt),
                _base64url_encode(derived_key),
            ]
        )

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Return whether a plaintext password matches a stored hash."""
        try:
            algorithm, iterations_text, salt_text, expected_text = password_hash.split("$", 3)
            iterations = int(iterations_text)
            salt = _base64url_decode(salt_text)
            expected_key = _base64url_decode(expected_text)
        except (TypeError, ValueError):
            return False

        if algorithm != PBKDF2_ALGORITHM:
            return False

        derived_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(derived_key, expected_key)


class TokenSigner:
    """Create and verify compact HMAC-signed access tokens."""

    def __init__(self, settings: Settings) -> None:
        """Initialize the signer from application settings."""
        self._secret = settings.auth_secret_key.encode("utf-8")
        self._access_token_ttl = timedelta(seconds=settings.access_token_ttl_seconds)
        self._mfa_challenge_ttl = timedelta(minutes=5)

    def create_access_token(self, *, user_id: UUID, role_name: str) -> str:
        """Create a signed access token for a user and role."""
        issued_at = datetime.now(UTC)
        expires_at = issued_at + self._access_token_ttl
        header = {"alg": JOSE_HMAC_SHA256_ALGORITHM, "typ": "JWT"}
        payload = {
            "sub": str(user_id),
            "role": role_name,
            "typ": "access",
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        signing_input = ".".join(
            [
                _base64url_json(header),
                _base64url_json(payload),
            ]
        )
        signature = _base64url_encode(
            hmac.digest(self._secret, signing_input.encode("ascii"), "sha256")
        )
        return f"{signing_input}.{signature}"

    def create_mfa_challenge_token(self, *, user_id: UUID) -> str:
        """Create a short-lived signed token for completing MFA login."""
        issued_at = datetime.now(UTC)
        expires_at = issued_at + self._mfa_challenge_ttl
        return self._create_token(
            {
                "sub": str(user_id),
                "typ": "mfa_challenge",
                "iat": int(issued_at.timestamp()),
                "exp": int(expires_at.timestamp()),
            }
        )

    def verify_access_token(self, token: str) -> AccessTokenClaims:
        """Verify a signed access token and return its claims."""
        try:
            header_text, payload_text, signature_text = token.split(".", 2)
            signing_input = f"{header_text}.{payload_text}"
            expected_signature = _base64url_encode(
                hmac.digest(self._secret, signing_input.encode("ascii"), "sha256")
            )
            if not hmac.compare_digest(signature_text, expected_signature):
                raise InvalidTokenError("Invalid token signature")

            header = json.loads(_base64url_decode(header_text))
            payload = json.loads(_base64url_decode(payload_text))
            if header.get("alg") != JOSE_HMAC_SHA256_ALGORITHM or payload.get("typ") != "access":
                raise InvalidTokenError("Unsupported token")

            expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
            if expires_at <= datetime.now(UTC):
                raise InvalidTokenError("Token expired")

            issued_at = datetime.fromtimestamp(int(payload["iat"]), UTC)
            return AccessTokenClaims(
                subject=str(payload["sub"]),
                role_name=str(payload["role"]),
                token_type=str(payload["typ"]),
                expires_at=expires_at,
                issued_at=issued_at,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise InvalidTokenError("Invalid token") from exc

    def verify_mfa_challenge_token(self, token: str) -> MfaChallengeClaims:
        """Verify a signed MFA challenge token and return its claims."""
        try:
            payload = self._verify_token(token, expected_type="mfa_challenge")
            expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
            issued_at = datetime.fromtimestamp(int(payload["iat"]), UTC)
            return MfaChallengeClaims(
                subject=str(payload["sub"]),
                token_type=str(payload["typ"]),
                expires_at=expires_at,
                issued_at=issued_at,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise InvalidTokenError("Invalid token") from exc

    def _create_token(self, payload: dict[str, object]) -> str:
        header = {"alg": JOSE_HMAC_SHA256_ALGORITHM, "typ": "JWT"}
        signing_input = ".".join([_base64url_json(header), _base64url_json(payload)])
        signature = _base64url_encode(
            hmac.digest(self._secret, signing_input.encode("ascii"), "sha256")
        )
        return f"{signing_input}.{signature}"

    def _verify_token(self, token: str, *, expected_type: str) -> dict[str, object]:
        header_text, payload_text, signature_text = token.split(".", 2)
        signing_input = f"{header_text}.{payload_text}"
        expected_signature = _base64url_encode(
            hmac.digest(self._secret, signing_input.encode("ascii"), "sha256")
        )
        if not hmac.compare_digest(signature_text, expected_signature):
            raise InvalidTokenError("Invalid token signature")

        header = json.loads(_base64url_decode(header_text))
        payload = json.loads(_base64url_decode(payload_text))
        if header.get("alg") != JOSE_HMAC_SHA256_ALGORITHM or payload.get("typ") != expected_type:
            raise InvalidTokenError("Unsupported token")

        expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
        if expires_at <= datetime.now(UTC):
            raise InvalidTokenError("Token expired")
        return payload


def _base64url_json(value: dict[str, object]) -> str:
    return _base64url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))
