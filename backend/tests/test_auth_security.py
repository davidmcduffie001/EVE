"""Tests for local authentication security primitives."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.services.auth.security import (
    InvalidTokenError,
    PasswordHasher,
    TokenSigner,
)


def test_password_hasher_verifies_matching_password_and_rejects_wrong_password() -> None:
    """Password hashes are salted and verifiable without storing plaintext."""
    hasher = PasswordHasher()

    stored_hash = hasher.hash_password("correct horse battery staple")

    assert stored_hash != "correct horse battery staple"
    assert hasher.verify_password("correct horse battery staple", stored_hash)
    assert not hasher.verify_password("wrong password", stored_hash)


def test_password_hasher_generates_distinct_hashes_for_same_password() -> None:
    """Each password hash uses a distinct random salt."""
    hasher = PasswordHasher()

    first_hash = hasher.hash_password("shared secret")
    second_hash = hasher.hash_password("shared secret")

    assert first_hash != second_hash
    assert hasher.verify_password("shared secret", first_hash)
    assert hasher.verify_password("shared secret", second_hash)


def test_token_signer_round_trips_access_token_claims() -> None:
    """Signed access tokens preserve the user and role claims."""
    signing_key = "test-secret"
    signer = TokenSigner(Settings(auth_secret_key=signing_key, access_token_ttl_seconds=900))
    user_id = uuid4()

    token = signer.create_access_token(user_id=user_id, role_name="admin")
    claims = signer.verify_access_token(token)

    assert claims.subject == str(user_id)
    assert claims.role_name == "admin"
    assert claims.token_type == "access"  # noqa: S105
    assert claims.expires_at > datetime.now(UTC)


def test_token_signer_rejects_tampered_token() -> None:
    """Token signatures prevent accepting modified payloads."""
    signing_key = "test-secret"
    signer = TokenSigner(Settings(auth_secret_key=signing_key))
    token = signer.create_access_token(user_id=uuid4(), role_name="viewer")
    tampered_token = f"{token[:-1]}x"

    with pytest.raises(InvalidTokenError):
        signer.verify_access_token(tampered_token)


def test_token_signer_rejects_expired_token() -> None:
    """Expired access tokens fail verification."""
    signing_key = "test-secret"
    signer = TokenSigner(Settings(auth_secret_key=signing_key, access_token_ttl_seconds=-1))
    token = signer.create_access_token(user_id=uuid4(), role_name="viewer")

    with pytest.raises(InvalidTokenError):
        signer.verify_access_token(token)
