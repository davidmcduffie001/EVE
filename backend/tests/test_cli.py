"""Tests for backend CLI bootstrap helpers."""

from argparse import Namespace

import pytest
from sqlalchemy import select

from app.cli import parse_args, run_bootstrap
from app.core.config import Settings
from app.core.database import create_sessionmaker
from app.models.base import User
from app.services.auth.security import PasswordHasher


def test_dev_bootstrap_defaults_to_documented_test_account() -> None:
    """The local dev bootstrap command exposes the documented test account."""
    args = parse_args(["dev-bootstrap"])
    documented_value = "correct-password"

    assert args.email == "admin@example.test"
    assert args.password == documented_value
    assert args.display_name == "Admin User"
    assert args.create_schema is True


def test_create_admin_requires_explicit_password() -> None:
    """Non-dev admin creation requires an explicit password."""
    with pytest.raises(SystemExit):
        parse_args(["create-admin", "--email", "admin@example.test"])


@pytest.mark.asyncio
async def test_run_bootstrap_creates_schema_and_documented_admin(tmp_path) -> None:
    """The dev bootstrap path creates a usable local admin in an empty SQLite DB."""
    database_path = tmp_path / "eve-dev.sqlite3"
    database_url = f"sqlite+aiosqlite:///{database_path}"
    args = Namespace(
        create_schema=True,
        database_url=database_url,
        email="admin@example.test",
        display_name="Admin User",
        **{"password": "correct-password"},
    )

    await run_bootstrap(args, settings=Settings(database_url=database_url))

    sessionmaker = create_sessionmaker(database_url)
    async with sessionmaker() as session:
        user = await session.scalar(select(User).where(User.email == "admin@example.test"))

    assert user is not None
    assert user.display_name == "Admin User"
    assert PasswordHasher().verify_password(args.password, user.password_hash)
    await sessionmaker.kw["bind"].dispose()
