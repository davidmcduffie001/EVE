"""Command line utilities for local EVE administration."""

from __future__ import annotations

import argparse
import asyncio

from app.core.config import Settings, get_settings
from app.core.database import create_sessionmaker
from app.models.base import Base
from app.services.bootstrap import (
    create_or_update_local_admin,
    seed_builtin_intel_sources,
)

DEV_ADMIN_EMAIL = "admin@example.test"
DEV_ADMIN_PASSWORD = "correct-password"  # noqa: S105  # nosec B105
DEV_ADMIN_DISPLAY_NAME = "Admin User"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse EVE backend CLI arguments."""
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)

    dev_bootstrap = subcommands.add_parser(
        "dev-bootstrap",
        help="Create local development tables, seed baseline data, and create a test admin.",
    )
    _add_admin_arguments(
        dev_bootstrap,
        default_email=DEV_ADMIN_EMAIL,
        default_password=DEV_ADMIN_PASSWORD,
        default_display_name=DEV_ADMIN_DISPLAY_NAME,
    )
    dev_bootstrap.add_argument(
        "--no-create-schema",
        action="store_false",
        dest="create_schema",
        help="Skip direct ORM table creation.",
    )
    dev_bootstrap.set_defaults(create_schema=True)

    create_admin = subcommands.add_parser(
        "create-admin",
        help="Create or update a local Admin user in an already-migrated database.",
    )
    _add_admin_arguments(create_admin, password_required=True)
    create_admin.set_defaults(create_schema=False)

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Run the EVE backend CLI."""
    args = parse_args(argv)
    settings = get_settings()
    if args.command == "dev-bootstrap" and settings.env.lower() == "production":
        raise SystemExit("dev-bootstrap is disabled when EVE_ENV=production")

    asyncio.run(run_bootstrap(args, settings=settings))


async def run_bootstrap(args: argparse.Namespace, *, settings: Settings) -> None:
    """Run database bootstrap actions from parsed CLI arguments."""
    sessionmaker = create_sessionmaker(args.database_url or settings.database_url)
    if args.create_schema:
        async with sessionmaker.kw["bind"].begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async with sessionmaker() as session:
        await seed_builtin_intel_sources(session)
        user = await create_or_update_local_admin(
            session,
            email=args.email,
            password=args.password,
            display_name=args.display_name,
        )
        await session.commit()

    await sessionmaker.kw["bind"].dispose()
    print(f"Local admin ready: {user.email}")


def _add_admin_arguments(
    parser: argparse.ArgumentParser,
    *,
    default_email: str | None = None,
    default_password: str | None = None,
    default_display_name: str | None = None,
    password_required: bool = False,
) -> None:
    parser.add_argument("--database-url", default=None, help="Override EVE_DATABASE_URL.")
    parser.add_argument("--email", default=default_email, required=default_email is None)
    parser.add_argument(
        "--password",
        default=default_password,
        required=password_required and default_password is None,
    )
    parser.add_argument(
        "--display-name",
        default=default_display_name,
        required=default_display_name is None,
    )


if __name__ == "__main__":
    main()
