"""Add user disabled timestamp.

Revision ID: a9d4f2c1e6b8
Revises: 8e4f05d8e2f7
Create Date: 2026-05-10 05:20:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a9d4f2c1e6b8"
down_revision: str | None = "8e4f05d8e2f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add disabled timestamp for local user administration."""
    op.add_column("users", sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    """Remove disabled timestamp."""
    op.drop_column("users", "disabled_at")
