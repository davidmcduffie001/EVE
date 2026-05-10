"""add auth session foundation

Revision ID: 8e4f05d8e2f7
Revises: 2cbec45ccc3d
Create Date: 2026-05-09 20:14:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8e4f05d8e2f7"
down_revision: str | None = "2cbec45ccc3d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply schema changes."""
    op.add_column(
        "users",
        sa.Column("password_hash", sa.String(length=512), server_default="", nullable=False),
    )
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_refresh_sessions_refresh_token_hash"),
        "refresh_sessions",
        ["refresh_token_hash"],
        unique=True,
    )
    op.create_index(op.f("ix_refresh_sessions_user_id"), "refresh_sessions", ["user_id"])


def downgrade() -> None:
    """Revert schema changes."""
    op.drop_index(op.f("ix_refresh_sessions_user_id"), table_name="refresh_sessions")
    op.drop_index(op.f("ix_refresh_sessions_refresh_token_hash"), table_name="refresh_sessions")
    op.drop_table("refresh_sessions")
    op.drop_column("users", "password_hash")
