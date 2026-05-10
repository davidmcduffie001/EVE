"""add sso configuration

Revision ID: c31c60fcb21e
Revises: a9d4f2c1e6b8
Create Date: 2026-05-10 03:45:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c31c60fcb21e"
down_revision: str | None = "a9d4f2c1e6b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply schema changes."""
    op.create_table(
        "sso_configurations",
        sa.Column("id", sa.String(length=40), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("provider", sa.Enum("oidc", "saml", name="sso_provider"), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("issuer_url", sa.String(length=2048), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("metadata_url", sa.String(length=2048), nullable=False),
        sa.Column("encrypted_client_secret", sa.Text(), nullable=True),
        sa.Column("auto_provision", sa.Boolean(), nullable=False),
        sa.Column("default_role", sa.String(length=120), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Revert schema changes."""
    op.drop_table("sso_configurations")
    sa.Enum("oidc", "saml", name="sso_provider").drop(op.get_bind(), checkfirst=True)
