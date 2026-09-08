"""fr-1: password reset tokens

Revision ID: 0005_pwreset
Revises: 0004_phase6
Create Date: 2026-09-08

Idempotent, consistent with 0002-0004.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_pwreset"
down_revision = "0004_phase6"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("password_reset_tokens"):
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False, index=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    if _has_table("password_reset_tokens"):
        op.drop_table("password_reset_tokens")
