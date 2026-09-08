"""phase 6: user mfa secret

Revision ID: 0004_phase6
Revises: 0003_phase5
Create Date: 2026-09-08

Idempotent, consistent with 0002/0003.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_phase6"
down_revision = "0003_phase5"
branch_labels = None
depends_on = None


def _has_column(table: str, col: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return col in [c["name"] for c in insp.get_columns(table)]


def upgrade() -> None:
    if not _has_column("users", "mfa_secret"):
        op.add_column("users", sa.Column("mfa_secret", sa.String(length=64), nullable=True))


def downgrade() -> None:
    if _has_column("users", "mfa_secret"):
        op.drop_column("users", "mfa_secret")
