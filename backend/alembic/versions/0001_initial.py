"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-21

This baseline migration creates the full schema directly from the SQLAlchemy
model metadata, so the migration can never drift from the models. Subsequent
migrations should be produced with `alembic revision --autogenerate`.
"""
from alembic import op

from app.core.database import Base
import app.models  # noqa: F401  (register models on Base.metadata)

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
