"""phase 2: event attributes, anomaly score, attack steps

Revision ID: 0002_phase2
Revises: 0001_initial
Create Date: 2026-09-07
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_phase2"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("events", sa.Column("attributes", sa.JSON(), nullable=True))
    op.add_column(
        "events",
        sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0"),
    )

    op.create_table(
        "attack_steps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mitre_id", sa.String(length=20), nullable=True),
        sa.Column("mitre_name", sa.String(length=120), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("attack_steps")
    op.drop_column("events", "anomaly_score")
    op.drop_column("events", "attributes")
