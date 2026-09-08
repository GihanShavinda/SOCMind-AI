"""phase 2: event attributes, anomaly score, attack steps

Revision ID: 0002_phase2
Revises: 0001_initial
Create Date: 2026-09-07

Idempotent: the baseline (0001) builds tables from current model metadata, so on
a brand-new database these objects may already exist. We guard each change so the
chain applies cleanly whether starting fresh or upgrading an existing DB.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_phase2"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _has_column(table: str, col: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return col in [c["name"] for c in insp.get_columns(table)]


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_column("events", "attributes"):
        op.add_column("events", sa.Column("attributes", sa.JSON(), nullable=True))
    if not _has_column("events", "anomaly_score"):
        op.add_column(
            "events",
            sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0"),
        )

    if not _has_table("attack_steps"):
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
    if _has_table("attack_steps"):
        op.drop_table("attack_steps")
    if _has_column("events", "anomaly_score"):
        op.drop_column("events", "anomaly_score")
    if _has_column("events", "attributes"):
        op.drop_column("events", "attributes")
