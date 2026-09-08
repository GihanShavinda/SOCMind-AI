"""phase 7: triage/sla + analyst feedback

Revision ID: 0006_phase7
Revises: 0005_pwreset
Create Date: 2026-09-08

Idempotent, consistent with 0002-0005.
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_phase7"
down_revision = "0005_pwreset"
branch_labels = None
depends_on = None


def _has_column(table: str, col: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return col in [c["name"] for c in insp.get_columns(table)]


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_column("incidents", "triage_score"):
        op.add_column("incidents", sa.Column("triage_score", sa.Float(),
                      nullable=False, server_default="0"))
    if not _has_column("incidents", "sla_due_at"):
        op.add_column("incidents", sa.Column("sla_due_at", sa.DateTime(timezone=True),
                      nullable=True))

    if not _has_table("feedback"):
        op.create_table(
            "feedback",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
            sa.Column("analyst", sa.String(length=120), nullable=False),
            sa.Column("verdict", sa.Enum("CONFIRM", "DISMISS", "CORRECT", name="feedbackverdict"),
                      nullable=False),
            sa.Column("rule_id", sa.String(length=120), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    if _has_table("feedback"):
        op.drop_table("feedback")
    if _has_column("incidents", "sla_due_at"):
        op.drop_column("incidents", "sla_due_at")
    if _has_column("incidents", "triage_score"):
        op.drop_column("incidents", "triage_score")
