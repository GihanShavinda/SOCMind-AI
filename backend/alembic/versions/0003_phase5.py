"""phase 5: decisions, actions, asset automation policy

Revision ID: 0003_phase5
Revises: 0002_phase2
Create Date: 2026-09-07

Idempotent (see 0002 note): guarded so it applies cleanly on a fresh DB (where
the metadata baseline already created these) and on an existing DB (where it adds
them for the first time).
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_phase5"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None


def _has_column(table: str, col: str) -> bool:
    insp = sa.inspect(op.get_bind())
    return col in [c["name"] for c in insp.get_columns(table)]


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    # Per-asset automation policy (FR-34)
    if not _has_column("assets", "automation_enabled"):
        op.add_column("assets", sa.Column("automation_enabled", sa.Boolean(),
                      nullable=False, server_default=sa.false()))
    if not _has_column("assets", "auto_action_types"):
        op.add_column("assets", sa.Column("auto_action_types", sa.JSON(), nullable=True))

    if not _has_table("decisions"):
        op.create_table(
            "decisions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
            sa.Column("action_type", sa.String(length=60), nullable=False),
            sa.Column("threat_conf", sa.Float(), nullable=False, server_default="0"),
            sa.Column("response_conf", sa.Float(), nullable=False, server_default="0"),
            sa.Column("asset_crit", sa.String(length=20), nullable=False, server_default="Low"),
            sa.Column("impact", sa.String(length=20), nullable=False, server_default="Low"),
            sa.Column("outcome", sa.Enum("AUTOMATE", "APPROVAL_REQUIRED", name="decisionoutcome"),
                      nullable=False),
            sa.Column("rationale", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        )

    if not _has_table("actions"):
        op.create_table(
            "actions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), nullable=False),
            sa.Column("decision_id", sa.Integer(), sa.ForeignKey("decisions.id"), nullable=True),
            sa.Column("type", sa.String(length=60), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("risk_level", sa.Enum("LOW", "MEDIUM", "HIGH", "RESTRICTED", name="risklevel"),
                      nullable=False, server_default="MEDIUM"),
            sa.Column("status", sa.Enum("PROPOSED", "PENDING_APPROVAL", "APPROVED", "REJECTED",
                      "EXECUTED", "ROLLED_BACK", name="actionstatus"),
                      nullable=False, server_default="PROPOSED"),
            sa.Column("reversible", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("undo_ref", sa.String(length=255), nullable=True),
            sa.Column("performed_by", sa.String(length=120), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    if _has_table("actions"):
        op.drop_table("actions")
    if _has_table("decisions"):
        op.drop_table("decisions")
    if _has_column("assets", "auto_action_types"):
        op.drop_column("assets", "auto_action_types")
    if _has_column("assets", "automation_enabled"):
        op.drop_column("assets", "automation_enabled")
