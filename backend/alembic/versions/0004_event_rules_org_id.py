"""Add organization_id and missing columns to event_rules; add event_rule_fires table.

Revision ID: 0004_event_rules_org_id
Revises: 0003_remediations_branch_cleanup_cols
Create Date: 2026-06-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_event_rules_org_id"
down_revision = "0003_remediations_branch_cleanup_cols"
branch_labels = None
depends_on = None


def _inspect():
    """Backend-agnostic schema introspection.

    PRAGMA table_info() and sqlite_master are SQLite-only; against the production Postgres database
    they raise a syntax error and abort `alembic upgrade head` entirely. The inspector works on both.
    """
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    inspector = _inspect()
    existing_tables = set(inspector.get_table_names())

    # event_rules: add missing columns
    er_cols = (
        {col["name"] for col in inspector.get_columns("event_rules")}
        if "event_rules" in existing_tables
        else set()
    )
    with op.batch_alter_table("event_rules") as batch_op:
        if "organization_id" not in er_cols:
            batch_op.add_column(sa.Column("organization_id", sa.Text(), nullable=False, server_default=""))
        if "cooldown_minutes" not in er_cols:
            batch_op.add_column(sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="0"))
        if "quantum_score_min" not in er_cols:
            batch_op.add_column(sa.Column("quantum_score_min", sa.Float(), nullable=False, server_default="-1"))
        if "fire_mode" not in er_cols:
            batch_op.add_column(sa.Column("fire_mode", sa.Text(), nullable=False, server_default="always"))

    op.create_index("ix_event_rules_organization_id", "event_rules", ["organization_id"], if_not_exists=True)
    op.create_index("ix_event_rules_enabled",         "event_rules", ["enabled"],         if_not_exists=True)

    # event_rule_fires: create if missing
    if "event_rule_fires" not in existing_tables:
        op.create_table(
            "event_rule_fires",
            sa.Column("organization_id", sa.Text(), nullable=False, server_default=""),
            sa.Column("rule_id",         sa.Integer(), nullable=False),
            sa.Column("fingerprint",     sa.Text(), nullable=False),
            sa.Column("last_fired_at",   sa.Text(), nullable=False),
            sa.PrimaryKeyConstraint("organization_id", "rule_id", "fingerprint"),
            sa.ForeignKeyConstraint(["rule_id"], ["event_rules.id"], ondelete="CASCADE"),
        )
    op.create_index("ix_event_rule_fires_rule_id", "event_rule_fires", ["rule_id"], if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_event_rule_fires_rule_id",    "event_rule_fires")
    op.drop_table("event_rule_fires")
    op.drop_index("ix_event_rules_enabled",         "event_rules")
    op.drop_index("ix_event_rules_organization_id", "event_rules")
    with op.batch_alter_table("event_rules") as batch_op:
        for col in ("fire_mode", "quantum_score_min", "cooldown_minutes", "organization_id"):
            batch_op.drop_column(col)
