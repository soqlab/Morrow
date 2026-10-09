"""Add branch_cleanup and drift columns to remediations table.

Revision ID: 0003_remediations_branch_cleanup_cols
Revises: 0002_collections_description
Create Date: 2026-06-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_remediations_branch_cleanup_cols"
down_revision = "0002_collections_description"
branch_labels = None
depends_on = None

_NEW_COLS = [
    ("branch_cleanup_status",   sa.Text(),    ""),
    ("branch_cleanup_at",       sa.Text(),    ""),
    ("branch_cleanup_error",    sa.Text(),    ""),
    ("branch_cleanup_attempts", sa.Integer(), 0),
    ("parent_remediation_id",   sa.Integer(), 0),
    ("drift_status",            sa.Text(),    ""),
    ("drift_detected_at",       sa.Text(),    ""),
    ("drift_ack_at",            sa.Text(),    ""),
    ("drift_ack_actor",         sa.Text(),    ""),
    ("drift_ack_note",          sa.Text(),    ""),
    ("drift_details_json",      sa.Text(),    "{}"),
    ("review_note",             sa.Text(),    ""),
    ("merged_at",               sa.Text(),    ""),
]


def _existing_columns(table: str) -> set[str]:
    """Column names of `table`, on any backend.

    PRAGMA table_info() is SQLite-only: against Postgres it fails with `syntax error at or near
    "PRAGMA"`, which aborted the whole migration run. Since Postgres is the production database,
    that meant `alembic upgrade head` -- and therefore AUTO_MIGRATE=1 and APP_COMPONENT=migrate --
    could never succeed on a real deployment. The inspector is the portable equivalent.
    """
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    existing_cols = _existing_columns("remediations")
    with op.batch_alter_table("remediations") as batch_op:
        for col_name, col_type, default in _NEW_COLS:
            if col_name not in existing_cols:
                batch_op.add_column(sa.Column(col_name, col_type, nullable=False, server_default=str(default)))
    op.create_index("ix_remediations_branch_cleanup_status", "remediations", ["branch_cleanup_status"], if_not_exists=True)
    op.create_index("ix_remediations_parent_remediation_id", "remediations", ["parent_remediation_id"], if_not_exists=True)
    op.create_index("ix_remediations_drift_status",          "remediations", ["drift_status"],          if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_remediations_drift_status",          "remediations")
    op.drop_index("ix_remediations_parent_remediation_id", "remediations")
    op.drop_index("ix_remediations_branch_cleanup_status", "remediations")
    with op.batch_alter_table("remediations") as batch_op:
        for col_name, _, _ in reversed(_NEW_COLS):
            batch_op.drop_column(col_name)
