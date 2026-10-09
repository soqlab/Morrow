"""Schema adjustments for enterprise security hardening.

Adds: request_id tracking column to audit_log, ip_address column to audit_log.

Revision ID: 0005_rate_limiting_and_security
Revises: 0004_event_rules_org_id
Create Date: 2026-06-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_rate_limiting_and_security"
down_revision = "0004_event_rules_org_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # sqlite_master and PRAGMA table_info() are SQLite-only and raise a syntax error on Postgres,
    # which aborted the entire migration run on the production backend. The inspector is portable.
    inspector = sa.inspect(op.get_bind())

    if "audit_log" in inspector.get_table_names():
        al_cols = {col["name"] for col in inspector.get_columns("audit_log")}
        with op.batch_alter_table("audit_log") as batch_op:
            if "ip_address" not in al_cols:
                batch_op.add_column(sa.Column("ip_address", sa.Text(), nullable=False, server_default=""))
            if "request_id" not in al_cols:
                batch_op.add_column(sa.Column("request_id", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_column("request_id")
        batch_op.drop_column("ip_address")
