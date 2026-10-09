"""Add persisted external findings queue for Security Truth.

Revision ID: 0006_external_findings_security_truth
Revises: 0005_rate_limiting_and_security
Create Date: 2026-06-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_external_findings_security_truth"
down_revision = "0005_rate_limiting_and_security"
branch_labels = None
depends_on = None


def _table_exists(conn, name: str) -> bool:
    dialect = conn.dialect.name
    if dialect == "sqlite":
        return bool(conn.execute(sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"), {"name": name}).fetchone())
    return bool(
        conn.execute(
            sa.text("SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = :name"),
            {"name": name},
        ).fetchone()
    )


def upgrade() -> None:
    conn = op.get_bind()
    dialect = conn.dialect.name
    if not _table_exists(conn, "external_findings"):
        id_type = sa.BigInteger() if dialect != "sqlite" else sa.Integer()
        evidence_type = postgresql.JSONB() if dialect == "postgresql" else sa.JSON()
        evidence_default = sa.text("'{}'::jsonb") if dialect == "postgresql" else "{}"
        op.create_table(
            "external_findings",
            sa.Column("id", id_type, primary_key=True, autoincrement=True),
            sa.Column("organization_id", sa.Text(), nullable=False),
            sa.Column("batch_id", sa.Text(), nullable=False),
            sa.Column("tool_source", sa.Text(), nullable=False),
            sa.Column("integration_type", sa.Text(), nullable=False),
            sa.Column("external_id", sa.Text(), nullable=False, server_default=""),
            sa.Column("title", sa.Text(), nullable=False, server_default=""),
            sa.Column("severity", sa.Text(), nullable=False, server_default="medium"),
            sa.Column("category", sa.Text(), nullable=False, server_default="external"),
            sa.Column("resource_type", sa.Text(), nullable=False, server_default=""),
            sa.Column("resource_id", sa.Text(), nullable=False, server_default=""),
            sa.Column("repo", sa.Text(), nullable=False, server_default=""),
            sa.Column("file_path", sa.Text(), nullable=False, server_default=""),
            sa.Column("line", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
            sa.Column("evidence_json", evidence_type, nullable=False, server_default=evidence_default),
            sa.Column("status", sa.Text(), nullable=False, server_default="open"),
            sa.Column("write_path_request_id", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.Text(), nullable=False),
            sa.Column("updated_at", sa.Text(), nullable=False),
        )
    op.create_index("idx_external_findings_org", "external_findings", ["organization_id"], if_not_exists=True)
    op.create_index("idx_external_findings_batch", "external_findings", ["batch_id"], if_not_exists=True)
    op.create_index("idx_external_findings_severity", "external_findings", ["severity"], if_not_exists=True)
    op.create_index("idx_external_findings_status", "external_findings", ["status"], if_not_exists=True)
    op.create_index("idx_external_findings_repo", "external_findings", ["repo"], if_not_exists=True)


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "external_findings"):
        return
    for name in (
        "idx_external_findings_repo",
        "idx_external_findings_status",
        "idx_external_findings_severity",
        "idx_external_findings_batch",
        "idx_external_findings_org",
    ):
        op.drop_index(name, table_name="external_findings", if_exists=True)
    op.drop_table("external_findings")
