"""Baseline existing Morrow schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-05-10
"""

from __future__ import annotations

from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The application still owns bootstrap for existing deployments. This baseline
    # lets live Cloud SQL environments be stamped and future schema changes become
    # explicit Alembic revisions instead of ad hoc deploy-time DDL.
    op.execute("SELECT 1")


def downgrade() -> None:
    op.execute("SELECT 1")
