"""Add description column to collections table.

Revision ID: 0002_collections_description
Revises: 0001_baseline
Create Date: 2026-06-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_collections_description"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The application bootstraps the schema itself (0001_baseline is only a stamp), and its own
    # CREATE TABLE for collections already includes `description`. Adding it unconditionally
    # therefore failed with DuplicateColumn on a bootstrapped database, and with UndefinedTable on
    # an empty one -- either way aborting `alembic upgrade head`. Both cases have to be tolerated
    # for the revision to be runnable on a real deployment.
    inspector = sa.inspect(op.get_bind())
    if "collections" not in inspector.get_table_names():
        return
    if any(col["name"] == "description" for col in inspector.get_columns("collections")):
        return
    with op.batch_alter_table("collections") as batch_op:
        batch_op.add_column(sa.Column("description", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "collections" not in inspector.get_table_names():
        return
    with op.batch_alter_table("collections") as batch_op:
        batch_op.drop_column("description")
