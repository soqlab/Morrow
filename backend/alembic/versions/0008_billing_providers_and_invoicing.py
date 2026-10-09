"""Provider-neutral billing: a provider column on the shared tables, and the direct-invoicing tables.

The vendor is based in Mauritius, where Stripe does not accept sellers, so money now arrives three
ways: a direct invoice paid by bank transfer (the primary path), a card subscription through Polar
as merchant of record, and the dormant Stripe integration. Two schema changes follow from that.

1. ``provider`` on ``billing_customers``, ``billing_subscriptions``, ``billing_invoices``,
   ``billing_events`` and ``billing_mrr_events``. The default is ``'stripe'`` and that is
   load-bearing: every row that exists before this revision was written by the Stripe integration,
   which was the only one there was. Keeping one set of tables is what makes MRR, ARR, outstanding
   and collected merge into a single revenue picture instead of needing one query per provider.

2. The direct-invoicing tables, which have no upstream system to copy from -- this platform *is*
   their system of record: the invoice, its line and tax items, the payments recorded against it,
   its status history, and the number counters.

Both backends. These tables are also created lazily at runtime by
``services/billing.init_tables`` through ``register_deferred_schema`` (the feature-store path), so
this revision exists to put the change on the migration path for a database that is migrated by a
privileged role before the application ever connects with a least-privilege one. Everything here is
guarded on what is already present, so running it after the runtime created the tables is a no-op.

``billing_invoice_sequences`` deliberately carries no organization_id: it holds the vendor's own
invoice-number counters, not any customer's data, and is therefore outside the row-level-security
plan (see services/postgres_rls.py).

Revision ID: 0008_billing_providers_and_invoicing
Revises: 0007_scan_results_observed_key_facts
Create Date: 2026-09-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_billing_providers_and_invoicing"
down_revision = "0007_scan_results_observed_key_facts"
branch_labels = None
depends_on = None


_PROVIDER_TABLES = (
    "billing_customers",
    "billing_subscriptions",
    "billing_invoices",
    "billing_events",
    "billing_mrr_events",
)


def _tables(conn) -> set:
    return set(sa.inspect(conn).get_table_names())


def _columns(conn, table: str) -> set:
    return {col["name"] for col in sa.inspect(conn).get_columns(table)}


def upgrade() -> None:
    conn = op.get_bind()
    present = _tables(conn)

    for table in _PROVIDER_TABLES:
        if table in present and "provider" not in _columns(conn, table):
            op.add_column(table, sa.Column("provider", sa.Text(), nullable=False, server_default="stripe"))

    if "billing_invoice_sequences" not in present:
        op.create_table(
            "billing_invoice_sequences",
            sa.Column("sequence_key", sa.Text(), primary_key=True),
            sa.Column("next_number", sa.BigInteger(), nullable=False, server_default="1"),
            sa.Column("updated_at", sa.Text(), nullable=False),
        )

    if "billing_accounts" not in present:
        op.create_table(
            "billing_accounts",
            sa.Column("organization_id", sa.Text(), primary_key=True),
            sa.Column("provider", sa.Text(), nullable=False, server_default="none"),
            sa.Column("pay_by", sa.Text(), nullable=False, server_default="none"),
            sa.Column("edition", sa.Text(), nullable=False, server_default=""),
            sa.Column("status", sa.Text(), nullable=False, server_default=""),
            sa.Column("currency", sa.Text(), nullable=False, server_default=""),
            sa.Column("contract_value_minor", sa.BigInteger(), nullable=True),
            sa.Column("billing_interval", sa.Text(), nullable=False, server_default=""),
            sa.Column("period_start", sa.Text(), nullable=True),
            sa.Column("period_end", sa.Text(), nullable=True),
            sa.Column("payment_terms_days", sa.Integer(), nullable=True),
            sa.Column("order_form_ref", sa.Text(), nullable=False, server_default=""),
            sa.Column("purchase_order", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_name", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_email", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_attention", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_address", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_country", sa.Text(), nullable=False, server_default=""),
            sa.Column("bill_to_tax_id", sa.Text(), nullable=False, server_default=""),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("status_changed_at", sa.Text(), nullable=True),
            sa.Column("created_at", sa.Text(), nullable=False),
            sa.Column("updated_at", sa.Text(), nullable=False),
        )
        op.create_index("idx_billing_accounts_pay_by", "billing_accounts", ["pay_by"])
        op.create_index("idx_billing_accounts_provider", "billing_accounts", ["provider"])

    if "billing_manual_invoices" not in present:
        op.create_table(
            "billing_manual_invoices",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("organization_id", sa.Text(), nullable=False),
            # NULL until the invoice is issued: a draft consumes no number, which is what keeps the
            # sequence gapless when a draft is discarded. NULLs repeat freely under a unique index
            # on both backends, so the same index proves no two issued invoices share a number.
            sa.Column("number", sa.Text(), nullable=True),
            sa.Column("sequence_key", sa.Text(), nullable=False, server_default=""),
            sa.Column("sequence_number", sa.BigInteger(), nullable=True),
            sa.Column("status", sa.Text(), nullable=False, server_default="draft"),
            sa.Column("currency", sa.Text(), nullable=False, server_default=""),
            sa.Column("edition", sa.Text(), nullable=False, server_default=""),
            sa.Column("subtotal_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("tax_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("total_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("paid_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("issue_date", sa.Text(), nullable=True),
            sa.Column("due_date", sa.Text(), nullable=True),
            sa.Column("period_start", sa.Text(), nullable=True),
            sa.Column("period_end", sa.Text(), nullable=True),
            sa.Column("payment_terms", sa.Text(), nullable=False, server_default=""),
            sa.Column("purchase_order", sa.Text(), nullable=False, server_default=""),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("vendor_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("bill_to_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("bank_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("void_reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("issued_at", sa.Text(), nullable=True),
            sa.Column("paid_at", sa.Text(), nullable=True),
            sa.Column("voided_at", sa.Text(), nullable=True),
            sa.Column("overdue_at", sa.Text(), nullable=True),
            sa.Column("overdue_notified_at", sa.Text(), nullable=True),
            sa.Column("created_by", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.Text(), nullable=False),
            sa.Column("updated_at", sa.Text(), nullable=False),
        )
        op.create_index("idx_billing_manual_invoice_number", "billing_manual_invoices", ["number"], unique=True)
        op.create_index("idx_billing_manual_invoices_org", "billing_manual_invoices", ["organization_id"])
        op.create_index("idx_billing_manual_invoices_status", "billing_manual_invoices", ["status"])

    if "billing_invoice_lines" not in present:
        op.create_table(
            "billing_invoice_lines",
            sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
            sa.Column("invoice_id", sa.Text(), nullable=False),
            sa.Column("organization_id", sa.Text(), nullable=False),
            sa.Column("kind", sa.Text(), nullable=False, server_default="item"),
            sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("quantity", sa.BigInteger(), nullable=False, server_default="1"),
            sa.Column("unit_amount_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("amount_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("tax_rate_bp", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.Text(), nullable=False),
        )
        op.create_index("idx_billing_invoice_lines_invoice", "billing_invoice_lines", ["invoice_id"])

    if "billing_manual_payments" not in present:
        op.create_table(
            "billing_manual_payments",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("invoice_id", sa.Text(), nullable=False),
            sa.Column("organization_id", sa.Text(), nullable=False),
            sa.Column("amount_minor", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("currency", sa.Text(), nullable=False, server_default=""),
            sa.Column("received_on", sa.Text(), nullable=False),
            sa.Column("received_at", sa.Text(), nullable=False),
            sa.Column("method", sa.Text(), nullable=False, server_default=""),
            sa.Column("reference", sa.Text(), nullable=False, server_default=""),
            sa.Column("note", sa.Text(), nullable=False, server_default=""),
            sa.Column("recorded_by", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.Text(), nullable=False),
        )
        op.create_index("idx_billing_manual_payments_invoice", "billing_manual_payments", ["invoice_id"])
        op.create_index("idx_billing_manual_payments_org", "billing_manual_payments", ["organization_id"])

    if "billing_invoice_events" not in present:
        op.create_table(
            "billing_invoice_events",
            sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
            sa.Column("invoice_id", sa.Text(), nullable=False),
            sa.Column("organization_id", sa.Text(), nullable=False),
            sa.Column("action", sa.Text(), nullable=False),
            sa.Column("from_status", sa.Text(), nullable=False, server_default=""),
            sa.Column("to_status", sa.Text(), nullable=False, server_default=""),
            sa.Column("reason", sa.Text(), nullable=False, server_default=""),
            sa.Column("actor", sa.Text(), nullable=False, server_default=""),
            sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.Text(), nullable=False),
        )
        op.create_index("idx_billing_invoice_events_invoice", "billing_invoice_events", ["invoice_id"])


def downgrade() -> None:
    conn = op.get_bind()
    present = _tables(conn)
    for table in ("billing_invoice_events", "billing_manual_payments", "billing_invoice_lines",
                  "billing_manual_invoices", "billing_accounts", "billing_invoice_sequences"):
        if table in present:
            op.drop_table(table)
    for table in _PROVIDER_TABLES:
        if table in present and "provider" in _columns(conn, table):
            op.drop_column(table, "provider")
