"""Drop the billing tables: the platform is free and nothing writes them.

The hosted service and the licence are both free, so there is no payment to take and no commercial
record to keep. ``services/billing.py``, ``billing_core.py``, ``invoicing.py``,
``polar_billing.py`` and ``routers/billing.py`` are gone, along with the operator portal's Revenue
views and the customer console's plan tab.

Revision 0008 is left exactly as it is. A migration that has been applied is history: editing it
would leave any database that already ran it unable to reconcile with the file, and `alembic
downgrade` would stop working. The way to undo a schema change is another revision, which is this
one.

Dropped in dependency order, children before parents, because the invoicing tables reference the
account they belong to. ``billing_invoice_sequences`` is in the list too: it held the vendor's own
invoice-number counters, which exist only to number invoices nobody will issue.

This is destructive and irreversible. ``downgrade`` refuses rather than recreating empty tables,
because an empty billing_invoices is not a restored one and a downgrade that appears to succeed is
worse than one that declines. A deployment with real invoices here should take a dump before
running this and keep it for however long its own tax rules require; the platform cannot know what
that period is and will not guess.
"""

from __future__ import annotations

from alembic import op

# Revision identifiers.
revision = "0009_drop_billing_tables"
down_revision = "0008_billing_providers_and_invoicing"
branch_labels = None
depends_on = None

#: Children first: billing_invoice_lines, _manual_payments and _invoice_events all point at
#: billing_manual_invoices, which points at billing_accounts.
_TABLES = (
    "billing_invoice_events",
    "billing_invoice_lines",
    "billing_manual_payments",
    "billing_manual_invoices",
    "billing_invoice_sequences",
    "billing_accounts",
    "billing_mrr_events",
    "billing_events",
    "billing_invoices",
    "billing_subscriptions",
    "billing_customers",
)


def upgrade() -> None:
    # CASCADE on Postgres only: SQLite has no such clause on DROP TABLE and answers with a syntax
    # error, and this revision runs on both backends. The order above already puts children before
    # parents, so CASCADE is belt and braces for a Postgres database that grew a view or a foreign
    # key from outside this migration.
    cascade = " CASCADE" if op.get_bind().dialect.name == "postgresql" else ""
    # IF EXISTS on every drop: these tables were also created lazily at runtime by the old
    # services/billing.init_tables, so a database may have some, all or none of them depending on
    # whether billing was ever switched on. A missing table is the expected case, not an error.
    for table in _TABLES:
        op.execute(f'DROP TABLE IF EXISTS "{table}"{cascade}')


def downgrade() -> None:
    """Refused, because it would be a lie.

    Recreating the tables is easy and useless: the rows are gone, and an empty billing_invoices is
    not a restored one. Anything that depended on this data needs the dump taken before the
    upgrade, restored by hand. Saying so is better than offering a downgrade that appears to work
    and silently returns an empty book.
    """
    raise NotImplementedError(
        "0009 dropped the billing tables and their contents. Recreating empty tables would not "
        "restore anything: restore the pre-upgrade dump instead, then re-run migrations from it."
    )
