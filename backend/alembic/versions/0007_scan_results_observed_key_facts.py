"""Record what the scan observed: key size, curve, cipher suite and scan status.

`scan_results` stored `key_type` and nothing else about the key, so every downstream report had to
invent the missing half: the org-wide CBOM resolved the entire estate to RSA-2048 / ECDSA-P256 and
the HNDL model priced every RSA endpoint at the RSA-2048 Q-Day probability, whatever the real key
size. It also had no way to tell a scan that failed from a scan that found an unclassifiable key.

All of these columns are NULLable, and that is load-bearing: NULL means "this scan did not observe
it" — a row written before this revision, or an endpoint that served no certificate. Readers must
render NULL as unknown rather than as zero or as a default algorithm.

The backfill only fills in what the stored key_type fixes on its own (Ed25519/Ed448/X25519/X448
have exactly one size and curve each, and the values match scanner._FIXED_KEY_BITS). RSA and the
bare "EC" that every elliptic-curve certificate
is stored as keep NULL, because a historic row genuinely does not say whether it was 2048 or 4096,
P-256 or P-521, and writing a guess is the bug this revision exists to fix.

Revision ID: 0007_scan_results_observed_key_facts
Revises: 0006_external_findings_security_truth
Create Date: 2026-09-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_scan_results_observed_key_facts"
down_revision = "0006_external_findings_security_truth"
branch_labels = None
depends_on = None


_COLUMNS = (
    ("key_bits", sa.Integer()),
    ("key_curve", sa.Text()),
    ("cipher_name", sa.Text()),
    ("scan_status", sa.Text()),
    # The negotiated TLS key-exchange group. Without it no org-wide report can tell whether an
    # endpoint runs hybrid post-quantum key exchange, however well the scanner observes it.
    ("key_exchange", sa.Text()),
)

#: key_type -> (bits, curve) for algorithms whose parameters are fixed by the algorithm itself.
_FIXED = (
    ("ed25519", 256, "Curve25519"),
    ("x25519", 256, "Curve25519"),
    ("ed448", 448, "Curve448"),
    ("x448", 448, "Curve448"),
)


def _table_exists(conn, name: str) -> bool:
    if conn.dialect.name == "sqlite":
        return bool(
            conn.execute(
                sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name=:name"),
                {"name": name},
            ).fetchone()
        )
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = current_schema() AND table_name = :name"
            ),
            {"name": name},
        ).fetchone()
    )


def _existing_columns(conn, table: str) -> set:
    if conn.dialect.name == "sqlite":
        return {row[1] for row in conn.execute(sa.text(f"PRAGMA table_info({table})")).fetchall()}
    rows = conn.execute(
        sa.text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :name"
        ),
        {"name": table},
    ).fetchall()
    return {str(r[0]) for r in rows}


def upgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "scan_results"):
        # A database that has never run the application has no scan_results yet; db.py creates it
        # with these columns already present.
        return

    present = _existing_columns(conn, "scan_results")
    for name, coltype in _COLUMNS:
        if name not in present:
            op.add_column("scan_results", sa.Column(name, coltype, nullable=True))

    for key_type, bits, curve in _FIXED:
        conn.execute(
            sa.text(
                "UPDATE scan_results SET key_bits = :bits, key_curve = :curve "
                "WHERE key_bits IS NULL AND LOWER(TRIM(key_type)) = :kt"
            ),
            {"bits": bits, "curve": curve, "kt": key_type},
        )


def downgrade() -> None:
    conn = op.get_bind()
    if not _table_exists(conn, "scan_results"):
        return
    present = _existing_columns(conn, "scan_results")
    for name, _ in reversed(_COLUMNS):
        if name in present:
            op.drop_column("scan_results", name)
