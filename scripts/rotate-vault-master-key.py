#!/usr/bin/env python3
"""Rotate MORROW_VAULT_MASTER_KEY: re-encrypt every value sealed with it, verify, and commit.

What is encrypted with the vault key (Fernet):

  * credentials.secret_enc                 Postgres (DATABASE_URL)   vault_db / vault_crypto
  * gateway_sites.data -> "sealed_key"     feature store             services/gateway.py
  * platform_operator_mfa.secret_enc       feature store             services/operator_auth.py (TOTP secrets)
  * platform_alert_channels.target_sealed  feature store             services/alert_routing.py ("fernet:" prefix:
                                                                     Slack/PagerDuty/webhook targets; "plain:"
                                                                     email recipient lists are not encrypted)
  * github_tokens.access_token             main SQLite database      services/github_oauth.py (derived key)

Other uses of MORROW_VAULT_MASTER_KEY are keyed hashes and signatures, not ciphertexts, so there is nothing
to re-encrypt: HS256 SSO JWTs (short-lived), evidence signatures (unless MORROW_EVIDENCE_SIGNING_KEY is
set), security-journal subject references and usage actor hashes (unless MORROW_USAGE_ACTOR_SALT is set).

The feature store is SQLite (MORROW_SCANNER_DB) unless MORROW_FEATURE_STORE_BACKEND / MORROW_MAIN_DB_BACKEND
select Postgres, in which case it lives in MORROW_PRODUCT_DATABASE_URL / DATABASE_URL.

Keys are read from the environment and never printed:

  MORROW_VAULT_MASTER_KEY       the current key (required)
  MORROW_VAULT_MASTER_KEY_NEW   the new key; or pass --generate-new-key-file PATH to create one. The
                             file is created exclusively (never overwritten) with owner-only
                             permissions, before anything is committed.

Default is a dry run: every value is decrypted with the old key, re-encrypted with the new key and
verified inside open transactions, which are then rolled back. --apply commits. Each database is one
transaction; with more than one database, all are prepared and verified first and committed last,
and if a later commit fails the earlier ones are restored to their original ciphertexts.

Exit codes: 0 success, 1 usage or configuration error, 2 a value could not be decrypted with the
old key (nothing changed), 3 commit or restore failure (read the report).

Usage (from the repository root, with the service stopped or in maintenance mode):

  set MORROW_VAULT_MASTER_KEY / MORROW_VAULT_MASTER_KEY_NEW in the environment
  backend/.venv/Scripts/python.exe scripts/rotate-vault-master-key.py            # dry run
  backend/.venv/Scripts/python.exe scripts/rotate-vault-master-key.py --apply    # commit
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sqlite3
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from cryptography.fernet import Fernet, InvalidToken  # noqa: E402


class RotationError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


# ── Key handling ─────────────────────────────────────────────────────────────


def vault_fernet(raw_key: str) -> Fernet:
    """vault_crypto: the env value is the Fernet key itself."""
    return Fernet(raw_key.strip().encode("utf-8"))


def github_fernet(raw_key: str) -> Fernet:
    """services/github_oauth.py: base64-decode, take 32 bytes (zero padded), urlsafe-encode."""
    raw_key = raw_key.strip()
    try:
        raw = base64.b64decode(raw_key)
    except Exception:
        raw = raw_key.encode()
    return Fernet(base64.urlsafe_b64encode(raw[:32].ljust(32, b"\x00")))


def check_key(name: str, value: str) -> None:
    try:
        vault_fernet(value)
    except Exception:
        raise RotationError(1, f"{name} is not a valid Fernet key (32 url-safe base64-encoded bytes).") from None


def write_key_file(path: str, key: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise RotationError(1, f"Refusing to overwrite existing file {path}.") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(key.encode("ascii") + b"\n")
    if os.name == "nt":  # owner-only ACL; os.open's mode does not restrict access on Windows
        user = os.environ.get("USERNAME") or getpass.getuser()
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.chmod(path, 0o600)


# ── Stores ───────────────────────────────────────────────────────────────────


class Store:
    """One database connection holding one transaction."""

    def __init__(self, label: str, kind: str, target: str):
        self.label, self.kind, self.target = label, kind, target
        self.conn: Any = None
        self.ph = "?" if kind == "sqlite" else "%s"
        self.updates: List[Tuple[str, str, str, Any, Any, Any]] = []  # (table, key_col, value_col, key, old, new)

    def open(self) -> None:
        if self.kind == "sqlite":
            if not os.path.exists(self.target):
                raise RotationError(1, f"SQLite database not found: {self.label}")
            self.conn = sqlite3.connect(self.target, timeout=30, isolation_level=None)
            self.conn.execute("BEGIN IMMEDIATE")  # blocks other writers until commit/rollback
        else:
            import psycopg2

            self.conn = psycopg2.connect(self.target)
            self.conn.autocommit = False

    def table_exists(self, table: str) -> bool:
        if self.kind == "sqlite":
            return bool(self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())
        cur = self.conn.cursor()
        cur.execute("SELECT to_regclass(%s)", (table,))
        return cur.fetchone()[0] is not None

    def query(self, sql: str, params: Tuple = ()) -> List[Tuple]:
        sql = sql.replace("?", self.ph)
        if self.kind == "sqlite":
            return list(self.conn.execute(sql, params).fetchall())
        cur = self.conn.cursor()
        # None, not (), when there are no parameters: psycopg2 %-formats the statement whenever a sequence is
        # passed, so a literal such as LIKE 'fernet:%' raised IndexError and failed every Postgres rotation.
        cur.execute(sql, params or None)
        return list(cur.fetchall()) if cur.description else []

    def execute(self, sql: str, params: Tuple = ()) -> int:
        sql = sql.replace("?", self.ph)
        if self.kind == "sqlite":
            return int(self.conn.execute(sql, params).rowcount or 0)
        cur = self.conn.cursor()
        cur.execute(sql, params or None)
        return int(cur.rowcount or 0)

    def commit(self) -> None:
        if self.kind == "sqlite":
            self.conn.execute("COMMIT")
        else:
            self.conn.commit()

    def rollback(self) -> None:
        try:
            if self.kind == "sqlite":
                self.conn.execute("ROLLBACK")
            else:
                self.conn.rollback()
        except Exception:
            pass

    def close(self) -> None:
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass


def _truthy(name: str) -> Optional[bool]:
    value = str(os.getenv(name) or "").strip().lower()
    if value in {"postgres", "postgresql", "pg", "1", "true"}:
        return True
    if value in {"sqlite", "file", "0", "false"}:
        return False
    return None


def discover_stores(args: argparse.Namespace) -> Dict[str, Store]:
    """Return {"main": Store, "feature": Store, "vault": Store?}; identical targets share one Store."""
    sqlite_path = args.sqlite or os.getenv("MORROW_SCANNER_DB") or ""
    if not sqlite_path:
        try:
            from db import DB_PATH  # noqa: WPS433

            sqlite_path = DB_PATH
        except Exception:
            sqlite_path = os.path.join(BACKEND, "morrow.db")
    stores: Dict[str, Store] = {}
    by_target: Dict[str, Store] = {}

    def store(role: str, label: str, kind: str, target: str) -> None:
        key = f"{kind}:{target}"
        if key not in by_target:
            by_target[key] = Store(label, kind, target)
        stores[role] = by_target[key]

    store("main", "main SQLite database", "sqlite", sqlite_path)
    feature_pg = _truthy("MORROW_FEATURE_STORE_BACKEND")
    if feature_pg is None:
        feature_pg = str(os.getenv("MORROW_MAIN_DB_BACKEND") or "").strip().lower() in {"postgres", "postgresql", "pg"}
    if feature_pg:
        dsn = os.getenv("MORROW_PRODUCT_DATABASE_URL") or os.getenv("DATABASE_URL") or ""
        if not dsn:
            raise RotationError(1, "The feature store is Postgres but no MORROW_PRODUCT_DATABASE_URL / DATABASE_URL is set.")
        store("feature", "feature-store Postgres", "pg", dsn)
    else:
        store("feature", "feature-store SQLite (same file as main)", "sqlite", sqlite_path)
    vault_dsn = os.getenv("DATABASE_URL") or ""
    if vault_dsn and not args.skip_postgres_vault:
        store("vault", "vault Postgres (DATABASE_URL)", "pg", vault_dsn)
    return stores


# ── Targets ──────────────────────────────────────────────────────────────────


def rotate_column(store: Store, table: str, key_col: str, value_col: str, old: Fernet, new: Fernet,
                  report: Dict[str, Any], label: str) -> None:
    entry = report.setdefault(label, {"table": table, "store": store.label, "rows": 0, "rotated": 0, "undecryptable": [], "present": True})
    if not store.table_exists(table):
        entry["present"] = False
        return
    lock = "" if store.kind == "sqlite" else " FOR UPDATE"
    rows = store.query(f"SELECT {key_col}, {value_col} FROM {table} WHERE {value_col} IS NOT NULL AND {value_col} <> ''{lock}")
    entry["rows"] = len(rows)
    for key, token in rows:
        try:
            plain = old.decrypt(str(token).encode("utf-8"))
        except InvalidToken:
            entry["undecryptable"].append(str(key))
            continue
        fresh = new.encrypt(plain).decode("utf-8")
        store.execute(f"UPDATE {table} SET {value_col} = ? WHERE {key_col} = ? AND {value_col} = ?", (fresh, key, token))
        store.updates.append((table, key_col, value_col, key, token, fresh))
        entry["rotated"] += 1


def rotate_gateway(store: Store, old: Fernet, new: Fernet, report: Dict[str, Any]) -> None:
    entry = report.setdefault("gateway_sealed_keys", {"table": "gateway_sites", "store": store.label, "rows": 0, "rotated": 0, "undecryptable": [], "present": True})
    if not store.table_exists("gateway_sites"):
        entry["present"] = False
        return
    lock = "" if store.kind == "sqlite" else " FOR UPDATE"
    for site_id, data in store.query(f"SELECT id, data FROM gateway_sites{lock}"):
        try:
            value = json.loads(data)
        except (TypeError, ValueError):
            continue
        sealed = value.get("sealed_key") if isinstance(value, dict) else None
        if not sealed:
            continue
        entry["rows"] += 1
        try:
            plain = old.decrypt(str(sealed).encode("utf-8"))
        except InvalidToken:
            entry["undecryptable"].append(str(site_id))
            continue
        value["sealed_key"] = new.encrypt(plain).decode("utf-8")
        # Same canonical form services/gateway.py writes, so the site digest logic is unaffected.
        fresh = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        store.execute("UPDATE gateway_sites SET data = ? WHERE id = ? AND data = ?", (fresh, site_id, data))
        store.updates.append(("gateway_sites", "id", "data", site_id, data, fresh))
        entry["rotated"] += 1


ALERT_PREFIX = "fernet:"


def rotate_alert_channels(store: Store, old: Fernet, new: Fernet, report: Dict[str, Any]) -> None:
    """services/alert_routing.py seals secret targets as "fernet:" + vault_crypto token; "plain:" rows are skipped."""
    entry = report.setdefault("alert_channel_targets", {"table": "platform_alert_channels", "store": store.label, "rows": 0, "rotated": 0,
                                                        "undecryptable": [], "present": True})
    if not store.table_exists("platform_alert_channels"):
        entry["present"] = False
        return
    lock = "" if store.kind == "sqlite" else " FOR UPDATE"
    rows = store.query(f"SELECT id, target_sealed FROM platform_alert_channels WHERE target_sealed LIKE 'fernet:%'{lock}")
    entry["rows"] = len(rows)
    for channel_id, sealed in rows:
        try:
            plain = old.decrypt(str(sealed)[len(ALERT_PREFIX):].encode("utf-8"))
        except InvalidToken:
            entry["undecryptable"].append(str(channel_id))
            continue
        fresh = ALERT_PREFIX + new.encrypt(plain).decode("utf-8")
        store.execute("UPDATE platform_alert_channels SET target_sealed = ? WHERE id = ? AND target_sealed = ?", (fresh, channel_id, sealed))
        store.updates.append(("platform_alert_channels", "id", "target_sealed", channel_id, sealed, fresh))
        entry["rotated"] += 1


def verify_store(store: Store, fernets: Dict[str, Fernet]) -> int:
    """Re-read every updated value inside the transaction and decrypt it with the new key."""
    checked = 0
    for table, key_col, value_col, key, _old, fresh in store.updates:
        row = store.query(f"SELECT {value_col} FROM {table} WHERE {key_col} = ?", (key,))
        if not row or row[0][0] != fresh:
            raise RotationError(3, f"Verification failed: {table} row {key} was not updated as expected.")
        if table == "gateway_sites":
            token = json.loads(row[0][0])["sealed_key"]
            fernet = fernets["vault"]
        elif table == "platform_alert_channels":
            token = str(row[0][0])[len(ALERT_PREFIX):]
            fernet = fernets["vault"]
        else:
            token = row[0][0]
            fernet = fernets["github"] if table == "github_tokens" else fernets["vault"]
        fernet.decrypt(str(token).encode("utf-8"))  # raises InvalidToken on failure
        checked += 1
    return checked


def restore(store: Store) -> int:
    """Compensate a committed store: write every original ciphertext back."""
    store.open()
    restored = 0
    for table, key_col, value_col, key, original, fresh in store.updates:
        restored += store.execute(f"UPDATE {table} SET {value_col} = ? WHERE {key_col} = ? AND {value_col} = ?", (original, key, fresh))
    store.commit()
    return restored


def run(args: argparse.Namespace, out: Callable[[str], None] = print) -> Dict[str, Any]:
    old_key = str(os.getenv("MORROW_VAULT_MASTER_KEY") or "").strip()
    if not old_key:
        raise RotationError(1, "MORROW_VAULT_MASTER_KEY (the current key) is not set.")
    check_key("MORROW_VAULT_MASTER_KEY", old_key)
    new_key = str(os.getenv("MORROW_VAULT_MASTER_KEY_NEW") or "").strip()
    generated = False
    if new_key:
        if args.generate_new_key_file:
            raise RotationError(1, "Use either MORROW_VAULT_MASTER_KEY_NEW or --generate-new-key-file, not both.")
        check_key("MORROW_VAULT_MASTER_KEY_NEW", new_key)
    elif args.generate_new_key_file:
        new_key, generated = Fernet.generate_key().decode("ascii"), True
    elif args.apply:
        raise RotationError(1, "Set MORROW_VAULT_MASTER_KEY_NEW or pass --generate-new-key-file PATH to apply a rotation.")
    else:
        new_key = Fernet.generate_key().decode("ascii")  # dry run: a throwaway key, never shown or saved
    if new_key == old_key:
        raise RotationError(1, "The new key is the same as the current key.")

    fernets = {"vault": vault_fernet(new_key), "github": github_fernet(new_key)}
    old = {"vault": vault_fernet(old_key), "github": github_fernet(old_key)}
    stores = discover_stores(args)
    unique: List[Store] = []
    for s in stores.values():
        if s not in unique:
            unique.append(s)
    report: Dict[str, Any] = {"mode": "apply" if args.apply else "dry-run", "targets": {}, "stores": [s.label for s in unique]}

    if generated and args.apply:
        write_key_file(args.generate_new_key_file, new_key)  # before any commit, so the key is never lost
        report["new_key_file"] = args.generate_new_key_file
    elif generated:
        report["new_key_file"] = f"(dry run: {args.generate_new_key_file} not written)"

    committed: List[Store] = []
    try:
        for s in unique:
            s.open()
        rotate_column(stores["main"], "github_tokens", "id", "access_token", old["github"], fernets["github"], report["targets"], "github_tokens")
        rotate_gateway(stores["feature"], old["vault"], fernets["vault"], report["targets"])
        rotate_column(stores["feature"], "ai_privacy_policy", "organization_id", "key_sealed", old["vault"], fernets["vault"], report["targets"], "ai_receipt_signing_keys")
        rotate_column(stores["feature"], "platform_operator_mfa", "identity", "secret_enc", old["vault"], fernets["vault"], report["targets"], "operator_mfa_secrets")
        rotate_alert_channels(stores["feature"], old["vault"], fernets["vault"], report["targets"])
        if "vault" in stores:
            rotate_column(stores["vault"], "credentials", "id", "secret_enc", old["vault"], fernets["vault"], report["targets"], "vault_credentials")
        else:
            report["targets"]["vault_credentials"] = {"table": "credentials", "store": "(DATABASE_URL not set)", "present": False, "rows": 0, "rotated": 0, "undecryptable": []}
        bad = {name: t["undecryptable"] for name, t in report["targets"].items() if t.get("undecryptable")}
        if bad:
            report["undecryptable"] = bad
            raise RotationError(2, "Some values do not decrypt with MORROW_VAULT_MASTER_KEY; nothing was changed. "
                                   "Row ids are listed under 'undecryptable'.")
        report["verified"] = sum(verify_store(s, fernets) for s in unique)
        if not args.apply:
            for s in unique:
                s.rollback()
            report["result"] = "dry run passed: every value re-encrypted and verified, then rolled back"
            return report
        for s in unique:
            s.commit()
            committed.append(s)
        report["result"] = "rotated and committed"
        return report
    except RotationError as exc:
        for s in unique:
            if s not in committed:
                s.rollback()
        exc.report = report
        raise
    except Exception as exc:
        for s in unique:
            if s not in committed:
                s.rollback()
        restored: Dict[str, Any] = {}
        for s in committed:
            try:
                s.close()
                restored[s.label] = restore(s)
            except Exception as restore_exc:  # pragma: no cover - requires a second failure
                restored[s.label] = f"RESTORE FAILED: {restore_exc.__class__.__name__}"
        report["restored_after_failure"] = restored
        failure = RotationError(3, f"Rotation failed ({exc.__class__.__name__}); uncommitted stores rolled back"
                                   f"{', committed stores restored' if committed else ''}.")
        failure.report = report
        raise failure from None
    finally:
        for s in unique:
            s.close()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Re-encrypt everything sealed with MORROW_VAULT_MASTER_KEY under a new key.")
    parser.add_argument("--apply", action="store_true", help="commit the rotation (default is a dry run)")
    parser.add_argument("--generate-new-key-file", metavar="PATH",
                        help="generate the new key and write it only to PATH (created exclusively, owner-only)")
    parser.add_argument("--sqlite", metavar="PATH", help="main SQLite database (default: MORROW_SCANNER_DB or backend/morrow.db)")
    parser.add_argument("--skip-postgres-vault", action="store_true", help="do not touch the Postgres credentials table")
    args = parser.parse_args(argv)
    report: Dict[str, Any] = {}
    try:
        report = run(args)
        code = 0
    except RotationError as exc:
        report = {**getattr(exc, "report", {}), "error": str(exc), "exit_code": exc.code}
        code = exc.code
    print(json.dumps(report, indent=2, default=str))
    if code == 0 and args.apply:
        print("\nNext: store the new key as MORROW_VAULT_MASTER_KEY in your secret manager, restart every API and worker "
              "replica, confirm the vault and MFA work, then destroy the old key and any key file.", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
