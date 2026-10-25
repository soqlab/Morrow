"""scripts/rotate-vault-master-key.py against a synthetic SQLite database (never real data)."""

import base64
import importlib.util
import json
import pathlib
import sqlite3

import pytest
from cryptography.fernet import Fernet

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "rotate-vault-master-key.py"


@pytest.fixture
def rotation(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("rotate_vault_master_key", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    old_key = Fernet.generate_key().decode()
    db = tmp_path / "rotation.db"
    vault_old, github_old = module.vault_fernet(old_key), module.github_fernet(old_key)
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE github_tokens (id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, access_token TEXT NOT NULL)")
        conn.execute("CREATE TABLE gateway_sites (id TEXT PRIMARY KEY, organization_id TEXT, hostname TEXT, revision INTEGER, data TEXT)")
        conn.execute("CREATE TABLE platform_operator_mfa (identity TEXT PRIMARY KEY, secret_enc TEXT NOT NULL, status TEXT)")
        conn.execute("INSERT INTO github_tokens VALUES ('t1', 'org', 'u1', ?)", (github_old.encrypt(b"gho_token_one").decode(),))
        site = {"id": "s1", "sealed_key": vault_old.encrypt(b"gateway-secret").decode(), "policy": {"mode": "observe"}}
        conn.execute("INSERT INTO gateway_sites VALUES ('s1', 'org', 'a.example', 1, ?)", (json.dumps(site),))
        conn.execute("INSERT INTO gateway_sites VALUES ('s2', 'org', 'b.example', 1, ?)", (json.dumps({"id": "s2"}),))
        conn.execute("INSERT INTO platform_operator_mfa VALUES ('sso:a@corp.example', ?, 'active')", (vault_old.encrypt(b"JBSWY3DPEHPK3PXP").decode(),))
        # services/alert_routing.py: secret targets are "fernet:" + vault token; email recipients are "plain:" JSON.
        conn.execute("CREATE TABLE platform_alert_channels (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, target_sealed TEXT NOT NULL)")
        conn.execute("INSERT INTO platform_alert_channels VALUES ('a1', 'pagerduty', 'PD', ?)",
                     ("fernet:" + vault_old.encrypt(b"R0UTINGKEY0123456789abcdefABCDEF").decode(),))
        conn.execute("INSERT INTO platform_alert_channels VALUES ('a2', 'email', 'Mail', ?)", ('plain:["oncall@example.com"]',))
    for name in ("MORROW_FEATURE_STORE_BACKEND", "MORROW_MAIN_DB_BACKEND", "DATABASE_URL", "MORROW_PRODUCT_DATABASE_URL", "MORROW_VAULT_MASTER_KEY_NEW"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", old_key)
    return module, db, old_key


def _values(db):
    with sqlite3.connect(db) as conn:
        return {
            "github": conn.execute("SELECT access_token FROM github_tokens").fetchone()[0],
            "gateway": json.loads(conn.execute("SELECT data FROM gateway_sites WHERE id='s1'").fetchone()[0])["sealed_key"],
            "mfa": conn.execute("SELECT secret_enc FROM platform_operator_mfa").fetchone()[0],
            "alert": conn.execute("SELECT target_sealed FROM platform_alert_channels WHERE id='a1'").fetchone()[0],
            "alert_plain": conn.execute("SELECT target_sealed FROM platform_alert_channels WHERE id='a2'").fetchone()[0],
        }


def test_dry_run_verifies_everything_and_changes_nothing(rotation, capsys):
    module, db, old_key = rotation
    before = _values(db)
    assert module.main(["--sqlite", str(db)]) == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["mode"] == "dry-run" and report["verified"] == 4
    assert report["targets"]["alert_channel_targets"]["rotated"] == 1 and report["targets"]["alert_channel_targets"]["rows"] == 1
    assert report["targets"]["github_tokens"]["rotated"] == 1 and report["targets"]["gateway_sealed_keys"]["rotated"] == 1
    assert _values(db) == before
    assert old_key not in out


def test_apply_reencrypts_under_the_new_key(rotation, monkeypatch, capsys):
    module, db, old_key = rotation
    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", new_key)
    assert module.main(["--sqlite", str(db), "--apply"]) == 0
    captured = capsys.readouterr()
    assert new_key not in captured.out + captured.err and old_key not in captured.out + captured.err
    values = _values(db)
    assert module.github_fernet(new_key).decrypt(values["github"].encode()) == b"gho_token_one"
    assert module.vault_fernet(new_key).decrypt(values["gateway"].encode()) == b"gateway-secret"
    assert module.vault_fernet(new_key).decrypt(values["mfa"].encode()) == b"JBSWY3DPEHPK3PXP"
    assert values["alert"].startswith("fernet:")
    assert module.vault_fernet(new_key).decrypt(values["alert"][len("fernet:"):].encode()) == b"R0UTINGKEY0123456789abcdefABCDEF"
    assert values["alert_plain"] == 'plain:["oncall@example.com"]'
    # The running app's own helpers read the new key.
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", new_key)
    import vault_crypto
    from services import alert_routing

    assert vault_crypto.decrypt_secret(values["mfa"]) == "JBSWY3DPEHPK3PXP"
    assert alert_routing.unseal(values["alert"]) == "R0UTINGKEY0123456789abcdefABCDEF"
    assert alert_routing.unseal(values["alert_plain"]) == '["oncall@example.com"]'


def test_ai_receipt_signing_key_survives_vault_rotation(rotation, monkeypatch, capsys):
    module, db, old_key = rotation
    new_key = Fernet.generate_key().decode()
    private = base64.b64encode(b"k" * 32).decode()
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE ai_privacy_policy (organization_id TEXT PRIMARY KEY,key_sealed TEXT NOT NULL)")
        conn.execute("INSERT INTO ai_privacy_policy VALUES ('org-a',?)", (module.vault_fernet(old_key).encrypt(private.encode()).decode(),))
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", new_key)
    assert module.main(["--sqlite", str(db), "--apply"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["targets"]["ai_receipt_signing_keys"]["rotated"] == 1
    with sqlite3.connect(db) as conn:
        sealed = conn.execute("SELECT key_sealed FROM ai_privacy_policy").fetchone()[0]
    assert module.vault_fernet(new_key).decrypt(sealed.encode()).decode() == private


def test_undecryptable_alert_target_aborts_without_changes(rotation, monkeypatch, capsys):
    module, db, _ = rotation
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO platform_alert_channels VALUES ('a3', 'slack_webhook', 'Stale', ?)",
                     ("fernet:" + Fernet(Fernet.generate_key()).encrypt(b"https://hooks.example/x").decode(),))
    before = _values(db)
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", Fernet.generate_key().decode())
    assert module.main(["--sqlite", str(db), "--apply"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["undecryptable"] == {"alert_channel_targets": ["a3"]}
    assert _values(db) == before


def test_failed_commit_restores_alert_targets(rotation, monkeypatch, capsys):
    """A later store's commit failure restores the committed store's alert targets to their original ciphertexts."""
    module, db, _ = rotation
    before = _values(db)
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", Fernet.generate_key().decode())
    real_discover = module.discover_stores

    def two_stores(args):
        stores = real_discover(args)
        stores["vault"] = module.Store("failing vault", "sqlite", str(db) + ".vault")
        return stores

    vault_db = str(db) + ".vault"
    with sqlite3.connect(vault_db) as conn:
        conn.execute("CREATE TABLE credentials (id TEXT PRIMARY KEY, secret_enc TEXT)")
    real_commit = module.Store.commit

    def commit(self):
        if self.label == "failing vault":
            raise RuntimeError("simulated commit failure")
        return real_commit(self)

    monkeypatch.setattr(module, "discover_stores", two_stores)
    monkeypatch.setattr(module.Store, "commit", commit)
    assert module.main(["--sqlite", str(db), "--apply"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["restored_after_failure"]
    assert _values(db) == before


def test_undecryptable_value_aborts_without_changes(rotation, monkeypatch, capsys):
    module, db, _ = rotation
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO platform_operator_mfa VALUES ('key:bob', ?, 'active')",
                     (Fernet(Fernet.generate_key()).encrypt(b"other").decode(),))
    before = _values(db)
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", Fernet.generate_key().decode())
    assert module.main(["--sqlite", str(db), "--apply"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["undecryptable"] == {"operator_mfa_secrets": ["key:bob"]}
    assert _values(db) == before


def test_generated_key_goes_only_to_the_file(rotation, tmp_path, capsys):
    module, db, _ = rotation
    key_file = tmp_path / "new-vault.key"
    assert module.main(["--sqlite", str(db), "--generate-new-key-file", str(key_file)]) == 0
    assert not key_file.exists()  # dry run writes nothing
    assert module.main(["--sqlite", str(db), "--apply", "--generate-new-key-file", str(key_file)]) == 0
    out = capsys.readouterr().out
    new_key = key_file.read_text().strip()
    assert new_key and new_key not in out
    assert module.vault_fernet(new_key).decrypt(_values(db)["mfa"].encode()) == b"JBSWY3DPEHPK3PXP"
    assert module.main(["--sqlite", str(db), "--apply", "--generate-new-key-file", str(key_file)]) == 1  # never overwrites


def test_apply_requires_a_new_key(rotation, capsys):
    module, db, _ = rotation
    assert module.main(["--sqlite", str(db), "--apply"]) == 1
    assert "MORROW_VAULT_MASTER_KEY_NEW" in json.loads(capsys.readouterr().out)["error"]


def test_github_key_derivation_matches_the_service(rotation, monkeypatch):
    module, _, old_key = rotation
    import services.github_oauth as github_oauth

    monkeypatch.setattr(github_oauth, "_VAULT_KEY_RAW", old_key)
    token = github_oauth._encrypt("gho_example")
    assert module.github_fernet(old_key).decrypt(token.encode()) == b"gho_example"
    assert base64.urlsafe_b64decode(Fernet.generate_key())  # sanity: generated keys are valid Fernet keys
