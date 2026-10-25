import os
from cryptography.fernet import Fernet

def _get_key() -> bytes:
    key = (os.getenv("MORROW_VAULT_MASTER_KEY") or "").strip()
    if not key:
        raise RuntimeError("MORROW_VAULT_MASTER_KEY is required for Vault operations")
    return key.encode("utf-8")

def encrypt_secret(plaintext: str) -> str:
    f = Fernet(_get_key())
    token = f.encrypt((plaintext or "").encode("utf-8"))
    return token.decode("utf-8")

def decrypt_secret(token: str) -> str:
    f = Fernet(_get_key())
    pt = f.decrypt((token or "").encode("utf-8"))
    return pt.decode("utf-8")
