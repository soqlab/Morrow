"""Cloud-native secret store backends for PQC Scanner credentials.

Activated via the PQC_SECRET_BACKEND environment variable:

  PQC_SECRET_BACKEND=aws        Use AWS Secrets Manager
  PQC_SECRET_BACKEND=azure      Use Azure Key Vault
  PQC_SECRET_BACKEND=vault      Use local Fernet/Postgres vault (default)

AWS Secrets Manager config:
  AWS_REGION                   e.g., us-east-1
  AWS_ACCESS_KEY_ID            (or use instance role / ECS task role)
  AWS_SECRET_ACCESS_KEY

Azure Key Vault config:
  AZURE_KEY_VAULT_URL          e.g., https://your-vault.vault.azure.net
  AZURE_CLIENT_ID
  AZURE_CLIENT_SECRET
  AZURE_TENANT_ID
"""

from __future__ import annotations
import os


_BACKEND = str(os.getenv("PQC_SECRET_BACKEND", "vault") or "vault").strip().lower()


def store_secret(name: str, value: str, description: str = "") -> str:
    """Store a secret and return its external reference (ARN, vault secret name, etc.)."""
    if _BACKEND == "aws":
        return _aws_store(name, value, description)
    if _BACKEND == "azure":
        return _azure_store(name, value)
    return name  # local vault: name is the reference


def retrieve_secret(reference: str) -> str:
    """Retrieve a secret by its reference returned from store_secret."""
    if _BACKEND == "aws":
        return _aws_retrieve(reference)
    if _BACKEND == "azure":
        return _azure_retrieve(reference)
    return ""  # local vault: handled by vault_crypto directly


def delete_secret(reference: str) -> None:
    """Best-effort deletion of a secret from the external store."""
    if _BACKEND == "aws":
        _aws_delete(reference)
    elif _BACKEND == "azure":
        _azure_delete(reference)


def backend_name() -> str:
    return _BACKEND


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------

def _aws_store(name: str, value: str, description: str = "") -> str:
    try:
        import boto3
        from botocore.exceptions import ClientError  # noqa: F401 - imported to confirm botocore is present
    except ImportError:
        raise RuntimeError(
            "boto3 is required for AWS Secrets Manager backend. "
            "Install with: pip install boto3"
        )
    region = str(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1").strip()
    client = boto3.client("secretsmanager", region_name=region)
    secret_name = f"pqc-scanner/{name}"
    try:
        client.create_secret(
            Name=secret_name,
            SecretString=value,
            Description=description or f"PQC Scanner credential: {name}",
        )
    except Exception:
        try:
            client.put_secret_value(SecretId=secret_name, SecretString=value)
        except Exception as exc:
            raise RuntimeError(f"AWS Secrets Manager write failed for {secret_name}: {exc}") from exc
    return secret_name


def _aws_retrieve(reference: str) -> str:
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is required for AWS Secrets Manager backend.")
    region = str(os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1").strip()
    client = boto3.client("secretsmanager", region_name=region)
    try:
        resp = client.get_secret_value(SecretId=reference)
        return str(resp.get("SecretString") or "")
    except Exception as exc:
        raise RuntimeError(f"AWS Secrets Manager read failed for {reference}: {exc}") from exc


def _aws_delete(reference: str) -> None:
    try:
        import boto3
        region = str(os.getenv("AWS_REGION") or "us-east-1").strip()
        client = boto3.client("secretsmanager", region_name=region)
        client.delete_secret(SecretId=reference, ForceDeleteWithoutRecovery=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Azure Key Vault
# ---------------------------------------------------------------------------

def _azure_store(name: str, value: str) -> str:
    vault_url = str(os.getenv("AZURE_KEY_VAULT_URL") or "").strip()
    if not vault_url:
        raise RuntimeError("AZURE_KEY_VAULT_URL is required for Azure Key Vault backend.")
    try:
        from azure.keyvault.secrets import SecretClient
        from azure.identity import ClientSecretCredential
    except ImportError:
        raise RuntimeError(
            "azure-keyvault-secrets and azure-identity are required for Azure Key Vault backend. "
            "Install with: pip install azure-keyvault-secrets azure-identity"
        )
    credential = ClientSecretCredential(
        tenant_id=str(os.getenv("AZURE_TENANT_ID") or ""),
        client_id=str(os.getenv("AZURE_CLIENT_ID") or ""),
        client_secret=str(os.getenv("AZURE_CLIENT_SECRET") or ""),
    )
    client = SecretClient(vault_url=vault_url, credential=credential)
    # Azure secret names must be alphanumeric + hyphens
    secret_name = "pqc-" + name.replace("_", "-").replace("/", "-").replace(":", "-")[:100]
    try:
        client.set_secret(secret_name, value)
    except Exception as exc:
        raise RuntimeError(f"Azure Key Vault write failed for {secret_name}: {exc}") from exc
    return secret_name


def _azure_retrieve(reference: str) -> str:
    vault_url = str(os.getenv("AZURE_KEY_VAULT_URL") or "").strip()
    if not vault_url:
        raise RuntimeError("AZURE_KEY_VAULT_URL is required for Azure Key Vault backend.")
    try:
        from azure.keyvault.secrets import SecretClient
        from azure.identity import ClientSecretCredential
    except ImportError:
        raise RuntimeError("azure-keyvault-secrets and azure-identity are required.")
    credential = ClientSecretCredential(
        tenant_id=str(os.getenv("AZURE_TENANT_ID") or ""),
        client_id=str(os.getenv("AZURE_CLIENT_ID") or ""),
        client_secret=str(os.getenv("AZURE_CLIENT_SECRET") or ""),
    )
    client = SecretClient(vault_url=vault_url, credential=credential)
    try:
        secret = client.get_secret(reference)
        return str(secret.value or "")
    except Exception as exc:
        raise RuntimeError(f"Azure Key Vault read failed for {reference}: {exc}") from exc


def _azure_delete(reference: str) -> None:
    try:
        vault_url = str(os.getenv("AZURE_KEY_VAULT_URL") or "").strip()
        from azure.keyvault.secrets import SecretClient
        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=str(os.getenv("AZURE_TENANT_ID") or ""),
            client_id=str(os.getenv("AZURE_CLIENT_ID") or ""),
            client_secret=str(os.getenv("AZURE_CLIENT_SECRET") or ""),
        )
        client = SecretClient(vault_url=vault_url, credential=credential)
        client.begin_delete_secret(reference)
    except Exception:
        pass
