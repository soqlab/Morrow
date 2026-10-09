"""Known-answer tests for the AWS secret scanner.

services.secrets_scanner.scan_aws was the last scanner entry point with no
coverage, because it needs AWS credentials. moto stands AWS up in-process, so the
real boto3 client, the real paginators and the real scanner code all run -- no
account, no credentials, no network.

The behaviour that matters here and is easy to get silently wrong:

  * Secrets Manager stores most secrets as a JSON envelope, not a bare PEM. A
    scanner that only looks for "-----BEGIN" at the top level reports a clean
    vault for the most common real-world layout.
  * A key found in a JSON field must be attributed to that field, not to the
    blob, or the remediation ticket points at the wrong thing.
  * Failures must land in `errors`. A scan that fails silently and returns zero
    findings is indistinguishable from a clean estate, which is the worst
    possible failure for this product.
"""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

moto = pytest.importorskip("moto", reason="moto provides the in-process AWS stub")
boto3 = pytest.importorskip("boto3")

from moto import mock_aws  # noqa: E402

from services.secrets_scanner import scan_aws  # noqa: E402

REGION = "us-east-1"
CREDS = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")


def _pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


RSA_2048_PEM = _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
EC_P256_PEM = _pem(ec.generate_private_key(ec.SECP256R1()))


def _scan(**kwargs):
    return scan_aws(CREDS[0], CREDS[1], aws_region=REGION, **kwargs)


@mock_aws
def test_ssm_parameter_holding_a_private_key_is_found_and_attributed():
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.put_parameter(Name="/prod/tls/private_key", Value=RSA_2048_PEM, Type="SecureString")
    ssm.put_parameter(Name="/prod/db/hostname", Value="db.internal", Type="String")

    result = _scan(scan_secrets_manager=False)

    assert not result["errors"], result["errors"]
    assert len(result["findings"]) == 1, "only the PEM parameter should be reported"

    finding = result["findings"][0]
    assert finding["source"] == "aws_ssm"
    assert finding["path"] == "ssm:///prod/tls/private_key"
    assert finding["field"] == "private_key"
    assert finding["key_type"] == "RSA"
    assert finding["key_bits"] == 2048
    assert finding["quantum_vulnerable"] is True
    assert "BEGIN" not in finding["fingerprint"], "key material must not leak into the report"


@mock_aws
def test_secrets_manager_bare_pem_is_found():
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name="prod/signing-key", SecretString=EC_P256_PEM)

    result = _scan(scan_ssm=False)

    assert not result["errors"], result["errors"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["source"] == "aws_secrets_manager"
    assert finding["path"] == "sm://prod/signing-key"
    assert finding["field"] == "secret_string"
    assert finding["key_type"] == "EC"
    assert finding["key_bits"] == 256


@mock_aws
def test_secrets_manager_json_envelope_is_unwrapped_and_the_field_is_named():
    """The common real-world layout: a JSON blob with the key as one field."""
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(
        Name="prod/app-bundle",
        SecretString=json.dumps({
            "db_password": "hunter2",
            "tls_private_key": RSA_2048_PEM,
            "region": REGION,
        }),
    )

    result = _scan(scan_ssm=False)

    assert not result["errors"], result["errors"]
    assert len(result["findings"]) == 1, "the PEM inside the JSON envelope was missed"
    finding = result["findings"][0]
    assert finding["field"] == "tls_private_key", "finding must name the field, not the blob"
    assert finding["path"] == "sm://prod/app-bundle"
    assert finding["key_type"] == "RSA"
    # The unrelated password must not be reported as key material.
    assert "hunter2" not in json.dumps(result)


@mock_aws
def test_both_stores_are_scanned_and_flags_are_honoured():
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.put_parameter(Name="/prod/ssm_key", Value=RSA_2048_PEM, Type="SecureString")
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(Name="prod/sm-key", SecretString=EC_P256_PEM)

    both = _scan()
    assert {f["source"] for f in both["findings"]} == {"aws_ssm", "aws_secrets_manager"}

    only_ssm = _scan(scan_secrets_manager=False)
    assert {f["source"] for f in only_ssm["findings"]} == {"aws_ssm"}

    only_sm = _scan(scan_ssm=False)
    assert {f["source"] for f in only_sm["findings"]} == {"aws_secrets_manager"}

    neither = _scan(scan_ssm=False, scan_secrets_manager=False)
    assert neither["findings"] == []


@mock_aws
def test_path_prefix_scopes_the_ssm_scan():
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.put_parameter(Name="/prod/key", Value=RSA_2048_PEM, Type="SecureString")
    ssm.put_parameter(Name="/staging/key", Value=EC_P256_PEM, Type="SecureString")

    result = _scan(scan_secrets_manager=False, path_prefix="/prod")

    assert len(result["findings"]) == 1
    assert result["findings"][0]["path"] == "ssm:///prod/key"


@mock_aws
def test_an_empty_account_is_reported_as_clean_without_errors():
    result = _scan()

    assert result["findings"] == []
    assert not result["errors"], "an empty account is clean, not broken"


def test_unreachable_aws_records_an_error_rather_than_returning_a_clean_result():
    """No moto here: the call goes to a bogus endpoint and must fail loudly in
    the result, because a silent zero-finding scan reads as a clean estate."""
    result = scan_aws("bad-key", "bad-secret", aws_region="not-a-real-region")

    assert result["findings"] == []
    assert result["errors"], "a failed AWS scan must not look like a clean one"


@mock_aws
def test_every_key_in_a_json_bundle_is_reported_with_its_real_size():
    """Regression: a JSON bundle contains "-----BEGIN", so the bare-PEM branch
    used to win and the envelope branch never ran. One key of two was reported,
    attributed to the blob, and sized 0 bits -- which _assess_key renders as a
    false critical: "RSA-0 ... breakable with ~0 logical qubits"."""
    sm = boto3.client("secretsmanager", region_name=REGION)
    sm.create_secret(
        Name="prod/multi",
        SecretString=json.dumps({
            "tls_private_key": RSA_2048_PEM,
            "signing_key": EC_P256_PEM,
            "note": "no key here",
        }),
    )

    result = _scan(scan_ssm=False)
    by_field = {f["field"]: f for f in result["findings"]}

    assert set(by_field) == {"tls_private_key", "signing_key"}, "both keys must be reported"

    rsa_finding = by_field["tls_private_key"]
    assert rsa_finding["key_type"] == "RSA"
    assert rsa_finding["key_bits"] == 2048, "the real key size, not 0"
    assert rsa_finding["risk_level"] == "high"
    assert "RSA-0" not in rsa_finding["reason"]

    ec_finding = by_field["signing_key"]
    assert ec_finding["key_type"] == "EC"
    assert ec_finding["key_bits"] == 256

    # No finding may claim a zero-bit key -- that is the fingerprint of the bug.
    assert all(f["key_bits"] > 0 for f in result["findings"])
