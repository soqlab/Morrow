"""Known-answer tests for the source-code scanners.

scan_file (services/sast_scanner), scan_python_source (py_ast_scanner) and scan_env_content
(services/secrets_scanner) had no tests at all, yet they are what the product reports on when a
customer points it at a repository.

Ground truth is by construction: each fixture below is a small file whose crypto usage is known
exactly, so the right answer is not a matter of opinion.

Negative cases carry equal weight. A scanner that flags quantum-safe code, or fires a
Python-specific rule on a Markdown file, is commercially worse than one that misses a finding: an
inventory nobody trusts does not get used. Rule scoping by file extension is asserted here rather
than assumed.

Two defects surfaced on the first run: py_ast_scanner reported every generate_private_key() call
twice (two checks with overlapping conditions), and scan_env_content missed a private key written
across multiple lines entirely.
"""
from __future__ import annotations


from py_ast_scanner import scan_python_source
from services.sast_scanner import scan_file


def _rule_ids(findings) -> set:
    return {str(f.get("rule_id") or f.get("rule_name") or "") for f in findings}


# =============================================================================================
# Positive cases: crypto that must be found
# =============================================================================================

def test_python_rsa_keygen_is_detected():
    content = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )

    findings = scan_file("app.py", content)

    assert "PQC-010" in _rule_ids(findings), f"RSA keygen not detected: {_rule_ids(findings)}"


def test_python_ec_keygen_is_detected():
    content = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "key = ec.generate_private_key(ec.SECP384R1())\n"
    )

    findings = scan_file("crypto.py", content)

    assert "PQC-011" in _rule_ids(findings), f"EC keygen not detected: {_rule_ids(findings)}"


def test_javascript_rsa_keygen_is_detected():
    content = (
        "const { generateKeyPair } = require('crypto');\n"
        "generateKeyPair('rsa', { modulusLength: 2048 }, cb);\n"
    )

    findings = scan_file("keys.js", content)

    assert "PQC-012" in _rule_ids(findings), f"JS RSA keygen not detected: {_rule_ids(findings)}"


def test_go_rsa_keygen_is_detected():
    content = 'package main\nimport "crypto/rsa"\nfunc f() { k, _ := rsa.GenerateKey(rand.Reader, 2048) }\n'

    findings = scan_file("main.go", content)

    assert "PQC-013" in _rule_ids(findings), f"Go RSA keygen not detected: {_rule_ids(findings)}"


def test_java_rsa_keygen_is_detected():
    content = 'public class K {\n  void f() throws Exception {\n    KeyPairGenerator.getInstance("RSA");\n  }\n}\n'

    findings = scan_file("K.java", content)

    assert "PQC-014" in _rule_ids(findings), f"Java RSA keygen not detected: {_rule_ids(findings)}"


def test_undersized_key_is_detected():
    """A 1024-bit key is a different severity of problem from a 2048-bit one."""
    findings = scan_file("legacy.py", "key = rsa.generate_private_key(key_size=1024)\n")

    assert "PQC-020" in _rule_ids(findings), f"1024-bit key not detected: {_rule_ids(findings)}"


def test_hardcoded_private_key_block_is_detected():
    content = "PRIVATE = '''-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----'''\n"

    findings = scan_file("secrets.py", content)

    assert "PQC-001" in _rule_ids(findings), f"embedded private key not detected: {_rule_ids(findings)}"


def test_rs256_jwt_algorithm_is_detected():
    findings = scan_file("auth.json", '{ "algorithm": "RS256" }\n')

    assert "PQC-030" in _rule_ids(findings), f"RS256 not detected: {_rule_ids(findings)}"


def test_weak_tls_cipher_configuration_is_detected():
    findings = scan_file("nginx.conf", "ssl_ciphers RC4:DES:3DES;\n")

    assert "PQC-041" in _rule_ids(findings), f"weak ciphers not detected: {_rule_ids(findings)}"


def test_dockerfile_copying_a_private_key_is_detected():
    findings = scan_file("Dockerfile", "FROM alpine\nCOPY server.key /etc/ssl/private.key\n")

    assert "PQC-060" in _rule_ids(findings), f"key COPY not detected: {_rule_ids(findings)}"


# =============================================================================================
# Negative cases: what must NOT be reported
# =============================================================================================

def test_post_quantum_code_is_not_flagged_as_vulnerable():
    """The migrated state must come back clean, or the tool cannot show progress.

    If ML-KEM code still trips a rule, a customer who has done the work sees no improvement and
    stops believing the report.
    """
    content = (
        "from kyber_py.ml_kem import ML_KEM_768\n"
        "ek, dk = ML_KEM_768.keygen()\n"
        "key, ct = ML_KEM_768.encaps(ek)\n"
    )

    findings = scan_file("pqc.py", content)

    assert not findings, f"post-quantum code was flagged: {findings}"


def test_hashing_only_code_is_not_flagged():
    """SHA-256 digests are not quantum-broken; flagging them would be noise."""
    content = (
        "import hashlib\n"
        "digest = hashlib.sha256(payload).hexdigest()\n"
    )

    findings = scan_file("hash.py", content)

    assert not findings, f"hashing code was flagged: {findings}"


def test_commented_out_crypto_is_not_flagged():
    """A commented line is not deployed code."""
    content = (
        "# key = rsa.generate_private_key(key_size=1024)\n"
        "// generateKeyPair('rsa', {}, cb)\n"
    )

    findings = scan_file("notes.py", content)

    assert not findings, f"commented-out code was flagged: {findings}"


def test_python_rules_do_not_fire_on_other_languages():
    """Rule extension scoping is what keeps a polyglot repository's report readable."""
    python_only_source = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"

    findings = scan_file("notes.md", python_only_source)

    assert "PQC-010" not in _rule_ids(findings), (
        f"a Python-only rule fired on a Markdown file: {_rule_ids(findings)}"
    )


def test_empty_and_whitespace_files_produce_nothing():
    for content in ("", "\n\n   \n", "   "):
        assert scan_file("blank.py", content) == []


# =============================================================================================
# Findings carry the information needed to act
# =============================================================================================

def test_findings_report_the_line_number_they_were_found_on():
    """A finding without a location cannot be triaged."""
    content = "import os\nimport sys\nkey = rsa.generate_private_key(key_size=2048)\n"

    findings = scan_file("app.py", content)

    assert findings, "expected at least one finding"
    lines = {f.get("line") for f in findings}
    assert 3 in lines, f"finding reported on lines {lines}, expected the call on line 3"


def test_findings_carry_a_severity_from_a_known_set():
    findings = scan_file("app.py", "key = rsa.generate_private_key(key_size=1024)\n")

    assert findings
    allowed = {"critical", "high", "medium", "low", "info"}
    for f in findings:
        assert str(f.get("severity", "")).lower() in allowed, f"unexpected severity: {f}"


# =============================================================================================
# The AST scanner
# =============================================================================================

def test_ast_scanner_detects_key_generation():
    content = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def make():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )

    findings = scan_python_source("make.py", content)

    assert findings, "AST scanner found no key generation"
    assert any(f.get("line") == 3 for f in findings), f"lines reported: {[f.get('line') for f in findings]}"


def test_ast_scanner_detects_hardcoded_pem_assignment():
    content = 'KEY = "-----BEGIN RSA PRIVATE KEY-----\\nAAAA\\n-----END RSA PRIVATE KEY-----"\n'

    findings = scan_python_source("cfg.py", content)

    names = {str(f.get("rule_name") or "") for f in findings}
    assert any("private key" in n.lower() for n in names), f"rules fired: {names}"


def test_ast_scanner_reports_one_finding_per_key_generation_call():
    """Two rules matched `generate_private_key`, so a single call produced two findings.

    Duplicate findings for one line inflate every count built on them -- risk scores, dashboard
    totals, "open findings" in a board report -- and make a clean-up look incomplete after the code
    is actually fixed.
    """
    content = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"

    findings = scan_python_source("one.py", content)

    on_line_1 = [f for f in findings if f.get("line") == 1]
    assert len(on_line_1) == 1, (
        f"one key-generation call produced {len(on_line_1)} findings: "
        f"{[f.get('rule_name') for f in on_line_1]}"
    )


def test_ast_scanner_ignores_syntactically_invalid_source():
    """A repository contains files that do not parse; a scan must not abort on them."""
    findings = scan_python_source("broken.py", "def f(:\n  pass\n")

    assert isinstance(findings, list)


# =============================================================================================
# Secrets in configuration
# =============================================================================================

def _rsa_pem(bits: int = 2048) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    key = _rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_private_key_written_with_escaped_newlines_is_found():
    from services.secrets_scanner import scan_env_content

    content = 'TLS_PRIVATE_KEY="' + _rsa_pem().replace("\n", "\\n") + '"\n'

    result = scan_env_content(content, "app.env")

    findings = result.get("findings") or []
    assert findings, "an RSA private key in a .env file was not reported"
    assert findings[0]["key_type"] == "RSA"
    assert findings[0]["key_bits"] == 2048


def test_private_key_spanning_multiple_lines_is_found():
    """The form that was missed completely.

    A PEM block in a .env file is often written across real lines rather than with escaped newlines.
    Splitting the file on newlines separated the variable name from the key body, so extraction
    failed — and the name-based fallback was skipped too, because the first line contains
    "-----BEGIN". A genuine private key in configuration produced no finding and no error.
    """
    from services.secrets_scanner import scan_env_content

    content = 'TLS_PRIVATE_KEY="' + _rsa_pem() + '"\n'

    result = scan_env_content(content, "app.env")

    findings = result.get("findings") or []
    assert findings, "a multi-line RSA private key in a .env file was not reported"
    assert findings[0]["key_type"] == "RSA", findings[0]
    assert findings[0]["quantum_vulnerable"] is True, findings[0]


def test_multiline_key_does_not_swallow_following_variables():
    """Joining the PEM back together must not consume the rest of the file."""
    from services.secrets_scanner import scan_env_content

    content = (
        'TLS_PRIVATE_KEY="' + _rsa_pem() + '"\n'
        "SIGNING_KEY=" + ("B" * 64) + "\n"
        "LOG_LEVEL=debug\n"
    )

    result = scan_env_content(content, "app.env")

    fields = {f.get("field") for f in (result.get("findings") or [])}
    assert "TLS_PRIVATE_KEY" in fields, fields
    assert "SIGNING_KEY" in fields, f"a variable after the PEM block was lost: {fields}"


def test_benign_environment_variables_are_not_reported():
    from services.secrets_scanner import scan_env_content

    content = "LOG_LEVEL=debug\nPORT=8000\n# PRIVATE_KEY=commented\nTIMEOUT=30\n"

    result = scan_env_content(content, "app.env")

    assert (result.get("findings") or []) == [], result.get("findings")


def test_ast_scanner_does_not_flag_post_quantum_keygen_as_rsa():
    """A PQC keygen call may be worth inventorying, but never as a quantum-vulnerable RSA finding."""
    content = "from kyber_py.ml_kem import ML_KEM_768\nek, dk = ML_KEM_768.keygen()\n"

    findings = scan_python_source("pqc.py", content)

    for f in findings:
        blob = f"{f.get('rule_name', '')} {f.get('recommendation', '')}".lower()
        assert "rsa" not in blob.split("kyber")[0], f"ML-KEM reported as RSA: {f}"
