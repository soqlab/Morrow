"""Known-answer tests for repository-archive scanning.

code_scanner.scan_zip_bytes is how an uploaded repository gets scanned, and it had no tests. The
archives here are built in memory, so what each one contains is known exactly.

Three defects surfaced on the first run and are pinned below: weak-hash rules never applied to
Python files, a hardcoded key in a Python assignment was reported twice, and a payload that is not a
readable archive raised BadZipFile at the caller instead of being reported.
"""
from __future__ import annotations

import io
import zipfile

from code_scanner import scan_zip_bytes


def _zip(files: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _rules(findings) -> list:
    return [str(f.get("rule_name") or "") for f in findings]


# =============================================================================================
# Weak hashes: the rules that never ran on Python
# =============================================================================================

def test_md5_in_python_is_detected():
    """MD5 in a .py file reported nothing, while the same usage in Go was flagged.

    Python files short-circuited to the AST pass and skipped every regex rule, so the weak-hash
    rules -- among the most common real findings, and among the likeliest to appear in Python --
    could not fire there at all.
    """
    findings = scan_zip_bytes(_zip({"app.py": "import hashlib\nh = hashlib.md5(x).hexdigest()\n"}))

    assert any("MD5" in r for r in _rules(findings)), f"MD5 in Python not detected: {_rules(findings)}"


def test_sha1_in_python_is_detected():
    findings = scan_zip_bytes(_zip({"app.py": "import hashlib\nh = hashlib.sha1(x).hexdigest()\n"}))

    assert any("SHA-1" in r for r in _rules(findings)), f"SHA-1 in Python not detected: {_rules(findings)}"


def test_md5_in_go_is_still_detected():
    """The language that already worked must keep working."""
    findings = scan_zip_bytes(_zip({"main.go": 'import "crypto/md5"\n'}))

    assert any("MD5" in r for r in _rules(findings)), _rules(findings)


def test_python_findings_report_the_real_line_number():
    content = "import hashlib\n\n\nh = hashlib.md5(x).hexdigest()\n"

    findings = scan_zip_bytes(_zip({"app.py": content}))

    md5 = [f for f in findings if "MD5" in str(f.get("rule_name"))]
    assert md5, _rules(findings)
    assert md5[0]["line"] == 4, f"MD5 on line 4 reported at line {md5[0]['line']}"


# =============================================================================================
# Hardcoded keys: reported once, at the most precise location
# =============================================================================================

def test_hardcoded_key_in_python_is_reported_exactly_once():
    """The AST pass and a whole-file text scan both reported it, so one key became two findings."""
    content = 'K = "-----BEGIN PRIVATE KEY-----AAA-----END PRIVATE KEY-----"\n'

    findings = scan_zip_bytes(_zip({"secrets.py": content}))

    pem = [f for f in findings if f.get("rule_name") == "Hardcoded private key material"]
    assert len(pem) == 1, f"one key produced {len(pem)} findings"


def test_hardcoded_key_in_a_python_dict_is_still_found():
    """The visitor only inspects assignments; a key in a dict value must not be missed."""
    content = 'KEYS = {"prod": "-----BEGIN PRIVATE KEY-----AAA-----END PRIVATE KEY-----"}\n'

    findings = scan_zip_bytes(_zip({"cfg.py": content}))

    pem = [f for f in findings if f.get("rule_name") == "Hardcoded private key material"]
    assert len(pem) == 1, f"expected exactly one finding, got {len(pem)}"


def test_hardcoded_key_in_a_non_python_file_is_found():
    findings = scan_zip_bytes(_zip({"key.go": 'const k = "-----BEGIN PRIVATE KEY-----AAA"\n'}))

    assert any("private key" in r.lower() for r in _rules(findings)), _rules(findings)


# =============================================================================================
# Malformed and hostile input
# =============================================================================================

def test_a_payload_that_is_not_an_archive_is_reported_not_raised():
    """This takes arbitrary bytes; a truncated upload is expected input, not a crash.

    zipfile.BadZipFile propagated to the caller, which becomes a 500 the moment this is wired to an
    upload endpoint.
    """
    findings = scan_zip_bytes(b"this is not a zip file")

    assert findings, "an unreadable archive produced no result at all"
    assert findings[0]["rule_name"] == "Unreadable archive", findings[0]


def test_truncated_archive_is_reported_not_raised():
    valid = _zip({"a.py": "import hashlib\n"})

    findings = scan_zip_bytes(valid[: len(valid) // 2])

    assert findings and findings[0]["rule_name"] == "Unreadable archive", findings


def test_empty_payload_is_empty_not_an_error():
    assert scan_zip_bytes(b"") == []


def test_path_traversal_entries_are_skipped():
    """A zip-slip name must not be scanned or reported under an escaping path."""
    findings = scan_zip_bytes(_zip({"../../etc/evil.py": "h = hashlib.md5(x)\n"}))

    for f in findings:
        assert ".." not in str(f.get("file") or ""), f"traversal path reported: {f}"


def test_unsupported_extensions_are_ignored():
    """The archive path scans source files; a binary or image must not produce findings."""
    findings = scan_zip_bytes(_zip({
        "logo.png": b"\x89PNG\r\n\x1a\n" + b"md5" * 10,
        "notes.txt": "md5 and sha1 are mentioned here",
    }))

    assert findings == [], f"non-source files produced findings: {findings}"


def test_clean_repository_produces_no_findings():
    """A repository with no quantum-vulnerable crypto must come back empty."""
    findings = scan_zip_bytes(_zip({
        "app.py": "import json\n\ndef handler(event):\n    return json.dumps({'ok': True})\n",
        "util.go": 'package util\n\nimport "fmt"\n',
    }))

    assert findings == [], f"clean repository produced findings: {findings}"


def test_findings_name_the_file_they_came_from():
    """With many files in an archive, a finding without its filename cannot be acted on."""
    findings = scan_zip_bytes(_zip({
        "clean.py": "import json\n",
        "weak.go": 'import "crypto/md5"\n',
    }))

    assert findings
    assert all(f.get("file") for f in findings), findings
    assert {f["file"] for f in findings} == {"weak.go"}, {f["file"] for f in findings}
