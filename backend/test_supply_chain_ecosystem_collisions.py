"""A package name that exists in two ecosystems must be detected in both.

_CRYPTO_VULN_DB is keyed by package name, but names are not unique across ecosystems: jsonwebtoken is
both an npm package and a cargo crate. The dict literal defined it twice, and Python keeps only the
last value, so the npm entry was silently discarded at import. Findings are then filtered with
`eco in (detected_eco, "any")`, so the surviving cargo entry never matched an npm scan -- meaning
jsonwebtoken, one of the most widely used RS256/ES256 signing libraries, was never reported for any
package.json.

Nothing failed loudly: the scan simply returned a smaller result set and read as a clean report.
"""
import ast
import json
import pathlib

from services import supply_chain
from services.supply_chain import _CRYPTO_VULN_DB, _eco_matches, scan_manifest


def _vulnerable_names(result):
    return {str(v.get("package_normalized") or v.get("package") or "").lower()
            for v in result.get("vulnerabilities") or []}


def test_jsonwebtoken_is_reported_for_an_npm_manifest():
    content = json.dumps({
        "name": "example-app",
        "dependencies": {"jsonwebtoken": "^9.0.0", "express": "^4.18.0"},
    })

    result = scan_manifest("package.json", content)

    assert result.get("ecosystem") == "npm", result
    assert "jsonwebtoken" in _vulnerable_names(result), (
        "jsonwebtoken was not flagged in an npm manifest; the npm database entry is being "
        f"shadowed. Findings: {result.get('vulnerabilities')}"
    )


def test_jsonwebtoken_is_still_reported_for_a_cargo_manifest():
    content = "\n".join([
        "[package]",
        'name = "example"',
        'version = "0.1.0"',
        "",
        "[dependencies]",
        'jsonwebtoken = "9"',
    ])

    result = scan_manifest("Cargo.toml", content)

    assert result.get("ecosystem") == "cargo", result
    assert "jsonwebtoken" in _vulnerable_names(result), result.get("vulnerabilities")


def test_eco_matches_accepts_single_and_multiple_ecosystems():
    assert _eco_matches({"eco": "npm"}, "npm")
    assert not _eco_matches({"eco": "npm"}, "cargo")
    assert _eco_matches({"eco": ("npm", "cargo")}, "cargo")
    assert _eco_matches({"eco": ("npm", "cargo")}, "npm")
    assert not _eco_matches({"eco": ("npm", "cargo")}, "pypi")
    assert _eco_matches({"eco": "any"}, "anything")
    # A malformed entry must not match everything by accident.
    assert not _eco_matches({}, "npm")
    assert not _eco_matches({"eco": ""}, "npm")


def _detectable_ecosystems() -> set:
    """The ecosystem tokens _detect_ecosystem can actually return.

    Derived from the function rather than hardcoded, so the vocabulary has one source of truth: a
    hardcoded list here would just be a second place to get "pip" vs "pypi" wrong.
    """
    source = pathlib.Path(supply_chain.__file__).read_text(encoding="utf-8-sig")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_detect_ecosystem":
            return {
                n.value.value
                for n in ast.walk(node)
                if isinstance(n, ast.Return)
                and isinstance(n.value, ast.Constant)
                and isinstance(n.value.value, str)
            }
    raise AssertionError("_detect_ecosystem not found")


def test_every_database_entry_declares_a_usable_ecosystem():
    """An entry whose eco no manifest can produce is unreachable — it can never yield a finding."""
    usable = (_detectable_ecosystems() | {"any"}) - {"unknown"}
    for name, entry in _CRYPTO_VULN_DB.items():
        declared = entry.get("eco")
        declared = (declared,) if isinstance(declared, str) else tuple(declared or ())
        assert declared, f"{name} declares no ecosystem, so it can never match a scan"
        unreachable = set(declared) - usable
        assert not unreachable, (
            f"{name} declares ecosystem(s) {unreachable} that _detect_ecosystem never returns, "
            f"so this entry is unreachable. Detectable: {sorted(usable)}"
        )


def _duplicate_dict_keys(path: pathlib.Path) -> list[str]:
    """Literal dict keys defined more than once in a module.

    Python resolves these silently by keeping the last value, so they cannot be found at runtime --
    only by reading the source. This is the check that would have caught the jsonwebtoken and rsa
    collisions.
    """
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    dupes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        seen = set()
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value in seen:
                    dupes.append(f"{path.name}:{key.lineno}: duplicate key {key.value!r}")
                seen.add(key.value)
    return dupes


def test_crypto_databases_have_no_duplicate_keys():
    here = pathlib.Path(__file__).resolve().parent
    problems = []
    for name in ("services/supply_chain.py", "services/dep_scanner.py"):
        problems.extend(_duplicate_dict_keys(here / name))

    assert not problems, (
        "duplicate keys silently discard a crypto database entry:\n" + "\n".join(problems)
    )
