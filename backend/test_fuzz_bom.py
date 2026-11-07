"""Fuzz: CycloneDX import -- /v1/sbom/import (parse_cyclonedx_json + import_sbom), /v1/cbom/import
(import_cbom, schema-validated) and the CBOM ingest body (/v1/cbom/ingest and the signed CI path,
cbom_webhook.parse_payload + ingest_cbom).

Properties: only ValueError (ImportTooLarge / SchemaInvalid are ValueErrors) escapes the import
functions and only ValueError/OverflowError escapes parse_payload; an accepted document is
stored without error and its classification fields have the declared types. Inputs are real
CBOMkit output and SBOMs with subtrees replaced by arbitrary JSON values.
"""

from __future__ import annotations

import copy
import json
import pathlib

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from fuzz import checks  # noqa: E402
from fuzz.hypo import byte_inputs, fuzz_settings, json_values, seeds  # noqa: E402
from services import sbom_import as si  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "tests" / "fixtures" / "cbomkit"
_CBOMS = [json.loads(b) for b in seeds("cbom", regressions=False)]
_SBOMS = [json.loads(b) for b in seeds("sbom", regressions=False)] + _CBOMS


def _paths(doc, prefix=()):
    """Every (path) to a value inside doc, for structural mutation."""
    out = [prefix]
    if isinstance(doc, dict):
        for k, v in doc.items():
            out += _paths(v, prefix + (k,))
    elif isinstance(doc, list):
        for i, v in enumerate(doc[:20]):
            out += _paths(v, prefix + (i,))
    return out


def _replace(doc, path, value):
    if not path:
        return value
    doc = copy.deepcopy(doc)
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return doc


@st.composite
def mutated_documents(draw, docs):
    doc = draw(st.sampled_from(docs))
    for _ in range(draw(st.integers(1, 4))):
        paths = _paths(doc)
        doc = _replace(doc, draw(st.sampled_from(paths)), draw(json_values(8)))
    return json.dumps(doc).encode()


@fuzz_settings(150)
@given(st.one_of(mutated_documents(_SBOMS), byte_inputs("sbom", max_size=1024)))
def test_sbom_import(data):
    checks.check_sbom(data)


@fuzz_settings(60)
@given(st.one_of(mutated_documents(_CBOMS), byte_inputs("cbom", max_size=1024)))
def test_cbom_import(data):
    checks.check_cbom(data)


@fuzz_settings(150)
@given(st.one_of(mutated_documents(_CBOMS + [json.loads(b) for b in seeds("cbom_ingest", regressions=False)]),
                 byte_inputs("cbom_ingest", max_size=1024)))
def test_cbom_ingest_body(data):
    checks.check_cbom_ingest(data)


def _nested(depth):
    comp = {"type": "library", "name": "leaf"}
    for i in range(depth):
        comp = {"type": "library", "name": f"lib{i}", "components": [comp]}
    return comp


@pytest.mark.parametrize("depth", [45, 400])
def test_deeply_nested_components_are_refused_or_imported(depth):
    """Regression: _collect recursed once per nesting level (RecursionError at ~1000), and a CBOM
    nested just under json's limit loaded but then blew the stack in jsonschema validation; both
    surfaced as HTTP 500/400 with a stack-depth message instead of a validation error."""
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [_nested(depth)]}
    data = json.dumps(doc).encode()
    checks.check_sbom(data)
    checks.check_cbom(data)
    checks.check_cbom_ingest(data)
    if depth > si.MAX_JSON_DEPTH // 2:
        with pytest.raises(ValueError):
            si.parse_cyclonedx_json(data)
    else:
        assert len(si.parse_cyclonedx_json(data)["components"]) == depth + 1


@pytest.mark.parametrize("comp", [
    {"name": 5},
    {"type": 3, "name": "openssl"},
    {"name": "openssl", "cryptoProperties": {"algorithmProperties": "x"}},
    {"name": "openssl", "properties": [{"name": "algorithm", "value": 7}]},
    {"name": "openssl", "properties": [{"name": ["keySize"], "value": "2048"}]},
    {"name": "openssl", "supplier": {"name": {"x": 1}}},
], ids=["int-name", "int-type", "str-algorithmProperties", "int-property-value", "list-property-name",
        "object-supplier-name"])
def test_sbom_field_of_the_wrong_json_type_is_ignored(comp):
    """Regression: the unvalidated SBOM path called .lower()/.get()/.strip() on whatever JSON
    type a field held, raising AttributeError (reported as a 400 carrying the Python message)."""
    data = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [comp]}).encode()
    checks.check_sbom(data)


@pytest.mark.parametrize("param", ["²", "99999999999999999999999", "-1", "2048"])
def test_parameter_set_identifier_is_parsed_safely(param):
    """Regression: str.isdigit() accepts "²", which int() then rejects with a ValueError from
    deep inside import_cbom; and an unbounded integer key size overflowed SQLite's INTEGER."""
    out = si._classify_cbom_algorithm("RSA", "pke", param)
    assert out["key_length"] in (None, 2048)


def test_huge_key_size_in_a_cbom_is_not_stored_as_an_overflowing_integer():
    """Regression: relatedCryptoMaterialProperties.size is a JSON integer of any size; stored as
    is, it raised OverflowError from sqlite3 (not a ValueError: HTTP 500)."""
    doc = json.loads(seeds("cbom", regressions=False)[0])
    doc["components"].append({
        "type": "cryptographic-asset", "bom-ref": "key@fuzz", "name": "key",
        "cryptoProperties": {"assetType": "related-crypto-material",
                             "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 10 ** 30}},
    })
    checks.check_cbom(json.dumps(doc).encode())
