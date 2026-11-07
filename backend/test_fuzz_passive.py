"""Fuzz: passive log ingest (/v1/runtime/passive/ingest): body decoding and the nginx, Envoy,
HAProxy, AWS ALB and Zeek line parsers.

Properties: decode_records raises only PayloadError; parse_batch never raises for a known format
and accounts for every record; every observation has a valid host, port and TLS version; and a
line of up to MAX_LINE_CHARS parses in bounded time (no regex backtracking blow-up).
"""

from __future__ import annotations

import gzip
import json

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from fuzz import checks  # noqa: E402
from fuzz.hypo import byte_inputs, fuzz_settings, json_values, seeds  # noqa: E402
from services import passive_discovery as pd  # noqa: E402
from services import passive_ingest as pi  # noqa: E402

FORMATS = st.sampled_from(pd.FORMATS)
_LINES = [line for s in seeds("passive", regressions=False) for line in s[1:].decode().splitlines()]
_FIELD_NAMES = sorted({n for fmt in pd._ALIASES.values() for names in fmt.values() for n in names}
                      | {"type", "ssl_protocol", "ssl_cipher", "domain_name", "request", "request_url"})

#: Long runs of one character class: what makes a backtracking regex go quadratic.
_RUNS = st.builds(lambda unit, n, head: head + unit * n,
                  st.sampled_from(["a", "a=", '"', '\\"', "a.", " ", '="', "\\", "a-", "\t", "https "]),
                  st.integers(1000, pd.MAX_LINE_CHARS // 2),
                  st.sampled_from(["", "https ", "#fields\t", 'a="', "x=", "{"]))


def _mutated_line(line, ops):
    return checks.mutate(line.encode(), ops).decode("utf-8", "replace")


_LINE = st.one_of(
    st.sampled_from(_LINES),
    st.builds(_mutated_line, st.sampled_from(_LINES),
              st.lists(st.tuples(st.integers(0, 5), st.integers(0, 1 << 16), st.integers(0, 1 << 16)), max_size=6)),
    st.text(max_size=300),
    _RUNS,
)


@fuzz_settings(300)
@given(FORMATS, st.lists(_LINE, max_size=8))
def test_line_parsers(fmt, lines):
    checks.check_passive_batch(fmt, lines)


_RECORD = st.dictionaries(st.sampled_from(_FIELD_NAMES), st.one_of(json_values(6), st.text(max_size=40)), max_size=8)


@fuzz_settings(200)
@given(FORMATS, st.lists(st.one_of(_RECORD, json_values(10)), max_size=6))
def test_structured_records(fmt, records):
    """Shipper JSON records: any JSON value in any field."""
    checks.check_passive_batch(fmt, [pi._unwrap(r) for r in records])


@fuzz_settings(200)
@given(byte_inputs("passive"))
def test_ingest_body(data):
    checks.check_passive_bytes(data)


@fuzz_settings(50)
@given(st.lists(json_values(8), max_size=5), st.sampled_from(["", "gzip", "deflate"]))
def test_compressed_json_bodies(records, encoding):
    import zlib

    body = json.dumps(records).encode()
    if encoding == "gzip":
        body = gzip.compress(body)
    elif encoding == "deflate":
        body = zlib.compress(body)
    checks.check_passive_body(body, "application/json", encoding)


@pytest.mark.parametrize("line", [
    "a" * pd.MAX_LINE_CHARS,
    'a="' + "\\a" * (pd.MAX_LINE_CHARS // 2 - 2),
    'https "' + "a " * (pd.MAX_LINE_CHARS // 2 - 4),
], ids=["letters", "unterminated-escaped-quote", "alb-unterminated-quote"])
def test_longest_allowed_line_parses_quickly(line):
    """Regression: _KV_RE retried a key match from every offset of a run of key characters, and
    the quoted-value alternatives backtracked, so one 16 KB line took ~20 s (nginx/envoy/haproxy
    key=value) or ~1 s (ALB) and a batch of them held an ingest worker for hours."""
    for fmt in pd.FORMATS:
        with checks.time_limit(1.0, what=f"{fmt} long line"):
            pd.parse_batch(fmt, [line] * 3)


@pytest.mark.parametrize("header", ["#separator ", "#separator \\x", "#separator \\xZZ"])
def test_bad_zeek_separator_header_is_counted_not_raised(header):
    """Regression: "#separator \\x" raised UnicodeDecodeError and an empty separator raised
    ValueError("empty separator") out of parse_batch, failing the whole ingest with a 500."""
    out = pd.parse_batch("zeek", [header, "#fields\tversion", "TLSv13"])
    assert out["received"] == 3


def test_zeek_hex_separator_is_decoded():
    out = pd.parse_batch("zeek", ["#separator \\x7c", "#fields|server_name|id.resp_p|version|cipher|curve",
                                  "a.example.com|443|TLSv13|TLS_AES_128_GCM_SHA256|x25519"])
    assert out["parsed"] == 1 and out["observations"][0]["host"] == "a.example.com"


@pytest.mark.parametrize("body,ctype", [
    (b"[" * 100_000, "application/json"),
    (b'{"a":' * 50_000 + b"1" + b"}" * 50_000 + b"\n{}", "application/x-ndjson"),
], ids=["deep-array", "deep-ndjson-line"])
def test_deeply_nested_json_is_a_payload_error_not_a_crash(body, ctype):
    """Regression: json.loads raised RecursionError (not a ValueError) on deep nesting, which
    escaped decode_records and turned the ingest request into a 500."""
    try:
        records = pi.decode_records(body, ctype)
    except pi.PayloadError:
        return
    checks.check_passive_batch("nginx", records)
