"""Fuzz: the certificate-manager API field parsers in services/cert_inventory (Keyfactor, Venafi,
DigiCert, AWS/Azure/GCP KMS responses): dates, sizes, algorithm names, fingerprints, CSRs.

Property: none of them raises for any JSON value a vendor API can return, so one odd record
cannot abort a whole inventory sync.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from fuzz import checks  # noqa: E402
from fuzz.hypo import fuzz_settings, json_values  # noqa: E402
from services import cert_inventory as ci  # noqa: E402

_DATE_LIKE = st.one_of(
    st.from_regex(r"/Date\(\d{1,25}\)/", fullmatch=True),
    st.from_regex(r"\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,9})?([+-]\d{2}:\d{2}|Z)?)?", fullmatch=True),
    st.from_regex(r"\d{9,11}(\.\d{1,6})?", fullmatch=True),
    st.floats(), st.integers(-(10 ** 20), 10 ** 20),
)


@fuzz_settings(400)
@given(st.one_of(json_values(10), _DATE_LIKE))
def test_vendor_field_parsers(value):
    checks.check_cert_inventory_value(value)


@pytest.mark.parametrize("value", [
    "/Date(99999999999999999999)/",
    "0001-01-01T00:00:00+05:00",
    "9999-12-31T23:59:59-05:00",
    float("inf"),
    10 ** 18,
])
def test_out_of_range_dates_are_blank_not_an_exception(value):
    """Regression: /Date(n)/ with a huge n raised OSError/OverflowError, and an ISO date at the
    edge of datetime's range raised OverflowError on conversion to UTC; either aborted the sync."""
    assert ci._date(value) == ""
