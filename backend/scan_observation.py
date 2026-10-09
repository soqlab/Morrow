"""What a scan actually observed, in the shape the `scan_results` table stores.

`scan_results` used to record only `key_type`, so every reader that needed a key size had to
invent one: the org-wide CBOM resolved the whole estate to RSA-2048 / ECDSA-P256 and the HNDL
model priced every RSA endpoint at the RSA-2048 Q-Day probability. The table now carries
`key_bits`, `key_curve`, `cipher_name`, `scan_status` and `key_exchange`, and this module is the
single mapping
from `scanner.scan_host()` output to those columns, shared by the SQLite and Postgres writers so
the two backends cannot drift.

The important rule here is that **absence is None, never a number and never a name**. A row whose
`key_bits` is NULL is a scan that did not observe a key size -- either it predates the column or
the endpoint served no certificate. Writing 0, or defaulting to 2048, turns "we did not measure
this" into "we measured this", which is the class of bug this table change exists to end.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

#: Key types whose size and curve are fixed by the algorithm, so they need no separate measurement.
FIXED_SIZE_KEY_TYPES: Dict[str, tuple] = {
    "ed25519": (256, "Curve25519"),
    "ed448":   (448, "Curve448"),
    "x25519":  (256, "Curve25519"),
    "x448":    (448, "Curve448"),
}


def _int_or_none(value: Any) -> Optional[int]:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _text_or_none(value: Any) -> Optional[str]:
    s = str(value or "").strip()
    return s or None


def observed_key_bits(result: Dict[str, Any]) -> Optional[int]:
    """The observed public-key size in bits, or None when the scan did not observe one."""
    bits = _int_or_none(result.get("key_bits") if result else None)
    if bits is None:
        bits = _int_or_none((result or {}).get("cert_key_bits"))
    if bits is None:
        fixed = FIXED_SIZE_KEY_TYPES.get(str((result or {}).get("key_type") or "").strip().lower())
        if fixed:
            bits = fixed[0]
    return bits


def observed_key_curve(result: Dict[str, Any]) -> Optional[str]:
    curve = _text_or_none((result or {}).get("key_curve"))
    if curve:
        return curve
    fixed = FIXED_SIZE_KEY_TYPES.get(str((result or {}).get("key_type") or "").strip().lower())
    return fixed[1] if fixed else None


def observed_scan_status(result: Dict[str, Any]) -> Optional[str]:
    """`scan_status` as the scanner set it.

    Never inferred: a caller that persists results it did not obtain from `scan_host()` (the
    /scans/synthetic path, tests, imports) leaves this NULL rather than asserting "ok" about a
    handshake nobody performed.
    """
    return _text_or_none((result or {}).get("scan_status"))


def scan_result_observation(result: Dict[str, Any]) -> Dict[str, Any]:
    """The observed-fact columns for one scan result row."""
    r = result or {}
    return {
        "key_bits": observed_key_bits(r),
        "key_curve": observed_key_curve(r),
        "cipher_name": _text_or_none(r.get("cipher_name") or r.get("cipher")),
        "scan_status": observed_scan_status(r),
        # The negotiated TLS key-exchange group. Persisted because it is the only field that can
        # tell an org-wide report whether an endpoint has hybrid post-quantum key exchange
        # enabled; without it the hybrid buckets are structurally unreachable no matter what the
        # scanner observes. Only stored when the scan actually observed it.
        "key_exchange": (
            _text_or_none(r.get("key_exchange") or r.get("negotiated_group"))
            if r.get("key_exchange_observed", True) else None
        ),
    }


def sized_algorithm_name(key_type: str, key_bits: Optional[int], key_curve: str = "") -> str:
    """A key-size-qualified algorithm label, or the bare type when the size was not observed.

    "RSA" with no size is graded as RSA-2048 by every classification table in the product, so an
    RSA-4096 endpoint was reported at the RSA-2048 verdict. Where the size *is* known this returns
    "RSA-4096" / "P-384"; where it is not, it returns "RSA" and the caller must keep treating that
    as an unsized observation rather than as a small key.
    """
    kt = str(key_type or "").strip()
    if not kt:
        return ""
    bits = _int_or_none(key_bits)
    upper = kt.upper()
    if upper.startswith("RSA") and bits and not any(ch.isdigit() for ch in kt):
        return f"RSA-{bits}"
    if upper in {"EC", "ECC", "ECDSA"}:
        curve = str(key_curve or "").strip()
        if curve.lower() in {"secp256r1", "prime256v1"}:
            return "P-256"
        if curve.lower() == "secp384r1":
            return "P-384"
        if curve.lower() == "secp521r1":
            return "P-521"
        if bits:
            if bits >= 500:
                return "P-521"
            if bits >= 384:
                return "P-384"
            if bits >= 256:
                return "P-256"
        return kt
    return kt
