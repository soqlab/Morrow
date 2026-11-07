"""The key-exchange probe sends an X25519MLKEM768 key share, not only X25519.

Found in the real-service e2e run (docs/DEMO_RUNBOOK.md): nginx 1.29 on OpenSSL 3.5 with
`ssl_ecdh_curve X25519MLKEM768:X25519` negotiated X25519MLKEM768 with curl but X25519 with the
scanner, because the probe's only key share was X25519 and OpenSSL takes a client share in an
acceptable group rather than asking for another (no HelloRetryRequest). The scan then reported a
hybrid-capable endpoint as classical, and the crypto kill switch could never confirm a switch.
"""
import scanner


def _key_shares(hello: bytes):
    body = hello[5 + 4:]                       # record header, handshake header
    pos = 2 + 32
    pos += 1 + body[pos]                       # session id
    suites = int.from_bytes(body[pos:pos + 2], "big")
    pos += 2 + suites
    pos += 1 + body[pos]                       # compression methods
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    while pos < end:
        ext_type = int.from_bytes(body[pos:pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
        ext = body[pos + 4:pos + 4 + ext_len]
        pos += 4 + ext_len
        if ext_type == 0x0033:
            shares, i = [], 2
            while i < len(ext):
                group = int.from_bytes(ext[i:i + 2], "big")
                n = int.from_bytes(ext[i + 2:i + 4], "big")
                shares.append((group, ext[i + 4:i + 4 + n]))
                i += 4 + n
            return shares
    return []


def test_client_hello_offers_hybrid_and_classical_key_shares():
    hello = scanner._build_client_hello("pq.example.com")
    shares = _key_shares(hello)
    assert [g for g, _ in shares] == [0x11EC, 0x001D]
    hybrid, x25519 = shares[0][1], shares[1][1]
    assert len(hybrid) == 1184 + 32           # ML-KEM-768 encapsulation key || X25519 public key
    assert len(x25519) == 32
    assert int.from_bytes(hello[3:5], "big") == len(hello) - 5


def test_fallback_encapsulation_key_is_well_formed(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_mlkem(name, *args, **kwargs):
        if name.endswith("asymmetric") and args and args[2] and "mlkem" in args[2]:
            raise ImportError("no ML-KEM in this build")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_mlkem)
    ek = scanner._mlkem768_encapsulation_key()
    assert len(ek) == 1184
    coeffs = []
    for i in range(0, 1152, 3):                # FIPS 203 ByteDecode_12: every coefficient < q
        b0, b1, b2 = ek[i], ek[i + 1], ek[i + 2]
        coeffs += [b0 | ((b1 & 0x0F) << 8), (b1 >> 4) | (b2 << 4)]
    assert len(coeffs) == 768 and max(coeffs) < 3329
