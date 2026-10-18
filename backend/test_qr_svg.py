"""Tests for services/qr_svg.py (stdlib QR encoder).

Known answers come from ISO/IEC 18004 tables and the widely published
"HELLO WORLD" 1-M worked example; module matrices were additionally
cross-checked (outside this test) against zxing-cpp decoding and segno.
"""
import base64
import re

import pytest

from services import qr_svg as q

OTP = (
    "otpauth://totp/Morrow:alice%40corp.example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    "&issuer=Morrow&algorithm=SHA1&digits=6&period=30"
)


def test_format_bits_known_answers():
    # ISO/IEC 18004 Annex C: ECC level M, masks 0..7
    assert [q.format_bits("M", m) for m in range(8)] == [
        0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
    ]
    assert q.format_bits("L", 0) == 0x77C4
    assert q.format_bits("Q", 0) == 0x355F
    assert q.format_bits("H", 0) == 0x1689


def test_version_bits_known_answer():
    assert q.version_bits(7) == 0x07C94
    assert q.version_bits(40) == 0x28C69


def test_rs_generator_degree_10():
    assert q.rs_generator(10) == [1, 216, 194, 159, 111, 199, 94, 95, 113, 157, 193]


def test_rs_ecc_hello_world_1m():
    # Classic alphanumeric "HELLO WORLD" 1-M data codewords and their ECC
    data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
    assert q.rs_remainder(data, 10) == [196, 35, 39, 119, 235, 215, 231, 226, 93, 23]


def test_byte_mode_codewords_hello_world_1m():
    cw = q._build_codewords(b"HELLO WORLD", 1, "M")
    # 0100 | 00001011 | 'H' 'E' ... 'D' | 0000 terminator | pad EC 11 EC
    assert cw[:16] == [64, 180, 132, 84, 196, 196, 242, 5, 116, 245, 36, 196, 64, 236, 17, 236]
    assert cw[16:] == q.rs_remainder(cw[:16], 10)


def test_capacity_table_spot_checks():
    assert q.data_codewords(1, "L") == 19
    assert q.data_codewords(1, "H") == 9
    assert q.data_codewords(7, "M") == 124
    assert q.data_codewords(10, "Q") == 154
    assert q.data_codewords(40, "L") == 2956


def _version(matrix):
    return (len(matrix) - 17) // 4


@pytest.mark.parametrize("ecc,ver", [("M", 1), ("L", 6), ("M", 7), ("Q", 9), ("M", 10), ("H", 20)])
def test_version_selection_boundaries(ecc, ver):
    cap = q.data_codewords(ver, ecc) - (2 if ver <= 9 else 3)
    assert _version(q.encode_matrix(b"a" * cap, ecc)) == ver
    assert _version(q.encode_matrix(b"a" * (cap + 1), ecc)) == ver + 1


def test_otpauth_uri_fits_small_version():
    m = q.encode_matrix(OTP, "M")
    assert _version(m) == 8 and len(m) == 49


def test_oversize_input_raises():
    with pytest.raises(ValueError):
        q.encode_matrix(b"x" * 2954, "L")
    with pytest.raises(ValueError):
        q.encode_matrix(b"x" * 1274, "H")
    with pytest.raises(ValueError):
        q.encode_matrix(b"x" * 20, "M", version=1)
    with pytest.raises(ValueError):
        q.encode_matrix("x", "Z")


def test_finder_timing_and_dark_module():
    m = q.encode_matrix(OTP, "M")
    n = len(m)
    finder = [[max(abs(dx), abs(dy)) not in (2, 4) for dx in range(-3, 4)] for dy in range(-3, 4)]
    for ox, oy in ((0, 0), (n - 7, 0), (0, n - 7)):
        assert [row[ox:ox + 7] for row in m[oy:oy + 7]] == finder
    # separators are light
    assert not any(m[7][0:8]) and not any(m[7][n - 8:]) and not any(m[n - 8][0:8])
    assert all(m[6][i] == (i % 2 == 0) for i in range(8, n - 8))
    assert all(m[i][6] == (i % 2 == 0) for i in range(8, n - 8))
    assert m[n - 8][8] is True


def test_format_and_version_info_placed():
    m = q.encode_matrix(b"v" * 110, "M")  # version 7 -> version info present
    n = len(m)
    assert _version(m) == 7
    # second format copy: bits 0..7 along row 8 (right), bits 8..14 down column 8 (bottom)
    low = sum(int(m[8][n - 1 - i]) << i for i in range(8))
    high = sum(int(m[n - 15 + i][8]) << i for i in range(8, 15))
    assert (low | high) in {q.format_bits("M", k) for k in range(8)}
    # first format copy around the top-left finder must agree
    first = sum(int(m[i][8]) << i for i in range(6)) | (int(m[7][8]) << 6) | (int(m[8][8]) << 7)
    first |= int(m[8][7]) << 8
    first |= sum(int(m[8][14 - i]) << i for i in range(9, 15))
    assert first == low | high
    vbits = q.version_bits(7)
    for i in range(18):
        a, b = n - 11 + i % 3, i // 3
        assert m[b][a] == bool((vbits >> i) & 1) == m[a][b]


def test_forced_mask_changes_matrix_and_is_deterministic():
    a = q.encode_matrix(OTP, "M", mask=0)
    b = q.encode_matrix(OTP, "M", mask=3)
    assert a != b
    assert q.encode_matrix(OTP, "M") == q.encode_matrix(OTP.encode(), "M")


def test_svg_structure():
    m = q.encode_matrix("hello", "M")
    svg = q.to_svg(m, scale=5, border=2, dark="#112233", light="#fafafa")
    n = len(m) + 4
    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"')
    assert f'width="{n * 5}" height="{n * 5}"' in svg
    assert f'viewBox="0 0 {n} {n}"' in svg
    assert 'shape-rendering="crispEdges"' in svg
    assert svg.count("<path") == 1 and 'fill="#112233"' in svg and 'fill="#fafafa"' in svg
    # path runs cover exactly the dark modules
    covered = set()
    for x, y, w in re.findall(r"M(\d+) (\d+)h(\d+)v1h-\d+z", svg):
        covered.update((int(x) - 2 + k, int(y) - 2) for k in range(int(w)))
    assert covered == {(x, y) for y, row in enumerate(m) for x, v in enumerate(row) if v}
    # only numbers and the two colours
    stripped = re.sub(r'"[^"]*"', '""', svg)
    assert re.fullmatch(r'[<>/a-zA-Z =":\-]*', stripped)


@pytest.mark.parametrize("bad", ["red", "#12", "#123456789", "#fff\" onload=\"x", "url(#a)", "", None])
def test_svg_colour_validation(bad):
    m = q.encode_matrix("x")
    with pytest.raises(ValueError):
        q.to_svg(m, dark=bad)
    with pytest.raises(ValueError):
        q.to_svg(m, light=bad)


def test_svg_data_uri():
    uri = q.svg_data_uri(OTP)
    assert uri.startswith("data:image/svg+xml;base64,")
    svg = base64.b64decode(uri.split(",", 1)[1]).decode("ascii")
    assert svg.startswith("<svg") and svg.endswith("</svg>")
