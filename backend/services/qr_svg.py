"""Dependency-free QR code encoder (ISO/IEC 18004, byte mode) with SVG output.

Used to render TOTP enrolment URIs (otpauth://...) in the admin portal without
any third-party request or pip dependency.

    matrix = encode_matrix("otpauth://totp/...", ecc="M")   # list[list[bool]], True = dark
    svg = to_svg(matrix)                                      # compact SVG string
    uri = svg_data_uri("otpauth://totp/...")                  # data:image/svg+xml;base64,...

Supports versions 1..40, error-correction levels L/M/Q/H, Reed-Solomon over
GF(256), block interleaving, format/version information and automatic mask
selection using the standard penalty rules.

Provenance: written from the ISO/IEC 18004 specification for this project. It is
not derived from, and shares no code with, any existing QR library (qrcode, segno,
qrcodegen or otherwise). The generator polynomials, the GF(256) log/antilog tables
built at import time from the standard 0x11D primitive polynomial, the
per-version error-correction block tables and the eight mask penalty rules are
specification data: any correct implementation necessarily reproduces the same
numbers, so matching values elsewhere are not evidence of copying. AGPL-3.0, like the
rest of this repository.
"""
from __future__ import annotations

import base64
import re

# --- Tables (index 0 unused; indexed by version 1..40) ------------------------------------

_ECC_ORDER = "LMQH"
_FORMAT_BITS = {"L": 1, "M": 0, "Q": 3, "H": 2}

_ECC_PER_BLOCK = {
    "L": (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    "Q": (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
          28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "H": (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
          30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
}
_NUM_BLOCKS = {
    "L": (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    "M": (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    "Q": (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20,
          23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    "H": (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
          25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
}

# --- GF(256) arithmetic and Reed-Solomon ---------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def rs_generator(degree: int) -> list[int]:
    """Coefficients of prod_{i<degree}(x - a^i), highest power first (leading 1 included)."""
    poly = [1]
    for i in range(degree):
        nxt = poly + [0]
        for j, c in enumerate(poly):
            nxt[j + 1] ^= _gf_mul(c, _EXP[i])
        poly = nxt
    return poly


def rs_remainder(data: list[int] | bytes, degree: int) -> list[int]:
    """Reed-Solomon ECC codewords for ``data`` (polynomial division remainder)."""
    gen = rs_generator(degree)[1:]
    rem = [0] * degree
    for byte in data:
        factor = byte ^ rem.pop(0)
        rem.append(0)
        if factor:
            for k, g in enumerate(gen):
                rem[k] ^= _gf_mul(g, factor)
    return rem


# --- Capacity helpers ------------------------------------------------------------------------

def _raw_data_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        num_align = ver // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if ver >= 7:
            result -= 36
    return result


def data_codewords(ver: int, ecc: str) -> int:
    return _raw_data_modules(ver) // 8 - _ECC_PER_BLOCK[ecc][ver] * _NUM_BLOCKS[ecc][ver]


def _alignment_positions(ver: int) -> list[int]:
    if ver == 1:
        return []
    num = ver // 7 + 2
    size = ver * 4 + 17
    step = 26 if ver == 32 else (ver * 4 + num * 2 + 1) // (num * 2 - 2) * 2
    positions = [size - 7 - i * step for i in range(num - 1)]
    return [6] + positions[::-1]


def format_bits(ecc: str, mask: int) -> int:
    """15-bit BCH-coded, XOR-masked format information word."""
    data = (_FORMAT_BITS[ecc] << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def version_bits(ver: int) -> int:
    """18-bit BCH-coded version information word (versions >= 7)."""
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return (ver << 12) | rem


# --- Codeword construction ---------------------------------------------------------------------

def _build_codewords(payload: bytes, ver: int, ecc: str) -> list[int]:
    capacity = data_codewords(ver, ecc)
    bits: list[int] = []

    def put(value: int, length: int) -> None:
        bits.extend((value >> i) & 1 for i in range(length - 1, -1, -1))

    put(0b0100, 4)
    put(len(payload), 8 if ver <= 9 else 16)
    for b in payload:
        put(b, 8)
    put(0, min(4, capacity * 8 - len(bits)))
    put(0, (-len(bits)) % 8)
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(data) < capacity:
        data.append(pad)
        pad ^= 0xEC ^ 0x11

    num_blocks = _NUM_BLOCKS[ecc][ver]
    ecc_len = _ECC_PER_BLOCK[ecc][ver]
    raw = _raw_data_modules(ver) // 8
    num_short = num_blocks - raw % num_blocks
    short_len = raw // num_blocks
    blocks, ecc_blocks, k = [], [], 0
    for i in range(num_blocks):
        n = short_len - ecc_len + (0 if i < num_short else 1)
        block = data[k:k + n]
        k += n
        blocks.append(block)
        ecc_blocks.append(rs_remainder(block, ecc_len))

    out = []
    for i in range(max(len(b) for b in blocks)):
        out.extend(b[i] for b in blocks if i < len(b))
    for i in range(ecc_len):
        out.extend(e[i] for e in ecc_blocks)
    assert len(out) == raw
    return out


# --- Matrix construction -----------------------------------------------------------------------

_MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


class _Grid:
    def __init__(self, ver: int):
        self.ver = ver
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.func = [[False] * self.size for _ in range(self.size)]

    def set(self, x: int, y: int, dark: bool) -> None:
        self.m[y][x] = bool(dark)
        self.func[y][x] = True

    def draw_function_patterns(self) -> None:
        size = self.size
        for i in range(size):
            self.set(6, i, i % 2 == 0)
            self.set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        self.set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _alignment_positions(self.ver)
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format("M", 0)  # reserve format areas; overwritten after masking
        if self.ver >= 7:
            bits = version_bits(self.ver)
            for i in range(18):
                bit = (bits >> i) & 1
                a, b = size - 11 + i % 3, i // 3
                self.set(a, b, bit)
                self.set(b, a, bit)

    def draw_format(self, ecc: str, mask: int) -> None:
        bits = format_bits(ecc, mask)
        size = self.size
        bit = lambda i: (bits >> i) & 1  # noqa: E731
        for i in range(6):
            self.set(8, i, bit(i))
        self.set(8, 7, bit(6))
        self.set(8, 8, bit(7))
        self.set(7, 8, bit(8))
        for i in range(9, 15):
            self.set(14 - i, 8, bit(i))
        for i in range(8):
            self.set(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set(8, size - 15 + i, bit(i))
        self.set(8, size - 8, True)

    def draw_codewords(self, codewords: list[int]) -> None:
        size, i, total = self.size, 0, len(codewords) * 8
        right = size - 1
        while right >= 1:
            if right == 6:
                right = 5
            upward = ((right + 1) & 2) == 0
            for vert in range(size):
                y = size - 1 - vert if upward else vert
                for x in (right, right - 1):
                    if not self.func[y][x] and i < total:
                        self.m[y][x] = bool((codewords[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        fn = _MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.func[y][x] and fn(x, y):
                    self.m[y][x] = not self.m[y][x]


_FINDER_LIKE = ([1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1])


def penalty(matrix: list[list[bool]]) -> int:
    """Standard mask penalty score (rules N1..N4)."""
    size = len(matrix)
    lines = [row for row in matrix] + [[matrix[y][x] for y in range(size)] for x in range(size)]
    score = 0
    for line in lines:
        run = 1
        for i in range(1, size + 1):
            if i < size and line[i] == line[i - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run = 1
        padded = [0] * 4 + [int(v) for v in line] + [0] * 4
        for i in range(len(padded) - 10):
            window = padded[i:i + 11]
            score += 40 * sum(window == pat for pat in _FINDER_LIKE)
    for y in range(size - 1):
        for x in range(size - 1):
            c = matrix[y][x]
            if c == matrix[y][x + 1] == matrix[y + 1][x] == matrix[y + 1][x + 1]:
                score += 3
    dark = sum(sum(row) for row in matrix)
    total = size * size
    score += 10 * (abs(dark * 20 - total * 10) // total)
    return score


def encode_matrix(data: bytes | str, ecc: str = "M", *, version: int | None = None,
                  mask: int | None = None) -> list[list[bool]]:
    """Encode ``data`` (byte mode) into a QR module matrix; True means a dark module.

    ``version`` and ``mask`` may be forced (mainly for testing); by default the smallest
    fitting version and the lowest-penalty mask are chosen. Raises ValueError if the data
    does not fit.
    """
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    ecc = ecc.upper()
    if ecc not in _ECC_ORDER:
        raise ValueError(f"ecc must be one of L, M, Q, H (got {ecc!r})")
    if mask is not None and mask not in range(8):
        raise ValueError("mask must be 0..7")
    candidates = [version] if version is not None else range(1, 41)
    for ver in candidates:
        if not 1 <= ver <= 40:
            raise ValueError("version must be 1..40")
        needed = 4 + (8 if ver <= 9 else 16) + 8 * len(payload)
        if needed <= data_codewords(ver, ecc) * 8:
            break
    else:
        raise ValueError(f"data too long for a QR code at ECC level {ecc} ({len(payload)} bytes)")

    grid = _Grid(ver)
    grid.draw_function_patterns()
    grid.draw_codewords(_build_codewords(payload, ver, ecc))
    best = None
    for m in ([mask] if mask is not None else range(8)):
        grid.apply_mask(m)
        grid.draw_format(ecc, m)
        score = penalty(grid.m)
        if best is None or score < best[0]:
            best = (score, m)
        grid.apply_mask(m)  # XOR again to undo
    grid.apply_mask(best[1])
    grid.draw_format(ecc, best[1])
    return grid.m


# --- SVG output ------------------------------------------------------------------------------------

_COLOUR_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")


def to_svg(matrix: list[list[bool]], scale: int = 4, border: int = 4,
           dark: str = "#000", light: str = "#fff") -> str:
    """Render a module matrix as a compact SVG (one path of horizontal runs)."""
    for colour in (dark, light):
        if not isinstance(colour, str) or not _COLOUR_RE.match(colour):
            raise ValueError(f"invalid colour {colour!r}; expected #rgb..#rrggbbaa")
    scale, border = int(scale), int(border)
    if scale < 1 or border < 0:
        raise ValueError("scale must be >= 1 and border >= 0")
    n = len(matrix) + 2 * border
    parts = []
    for y, row in enumerate(matrix):
        x = 0
        while x < len(row):
            if row[x]:
                start = x
                while x < len(row) and row[x]:
                    x += 1
                parts.append(f"M{start + border} {y + border}h{x - start}v1h-{x - start}z")
            else:
                x += 1
    px = n * scale
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{px}" height="{px}" '
        f'viewBox="0 0 {n} {n}" shape-rendering="crispEdges">'
        f'<rect width="{n}" height="{n}" fill="{light}"/>'
        f'<path fill="{dark}" d="{"".join(parts)}"/></svg>'
    )


def svg_data_uri(data: bytes | str, ecc: str = "M") -> str:
    """Encode ``data`` and return the SVG as a base64 data: URI."""
    svg = to_svg(encode_matrix(data, ecc))
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("ascii")).decode("ascii")
