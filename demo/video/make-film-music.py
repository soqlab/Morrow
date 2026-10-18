"""Generate the score for the Morrow three-minute film.

Standard library only (`wave`, `math`, `array`). The promo's track is the wrong
shape for three minutes — a kick on every beat from bar four is insistent over a
minute and exhausting over three — so this is its own arrangement, with an arc:

    bars  0-10   opening     a low drone, a sub on each downbeat, one bell a bar
    bars 11-24   the problem a pad joins; a soft pulse on beats one and three
    bars 25-37   discovery   eighth-note figure; the kick arrives, still halved
    bars 38-55   exposure    full: kick on the beat, pad, figure, hats offbeat
    bars 56-70   evidence    the pulse thins again so the words can carry
    bars 71-77   build       sixteenths and a rising noise sweep
    bars 78-89   resolve     one long chord, no pulse, a decaying tail

120 BPM, so a beat is 0.5 s and a bar 2 s; ninety bars is three minutes exactly,
and every cut in render-3min.js lands on a beat of that grid.

    backend/.venv/Scripts/python.exe demo/video/make-film-music.py

Speed note: pure Python cannot afford a sine call per sample per voice. Every
voice is rendered once into a cache keyed by pitch, length and timbre and then
mixed by slice addition.
"""
from __future__ import annotations

import argparse
import array
import math
import pathlib
import wave

SR = 44100
BPM = 120.0
BEAT = 60.0 / BPM
BAR = BEAT * 4
BARS = 90                       # 180 s
ROOT = 55.0                     # A1
PEAK_DBFS = -16.0
FADE_IN = 0.6
FADE_OUT = 6.0

PROGRESSION = [0, -4, 3, -2]    # i - VI - III - VII in A minor
CHORD_SHAPE = {
    0:  [0, 12, 15, 19, 24],
    -4: [0, 12, 16, 19, 24],
    3:  [0, 12, 16, 19, 23],
    -2: [0, 12, 16, 19, 24],
}
FIGURE = [0, 2, 4, 2, 3, 2, 4, 1]

# Section boundaries, in bars.
OPEN_END, PAD_IN, PULSE_IN, FULL_IN, THIN_IN, BUILD_IN, RESOLVE = 11, 11, 25, 38, 56, 71, 78

_cache: dict = {}


def semis(n: float) -> float:
    return ROOT * (2.0 ** (n / 12.0))


def tone(freq: float, seconds: float, partials, decay: float, attack_ms: float = 3.0) -> list[float]:
    key = (round(freq, 3), round(seconds, 4), partials, decay, attack_ms)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    n = int(seconds * SR)
    atk = max(1, int(attack_ms * SR / 1000.0))
    out = [0.0] * n
    for h, gain in enumerate(partials, start=1):
        f = freq * h
        if f > 15000.0:
            break
        w = 2.0 * math.pi * f / SR
        sin = math.sin
        for i in range(n):
            out[i] += gain * sin(w * i)
    for i in range(n):
        a = min(1.0, i / atk)
        out[i] *= a * math.exp(-decay * i / SR)
    _cache[key] = out
    return out


def kick(seconds: float = 0.34) -> list[float]:
    key = ("kick", seconds)
    if key in _cache:
        return _cache[key]
    n = int(seconds * SR)
    out = [0.0] * n
    phase = 0.0
    for i in range(n):
        t = i / SR
        f = 42.0 + 84.0 * math.exp(-t * 24.0)
        phase += 2.0 * math.pi * f / SR
        out[i] = math.sin(phase) * math.exp(-t * 6.4)
    _cache[key] = out
    return out


def noise(seconds: float, decay: float, seed: int, hp: float = 0.0) -> list[float]:
    key = ("n", round(seconds, 4), decay, seed, hp)
    if key in _cache:
        return _cache[key]
    n = int(seconds * SR)
    s = seed & 0xFFFFFFFF
    out = [0.0] * n
    prev = 0.0
    for i in range(n):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        v = (s / 0x3FFFFFFF) - 1.0
        if hp:
            v, prev = v - hp * prev, v
        out[i] = v * math.exp(-decay * i / SR)
    _cache[key] = out
    return out


def riser(seconds: float) -> list[float]:
    n = int(seconds * SR)
    s = 20261
    out = [0.0] * n
    lp = 0.0
    for i in range(n):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        v = (s / 0x3FFFFFFF) - 1.0
        t = i / n
        lp += (0.015 + 0.38 * t) * (v - lp)
        out[i] = lp * (0.08 + 0.92 * t * t)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bars", type=int, default=BARS)
    ap.add_argument("--out", default=str(pathlib.Path(__file__).with_name("morrow-3min-music.wav")))
    args = ap.parse_args()

    total = int(args.bars * BAR * SR) + int(3.0 * SR)
    left = [0.0] * total
    right = [0.0] * total

    def put(buf, at, gain, pan=0.5):
        i = int(at * SR)
        if i < 0 or i >= total:
            return
        gl, gr = gain * (1.0 - pan) * 2.0, gain * pan * 2.0
        end = min(total, i + len(buf))
        for k in range(end - i):
            v = buf[k]
            left[i + k] += v * gl
            right[i + k] += v * gr

    for bar in range(args.bars):
        t0 = bar * BAR
        chord = PROGRESSION[bar % len(PROGRESSION)]
        notes = [semis(chord + s) for s in CHORD_SHAPE[chord]]
        resolve = bar >= RESOLVE
        build = BUILD_IN <= bar < RESOLVE
        thin = THIN_IN <= bar < BUILD_IN
        full = FULL_IN <= bar < THIN_IN
        pulse = PULSE_IN <= bar < RESOLVE
        pad = PAD_IN <= bar

        # --- drone, under everything ------------------------------------
        put(tone(notes[0], BAR + 0.6, (1.0, 0.20, 0.05), 0.75), t0,
            0.34 if bar < OPEN_END else 0.24)
        # --- the downbeat sub -------------------------------------------
        put(tone(notes[0] / 2.0, 1.8, (1.0, 0.07), 2.2, 8.0), t0, 0.50)

        # --- one bell a bar in the opening ------------------------------
        if bar < OPEN_END:
            f = notes[min(3, len(notes) - 1)] * 2.0
            put(tone(f, 2.4, (1.0, 0.5, 0.26, 0.10), 2.4, 1.5), t0 + BEAT * 2,
                0.16, 0.5 + 0.22 * math.sin(bar * 1.3))

        # --- pad ---------------------------------------------------------
        if pad:
            hold = (BAR * 7.0) if (resolve and bar == RESOLVE) else BAR * 1.05
            level = 0.26 if resolve else (0.20 if full else 0.15)
            for j, f in enumerate(notes[1:], start=1):
                put(tone(f, hold, (1.0, 0.28, 0.13, 0.05), 0.5 if resolve else 1.0),
                    t0, level / (1.0 + 0.35 * j), 0.5 + 0.30 * math.sin(j * 1.9))

        # --- pulse: halved until the film opens up -----------------------
        if pulse and not resolve:
            beats = (0, 2) if (bar < FULL_IN or thin) else (0, 1, 2, 3)
            for b in beats:
                put(kick(), t0 + b * BEAT, 0.52 if full else 0.40)
            if full:
                for b in range(4):
                    put(noise(0.04, 96.0, 11 + b, 0.85), t0 + (b + 0.5) * BEAT,
                        0.10, 0.42 + 0.16 * (b % 2))
            if bar % 8 == 7 and (full or build):
                for k in range(4):
                    put(noise(0.08, 52.0, 41 + k), t0 + BEAT * (3 + k * 0.25), 0.13 + 0.04 * k)

        # --- the figure ---------------------------------------------------
        if PULSE_IN <= bar < RESOLVE:
            step = BEAT / (4 if build else 2)
            for k in range(int(BAR / step)):
                idx = FIGURE[k % len(FIGURE)]
                f = notes[min(idx, len(notes) - 1)] * 2.0
                dur = step * (0.9 if build else 1.5)
                put(tone(f, dur, (1.0, 0.42, 0.20, 0.09), 9.0 if build else 6.0, 1.2),
                    t0 + k * step, 0.11 if build else 0.085,
                    0.5 + 0.32 * math.sin(k * 0.8 + bar))

        if bar == RESOLVE - 4:
            put(riser(BAR * 4.0), t0, 0.30)
        if bar == RESOLVE:
            put(noise(1.8, 2.8, 777, 0.4), t0, 0.26)
            put(kick(0.7), t0, 0.90)

    fi, fo = int(FADE_IN * SR), int(FADE_OUT * SR)
    for i in range(min(fi, total)):
        g = 0.5 - 0.5 * math.cos(math.pi * i / fi)
        left[i] *= g
        right[i] *= g
    for k in range(min(fo, total)):
        i = total - 1 - k
        g = 0.5 - 0.5 * math.cos(math.pi * k / fo)
        left[i] *= g
        right[i] *= g

    def soft(v):
        return math.tanh(v * 0.70) / 0.70

    left = [soft(v) for v in left]
    right = [soft(v) for v in right]
    peak = max(1e-9, max(max(map(abs, left)), max(map(abs, right))))
    gain = (10.0 ** (PEAK_DBFS / 20.0)) / peak * 32767.0

    frames = array.array("h", bytes(total * 4))
    for i in range(total):
        a = int(left[i] * gain)
        b = int(right[i] * gain)
        frames[2 * i] = -32767 if a < -32767 else (32767 if a > 32767 else a)
        frames[2 * i + 1] = -32767 if b < -32767 else (32767 if b > 32767 else b)

    with wave.open(args.out, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(frames.tobytes())
    print(f"wrote {args.out}: {total / SR:.2f}s, {BPM:.0f} BPM, {args.bars} bars, "
          f"peak {PEAK_DBFS} dBFS")


if __name__ == "__main__":
    main()
