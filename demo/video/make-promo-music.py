"""Generate the rhythmic music bed for the Morrow promo.

Standard library only (`wave`, `math`, `array`) — numpy is not installed here,
and the long film's ambient bed (make-music.py) is the wrong shape for a
seventy-five second cut: the promo needs something you can put a cut on.

The shape, at 120 BPM — a beat every 0.5 s, a bar every 2 s:

    bars  0-3    cold open   sub pulse on the downbeat, a low drone, nothing else
    bars  4-11   pulse       kick on every beat, hats on the offbeat, arpeggio in
    bars 12-23   full        chords over the pulse, the arpeggio doubled
    bars 24-31   build       sixteenth arpeggio, a rising noise sweep, snare fills
    bars 32-37   resolve     one long chord, the pulse gone, a decaying tail

The progression is Am - F - C - G, one bar each, which resolves back to Am.
Every cut in render-promo.js lands on a beat of this grid, so the picture and
the sound are the same clock.

    backend/.venv/Scripts/python.exe demo/video/make-promo-music.py

Speed note: pure Python cannot afford a sine call per sample per voice. Every
voice is rendered once into a cached buffer keyed by pitch, length and timbre,
and then mixed in by slice addition, so the whole track costs a few seconds.
"""
from __future__ import annotations

import argparse
import array
import math
import pathlib
import wave

SR = 44100
BPM = 120.0
BEAT = 60.0 / BPM              # 0.5 s
BAR = BEAT * 4                 # 2.0 s
BARS = 38                      # 76 s
ROOT = 55.0                    # A1
PEAK_DBFS = -14.0              # louder than the tour bed: this one is the point
FADE_IN = 0.25
FADE_OUT = 5.0

# i - VI - III - VII in A minor, as semitone offsets from ROOT.
PROGRESSION = [0, -4, 3, -2]
CHORD_SHAPE = {
    0:  [0, 12, 15, 19, 24],       # Am
    -4: [0, 12, 16, 19, 24],       # F
    3:  [0, 12, 16, 19, 23],       # C
    -2: [0, 12, 16, 19, 24],       # G
}
# The arpeggio walks this pattern of chord-tone indices, one per sixteenth.
ARP = [0, 2, 3, 2, 4, 2, 3, 1]


def semis(n: float) -> float:
    return ROOT * (2.0 ** (n / 12.0))


def env_exp(n: int, attack: int, decay: float) -> list[float]:
    """A fast attack and an exponential decay, as a per-sample gain."""
    out = []
    for i in range(n):
        a = min(1.0, i / max(1, attack))
        out.append(a * math.exp(-decay * i / SR))
    return out


_cache: dict = {}


def tone(freq: float, seconds: float, partials, decay: float, attack_ms: float = 2.0) -> list[float]:
    """One cached voice: a sum of harmonics under an exponential envelope."""
    key = (round(freq, 3), round(seconds, 4), partials, decay, attack_ms)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    n = int(seconds * SR)
    env = env_exp(n, int(attack_ms * SR / 1000.0), decay)
    out = [0.0] * n
    for h, gain in enumerate(partials, start=1):
        f = freq * h
        if f > 16000.0:
            break
        w = 2.0 * math.pi * f / SR
        sin = math.sin
        for i in range(n):
            out[i] += gain * sin(w * i)
    out = [v * e for v, e in zip(out, env)]
    _cache[key] = out
    return out


def kick(seconds: float = 0.30) -> list[float]:
    """A pitch-swept sine: 130 Hz down to 44 Hz over the first 60 ms."""
    key = ("kick", seconds)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    n = int(seconds * SR)
    out = [0.0] * n
    phase = 0.0
    for i in range(n):
        t = i / SR
        f = 44.0 + 86.0 * math.exp(-t * 26.0)
        phase += 2.0 * math.pi * f / SR
        out[i] = math.sin(phase) * math.exp(-t * 7.0)
    # A click at the very front so it cuts through on a laptop speaker.
    for i in range(min(n, 90)):
        out[i] += 0.5 * math.exp(-i / 24.0) * (1.0 if i % 2 else -1.0)
    _cache[key] = out
    return out


def noise(seconds: float, decay: float, seed: int, hp: float = 0.0) -> list[float]:
    """Deterministic noise under an exponential decay, optionally brightened."""
    key = ("noise", round(seconds, 4), decay, seed, hp)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    n = int(seconds * SR)
    s = seed & 0xFFFFFFFF
    out = [0.0] * n
    prev = 0.0
    for i in range(n):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        v = (s / 0x3FFFFFFF) - 1.0
        if hp:
            v, prev = v - hp * prev, v      # a one-pole difference: brighter
        out[i] = v * math.exp(-decay * i / SR)
    _cache[key] = out
    return out


def riser(seconds: float) -> list[float]:
    """A noise band whose centre climbs, for the four bars before the resolve."""
    n = int(seconds * SR)
    s = 99991
    out = [0.0] * n
    lp = 0.0
    for i in range(n):
        s = (1103515245 * s + 12345) & 0x7FFFFFFF
        v = (s / 0x3FFFFFFF) - 1.0
        t = i / n
        a = 0.02 + 0.42 * t                  # the filter opens as it rises
        lp += a * (v - lp)
        out[i] = lp * (0.12 + 0.88 * t * t)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(pathlib.Path(__file__).with_name("morrow-promo-music.wav")))
    ap.add_argument("--bars", type=int, default=BARS)
    args = ap.parse_args()

    # The five sections are fractions of the length, so a 30-bar cut and a
    # 38-bar cut have the same shape. For 30 bars: cold 0-2, pulse from 3,
    # chords from 7, build from 21, resolve on 24 — which is where the picture
    # cuts to its end card.
    global COLD_END, FULL, BUILD, RESOLVE
    B = args.bars
    COLD_END = max(2, round(B * 0.10))
    FULL = round(B * 0.233)
    BUILD = round(B * 0.70)
    RESOLVE = round(B * 0.80)
    print(f"sections: cold<{COLD_END} pulse>={COLD_END} full>={FULL} "
          f"build>={BUILD} resolve>={RESOLVE} of {B} bars")

    total = int(args.bars * BAR * SR) + int(2.0 * SR)
    left = [0.0] * total
    right = [0.0] * total

    def put(buf, at, gain, pan=0.5):
        i = int(at * SR)
        if i < 0:
            return
        gl, gr = gain * (1.0 - pan) * 2.0, gain * pan * 2.0
        end = min(total, i + len(buf))
        for k in range(end - i):
            v = buf[k]
            left[i + k] += v * gl
            right[i + k] += v * gr

    # ---------------------------------------------------------------- the plan
    for bar in range(args.bars):
        t0 = bar * BAR
        chord = PROGRESSION[bar % len(PROGRESSION)]
        notes = [semis(chord + s) for s in CHORD_SHAPE[chord]]

        cold = bar < COLD_END
        pulse = COLD_END <= bar < RESOLVE
        full = FULL <= bar < RESOLVE
        build = BUILD <= bar < RESOLVE
        resolve = bar >= RESOLVE

        # --- drone, under everything until the resolve --------------------
        if not resolve:
            put(tone(notes[0], BAR + 0.4, (1.0, 0.22, 0.06), 0.9), t0, 0.30 if cold else 0.22, 0.5)
        # --- the downbeat sub, which is all the cold open has --------------
        if cold or resolve:
            put(tone(notes[0] / 2.0, 1.6, (1.0, 0.08), 2.6, 6.0), t0, 0.55, 0.5)

        # --- pulse ---------------------------------------------------------
        if pulse:
            for b in range(4):
                put(kick(), t0 + b * BEAT, 0.62, 0.5)
                put(noise(0.045, 90.0, 7 + b, 0.85), t0 + (b + 0.5) * BEAT, 0.13, 0.42 + 0.16 * (b % 2))
            if bar % 4 == 3:
                for k in range(4):
                    put(noise(0.09, 46.0, 31 + k, 0.7), t0 + BEAT * (3 + k * 0.25), 0.16 + 0.05 * k, 0.5)

        # --- chords ---------------------------------------------------------
        if full or resolve:
            hold = (BAR * 6.0) if resolve and bar == RESOLVE else BAR * 1.05
            for j, f in enumerate(notes[1:], start=1):
                put(tone(f, hold, (1.0, 0.30, 0.14, 0.05), 0.55 if resolve else 1.1),
                    t0, (0.26 if resolve else 0.18) / (1.0 + 0.35 * j),
                    0.5 + 0.30 * math.sin(j * 1.9))

        # --- arpeggio --------------------------------------------------------
        if pulse:
            step = BEAT / (4 if build else 2)
            count = int(BAR / step)
            for k in range(count):
                idx = ARP[k % len(ARP)]
                f = notes[min(idx, len(notes) - 1)] * 2.0
                dur = step * (0.85 if build else 1.6)
                put(tone(f, dur, (1.0, 0.45, 0.22, 0.11, 0.05), 8.0 if build else 5.0, 1.0),
                    t0 + k * step, 0.13 if build else 0.10,
                    0.5 + 0.34 * math.sin(k * 0.8))

        # --- the build's rising sweep ----------------------------------------
        if bar == RESOLVE - 4:
            put(riser(BAR * 4.0), t0, 0.34, 0.5)
        if bar == RESOLVE:
            # The hit the build resolves onto.
            put(noise(1.6, 3.2, 4242, 0.4), t0, 0.30, 0.5)
            put(kick(0.6), t0, 0.95, 0.5)

    # ------------------------------------------------------------- finishing
    fi, fo = int(FADE_IN * SR), int(FADE_OUT * SR)
    for i in range(min(fi, total)):
        g = i / fi
        left[i] *= g
        right[i] *= g
    for k in range(min(fo, total)):
        i = total - 1 - k
        g = 0.5 - 0.5 * math.cos(math.pi * k / fo)
        left[i] *= g
        right[i] *= g

    # A soft knee rather than a hard clip, then normalise to PEAK_DBFS.
    def soft(v):
        return math.tanh(v * 0.72) / 0.72

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
    print(f"wrote {args.out}: {total / SR:.2f}s, {BPM:.0f} BPM, beat {BEAT:.3f}s, "
          f"{args.bars} bars, peak {PEAK_DBFS} dBFS")


if __name__ == "__main__":
    main()
