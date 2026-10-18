"""Generate the ambient music bed for the walkthrough video.

Standard library only (`wave`, `math`, `array`) — numpy is not installed here.

The sound: a slow pad. Every chord tone is three slightly detuned voices,
each summed from its first three harmonics, which is a lowpass by
construction rather than by filtering. Chords cross-fade into one another
under a Hann window with a half-bar hop, so the sum of the windows is
constant and there is never a dip or a seam. The progression resolves back
to the tonic and the bed loops cleanly at LOOP_SECONDS. There is no
percussion. The result is normalised to a peak of about -20 dBFS, with a
fade in and a fade out.

    backend/.venv/Scripts/python.exe demo/video/make-music.py --seconds 660

To change the mood: edit PROGRESSION (semitones above ROOT_HZ), ROOT_HZ, or
BAR_SECONDS. A shorter PARTIAL_GAINS tail is darker; a longer one brighter.

Speed note: pure Python cannot afford one sine call per sample per voice for
eleven minutes of stereo audio. Every voice frequency is therefore snapped to
the grid SR/BLOCK, which makes each voice — and so their sum — exactly
periodic over BLOCK samples. Each chord is synthesised once over that block
and tiled, which takes the run time from hours to about a minute. The grid is
1/BLOCK_SECONDS Hz, fine enough that the detuning survives it. The bed is
synthesised for one LOOP_SECONDS pass and tiled, which also keeps memory in
hundreds of megabytes rather than gigabytes.
"""
from __future__ import annotations

import argparse
import array
import math
import pathlib
import wave
from operator import add, mul

SR = 44100
ROOT_HZ = 110.0           # A2
BAR_SECONDS = 16.0        # one chord per bar; long enough to feel still
BLOCK_SECONDS = 4.0       # periodicity block -> 0.25 Hz frequency grid
PEAK_DBFS = -20.0
FADE_IN = 6.0
FADE_OUT = 9.0

# Am -> Am(add9) -> F -> F6 -> C/E -> G -> Am -> Am open fifth (home).
PROGRESSION = [
    [0, 3, 7, 12],
    [0, 3, 7, 14],
    [-4, 0, 5, 12],
    [-4, 0, 5, 9],
    [-9, 3, 7, 12],
    [-2, 2, 7, 14],
    [0, 3, 7, 12],
    [0, 7, 12, 19],
]
LOOP_SECONDS = len(PROGRESSION) * BAR_SECONDS

PARTIAL_GAINS = [1.0, 0.34, 0.12]          # first three harmonics only
DETUNE_CENTS = [-6.5, 0.0, 7.0]            # three voices per note


def semitone(n: float) -> float:
    return ROOT_HZ * (2.0 ** (n / 12.0))


def chord_voices(chord, block):
    """(frequency, left gain, right gain) for every voice in one chord.

    Frequencies are snapped to the SR/block grid so the chord is periodic
    over `block` samples.
    """
    grid = SR / block
    out = []
    for i, note in enumerate(chord):
        base = semitone(note)
        voice_gain = 1.0 / (1.0 + 0.55 * i)          # upper notes sit back
        for det in DETUNE_CENTS:
            f0 = base * (2.0 ** (det / 1200.0))
            for h, hg in enumerate(PARTIAL_GAINS, start=1):
                f = f0 * h
                if f > 5200.0:
                    break
                f = round(f / grid) * grid           # snap to the grid
                g = voice_gain * hg / len(DETUNE_CENTS)
                vi = len(out)
                pan = 0.5 + 0.42 * math.sin(vi * 1.7)
                out.append((f, g * (1.0 - pan) * 2.0, g * pan * 2.0))
    return out


def chord_block(chord, block):
    """One chord summed over a single period, as (left, right) lists."""
    left = [0.0] * block
    right = [0.0] * block
    two_pi = 2.0 * math.pi
    sin = math.sin
    for vi, (f, gl, gr) in enumerate(chord_voices(chord, block)):
        w = two_pi * f / SR
        phase = (vi * 0.61803398875) % 1.0 * two_pi
        tone = [sin(w * i + phase) for i in range(block)]
        left = list(map(add, left, [s * gl for s in tone]))
        right = list(map(add, right, [s * gr for s in tone]))
    return left, right


def tile(src, n):
    return (src * (-(-n // len(src))))[:n]


def render_loop():
    """One seamless LOOP_SECONDS pass of the bed, as int16 stereo frames.

    Windows are overlap-added circularly, so the end runs into the start with
    no discontinuity: the file can be looped or cut anywhere.
    """
    bar = int(BAR_SECONDS * SR)
    block = int(BLOCK_SECONDS * SR)
    loop = bar * len(PROGRESSION)
    win = bar * 2

    hann = [0.5 - 0.5 * math.cos(2.0 * math.pi * i / win) for i in range(win)]

    left = [0.0] * loop
    right = [0.0] * loop
    for b, chord in enumerate(PROGRESSION):
        bl, br = chord_block(chord, block)
        wl = list(map(mul, tile(bl, win), hann))
        wr = list(map(mul, tile(br, win), hann))
        base = b * bar - bar // 2
        for i in range(win):                      # circular overlap-add
            t = (base + i) % loop
            left[t] += wl[i]
            right[t] += wr[i]

    # A very slow breath, exactly one cycle per loop, so it stays seamless.
    breath = [0.88 + 0.12 * math.sin(2.0 * math.pi * i / loop) for i in range(loop)]
    left = list(map(mul, left, breath))
    right = list(map(mul, right, breath))

    peak = max(1e-9, max(max(map(abs, left)), max(map(abs, right))))
    gain = (10.0 ** (PEAK_DBFS / 20.0)) / peak * 32767.0

    frames = array.array("h", bytes(loop * 4))
    for t in range(loop):
        li = int(left[t] * gain)
        ri = int(right[t] * gain)
        frames[2 * t] = -32767 if li < -32767 else (32767 if li > 32767 else li)
        frames[2 * t + 1] = -32767 if ri < -32767 else (32767 if ri > 32767 else ri)
    return frames


def render(seconds: float):
    """The loop, repeated to length, with a fade in and a fade out."""
    total = int(seconds * SR)
    frames = render_loop()
    out = array.array("h", tile(frames, total * 2))

    fi, fo = int(FADE_IN * SR), int(FADE_OUT * SR)
    for t in range(min(fi, total)):
        f = 0.5 - 0.5 * math.cos(math.pi * t / fi)
        out[2 * t] = int(out[2 * t] * f)
        out[2 * t + 1] = int(out[2 * t + 1] * f)
    for k in range(min(fo, total)):
        t = total - 1 - k
        f = 0.5 - 0.5 * math.cos(math.pi * k / fo)
        out[2 * t] = int(out[2 * t] * f)
        out[2 * t + 1] = int(out[2 * t + 1] * f)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=660.0)
    ap.add_argument("--out", default=str(pathlib.Path(__file__).with_name(
        "morrow-walkthrough-music.wav")))
    args = ap.parse_args()

    samples = render(args.seconds)
    with wave.open(args.out, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(samples.tobytes())
    print(f"wrote {args.out}: {args.seconds:.1f}s, peak {PEAK_DBFS} dBFS, "
          f"loops every {LOOP_SECONDS:.0f}s")


if __name__ == "__main__":
    main()
