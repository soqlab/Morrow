"""Rewrite the walkthrough .srt to match the delivered cut.

The recorder writes cue times against the start of the raw Playwright capture,
in real wall-clock seconds. build-walkthrough.ps1 trims the console's first
load off the head and rescales the picture to a fixed delivered length, so the
subtitle file has to be shifted and scaled the same way.

    backend/.venv/Scripts/python.exe demo/video/shift-srt.py <trim> <playback> <end> [cutStart cutEnd]

    trim      seconds dropped from the head (build's -TrimStart)
    playback  how much faster the cut plays than the live session
    end       delivered length; cues are clipped to it
    cutStart, cutEnd   an optional removed region, in delivered seconds
                       (build's -CutStart / -CutEnd). Cues inside it are
                       dropped and later cues move up by its length.

Defaults match build-walkthrough.ps1's own defaults.
"""
from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRT = HERE / "airlock-command-walkthrough.srt"
TIMINGS = HERE / "walkthrough-timings.json"


def stamp(seconds: float) -> str:
    ms = max(0, round(seconds * 1000))
    return (f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:"
            f"{ms // 1000 % 60:02d},{ms % 1000:03d}")


def main() -> None:
    argv = sys.argv[1:]
    trim = float(argv[0]) if len(argv) > 0 else 8.0
    playback = float(argv[1]) if len(argv) > 1 else 1.0
    end = float(argv[2]) if len(argv) > 2 else None
    cut0 = float(argv[3]) if len(argv) > 3 else 0.0
    cut1 = float(argv[4]) if len(argv) > 4 else 0.0
    gap = max(0.0, cut1 - cut0)
    data = json.loads(TIMINGS.read_text(encoding="utf-8"))

    out, n = [], 0
    for cue in data["cues"]:
        t0 = (cue["t0"] - trim) / playback
        t1 = (cue["t1"] - trim) / playback
        if gap:
            if cut0 - 0.05 <= (t0 + t1) / 2 <= cut1 + 0.05:
                continue                      # this cue's beat was cut
            if t0 >= cut1:
                t0 -= gap
                t1 -= gap
        if end is not None:
            t1 = min(t1, end)
        if t1 <= 0.05:
            continue
        n += 1
        out.append(f"{n}\n{stamp(max(0.0, t0))} --> {stamp(max(0.15, t1 - 0.12))}\n"
                   + "\n".join(cue["lines"]) + "\n")

    SRT.write_text("\n".join(out), encoding="utf-8")
    print(f"wrote {SRT}: {n} cues, head -{trim:.2f}s, playback {playback:.4f}x"
          + (f", cut {cut0:.1f}-{cut1:.1f}s" if gap else ""))


if __name__ == "__main__":
    main()
