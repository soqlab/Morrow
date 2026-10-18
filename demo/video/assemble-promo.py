"""Assemble the Morrow promo from the rendered segments.

render-promo.js cuts on the beat of morrow-promo-music.wav — every
shot is a whole number of 0.5 s beats at 120 BPM — so this is a plain concat
against the track from its first sample. Nothing is stretched to fit.

    backend\\.venv\\Scripts\\python.exe demo\\video\\assemble-promo.py \\
        --work %TEMP%\\airlock-promo
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FFMPEG = ROOT / ".tools" / "ffmpeg" / "ffmpeg.exe"
FFPROBE = ROOT / ".tools" / "ffmpeg" / "ffprobe.exe"
HERE = pathlib.Path(__file__).resolve().parent
FPS = 60


def run(args, cwd=None):
    subprocess.run([str(a) for a in args], check=True, cwd=None if cwd is None else str(cwd))


def probe_frames(path: pathlib.Path) -> int:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-select_streams", "v:0", "-count_frames",
         "-show_entries", "stream=nb_read_frames", "-of", "default=nk=1:nw=1", str(path)],
        check=True, capture_output=True, text=True).stdout.strip().splitlines()
    return int(out[-1])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", default=str(HERE / "morrow-promo.mp4"))
    ap.add_argument("--music", default=str(HERE / "morrow-promo-music.wav"))
    ap.add_argument("--crf", type=int, default=17)
    ap.add_argument("--preset", default="slow")
    args = ap.parse_args()

    work = pathlib.Path(args.work).resolve()
    build = work / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)

    manifest = json.loads((work / "promo.json").read_text(encoding="utf-8"))
    shots = manifest["shots"]

    parts, t, missing = [], 0.0, []
    for i, shot in enumerate(shots):
        seg = work / "seg" / f"{i:03d}.mp4"
        if not seg.exists():
            missing.append(i)
            continue
        n = probe_frames(seg)
        if n != shot["frames"]:
            print(f"  ! segment {i:03d} has {n} frames, manifest says {shot['frames']}")
        parts.append(seg)
        t += n / FPS
    if missing:
        print(f"missing segments: {missing}", file=sys.stderr)
        return 1

    beats = sum(s["beats"] for s in shots)
    print(f"{len(parts)} shots, {beats} beats at {manifest['bpm']} BPM, "
          f"{t:.2f}s ({int(round(t * FPS))} frames)")

    listing = build / "parts.txt"
    listing.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")

    fade_out = max(1.0, t - 4.0)
    vfilter = f"fade=t=in:st=0:d=0.5,fade=t=out:st={fade_out:.3f}:d=4.0"
    # The promo is meant to be heard: louder than the tour bed, and peak-limited
    # rather than pulled down, since nothing has to sit under a caption.
    afilter = (f"loudnorm=I=-16:TP=-1.5:LRA=11,"
               f"afade=t=in:st=0:d=0.3,afade=t=out:st={fade_out:.3f}:d=4.0")

    out = pathlib.Path(args.out)
    run([FFMPEG, "-y", "-nostdin", "-v", "error", "-stats",
         "-f", "concat", "-safe", "0", "-i", listing,
         "-i", args.music,
         "-t", f"{t:.4f}",
         "-filter_complex", f"[0:v]{vfilter}[v];[1:a]{afilter}[a]",
         "-map", "[v]", "-map", "[a]",
         "-c:v", "libx264", "-preset", args.preset, "-crf", args.crf,
         "-profile:v", "high", "-level", "4.2", "-pix_fmt", "yuv420p",
         "-r", FPS, "-g", "120",
         "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
         "-c:a", "aac", "-b:a", "192k", "-ar", "44100", "-ac", "2",
         "-movflags", "+faststart", out.resolve()], cwd=build)

    run([FFPROBE, "-v", "error", "-show_entries",
         "stream=codec_type,codec_name,profile,width,height,r_frame_rate,nb_frames",
         "-show_entries", "format=duration,size", "-of", "default=nw=1", out])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
