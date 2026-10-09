"""Assemble the Airlock Command sixty-second film, and its 30 fps fallback.

render-60s.js writes one silent 60 fps segment per shot plus film.json. Every
transition is already inside the segments, so this is a plain concat: the
delivered frame count is exactly the sum of the segments and nothing is
resampled twice.

The delivery profile is deliberate, and it is the fix for the "keeps freezing"
report on the earlier promo — which was never duplicate frames (mpdecimate kept
4 503 of 4 560) but a file weak decoders struggled with:

  * **yuv420p, limited range.** The capture path is JPEG, which is full range,
    so the segments convert to `tv` range on the way in and the delivered file
    is tagged `bt709` / `tv` rather than the `yuvj420p` the earlier cut carried.
    A player that assumes limited range no longer has to guess.
  * **High@4.1, not 4.2.** 1080p60 at level 4.2 stutters in Windows' built-in
    player; 4.1 is inside what every hardware decoder of the last decade
    advertises.
  * **A closed GOP every two seconds**, with scene-cut insertion off, so seeking
    and mid-stream decoder resets land on a keyframe.
  * **A bitrate ceiling** (`-maxrate` / `-bufsize`) so a burst on a hard cut
    cannot spike past what a weak decoder can pull.
  * **`+faststart`**, so the moov atom is at the front and the file plays before
    it has finished downloading.

The 30 fps fallback is the same picture decimated, at level 4.0, for machines
that cannot sustain 60.

    backend\\.venv\\Scripts\\python.exe demo\\video\\assemble-60s.py \\
        --work %TEMP%\\airlock-60s
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
        [str(FFPROBE), "-v", "error", "-select_streams", "v:0",
         "-show_entries", "stream=nb_frames", "-of", "default=nk=1:nw=1", str(path)],
        check=True, capture_output=True, text=True).stdout.strip().splitlines()
    return int(out[-1]) if out and out[-1].isdigit() else -1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", default=str(HERE / "airlock-command-60s.mp4"))
    ap.add_argument("--out30", default=str(HERE / "airlock-command-60s-30fps.mp4"))
    ap.add_argument("--music", default=str(HERE / "airlock-command-60s-music.wav"))
    ap.add_argument("--crf", type=int, default=18)
    ap.add_argument("--preset", default="slow")
    args = ap.parse_args()

    work = pathlib.Path(args.work).resolve()
    build = work / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)

    manifest = json.loads((work / "film.json").read_text(encoding="utf-8"))
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
          f"{t:.3f}s ({int(round(t * FPS))} frames)")

    listing = build / "parts.txt"
    listing.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")

    fade_out = max(0.5, t - 2.0)
    # A grade rather than a filter: a point of contrast and a little saturation,
    # so the cut reads as one piece. The vignette is drawn in the browser (see
    # tour-overlay.js) so it moves with the camera instead of sitting on the glass.
    vfilter = (f"eq=contrast=1.035:saturation=1.06,"
               f"fade=t=in:st=0:d=0.45,fade=t=out:st={fade_out:.3f}:d=2.0")
    # Loudness up from the tour's bed, with the true peak held at -14 dBFS by a
    # limiter rather than by pulling the whole track down.
    afilter = (f"loudnorm=I=-20:TP=-2:LRA=11,"
               f"alimiter=limit=0.1995:attack=4:release=60:level=disabled,"
               f"afade=t=in:st=0:d=0.25,afade=t=out:st={fade_out:.3f}:d=2.0")

    VIDEO = [
        "-c:v", "libx264", "-preset", args.preset, "-crf", str(args.crf),
        "-profile:v", "high", "-level", "4.1", "-pix_fmt", "yuv420p",
        "-maxrate", "16M", "-bufsize", "32M",
        "-g", "120", "-keyint_min", "120", "-sc_threshold", "0", "-flags", "+cgop",
        "-x264-params", "scenecut=0:open-gop=0",
        "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
        "-color_range", "tv",
    ]
    AUDIO = ["-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-ac", "2"]

    out = pathlib.Path(args.out)
    run([FFMPEG, "-y", "-nostdin", "-v", "error", "-stats",
         "-f", "concat", "-safe", "0", "-i", listing,
         "-i", args.music,
         "-t", f"{t:.4f}",
         "-filter_complex", f"[0:v]{vfilter}[v];[1:a]{afilter}[a]",
         "-map", "[v]", "-map", "[a]",
         *VIDEO, "-r", str(FPS), *AUDIO,
         "-movflags", "+faststart", out.resolve()], cwd=build)

    # The fallback: the same master, decimated. Level 4.0 is ample at 1080p30.
    out30 = pathlib.Path(args.out30)
    run([FFMPEG, "-y", "-nostdin", "-v", "error", "-stats", "-i", out.resolve(),
         "-vf", "fps=30",
         "-c:v", "libx264", "-preset", args.preset, "-crf", str(args.crf),
         "-profile:v", "high", "-level", "4.0", "-pix_fmt", "yuv420p",
         "-maxrate", "10M", "-bufsize", "20M",
         "-g", "60", "-keyint_min", "60", "-sc_threshold", "0", "-flags", "+cgop",
         "-x264-params", "scenecut=0:open-gop=0",
         "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
         "-color_range", "tv", "-r", "30",
         "-c:a", "copy", "-movflags", "+faststart", out30.resolve()], cwd=build)

    for f in (out, out30):
        print(f"\n{f.name}")
        run([FFPROBE, "-v", "error", "-show_entries",
             "stream=codec_type,codec_name,profile,level,width,height,pix_fmt,"
             "color_range,color_space,r_frame_rate,nb_frames",
             "-show_entries", "format=duration,size", "-of", "default=nw=1", f])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
