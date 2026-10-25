"""Assemble the Morrow tour from the rendered segments.

render-tour.js writes one silent 60 fps segment per shot plus tour.json. Every
transition is already inside the segments — the outgoing frame is wiped away
over the live incoming picture by the overlay — so this is a plain concat with
no xfade, which means the delivered frame count is exactly the sum of the
segments and nothing is resampled twice.

What this adds: the music, a fade from and to black, and the .srt. The words
are burned in by the overlay during the render, so no subtitle filter runs
here; the .srt carries the same words with the same timings for a vendor who
wants to re-voice or re-cut.

    backend\\.venv\\Scripts\\python.exe demo\\video\\assemble-tour.py \\
        --work %TEMP%\\airlock-tour

Nothing here touches port 8001, backend/morrow.db or backend/.env.
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

# The section a caption opens, keyed by its first line.
SECTIONS = {
    "Everything here is a live build reading a seeded database.": "Opening",
    "Traffic your organisation encrypts today": "1. The problem in plain words",
    "Morrow scans TLS endpoints and records": "2. Discovery",
    "It is what an adversary could store today": "3. Exposure",
    "The cryptographic bill of materials is generated": "4. Evidence",
    "Every fix moves through suggested, approved,": "5. Action",
    "For the board, one number — with its working.": "6. Governance",
    "One: tenant isolation is enforced in the database,": "7. For the buyer's security team",
    "Six to eight weeks. One organisation.": "8. Close",
}


def run(args, cwd=None):
    subprocess.run([str(a) for a in args], check=True, cwd=None if cwd is None else str(cwd))


def probe_frames(path: pathlib.Path) -> int:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-select_streams", "v:0", "-count_frames",
         "-show_entries", "stream=nb_read_frames", "-of", "default=nk=1:nw=1", str(path)],
        check=True, capture_output=True, text=True).stdout.strip().splitlines()
    return int(out[-1])


def ts_srt(t: float) -> str:
    ms = max(0, round(t * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def clock(t: float) -> str:
    return f"{int(t) // 60}:{int(t) % 60:02d}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", default=str(HERE / "morrow-tour.mp4"))
    ap.add_argument("--srt", default=str(HERE / "morrow-tour.srt"))
    ap.add_argument("--script", default=str(HERE / "morrow-tour-script.md"))
    ap.add_argument("--music", default=str(HERE / "morrow-walkthrough-music.wav"))
    ap.add_argument("--crf", type=int, default=18)
    # x264 preset for the delivered file. "slow" is the default; "fast" with a
    # point lower crf is visually the same on screen content and about six
    # times cheaper, which matters when the machine is busy.
    ap.add_argument("--preset", default="slow")
    args = ap.parse_args()

    work = pathlib.Path(args.work).resolve()
    seg_dir = work / "seg"
    build = work / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)

    manifest = json.loads((work / "tour.json").read_text(encoding="utf-8"))
    shots = manifest["shots"]

    parts, cues = [], []
    t = 0.0
    missing = []
    for i, shot in enumerate(shots):
        seg = seg_dir / f"{i:03d}.mp4"
        if not seg.exists():
            missing.append(i)
            continue
        n = probe_frames(seg)
        if n != shot["frames"]:
            print(f"  ! segment {i:03d} has {n} frames, manifest says {shot['frames']}")
        parts.append(seg)
        # The narration comes up a beat after the cut and leaves a beat before
        # the next one; the .srt says the same.
        if shot["cap"]:
            cues.append([t + 0.70, t + n / FPS - 0.25, shot["cap"]])
        t += n / FPS
    if missing:
        print(f"missing segments: {missing}", file=sys.stderr)
        return 1

    total = t
    print(f"{len(parts)} segments, {len(cues)} captions, {total:.2f}s "
          f"({int(round(total * FPS))} frames)")
    worst = max(cues, key=lambda c: len(" ".join(c[2])) / (c[1] - c[0]))
    print(f"fastest caption: {len(' '.join(worst[2])) / (worst[1] - worst[0]):.1f} characters a second")

    pathlib.Path(args.srt).write_text("\n".join(
        f"{n + 1}\n{ts_srt(a)} --> {ts_srt(b)}\n" + "\n".join(lines) + "\n"
        for n, (a, b, lines) in enumerate(cues)), encoding="utf-8")

    md = [
        "# Morrow tour — narration script", "",
        "The words burned into `morrow-tour.mp4`, in order. Timings are",
        "for the delivered cut. There is no voice-over in the delivered file;",
        "these are the words to read if you want one.", "",
        "Generated by `assemble-tour.py` from the cut it builds, so it cannot",
        "drift from the picture.", "",
    ]
    seen = False
    for a, b, cap in cues:
        section = SECTIONS.get(cap[0])
        if section:
            md += (["", f"## {section}", ""] if seen else [f"## {section}", ""])
            seen = True
        md.append(f"**{clock(a)}**  " + " ".join(cap))
        md.append("")
    pathlib.Path(args.script).write_text("\n".join(md).rstrip() + "\n", encoding="utf-8")

    listing = build / "parts.txt"
    listing.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")

    fade_out = max(1.0, total - 6.0)
    vfilter = f"fade=t=in:st=0:d=1.2,fade=t=out:st={fade_out:.3f}:d=6.0"
    afilter = (f"loudnorm=I=-29:TP=-9:LRA=9,volume=-3.0dB,"
               f"afade=t=in:st=0:d=5,afade=t=out:st={fade_out:.3f}:d=6")

    out = pathlib.Path(args.out)
    run([FFMPEG, "-y", "-nostdin", "-v", "error", "-stats",
         "-f", "concat", "-safe", "0", "-i", listing,
         "-stream_loop", "-1", "-i", args.music,
         "-t", f"{total:.4f}",
         "-filter_complex", f"[0:v]{vfilter}[v];[1:a]{afilter}[a]",
         "-map", "[v]", "-map", "[a]",
         "-c:v", "libx264", "-preset", args.preset, "-crf", args.crf,
         "-profile:v", "high", "-level", "4.2", "-pix_fmt", "yuv420p",
         "-r", FPS, "-g", "120",
         "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
         "-c:a", "aac", "-b:a", "160k", "-ar", "44100", "-ac", "2",
         "-movflags", "+faststart", out.resolve()], cwd=build)

    run([FFPROBE, "-v", "error", "-show_entries",
         "stream=codec_type,codec_name,profile,width,height,r_frame_rate,nb_frames",
         "-show_entries", "format=duration,size", "-of", "default=nw=1", out])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
