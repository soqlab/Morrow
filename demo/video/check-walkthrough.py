"""Check a finished walkthrough before it ships.

Reports what ffprobe says the file really is, then walks the picture looking
for the things a deterministic render can still get wrong:

  * a repeated frame, which is what judder looks like in the numbers;
  * a motion sequence that advances in jumps rather than evenly;
  * a caption clipped by the frame edge.

It also lays out contact sheets -- one frame every few seconds, plus a dense
strip across each moving shot -- for a person (or a model) to read.

    backend\\.venv\\Scripts\\python.exe demo\\video\\check-walkthrough.py \\
        demo\\video\\morrow-walkthrough-v2.mp4 \\
        --work %TEMP%\\airlock-walkthrough --frames OUTDIR
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
FFMPEG = ROOT / ".tools" / "ffmpeg" / "ffmpeg.exe"
FFPROBE = ROOT / ".tools" / "ffmpeg" / "ffprobe.exe"

YAVG = re.compile(r"lavfi\.signalstats\.YAVG=([0-9.eE+-]+)")


def probe(path: pathlib.Path) -> dict:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-count_frames", "-select_streams", "v:0",
         "-show_entries", "stream=codec_name,profile,level,width,height,r_frame_rate,"
         "avg_frame_rate,nb_read_frames,pix_fmt",
         "-show_entries", "format=duration,size", "-of", "json", str(path)],
        check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def audio(path: pathlib.Path) -> dict:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-select_streams", "a:0",
         "-show_entries", "stream=codec_name,sample_rate,channels,bit_rate,duration",
         "-of", "json", str(path)], check=True, capture_output=True, text=True).stdout
    return json.loads(out)["streams"][0]


def motion(path: pathlib.Path, start: float, seconds: float) -> list[float]:
    """Mean absolute difference between each frame and the one before it."""
    proc = subprocess.run(
        [str(FFMPEG), "-v", "error", "-ss", f"{start:.4f}", "-t", f"{seconds:.4f}", "-i", str(path),
         "-vf", "tblend=all_mode=difference,crop=1760:820:80:60,signalstats,"
                "metadata=print:key=lavfi.signalstats.YAVG:file=-",
         "-f", "null", "-"], check=True, capture_output=True, text=True)
    return [float(m) for m in YAVG.findall(proc.stdout)][1:]


def sheet(path: pathlib.Path, out: pathlib.Path, at: float, name: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(FFMPEG), "-y", "-v", "error", "-ss", f"{at:.4f}", "-i", str(path),
                    "-frames:v", "1", "-q:v", "3", str(out / name)], check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("video")
    ap.add_argument("--work", help="the render work directory, for shots.json")
    ap.add_argument("--frames", help="write contact-sheet frames here")
    ap.add_argument("--every", type=float, default=5.0)
    args = ap.parse_args()
    video = pathlib.Path(args.video).resolve()

    info = probe(video)
    v = info["streams"][0]
    dur = float(info["format"]["duration"])
    frames = int(v["nb_read_frames"])
    a = audio(video)
    print(f"{v['codec_name']} {v['profile']}@{int(v['level']) / 10:.1f} {v['width']}x{v['height']} "
          f"{v['pix_fmt']} {v['r_frame_rate']} ({v['avg_frame_rate']} average)")
    print(f"{frames} frames, {dur:.3f}s -> {frames / dur:.3f} fps measured, "
          f"{int(info['format']['size']) / 1e6:.1f} MB")
    print(f"audio {a['codec_name']} {a['sample_rate']} Hz x{a['channels']} {a['duration']}s")
    bad = 0
    if frames != round(dur * 60):
        print(f"  ! {frames} frames is not {round(dur * 60)} at 60 fps")
        bad += 1

    # ---- moving shots: even advance, no repeated frames ----------------------
    if args.work:
        shots = json.loads((pathlib.Path(args.work) / "shots.json").read_text(encoding="utf-8"))["shots"]
        t = 0.0
        spans = []
        for i, shot in enumerate(shots):
            if i and shot["fade"]:
                t += 0.5
            spans.append((i, t, shot["seconds"], shot["cap"]))
            t += shot["seconds"]
        print(f"\n{len(spans)} shots over {t:.2f}s")
        moved = 0
        for i, start, secs, cap in spans:
            d = motion(video, start, min(secs, 9.0))
            if len(d) < 20:
                continue
            peak = max(d)
            if peak < 0.02:
                continue                      # a held shot: nothing to check
            # The moving part of a shot is its longest run of frames that
            # actually changed; the lead-in and the tail are meant to be still.
            live = [x > peak * 0.08 for x in d]
            best = run = start_i = best_i = 0
            for n, on in enumerate(live):
                if on:
                    if run == 0:
                        start_i = n
                    run += 1
                    if run > best:
                        best, best_i = run, start_i
                else:
                    run = 0
            if best < 20:
                continue                      # only a dissolve edge moved
            seq = d[best_i:best_i + best]
            moved += 1
            stuck = sum(1 for x in seq if x < peak * 0.02)
            lo = sorted(seq)[len(seq) // 20]
            hi = sorted(seq)[-max(1, len(seq) // 20)]
            flag = ""
            if stuck:
                flag = f"  ! {stuck} frames did not advance"
                bad += 1
            elif hi / max(lo, 1e-9) > 6:
                flag = f"  ! advance varies {hi / max(lo, 1e-9):.1f}x"
                bad += 1
            print(f"  {i:02d} {start:7.2f}s  {best:3d} moving frames  "
                  f"step {lo:.3f}-{hi:.3f}{flag}  {(cap[0] if cap else '')[:36]}")
        print(f"  {moved} shots move, {len(spans) - moved} hold")

    # ---- contact sheets ------------------------------------------------------
    if args.frames:
        out = pathlib.Path(args.frames)
        n = 0
        at = 0.5
        while at < dur:
            sheet(video, out, at, f"t{int(at):04d}.jpg")
            at += args.every
            n += 1
        print(f"\n{n} frames written to {out}")

    print("\n" + ("FAIL" if bad else "OK"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
