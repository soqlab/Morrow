"""Read a finished Airlock Command film back before it ships.

Three things, in order:

  1. what ffprobe says the file really is — codec, profile, resolution, frame
     rate, counted frames, audio;
  2. **per-frame difference sampling**: at every sample point a run of
     consecutive frames is decoded and each pair compared tile by tile over a
     6x4 grid. A frame that did not advance shows up as a pair whose every
     tile is zero. Because the product's own animation is what should be
     moving, the report names how many tiles changed, not just whether
     anything did: a camera move alone lights every tile, whereas a held shot
     with the product animating lights the few tiles the fabric, the ops
     panels and the CSS sweeps occupy.
  3. a contact sheet, one frame every N seconds, for a person to read.

    backend\\.venv\\Scripts\\python.exe demo\\video\\check-video.py \\
        demo\\video\\airlock-command-tour.mp4 --frames OUTDIR --every 5

Standard library plus Pillow. numpy is not installed here.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile

from PIL import Image, ImageChops, ImageStat

ROOT = pathlib.Path(__file__).resolve().parents[2]
FFMPEG = ROOT / ".tools" / "ffmpeg" / "ffmpeg.exe"
FFPROBE = ROOT / ".tools" / "ffmpeg" / "ffprobe.exe"

COLS, ROWS = 6, 4          # the tile grid the difference is reported over
TILE_ON = 0.35             # mean absolute difference, 0-255, that counts as motion


def probe(path: pathlib.Path) -> dict:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-count_frames", "-select_streams", "v:0",
         "-show_entries", "stream=codec_name,profile,level,width,height,r_frame_rate,"
         "avg_frame_rate,nb_read_frames,pix_fmt",
         "-show_entries", "format=duration,size,bit_rate", "-of", "json", str(path)],
        check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def audio(path: pathlib.Path) -> dict | None:
    out = subprocess.run(
        [str(FFPROBE), "-v", "error", "-select_streams", "a:0",
         "-show_entries", "stream=codec_name,sample_rate,channels,bit_rate,duration",
         "-of", "json", str(path)], check=True, capture_output=True, text=True).stdout
    st = json.loads(out).get("streams") or []
    return st[0] if st else None


def grab(video: pathlib.Path, at: float, count: int, out: pathlib.Path) -> list[pathlib.Path]:
    """`count` consecutive frames starting at `at`, decoded once."""
    for f in out.glob("g*.png"):
        f.unlink()
    subprocess.run([str(FFMPEG), "-v", "error", "-ss", f"{at:.4f}", "-i", str(video),
                    "-frames:v", str(count), "-vsync", "0",
                    str(out / "g%03d.png")], check=True)
    return sorted(out.glob("g*.png"))


def tile_diff(a: Image.Image, b: Image.Image) -> list[float]:
    d = ImageChops.difference(a, b)
    w, h = d.size
    out = []
    for r in range(ROWS):
        for c in range(COLS):
            box = (c * w // COLS, r * h // ROWS, (c + 1) * w // COLS, (r + 1) * h // ROWS)
            out.append(ImageStat.Stat(d.crop(box)).mean[0])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("video")
    ap.add_argument("--frames", help="write contact-sheet frames here")
    ap.add_argument("--every", type=float, default=5.0, help="contact sheet interval")
    ap.add_argument("--motion-every", type=float, default=5.0, help="motion sample interval")
    ap.add_argument("--run", type=int, default=8, help="consecutive frames per motion sample")
    ap.add_argument("--expect-fps", type=float, default=60.0)
    args = ap.parse_args()
    video = pathlib.Path(args.video).resolve()

    info = probe(video)
    v = info["streams"][0]
    dur = float(info["format"]["duration"])
    frames = int(v["nb_read_frames"])
    a = audio(video)
    bad = 0

    print(f"{video.name}")
    print(f"  {v['codec_name']} {v['profile']}@{int(v['level']) / 10:.1f} "
          f"{v['width']}x{v['height']} {v['pix_fmt']} {v['r_frame_rate']} "
          f"({v['avg_frame_rate']} average)")
    print(f"  {frames} frames, {dur:.3f}s -> {frames / dur:.4f} fps measured, "
          f"{int(info['format']['size']) / 1e6:.1f} MB")
    if a:
        print(f"  audio {a['codec_name']} {a['sample_rate']} Hz x{a['channels']} "
              f"{float(a.get('duration') or 0):.2f}s")
    else:
        print("  ! no audio stream")
        bad += 1
    if (v["width"], v["height"]) != (1920, 1080):
        print("  ! not 1920x1080")
        bad += 1
    if abs(frames / dur - args.expect_fps) > 0.01:
        print(f"  ! measured {frames / dur:.4f} fps, expected {args.expect_fps}")
        bad += 1
    if frames != round(dur * args.expect_fps):
        print(f"  ! {frames} frames is not {round(dur * args.expect_fps)}")
        bad += 1

    # ---------------------------------------------------- per-frame difference
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="airlock-check-"))
    print(f"\nper-frame difference, {args.run} consecutive frames every "
          f"{args.motion_every:.0f}s (tiles {COLS}x{ROWS}, on at {TILE_ON})")
    at = 1.0
    stalls, samples, tile_hist = [], 0, []
    while at < dur - 1.0:
        files = grab(video, at, args.run, tmp)
        imgs = [Image.open(f).convert("L") for f in files]
        pairs = []
        for i in range(1, len(imgs)):
            t = tile_diff(imgs[i - 1], imgs[i])
            pairs.append((sum(1 for x in t if x > TILE_ON), max(t), sum(t) / len(t)))
        if pairs:
            samples += 1
            dead = [i for i, (on, mx, _) in enumerate(pairs) if mx < 0.02]
            live = min(on for on, _, _ in pairs)
            tile_hist.append(live)
            flag = ""
            if dead:
                flag = f"   ! {len(dead)} frame pair(s) identical"
                stalls.append(at)
                bad += 1
            print(f"  {int(at) // 60}:{int(at) % 60:02d}  tiles moving "
                  f"{live}-{max(on for on, _, _ in pairs)}/{COLS * ROWS}  "
                  f"peak {max(mx for _, mx, _ in pairs):6.2f}  "
                  f"mean {sum(m for _, _, m in pairs) / len(pairs):5.2f}{flag}")
        for f in files:
            f.unlink(missing_ok=True)
        at += args.motion_every
    if samples:
        print(f"  {samples} samples; every sample advanced on every frame"
              if not stalls else f"  {len(stalls)} samples contain a repeated frame")
        print(f"  fewest tiles moving in any sampled pair: {min(tile_hist)}/{COLS * ROWS}")

    # ------------------------------------------------------------ contact sheet
    if args.frames:
        out = pathlib.Path(args.frames)
        out.mkdir(parents=True, exist_ok=True)
        n, at = 0, 0.5
        while at < dur:
            subprocess.run([str(FFMPEG), "-y", "-v", "error", "-ss", f"{at:.4f}",
                            "-i", str(video), "-frames:v", "1", "-q:v", "3",
                            str(out / f"t{int(at):04d}.jpg")], check=True)
            at += args.every
            n += 1
        print(f"\n{n} contact-sheet frames in {out}")

    print("\n" + ("FAIL" if bad else "OK"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
