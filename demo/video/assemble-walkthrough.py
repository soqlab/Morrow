"""Assemble the Morrow walkthrough from the rendered segments.

render-walkthrough.js writes one silent 60 fps segment per caption, plus
shots.json. This turns that into the delivered file:

  * a half-second cross-dissolve wherever the tour changes page, tab or
    scroll position, built from the last frame of one shot and the first of
    the next -- no page load is ever filmed;
  * the subtitles, rendered by libass from an ASS file generated here, so the
    timing is exact and the type is the same on every cue;
  * the ambient music bed, trimmed to length, normalised and faded.

    backend\\.venv\\Scripts\\python.exe demo\\video\\assemble-walkthrough.py \\
        --work %TEMP%\\airlock-walkthrough \\
        --out demo\\video\\morrow-walkthrough-v2.mp4

Nothing here touches port 8001, backend/pqc_scanner.db or backend/.env.
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
XFADE = 0.5          # seconds of cross-dissolve at every change of page
CUE_GAP = 0.10       # blank between one caption and the next

# The caption style. Two lines at most, white on a near-opaque dark plate, the
# same plate the console itself uses, set well inside the frame so nothing can
# clip. ASS colours are &HAABBGGRR, and alpha counts up from 00 = opaque.
ASS_HEAD = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 0
ScaledBorderAndShadow: yes
YCbCr Matrix: TV.709

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Cap,Segoe UI,38,&H00FBF8F4,&H00FBF8F4,&H0014100B,&H1A14100B,0,0,0,0,100,100,0,0,3,14,0,2,150,150,58,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""


# The tour's sections, keyed by the first line of the caption that opens each.
SECTIONS = {
    "Morrow": "Opening",
    "Traffic your organisation encrypts today": "1. The problem in plain words",
    "Discovery.": "2. Discovery",
    "Exposure.": "3. Exposure",
    "Evidence.": "4. Evidence",
    "Action.": "5. Action",
    "Governance.": "6. Governance",
    "If you are the security team buying this,": "7. For the buyer's security team",
    "Where to start.": "8. Close",
}


def clock(t: float) -> str:
    return f"{int(t) // 60}:{int(t) % 60:02d}"


def run(args: list[str], cwd: pathlib.Path | None = None) -> None:
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


def ts_ass(t: float) -> str:
    cs = max(0, round(t * 100))
    return f"{cs // 360000:d}:{cs // 6000 % 60:02d}:{cs // 100 % 60:02d}.{cs % 100:02d}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True, help="the directory render-walkthrough.js wrote to")
    ap.add_argument("--out", default=str(HERE / "morrow-walkthrough-v2.mp4"))
    ap.add_argument("--srt", default=str(HERE / "morrow-walkthrough-v2.srt"))
    ap.add_argument("--script", default=str(HERE / "morrow-walkthrough-script.md"))
    ap.add_argument("--music", default=str(HERE / "morrow-walkthrough-music.wav"))
    ap.add_argument("--crf", type=int, default=19)
    args = ap.parse_args()

    work = pathlib.Path(args.work).resolve()
    seg_dir = work / "seg"
    build = work / "build"
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)

    manifest = json.loads((work / "shots.json").read_text(encoding="utf-8"))
    shots = manifest["shots"]

    # ---------------------------------------------------------------- timeline
    parts: list[pathlib.Path] = []
    cues: list[tuple[float, float, list[str]]] = []
    t = 0.0
    for i, shot in enumerate(shots):
        seg = seg_dir / f"{i:03d}.mp4"
        if not seg.exists():
            print(f"missing segment {seg}", file=sys.stderr)
            return 1
        frames = probe_frames(seg)
        if i and shot["fade"]:
            # A dissolve between the two shots' own frames. Both segments hold
            # still across the join (a shot leads in and tails out on a held
            # frame), so the join carries no motion of its own to break.
            last = build / f"{i:03d}_a.png"
            first = build / f"{i:03d}_b.png"
            run([FFMPEG, "-y", "-nostdin", "-v", "error", "-sseof", "-0.2", "-i", parts[-1],
                 "-update", "1", "-frames:v", "1", last])
            run([FFMPEG, "-y", "-nostdin", "-v", "error", "-i", seg, "-frames:v", "1", first])
            tr = build / f"{i:03d}_tr.mp4"
            run([FFMPEG, "-y", "-nostdin", "-v", "error",
                 "-loop", "1", "-framerate", FPS, "-t", XFADE, "-i", last,
                 "-loop", "1", "-framerate", FPS, "-t", XFADE, "-i", first,
                 "-filter_complex", f"[0:v][1:v]xfade=transition=fade:duration={XFADE}:offset=0,setsar=1",
                 "-frames:v", round(XFADE * FPS),
                 "-c:v", "libx264", "-preset", "medium", "-crf", "16", "-profile:v", "high",
                 "-level", "4.2", "-pix_fmt", "yuv420p", "-r", FPS, "-g", "120", "-an", tr])
            parts.append(tr)
            start = t + XFADE / 2
            t += XFADE
        else:
            start = t
        parts.append(seg)
        t += frames / FPS
        if shot["cap"]:
            cues.append([start, t, shot["cap"]])

    total = t
    # Each caption runs until the next one is due, so the words never blink out
    # over a dissolve.
    for n, cue in enumerate(cues):
        nxt = cues[n + 1][0] if n + 1 < len(cues) else total
        cue[1] = max(cue[0] + 1.0, min(cue[1], nxt) - CUE_GAP)

    print(f"{len(shots)} shots, {len(parts) - len(shots)} dissolves, {len(cues)} captions, "
          f"{total:.2f}s ({int(round(total * FPS))} frames)")
    worst = max(cues, key=lambda c: len(" ".join(c[2])) / (c[1] - c[0]))
    print(f"fastest caption: {len(' '.join(worst[2])) / (worst[1] - worst[0]):.1f} characters a second")

    # ---------------------------------------------------------------- captions
    srt = "\n".join(
        f"{n + 1}\n{ts_srt(a)} --> {ts_srt(b)}\n" + "\n".join(lines) + "\n"
        for n, (a, b, lines) in enumerate(cues))
    pathlib.Path(args.srt).write_text(srt, encoding="utf-8")

    # The narration script, written from the cut it describes so the two cannot
    # drift apart.
    md = [
        "# Morrow walkthrough — narration script", "",
        "The caption text burned into `morrow-walkthrough-v2.mp4`, in order.",
        "Timings are for the delivered cut. There is no voice-over in the delivered",
        "file; these are the words to read if you want one.", "",
        "Generated by `assemble-walkthrough.py` from the cut it builds, so it cannot",
        "drift from the picture.", "",
    ]
    seen = False
    for a, b, cap in cues:
        section = SECTIONS.get(cap[0])
        if section:
            md += ["", f"## {section}", ""] if seen else [f"## {section}", ""]
            seen = True
        md.append(f"**{clock(a)}**  " + " ".join(cap))
        md.append("")
    pathlib.Path(args.script).write_text(chr(10).join(md).rstrip() + chr(10), encoding="utf-8")

    ass = build / "captions.ass"
    ass.write_text(ASS_HEAD + "".join(
        f"Dialogue: 0,{ts_ass(a)},{ts_ass(b)},Cap,,0,0,0,,{r'\N'.join(lines)}\n"
        for a, b, lines in cues), encoding="utf-8")

    # ---------------------------------------------------------------- assemble
    listing = build / "parts.txt"
    listing.write_text("".join(f"file '{p.as_posix()}'\n" for p in parts), encoding="utf-8")

    fade_out = max(1.0, total - 8)
    # The same audio chain the first cut used: loudnorm puts the bed at a fixed
    # loudness on every re-cut, and the trim after it brings the true peak back
    # to about -20 dBFS, well under burned-in subtitles.
    afilter = (f"loudnorm=I=-29:TP=-9:LRA=9,volume=-3.4dB,"
               f"afade=t=in:st=0:d=5,afade=t=out:st={fade_out:.3f}:d=8")

    out = pathlib.Path(args.out)
    run([FFMPEG, "-y", "-nostdin", "-v", "error", "-stats",
         "-f", "concat", "-safe", "0", "-i", listing,
         "-stream_loop", "-1", "-i", args.music,
         "-t", f"{total:.4f}",
         # ffmpeg runs in the build directory, so the subtitle file needs no
         # path and therefore no filter-graph escaping.
         "-filter_complex", f"[0:v]ass={ass.name}[v];[1:a]{afilter}[a]",
         "-map", "[v]", "-map", "[a]",
         "-c:v", "libx264", "-preset", "slow", "-crf", args.crf,
         "-profile:v", "high", "-level", "4.2", "-pix_fmt", "yuv420p",
         "-r", FPS, "-g", "120",
         "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
         "-c:a", "aac", "-b:a", "160k", "-ar", "44100", "-ac", "2",
         "-movflags", "+faststart", out.resolve()], cwd=build)

    run([FFPROBE, "-v", "error", "-show_entries",
         "stream=codec_type,codec_name,width,height,r_frame_rate,nb_frames",
         "-show_entries", "format=duration,size", "-of", "default=nw=1", out])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
