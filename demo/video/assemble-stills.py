"""Assemble the motionless cut: one still per shot, crossfades, music ducked under the voice.

Every shot holds for exactly its beats on the 120 BPM grid (beats x 0.5 s), so the score still
lands where it was written. Nothing moves except the half-second crossfade between shots -- no
truck, no push-in, no turning charts -- which is the point of this cut.

    backend/.venv/Scripts/python.exe demo/video/assemble-stills.py
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FFMPEG = HERE.parents[1] / ".tools" / "ffmpeg" / "ffmpeg.exe"
TMP = pathlib.Path.home() / "AppData/Local/Temp"
STILLS = TMP / "airlock-stills" / "stills"
FILM = TMP / "airlock-stills" / "film.json"
MUSIC = HERE / "airlock-promo3-music.wav"
VOICE = TMP / "airlock-promo3" / "vo" / "voiceover.wav"
OUT = HERE / "morrow-promo-stills.mp4"
FPS = 30
XF = 0.5          # crossfade length, seconds
TOTAL = 180.0


def main() -> int:
    shots = json.loads(FILM.read_text(encoding="utf-8"))["shots"]
    durs = [s["beats"] * 0.5 for s in shots]
    starts = [sum(durs[:i]) for i in range(len(durs))]
    assert abs(sum(durs) - TOTAL) < 1e-6, sum(durs)
    missing = [i for i in range(len(shots)) if not (STILLS / f"{i:03d}.jpg").exists()]
    if missing:
        print("missing stills:", missing)
        return 1

    args = [str(FFMPEG), "-y", "-v", "error", "-stats"]
    for i, d in enumerate(durs):
        args += ["-loop", "1", "-framerate", str(FPS), "-t", f"{d + XF:.3f}", "-i", str(STILLS / f"{i:03d}.jpg")]
    music_in, voice_in = len(durs), len(durs) + 1
    args += ["-i", str(MUSIC), "-i", str(VOICE)]

    f = []
    for i in range(len(durs)):
        f.append(f"[{i}:v]scale=1920:1080:flags=lanczos,setsar=1,format=yuv420p,fps={FPS}[s{i}]")
    prev = "s0"
    for i in range(1, len(durs)):
        off = starts[i] - XF / 2
        f.append(f"[{prev}][s{i}]xfade=transition=fade:duration={XF}:offset={off:.3f}[x{i}]")
        prev = f"x{i}"
    f.append(f"[{prev}]trim=0:{TOTAL},fade=t=in:st=0:d=0.8,fade=t=out:st={TOTAL - 3:.1f}:d=3[v]")

    # The music ducks under the narrator by itself: the voice drives a sidechain compressor on the
    # score, so every line is intelligible without hand-drawn volume curves.
    f.append(f"[{music_in}:a]aresample=48000,volume=0.60[m]")
    f.append(f"[{voice_in}:a]aresample=48000,asplit=2[vo][key]")
    f.append("[m][key]sidechaincompress=threshold=0.025:ratio=7:attack=15:release=420:makeup=1[md]")
    f.append("[md][vo]amix=inputs=2:normalize=0:weights='1 1.7'[mix]")
    f.append(f"[mix]loudnorm=I=-16:TP=-1.5:LRA=11,atrim=0:{TOTAL},afade=t=in:st=0:d=0.5,"
             f"afade=t=out:st={TOTAL - 3:.1f}:d=3[a]")

    args += ["-filter_complex", ";".join(f), "-map", "[v]", "-map", "[a]",
             "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-profile:v", "high", "-level", "4.1",
             "-pix_fmt", "yuv420p", "-color_range", "tv", "-colorspace", "bt709", "-color_primaries", "bt709",
             "-color_trc", "bt709", "-r", str(FPS), "-g", str(FPS * 2),
             "-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-movflags", "+faststart", str(OUT)]
    subprocess.run(args, check=True)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
