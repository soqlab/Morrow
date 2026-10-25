"""Voice-over for the three-minute commercial: one clip per line, each placed on the shot it
describes, then mixed into a single track the length of the film.

The cue times are the shot start times from render-promo3.js (beat / 2 at 120 BPM), plus a few
hundred milliseconds so a line starts after the cut rather than on it. A line that would run into
the next one is sped up slightly (at most 10 %); anything longer is reported, not squeezed.

Voice: Microsoft's en-US-AndrewNeural through edge-tts. Only the script text below is sent.

    backend/.venv/Scripts/python.exe demo/video/make-voiceover.py
"""
import asyncio
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FFMPEG = HERE.parents[1] / ".tools" / "ffmpeg" / "ffmpeg.exe"
WORK = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path.home() / "AppData/Local/Temp/airlock-promo3/vo"
VOICE = "en-US-AndrewNeural"
TOTAL = 180.0

LINES = [
    # Act one: the problem
    (0.6,   "Almost everything you send is encrypted."),
    (3.6,   "But the encryption you trust today can be copied today, and kept."),
    (9.7,   "Harvest now, decrypt later. When a quantum computer can break today's keys, everything stored can be read."),
    (17.6,  "The deadlines to replace it are already published."),
    (21.3,  "The hard part is knowing what you're actually running."),
    (25.2,  "So start smaller."),
    # Act two: one domain
    (28.4,  "Start with one domain. No account, no card, nothing to install."),
    (33.2,  "It checks what your public endpoint really negotiates."),
    (39.8,  "Every result becomes a permanent public record, classified against the NIST post-quantum standards."),
    (47.6,  "This endpoint was classical in July, and hybrid post-quantum by October. The record shows exactly when it changed."),
    (55.8,  "Link to it, cite it, or put the badge in your README."),
    (62.7,  "Then, the whole estate."),
    # Act three: the estate
    (67.3,  "Every asset and every owner. Every endpoint, as it was actually measured."),
    (75.3,  "Your harvest-now exposure, per endpoint, with the model's assumptions shown."),
    (83.8,  "And which data still matters by the time those keys fall."),
    (91.7,  "A cryptographic bill of materials, generated from real scans, and mapped to the frameworks you're judged on."),
    (99.7,  "Fixes, carried all the way to verified closure."),
    (103.7, "Canary keys, so you'll know if anything is ever broken."),
    (108.0, "A score for the board, with every weight shown."),
    (115.7, "Evidence an auditor can read. Not a score you have to take on trust."),
    (124.2, "Where something is a model, it says so. And a failed check is never reported as a clean one."),
    # Act four: free and open
    (132.5, "So what does it cost?"),
    (136.3, "Nothing."),
    (140.5, "Three ways in, and none of them are paid."),
    (144.3, "The hosted service is free, and the platform is MIT open source."),
    (149.6, "Clone it, run it, change it. It stays yours."),
    (153.0, "Want a full workspace? Ask, and a person reads every request."),
    (160.3, "There's no service-level agreement, and nobody is on call."),
    (164.5, "If that won't do, run your own copy. That's what the licence is for."),
    (170.0, "Morrow. Free. Open source."),
    (174.6, "Start with one domain."),
]


def duration(path: pathlib.Path) -> float:
    out = subprocess.run([str(FFMPEG), "-hide_banner", "-i", str(path)], capture_output=True, text=True).stderr
    for line in out.splitlines():
        if "Duration:" in line:
            h, m, s = line.split("Duration:")[1].split(",")[0].strip().split(":")
            return int(h) * 3600 + int(m) * 60 + float(s)
    raise RuntimeError(f"no duration for {path}")


async def synth(i: int, text: str) -> pathlib.Path:
    import edge_tts
    out = WORK / f"line{i:02d}.mp3"
    await edge_tts.Communicate(text, VOICE, rate="-4%").save(str(out))
    return out


async def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    clips = await asyncio.gather(*(synth(i, t) for i, (_, t) in enumerate(LINES)))
    inputs, filters, labels = [], [], []
    for i, ((start, text), clip) in enumerate(zip(LINES, clips)):
        length = duration(clip)
        room = (LINES[i + 1][0] if i + 1 < len(LINES) else TOTAL - 0.5) - start - 0.25
        tempo = 1.0
        if length > room:
            tempo = min(1.10, length / room)
            note = "OVERRUNS" if length / tempo > room + 0.05 else "sped up"
            print(f"  line {i:02d}: {length:.2f}s in {room:.2f}s -> x{tempo:.2f} ({note})")
        inputs += ["-i", str(clip)]
        ms = int(start * 1000)
        chain = f"[{i}:a]aresample=48000,aformat=channel_layouts=stereo"
        if tempo > 1.0:
            chain += f",atempo={tempo:.3f}"
        filters.append(f"{chain},adelay={ms}|{ms}[v{i}]")
        labels.append(f"[v{i}]")
    filters.append(f"{''.join(labels)}amix=inputs={len(labels)}:normalize=0,apad,atrim=0:{TOTAL}[vo]")
    track = WORK / "voiceover.wav"
    subprocess.run([str(FFMPEG), "-y", "-v", "error", *inputs, "-filter_complex", ";".join(filters),
                    "-map", "[vo]", "-ar", "48000", str(track)], check=True)
    print(f"wrote {track}: {duration(track):.2f}s, {len(LINES)} lines, voice {VOICE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
