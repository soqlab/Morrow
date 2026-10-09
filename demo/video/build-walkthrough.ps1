<#
    Turns the Playwright recording plus the generated music into the delivered MP4.

        backend\.venv\Scripts\python.exe demo\video\run-demo-server.py      # terminal 1
        backend\.venv\Scripts\python.exe demo\video\seed-demo-data.py
        $env:NODE_PATH = ".tools\video\node_modules"; node demo\video\record-walkthrough.js
        backend\.venv\Scripts\python.exe demo\video\make-music.py --seconds 660
        powershell -File demo\video\build-walkthrough.ps1

    Two corrections happen here.

    1. Playwright's webm runs slower than real time: Chrome's screencast hands
       it more frames than the nominal 25 a second, and they are written one
       after another, so an 11-minute session comes out as a 12-minute file in
       slow motion. The recorder writes the true wall-clock length to
       walkthrough-timings.json, which is what setpts scales the picture to.
    2. -TrimStart drops the console's first load off the head, and
       -TargetSeconds then rescales the whole thing uniformly to a fixed
       delivered length. Nothing is cut, reordered or dropped; the tour simply
       plays a few per cent faster than the live session did.

    shift-srt.py applies the same shift and the same scale to the subtitle
    file. (The captions are burned into the frames; the .srt is for re-cutting.)
#>
param(
  [double]$TrimStart = 8.0,
  [double]$TailTrim = 2.5,
  # 0 keeps the tour at real time, which is what the delivered file uses.
  # Set it to a number of seconds to land on a fixed length instead: the
  # picture is then rescaled uniformly.
  [double]$TargetSeconds = 0,
  # Optional single cut, in delivered seconds (0 = no cut). Used once, to drop
  # the beat where the console printed a binary evidence pack as raw bytes; the
  # recorder no longer performs that click, so a fresh recording needs no cut.
  # Note: measured against the finished file, the cut lands about 1.6 s later
  # than the value given here (an interaction between the input -ss seek and
  # setpts). Check the join with ffmpeg and pre-compensate if you use this.
  [double]$CutStart = 0,
  [double]$CutEnd = 0,
  [string]$Output = "airlock-command-walkthrough.mp4"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent (Split-Path -Parent $here)
$ffmpeg = Join-Path $repo ".tools\ffmpeg\ffmpeg.exe"
$ffprobe = Join-Path $repo ".tools\ffmpeg\ffprobe.exe"

$webm = Get-ChildItem (Join-Path $here "raw") -Filter *.webm | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $webm) { throw "No recording in demo\video\raw. Run record-walkthrough.js first." }
$music = Join-Path $here "airlock-command-walkthrough-music.wav"
if (-not (Test-Path $music)) { throw "No music. Run make-music.py first." }
$timings = Join-Path $here "walkthrough-timings.json"
if (-not (Test-Path $timings)) { throw "No walkthrough-timings.json beside the recording." }
$outPath = Join-Path $here $Output

# The webm has no container duration, so count frames for its own timeline.
$frames = [double]((& $ffprobe -v error -count_frames -select_streams v:0 `
    -show_entries stream=nb_read_frames -of default=nokey=1:noprint_wrappers=1 $webm.FullName | Select-Object -Last 1).Trim())
$videoSeconds = $frames / 25.0
$realSeconds = [double](Get-Content $timings -Raw | ConvertFrom-Json).total_seconds
$speed = $videoSeconds / $realSeconds
$content = $realSeconds - $TrimStart - $TailTrim
if ($content -le 60) { throw "Recording is only $realSeconds s; nothing to cut." }
$playback = if ($TargetSeconds -gt 0) { $content / $TargetSeconds } else { 1.0 }
$final = [math]::Round($(if ($TargetSeconds -gt 0) { $TargetSeconds } else { $content }), 3)
$factor = [math]::Round($speed * $playback, 6)
$seekIn = [math]::Round($TrimStart * $speed, 4)
$fadeOut = [math]::Round($final - 8, 3)

Write-Host ("webm {0:N1}s / real {1:N1}s / content {2:N1}s -> playback {3:N4}x, delivered {4:N1}s" `
  -f $videoSeconds, $realSeconds, $content, $playback, $final)

# Audio normalisation: loudnorm puts the bed at the same loudness on every
# re-cut (its TP parameter cannot go below -9), and the volume trim after it
# brings the true peak back to about -20 dBFS, which is where the brief wants
# a bed sitting under burned-in subtitles. Measured after this chain:
# max_volume -20.0 dB, mean_volume -34.0 dB.
$cut = ($CutEnd -gt $CutStart)
if ($cut) {
  $final = [math]::Round($final - ($CutEnd - $CutStart), 3)
  $fadeOut = [math]::Round($final - 8, 3)
  Write-Host ("cutting {0:N1}s-{1:N1}s -> delivered {2:N1}s" -f $CutStart, $CutEnd, $final)
}
$vchain = if ($cut) {
  "[0:v]setpts=(PTS-STARTPTS)/${factor},split=2[c0][c1];" +
  "[c0]trim=start=0:end=${CutStart},setpts=PTS-STARTPTS[p0];" +
  "[c1]trim=start=${CutEnd},setpts=PTS-STARTPTS[p1];" +
  "[p0][p1]concat=n=2:v=1:a=0[v];"
} else {
  "[0:v]setpts=(PTS-STARTPTS)/${factor}[v];"
}
$filter = $vchain +
          "[1:a]loudnorm=I=-29:TP=-9:LRA=9,volume=-3.4dB," +
          "afade=t=in:st=0:d=5,afade=t=out:st=${fadeOut}:d=8[a]"

$ff = @(
  "-y", "-nostdin", "-v", "error",
  "-ss", "$seekIn", "-i", $webm.FullName,
  "-i", $music,
  "-t", "$final",
  "-filter_complex", $filter,
  "-map", "[v]", "-map", "[a]",
  "-c:v", "libx264", "-preset", "slow", "-crf", "21",
  "-profile:v", "high", "-level", "4.1", "-pix_fmt", "yuv420p",
  "-r", "25", "-g", "50",
  "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
  "-c:a", "aac", "-b:a", "160k", "-ar", "44100", "-ac", "2",
  "-movflags", "+faststart",
  $outPath
)

Write-Host "encoding $($webm.Name) -> $Output"
& $ffmpeg @ff
if ($LASTEXITCODE -ne 0) { throw "ffmpeg failed ($LASTEXITCODE)" }

& $ffprobe -v error -show_entries stream=codec_type,codec_name,width,height,r_frame_rate `
  -show_entries format=duration,size -of default=noprint_wrappers=1 $outPath
Write-Host ""
Write-Host "Now shift the subtitles to match:"
Write-Host ("  backend\.venv\Scripts\python.exe demo\video\shift-srt.py {0} {1} {2}" -f $TrimStart, $playback, $final)
