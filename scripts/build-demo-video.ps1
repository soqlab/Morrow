param(
  [string]$BaseUrl = "http://localhost:8000",
  [string]$Output = "demo\video\pqc-scanner-demo.mp4",
  [switch]$StartStack,
  [switch]$SkipCapture
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"
$Ffmpeg = Join-Path $RepoRoot ".tools\ffmpeg\bin\ffmpeg.exe"
$Ffprobe = Join-Path $RepoRoot ".tools\ffmpeg\bin\ffprobe.exe"
$NodeModules = Join-Path $RepoRoot ".tools\video\node_modules"
$ScreensDir = Join-Path $RepoRoot "demo\video\screens"
$FramesDir = Join-Path $RepoRoot "demo\video\frames"
$SegmentsDir = Join-Path $RepoRoot "demo\video\segments"
$CaptionsDir = Join-Path $RepoRoot "demo\video\captions"
$AudioDir = Join-Path $RepoRoot "demo\video\audio"
$OutputPath = Join-Path $RepoRoot $Output
$VoiceOnlyOutputPath = Join-Path $SegmentsDir "voice-only-demo.mp4"
$MusicFile = Join-Path $AudioDir "background-music.wav"

function Invoke-Step {
  param([string]$Name, [scriptblock]$Script)
  Write-Host "==> $Name"
  & $Script
}

if (-not (Test-Path $Ffmpeg)) {
  throw "FFmpeg not found at $Ffmpeg. Install it first or rerun the FFmpeg install step."
}

if ($StartStack) {
  Invoke-Step "Starting Docker Compose stack" {
    Push-Location $BackendDir
    try {
      docker compose --env-file .env -f compose.yml up -d --build
    } finally {
      Pop-Location
    }
  }
}

Invoke-Step "Checking platform health" {
  Invoke-RestMethod -Uri "$BaseUrl/health" -TimeoutSec 20 | Out-Null
}

New-Item -ItemType Directory -Force -Path $ScreensDir, $FramesDir, $SegmentsDir, $CaptionsDir, $AudioDir | Out-Null

if (-not $SkipCapture) {
  Invoke-Step "Capturing real frontend screenshots" {
    $env:PQC_DEMO_BASE_URL = $BaseUrl
    $env:NODE_PATH = $NodeModules
    node (Join-Path $RepoRoot "scripts\capture-demo-screenshots.js")
  }
}

Add-Type -AssemblyName System.Speech
Add-Type -AssemblyName System.Drawing

$speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speaker.SelectVoice("Microsoft Zira Desktop")
$speaker.Rate = 0
$speaker.Volume = 95

function Convert-ToFfmpegPath {
  param([string]$Path)
  $full = [System.IO.Path]::GetFullPath($Path).Replace("\", "/")
  return $full -replace ":", "\:"
}

function Invoke-Ffmpeg {
  param([string[]]$FfmpegArgs)
  & $Ffmpeg @FfmpegArgs
  if ($LASTEXITCODE -ne 0) {
    throw "FFmpeg failed with exit code $LASTEXITCODE"
  }
}

function New-TitleSlide {
  param(
    [string]$OutputPath,
    [string]$Label,
    [string]$Title,
    [string]$Subtitle,
    [string[]]$Bullets,
    [string]$Footer
  )

  $width = 1280
  $height = 720
  $bitmap = New-Object System.Drawing.Bitmap $width, $height
  $g = [System.Drawing.Graphics]::FromImage($bitmap)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
  $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

  $colBg        = [System.Drawing.Color]::FromArgb(255, 9, 13, 11)
  $colAccent    = [System.Drawing.Color]::FromArgb(255, 52, 211, 128)
  $colTitle     = [System.Drawing.Color]::FromArgb(255, 237, 248, 240)
  $colSubtitle  = [System.Drawing.Color]::FromArgb(255, 138, 175, 150)
  $colBullet    = [System.Drawing.Color]::FromArgb(255, 215, 238, 222)
  $colFooter    = [System.Drawing.Color]::FromArgb(255, 65, 110, 80)
  $colDivider   = [System.Drawing.Color]::FromArgb(160, 52, 211, 128)
  $colDot       = [System.Drawing.Color]::FromArgb(255, 52, 211, 128)

  $g.Clear($colBg)

  $accentBrush = New-Object System.Drawing.SolidBrush $colAccent
  $g.FillRectangle($accentBrush, 0, 0, $width, 6)

  $labelFont  = New-Object System.Drawing.Font "Segoe UI", 17, ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
  $labelBrush = New-Object System.Drawing.SolidBrush $colAccent
  $g.DrawString($Label.ToUpper(), $labelFont, $labelBrush, (New-Object System.Drawing.PointF 72, 34))

  $titleFont  = New-Object System.Drawing.Font "Segoe UI", 52, ([System.Drawing.FontStyle]::Bold), ([System.Drawing.GraphicsUnit]::Pixel)
  $titleBrush = New-Object System.Drawing.SolidBrush $colTitle
  $fmt = New-Object System.Drawing.StringFormat
  $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisWord
  $g.DrawString($Title, $titleFont, $titleBrush, (New-Object System.Drawing.RectangleF 72, 82, 1136, 130), $fmt)

  $subFont  = New-Object System.Drawing.Font "Segoe UI", 24, ([System.Drawing.FontStyle]::Regular), ([System.Drawing.GraphicsUnit]::Pixel)
  $subBrush = New-Object System.Drawing.SolidBrush $colSubtitle
  $g.DrawString($Subtitle, $subFont, $subBrush, (New-Object System.Drawing.RectangleF 72, 220, 1136, 52), $fmt)

  $dividerPen = New-Object System.Drawing.Pen ([System.Drawing.Color]$colDivider), 2
  $g.DrawLine($dividerPen, 72, 284, 1208, 284)

  $bulletFont  = New-Object System.Drawing.Font "Segoe UI", 25, ([System.Drawing.FontStyle]::Regular), ([System.Drawing.GraphicsUnit]::Pixel)
  $bulletBrush = New-Object System.Drawing.SolidBrush $colBullet
  $dotBrush    = New-Object System.Drawing.SolidBrush $colDot
  $y = 304
  foreach ($line in $Bullets) {
    $g.FillEllipse($dotBrush, 72, ($y + 9), 9, 9)
    $g.DrawString($line, $bulletFont, $bulletBrush, (New-Object System.Drawing.RectangleF 96, $y, 1112, 46), $fmt)
    $y += 52
  }

  $footerFont  = New-Object System.Drawing.Font "Segoe UI", 19, ([System.Drawing.FontStyle]::Regular), ([System.Drawing.GraphicsUnit]::Pixel)
  $footerBrush = New-Object System.Drawing.SolidBrush $colFooter
  $centerFmt   = New-Object System.Drawing.StringFormat
  $centerFmt.Alignment = [System.Drawing.StringAlignment]::Center
  $g.DrawString($Footer, $footerFont, $footerBrush, (New-Object System.Drawing.RectangleF 0, 678, 1280, 38), $centerFmt)

  $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)

  $accentBrush.Dispose(); $labelBrush.Dispose(); $labelFont.Dispose()
  $titleBrush.Dispose(); $titleFont.Dispose(); $fmt.Dispose()
  $subBrush.Dispose(); $subFont.Dispose()
  $dividerPen.Dispose()
  $bulletBrush.Dispose(); $bulletFont.Dispose(); $dotBrush.Dispose()
  $footerBrush.Dispose(); $footerFont.Dispose(); $centerFmt.Dispose()
  $g.Dispose(); $bitmap.Dispose()
}

function New-AnnotatedFrame {
  param(
    [string]$SourcePath,
    [string]$OutputPath,
    [string]$Title,
    [string]$Caption
  )

  $width = 1280
  $height = 720
  $bitmap = New-Object System.Drawing.Bitmap $width, $height
  $g = [System.Drawing.Graphics]::FromImage($bitmap)
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

  $g.Clear([System.Drawing.Color]::FromArgb(255, 16, 21, 19))

  $source = [System.Drawing.Image]::FromFile($SourcePath)
  try {
    $scale    = [Math]::Min($width / $source.Width, $height / $source.Height)
    $drawW    = [int]($source.Width  * $scale)
    $drawH    = [int]($source.Height * $scale)
    $drawX    = [int](($width  - $drawW) / 2)
    $drawY    = [int](($height - $drawH) / 2)
    $g.DrawImage($source, $drawX, $drawY, $drawW, $drawH)
  } finally {
    $source.Dispose()
  }

  $overlay = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(232, 7, 16, 13))
  $g.FillRectangle($overlay, 0,   0, $width,  88)
  $g.FillRectangle($overlay, 0, 550, $width, 170)

  $accentBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 52, 211, 128))
  $g.FillRectangle($accentBrush, 0, 0, $width, 5)

  $titleFont   = New-Object System.Drawing.Font "Segoe UI", 30, ([System.Drawing.FontStyle]::Bold),    ([System.Drawing.GraphicsUnit]::Pixel)
  $captionFont = New-Object System.Drawing.Font "Segoe UI", 26, ([System.Drawing.FontStyle]::Regular), ([System.Drawing.GraphicsUnit]::Pixel)
  $titleBrush  = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 243, 248, 242))
  $captBrush   = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
  $fmt = New-Object System.Drawing.StringFormat
  $fmt.Trimming = [System.Drawing.StringTrimming]::EllipsisWord

  $g.DrawString($Title,   $titleFont,   $titleBrush, (New-Object System.Drawing.RectangleF 46,  22, 1188,  50), $fmt)
  $g.DrawString($Caption, $captionFont, $captBrush,  (New-Object System.Drawing.RectangleF 46, 580, 1188, 112), $fmt)

  $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)

  $overlay.Dispose(); $accentBrush.Dispose()
  $titleBrush.Dispose(); $captBrush.Dispose()
  $titleFont.Dispose(); $captionFont.Dispose()
  $fmt.Dispose(); $g.Dispose(); $bitmap.Dispose()
}

function Wrap-Text {
  param([string]$Text, [int]$MaxLineLength = 68)
  $words = $Text -split "\s+"
  $lines = New-Object System.Collections.Generic.List[string]
  $line  = ""
  foreach ($word in $words) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      $line = $word
    } elseif (($line.Length + 1 + $word.Length) -le $MaxLineLength) {
      $line = "$line $word"
    } else {
      $lines.Add($line); $line = $word
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($line)) { $lines.Add($line) }
  return ($lines -join "`n")
}

$slides = @(
  @{
    TextCard = $true
    Label    = "Morrow"
    Title    = "The Quantum Migration Crisis"
    Subtitle = "Every major enterprise is carrying risk they cannot see or quantify."
    Bullets  = @(
      "RSA and elliptic-curve encryption will be broken by quantum computers",
      "NIST finalized post-quantum standards in 2024  - migration is now mandatory",
      "Enterprise migration spans cloud, repos, CDNs, cert authorities, and distributed teams",
      "Most companies have no inventory, no owner map, and no governance process"
    )
    Footer   = "Morrow   -  Cryptographic Governance for the Post-Quantum Era"
    Narration = "Every major enterprise is carrying quantum cryptographic risk they cannot see. RSA and elliptic-curve encryption  - the cryptography protecting banking systems, healthcare records, government networks, and financial infrastructure  - will be broken by quantum computers. NIST published post-quantum standards in 2024. Regulatory deadlines are real. The migration spans cloud providers, repositories, CDNs, certificate authorities, and distributed teams, and it takes years. Most companies have no clean inventory, no owner map, and no governance process for this. Morrow was built to solve exactly that."
    Seconds  = 36
  },
  @{
    Image     = "01-dashboard-hero.png"
    Title     = "1. Cryptographic Command Center"
    Caption   = "One platform: crypto risk, ownership, remediation, validation, drift, and evidence."
    Narration = "Security teams today are managing post-quantum migration across spreadsheets, manually tracking assets, owners, and remediation state across hundreds of services and teams. Morrow replaces that with a single command center. Every cryptographic risk, owner, remediation stage, validation result, and evidence artifact flows through one interface. This is not just another scanner. It is a cryptographic governance operating system for the migration."
    Seconds   = 28
  },
  @{
    Image     = "02-board-risk-radar.png"
    Title     = "2. Board-Level Risk Posture"
    Caption   = "Five risk dimensions compressed into one executive posture signal."
    Narration = "The first question every CISO gets from the board is: how exposed are we, and are we improving? The board radar answers that without a manual report. Quantum risk index, regulatory alignment, remediation pressure, certificate posture, and shadow exposure, compressed into a single shape. A program that is improving should show these edges contracting over time. This is the executive reporting view that replaces quarterly spreadsheet presentations."
    Seconds   = 28
  },
  @{
    Image     = "03-readiness-checklist.png"
    Title     = "3. Enterprise Operating Controls"
    Caption   = "Production-grade controls proven before the enterprise signs."
    Narration = "Enterprise buyers need proof of production-grade operating controls before they sign a purchase order. The readiness checklist maps every critical control into a verifiable view: environment configuration, authentication, RBAC, multi-tenancy, GitHub integration, scan lifecycle, remediation workflow, validation, reporting, and restart safety. This is the enterprise onboarding and due diligence story that gets the pilot approved."
    Seconds   = 25
  },
  @{
    Image     = "04-compliance-summary.png"
    Title     = "4. Governance-Ready Compliance Report"
    Caption   = "Scans, validation, PR state, drift, and audit events  - one report."
    Narration = "The second biggest barrier to closing an enterprise security deal is the governance conversation. The compliance summary answers it. Scan results, remediation status, validation outcome, pull request state, verify-close, drift history, and audit events  - in one document. A CISO can take this to a board meeting or hand it to a regulator. This is how the platform becomes the system of record for the migration."
    Seconds   = 27
  },
  @{
    Image     = "05-crypto-weather.png"
    Title     = "5. External Crypto Threat Intelligence"
    Caption   = "New advisories and policy changes mapped automatically to internal assets."
    Narration = "Static point-in-time scanning is not enough. Algorithm guidance changes. TLS policy updates. Provider signals shift. When a new advisory is published, an enterprise needs to know which of their assets are affected. Crypto Weather maps external cryptographic pressure signals directly back to internal asset inventory and ownership. This continuous external monitoring is something no legacy scanner provides."
    Seconds   = 24
  },
  @{
    Image     = "06-flight-recorder.png"
    Title     = "6. Audit-Grade Evidence Timeline"
    Caption   = "Every change, action, and control update recorded for governance proof."
    Narration = "Enterprise buyers and their legal teams need an audit trail, not just a dashboard. The cryptographic flight recorder captures the full program timeline: when evidence was collected, when controls changed, when validation ran, when drift was detected, and who acted. This is the artifact that legal, compliance, and governance teams require during security reviews, customer audits, and regulatory examinations."
    Seconds   = 25
  },
  @{
    Image     = "07-enterprise-metrics.png"
    Title     = "7. Business Value Measurement"
    Caption   = "Remediation throughput and governance posture  - proven to be improving."
    Narration = "Investors and enterprise buyers both need to see the product move the needle. Enterprise metrics show the business value story: risks found, moved into remediation, validated, verified closed, and drift under control. This is the health-of-the-program layer  - the view a CTO and CISO use in quarterly reviews to show progress to leadership and demonstrate return on investment in renewal conversations."
    Seconds   = 25
  },
  @{
    Image     = "08-runtime-topology.png"
    Title     = "8. Runtime Crypto Visibility"
    Caption   = "East-west traffic exposes weak crypto that static code scanning misses entirely."
    Narration = "Every other product in this market stops at static code scanning. Morrow goes further. Runtime Traffic captures live crypto behavior between services: east-west internal traffic, weak TLS edges, shadow IT exposure, and runtime dependencies that never appear in public endpoint scans. This is a genuine technical differentiator  - the riskiest crypto exposure in most enterprises lives in internal microservices, not public websites."
    Seconds   = 26
  },
  @{
    Image     = "09-workflow-status.png"
    Title     = "9. Operator Workflow: Discovery to Action"
    Caption   = "The workflow board tells operators exactly what needs attention next."
    Narration = "The platform must be usable by a security engineer, not just a researcher. The operator workflow board connects asset discovery to the next best action. The operator sees what is exposed, who owns it, what remediation stage it is in, and what to do next  - without manually stitching together reports across five different tools. This makes the day-to-day migration work actually manageable at scale."
    Seconds   = 25
  },
  @{
    Image     = "10-github-ownership.png"
    Title     = "10. Risk to Engineering Routing"
    Caption   = "Findings route to the repository and team that can actually fix them."
    Narration = "The only way a security finding becomes an engineering fix is if the right team receives it in their normal workflow. Morrow connects assets to repositories and teams so a cryptographic finding travels directly to the engineering surface that can remediate it  - as a pull request, not an email or a spreadsheet row. This is what separates a governance platform from shelfware."
    Seconds   = 25
  },
  @{
    Image     = "11-remediation-queue.png"
    Title     = "11. Closed-Loop Remediation"
    Caption   = "Candidate to validated PR to verified closure to drift monitoring  - all audited."
    Narration = "The remediation queue is where discovery becomes governed action. A finding moves from candidate review, to human approval, to sandbox validation, to pull request creation, to verified closure, to drift monitoring. Every step is audited. This closed-loop workflow is what enterprise buyers care most about  - it proves the product does not just find problems, it tracks the full lifecycle until the risk is demonstrably closed."
    Seconds   = 27
  },
  @{
    Image     = "12-evidence-report.png"
    Title     = "12. Portable Audit Proof"
    Caption   = "One exportable report: scan state, PR merges, drift, and audit events."
    Narration = "The final output is portable proof. The evidence report gives security, legal, engineering, and leadership one source of truth instead of disconnected screenshots and manual spreadsheets. Scan state, compliance result, remediation history, validation outcome, pull request state, verify-close, drift, and audit events  - all in one exportable document. This can be shared with a regulator, a customer security team, or a board risk committee."
    Seconds   = 26
  },
  @{
    Image     = "13-closing-dashboard.png"
    Title     = "13. The Platform, Returned to Dashboard"
    Caption   = "The full migration loop: discover, own, remediate, validate, verify, drift, report."
    Narration = "Every view in this platform serves the same loop: discover cryptographic exposure, assign accountable owners, create remediation candidates, validate the suggested fix, open a pull request, verify the fix externally after deployment, monitor for drift, and produce audit evidence. That loop, repeated across hundreds of assets and teams, is the post-quantum migration program. Morrow is the operating system for it."
    Seconds   = 27
  },
  @{
    TextCard = $true
    Label    = "Morrow"
    Title    = "Start with a Controlled Pilot"
    Subtitle = "Concrete deliverables in six to eight weeks."
    Bullets  = @(
      "One organization, one to three repositories, real production assets",
      "One complete remediation: scan, suggest, validate, PR, verify, drift-check",
      "One compliance gate failure  - proving the enforcement layer works",
      "One evidence report ready for an auditor, a customer, or a board committee"
    )
    Footer   = "Morrow   -  Cryptographic Governance for the Post-Quantum Era"
    Narration = "The go-to-market story is a controlled pilot with a concrete deliverable. One organization. One to three repositories. Real production assets. One complete remediation workflow: scan, correlate, fail the compliance gate, generate a suggestion, validate it, open a pull request, verify the fix externally, run a drift check, and produce a final evidence report. That is a six to eight week pilot story and the foundation for closing the first enterprise deal. Morrow is the only platform built to turn post-quantum migration from a spreadsheet problem into a governed, auditable, engineering-led program."
    Seconds  = 40
  }
)

$segmentFiles = @()
$idx = 0

foreach ($slide in $slides) {
  $idx += 1
  $segment     = Join-Path $SegmentsDir ("segment-{0:D2}.mp4"  -f $idx)
  $framePath   = Join-Path $FramesDir   ("frame-{0:D2}.png"    -f $idx)
  $captionFile = Join-Path $CaptionsDir ("caption-{0:D2}.txt"  -f $idx)
  $audioFile   = Join-Path $AudioDir    ("voice-{0:D2}.wav"    -f $idx)
  $segmentFiles += $segment

  if ($slide.TextCard) {
    "TextCard" | Set-Content -Encoding ASCII $captionFile
    New-TitleSlide `
      -OutputPath $framePath `
      -Label      $slide.Label `
      -Title      $slide.Title `
      -Subtitle   $slide.Subtitle `
      -Bullets    $slide.Bullets `
      -Footer     $slide.Footer
  } else {
    $imagePath = Join-Path $ScreensDir $slide.Image
    if (-not (Test-Path $imagePath)) {
      throw "Missing screenshot: $imagePath"
    }
    $wrappedCaption = Wrap-Text -Text $slide.Caption -MaxLineLength 68
    $wrappedCaption | Set-Content -Encoding ASCII $captionFile
    New-AnnotatedFrame `
      -SourcePath $imagePath `
      -OutputPath $framePath `
      -Title      $slide.Title `
      -Caption    $wrappedCaption
  }

  $speaker.SetOutputToWaveFile($audioFile)
  $speaker.Speak($slide.Narration)
  $speaker.SetOutputToNull()

  $slideSeconds = $slide.Seconds
  Invoke-Step "Rendering segment $idx / $($slides.Count)" {
    Invoke-Ffmpeg -FfmpegArgs @(
      "-y", "-nostdin",
      "-loop", "1", "-i", $framePath,
      "-i", $audioFile,
      "-t", [string]$slideSeconds,
      "-r", "24",
      "-c:v", "libx264", "-preset", "ultrafast", "-crf", "26",
      "-pix_fmt", "yuv420p",
      "-c:a", "aac", "-b:a", "128k",
      $segment
    )
  }
}

$concatFile  = Join-Path $SegmentsDir "concat.txt"
$concatLines = $segmentFiles | ForEach-Object { "file '$($_.Replace('\', '/'))'" }
$concatLines | Set-Content -Encoding ASCII $concatFile

Invoke-Step "Assembling final video" {
  Invoke-Ffmpeg -FfmpegArgs @(
    "-y", "-nostdin", "-f", "concat", "-safe", "0",
    "-i", $concatFile, "-c", "copy", $VoiceOnlyOutputPath
  )
}

$durationText  = (& $Ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 $VoiceOnlyOutputPath | Select-Object -Last 1).Trim()
if ($LASTEXITCODE -ne 0) { throw "FFprobe failed while reading duration" }
$durationText  = $durationText -replace "^duration=", ""
$duration      = [double]::Parse($durationText, [System.Globalization.CultureInfo]::InvariantCulture)
$durationValue = $duration.ToString("0.###", [System.Globalization.CultureInfo]::InvariantCulture)
$fadeStart     = [Math]::Max(0, $duration - 4)
$fadeStartValue= $fadeStart.ToString("0.###", [System.Globalization.CultureInfo]::InvariantCulture)

Invoke-Step "Generating background music" {
  $musicFilter = "sine=frequency=196:duration=${durationValue}:sample_rate=44100[a0];" +
                 "sine=frequency=247:duration=${durationValue}:sample_rate=44100[a1];" +
                 "sine=frequency=330:duration=${durationValue}:sample_rate=44100[a2];" +
                 "[a0][a1][a2]amix=inputs=3:duration=longest,volume=0.028," +
                 "afade=t=in:st=0:d=3,afade=t=out:st=${fadeStartValue}:d=4"
  Invoke-Ffmpeg -FfmpegArgs @(
    "-y", "-nostdin", "-f", "lavfi", "-i", $musicFilter,
    "-c:a", "pcm_s16le", $MusicFile
  )
}

Invoke-Step "Mixing narration with background music" {
  Invoke-Ffmpeg -FfmpegArgs @(
    "-y", "-nostdin",
    "-i", $VoiceOnlyOutputPath,
    "-i", $MusicFile,
    "-filter_complex", "[0:a]volume=1.0[voice];[1:a]volume=0.55[music];[voice][music]amix=inputs=2:duration=first:dropout_transition=3[a]",
    "-map", "0:v",
    "-map", "[a]",
    "-c:v", "libx264", "-profile:v", "high", "-level", "4.1",
    "-pix_fmt", "yuv420p",
    "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
    "-crf", "23", "-preset", "medium",
    "-c:a", "aac", "-ar", "44100", "-ac", "2", "-b:a", "192k",
    "-movflags", "+faststart",
    $OutputPath
  )
}

if (Test-Path $Ffprobe) {
  Invoke-Step "Validating final video" {
    & $Ffprobe -v error -show_entries format=duration,size -of default=noprint_wrappers=1 $OutputPath
    if ($LASTEXITCODE -ne 0) { throw "FFprobe failed with exit code $LASTEXITCODE" }
  }
}

Write-Host ""
Write-Host "Demo video created: $OutputPath"
$durationMin = [int]($duration / 60)
$durationSec = [int]($duration % 60)
Write-Host ("Duration: {0}m {1:D2}s" -f $durationMin, $durationSec)
