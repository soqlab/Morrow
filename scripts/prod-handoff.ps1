param(
  [string]$EnvFile = ".env.prod",
  [string]$BaseUrl = "http://127.0.0.1:8001",
  [switch]$SkipHttp,
  [switch]$GenerateEnvIfMissing,
  [string]$OutDir = "reports\prod-handoff"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvPath = Join-Path $RepoRoot $EnvFile
$OutPath = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $OutPath | Out-Null

if (-not (Test-Path -LiteralPath $EnvPath) -and $GenerateEnvIfMissing) {
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\new-prod-env.ps1") -OutFile $EnvFile
}

function Read-EnvFile {
  param([string]$Path)
  $map = @{}
  if (-not (Test-Path -LiteralPath $Path)) { return $map }
  foreach ($line in Get-Content -LiteralPath $Path) {
    $trim = $line.TrimStart([char]0xFEFF).Trim()  # tolerate a UTF-8 BOM even where Get-Content keeps it
    if (-not $trim -or $trim.StartsWith("#") -or -not $trim.Contains("=")) { continue }
    $parts = $trim -split "=", 2
    $map[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
  }
  return $map
}

function Invoke-Check {
  param(
    [string]$Name,
    [scriptblock]$Script
  )
  $started = Get-Date
  $tmp = [System.IO.Path]::GetTempFileName()
  try {
    & $Script *>&1 | Tee-Object -FilePath $tmp | Out-Null
    [pscustomobject]@{
      name = $Name
      status = "pass"
      duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
      output = ((Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue) -as [string]).Trim()
      error = ""
    }
  } catch {
    [pscustomobject]@{
      name = $Name
      status = "fail"
      duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
      output = ((Get-Content -LiteralPath $tmp -Raw -ErrorAction SilentlyContinue) -as [string]).Trim()
      error = $_.Exception.Message
    }
  } finally {
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
  }
}

$envMap = Read-EnvFile -Path $EnvPath
$unresolved = New-Object System.Collections.Generic.List[string]
foreach ($entry in $envMap.GetEnumerator()) {
  $value = [string]$entry.Value
  if ($value -match "(?i)(replace[_-]?with|change[_-]?me|your-domain|your[_-]|placeholder|example|test-only)") {
    $unresolved.Add($entry.Key) | Out-Null
  }
}

$checks = New-Object System.Collections.Generic.List[object]
$checks.Add((Invoke-Check "production_preflight" {
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\prod-preflight.ps1") -EnvFile $EnvFile -Strict
  if ($LASTEXITCODE -ne 0) { throw "prod-preflight exited $LASTEXITCODE" }
})) | Out-Null

$launchArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $RepoRoot "scripts\launch-collateral-check.ps1"))
if ($SkipHttp) {
  $launchArgs += "-SkipHttp"
} else {
  $launchArgs += @("-BaseUrl", $BaseUrl)
}
$checks.Add((Invoke-Check "launch_collateral" {
  powershell @launchArgs
  if ($LASTEXITCODE -ne 0) { throw "launch-collateral-check exited $LASTEXITCODE" }
})) | Out-Null

$manualActions = @(
  "Replace unresolved environment placeholders and move all real secrets to a cloud secret manager.",
  "Configure production SSO/JWT: issuer, audience, JWKS URL, role claim, org claim, redirect URLs, and MFA policy.",
  "Provision managed Postgres and Redis; use a least-privilege Postgres runtime role with no superuser and no BYPASSRLS.",
  "Run migrations, apply RLS/FORCE policies from /platform/rls-plan, then verify POST /platform/tenant-isolation/verify.",
  "Configure production DNS, TLS, PQC_ALLOWED_HOSTS, PQC_CORS_ORIGINS, CSP connect-src, and trusted proxy header behavior.",
  "Configure Sentry or equivalent error telemetry plus log retention, alert routing, and incident contacts.",
  "Connect /platform/traffic/export.ndjson or /platform/traffic/otel to SIEM/OpenTelemetry and keep PQC_TRAFFIC_PERSIST_TO_DB=1.",
  "Review /platform/state/coverage and keep one API replica until auxiliary state is migrated or explicitly accepted.",
  "Rotate any local/live-looking secrets that were shared, logged, committed, or exposed outside secret manager.",
  "Get counsel approval for terms, privacy policy, DPA, support commitments, and incident process.",
  "Run backup and restore drill; archive the evidence bundle.",
  "Deploy to staging, run browser smoke and scripts/market-ready-check.ps1 against the real deployed URL."
)

$failed = @($checks | Where-Object status -eq "fail")
$status = if (-not (Test-Path -LiteralPath $EnvPath)) {
  "missing_env"
} elseif ($failed.Count -gt 0 -or $unresolved.Count -gt 0) {
  "manual_blockers"
} else {
  "handoff_ready"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutPath "prod-handoff-$stamp.json"
$mdPath = Join-Path $OutPath "prod-handoff-$stamp.md"

$report = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  status = $status
  env_file = $EnvFile
  base_url = $BaseUrl
  unresolved_env_keys = @($unresolved | Sort-Object -Unique)
  checks = $checks
  manual_actions = $manualActions
  production_links = @{
    launch = "$BaseUrl/launch"
    console = "$BaseUrl/"
    vendor_admin = "$BaseUrl/vendor-admin/"
    traffic_monitor = "$BaseUrl/vendor-admin/traffic.html"
    access_policy = "$BaseUrl/auth/access-policy"
    readiness = "$BaseUrl/platform/readiness"
    go_live_gate = "$BaseUrl/platform/go-live-gate"
  }
}

$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$checkRows = $checks | ForEach-Object {
  $line = "- $($_.status.ToUpperInvariant()) $($_.name) $($_.duration_seconds)s"
  if ($_.error) { $line += " - $($_.error)" }
  $line
}
$unresolvedRows = if ($unresolved.Count -gt 0) {
  @($unresolved | Sort-Object -Unique | ForEach-Object { "- $_" }) -join "`n"
} else {
  "- None"
}
$manualRows = $manualActions | ForEach-Object { "- [ ] $_" }

$md = @"
# Production Handoff Report

- Generated: $($report.generated_at)
- Status: $status
- Env file: $EnvFile
- Base URL: $BaseUrl

## Checks

$($checkRows -join "`n")

## Unresolved Environment Keys

$unresolvedRows

## Manual Actions

$($manualRows -join "`n")

## Operator Links

- Launch: $BaseUrl/launch
- Console: $BaseUrl/
- Vendor admin: $BaseUrl/vendor-admin/
- Traffic monitor: $BaseUrl/vendor-admin/traffic.html
- Access policy: $BaseUrl/auth/access-policy
- Readiness: $BaseUrl/platform/readiness
- Go-live gate: $BaseUrl/platform/go-live-gate

## Evidence Files

- JSON: $jsonPath
- Markdown: $mdPath
"@
$md | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host "Production handoff status: $status"
Write-Host "Report: $mdPath"
Write-Host "Evidence: $jsonPath"
if ($status -ne "handoff_ready") { exit 1 }
exit 0
