param(
  [string]$BaseUrl = "http://127.0.0.1:8000",
  [string]$PlatformKey = $env:MORROW_PLATFORM_ADMIN_KEY,
  [string]$OperatorSession = $env:MORROW_OPERATOR_SESSION,
  [string]$OutDir = "reports\release-evidence",
  [switch]$RunBrowserSmoke,
  [switch]$ExpectHsts
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "launch-auth.ps1")
$operatorRequest = Get-LaunchRequestParameters -BaseUrl $BaseUrl -PlatformKey $PlatformKey -OperatorSession $OperatorSession
if ($PlatformKey -and -not $OperatorSession) { $operatorRequest.Headers["x-platform-admin-role"] = "operator" }

$root = $BaseUrl.TrimEnd("/")
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bundleName = "release-evidence-$stamp"
$bundleDir = Join-Path $OutDir $bundleName
# The tenant-isolation probe is a write; shared-key callers default to the read-only auditor role.

New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null

function Write-JsonFile($Name, $Value) {
  $path = Join-Path $bundleDir $Name
  $json = $Value | ConvertTo-Json -Depth 30
  [System.IO.File]::WriteAllText((Resolve-Path $bundleDir).Path + [System.IO.Path]::DirectorySeparatorChar + $Name, $json, [System.Text.UTF8Encoding]::new($false))
  return $path
}

function Get-Json($Path, $Admin = $false) {
  $parameters = @{}
  if ($Admin) { $parameters = $script:operatorRequest }
  Invoke-RestMethod -Uri "$root$Path" @parameters -TimeoutSec 30 -MaximumRedirection 0
}

function Post-Json($Path, $Body = $null) {
  $bodyJson = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 20 } else { "{}" }
  Invoke-RestMethod -Uri "$root$Path" @operatorRequest -Method POST -ContentType "application/json" -Body $bodyJson -TimeoutSec 90 -MaximumRedirection 0
}

function Run-CommandCapture($Name, [scriptblock]$Command) {
  $stdout = Join-Path $bundleDir "$Name.out.txt"
  $stderr = Join-Path $bundleDir "$Name.err.txt"
  $result = [ordered]@{
    name = $Name
    started_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    exit_code = 0
    stdout_file = (Split-Path $stdout -Leaf)
    stderr_file = (Split-Path $stderr -Leaf)
  }
  try {
    $global:LASTEXITCODE = 0
    & $Command 1> $stdout 2> $stderr
    $result.exit_code = $LASTEXITCODE
    if ($null -eq $result.exit_code) { $result.exit_code = 0 }
  } catch {
    $result.exit_code = 1
    $_.Exception.Message | Out-File -FilePath $stderr -Encoding utf8
  }
  $result.finished_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  return $result
}

Write-Host "Collecting release evidence from $root"

$summary = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  base_url = $root
  bundle = $bundleName
  files = @()
  commands = @()
  status = "unknown"
  go_live_allowed = $false
  evidence_errors = @()
}

$statusResponse = Invoke-WebRequest -Uri "$root/status" -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 0
$statusJson = $statusResponse.Content | ConvertFrom-Json
$summary.files += Write-JsonFile "status.json" $statusJson

$headerEvidence = [ordered]@{
  url = "$root/status"
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  required = @("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Content-Security-Policy")
  headers = [ordered]@{}
  missing = @()
}
foreach ($name in $headerEvidence.required) {
  $value = $statusResponse.Headers[$name]
  $headerEvidence.headers[$name] = [string]$value
  if (-not $value) { $headerEvidence.missing += $name }
}
$hsts = $statusResponse.Headers["Strict-Transport-Security"]
$headerEvidence.headers["Strict-Transport-Security"] = [string]$hsts
if (($ExpectHsts -or ([uri]$root).Scheme -eq "https") -and -not $hsts) { $headerEvidence.missing += "Strict-Transport-Security" }
$summary.files += Write-JsonFile "security-headers.json" $headerEvidence

$checks = [ordered]@{
  health = Get-Json "/health"
  platform_health = Get-Json "/platform/health" $true
  readiness = Get-Json "/platform/readiness" $true
  go_live_gate = Get-Json "/platform/go-live-gate" $true
  admin_mode = Get-Json "/platform/admin-mode" $true
  retention_policy = Get-Json "/platform/retention/policy" $true
  retention_dry_run = Post-Json "/platform/retention/run" @{ dry_run = $true }
  observability = Get-Json "/platform/observability?limit=200" $true
  incidents = Get-Json "/platform/incidents" $true
  abuse = Get-Json "/platform/abuse" $true
  traffic_summary = Get-Json "/platform/traffic/summary?limit=200" $true
  traffic_otel = Get-Json "/platform/traffic/otel?limit=500" $true
  state_coverage = Get-Json "/platform/state/coverage" $true
}

foreach ($entry in $checks.GetEnumerator()) {
  $summary.files += Write-JsonFile "$($entry.Key).json" $entry.Value
}

try {
  $trafficNdjson = Invoke-WebRequest -Uri "$root/platform/traffic/export.ndjson?limit=5000" @operatorRequest -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 0
  [System.IO.File]::WriteAllText((Join-Path $bundleDir "traffic-events.ndjson"), [string]$trafficNdjson.Content, [System.Text.UTF8Encoding]::new($false))
  $summary.files += "traffic-events.ndjson"
} catch {
  $summary.evidence_errors += "traffic_export"
  $summary.files += Write-JsonFile "traffic-events.error.json" @{ error = $_.Exception.Message }
}

try {
  $tenant = Post-Json "/platform/tenant-isolation/verify" @{}
  $summary.files += Write-JsonFile "tenant-isolation.json" $tenant
} catch {
  $summary.evidence_errors += "tenant_isolation"
  $summary.files += Write-JsonFile "tenant-isolation.error.json" @{ error = $_.Exception.Message }
}

$summary.commands += Run-CommandCapture "verify-cloud-deployment" {
  $arguments = @("-BaseUrl", $root)
  if ($ExpectHsts) { $arguments += "-ExpectHsts" }
  Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "verify-cloud-deployment.ps1") -Arguments $arguments -PlatformKey $PlatformKey -OperatorSession $OperatorSession
}

if ($RunBrowserSmoke) {
  $summary.commands += Run-CommandCapture "e2e-smoke" {
    Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "e2e-smoke.ps1") -Arguments @("-BaseUrl", $root) -PlatformKey $PlatformKey -OperatorSession $OperatorSession
  }
}

$gate = $checks.go_live_gate
$summary.go_live_allowed = ((Test-LaunchGatePassed $gate) -and $tenant.status -eq "pass" -and
  $headerEvidence.missing.Count -eq 0 -and $summary.evidence_errors.Count -eq 0 -and
  @($summary.commands | Where-Object exit_code -ne 0).Count -eq 0)
$summary.status = if ($summary.go_live_allowed) { "go" } else { "no_go" }

$summaryPath = Write-JsonFile "summary.json" $summary

$markdown = @"
# Release Evidence Bundle

- Generated: $($summary.generated_at)
- Base URL: $root
- Bundle: $bundleName
- Status: $($summary.status)
- Go-live allowed: $($summary.go_live_allowed)
- Missing security headers: $(if ($headerEvidence.missing.Count) { $headerEvidence.missing -join ", " } else { "none" })

## Evidence Files

$((Get-ChildItem $bundleDir -File | Sort-Object Name | ForEach-Object { "- $($_.Name)" }) -join "`n")

## Manual Review

- Confirm production startup guard does not require break-glass override.
- Confirm readiness/go-live failures are accepted only for local/staging.
- Confirm retention dry-run output before any destructive retention run.
- Confirm tenant-isolation probe output after RLS/schema changes.
"@
[System.IO.File]::WriteAllText((Join-Path $bundleDir "README.md"), $markdown, [System.Text.UTF8Encoding]::new($false))

$zipPath = Join-Path $OutDir "$bundleName.zip"
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $bundleDir "*") -DestinationPath $zipPath -Force

Write-Host "Release evidence bundle created:"
Write-Host "  Folder: $bundleDir"
Write-Host "  ZIP:    $zipPath"

if ($summary.status -ne "go") {
  exit 2
}
exit 0
