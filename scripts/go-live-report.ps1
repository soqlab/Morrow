param(
  [string]$BaseUrl = "http://127.0.0.1:8000",
  [string]$PlatformKey = $env:PQC_PLATFORM_ADMIN_KEY,
  [string]$OperatorSession = $env:PQC_OPERATOR_SESSION,
  [switch]$RunBrowserSmoke,
  [switch]$RunBackupDrill,
  [string]$OutDir = "reports\go-live"
)

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "launch-auth.ps1")
$operatorRequest = Get-LaunchRequestParameters -BaseUrl $BaseUrl -PlatformKey $PlatformKey -OperatorSession $OperatorSession
if ($PlatformKey -and -not $OperatorSession) { $operatorRequest.Headers["x-platform-admin-role"] = "operator" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutDir "go-live-$stamp.json"
$mdPath = Join-Path $OutDir "go-live-$stamp.md"
# The tenant-isolation probe is a write; shared-key callers default to the read-only auditor role.
$root = $BaseUrl.TrimEnd("/")

function Get-Json([string]$Path) {
  $res = Invoke-WebRequest -UseBasicParsing "$root$Path" @operatorRequest -TimeoutSec 30 -MaximumRedirection 0
  return $res.Content | ConvertFrom-Json
}

function Post-Json([string]$Path) {
  $res = Invoke-WebRequest -UseBasicParsing "$root$Path" @operatorRequest -Method POST -TimeoutSec 60 -MaximumRedirection 0
  return $res.Content | ConvertFrom-Json
}

$report = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  base_url = $root
  checks = [ordered]@{}
  command_results = @()
}

$report.checks.status = Invoke-WebRequest -UseBasicParsing "$root/status" -TimeoutSec 15 -MaximumRedirection 0 | Select-Object -ExpandProperty Content | ConvertFrom-Json
$report.checks.health = Get-Json "/platform/health"
$report.checks.readiness = Get-Json "/platform/readiness"
$report.checks.go_live_gate = Get-Json "/platform/go-live-gate"
$report.checks.tenant_isolation = Post-Json "/platform/tenant-isolation/verify"
$report.checks.observability = Get-Json "/platform/observability?limit=200"
$report.checks.incidents = Get-Json "/platform/incidents"
$report.checks.abuse = Get-Json "/platform/abuse"

if ($RunBrowserSmoke) {
  try {
    Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "e2e-smoke.ps1") -Arguments @("-BaseUrl", $root) -PlatformKey $PlatformKey -OperatorSession $OperatorSession
    $report.command_results += @{ name = "browser_smoke"; status = "pass" }
  } catch {
    $report.command_results += @{ name = "browser_smoke"; status = "fail"; error = $_.Exception.Message }
  }
}

if ($RunBackupDrill) {
  try {
    if (-not ($env:PQC_BACKUP_DRILL_DSN -or $env:PQC_PRODUCT_DATABASE_URL -or $env:DATABASE_URL)) {
      throw "The release backup drill requires a PostgreSQL owner DSN in the environment."
    }
    Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "backup-restore-drill.ps1") -PlatformKey $PlatformKey -OperatorSession $OperatorSession
    $report.command_results += @{ name = "backup_drill"; status = "pass" }
  } catch {
    $report.command_results += @{ name = "backup_drill"; status = "fail"; error = $_.Exception.Message }
  }
}

$gate = $report.checks.go_live_gate
$tenant = $report.checks.tenant_isolation
$report.go_live_allowed = ((Test-LaunchGatePassed $gate) -and $tenant.status -eq "pass" -and
  $report.checks.status.status -in @("ok", "operational") -and
  @($report.command_results | Where-Object status -ne "pass").Count -eq 0)
$report.status = if ($report.go_live_allowed) { "go" } else { "no_go" }
$json = $report | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText((Join-Path (Resolve-Path $OutDir).Path (Split-Path $jsonPath -Leaf)), $json, [System.Text.UTF8Encoding]::new($false))

$gate = $report.checks.go_live_gate
$tenant = $report.checks.tenant_isolation
$incidents = $report.checks.incidents
$md = @"
# Go-Live Report

- Generated: $($report.generated_at)
- Base URL: $root
- Automated report status: $($report.status)
- Go-live allowed: $($report.go_live_allowed)
- Gate status: $($gate.status)
- Required failed checks: $($gate.required_failed)
- Tenant isolation: $($tenant.status)
- Incident count: $($incidents.incident_count)

## Manual Exit Criteria

$((($gate.manual_exit_criteria | ForEach-Object { "- [ ] $_" }) -join "`n"))

## Files

- JSON evidence: $jsonPath
"@
[System.IO.File]::WriteAllText((Join-Path (Resolve-Path $OutDir).Path (Split-Path $mdPath -Leaf)), $md, [System.Text.UTF8Encoding]::new($false))

Write-Host "Go-live report written:"
Write-Host "  $jsonPath"
Write-Host "  $mdPath"
if (-not $report.go_live_allowed) { exit 2 }
exit 0
