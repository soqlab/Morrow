param(
  [string]$BaseUrl = "http://localhost:8000",
  [string]$PlatformKey = $env:MORROW_PLATFORM_ADMIN_KEY,
  [string]$OperatorSession = $env:MORROW_OPERATOR_SESSION,
  [switch]$Json
)

$ErrorActionPreference = "Stop"

if (-not $PlatformKey -and -not $OperatorSession -and ([uri]$BaseUrl).Host -in @("localhost", "127.0.0.1", "::1", "[::1]")) {
  $envFile = Join-Path (Get-Location) "backend\.env"
  if (Test-Path $envFile) {
    $line = Get-Content $envFile | ForEach-Object { $_.TrimStart([char]0xFEFF) } | Where-Object { $_ -match "^MORROW_PLATFORM_ADMIN_KEY=" } | Select-Object -First 1
    if ($line) {
      $PlatformKey = ($line -split "=", 2)[1].Trim()
    }
  }
}

$uri = ($BaseUrl.TrimEnd("/")) + "/platform/go-live-gate"
. (Join-Path $PSScriptRoot "launch-auth.ps1")
$operatorRequest = Get-LaunchRequestParameters -BaseUrl $BaseUrl -PlatformKey $PlatformKey -OperatorSession $OperatorSession
$result = Invoke-RestMethod -Method Get -Uri $uri @operatorRequest -TimeoutSec 30 -MaximumRedirection 0

if ($Json) {
  $result | ConvertTo-Json -Depth 12
} else {
  Write-Host "Go-live status: $($result.status)"
  Write-Host "Allowed: $($result.go_live_allowed)"
  Write-Host "Required failed: $($result.required_failed)"
  if ($result.failed_required_checks.Count -gt 0) {
    Write-Host ""
    Write-Host "Failed required checks:"
    foreach ($check in $result.failed_required_checks) {
      Write-Host "- $($check.key): $($check.detail)"
      if ($check.fix) { Write-Host "  Fix: $($check.fix)" }
    }
  }
  if ($result.warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings (these block go-live):"
    foreach ($warning in $result.warnings) {
      Write-Host "- $warning"
    }
  }
  # Standing consequences of the features that are still SQLite-backed. Reported because operators
  # need to know them, but they hold on every Postgres deployment regardless of configuration, so
  # they are not blockers.
  if ($result.advisories -and $result.advisories.Count -gt 0) {
    Write-Host ""
    Write-Host "Advisories (informational, do not block go-live):"
    foreach ($advisory in $result.advisories) {
      Write-Host "- $advisory"
    }
  }
  Write-Host ""
  Write-Host "Manual exit criteria:"
  foreach ($item in $result.manual_exit_criteria) {
    Write-Host "- $item"
  }
}

if ($result.go_live_allowed -ne $true -or $result.status -ne "go" -or $result.required_failed -ne 0 -or $result.failed_required_checks.Count -gt 0 -or $result.warnings.Count -gt 0) {
  exit 1
}
