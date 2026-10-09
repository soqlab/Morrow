param(
  [Parameter(Mandatory=$true)][string]$BaseUrl,
  [Parameter(Mandatory=$false)][string]$PlatformKey = $env:PQC_PLATFORM_ADMIN_KEY,
  [string]$OperatorSession = $env:PQC_OPERATOR_SESSION,
  [switch]$ExpectHsts,
  [switch]$ExpectLocalNoGo
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")
. (Join-Path $PSScriptRoot "launch-auth.ps1")
$operatorRequest = Get-LaunchRequestParameters -BaseUrl $base -PlatformKey $PlatformKey -OperatorSession $OperatorSession

# CI runs a deliberately unconfigured local server and must prove that its gate refuses launch.
if ($ExpectLocalNoGo) {
  if (([uri]$base).Host -notin @("127.0.0.1", "localhost", "::1", "[::1]")) {
    throw "-ExpectLocalNoGo is restricted to a loopback server. Remote deployments must pass the launch gate."
  }
  if (-not $PlatformKey) { throw "-ExpectLocalNoGo requires a platform key to verify the gate." }
}

function Fail($Message) {
  Write-Error $Message
  exit 1
}

function Get-Json($Path, $Admin = $false) {
  $parameters = @{}
  if ($Admin) { $parameters = $script:operatorRequest }
  Invoke-RestMethod -Uri "$base$Path" @parameters -TimeoutSec 20 -MaximumRedirection 0
}

Write-Host "Verifying $base"

$status = Get-Json "/status"
if ($status.status -notin @("operational", "ok")) { Fail "/status is not operational: $($status | ConvertTo-Json -Compress)" }

$health = Get-Json "/health"
if ($health.status -ne "ok") { Fail "/health is not ok: $($health | ConvertTo-Json -Compress)" }

$response = Invoke-WebRequest -Uri "$base/status" -TimeoutSec 20 -UseBasicParsing -MaximumRedirection 0
$requiredHeaders = @("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Content-Security-Policy")
foreach ($name in $requiredHeaders) {
  if (-not $response.Headers[$name]) { Fail "Missing security header: $name" }
}
if (($ExpectHsts -or ([uri]$base).Scheme -eq "https") -and -not $response.Headers["Strict-Transport-Security"]) {
  Fail "Missing Strict-Transport-Security header on HTTPS deployment"
}

if ($operatorRequest) {
  $readiness = Get-Json "/platform/readiness" $true
  $gate = Get-Json "/platform/go-live-gate" $true
  $adminMode = Get-Json "/platform/admin-mode" $true
  $retention = Get-Json "/platform/retention/policy" $true
  Write-Host "Readiness: $($readiness.status), Go-live gate: $($gate.status), Admin mode: $($adminMode.mode)"
  if ($ExpectLocalNoGo) {
    if ($gate.go_live_allowed -ne $false -or $gate.status -ne "no_go" -or $gate.required_failed -lt 1) {
      Fail "Local guardrail failure: the unconfigured test server must refuse deployment."
    }
    if ($adminMode.mode -ne "development") { Fail "Expected a development server for local guardrail verification." }
  } elseif ($gate.go_live_allowed -ne $true -or $gate.status -ne "go" -or $gate.required_failed -ne 0 -or $gate.failed_required_checks.Count -gt 0 -or $gate.warnings.Count -gt 0) {
    Fail "Go-live gate is not passing. Required failures: $($gate.required_failed)"
  }
  if (-not $retention.defaults.dry_run) { Fail "Retention policy must default to dry_run=true" }
}

if ($ExpectLocalNoGo) {
  Write-Host "Local launch guardrails passed. This development server remains blocked from production."
} else {
  Write-Host "Cloud deployment verification passed."
}
exit 0
