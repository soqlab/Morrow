param(
  [string]$BaseUrl = "http://127.0.0.1:8001",
  [string]$EnvFile = "backend\.env",
  [string]$PlatformKey = $env:PQC_PLATFORM_ADMIN_KEY,
  [string]$Token = $env:PQC_MARKET_READY_TOKEN,
  [switch]$StartLocal,
  [switch]$SkipScanSmoke,
  [switch]$SkipAirlockSmoke,
  [switch]$SkipReleaseEvidence,
  [switch]$RunBrowserSmoke,
  [string]$OutDir = "reports\market-ready"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "launch-auth.ps1")
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BaseUrl = $BaseUrl.TrimEnd("/")
$BaseUri = [uri]$BaseUrl
$IsLocalBaseUrl = $BaseUri.Host -in @("localhost", "127.0.0.1", "::1")
$OutPath = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $OutPath | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutPath "market-ready-$stamp.json"
$mdPath = Join-Path $OutPath "market-ready-$stamp.md"

function Invoke-CommandCheck {
  param(
    [string]$Name,
    [scriptblock]$Script
  )
  $started = Get-Date
  $tmpOutput = [System.IO.Path]::GetTempFileName()
  try {
    & $Script *>&1 | Tee-Object -FilePath $tmpOutput | Out-Null
    $output = Get-Content -LiteralPath $tmpOutput -Raw -ErrorAction SilentlyContinue
    [pscustomobject]@{
      name = $Name
      status = "pass"
      duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
      output = ($output -as [string]).Trim()
      error = ""
    }
  } catch {
    $output = Get-Content -LiteralPath $tmpOutput -Raw -ErrorAction SilentlyContinue
    [pscustomobject]@{
      name = $Name
      status = "fail"
      duration_seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
      output = ($output -as [string]).Trim()
      error = $_.Exception.Message
    }
  } finally {
    Remove-Item -LiteralPath $tmpOutput -ErrorAction SilentlyContinue
  }
}

function Get-EnvValue {
  param([string]$Name)
  $envPath = Join-Path $RepoRoot $EnvFile
  if (-not (Test-Path $envPath)) { return "" }
  $line = Get-Content -LiteralPath $envPath | Where-Object { $_ -match "^$([regex]::Escape($Name))=" } | Select-Object -First 1
  if (-not $line) { return "" }
  ($line -split "=", 2)[1].Trim()
}

if (-not $PlatformKey) {
  $PlatformKey = Get-EnvValue -Name "PQC_PLATFORM_ADMIN_KEY"
}

$checks = New-Object System.Collections.Generic.List[object]

if ($StartLocal -and -not $IsLocalBaseUrl) {
  throw "-StartLocal can only be used with localhost or 127.0.0.1 BaseUrl."
}

if ($StartLocal) {
  $checks.Add((Invoke-CommandCheck "start_local_server" {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\start-local-server.ps1") -Restart -Port $BaseUri.Port -EnvFile $EnvFile
    if ($LASTEXITCODE -ne 0) { throw "start-local-server exited $LASTEXITCODE" }
  }))
}

$checks.Add((Invoke-CommandCheck "production_preflight" {
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\prod-preflight.ps1") -EnvFile $EnvFile -Strict
  if ($LASTEXITCODE -ne 0) { throw "prod-preflight exited $LASTEXITCODE" }
}))

if ($IsLocalBaseUrl) {
  $checks.Add((Invoke-CommandCheck "server_status" {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\status-local-server.ps1") -Port $BaseUri.Port
    if ($LASTEXITCODE -ne 0) { throw "status-local-server exited $LASTEXITCODE" }
  }))
} else {
  $checks.Add((Invoke-CommandCheck "remote_health" {
    $health = Invoke-RestMethod -Uri "$BaseUrl/health" -TimeoutSec 20
    if ($health.status -ne "ok") { throw "/health did not return ok" }
    $status = Invoke-RestMethod -Uri "$BaseUrl/status" -TimeoutSec 20
    if ($status.status -notin @("ok", "operational")) { throw "/status is not operational" }
  }))
}

$checks.Add((Invoke-CommandCheck "launch_collateral" {
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\launch-collateral-check.ps1") -BaseUrl $BaseUrl
  if ($LASTEXITCODE -ne 0) { throw "launch-collateral-check exited $LASTEXITCODE" }
}))

if ($SkipScanSmoke) {
  $checks.Add([pscustomobject]@{
    name = "scan_flow_smoke"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "Skipped by -SkipScanSmoke"
  })
} else {
  $checks.Add((Invoke-CommandCheck "scan_flow_smoke" {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\scan-flow-smoke.ps1") -BaseUrl $BaseUrl -Targets "cloudflare.com" -TimeoutSeconds 120
    if ($LASTEXITCODE -ne 0) { throw "scan-flow-smoke exited $LASTEXITCODE" }
  }))
}

if ($SkipAirlockSmoke) {
  $checks.Add([pscustomobject]@{
    name = "airlock_enterprise_smoke"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "Skipped by -SkipAirlockSmoke"
  })
} elseif ($Token -or $IsLocalBaseUrl) {
  $checks.Add((Invoke-CommandCheck "airlock_enterprise_smoke" {
    $headers = @{}
    if ($Token) {
      $headers["Authorization"] = "Bearer $Token"
    } elseif ($IsLocalBaseUrl) {
      $headers["x-user-role"] = "operator"
      $headers["x-user-id"] = "market-ready-airlock"
      $headers["x-org-id"] = "00000000-0000-0000-0000-000000000001"
    }
    $ready = Invoke-RestMethod -Uri "$BaseUrl/airlock/enterprise-readiness" -Headers $headers -TimeoutSec 20
    if (-not $ready.kind) { throw "Airlock readiness did not return a valid response" }
    $agent = Invoke-RestMethod -Uri "$BaseUrl/airlock/agent-package" -Method Post -Headers $headers -ContentType "application/json" -Body '{"customer_id":"market-ready","deployment_mode":"read_only","allow_write_actions":false}' -TimeoutSec 30
    if (-not $agent.artifacts.'pqc_airlock_agent.py') { throw "Airlock agent package did not include collector source" }
    $sim = Invoke-RestMethod -Uri "$BaseUrl/airlock/change-simulator" -Method Post -Headers $headers -ContentType "application/json" -Body '{"rollout_percent":10,"services":[{"name":"legacy-api","algorithm":"TLS_RSA_WITH_AES_128_CBC_SHA","supports_hybrid_tls":false}]}' -TimeoutSec 30
    if ($sim.payload.no_change_applied -ne $true) { throw "Airlock simulator must be no-change by default" }
  }))
} else {
  $checks.Add([pscustomobject]@{
    name = "airlock_enterprise_smoke"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "Set -Token or run against localhost to smoke Airlock enterprise endpoints"
  })
}

if ($PlatformKey -or $env:PQC_OPERATOR_SESSION) {
  $checks.Add((Invoke-CommandCheck "go_live_gate" {
    Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "check-go-live-gate.ps1") -Arguments @("-BaseUrl", $BaseUrl) -PlatformKey $PlatformKey -OperatorSession $env:PQC_OPERATOR_SESSION
  }))
} else {
  $checks.Add([pscustomobject]@{
    name = "go_live_gate"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "PQC_PLATFORM_ADMIN_KEY not available"
  })
}

if ($SkipReleaseEvidence) {
  $checks.Add([pscustomobject]@{
    name = "release_evidence_bundle"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "Skipped by -SkipReleaseEvidence"
  })
} elseif ($PlatformKey -or $env:PQC_OPERATOR_SESSION) {
  $checks.Add((Invoke-CommandCheck "release_evidence_bundle" {
    $args = @(
      "-BaseUrl", $BaseUrl
    )
    if ($RunBrowserSmoke) { $args += "-RunBrowserSmoke" }
    if (-not $IsLocalBaseUrl) { $args += "-ExpectHsts" }
    Invoke-LaunchScript -ScriptPath (Join-Path $PSScriptRoot "release-evidence-bundle.ps1") -Arguments $args -PlatformKey $PlatformKey -OperatorSession $env:PQC_OPERATOR_SESSION
  }))
} else {
  $checks.Add([pscustomobject]@{
    name = "release_evidence_bundle"
    status = "skip"
    duration_seconds = 0
    output = ""
    error = "PQC_PLATFORM_ADMIN_KEY not available"
  })
}

if ($RunBrowserSmoke) {
  $checks.Add((Invoke-CommandCheck "browser_smoke" {
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\e2e-smoke.ps1") -BaseUrl $BaseUrl
    if ($LASTEXITCODE -ne 0) { throw "e2e-smoke exited $LASTEXITCODE" }
  }))
}

$failed = @($checks | Where-Object { $_.status -eq "fail" })
$skipped = @($checks | Where-Object { $_.status -eq "skip" })
$status = if ($failed.Count -gt 0) { "block" } elseif ($skipped.Count -gt 0) { "warn" } else { "pass" }

$report = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  base_url = $BaseUrl
  status = $status
  failed = $failed.Count
  skipped = $skipped.Count
  checks = $checks
  market_claim = if ($status -eq "pass") {
    "Ready for controlled enterprise pilot evidence review."
  } else {
    "Not ready for external go-live. Resolve blockers before market claims."
  }
  non_code_exit_criteria = @(
    "Rotate all secrets that were ever exposed outside a secret manager.",
    "Configure production JWT issuer, audience, JWKS URL, role claim, and org claim.",
    "Use managed Postgres and Redis with backup/restore drill evidence.",
    "Apply and verify Postgres RLS with a non-superuser runtime role.",
    "Confirm counsel-approved legal terms, DPA, privacy policy, support process, and incident contacts.",
    "Confirm public /launch, /trust-passport-demo, /enterprise-admin, /security, /support, /privacy, and /terms pages match the current customer agreement.",
    "Confirm /vendor-admin/traffic.html works with x-platform-key and is protected behind SSO/VPN or an identity-aware proxy.",
    "Confirm /auth/access-policy reflects the final no-login and signed-proof access boundary.",
    "Confirm traffic export is connected to SIEM/OpenTelemetry and release evidence bundle is archived.",
    "Confirm auxiliary SQLite state coverage is accepted, archived, or migrated before increasing API replicas.",
    "Run browser smoke and backup restore drill against staging."
  )
}

$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$rows = $checks | ForEach-Object {
  $line = "- {0} `{1}` {2}s" -f $_.status.ToUpperInvariant(), $_.name, $_.duration_seconds
  if ($_.error) { $line += " - $($_.error)" }
  $line
}
$criteria = $report.non_code_exit_criteria | ForEach-Object { "- [ ] $_" }
$md = @"
# Market Readiness Report

- Generated: $($report.generated_at)
- Base URL: $BaseUrl
- Status: $status
- Failed checks: $($failed.Count)
- Skipped checks: $($skipped.Count)

## Checks

$($rows -join "`n")

## Market Claim

$($report.market_claim)

## Non-Code Exit Criteria

$($criteria -join "`n")

## Evidence Files

- JSON: $jsonPath
- Markdown: $mdPath
"@
$md | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host "Market readiness status: $status"
Write-Host "Report: $mdPath"
Write-Host "Evidence: $jsonPath"
if ($status -ne "pass") { exit 1 }
exit 0
