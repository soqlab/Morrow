param(
  [string]$BaseUrl = "http://localhost:8000",
  [switch]$StartStack,
  [switch]$RunPytest
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Script
  )

  Write-Host "==> $Name"
  & $Script
}

function Invoke-JsonGet {
  param(
    [string]$Path
  )

  $headers = @{
    "x-user-role" = "admin"
    "x-user-id" = "local-gtm-smoke"
  }

  Invoke-RestMethod -Method Get -Uri "$BaseUrl$Path" -Headers $headers -TimeoutSec 30
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

Invoke-Step "Checking API health" {
  $health = Invoke-JsonGet "/health"
  if ($health.status -ne "ok") {
    throw "Health check failed: $($health | ConvertTo-Json -Compress)"
  }
  Write-Host "health=ok"
}

Invoke-Step "Checking UI" {
  $response = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/ui/" -TimeoutSec 30
  if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
    throw "UI returned HTTP $($response.StatusCode)"
  }
  Write-Host "ui=http_$($response.StatusCode)"
}

Invoke-Step "Checking readiness" {
  $readiness = Invoke-JsonGet "/v1/readiness/e2e"
  $summary = $readiness.summary
  Write-Host "readiness=$($summary.readiness_percent)% ready=$($summary.ready)/$($summary.total) blocked=$($summary.blocked)"

  $blocked = @($readiness.items | Where-Object { $_.status -ne "ready" })
  if ($blocked.Count -gt 0) {
    Write-Host "blocked_items:"
    foreach ($item in $blocked) {
      Write-Host "- $($item.id): $($item.title) -> $($item.next_action)"
    }
  }
}

Invoke-Step "Checking crypto weather" {
  $weather = Invoke-JsonGet "/v1/org/demo-org/crypto-weather"
  $summary = $weather.crypto_weather.summary
  Write-Host "crypto_weather_signals=$($summary.active_signals_total) policy_advisories=$($summary.policy_advisories_total)"
}

Invoke-Step "Checking QRI" {
  $qri = Invoke-JsonGet "/v1/org/demo-org/qri"
  Write-Host "qri_score=$($qri.quantum_risk_index.score)"
}

Invoke-Step "Checking Postgres RLS plan" {
  $rls = Invoke-JsonGet "/v1/admin/postgres-rls/plan"
  # The table list is under .plan, not at the top level. Reading $rls.tables yielded $null, and
  # @($null).Count is 1, so this reported "rls_tables=1" no matter what the plan contained -- it
  # would have printed 1 for an empty plan just as happily.
  $tables = @($rls.plan.tables)
  if ($tables.Count -lt 2) {
    throw "RLS plan returned $($tables.Count) table(s); expected the full org-scoped set. The response shape may have changed."
  }
  Write-Host "rls_tables=$($tables.Count)"
  Write-Host "rls_app_sets_org_setting=$($rls.plan.app_sets_org_setting)"
}

if ($RunPytest) {
  Invoke-Step "Running backend regression suite" {
    Push-Location $BackendDir
    try {
      docker compose --env-file .env -f compose.yml exec -T api sh -lc "PYTHONPATH=/app MORROW_MAIN_DB_BACKEND=sqlite MORROW_SCANNER_DB=/tmp/pq_regression.sqlite pytest -q"
    } finally {
      Pop-Location
    }
  }
}

Write-Host "GTM smoke check complete"
