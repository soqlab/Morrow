param(
  [string]$BaseUrl = "http://127.0.0.1:8001",
  [string[]]$Targets = @("cloudflare.com"),
  [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")
$Headers = @{
  "x-user-role" = "admin"
  "x-user-id" = "scan-flow-smoke"
}

function Invoke-Json {
  param(
    [ValidateSet("GET", "POST")]
    [string]$Method,
    [string]$Path,
    [object]$Body = $null
  )

  $args = @{
    Method = $Method
    Uri = "$BaseUrl$Path"
    Headers = $Headers
    TimeoutSec = 30
  }
  if ($null -ne $Body) {
    $args.ContentType = "application/json"
    $args.Body = ($Body | ConvertTo-Json -Depth 10)
  }
  Invoke-RestMethod @args
}

Write-Host "Checking health: $BaseUrl/health"
$health = Invoke-Json -Method GET -Path "/health"
if ($health.status -ne "ok") {
  throw "Health check returned $($health.status)"
}

Write-Host "Checking UI"
$ui = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/" -TimeoutSec 30
if ($ui.StatusCode -lt 200 -or $ui.StatusCode -ge 300) {
  throw "UI returned HTTP $($ui.StatusCode)"
}

Write-Host "Creating scan for targets: $($Targets -join ', ')"
$created = Invoke-Json -Method POST -Path "/scans" -Body @{ targets = $Targets }
$scanId = $created.id
if (-not $scanId) {
  throw "POST /scans did not return an id: $($created | ConvertTo-Json -Compress)"
}
Write-Host "scan_id=$scanId status=$($created.status)"

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$terminal = @("completed", "failed", "error")
$scan = $created
do {
  Start-Sleep -Seconds 2
  $scan = Invoke-Json -Method GET -Path "/scans/$scanId"
  $status = [string]$scan.status
  $progress = $scan.progress
  Write-Host "status=$status progress=$($progress.percent)% done=$($progress.done)/$($progress.total)"
  if ($terminal -contains $status.ToLowerInvariant()) { break }
} while ((Get-Date) -lt $deadline)

if (-not ($terminal -contains ([string]$scan.status).ToLowerInvariant())) {
  throw "Timed out waiting for scan $scanId to finish"
}
if ($scan.status -ne "completed") {
  throw "Scan $scanId ended with status=$($scan.status) error=$($scan.error)"
}

$results = @($scan.results)
if ($results.Count -lt 1) {
  throw "Scan $scanId completed but returned no results"
}

Write-Host "Checking migration plan and CSV export"
Invoke-Json -Method GET -Path "/scans/$scanId/migration-plan" | Out-Null
$csv = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/scans/$scanId/export.csv" -Headers $Headers -TimeoutSec 30
if ($csv.StatusCode -lt 200 -or $csv.StatusCode -ge 300) {
  throw "CSV export returned HTTP $($csv.StatusCode)"
}

Write-Host "Scan flow smoke passed: $scanId"
exit 0
