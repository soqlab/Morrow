param(
  [string]$BaseUrl = "http://localhost:8000",
  [int]$Requests = 50,
  [int]$Concurrency = 5,
  # Supply a credential to include endpoints that require authentication. Without one the probe
  # covers only endpoints that are reachable unauthenticated, which is what a load balancer or
  # uptime monitor sees.
  [string]$Token = $env:PQC_LOAD_SMOKE_TOKEN,
  [string]$PlatformKey = $env:PQC_PLATFORM_ADMIN_KEY
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")

# /health, /healthz and /ui/ are auth-public (see _auth_public_path in backend/app.py), so they can
# be probed on a hardened deployment without credentials. /health/deep is NOT public: it reports
# component-level internals, so it answers 401 under PQC_AUTH_REQUIRED=1. Probing it anyway made
# this script exit 1 against every correctly-hardened deployment -- a third of all calls "failing"
# on a server that was behaving exactly as designed.
$endpoints = @("/health", "/healthz", "/ui/")
$headers = @{}
if ($Token) { $headers["Authorization"] = "Bearer $Token" }
if ($PlatformKey) { $headers["x-platform-key"] = $PlatformKey }
if ($Token) {
  # Only a user token gets past the auth middleware for /health/deep; the platform key authenticates
  # /platform/* paths only.
  $endpoints += "/health/deep"
}

$bag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$jobs = @()
$started = Get-Date

for ($worker = 0; $worker -lt $Concurrency; $worker++) {
  $jobs += Start-Job -ScriptBlock {
    param($BaseUrl, $Requests, $Endpoints, $Headers)
    $out = @()
    for ($i = 0; $i -lt $Requests; $i++) {
      foreach ($path in $Endpoints) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
          $res = Invoke-WebRequest -UseBasicParsing -Uri ($BaseUrl + $path) -Headers $Headers -TimeoutSec 15
          $sw.Stop()
          $out += [pscustomobject]@{ path=$path; status=[int]$res.StatusCode; ms=[int]$sw.ElapsedMilliseconds; transport=$true }
        } catch {
          $sw.Stop()
          # Invoke-WebRequest throws on any non-2xx, so recover the status code: a 401 is a response
          # from a working server, not a transport failure, and conflating the two hides real faults.
          $code = 0
          if ($_.Exception.Response) { try { $code = [int]$_.Exception.Response.StatusCode } catch {} }
          $out += [pscustomobject]@{ path=$path; status=$code; ms=[int]$sw.ElapsedMilliseconds; transport=($code -ne 0); error=$_.Exception.Message }
        }
      }
    }
    $out
  } -ArgumentList $BaseUrl, $Requests, $endpoints, $headers
}

Receive-Job -Job $jobs -Wait -AutoRemoveJob | ForEach-Object { $bag.Add($_) }
$duration = ((Get-Date) - $started).TotalSeconds
$items = $bag.ToArray()
$total = $items.Count

# A failure is the server erroring or not answering. Any other non-2xx is surfaced separately so it
# is visible without being miscounted as a fault.
$failed = @($items | Where-Object { -not $_.transport -or $_.status -ge 500 }).Count
$unexpected = @($items | Where-Object { $_.transport -and $_.status -lt 500 -and ($_.status -lt 200 -or $_.status -ge 300) })

$sorted = @($items | Sort-Object ms)
$p95Index = [Math]::Min($sorted.Count - 1, [Math]::Max(0, [int]([Math]::Ceiling($sorted.Count * 0.95) - 1)))
$p95 = if ($sorted.Count) { $sorted[$p95Index].ms } else { 0 }
$avg = if ($sorted.Count) { [Math]::Round((($sorted | Measure-Object ms -Average).Average), 1) } else { 0 }

Write-Host "Load smoke complete"
Write-Host "Base URL: $BaseUrl"
Write-Host "Endpoints: $($endpoints -join ', ')"
Write-Host "Authenticated: $(if ($Token) { 'yes (bearer token supplied)' } else { 'no (public endpoints only)' })"
Write-Host "Requests per worker: $Requests"
Write-Host "Concurrency: $Concurrency"
Write-Host "Total HTTP calls: $total"
Write-Host "Failed (5xx or no response): $failed"
Write-Host "Avg ms: $avg"
Write-Host "P95 ms: $p95"
Write-Host "Duration sec: $([Math]::Round($duration, 1))"

Write-Host ""
Write-Host "Per-endpoint latency:"
foreach ($group in ($items | Group-Object path | Sort-Object Name)) {
  $gs = @($group.Group | Sort-Object ms)
  $gp95 = $gs[[Math]::Min($gs.Count - 1, [Math]::Max(0, [int]([Math]::Ceiling($gs.Count * 0.95) - 1)))].ms
  $gavg = [Math]::Round((($gs | Measure-Object ms -Average).Average), 1)
  $codes = ($group.Group | Group-Object status | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join " "
  Write-Host ("- {0,-14} avg {1,7}ms  p95 {2,7}ms  [{3}]" -f $group.Name, $gavg, $gp95, $codes)
}

if ($unexpected.Count -gt 0) {
  Write-Host ""
  Write-Host "Unexpected non-2xx responses (server answered, but not as expected):"
  foreach ($group in ($unexpected | Group-Object path, status)) {
    Write-Host "- $($group.Name): $($group.Count)"
  }
}

if ($failed -gt 0) {
  exit 1
}
