param(
  [string]$BaseUrl = "",
  [switch]$SkipHttp,
  [string]$OutDir = "reports\market-ready"
)

# Checks the public launch collateral: the pages a stranger can reach, their load-bearing phrases,
# and that each one answers over HTTP.
#
# It deliberately does NOT check the commercial collateral -- the pricing, pilot, support, DPA and
# launch-pack documents live in the private repository alongside the rest of the go-to-market
# material, and depending on them here is what broke this script when they moved. That material has
# its own check next to it.
#
# backend/test_launch_collateral.py covers the same public pages from the test suite and runs in
# CI. This script exists to run the same assertions against a deployed URL.

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutPath = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $OutPath | Out-Null

$requiredFiles = @(
  @{ path = "backend\static\landing.html"; phrases = @("Prove quantum readiness without deep customer access.", "Quantum Airlock", "Open Console", "controlled enterprise pilot") },
  @{ path = "backend\static\public.css"; phrases = @("passport-stage", "doc-hero", "hero-proof") },
  @{ path = "backend\static\robots.txt"; phrases = @("Disallow: /platform/", "Disallow: /vendor-admin/", "Disallow: /ui/") },
  @{ path = "backend\static\enterprise-admin.html"; phrases = @("Enterprise Control Center", "Production Must-Pass", "Operator Flow") },
  @{ path = "backend\static_admin\traffic.html"; phrases = @("Traffic Monitor", "Platform-admin only", "No payload capture") },
  @{ path = "backend\static\security.html"; phrases = @("minimum customer access", "Production Controls", "Buyer Review References") },
  @{ path = "backend\static\trust-passport-demo.html"; phrases = @("Proof a buyer can actually review.", "Minimum Access", "verify signatures") },
  @{ path = "backend\static\pricing.html"; phrases = @("Airlock Command is free", "no service", "MIT") },
  @{ path = "backend\static\pilot.html"; phrases = @("6-8 week", "3-5 critical", "success criteria") },
  @{ path = "backend\static\data-boundary.html"; phrases = @("Optional integrations", "Platform traffic metadata") },
  @{ path = "backend\static\dpa.html"; phrases = @("Contract review required", "not an executed") },
  @{ path = "backend\static\airlock-deployment.html"; phrases = @("Validate one collection", "run-once") },
  @{ path = "backend\static\support.html"; phrases = @("How to reach us", "Severity targets", "Incident process") },
  @{ path = "backend\static\ai-trust.html"; phrases = @("AI starts off", "Filter before uploading", "Evidence with honest limits") },
  @{ path = "backend\static\privacy.html"; phrases = @("Counsel review required", "Data We Do Not Collect By Default", "Quantum Airlock") },
  @{ path = "backend\static\terms.html"; phrases = @("Authorization To Scan", "Acceptable Use", "Remediation Workflow") },
  @{ path = "docs\DATA_BOUNDARY_AND_PRIVACY.md"; phrases = @("Default Principle", "Quantum Airlock Boundary", "Redaction Guarantees") },
  @{ path = "docs\AUTH_AND_ACCESS_POLICY.md"; phrases = @("No-login is allowed only", "Traffic Data Boundary", "PQC_TRUST_PROXY_HEADERS") },
  @{ path = "docs\CAM_TRANSPARENT_PROXY_DEPLOYMENT.md"; phrases = @("CAM/API Transparent Proxy Deployment", "zero application code changes", "Production Guardrails") },
  @{ path = "docs\BUYER_SECURITY_FAQ.md"; phrases = @("Quantum Airlock", "What data does the platform need", "What should not be promised") }
)

$failures = New-Object System.Collections.Generic.List[string]
$checked = New-Object System.Collections.Generic.List[object]

foreach ($item in $requiredFiles) {
  $fullPath = Join-Path $RepoRoot $item.path
  if (-not (Test-Path -LiteralPath $fullPath)) {
    $failures.Add("Missing file: $($item.path)")
    continue
  }
  $content = Get-Content -LiteralPath $fullPath -Raw
  if (($content.Trim()).Length -lt 200) {
    $failures.Add("File is too small to be useful: $($item.path)")
  }
  foreach ($phrase in $item.phrases) {
    if ($content -notlike "*$phrase*") {
      $failures.Add("Missing phrase '$phrase' in $($item.path)")
    }
  }
  $checked.Add([pscustomobject]@{
    path = $item.path
    bytes = (Get-Item -LiteralPath $fullPath).Length
    required_phrases = $item.phrases
  }) | Out-Null
}

$routesChecked = New-Object System.Collections.Generic.List[object]
if (-not $SkipHttp -and $BaseUrl) {
  $BaseUrl = $BaseUrl.TrimEnd("/")
  $routes = @(
    @{ path = "/launch"; phrase = "Prove quantum readiness without deep customer access." },
    @{ path = "/landing"; phrase = "Prove quantum readiness without deep customer access." },
    @{ path = "/enterprise-admin"; phrase = "Enterprise Control Center" },
    @{ path = "/admin-page"; phrase = "Enterprise Control Center" },
    @{ path = "/vendor-admin/traffic.html"; phrase = "Traffic Monitor" },
    @{ path = "/trust-passport-demo"; phrase = "Proof a buyer can actually review." },
    @{ path = "/security"; phrase = "minimum customer access" },
    @{ path = "/support"; phrase = "How to reach us" },
    @{ path = "/ui/ai-trust.html"; phrase = "AI starts off" },
    @{ path = "/privacy"; phrase = "Privacy Policy" },
    @{ path = "/terms"; phrase = "Terms of Service" },
    @{ path = "/pricing"; phrase = "Airlock Command is free" },
    @{ path = "/pilot"; phrase = "success criteria" },
    @{ path = "/data-boundary"; phrase = "Platform traffic metadata" },
    @{ path = "/airlock-deployment"; phrase = "Validate one collection" },
    @{ path = "/dpa"; phrase = "Contract review required" },
    @{ path = "/robots.txt"; phrase = "Disallow: /vendor-admin/" },
    # The public funnel. These three are the whole route from a stranger arriving to an account
    # existing, and each fails silently: the site keeps working and nobody can get in.
    @{ path = "/check"; phrase = "Is your TLS quantum" },
    @{ path = "/trial"; phrase = "Ask for a trial" },
    @{ path = "/sitemap.xml"; phrase = "<loc>" },
    # The checker's public documents. A domain owner who found one of our handshakes in their logs
    # has no account and never will, so these must answer without one.
    @{ path = "/abuse"; phrase = "Never check my domain again" },
    @{ path = "/scanner"; phrase = "You found us in your logs" },
    @{ path = "/public-check/terms"; phrase = "they bind on use" },
    @{ path = "/public-check/acceptable-use"; phrase = "Mapping someone else's attack surface" },
    @{ path = "/public-check/privacy"; phrase = "If You Are The Party Being Checked" }
  )
  # The registry record for a domain nobody has checked is a deliberate 404 carrying a noindex
  # page, because /r/{anything} is unbounded crawl space. It cannot sit in the list above, which
  # asserts 200, so it is checked on its own terms.
  # Windows PowerShell 5.1 throws on a 404 and has no -SkipHttpErrorCheck, so the expected status
  # has to be read off the exception's response rather than the result.
  # The noindex is checked on the X-Robots-Tag header rather than the page's meta tag: Windows
  # PowerShell 5.1 strips tags out of an error response body, so a meta-only signal is invisible
  # here. The pages carry both.
  $recordStatus = 0
  $recordRobots = ""
  try {
    $probe = Invoke-WebRequest -Uri "$BaseUrl/r/example.com" -TimeoutSec 20 -UseBasicParsing
    $recordStatus = [int]$probe.StatusCode
    $recordRobots = [string]$probe.Headers["X-Robots-Tag"]
  } catch {
    $response = $_.Exception.Response
    if ($response) {
      $recordStatus = [int]$response.StatusCode
      $recordRobots = [string]$response.Headers["X-Robots-Tag"]
    } else {
      $failures.Add("Registry probe could not reach $BaseUrl/r/example.com: $($_.Exception.Message)")
    }
  }
  try {
    if ($recordStatus -ne 0) {
      if ($recordStatus -ne 404) {
        $failures.Add("/r/example.com answered $recordStatus; an unchecked domain must be 404")
      } elseif ($recordRobots -notlike '*noindex*') {
        $failures.Add("/r/example.com has no X-Robots-Tag noindex: unbounded crawl space would be indexed")
      }
    }
    $badge = Invoke-WebRequest -Uri "$BaseUrl/r/example.com/badge.svg" -TimeoutSec 20 -UseBasicParsing
    if ($badge.StatusCode -ne 200 -or $badge.Content -notlike '*unknown*') {
      $failures.Add("/r/example.com/badge.svg must answer 200 with the neutral badge")
    }
    $routesChecked.Add([pscustomobject]@{ path = "/r/{domain}"; status = "checked"; phrase = "404 + X-Robots-Tag noindex, neutral badge" })
  } catch {
    $failures.Add("Registry probe failed: $($_.Exception.Message)")
  }

  foreach ($route in $routes) {
    $url = "$BaseUrl$($route.path)"
    try {
      $res = Invoke-WebRequest -Uri $url -TimeoutSec 20 -UseBasicParsing
      if ([int]$res.StatusCode -lt 200 -or [int]$res.StatusCode -ge 400) {
        $failures.Add("Route $url returned HTTP $($res.StatusCode)")
      }
      if ($res.Content -notlike "*$($route.phrase)*") {
        $failures.Add("Route $url did not contain '$($route.phrase)'")
      }
      $routesChecked.Add([pscustomobject]@{
        url = $url
        status_code = [int]$res.StatusCode
        required_phrase = $route.phrase
      }) | Out-Null
    } catch {
      $failures.Add("Route $url failed: $($_.Exception.Message)")
    }
  }
}

$result = [ordered]@{
  generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  status = if ($failures.Count -eq 0) { "pass" } else { "fail" }
  checked_files = $checked
  checked_routes = $routesChecked
  failures = $failures
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonPath = Join-Path $OutPath "launch-collateral-$stamp.json"
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

Write-Host "Launch collateral status: $($result.status)"
Write-Host "Evidence: $jsonPath"
if ($failures.Count -gt 0) {
  $failures | ForEach-Object { Write-Host "FAIL: $_" }
  exit 1
}
exit 0
