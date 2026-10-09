param(
  [string]$BaseUrl = "http://localhost:8000",
  [string]$PlatformKey = $env:PQC_PLATFORM_ADMIN_KEY
)

$ErrorActionPreference = "Stop"
$env:PQC_E2E_BASE_URL = $BaseUrl
if ($PlatformKey) {
  $env:PQC_E2E_PLATFORM_KEY = $PlatformKey
}

if (-not (Test-Path ".tools\video\node_modules\playwright")) {
  throw "Playwright dependency is missing. Run npm install in .tools/video first."
}

node scripts/e2e-smoke.js
if ($LASTEXITCODE -ne 0) {
  throw "e2e-smoke.js exited $LASTEXITCODE"
}
exit 0
