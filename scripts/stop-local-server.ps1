$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"
$PidFile = Join-Path $BackendDir ".pq-server.pid"

if (-not (Test-Path $PidFile)) {
  Write-Host "No local post-quantum server pid file found."
  exit 0
}

$raw = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue

if (-not $raw) {
  Write-Host "Removed empty pid file."
  exit 0
}

$proc = Get-Process -Id ([int]$raw) -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Process $raw is not running."
  exit 0
}

Stop-Process -Id $proc.Id -Force
Write-Host "Stopped post-quantum server process $($proc.Id)."
exit 0
