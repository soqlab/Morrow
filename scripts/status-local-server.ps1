param(
  [int]$Port = 8001
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"
$PidFile = Join-Path $BackendDir ".pq-server.pid"
$BaseUrl = "http://127.0.0.1:$Port"
$Python = Join-Path $BackendDir ".venv\Scripts\python.exe"

function Get-ListenerProcess {
  param([int]$Port)
  try {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
      Select-Object -First 1
    if (-not $listener) { return $null }
    Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
  } catch {
    return $null
  }
}

if (Test-Path $PidFile) {
  $pidValue = Get-Content -LiteralPath $PidFile | Select-Object -First 1
  $proc = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
  if ($proc) {
    Write-Host "Process: running pid=$pidValue"
  } else {
    $listenerProc = Get-ListenerProcess -Port $Port
    if ($listenerProc) {
      $expectedPython = if (Test-Path $Python) { (Resolve-Path -LiteralPath $Python).Path } else { "" }
      $actualPath = ""
      $commandLine = ""
      try { $actualPath = $listenerProc.Path } catch { $actualPath = "" }
      try {
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($listenerProc.Id)").CommandLine
      } catch { $commandLine = "" }
      $isManaged = (
        ($expectedPython -and $actualPath -and ($actualPath -ieq $expectedPython)) -or
        ($expectedPython -and $commandLine -and $commandLine.Contains($expectedPython) -and $commandLine.Contains("uvicorn app:app"))
      )
      if ($isManaged) {
        Set-Content -LiteralPath $PidFile -Value ([string]$listenerProc.Id)
        Write-Host "Process: running pid=$($listenerProc.Id) (pid file repaired)"
      } else {
        Write-Host "Process: port $Port is used by pid=$($listenerProc.Id)"
      }
    } else {
      Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
      Write-Host "Process: stale pid file removed; no listener on port $Port"
    }
  }
} else {
  $listenerProc = Get-ListenerProcess -Port $Port
  if ($listenerProc) {
    Write-Host "Process: port $Port is used by pid=$($listenerProc.Id)"
  } else {
    Write-Host "Process: no pid file"
  }
}

try {
  $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health" -TimeoutSec 5
  Write-Host "Health: $($health.status)"
  Write-Host "URL: $BaseUrl"
  exit 0
} catch {
  Write-Host "Health: unreachable ($($_.Exception.Message))"
  exit 1
}
