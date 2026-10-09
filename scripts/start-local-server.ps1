param(
  [int]$Port = 8001,
  [string]$EnvFile = "backend\.env",
  [switch]$Restart,
  [switch]$Foreground
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"
$Python = Join-Path $BackendDir ".venv\Scripts\python.exe"
$PidFile = Join-Path $BackendDir ".pqc-server.pid"
$OutLog = Join-Path $BackendDir "uvicorn-$Port.out.log"
$ErrLog = Join-Path $BackendDir "uvicorn-$Port.err.log"
$EnvPath = Join-Path $RepoRoot $EnvFile

function Import-EnvFile {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    Write-Host "Env file not found, using inherited environment: $Path"
    return
  }
  foreach ($line in Get-Content -LiteralPath $Path) {
    $trim = $line.TrimStart([char]0xFEFF).Trim()  # tolerate a UTF-8 BOM even where Get-Content keeps it
    if (-not $trim -or $trim.StartsWith("#") -or -not $trim.Contains("=")) { continue }
    $parts = $trim -split "=", 2
    $name = $parts[0].Trim()
    $value = $parts[1].Trim().Trim('"').Trim("'")
    if ($name) {
      [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
  }
  Write-Host "Loaded environment from $Path"
}

function Get-ManagedListener {
  param([int]$Port)
  try {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
      Select-Object -First 1
    if (-not $listener) { return $null }
    $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    if (-not $proc) { return $null }
    $expectedPython = (Resolve-Path -LiteralPath $Python).Path
    $actualPath = ""
    $commandLine = ""
    try { $actualPath = $proc.Path } catch { $actualPath = "" }
    try {
      $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)").CommandLine
    } catch { $commandLine = "" }
    $isManaged = (
      ($actualPath -and ($actualPath -ieq $expectedPython)) -or
      ($commandLine -and $commandLine.Contains($expectedPython) -and $commandLine.Contains("uvicorn app:app"))
    )
    [pscustomobject]@{
      Process = $proc
      IsManagedPython = $isManaged
      Path = $actualPath
      CommandLine = $commandLine
    }
  } catch {
    return $null
  }
}

function Stop-ExistingServer {
  param([int]$Port)
  $listener = Get-ManagedListener -Port $Port
  if ($listener -and -not $listener.IsManagedPython) {
    throw "Port $Port is used by an unmanaged process; refusing to stop it."
  }
  # On Windows the venv launcher and the listening Python process can be different.
  # Verify the PID-file entry before stopping it: stale/reused PIDs are not authority.
  $targets = @()
  if ($listener) { $targets += $listener.Process }
  $raw = ""
  if (Test-Path $PidFile) {
    $raw = (Get-Content -LiteralPath $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  }
  $pidValue = 0
  if ($raw -and [int]::TryParse($raw, [ref]$pidValue)) {
    $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($proc) {
      $info = Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue"
      $expectedPython = (Resolve-Path -LiteralPath $Python).Path
      $commandLine = [string]$info.CommandLine
      if ($commandLine.Contains($expectedPython) -and $commandLine.Contains("uvicorn app:app") -and $commandLine -match "--port\s+$Port(?:\s|$)") {
        $targets += $proc
      } else {
        Write-Warning "Ignoring stale PID file: process $pidValue is not this managed server."
      }
    }
  }
  foreach ($target in ($targets | Sort-Object Id -Unique)) {
    if (Get-Process -Id $target.Id -ErrorAction SilentlyContinue) {
      Write-Host "Stopping managed PQC server process $($target.Id)"
      Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue
    }
  }
  if ($targets.Count) { Start-Sleep -Seconds 1 }

  Remove-Item -LiteralPath $PidFile -ErrorAction SilentlyContinue
}

function Wait-ForHealth {
  param([string]$BaseUrl)
  for ($i = 1; $i -le 45; $i++) {
    try {
      $res = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/health" -TimeoutSec 3
      if ($res.StatusCode -ge 200 -and $res.StatusCode -lt 300) { return $true }
    } catch {
      Start-Sleep -Seconds 1
    }
  }
  return $false
}

if (-not (Test-Path $Python)) {
  throw "Python virtualenv not found: $Python. Create it and run pip install -r backend\requirements.txt."
}

Import-EnvFile -Path $EnvPath

if ($Restart) {
  Stop-ExistingServer -Port $Port
}

$BaseUrl = "http://127.0.0.1:$Port"

if ($Foreground) {
  Write-Host "Starting PQC Scanner in foreground: $BaseUrl"
  Push-Location $BackendDir
  try {
    & $Python -m uvicorn app:app --host 127.0.0.1 --port $Port --log-level info
  } finally {
    Pop-Location
  }
  exit $LASTEXITCODE
}

Remove-Item -LiteralPath $OutLog,$ErrLog -ErrorAction SilentlyContinue

$argList = @(
  "-m", "uvicorn", "app:app",
  "--host", "127.0.0.1",
  "--port", [string]$Port,
  "--log-level", "info"
)

$proc = Start-Process -FilePath $Python `
  -ArgumentList $argList `
  -WorkingDirectory $BackendDir `
  -RedirectStandardOutput $OutLog `
  -RedirectStandardError $ErrLog `
  -PassThru `
  -WindowStyle Hidden

Set-Content -LiteralPath $PidFile -Value ([string]$proc.Id)
Write-Host "Started PQC Scanner process $($proc.Id). Waiting for $BaseUrl/health ..."

if (Wait-ForHealth -BaseUrl $BaseUrl) {
  Write-Host "Ready: $BaseUrl"
  Write-Host "Logs: $OutLog"
  Write-Host "Errors: $ErrLog"
  exit 0
}

Write-Host "Server did not become healthy. Last logs:"
if (Test-Path $ErrLog) { Get-Content -LiteralPath $ErrLog -Tail 80 }
if (Test-Path $OutLog) { Get-Content -LiteralPath $OutLog -Tail 80 }
exit 1
