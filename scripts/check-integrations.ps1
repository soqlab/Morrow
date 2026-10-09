param(
  [string]$EnvFile = "",
  [switch]$Offline,
  [switch]$SendTest,
  [switch]$CheckAi,
  [switch]$Json,
  [string]$Only = ""
)

# Thin wrapper around scripts/check-integrations.py so the self-test runs the same way as the other
# go-live scripts here (prod-preflight.ps1, check-go-live-gate.ps1). The checks, the report and the
# exit codes all live in the Python file; this only picks the interpreter and forwards the flags.
#   0  nothing is broken
#   1  something configured is failing
#   2  a required production setting is missing

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot "backend"
$Script = Join-Path $PSScriptRoot "check-integrations.py"

$Python = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
  $found = Get-Command python -ErrorAction SilentlyContinue
  if (-not $found) { Write-Error "No Python found. Create backend\.venv or put python on PATH." }
  $Python = $found.Source
}

$argv = @($Script)
if ($EnvFile) { $argv += @("--env-file", $EnvFile) }
if ($Offline) { $argv += "--offline" }
if ($SendTest) { $argv += "--send-test" }
if ($CheckAi) { $argv += "--check-ai" }
if ($Json) { $argv += "--json" }
if ($Only) { $argv += @("--only", $Only) }

& $Python @argv
exit $LASTEXITCODE
