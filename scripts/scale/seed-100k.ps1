# Seed a 100,000-asset SQLite database as five bounded runs of 20,000 assets each.
# Each slice is its own process (about 15 minutes on a 4-core laptop), and together they write
# exactly what one full run would (see seed.py --start/--stop).
#
#   powershell -File scripts\scale\seed-100k.ps1 -Database C:\path\to\scale-100k.db [-Python path\to\python.exe]
param(
    [Parameter(Mandatory = $true)][string]$Database,
    [string]$Python = "python",
    [int]$Assets = 100000,
    [int]$Slice = 20000
)
$ErrorActionPreference = "Stop"
$backend = Join-Path $PSScriptRoot "..\..\backend"
Push-Location $backend
try {
    for ($start = 0; $start -lt $Assets; $start += $Slice) {
        $stop = [Math]::Min($start + $Slice, $Assets)
        Write-Host "== slice $start..$stop"
        & $Python ..\scripts\scale\seed.py --assets $Assets --db $Database --start $start --stop $stop
        if ($LASTEXITCODE -ne 0) { throw "slice $start..$stop failed ($LASTEXITCODE)" }
    }
} finally {
    Pop-Location
}
