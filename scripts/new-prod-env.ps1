param(
  [string]$Template = ".env.prod.example",
  [string]$OutFile = ".env.prod",
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TemplatePath = Join-Path $RepoRoot $Template
$OutPath = Join-Path $RepoRoot $OutFile

if (-not (Test-Path -LiteralPath $TemplatePath)) {
  throw "Template not found: $Template"
}
if ((Test-Path -LiteralPath $OutPath) -and -not $Force) {
  throw "$OutFile already exists. Re-run with -Force to overwrite it."
}

function New-RandomBytes {
  param([int]$Count)
  $bytes = New-Object byte[] $Count
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
  } finally {
    $rng.Dispose()
  }
  return $bytes
}

function ConvertTo-UrlSafeBase64 {
  param(
    [byte[]]$Bytes,
    [switch]$TrimPadding
  )
  $value = [Convert]::ToBase64String($Bytes).Replace("+", "-").Replace("/", "_")
  if ($TrimPadding) { $value = $value.TrimEnd("=") }
  return $value
}

function New-TokenUrlSafe {
  param([int]$Bytes = 48)
  ConvertTo-UrlSafeBase64 -Bytes (New-RandomBytes -Count $Bytes) -TrimPadding
}

function New-HexSecret {
  param([int]$Bytes = 32)
  -join ((New-RandomBytes -Count $Bytes) | ForEach-Object { $_.ToString("x2") })
}

$redisPassword = New-TokenUrlSafe -Bytes 32
$generated = @{
  "MORROW_AUTH_ISSUER_ENABLED"       = "0"
  "MORROW_ALLOW_HS256_IN_PRODUCTION" = "0"
  "MORROW_AUTH_JWT_SECRET"           = New-HexSecret -Bytes 32
  "MORROW_ADMIN_PASSWORD"            = New-TokenUrlSafe -Bytes 32
  "MORROW_VAULT_MASTER_KEY"          = ConvertTo-UrlSafeBase64 -Bytes (New-RandomBytes -Count 32)
  "MORROW_PLATFORM_ADMIN_KEY"        = New-TokenUrlSafe -Bytes 48
  "MORROW_AIRLOCK_SIGNING_KEY"       = New-HexSecret -Bytes 32
  "MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE" = "1"
  "MORROW_AIRLOCK_MAX_CLOCK_SKEW_SECONDS" = "600"
  "REDIS_PASSWORD"                = $redisPassword
  "CELERY_BROKER_URL"             = "redis://:$redisPassword@redis:6379/0"
  "CELERY_RESULT_BACKEND"         = "redis://:$redisPassword@redis:6379/1"
  "MORROW_CORS_ALLOW_ALL"            = "0"
  "MORROW_CSP_ENABLED"               = "1"
  "MORROW_API_REPLICA_COUNT"         = "1"
  "MORROW_AUXILIARY_STATE_MIGRATED"  = "0"
  "MORROW_TRAFFIC_MONITOR_ENABLED"   = "1"
  "MORROW_TRAFFIC_PERSIST_TO_DB"     = "1"
  "MORROW_ALLOW_UNSAFE_PRODUCTION_STARTUP" = "0"
  "MORROW_ALLOW_DEMO_IN_PRODUCTION"        = "0"
  "MORROW_ALLOW_PLATFORM_KEY_QUERY"        = "0"
}

$seen = @{}
$lines = Get-Content -LiteralPath $TemplatePath
$out = foreach ($line in $lines) {
  $match = [regex]::Match($line, "^\s*#?\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)=(?<value>.*)$")
  if ($match.Success -and $generated.ContainsKey($match.Groups["name"].Value)) {
    $name = $match.Groups["name"].Value
    $seen[$name] = $true
    "$name=$($generated[$name])"
  } else {
    $line
  }
}

foreach ($name in $generated.Keys | Sort-Object) {
  if (-not $seen.ContainsKey($name)) {
    $out += "$name=$($generated[$name])"
  }
}

[System.IO.File]::WriteAllText($OutPath, ($out -join [Environment]::NewLine) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

$manual = New-Object System.Collections.Generic.List[string]
foreach ($line in $out) {
  $match = [regex]::Match($line, "^\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)=(?<value>.*)$")
  if (-not $match.Success) { continue }
  $name = $match.Groups["name"].Value
  $value = $match.Groups["value"].Value
  if ($value -match "(?i)(change[_-]?me|replace[_-]?with|your[_-]|your-app|your-project|user:password@host|password@host)") {
    $manual.Add($name)
  }
}

Write-Host "Wrote $OutFile with generated local secrets."
if ($manual.Count -gt 0) {
  Write-Host "Still requires production values:"
  foreach ($name in ($manual | Sort-Object -Unique)) {
    Write-Host "- $name"
  }
}
Write-Host "Next check:"
Write-Host "  .\scripts\prod-preflight.ps1 -EnvFile $OutFile -Strict"
