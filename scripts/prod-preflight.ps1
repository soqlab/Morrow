param(
  [string]$EnvFile = "backend\.env",
  [switch]$Strict,
  [switch]$Json
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvPath = Join-Path $RepoRoot $EnvFile
$Findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
  param(
    [ValidateSet("blocker", "warning", "ok")]
    [string]$Severity,
    [string]$Check,
    [string]$Detail,
    [string]$Fix = ""
  )
  $Findings.Add([pscustomobject]@{
    severity = $Severity
    check = $Check
    detail = $Detail
    fix = $Fix
  })
}

function Read-EnvFile {
  param([string]$Path)
  $map = @{}
  if (-not (Test-Path $Path)) { return $map }
  foreach ($line in Get-Content -LiteralPath $Path) {
    $trim = $line.TrimStart([char]0xFEFF).Trim()  # tolerate a UTF-8 BOM even where Get-Content keeps it
    if (-not $trim -or $trim.StartsWith("#") -or -not $trim.Contains("=")) { continue }
    $parts = $trim -split "=", 2
    $map[$parts[0].Trim()] = $parts[1].Trim().Trim('"').Trim("'")
  }
  $map
}

function Test-Truthy {
  param([string]$Value)
  if ($null -eq $Value) { return $false }
  $Value.Trim().ToLowerInvariant() -in @("1", "true", "yes", "on")
}

$envMap = Read-EnvFile -Path $EnvPath
if (-not (Test-Path $EnvPath)) {
  Add-Finding blocker "env_file" "Environment file not found: $EnvFile" "Create one from backend\.env.production.example or backend\.env.local.example."
} else {
  Add-Finding ok "env_file" "Found $EnvFile"
}

$required = @(
  "PQC_VAULT_MASTER_KEY",
  "PQC_PLATFORM_ADMIN_KEY",
  "PQC_AUTH_REQUIRED",
  "PQC_AUTH_MODE",
  "PQC_AUTH_ISSUER_ENABLED",
  "PQC_DEFAULT_ROLE",
  "PQC_ALLOWED_HOSTS",
  "PQC_AIRLOCK_SIGNING_KEY",
  "PQC_AIRLOCK_REQUIRE_AGENT_SIGNATURE"
)
foreach ($key in $required) {
  if (-not $envMap.ContainsKey($key) -or -not $envMap[$key]) {
    Add-Finding blocker "required_env:$key" "$key is missing" "Set $key before go-live."
  }
}

$environment = [string]$envMap["PQC_ENVIRONMENT"]
if ($environment -notin @("staging", "prod", "production")) {
  Add-Finding blocker "environment" "PQC_ENVIRONMENT is not staging/production" "Set PQC_ENVIRONMENT=production before go-live."
} else {
  Add-Finding ok "environment" "Environment is $environment."
}

if (($envMap["PQC_AUTH_REQUIRED"] -as [string]) -ne "1") {
  Add-Finding blocker "auth_required" "PQC_AUTH_REQUIRED is not 1" "Set PQC_AUTH_REQUIRED=1."
} else {
  Add-Finding ok "auth_required" "Authentication is required."
}

if (($envMap["PQC_AUTH_MODE"] -as [string]) -ne "jwt") {
  Add-Finding blocker "auth_mode" "PQC_AUTH_MODE is not jwt" "Use PQC_AUTH_MODE=jwt for production."
} else {
  Add-Finding ok "auth_mode" "JWT auth mode configured."
}

foreach ($key in @("PQC_AUTH_JWT_ISSUER", "PQC_AUTH_JWT_AUDIENCE", "PQC_AUTH_JWT_JWKS_URL")) {
  if (-not ([string]$envMap[$key])) {
    Add-Finding blocker "jwt:$key" "$key is missing" "Configure hosted JWT provider metadata."
  }
}

$jwtAlgorithms = [string]$envMap["PQC_AUTH_JWT_ALGORITHMS"]
if (-not $jwtAlgorithms) { $jwtAlgorithms = "RS256" }
$jwtAlgorithmList = @($jwtAlgorithms.Split(",") | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ })
$issuerEnabled = Test-Truthy ([string]$envMap["PQC_AUTH_ISSUER_ENABLED"])
$jwtSecret = [string]$envMap["PQC_AUTH_JWT_SECRET"]
if (Test-Truthy ([string]$envMap["PQC_JWT_ALLOW_NO_EXP"])) {
  Add-Finding blocker "jwt_expiry" "Non-expiring tokens are enabled" "Unset PQC_JWT_ALLOW_NO_EXP."
}
if (Test-Truthy ([string]$envMap["PQC_ALLOW_UNSAFE_PRODUCTION_STARTUP"])) {
  Add-Finding blocker "startup_override" "Unsafe startup override is enabled" "Set PQC_ALLOW_UNSAFE_PRODUCTION_STARTUP=0."
}
if (@($jwtAlgorithmList | Where-Object { $_ -notin @("RS256", "HS256") }).Count -or -not $jwtAlgorithmList.Count) {
  Add-Finding blocker "jwt_algorithms" "JWT algorithm list contains unsupported algorithms" "Use RS256; the verifier implements RS256 and explicitly approved HS256 only."
}
foreach ($key in @("PQC_PUBLIC_BASE_URL", "PQC_AUTH_JWT_JWKS_URL", "PQC_ADMIN_OIDC_ISSUER")) {
  $uri = $null
  if (-not [uri]::TryCreate([string]$envMap[$key], [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne "https" -or $uri.UserInfo -or $uri.Fragment) {
    Add-Finding blocker "https:$key" "$key must be a credential-free HTTPS URL" "Configure the actual production URL."
  }
}
if (-not ([string]$envMap["PQC_ADMIN_OIDC_CLIENT_ID"])) {
  Add-Finding blocker "operator_sso" "Operator SSO client ID is missing" "Set PQC_ADMIN_OIDC_CLIENT_ID and register /vendor-admin/sso/callback at your IdP."
}
if (-not ([string]$envMap["PQC_ADMIN_OPERATOR_ROLES"]) -and -not ([string]$envMap["PQC_ADMIN_OIDC_ALLOWED_DOMAINS"])) {
  Add-Finding blocker "operator_roster" "No operator SSO roster or approved domain is configured" "Set PQC_ADMIN_OPERATOR_ROLES to your authorized staff and roles."
}
if (([string]$envMap["PQC_ADMIN_REQUIRE_MFA"]) -match "^(0|false|no|off)$") {
  Add-Finding blocker "operator_mfa" "Operator MFA is disabled" "Set PQC_ADMIN_REQUIRE_MFA=1."
}
if (Test-Truthy ([string]$envMap["PQC_ALLOW_BREAK_GLASS_KEY"])) {
  Add-Finding blocker "break_glass" "Shared-key emergency access is enabled" "Set PQC_ALLOW_BREAK_GLASS_KEY=0 before launch."
}
if ($issuerEnabled -and -not $jwtSecret) {
  Add-Finding blocker "auth_issuer_secret" "PQC_AUTH_ISSUER_ENABLED=1 but PQC_AUTH_JWT_SECRET is missing" "Set a stable token signing secret or set PQC_AUTH_ISSUER_ENABLED=0 for external IdP deployments."
}
if ($issuerEnabled -and -not (Test-Truthy ([string]$envMap["PQC_ALLOW_HS256_IN_PRODUCTION"]))) {
  Add-Finding blocker "auth_issuer_hs256" "Built-in password issuer requires HS256 but HS256 is not explicitly allowed" "Prefer PQC_AUTH_ISSUER_ENABLED=0 with RS256/JWKS. Only set PQC_ALLOW_HS256_IN_PRODUCTION=1 with a documented exception."
}
if ($jwtAlgorithmList -contains "HS256" -and -not (Test-Truthy ([string]$envMap["PQC_ALLOW_HS256_IN_PRODUCTION"]))) {
  Add-Finding blocker "jwt_hs256" "PQC_AUTH_JWT_ALGORITHMS includes HS256 without an explicit production exception" "Use RS256/JWKS or set PQC_ALLOW_HS256_IN_PRODUCTION=1 with a documented exception."
}

if (($envMap["PQC_DEFAULT_ROLE"] -as [string]) -ne "viewer") {
  Add-Finding blocker "default_role" "PQC_DEFAULT_ROLE is not viewer" "Set PQC_DEFAULT_ROLE=viewer."
} else {
  Add-Finding ok "default_role" "Default role is viewer."
}

if (Test-Truthy ([string]$envMap["PQC_CORS_ALLOW_ALL"])) {
  Add-Finding blocker "cors" "PQC_CORS_ALLOW_ALL=1" "Set explicit PQC_CORS_ORIGINS for production."
}
if (-not ([string]$envMap["PQC_CORS_ORIGINS"]) -and -not (Test-Truthy ([string]$envMap["PQC_CORS_ALLOW_ALL"]))) {
  Add-Finding blocker "cors_origins" "PQC_CORS_ORIGINS is missing" "Set the exact production origin(s)."
}

$allowedHosts = [string]$envMap["PQC_ALLOWED_HOSTS"]
if (-not $allowedHosts) {
  Add-Finding blocker "allowed_hosts" "PQC_ALLOWED_HOSTS is missing" "Set the exact production app/admin/API hostnames."
} elseif (@($allowedHosts.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq "*" }).Count -gt 0) {
  Add-Finding blocker "allowed_hosts" "PQC_ALLOWED_HOSTS contains wildcard '*'" "Replace wildcard hosts with exact production hostnames."
} else {
  Add-Finding ok "allowed_hosts" "Allowed hosts are explicit."
}

$dbUrl = [string]$envMap["PQC_PRODUCT_DATABASE_URL"]
if (-not $dbUrl) {
  $dbUrl = [string]$envMap["DATABASE_URL"]
}
if ($dbUrl -notmatch "^postgres(?:ql)?://") {
  Add-Finding blocker "database" "Production database URL is not Postgres" "Use managed Postgres and set PQC_PRODUCT_DATABASE_URL."
} elseif ($dbUrl -match "localhost|127\.0\.0\.1|postgres:5432|pqc:pqc") {
  Add-Finding blocker "database_nonprod" "Database URL looks local or default" "Use a managed production Postgres DSN with a least-privilege runtime role."
} else {
  Add-Finding ok "database" "Postgres DSN is configured."
}

foreach ($key in @("CELERY_BROKER_URL", "CELERY_RESULT_BACKEND")) {
  $value = [string]$envMap[$key]
  if (-not $value) {
    Add-Finding blocker "redis:$key" "$key is missing" "Use managed Redis for durable background work."
  } elseif ($value -notmatch "^rediss?://") {
    Add-Finding blocker "redis:$key" "$key is not a Redis URL" "Use managed Redis for durable background work."
  } elseif ($value -notmatch "^rediss?://[^/@]*:[^@]+@") {
    Add-Finding blocker "redis_password:$key" "$key has no Redis password" "Use redis://:PASSWORD@host:6379/db."
  } elseif ($value -match "^rediss://" -and $value -notmatch "[?&]ssl_cert_reqs=(required|CERT_REQUIRED)(&|$)") {
    Add-Finding blocker "redis_tls:$key" "$key must validate the Redis TLS certificate" "Set ssl_cert_reqs=required in the rediss URL."
  } elseif ($value -match "localhost|127\.0\.0\.1|redis:6379") {
    Add-Finding warning "redis_nonprod:$key" "$key looks local/default" "Use managed Redis for production."
  } else {
    Add-Finding ok "redis:$key" "$key is configured with authentication."
  }
}

if (Test-Truthy ([string]$envMap["PQC_ALLOW_PLATFORM_KEY_QUERY"])) {
  Add-Finding blocker "platform_key_query" "PQC_ALLOW_PLATFORM_KEY_QUERY=1" "Platform keys must only be accepted in headers in production."
}
if (Test-Truthy ([string]$envMap["PQC_ALLOW_DEMO_IN_PRODUCTION"])) {
  Add-Finding blocker "demo_mode" "Demo mode is enabled in production" "Set PQC_ALLOW_DEMO_IN_PRODUCTION=0."
}
if (($envMap["PQC_CSP_ENABLED"] -as [string]) -eq "0") {
  Add-Finding blocker "csp" "CSP is disabled" "Set PQC_CSP_ENABLED=1 and configure PQC_CSP_VALUE."
}
if (-not ([string]$envMap["PQC_CSP_VALUE"])) {
  Add-Finding warning "csp_value" "PQC_CSP_VALUE is missing" "Set an explicit Content-Security-Policy before internet exposure."
}
if (-not ([string]$envMap["SENTRY_DSN"])) {
  Add-Finding warning "sentry" "SENTRY_DSN is missing" "Configure runtime exception reporting before launch."
}

if (($envMap["PQC_TRAFFIC_MONITOR_ENABLED"] -as [string]) -eq "0") {
  Add-Finding warning "traffic_monitor" "PQC_TRAFFIC_MONITOR_ENABLED=0" "Keep the admin traffic monitor enabled for launch operations."
} else {
  Add-Finding ok "traffic_monitor" "Admin traffic monitor is enabled or using the secure default."
}
if (($envMap["PQC_TRAFFIC_PERSIST_TO_DB"] -as [string]) -ne "1") {
  Add-Finding warning "traffic_persistence" "PQC_TRAFFIC_PERSIST_TO_DB is not 1" "Set PQC_TRAFFIC_PERSIST_TO_DB=1 to persist admin traffic metadata into Postgres for SIEM export."
} else {
  Add-Finding ok "traffic_persistence" "Admin traffic metadata persistence is enabled."
}
Add-Finding ok "proxy_headers" "Forwarded-header trust must match the deployed edge; leaving it off is a safe default."

$replicasRaw = [string]$envMap["PQC_API_REPLICA_COUNT"]
if (-not $replicasRaw) { $replicasRaw = "1" }
$replicas = 1
[void][int]::TryParse($replicasRaw, [ref]$replicas)
if ($replicas -gt 1 -and -not (Test-Truthy ([string]$envMap["PQC_AUXILIARY_STATE_MIGRATED"]))) {
  Add-Finding blocker "api_replicas" "PQC_API_REPLICA_COUNT=$replicas but auxiliary SQLite state is not marked migrated" "Keep one API replica or complete auxiliary state migration and set PQC_AUXILIARY_STATE_MIGRATED=1."
} else {
  Add-Finding ok "api_replicas" "API replica count is compatible with current state backend."
}

$airlockSigningKey = [string]$envMap["PQC_AIRLOCK_SIGNING_KEY"]
if (-not $airlockSigningKey) {
  Add-Finding blocker "airlock_signing_key" "PQC_AIRLOCK_SIGNING_KEY is missing" "Generate a production-only Airlock signing key."
} elseif ($airlockSigningKey.Length -lt 32) {
  Add-Finding blocker "airlock_signing_key_length" "PQC_AIRLOCK_SIGNING_KEY is shorter than 32 characters" "Use at least 32 random bytes/64 hex characters."
} else {
  Add-Finding ok "airlock_signing_key" "Airlock signing key is configured."
}

if (-not (Test-Truthy ([string]$envMap["PQC_AIRLOCK_REQUIRE_AGENT_SIGNATURE"]))) {
  Add-Finding blocker "airlock_agent_signatures" "Airlock agent signatures are not required" "Set PQC_AIRLOCK_REQUIRE_AGENT_SIGNATURE=1 in production."
} else {
  Add-Finding ok "airlock_agent_signatures" "Airlock agent signatures are required."
}

Add-Finding ok "ai_policy" "AI is optional and off by default; enabling it requires organization approval and a configured destination."

foreach ($entry in $envMap.GetEnumerator()) {
  $value = [string]$entry.Value
  if (-not $value) { continue }
  if ($value -match "(?i)(change[_-]?me|replace[_-]?with|your[_-]|placeholder|example|test-only|user:password@host|password@host|sk-ant-change_me|sk-change_me)") {
    Add-Finding blocker "placeholder:$($entry.Key)" "$($entry.Key) still contains a template or placeholder value" "Replace every placeholder before go-live."
  }
}

foreach ($name in @("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "PQC_PLATFORM_ADMIN_KEY", "PQC_AIRLOCK_SIGNING_KEY", "REDIS_PASSWORD", "PQC_VAULT_MASTER_KEY", "PQC_AUTH_JWT_SECRET", "PQC_ADMIN_PASSWORD")) {
  $value = [string]$envMap[$name]
  if (-not $value) { continue }
  if ($value -match "(?i)(change[_-]?me|replace[_-]?with|example|placeholder|test-only)") {
    Add-Finding blocker "secret_placeholder:$name" "$name looks like a placeholder" "Generate a new production secret."
  }
  if ($name -eq "OPENAI_API_KEY" -and $value -match "^sk-") {
    Add-Finding warning "secret_rotation:$name" "$name contains a live-looking API key in a local env file" "Rotate it if this file was shared, committed, logged, or exposed."
  }
  if ($Strict -and $value -match "local|dev|test|demo|pqc|scanner") {
    Add-Finding warning "strict_secret_name:$name" "$name contains a development-looking token" "Use a fresh production-only secret."
  }
}

if (([string]$envMap["PQC_PLATFORM_ADMIN_KEY"]).Length -lt 32) {
  Add-Finding blocker "platform_key_length" "PQC_PLATFORM_ADMIN_KEY is shorter than 32 characters" "Generate a long random platform admin key."
}

if ([string]$envMap["REDIS_PASSWORD"] -and ([string]$envMap["REDIS_PASSWORD"]).Length -lt 24) {
  Add-Finding blocker "redis_password_length" "REDIS_PASSWORD is shorter than 24 characters" "Generate a long random Redis password."
}

if ([string]$envMap["PQC_AUTH_JWT_SECRET"] -and ([string]$envMap["PQC_AUTH_JWT_SECRET"]).Length -lt 32) {
  Add-Finding blocker "jwt_secret_length" "PQC_AUTH_JWT_SECRET is shorter than 32 characters" "Generate a stable random token signing secret."
}

$trackedEnv = git -C $RepoRoot ls-files "backend/.env" ".env" ".env.prod" 2>$null
if ($trackedEnv) {
  Add-Finding blocker "tracked_env" "A real env file is tracked by git: $trackedEnv" "Remove it from git history and rotate secrets."
} else {
  Add-Finding ok "tracked_env" "Real env files are not tracked."
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($docker) {
  Add-Finding ok "docker" "Docker CLI is installed."
} else {
  Add-Finding warning "docker" "Docker CLI not found" "Install Docker Desktop for compose-based production parity."
}

$summary = [pscustomobject]@{
  status = if (@($Findings | Where-Object severity -eq "blocker").Count -gt 0) { "block" } elseif (@($Findings | Where-Object severity -eq "warning").Count -gt 0) { "warn" } else { "pass" }
  blockers = @($Findings | Where-Object severity -eq "blocker").Count
  warnings = @($Findings | Where-Object severity -eq "warning").Count
  checks = $Findings
}

if ($Json) {
  $summary | ConvertTo-Json -Depth 8
} else {
  Write-Host "Production preflight: $($summary.status) ($($summary.blockers) blocker(s), $($summary.warnings) warning(s))"
  foreach ($finding in $Findings) {
    $prefix = if ($finding.severity -eq "blocker") { "[BLOCK]" } elseif ($finding.severity -eq "warning") { "[WARN]" } else { "[ OK ]" }
    Write-Host "$prefix $($finding.check): $($finding.detail)"
    if ($finding.fix) { Write-Host "       Fix: $($finding.fix)" }
  }
}

if ($summary.blockers -gt 0) { exit 1 }
if ($Strict -and $summary.warnings -gt 0) { exit 1 }
exit 0
