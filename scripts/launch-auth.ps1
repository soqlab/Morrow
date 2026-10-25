# Launch checks must never silently skip privileged verification.
function Get-LaunchRequestParameters {
  param([string]$BaseUrl, [string]$PlatformKey, [string]$OperatorSession)
  $uri = $null
  if (-not [uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$uri) -or
      $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne "/") {
    throw "Use an absolute deployment origin without credentials, path, query or fragment."
  }
  $loopback = $uri.Host -in @("localhost", "127.0.0.1", "::1", "[::1]")
  if ($uri.Scheme -ne "https" -and -not ($loopback -and $uri.Scheme -eq "http")) {
    throw "Remote deployment checks require HTTPS."
  }
  $headers = @{}
  $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  if ($OperatorSession) {
    if ($OperatorSession -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid operator session format." }
    # Windows PowerShell ignores Cookie in -Headers; use its actual cookie jar.
    $cookie = New-Object System.Net.Cookie("morrow_admin_session", $OperatorSession, "/", $uri.Host)
    $cookie.Secure = $uri.Scheme -eq "https"
    $cookie.HttpOnly = $true
    $session.Cookies.Add($cookie)
  } elseif ($PlatformKey) {
    if ($PlatformKey -match '[\r\n]') { throw "Invalid operator key format." }
    $headers["x-platform-key"] = $PlatformKey
  } else {
    throw "Operator authentication is required: set MORROW_OPERATOR_SESSION after SSO/MFA or supply an authorized named operator key. No launch checks were skipped."
  }
  return @{ Headers = $headers; WebSession = $session }
}

function Test-LaunchGatePassed {
  param($Gate)
  return ($Gate.go_live_allowed -is [bool] -and $Gate.go_live_allowed -eq $true -and
    $Gate.status -eq "go" -and $Gate.required_failed -eq 0 -and
    $Gate.failed_required_checks.Count -eq 0 -and $Gate.warnings.Count -eq 0)
}

function Invoke-LaunchScript {
  param([string]$ScriptPath, [string[]]$Arguments, [string]$PlatformKey, [string]$OperatorSession)
  $previousKey = $env:MORROW_PLATFORM_ADMIN_KEY
  $previousSession = $env:MORROW_OPERATOR_SESSION
  try {
    # Child processes inherit credentials privately, never through command arguments.
    $env:MORROW_PLATFORM_ADMIN_KEY = $PlatformKey
    $env:MORROW_OPERATOR_SESSION = $OperatorSession
    $shell = (Get-Process -Id $PID).Path
    & $shell -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Launch subprocess failed: $(Split-Path $ScriptPath -Leaf) (exit $LASTEXITCODE)" }
  } finally {
    $env:MORROW_PLATFORM_ADMIN_KEY = $previousKey
    $env:MORROW_OPERATOR_SESSION = $previousSession
  }
}
