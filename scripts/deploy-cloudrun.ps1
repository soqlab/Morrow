param(
  [string]$ProjectId = "pqc-scanner-2026",
  [string]$Region = "europe-west1",
  [string]$Repository = "pqc-containers",
  [string]$ImageName = "backend",
  [string]$ApiService = "pq-api",
  [string]$WorkerPool = "pq-worker",
  [string]$BeatPool = "pq-beat",
  [string]$Tag = ("deploy-" + (Get-Date -Format "yyyyMMdd-HHmmss")),
  [string]$PlatformKey = $env:MORROW_PLATFORM_ADMIN_KEY,
  [switch]$SkipBuild,
  [switch]$SkipSmoke,
  [switch]$UpdateTfvars
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Script
  )
  Write-Host "==> $Name"
  & $Script
}

$Image = "$Region-docker.pkg.dev/$ProjectId/$Repository/$ImageName`:$Tag"

Invoke-Step "Checking tools" {
  gcloud --version | Out-Null
}

if (-not $SkipBuild) {
  Invoke-Step "Building and pushing $Image" {
    gcloud builds submit backend --tag $Image --project $ProjectId
  }
}

Invoke-Step "Deploying API service $ApiService" {
  gcloud run services update $ApiService --image $Image --region $Region --project $ProjectId --quiet
}

Invoke-Step "Deploying worker pool $WorkerPool" {
  gcloud run worker-pools deploy $WorkerPool --image $Image --region $Region --project $ProjectId --quiet
}

Invoke-Step "Deploying worker pool $BeatPool" {
  gcloud run worker-pools deploy $BeatPool --image $Image --region $Region --project $ProjectId --quiet
}

$Digest = ""
try {
  $Digest = gcloud artifacts docker images describe $Image --project $ProjectId --format "value(image_summary.digest)"
} catch {
  Write-Warning "Could not resolve image digest for $Image"
}

if ($UpdateTfvars -and $Digest) {
  $DigestImage = "$Region-docker.pkg.dev/$ProjectId/$Repository/$ImageName@$Digest"
  $TfvarsPath = "infra/gcp/cloudrun/terraform.tfvars"
  if (Test-Path $TfvarsPath) {
    Invoke-Step "Updating $TfvarsPath image digest" {
      (Get-Content $TfvarsPath) -replace '^image\s*=.*$', "image = `"$DigestImage`"" | Set-Content $TfvarsPath
    }
  }
}

$Url = ""
try {
  $Url = gcloud run services describe $ApiService --region $Region --project $ProjectId --format "value(status.url)"
} catch {
  Write-Warning "Could not resolve Cloud Run service URL for $ApiService"
}

if (-not $SkipSmoke) {
  if (-not $Url) { throw "Cloud Run service URL is unavailable; cannot run smoke tests." }

  Invoke-Step "Smoke testing health" {
    $Health = curl.exe -fsS "$Url/health"
    if ($Health -notmatch '"status"\s*:\s*"ok"') {
      throw "Health check failed: $Health"
    }
  }

  Invoke-Step "Smoke testing UI" {
    $Headers = curl.exe -fsS -D - "$Url/ui/" -o NUL
    if (($Headers -join "`n") -notmatch "200") {
      throw "UI did not return HTTP 200"
    }
  }

  if ($PlatformKey) {
    Invoke-Step "Verifying production go-live gate" {
      powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-cloud-deployment.ps1 -BaseUrl $Url -PlatformKey $PlatformKey
      if ($LASTEXITCODE -ne 0) { throw "verify-cloud-deployment exited $LASTEXITCODE" }
    }
  } else {
    Write-Warning "Skipping go-live gate verification because no PlatformKey was provided."
  }
}

Write-Host "Deployed image: $Image"
if ($Digest) {
  Write-Host "Digest: $Digest"
}
if ($Url) {
  Write-Host "URL: $Url"
}
