[CmdletBinding()]
param(
  [ValidateSet('Prepare', 'Start', 'Stop', 'Status')]
  [string]$Action = 'Start',
  [string]$GestionChurchRoot = 'X:\CODE\GestionChurch',
  [switch]$NoPrepare,
  [ValidateRange(15, 300)]
  [int]$TimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $repositoryRoot '.local\gestionchurch-module'
$pidFile = Join-Path $runtimeRoot 'processes.json'
$apiLog = Join-Path $runtimeRoot 'api.log'
$apiErrorLog = Join-Path $runtimeRoot 'api-error.log'
$workerLog = Join-Path $runtimeRoot 'worker.log'
$workerErrorLog = Join-Path $runtimeRoot 'worker-error.log'
$webLog = Join-Path $runtimeRoot 'web.log'
$webErrorLog = Join-Path $runtimeRoot 'web-error.log'
$workerStopFile = Join-Path $repositoryRoot '.local\provisioning-worker.stop'
$installPath = Join-Path $repositoryRoot 'packages\database\.local\install.json'
$gestionChurchEnvPath = Join-Path $GestionChurchRoot '.env'
$apiHealth = 'http://127.0.0.1:4100/healthz'
$webUrl = 'http://localhost:3300'
$webHealth = 'http://127.0.0.1:3300/healthz'
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

function Get-DotEnvValue([string]$Path, [string]$Name) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing environment file: $Path" }
  $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match ('^\s*' + [regex]::Escape($Name) + '\s*=') } | Select-Object -Last 1
  if ($null -eq $line) { throw "Missing $Name in $Path" }
  $value = ($line -split '=', 2)[1].Trim()
  if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
    $value = $value.Substring(1, $value.Length - 2)
  }
  if ([string]::IsNullOrWhiteSpace($value)) { throw "$Name cannot be empty." }
  return $value
}

function Set-ModuleEnvironment {
  if (-not (Test-Path -LiteralPath $installPath -PathType Leaf)) { throw "Nombramientos install metadata is missing: $installPath" }
  $install = Get-Content -Raw -LiteralPath $installPath | ConvertFrom-Json
  foreach ($property in $install.PSObject.Properties) {
    [Environment]::SetEnvironmentVariable($property.Name, [string]$property.Value, 'Process')
  }
  $sharedSecret = Get-DotEnvValue -Path $gestionChurchEnvPath -Name 'NOMINATIONS_INTEGRATION_SECRET'
  if ($sharedSecret.Length -lt 32) { throw 'NOMINATIONS_INTEGRATION_SECRET must contain at least 32 characters.' }
  $env:GESTIONCHURCH_MODULE_MODE = 'true'
  $env:GESTIONCHURCH_REDEEM_URL = 'http://127.0.0.1:4000/api/v1/integrations/nominations/redeem'
  $env:GESTIONCHURCH_AUTHORIZE_URL = 'http://127.0.0.1:4000/api/v1/integrations/nominations/authorize'
  $env:GESTIONCHURCH_ORGANIZATION_URL = 'http://127.0.0.1:4000/api/v1/integrations/nominations/organization'
  $env:GESTIONCHURCH_INTEGRATION_SECRET = $sharedSecret
  $env:GESTIONCHURCH_CONTROL_DATABASE_URL = 'postgresql://postgres@127.0.0.1:55432/gestionchurch_control'
  $env:API_HOST = '127.0.0.1'
  $env:API_PORT = '4100'
  $env:API_CORS_ORIGINS = 'http://localhost:3300'
  $env:WEBAUTHN_EXPECTED_ORIGINS = 'http://localhost:3300'
  $env:NEXT_PUBLIC_API_URL = 'http://localhost:4100'
  $env:NEXT_PUBLIC_GESTIONCHURCH_URL = 'http://localhost:3000'
  $env:NOMBRAMIENTOS_WEB_HOST = '127.0.0.1'
  $env:NOMBRAMIENTOS_WEB_PORT = '3300'
}

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
  Write-Output "[$(Get-Date -Format o)] $Label"
  & $Command
  if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE." }
}

function Invoke-Prepare {
  Set-ModuleEnvironment
  Push-Location $repositoryRoot
  try {
    Invoke-Checked 'Checking Nombramientos dependencies' { pnpm.cmd install --frozen-lockfile }
    Invoke-Checked 'Building the integrated Nombramientos module' { pnpm.cmd build }
    Invoke-Checked 'Migrating the Nombramientos control plane' { pnpm.cmd db:migrate }
    Invoke-Checked 'Synchronizing GestionChurch tenants' { pnpm.cmd db:sync:gestionchurch }
    Invoke-Checked 'Verifying the consolidated database state' { pnpm.cmd db:verify:local-state }
  }
  finally { Pop-Location }
}

function Get-ManagedProcesses {
  if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { return @() }
  try { $record = Get-Content -Raw -LiteralPath $pidFile | ConvertFrom-Json } catch { return @() }
  $found = @()
  foreach ($processProperty in @('workerPid', 'apiPid', 'webPid')) {
    $property = $record.PSObject.Properties[$processProperty]
    if ($null -eq $property) { continue }
    $processId = $property.Value
    if ($null -eq $processId) { continue }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue
    if ($null -ne $process -and -not [string]::IsNullOrWhiteSpace($process.CommandLine) -and $process.CommandLine.IndexOf($repositoryRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
      $found += $process
    }
  }
  return $found
}

function Test-Endpoint([string]$Uri) {
  try {
    $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 3
    return $response.StatusCode -ge 200 -and $response.StatusCode -lt 400
  } catch { return $false }
}

function Test-ApiReady {
  try {
    $health = Invoke-RestMethod -Uri $apiHealth -TimeoutSec 3
    return $health.status -eq 'ok' -and $health.worker.status -eq 'running' -and $health.worker.healthy -eq $true
  } catch { return $false }
}

function Stop-Module {
  $processes = @(Get-ManagedProcesses)
  if ($processes.Count -gt 0) {
    Set-Content -LiteralPath $workerStopFile -Value 'stop' -Encoding UTF8
    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $deadline -and @(Get-ManagedProcesses).Count -gt 2) {
      Start-Sleep -Milliseconds 250
    }
    $remaining = @(Get-ManagedProcesses)
    if ($remaining.Count -gt 0) {
      Stop-Process -Id ($remaining | Select-Object -ExpandProperty ProcessId) -Force -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 500
    }
  }
  if (Test-Path -LiteralPath $pidFile -PathType Leaf) { Remove-Item -LiteralPath $pidFile -Force }
  Remove-Item -LiteralPath $workerStopFile -Force -ErrorAction SilentlyContinue
  Write-Output 'Nombramientos module: STOPPED'
}

function Start-Module {
  if (-not $NoPrepare) { Invoke-Prepare }
  Set-ModuleEnvironment
  Stop-Module | Out-Null
  foreach ($log in @($workerLog, $workerErrorLog, $apiLog, $apiErrorLog, $webLog, $webErrorLog)) { Set-Content -LiteralPath $log -Value '' -Encoding UTF8 }
  $workerEntry = Join-Path $repositoryRoot 'packages\database\dist\scripts\process-provisioning-jobs.js'
  $apiEntry = Join-Path $repositoryRoot 'apps\api\dist\src\main.js'
  $webEntry = Join-Path $repositoryRoot 'apps\web\scripts\start-standalone.mjs'
  $worker = Start-Process -FilePath 'node.exe' -ArgumentList ('"{0}"' -f $workerEntry) -WorkingDirectory (Join-Path $repositoryRoot 'packages\database') -WindowStyle Hidden -RedirectStandardOutput $workerLog -RedirectStandardError $workerErrorLog -PassThru
  $api = Start-Process -FilePath 'node.exe' -ArgumentList ('"{0}"' -f $apiEntry) -WorkingDirectory (Join-Path $repositoryRoot 'apps\api') -WindowStyle Hidden -RedirectStandardOutput $apiLog -RedirectStandardError $apiErrorLog -PassThru
  $web = Start-Process -FilePath 'node.exe' -ArgumentList ('"{0}"' -f $webEntry) -WorkingDirectory (Join-Path $repositoryRoot 'apps\web') -WindowStyle Hidden -RedirectStandardOutput $webLog -RedirectStandardError $webErrorLog -PassThru
  [ordered]@{ workerPid = $worker.Id; apiPid = $api.Id; webPid = $web.Id; startedAt = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding UTF8
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if ($worker.HasExited -or $api.HasExited -or $web.HasExited) { break }
    if ((Test-ApiReady) -and (Test-Endpoint $webHealth)) {
      Write-Output "Nombramientos module: UP (web=$webUrl, api=http://127.0.0.1:4100)"
      return
    }
    Start-Sleep -Seconds 2
  }
  Get-Content -LiteralPath $workerErrorLog -Tail 80 -ErrorAction SilentlyContinue | Write-Error
  Get-Content -LiteralPath $apiErrorLog -Tail 80 -ErrorAction SilentlyContinue | Write-Error
  Get-Content -LiteralPath $webErrorLog -Tail 80 -ErrorAction SilentlyContinue | Write-Error
  Stop-Module | Out-Null
  throw 'Nombramientos did not reach a healthy state.'
}

function Show-Status {
  $apiReady = Test-ApiReady
  $webReady = Test-Endpoint $webHealth
  $processes = @(Get-ManagedProcesses)
  if ($apiReady -and $webReady) {
    Write-Output "Nombramientos module: UP (web=$webUrl, api=http://127.0.0.1:4100)"
    return
  }
  Write-Output "Nombramientos module: $(if ($processes.Count -gt 0) { 'DEGRADED' } else { 'DOWN' }) (web=$(if ($webReady) { 'UP' } else { 'DOWN' }), api=$(if ($apiReady) { 'UP' } else { 'DOWN' }))"
  if ($processes.Count -eq 0) { exit 3 }
  exit 2
}

switch ($Action) {
  'Prepare' { Invoke-Prepare }
  'Start' { Start-Module }
  'Stop' { Stop-Module }
  'Status' { Show-Status }
}
