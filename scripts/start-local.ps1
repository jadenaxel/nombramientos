[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$NomRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomRuntimeRoot = Join-Path $NomRoot '.local'
$NomStateFile = Join-Path $NomRuntimeRoot 'services.json'
$NomNode = (Get-Command node.exe -ErrorAction Stop).Source
$NomPnpm = (Get-Command pnpm.cmd -ErrorAction Stop).Source
$NomApiRoot = Join-Path $NomRoot 'apps\api'
$NomWebRoot = Join-Path $NomRoot 'apps\web'
$NomDatabaseRoot = Join-Path $NomRoot 'packages\database'
$NomApiEntry = Join-Path $NomApiRoot 'dist\src\main.js'
$NomWebEntry = Join-Path $NomWebRoot 'scripts\start-standalone.mjs'
$NomWebServer = Join-Path $NomWebRoot '.next\standalone\apps\web\server.js'
$NomWorkerEntry = Join-Path $NomDatabaseRoot 'dist\scripts\process-provisioning-jobs.js'
$NomWorkerStopFile = Join-Path $NomRuntimeRoot 'provisioning-worker.stop'

if (Test-Path -LiteralPath $NomStateFile -PathType Leaf) {
  $NomExisting = Get-Content -LiteralPath $NomStateFile -Raw | ConvertFrom-Json
  $NomLive = @($NomExisting.workerPid, $NomExisting.apiPid, $NomExisting.webPid) | Where-Object { $_ -and (Get-Process -Id $_ -ErrorAction SilentlyContinue) }
  if ($NomLive.Count -gt 0) { throw 'A recorded local service is still running. Use pnpm stop:local first.' }
}
if (-not (Test-Path -LiteralPath $NomApiEntry -PathType Leaf)) { throw 'API build is missing. Run pnpm bootstrap:local first.' }
if (-not (Test-Path -LiteralPath $NomWorkerEntry -PathType Leaf)) { throw 'Provisioning worker build is missing. Run pnpm bootstrap:local first.' }
if (-not (Test-Path -LiteralPath (Join-Path $NomWebRoot '.next\BUILD_ID') -PathType Leaf)) { throw 'Web production build is missing. Run pnpm bootstrap:local first.' }
if (-not (Test-Path -LiteralPath $NomWebEntry -PathType Leaf) -or -not (Test-Path -LiteralPath $NomWebServer -PathType Leaf)) { throw 'Next.js standalone runtime is missing. Run pnpm bootstrap:local first.' }

Push-Location $NomRoot
try {
  & $NomPnpm run db:start
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL did not start.' }
  New-Item -ItemType Directory -Path $NomRuntimeRoot -Force | Out-Null
  Remove-Item -LiteralPath $NomWorkerStopFile -Force -ErrorAction SilentlyContinue
  $NomWorker = $null
  $NomApi = $null
  $NomWeb = $null
  try {
    $NomWorker = Start-Process -FilePath $NomNode -ArgumentList @($NomWorkerEntry) -WorkingDirectory $NomDatabaseRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $NomRuntimeRoot 'worker.stdout.log') -RedirectStandardError (Join-Path $NomRuntimeRoot 'worker.stderr.log')
    $NomApi = Start-Process -FilePath $NomNode -ArgumentList @($NomApiEntry) -WorkingDirectory $NomApiRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $NomRuntimeRoot 'api.stdout.log') -RedirectStandardError (Join-Path $NomRuntimeRoot 'api.stderr.log')
    $NomWeb = Start-Process -FilePath $NomNode -ArgumentList @($NomWebEntry) -WorkingDirectory $NomWebRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $NomRuntimeRoot 'web.stdout.log') -RedirectStandardError (Join-Path $NomRuntimeRoot 'web.stderr.log')
    $NomState = [ordered]@{
      workerPid = $NomWorker.Id
      workerStartedAt = $NomWorker.StartTime.ToUniversalTime().ToString('O')
      apiPid = $NomApi.Id
      apiStartedAt = $NomApi.StartTime.ToUniversalTime().ToString('O')
      webPid = $NomWeb.Id
      webStartedAt = $NomWeb.StartTime.ToUniversalTime().ToString('O')
    }
    [System.IO.File]::WriteAllText($NomStateFile, (($NomState | ConvertTo-Json -Compress) + [Environment]::NewLine), [System.Text.UTF8Encoding]::new($false))

    $NomReady = $false
    foreach ($NomAttempt in 1..60) {
      if ($NomWorker.HasExited -or $NomApi.HasExited -or $NomWeb.HasExited) { break }
      try {
        $NomHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:4000/healthz' -TimeoutSec 2
        $NomWebHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/healthz' -TimeoutSec 2
        if ($NomHealth.status -eq 'ok' -and $NomHealth.worker.healthy -eq $true -and $NomWebHealth.status -eq 'ok' -and -not $NomWorker.HasExited -and -not $NomApi.HasExited -and -not $NomWeb.HasExited) { $NomReady = $true; break }
      }
      catch { Start-Sleep -Milliseconds 250 }
    }
    if (-not $NomReady) { throw 'Local services did not become ready. Inspect .local/*.stderr.log.' }
    Write-Output 'Nombramientos is ready at http://localhost:3000/es/auth/sign-in (canonical WebAuthn origin)'
    Write-Output 'API health is available at http://127.0.0.1:4000/healthz'
  }
  catch {
    foreach ($NomStartedProcess in @($NomWorker, $NomApi, $NomWeb)) {
      if ($null -ne $NomStartedProcess -and -not $NomStartedProcess.HasExited) {
        Stop-Process -Id $NomStartedProcess.Id -Force -ErrorAction SilentlyContinue
      }
    }
    Remove-Item -LiteralPath $NomWorkerStopFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $NomStateFile -Force -ErrorAction SilentlyContinue
    throw
  }
}
finally {
  Pop-Location
}
