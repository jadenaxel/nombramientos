[CmdletBinding()]
param(
  [switch]$KeepDatabase
)

$ErrorActionPreference = 'Stop'
$NomRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomRuntimeRoot = Join-Path $NomRoot '.local'
$NomStateFile = Join-Path $NomRuntimeRoot 'services.json'
$NomWorkerStopFile = Join-Path $NomRuntimeRoot 'provisioning-worker.stop'
$NomPnpm = (Get-Command pnpm.cmd -ErrorAction Stop).Source

if (Test-Path -LiteralPath $NomStateFile -PathType Leaf) {
  $NomState = Get-Content -LiteralPath $NomStateFile -Raw | ConvertFrom-Json
  foreach ($NomService in @(
    @{ Name = 'provisioning worker'; Pid = $NomState.workerPid; StartedAt = $NomState.workerStartedAt; Graceful = $true },
    @{ Name = 'API'; Pid = $NomState.apiPid; StartedAt = $NomState.apiStartedAt },
    @{ Name = 'web'; Pid = $NomState.webPid; StartedAt = $NomState.webStartedAt }
  )) {
    if (-not $NomService.Pid) { continue }
    $NomProcess = Get-Process -Id $NomService.Pid -ErrorAction SilentlyContinue
    if (-not $NomProcess) { continue }
    $NomRecorded = [DateTime]::Parse($NomService.StartedAt).ToUniversalTime()
    $NomObserved = $NomProcess.StartTime.ToUniversalTime()
    if ([Math]::Abs(($NomRecorded - $NomObserved).TotalSeconds) -gt 2) {
      throw "Refusing to stop reused PID $($NomService.Pid) for $($NomService.Name)."
    }
    if ($NomService.Graceful) {
      [System.IO.File]::WriteAllText($NomWorkerStopFile, "stop$([Environment]::NewLine)", [System.Text.UTF8Encoding]::new($false))
      foreach ($NomWait in 1..60) {
        if (-not (Get-Process -Id $NomService.Pid -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
      }
    }
    if (Get-Process -Id $NomService.Pid -ErrorAction SilentlyContinue) {
      Stop-Process -Id $NomService.Pid -Force
    }
  }
  $NomResolvedRoot = [System.IO.Path]::GetFullPath($NomRuntimeRoot)
  $NomResolvedState = [System.IO.Path]::GetFullPath($NomStateFile)
  if (-not $NomResolvedState.StartsWith(($NomResolvedRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid service state path.' }
  Remove-Item -LiteralPath $NomStateFile -Force
}
Remove-Item -LiteralPath $NomWorkerStopFile -Force -ErrorAction SilentlyContinue

if (-not $KeepDatabase) {
  Push-Location $NomRoot
  try {
    & $NomPnpm run db:stop
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL did not stop cleanly.' }
  }
  finally { Pop-Location }
}
Write-Output 'Local Nombramientos services are stopped.'
