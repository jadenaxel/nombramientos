[CmdletBinding()]
param(
  [switch]$SkipInstall,
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$NomRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomPnpm = (Get-Command pnpm.cmd -ErrorAction Stop).Source

function Invoke-NomPnpm {
  param([Parameter(Mandatory)][string[]]$Arguments)
  & $NomPnpm @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "pnpm failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
  }
}

Push-Location $NomRoot
try {
  if (-not $SkipInstall) {
    if (-not (Test-Path -LiteralPath (Join-Path $NomRoot 'pnpm-lock.yaml') -PathType Leaf)) {
      throw 'pnpm-lock.yaml is missing. Generate and review the root lockfile before bootstrap.'
    }
    Invoke-NomPnpm @('install', '--frozen-lockfile')
  }

  if (-not $SkipBuild) {
    Invoke-NomPnpm @('run', 'build')
  }
  else {
    foreach ($NomRequiredBuild in @(
      'packages\catalog\dist\index.js',
      'packages\domain\dist\index.js',
      'packages\database\dist\scripts\migrate-control.js',
      'packages\database\dist\scripts\provision-tenants.js',
      'packages\database\dist\scripts\seed-demo.js',
      'packages\database\dist\scripts\issue-platform-admin-bootstrap.js',
      'apps\api\dist\src\main.js',
      'apps\web\.next\BUILD_ID'
    )) {
      if (-not (Test-Path -LiteralPath (Join-Path $NomRoot $NomRequiredBuild) -PathType Leaf)) {
        throw "Build artifact missing while -SkipBuild was requested: $NomRequiredBuild"
      }
    }
  }

  Invoke-NomPnpm @('run', 'db:bootstrap')
  Invoke-NomPnpm @('run', 'db:start')
  Invoke-NomPnpm @('run', 'db:migrate')
  Invoke-NomPnpm @('run', 'db:provision')
  Invoke-NomPnpm @('run', 'db:seed:demo')
  Invoke-NomPnpm @('run', 'db:bootstrap:platform-admin')

  Write-Output 'Local bootstrap completed without printing credentials.'
  Write-Output 'Demo access material is stored in packages/database/.local/demo-access.json with a restricted ACL.'
  Write-Output 'One-use platform administrator activation material is stored under protected local state.'
  Write-Output 'Run pnpm start:local, then open http://localhost:3000/es/auth/sign-in (canonical WebAuthn origin).'
}
finally {
  Pop-Location
}
