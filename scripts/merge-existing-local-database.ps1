[CmdletBinding()]
param(
  [int]$SourcePort = 55433,
  [int]$TargetPort = 55432
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$installPath = Join-Path $repositoryRoot 'packages\database\.local\install.json'
$localRoot = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot 'packages\database\.local'))
$stagingPath = [System.IO.Path]::GetFullPath((Join-Path $localRoot 'merge-staging'))

if ($SourcePort -eq $TargetPort) { throw 'SourcePort and TargetPort must be different.' }
if ($TargetPort -ne 55432) { throw 'The consolidated GestionChurch PostgreSQL endpoint must remain on port 55432.' }
if (-not (Test-Path -LiteralPath $installPath)) { throw "Nombramientos local install metadata is missing: $installPath" }
if (-not $stagingPath.StartsWith($localRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'The staging path escaped the protected Nombramientos local directory.'
}

$install = Get-Content -Raw -LiteralPath $installPath | ConvertFrom-Json
$postgresBin = [string]$install.POSTGRES_BIN
$psql = Join-Path $postgresBin 'psql.exe'
$pgDump = Join-Path $postgresBin 'pg_dump.exe'
$pgRestore = Join-Path $postgresBin 'pg_restore.exe'
$pgIsReady = Join-Path $postgresBin 'pg_isready.exe'
foreach ($binary in @($psql, $pgDump, $pgRestore, $pgIsReady)) {
  if (-not (Test-Path -LiteralPath $binary)) { throw "Required PostgreSQL binary is missing: $binary" }
}

& $pgIsReady -h 127.0.0.1 -p $SourcePort | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Source PostgreSQL is not ready on port $SourcePort." }
& $pgIsReady -h 127.0.0.1 -p $TargetPort | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Target PostgreSQL is not ready on port $TargetPort." }

$adminUri = [uri][string]$install.DATABASE_ADMIN_URL
$sourceAdminPassword = [uri]::UnescapeDataString($adminUri.UserInfo.Split(':', 2)[1])
$previousPassword = $env:PGPASSWORD

try {
  $env:PGPASSWORD = ''
  $targetObjects = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $TargetPort -U postgres -d postgres -Atc "SELECT datname FROM pg_database WHERE datname LIKE 'nom%'; SELECT rolname FROM pg_roles WHERE rolname LIKE 'nom%';"
  if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the target PostgreSQL cluster.' }
  if (@($targetObjects).Count -gt 0) {
    throw 'The target already contains Nombramientos databases or roles; merge refused to prevent an overwrite.'
  }

  if (Test-Path -LiteralPath $stagingPath) {
    Remove-Item -LiteralPath $stagingPath -Recurse -Force
  }
  New-Item -ItemType Directory -Path $stagingPath | Out-Null
  $rolesFile = Join-Path $stagingPath 'roles.sql'

  $env:PGPASSWORD = $sourceAdminPassword
  $roleSql = @"
SELECT format(
  'CREATE ROLE %I %s %s %s %s %s %s %s CONNECTION LIMIT %s%s;',
  rolname,
  CASE WHEN rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END,
  CASE WHEN rolsuper THEN 'SUPERUSER' ELSE 'NOSUPERUSER' END,
  CASE WHEN rolcreatedb THEN 'CREATEDB' ELSE 'NOCREATEDB' END,
  CASE WHEN rolcreaterole THEN 'CREATEROLE' ELSE 'NOCREATEROLE' END,
  CASE WHEN rolinherit THEN 'INHERIT' ELSE 'NOINHERIT' END,
  CASE WHEN rolreplication THEN 'REPLICATION' ELSE 'NOREPLICATION' END,
  CASE WHEN rolbypassrls THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END,
  rolconnlimit,
  CASE WHEN rolpassword IS NULL THEN '' ELSE format(' PASSWORD %L', rolpassword) END
)
FROM pg_authid
WHERE rolname LIKE 'nom\_%' ESCAPE '\'
ORDER BY rolname;
SELECT format(
  'GRANT %I TO %I%s;',
  pg_get_userbyid(roleid),
  pg_get_userbyid(member),
  CASE WHEN admin_option THEN ' WITH ADMIN OPTION' ELSE '' END
)
FROM pg_auth_members
WHERE pg_get_userbyid(roleid) LIKE 'nom\_%' ESCAPE '\'
   OR pg_get_userbyid(member) LIKE 'nom\_%' ESCAPE '\'
ORDER BY 1;
"@
  $roleStatements = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $SourcePort -U nom_admin -d postgres -Atc $roleSql
  if ($LASTEXITCODE -ne 0 -or @($roleStatements).Count -eq 0) { throw 'Could not export the Nombramientos role contract.' }
  [System.IO.File]::WriteAllLines($rolesFile, [string[]]$roleStatements, [System.Text.UTF8Encoding]::new($false))

  $databaseRows = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $SourcePort -U nom_admin -d postgres -Atc "SELECT datname || '|' || pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'nombramientos_control' OR datname LIKE 'nom_t_%' ORDER BY datname;"
  if ($LASTEXITCODE -ne 0 -or @($databaseRows).Count -eq 0) { throw 'No Nombramientos databases were found in the source cluster.' }

  $env:PGPASSWORD = ''
  & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $TargetPort -U postgres -d postgres -f $rolesFile | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not recreate the Nombramientos role contract on the target cluster.' }

  foreach ($row in $databaseRows) {
    $parts = ([string]$row).Split('|', 2)
    $databaseName = $parts[0]
    $ownerName = $parts[1]
    if ($databaseName -notmatch '^nombramientos_control$|^nom_t_[a-f0-9]{32}$' -or $ownerName -notmatch '^nom_(admin|o_[a-f0-9]{32})$') {
      throw "Unsafe database metadata returned by source cluster: $row"
    }
    $dumpFile = Join-Path $stagingPath ($databaseName + '.dump')
    $env:PGPASSWORD = $sourceAdminPassword
    & $pgDump -h 127.0.0.1 -p $SourcePort -U nom_admin -d $databaseName --format=custom --file=$dumpFile
    if ($LASTEXITCODE -ne 0) { throw "Backup failed for $databaseName." }

    $env:PGPASSWORD = ''
    $createSql = & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $TargetPort -U postgres -d postgres -Atc "SELECT format('CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING %L', '$databaseName', '$ownerName', 'UTF8')"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$createSql)) { throw "Database creation statement failed for $databaseName." }
    & $psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -p $TargetPort -U postgres -d postgres -c ([string]$createSql) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Database creation failed for $databaseName." }
    & $pgRestore -h 127.0.0.1 -p $TargetPort -U postgres -d $databaseName --exit-on-error $dumpFile
    if ($LASTEXITCODE -ne 0) { throw "Restore failed for $databaseName." }
  }

  Write-Output "Nombramientos data was consolidated into PostgreSQL on port $TargetPort without installing a second server."
}
finally {
  if ($null -eq $previousPassword) { Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue } else { $env:PGPASSWORD = $previousPassword }
  if (Test-Path -LiteralPath $stagingPath) {
    $resolvedStaging = [System.IO.Path]::GetFullPath($stagingPath)
    if ($resolvedStaging.StartsWith($localRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
      Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
  }
}
