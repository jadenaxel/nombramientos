[CmdletBinding()]
param(
  [ValidateSet('bootstrap', 'init', 'start', 'stop', 'status')]
  [string]$Action = 'status',
  [ValidateRange(1024, 65535)]
  [int]$Port = 55432,
  [string]$PgBin = 'C:\Program Files\PostgreSQL\18\bin',
  [string]$DataDirectory = ''
)

$ErrorActionPreference = 'Stop'
$NomPackageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomWorkspaceRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '..\..'))
$NomLocalRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '.local'))
$NomLocalBoundary = $NomLocalRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
  $DataDirectory = Join-Path $NomLocalRoot 'pgdata'
}
$NomData = [System.IO.Path]::GetFullPath($DataDirectory)
if (-not $NomData.StartsWith($NomLocalBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw "DataDirectory must stay inside $NomLocalRoot"
}

$NomInitDb = Join-Path $PgBin 'initdb.exe'
$NomPgCtl = Join-Path $PgBin 'pg_ctl.exe'
$NomPgReady = Join-Path $PgBin 'pg_isready.exe'
foreach ($NomExecutable in @($NomInitDb, $NomPgCtl, $NomPgReady)) {
  if (-not (Test-Path -LiteralPath $NomExecutable -PathType Leaf)) {
    throw "PostgreSQL 18 executable not found: $NomExecutable"
  }
}

New-Item -ItemType Directory -Path $NomLocalRoot -Force | Out-Null
$NomLog = Join-Path $NomLocalRoot 'postgres.log'
$NomInstallFile = Join-Path $NomLocalRoot 'install.json'
$NomBackupScript = Join-Path $PSScriptRoot 'backup-local.ps1'

function New-NomRandomBase64Url {
  param([int]$ByteCount = 32)
  $NomBytes = New-Object byte[] $ByteCount
  $NomRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $NomRng.GetBytes($NomBytes)
    return [Convert]::ToBase64String($NomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
  }
  finally {
    $NomRng.Dispose()
    [Array]::Clear($NomBytes, 0, $NomBytes.Length)
  }
}

function Protect-NomLocalPath {
  param([string]$LiteralPath, [switch]$Container)
  if ($env:OS -ne 'Windows_NT') { return }
  $NomIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  # Package directories created by an automation sandbox can be owned by its
  # restricted worker. Never turn that technical owner into a secret reader.
  # A distinct non-sandbox workspace owner may still represent the interactive
  # operator and is retained for installations created outside Codex.
  try {
    $NomWorkspaceOwner = ([System.IO.DirectoryInfo]::new($NomWorkspaceRoot).GetAccessControl()).Owner
  }
  catch {
    $NomWorkspaceOwner = (Get-Acl -LiteralPath $NomWorkspaceRoot).Owner
  }
  $NomPrincipals = @($NomIdentity, '*S-1-5-18')
  if ($NomWorkspaceOwner -notmatch '(?i)\\CodexSandbox[^\\]*$') {
    $NomPrincipals += $NomWorkspaceOwner
  }
  $NomRights = if ($Container) { '(OI)(CI)F' } else { 'F' }
  $NomAclArguments = @($LiteralPath, '/inheritance:r')
  foreach ($NomPrincipal in ($NomPrincipals | Select-Object -Unique)) {
    $NomAclArguments += '/grant:r'
    $NomAclArguments += ($NomPrincipal + ':' + $NomRights)
  }
  & icacls.exe @NomAclArguments *> $null
  if ($LASTEXITCODE -ne 0) {
    throw "Could not establish the required restricted ACL: $LiteralPath"
  }
  if ($NomWorkspaceOwner -match '(?i)\\CodexSandbox[^\\]*$' -and $NomWorkspaceOwner -ne $NomIdentity) {
    & icacls.exe $LiteralPath /remove:g $NomWorkspaceOwner *> $null
    if ($LASTEXITCODE -ne 0) {
      throw "Could not remove the technical workspace owner from the secret ACL: $LiteralPath"
    }
  }
}

function Initialize-NomCluster {
  param([string]$Password)
  if ([string]::IsNullOrWhiteSpace($Password) -or $Password.Length -lt 16) {
    throw 'Use an administrative password with at least 16 characters.'
  }
  Protect-NomLocalPath -LiteralPath $NomLocalRoot -Container
  New-Item -ItemType Directory -Path $NomData -Force | Out-Null
  $NomPasswordFile = Join-Path $NomLocalRoot ('.initdb-password-' + [guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [System.IO.File]::WriteAllText($NomPasswordFile, $Password, [System.Text.UTF8Encoding]::new($false))
    Protect-NomLocalPath -LiteralPath $NomPasswordFile
    & $NomInitDb -D $NomData --encoding=UTF8 --username=nom_admin --auth-host=scram-sha-256 --auth-local=scram-sha-256 --pwfile=$NomPasswordFile
    if ($LASTEXITCODE -ne 0) { throw "initdb failed with exit code $LASTEXITCODE" }
  }
  finally {
    if (Test-Path -LiteralPath $NomPasswordFile) { Remove-Item -LiteralPath $NomPasswordFile -Force }
  }
}

function Write-NomInstallConfiguration {
  param(
    [string]$AdminPassword,
    [string]$ControlPassword,
    [string]$DatabaseMasterKey,
    [string]$AuthEncryptionKey,
    [string]$DemoInitialPassword
  )
  $NomPayload = [ordered]@{
    version = 1
    DATABASE_ADMIN_URL = "postgresql://nom_admin:$AdminPassword@127.0.0.1:$Port/postgres"
    DATABASE_CONTROL_URL = "postgresql://nom_control:$ControlPassword@127.0.0.1:$Port/nombramientos_control"
    DATABASE_SECRET_MASTER_KEY_B64 = $DatabaseMasterKey
    AUTH_ENCRYPTION_KEY_B64 = $AuthEncryptionKey
    DEMO_INITIAL_PASSWORD = $DemoInitialPassword
    DATABASE_SECRET_FILE = (Join-Path $NomLocalRoot 'secrets.enc.json')
    API_HOST = '127.0.0.1'
    API_PORT = '4000'
    API_CORS_ORIGINS = 'http://localhost:3000'
    API_COOKIE_SECURE = 'false'
  }
  $NomTemporaryInstall = $NomInstallFile + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {
    [System.IO.File]::WriteAllText(
      $NomTemporaryInstall,
      (($NomPayload | ConvertTo-Json -Depth 4 -Compress) + [Environment]::NewLine),
      [System.Text.UTF8Encoding]::new($false)
    )
    Protect-NomLocalPath -LiteralPath $NomTemporaryInstall
    Move-Item -LiteralPath $NomTemporaryInstall -Destination $NomInstallFile
    Protect-NomLocalPath -LiteralPath $NomInstallFile
  }
  finally {
    if (Test-Path -LiteralPath $NomTemporaryInstall) { Remove-Item -LiteralPath $NomTemporaryInstall -Force }
  }
}

function Update-NomInstallBrowserOrigin {
  if (-not (Test-Path -LiteralPath $NomInstallFile -PathType Leaf)) {
    throw 'The existing workspace install configuration is missing.'
  }
  $NomInstallInfo = Get-Item -LiteralPath $NomInstallFile -Force
  if (($NomInstallInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The workspace install configuration must not be a reparse point.'
  }

  $NomPayload = Get-Content -LiteralPath $NomInstallFile -Raw -ErrorAction Stop | ConvertFrom-Json
  foreach ($NomRequiredProperty in @(
    'DATABASE_ADMIN_URL',
    'DATABASE_CONTROL_URL',
    'DATABASE_SECRET_MASTER_KEY_B64',
    'AUTH_ENCRYPTION_KEY_B64'
  )) {
    if ($null -eq $NomPayload.PSObject.Properties[$NomRequiredProperty] -or
        [string]::IsNullOrWhiteSpace([string]$NomPayload.$NomRequiredProperty)) {
      throw 'The existing workspace install configuration is incomplete.'
    }
  }
  if ([string]$NomPayload.API_CORS_ORIGINS -ceq 'http://localhost:3000') { return }

  if ($null -eq $NomPayload.PSObject.Properties['API_CORS_ORIGINS']) {
    $NomPayload | Add-Member -NotePropertyName 'API_CORS_ORIGINS' -NotePropertyValue 'http://localhost:3000'
  }
  else {
    $NomPayload.API_CORS_ORIGINS = 'http://localhost:3000'
  }

  $NomTemporaryInstall = $NomInstallFile + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {
    [System.IO.File]::WriteAllText(
      $NomTemporaryInstall,
      (($NomPayload | ConvertTo-Json -Depth 8 -Compress) + [Environment]::NewLine),
      [System.Text.UTF8Encoding]::new($false)
    )
    Protect-NomLocalPath -LiteralPath $NomTemporaryInstall
    [System.IO.File]::Replace($NomTemporaryInstall, $NomInstallFile, $null)
    Protect-NomLocalPath -LiteralPath $NomInstallFile
  }
  finally {
    if (Test-Path -LiteralPath $NomTemporaryInstall) { Remove-Item -LiteralPath $NomTemporaryInstall -Force }
    $NomPayload = $null
  }
}

function Get-NomClusterStatus {
  if (-not (Test-Path -LiteralPath (Join-Path $NomData 'PG_VERSION'))) {
    return 'not-initialized'
  }
  & $NomPgCtl status -D $NomData *> $null
  if ($LASTEXITCODE -eq 0) {
    # The data-directory-specific process check is authoritative. pg_isready is
    # only a secondary readiness probe and can never make an unrelated server
    # on the same port look like this workspace cluster.
    & $NomPgReady -h 127.0.0.1 -p $Port *> $null
    return 'running'
  }
  $NomPidFile = Join-Path $NomData 'postmaster.pid'
  if (Test-Path -LiteralPath $NomPidFile -PathType Leaf) {
    # pg_ctl can return a false negative when Windows denies one local identity
    # access to a postmaster started by another. Cross-check the data-directory
    # PID file with the loopback listener before deciding that it is stopped.
    try {
      $NomPidLines = @(Get-Content -LiteralPath $NomPidFile -ErrorAction Stop)
      if ($NomPidLines.Count -lt 8) { return 'indeterminate' }
      $NomPid = 0
      $NomPidPort = 0
      if (-not [int]::TryParse($NomPidLines[0].Trim(), [ref]$NomPid)) { return 'indeterminate' }
      if (-not [int]::TryParse($NomPidLines[3].Trim(), [ref]$NomPidPort)) { return 'indeterminate' }
      $NomPidData = [System.IO.Path]::GetFullPath($NomPidLines[1].Trim())
      $NomPidAddress = $NomPidLines[5].Trim()
      $NomPidState = $NomPidLines[7].Trim()
      # Get-NetTCPConnection itself can be access-denied across sandbox
      # identities. netstat still exposes the listener/PID tuple read-only.
      $NomNetstat = (Get-Command netstat.exe -ErrorAction Stop).Source
      $NomListenerPattern = '^\s*TCP\s+127\.0\.0\.1:' + $Port + '\s+0\.0\.0\.0:0\s+\S+\s+' + $NomPid + '\s*$'
      $NomListener = @(& $NomNetstat -ano -p tcp | Where-Object { $_ -match $NomListenerPattern })
      & $NomPgReady -h 127.0.0.1 -p $Port *> $null
      $NomReady = $LASTEXITCODE -eq 0
      if (
        $NomPidData.Equals($NomData, [System.StringComparison]::OrdinalIgnoreCase) -and
        $NomPidPort -eq $Port -and
        $NomPidAddress -eq '127.0.0.1' -and
        $NomPidState -eq 'ready' -and
        $NomListener.Count -eq 1 -and
        $NomReady
      ) {
        return 'running'
      }
    }
    catch {
      # A PID file with unverifiable ownership is not proof of a stopped
      # cluster. Preserve it and require explicit inspection.
    }
    return 'indeterminate'
  }
  return 'stopped'
}

function Initialize-NomBackupSupport {
  if (-not (Test-Path -LiteralPath $NomBackupScript -PathType Leaf)) {
    throw 'The local backup configuration script is missing.'
  }
  & $NomBackupScript -Action configure -PgBin $PgBin
}

switch ($Action) {
  'bootstrap' {
    $NomHasCluster = (Get-NomClusterStatus) -ne 'not-initialized'
    $NomHasInstall = Test-Path -LiteralPath $NomInstallFile -PathType Leaf
    if ($NomHasCluster -and $NomHasInstall) {
      Update-NomInstallBrowserOrigin
      Initialize-NomBackupSupport
      Write-Output 'Workspace bootstrap already exists; browser-origin policy was reconciled without changing credentials.'
      break
    }
    if ($NomHasCluster -or $NomHasInstall) {
      throw 'Partial workspace bootstrap detected. Preserve the data and repair the missing cluster/configuration explicitly.'
    }
    $NomAdminPassword = New-NomRandomBase64Url 36
    $NomControlPassword = New-NomRandomBase64Url 36
    $NomDatabaseMasterKey = New-NomRandomBase64Url 32
    $NomAuthEncryptionKey = New-NomRandomBase64Url 32
    $NomDemoInitialPassword = New-NomRandomBase64Url 32
    try {
      Initialize-NomCluster -Password $NomAdminPassword
      Write-NomInstallConfiguration -AdminPassword $NomAdminPassword -ControlPassword $NomControlPassword -DatabaseMasterKey $NomDatabaseMasterKey -AuthEncryptionKey $NomAuthEncryptionKey -DemoInitialPassword $NomDemoInitialPassword
      Initialize-NomBackupSupport
    }
    finally {
      $NomAdminPassword = $null
      $NomControlPassword = $null
      $NomDatabaseMasterKey = $null
      $NomAuthEncryptionKey = $null
      $NomDemoInitialPassword = $null
    }
    Write-Output "Initialized isolated workspace cluster at $NomData with per-install secrets."
    Write-Output "Secrets were stored only in $NomInstallFile with a restricted ACL and were not printed."
    Write-Output 'It does not register or modify a Windows service.'
  }
  'init' {
    if ((Get-NomClusterStatus) -ne 'not-initialized') {
      throw "Workspace cluster is already initialized at $NomData"
    }
    $NomSecure = Read-Host 'Create the workspace PostgreSQL admin password' -AsSecureString
    $NomPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NomSecure)
    try {
      $NomPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($NomPointer)
      Initialize-NomCluster -Password $NomPlain
    }
    finally {
      if ($NomPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($NomPointer) }
      $NomPlain = $null
    }
    Write-Output "Initialized isolated workspace cluster at $NomData"
    Write-Output 'It does not register or modify a Windows service.'
  }
  'start' {
    $NomStatus = Get-NomClusterStatus
    if ($NomStatus -eq 'not-initialized') { throw 'Run -Action init first.' }
    if ($NomStatus -eq 'running') { Write-Output 'Workspace PostgreSQL cluster is already running.'; break }
    if ($NomStatus -eq 'indeterminate') { throw 'Workspace PostgreSQL state is indeterminate; refusing to start while postmaster.pid exists.' }
    & $NomPgCtl start -D $NomData -l $NomLog -w -o "-p $Port -h 127.0.0.1"
    if ($LASTEXITCODE -ne 0) { throw "pg_ctl start failed with exit code $LASTEXITCODE" }
    Write-Output "Workspace PostgreSQL is listening only on 127.0.0.1:$Port"
    Write-Output "Admin URL (password omitted): postgresql://nom_admin@127.0.0.1:$Port/postgres"
  }
  'stop' {
    $NomStatus = Get-NomClusterStatus
    if ($NomStatus -eq 'indeterminate') { throw 'Workspace PostgreSQL state is indeterminate; refusing to stop an unverified process.' }
    if ($NomStatus -ne 'running') { Write-Output 'Workspace PostgreSQL cluster is not running.'; break }
    & $NomPgCtl stop -D $NomData -m fast -w
    if ($LASTEXITCODE -ne 0) { throw "pg_ctl stop failed with exit code $LASTEXITCODE" }
    Write-Output 'Workspace PostgreSQL cluster stopped.'
  }
  'status' {
    $NomStatus = Get-NomClusterStatus
    Write-Output "Workspace cluster: $NomStatus"
    if ($NomStatus -eq 'running') { & $NomPgReady -h 127.0.0.1 -p $Port }
  }
}
