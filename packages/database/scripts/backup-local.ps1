[CmdletBinding()]
param(
  [ValidateSet('configure', 'backup', 'drill', 'rotate-key')]
  [string]$Action = 'configure',
  [string]$TenantId = '',
  [string]$BackupDirectory = '',
  [string]$PgBin = 'C:\Program Files\PostgreSQL\18\bin'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$NomPackageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomWorkspaceRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '..\..'))
$NomLocalRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '.local'))
$NomInstallFile = Join-Path $NomLocalRoot 'install.json'
$NomDefaultKeyFile = Join-Path $NomLocalRoot 'backup-keys.json'
$NomBackupRoot = Join-Path $NomLocalRoot 'backups'
$NomWorkRoot = Join-Path $NomLocalRoot 'backup-work'

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

function Protect-NomBackupPath {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [switch]$Container
  )
  if ($env:OS -ne 'Windows_NT') {
    if (-not $Container) {
      & chmod 600 -- $LiteralPath
      if ($LASTEXITCODE -ne 0) { throw "Could not restrict backup secret permissions: $LiteralPath" }
    }
    return
  }

  $NomIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  # Windows PowerShell can resolve the owner directly through DirectoryInfo
  # even when an inherited PowerShell 7 module path makes Get-Acl unloadable.
  # PowerShell 7 exposes Get-Acl instead, so retain that as the compatible
  # fallback. This keeps the pnpm wrapper and direct invocation equivalent.
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
  $NomPrincipals = $NomPrincipals | Select-Object -Unique
  $NomRights = if ($Container) { '(OI)(CI)F' } else { 'F' }
  $NomAclArguments = @($LiteralPath, '/inheritance:r')
  foreach ($NomPrincipal in $NomPrincipals) {
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

function Resolve-NomLocalPath {
  param(
    [Parameter(Mandatory = $true)][string]$Value,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $NomCandidate = if ([System.IO.Path]::IsPathRooted($Value)) {
    [System.IO.Path]::GetFullPath($Value)
  }
  else {
    [System.IO.Path]::GetFullPath((Join-Path $NomLocalRoot $Value))
  }
  $NomBoundary = $NomLocalRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
  if (-not $NomCandidate.StartsWith($NomBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label must remain inside the package .local directory"
  }
  return $NomCandidate
}

function Write-NomAtomicJson {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][object]$Value
  )
  $NomTemporary = $LiteralPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  $NomRollback = $LiteralPath + '.' + [guid]::NewGuid().ToString('N') + '.rollback.tmp'
  try {
    $NomJson = ($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine
    [System.IO.File]::WriteAllText($NomTemporary, $NomJson, [System.Text.UTF8Encoding]::new($false))
    Protect-NomBackupPath -LiteralPath $NomTemporary
    if (Test-Path -LiteralPath $LiteralPath -PathType Leaf) {
      [System.IO.File]::Replace($NomTemporary, $LiteralPath, $NomRollback, $true)
    }
    else {
      Move-Item -LiteralPath $NomTemporary -Destination $LiteralPath
    }
    Protect-NomBackupPath -LiteralPath $LiteralPath
  }
  finally {
    if (Test-Path -LiteralPath $NomTemporary) {
      Remove-Item -LiteralPath $NomTemporary -Force
    }
    if (Test-Path -LiteralPath $NomRollback) {
      Remove-Item -LiteralPath $NomRollback -Force
    }
  }
}

function Set-NomJsonProperty {
  param(
    [Parameter(Mandatory = $true)][object]$Target,
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Value
  )
  $NomProperty = $Target.PSObject.Properties[$Name]
  if ($null -eq $NomProperty) {
    $Target | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    return $true
  }
  if ([string]$NomProperty.Value -eq $Value) {
    return $false
  }
  $NomProperty.Value = $Value
  return $true
}

function Assert-NomAdminEndpoint {
  param([Parameter(Mandatory = $true)][string]$ConnectionString)
  $NomUri = [System.Uri]::new($ConnectionString)
  if ($NomUri.Scheme -notin @('postgres', 'postgresql')) {
    throw 'The installed database administrator URL is not PostgreSQL.'
  }
  if (
    $ConnectionString -cnotmatch '^postgres(?:ql)?://nom_admin:[^@/?#]+@127\.0\.0\.1:55432/postgres$' -or
    $NomUri.Host -cne '127.0.0.1' -or
    $NomUri.Port -ne 55432 -or
    $NomUri.AbsolutePath -cne '/postgres' -or
    -not [string]::IsNullOrEmpty($NomUri.Query) -or
    -not [string]::IsNullOrEmpty($NomUri.Fragment)
  ) {
    throw 'Backup operations require the exact protected workspace PostgreSQL administrator endpoint.'
  }
}

function Assert-NomPg18Tooling {
  param([Parameter(Mandatory = $true)][string]$BinDirectory)
  $NomResolvedBin = [System.IO.Path]::GetFullPath($BinDirectory)
  foreach ($NomToolName in @('pg_dump.exe', 'pg_restore.exe')) {
    $NomTool = Join-Path $NomResolvedBin $NomToolName
    if (-not (Test-Path -LiteralPath $NomTool -PathType Leaf)) {
      throw "PostgreSQL 18 tool is missing: $NomToolName"
    }
    $NomVersion = (& $NomTool --version 2>$null) -join ' '
    if ($LASTEXITCODE -ne 0 -or $NomVersion -notmatch '\b18\.\d+\b') {
      throw "$NomToolName must be from PostgreSQL 18."
    }
  }
  return $NomResolvedBin
}

function Read-NomJson {
  param([Parameter(Mandatory = $true)][string]$LiteralPath)
  return Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Assert-NomKeyInventory {
  param([Parameter(Mandatory = $true)][object]$Inventory)
  if ($Inventory.version -ne 1) { throw 'Unsupported backup key inventory version.' }
  $NomKeys = @($Inventory.keys)
  if ($NomKeys.Count -lt 1) { throw 'Backup key inventory is empty.' }
  $NomActive = @($NomKeys | Where-Object { $_.status -eq 'active' })
  if ($NomActive.Count -ne 1 -or $NomActive[0].id -ne $Inventory.activeKeyId) {
    throw 'Backup key inventory must contain one matching active key.'
  }
  $NomIds = @($NomKeys | ForEach-Object { $_.id } | Select-Object -Unique)
  if ($NomIds.Count -ne $NomKeys.Count) { throw 'Backup key inventory contains duplicate ids.' }
  foreach ($NomKey in $NomKeys) {
    if ($NomKey.status -notin @('active', 'retired')) {
      throw 'Backup key inventory contains an unsupported key status.'
    }
    $NomParsedId = [guid]::Empty
    if (-not [guid]::TryParse([string]$NomKey.id, [ref]$NomParsedId)) {
      throw 'Backup key inventory contains an invalid key id.'
    }
    $NomKeyBytes = [Convert]::FromBase64String(([string]$NomKey.keyB64).Replace('-', '+').Replace('_', '/') + ('=' * ((4 - ([string]$NomKey.keyB64).Length % 4) % 4)))
    try {
      if ($NomKeyBytes.Length -ne 32) { throw 'Every backup key must contain exactly 32 bytes.' }
    }
    finally {
      [Array]::Clear($NomKeyBytes, 0, $NomKeyBytes.Length)
    }
  }
}

function Initialize-NomBackupConfiguration {
  if (-not (Test-Path -LiteralPath $NomInstallFile -PathType Leaf)) {
    throw 'Local install configuration is missing. Run the workspace database bootstrap first.'
  }
  New-Item -ItemType Directory -Path $NomLocalRoot -Force | Out-Null
  Protect-NomBackupPath -LiteralPath $NomLocalRoot -Container

  $NomInstall = Read-NomJson -LiteralPath $NomInstallFile
  if ($NomInstall.version -ne 1) { throw 'Unsupported local install configuration version.' }
  Assert-NomAdminEndpoint -ConnectionString ([string]$NomInstall.DATABASE_ADMIN_URL)
  $NomResolvedPgBin = Assert-NomPg18Tooling -BinDirectory $PgBin

  $NomConfiguredKeyPath = $NomDefaultKeyFile
  $NomHadKeyProperty = $null -ne $NomInstall.PSObject.Properties['DATABASE_BACKUP_KEY_FILE']
  if ($NomHadKeyProperty) {
    if ([string]::IsNullOrWhiteSpace([string]$NomInstall.DATABASE_BACKUP_KEY_FILE)) {
      throw 'The configured backup key inventory path is empty.'
    }
    $NomConfiguredKeyPath = Resolve-NomLocalPath -Value ([string]$NomInstall.DATABASE_BACKUP_KEY_FILE) -Label 'Backup key inventory'
  }
  if (Test-Path -LiteralPath $NomConfiguredKeyPath -PathType Leaf) {
    $NomInventory = Read-NomJson -LiteralPath $NomConfiguredKeyPath
    Assert-NomKeyInventory -Inventory $NomInventory
    Protect-NomBackupPath -LiteralPath $NomConfiguredKeyPath
  }
  else {
    if ($NomHadKeyProperty) {
      throw 'The configured backup key inventory is missing; refusing to replace keys needed by historical backups.'
    }
    $NomInventory = [ordered]@{
      version = 1
      activeKeyId = [guid]::NewGuid().ToString()
      keys = @()
    }
    $NomInventory.keys = @([ordered]@{
      id = $NomInventory.activeKeyId
      createdAt = [DateTimeOffset]::UtcNow.ToString('o')
      status = 'active'
      keyB64 = New-NomRandomBase64Url 32
    })
    try {
      Write-NomAtomicJson -LiteralPath $NomConfiguredKeyPath -Value $NomInventory
    }
    finally {
      $NomInventory = $null
    }
  }

  $NomInstallChanged = $false
  if (Set-NomJsonProperty -Target $NomInstall -Name 'DATABASE_BACKUP_KEY_FILE' -Value $NomConfiguredKeyPath) {
    $NomInstallChanged = $true
  }
  if (Set-NomJsonProperty -Target $NomInstall -Name 'POSTGRES_BIN' -Value $NomResolvedPgBin) {
    $NomInstallChanged = $true
  }
  if ($NomInstallChanged) {
    Write-NomAtomicJson -LiteralPath $NomInstallFile -Value $NomInstall
  }
  else {
    Protect-NomBackupPath -LiteralPath $NomInstallFile
  }

  foreach ($NomDirectory in @($NomBackupRoot, $NomWorkRoot)) {
    New-Item -ItemType Directory -Path $NomDirectory -Force | Out-Null
    Protect-NomBackupPath -LiteralPath $NomDirectory -Container
  }
  return $NomConfiguredKeyPath
}

function Rotate-NomBackupKey {
  param([Parameter(Mandatory = $true)][string]$KeyFile)
  $NomInventory = Read-NomJson -LiteralPath $KeyFile
  Assert-NomKeyInventory -Inventory $NomInventory
  foreach ($NomKey in @($NomInventory.keys)) {
    $NomKey.status = 'retired'
  }
  $NomNewKey = [ordered]@{
    id = [guid]::NewGuid().ToString()
    createdAt = [DateTimeOffset]::UtcNow.ToString('o')
    status = 'active'
    keyB64 = New-NomRandomBase64Url 32
  }
  try {
    $NomInventory.activeKeyId = $NomNewKey.id
    $NomInventory.keys = @($NomInventory.keys) + @($NomNewKey)
    Write-NomAtomicJson -LiteralPath $KeyFile -Value $NomInventory
  }
  finally {
    $NomNewKey = $null
    $NomInventory = $null
  }
}

function Get-NomCanonicalTenantId {
  if ([string]::IsNullOrWhiteSpace($TenantId)) {
    throw 'A tenant UUID is required; backup operations never default to all tenants.'
  }
  $NomParsedTenant = [guid]::Empty
  if (-not [guid]::TryParse($TenantId, [ref]$NomParsedTenant)) {
    throw 'TenantId must be a UUID.'
  }
  return $NomParsedTenant.ToString()
}

function Invoke-NomTenantBackupTool {
  param([ValidateSet('backup', 'drill')][string]$Operation)
  $NomEntryPoint = Join-Path $NomPackageRoot 'dist\scripts\tenant-backup.js'
  if (-not (Test-Path -LiteralPath $NomEntryPoint -PathType Leaf)) {
    throw 'Compiled database tooling is missing. Build @nombramientos/database before backup operations.'
  }
  $NomNode = (Get-Command node -ErrorAction Stop).Source
  $NomArguments = @($NomEntryPoint, '--action', $Operation, '--tenant-id', (Get-NomCanonicalTenantId))
  if (-not [string]::IsNullOrWhiteSpace($BackupDirectory)) {
    if ($Operation -ne 'drill') { throw 'BackupDirectory is valid only for a restore drill.' }
    $NomArguments += @('--backup-dir', [System.IO.Path]::GetFullPath($BackupDirectory))
  }
  $NomOutput = @(& $NomNode @NomArguments)
  if ($LASTEXITCODE -ne 0) {
    throw "Tenant $Operation operation failed safely with exit code $LASTEXITCODE."
  }
  $NomResultLine = @($NomOutput | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Last 1)
  if ($NomResultLine.Count -ne 1) {
    throw 'Tenant backup tooling did not return its sanitized result.'
  }
  try {
    $NomResult = [string]$NomResultLine[0] | ConvertFrom-Json
  }
  catch {
    throw 'Tenant backup tooling returned an invalid sanitized result.'
  }
  $NomArtifact = [System.IO.Path]::GetFullPath([string]$NomResult.backupDirectory)
  $NomBackupBoundary = [System.IO.Path]::GetFullPath($NomBackupRoot).TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
  if (-not $NomArtifact.StartsWith($NomBackupBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Tenant backup tooling returned an artifact outside the protected backup root.'
  }
  if (-not (Test-Path -LiteralPath $NomArtifact -PathType Container)) {
    throw 'Tenant backup artifact directory is unavailable after completion.'
  }
  Protect-NomBackupPath -LiteralPath $NomArtifact -Container
  foreach ($NomArtifactItem in Get-ChildItem -LiteralPath $NomArtifact -Force -Recurse) {
    Protect-NomBackupPath -LiteralPath $NomArtifactItem.FullName -Container:($NomArtifactItem.PSIsContainer)
  }
  $NomOutput | Write-Output
}

$NomBackupKeyFile = Initialize-NomBackupConfiguration
switch ($Action) {
  'configure' {
    Write-Output 'Local backup configuration is ready; key material was not printed.'
  }
  'rotate-key' {
    Rotate-NomBackupKey -KeyFile $NomBackupKeyFile
    Write-Output 'The backup key was rotated; historical keys remain available for authenticated restore.'
  }
  'backup' {
    Invoke-NomTenantBackupTool -Operation 'backup'
  }
  'drill' {
    Invoke-NomTenantBackupTool -Operation 'drill'
  }
}
