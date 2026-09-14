[CmdletBinding()]
param(
  [ValidateSet('configure', 'checkpoint', 'verify', 'drill')]
  [string]$Action = 'verify',
  [string]$TenantId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$NomPackageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomWorkspaceRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '..\..'))
$NomLocalRoot = [System.IO.Path]::GetFullPath((Join-Path $NomPackageRoot '.local'))
$NomInstallFile = Join-Path $NomLocalRoot 'install.json'
$NomAuditRoot = Join-Path $NomLocalRoot 'audit-anchors'
$NomSigningInventory = Join-Path $NomLocalRoot 'audit-signing-keys.json'
$NomEntryPoint = Join-Path $NomPackageRoot 'dist\scripts\audit-anchor.js'

function Assert-NomPathInsideLocal {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [Parameter(Mandatory = $true)][string]$Label
  )
  $NomResolved = [System.IO.Path]::GetFullPath($LiteralPath)
  $NomBoundary = $NomLocalRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
  if (-not $NomResolved.StartsWith($NomBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "$Label must remain inside the package .local directory"
  }
  return $NomResolved
}

function Protect-NomAuditPath {
  param(
    [Parameter(Mandatory = $true)][string]$LiteralPath,
    [switch]$Container
  )
  if ($env:OS -ne 'Windows_NT') {
    $NomMode = if ($Container) { '700' } else { '600' }
    & chmod $NomMode -- $LiteralPath
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict local audit artifact permissions: $LiteralPath" }
    return
  }
  $NomIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
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
  if ($LASTEXITCODE -ne 0) { throw "Could not establish the required local audit ACL: $LiteralPath" }
  if ($NomWorkspaceOwner -match '(?i)\\CodexSandbox[^\\]*$' -and $NomWorkspaceOwner -ne $NomIdentity) {
    & icacls.exe $LiteralPath /remove:g $NomWorkspaceOwner *> $null
    if ($LASTEXITCODE -ne 0) { throw "Could not remove the technical workspace owner from the audit ACL: $LiteralPath" }
  }
}

function Get-NomCanonicalTenantId {
  if ([string]::IsNullOrWhiteSpace($TenantId)) {
    throw 'TenantId is required; audit tooling never defaults to every tenant.'
  }
  $NomParsed = [guid]::Empty
  if (-not [guid]::TryParse($TenantId, [ref]$NomParsed)) { throw 'TenantId must be a UUID.' }
  return $NomParsed.ToString()
}

if (-not (Test-Path -LiteralPath $NomInstallFile -PathType Leaf)) {
  throw 'Local install configuration is missing. Run the database bootstrap first.'
}
if (-not (Test-Path -LiteralPath $NomEntryPoint -PathType Leaf)) {
  throw 'Compiled audit tooling is missing. Build @nombramientos/database first.'
}

$NomInstall = Get-Content -LiteralPath $NomInstallFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($NomInstall.version -ne 1) { throw 'Unsupported local install configuration version.' }
$NomAdminUri = [System.Uri]::new([string]$NomInstall.DATABASE_ADMIN_URL)
if (
  [string]$NomInstall.DATABASE_ADMIN_URL -cnotmatch '^postgres(?:ql)?://nom_admin:[^@/?#]+@127\.0\.0\.1:55432/postgres$' -or
  $NomAdminUri.Scheme -notin @('postgres', 'postgresql') -or
  $NomAdminUri.Host -cne '127.0.0.1' -or
  $NomAdminUri.Port -ne 55432 -or
  $NomAdminUri.AbsolutePath -cne '/postgres' -or
  -not [string]::IsNullOrEmpty($NomAdminUri.Query) -or
  -not [string]::IsNullOrEmpty($NomAdminUri.Fragment)
) {
  throw 'Audit operations require the exact protected workspace PostgreSQL administrator endpoint.'
}

if ($Action -eq 'configure' -and -not [string]::IsNullOrWhiteSpace($TenantId)) {
  throw 'TenantId is not valid for configure.'
}
$NomCanonicalTenant = if ($Action -eq 'configure') { $null } else { Get-NomCanonicalTenantId }

foreach ($NomDirectory in @(
  $NomAuditRoot,
  (Join-Path $NomAuditRoot 'ledgers'),
  (Join-Path $NomAuditRoot 'receipts'),
  (Join-Path $NomAuditRoot 'work'),
  (Join-Path $NomAuditRoot 'locks')
)) {
  $NomSafeDirectory = Assert-NomPathInsideLocal -LiteralPath $NomDirectory -Label 'Audit directory'
  New-Item -ItemType Directory -Path $NomSafeDirectory -Force | Out-Null
}
Protect-NomAuditPath -LiteralPath $NomAuditRoot -Container

$NomNode = (Get-Command node -ErrorAction Stop).Source
$NomArguments = @($NomEntryPoint, '--action', $Action)
if ($null -ne $NomCanonicalTenant) { $NomArguments += @('--tenant-id', $NomCanonicalTenant) }
$NomOutput = @(& $NomNode @NomArguments)
if ($LASTEXITCODE -ne 0) {
  throw "Tenant audit $Action operation failed safely with exit code $LASTEXITCODE."
}
$NomResultLine = @($NomOutput | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Last 1)
if ($NomResultLine.Count -ne 1) { throw 'Audit tooling did not return its sanitized JSON result.' }
try {
  $NomResult = [string]$NomResultLine[0] | ConvertFrom-Json
}
catch {
  throw 'Audit tooling returned an invalid sanitized JSON result.'
}
$NomResultJson = $NomResult | ConvertTo-Json -Depth 12 -Compress
if ($NomResultJson -match '"(?:password|privateKey|secret|connectionString|keyB64|privateKeyPkcs8Pem)"') {
  throw 'Audit tooling attempted to return a sensitive field.'
}
if ($null -ne $NomCanonicalTenant -and [string]$NomResult.tenantId -ne $NomCanonicalTenant) {
  throw 'Audit tooling returned a result for another tenant.'
}

if (Test-Path -LiteralPath $NomSigningInventory -PathType Leaf) {
  Protect-NomAuditPath -LiteralPath (Assert-NomPathInsideLocal -LiteralPath $NomSigningInventory -Label 'Signing inventory')
}
foreach ($NomArtifact in Get-ChildItem -LiteralPath $NomAuditRoot -Force -Recurse) {
  $NomSafeArtifact = Assert-NomPathInsideLocal -LiteralPath $NomArtifact.FullName -Label 'Audit artifact'
  Protect-NomAuditPath -LiteralPath $NomSafeArtifact -Container:($NomArtifact.PSIsContainer)
}

$NomOutput | Write-Output
