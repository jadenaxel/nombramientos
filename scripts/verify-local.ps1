[CmdletBinding()]
param(
  [switch]$SkipE2E
)

$ErrorActionPreference = 'Stop'
$NomRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$NomArtifactsDirectory = Join-Path $NomRoot 'artifacts'
$NomRunLockPath = Join-Path $NomArtifactsDirectory '.verify-local.lock'
$NomRunLockStream = $null

function Open-NomRunLock {
  param([Parameter(Mandatory)][string]$Path)
  try {
    return [System.IO.File]::Open(
      $Path,
      [System.IO.FileMode]::OpenOrCreate,
      [System.IO.FileAccess]::ReadWrite,
      [System.IO.FileShare]::None
    )
  }
  catch [System.IO.IOException] {
    throw 'Another verify:local run already owns the exclusive verification lock.'
  }
}

function Get-NomEvidenceFileSha256 {
  param([Parameter(Mandatory)][string]$LiteralPath)
  $NomHashStream = $null
  $NomHashAlgorithm = $null
  try {
    $NomHashStream = [System.IO.File]::Open(
      $LiteralPath,
      [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read,
      [System.IO.FileShare]::Read
    )
    $NomHashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
    $NomHashBytes = $NomHashAlgorithm.ComputeHash($NomHashStream)
    return ([System.BitConverter]::ToString($NomHashBytes).Replace('-', '').ToLowerInvariant())
  }
  finally {
    if ($null -ne $NomHashAlgorithm) { $NomHashAlgorithm.Dispose() }
    if ($null -ne $NomHashStream) { $NomHashStream.Dispose() }
  }
}

function Move-NomVerificationEvidenceToHistory {
  param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [Parameter(Mandatory)][string]$ArtifactsDirectory
  )
  $NomCanonicalArtifacts = [System.IO.Path]::GetFullPath($ArtifactsDirectory)
  $NomCanonicalEvidence = [System.IO.Path]::GetFullPath($EvidencePath)
  $NomArtifactsBoundary = $NomCanonicalArtifacts.TrimEnd([char[]]@('\', '/')) +
    [System.IO.Path]::DirectorySeparatorChar
  if (-not $NomCanonicalEvidence.StartsWith($NomArtifactsBoundary, [System.StringComparison]::OrdinalIgnoreCase) -or
      [System.IO.Path]::GetDirectoryName($NomCanonicalEvidence) -ine $NomCanonicalArtifacts -or
      [System.IO.Path]::GetFileName($NomCanonicalEvidence) -cne 'verify-local-final.json') {
    throw 'Historical verification archival accepts only the canonical artifacts/verify-local-final.json path.'
  }
  if (-not [System.IO.File]::Exists($NomCanonicalEvidence)) { return $null }

  $NomArtifactsInfo = Get-Item -LiteralPath $NomCanonicalArtifacts -Force -ErrorAction Stop
  $NomEvidenceInfo = Get-Item -LiteralPath $NomCanonicalEvidence -Force -ErrorAction Stop
  if (($NomArtifactsInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      ($NomEvidenceInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Verification evidence archival refuses reparse points.'
  }

  $NomHistoryDirectory = [System.IO.Path]::Combine($NomCanonicalArtifacts, 'history')
  if ([System.IO.File]::Exists($NomHistoryDirectory)) {
    throw 'Verification evidence history must be a directory.'
  }
  [System.IO.Directory]::CreateDirectory($NomHistoryDirectory) | Out-Null
  $NomHistoryInfo = Get-Item -LiteralPath $NomHistoryDirectory -Force -ErrorAction Stop
  if (($NomHistoryInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
      -not $NomHistoryInfo.PSIsContainer -or
      -not $NomHistoryInfo.FullName.StartsWith($NomArtifactsBoundary, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Verification evidence history resolved outside its guarded artifacts directory.'
  }

  $NomEvidenceSha256 = Get-NomEvidenceFileSha256 -LiteralPath $NomCanonicalEvidence
  if ($NomEvidenceSha256 -notmatch '^[a-f0-9]{64}$') {
    throw 'Historical verification evidence did not produce a canonical SHA-256.'
  }
  $NomHistoryPath = [System.IO.Path]::Combine(
    $NomHistoryDirectory,
    ('verify-local-final.sha256-' + $NomEvidenceSha256 + '.json')
  )
  if ([System.IO.File]::Exists($NomHistoryPath) -or [System.IO.Directory]::Exists($NomHistoryPath)) {
    throw 'The deterministic historical verification evidence destination already exists; refusing to overwrite it.'
  }

  [System.IO.File]::Move($NomCanonicalEvidence, $NomHistoryPath)
  $NomArchivedInfo = Get-Item -LiteralPath $NomHistoryPath -Force -ErrorAction Stop
  $NomArchivedInfo.IsReadOnly = $true
  $NomArchivedInfo.Refresh()
  if (-not $NomArchivedInfo.IsReadOnly) {
    throw 'Historical verification evidence could not be marked read-only.'
  }
  $NomArchivedSha256 = Get-NomEvidenceFileSha256 -LiteralPath $NomHistoryPath
  if ($NomArchivedSha256 -cne $NomEvidenceSha256) {
    throw 'Historical verification evidence changed during archival.'
  }
  return $NomHistoryPath
}

[System.IO.Directory]::CreateDirectory($NomArtifactsDirectory) | Out-Null
$NomRunLockStream = Open-NomRunLock -Path $NomRunLockPath
$NomEarlyEvidencePath = Join-Path $NomArtifactsDirectory 'verify-local-final.json'
$NomArchivedEvidencePath = Move-NomVerificationEvidenceToHistory `
  -EvidencePath $NomEarlyEvidencePath `
  -ArtifactsDirectory $NomArtifactsDirectory

$NomPnpm = (Get-Command pnpm.cmd -ErrorAction Stop).Source
$NomNode = (Get-Command node.exe -ErrorAction Stop).Source
$NomStopScript = Join-Path $PSScriptRoot 'stop-local.ps1'
$NomStartScript = Join-Path $PSScriptRoot 'start-local.ps1'
$NomEvidenceScript = Join-Path $PSScriptRoot 'verify-local-evidence.mjs'
$NomAllowlistPath = Join-Path $NomRoot 'apps\web\e2e\intentional-skips.json'
$NomFinalEvidencePath = Join-Path $NomRoot 'artifacts\verify-local-final.json'
$NomScratchDirectory = Join-Path $NomRoot ('artifacts\.verify-local-' + [guid]::NewGuid().ToString('N'))
$NomRunEvidencePath = Join-Path $NomScratchDirectory 'run.json'
$NomPlaywrightEvidencePath = Join-Path $NomScratchDirectory 'playwright.json'
$NomRunStartedAt = [DateTime]::UtcNow.ToString('o')
$NomRunFailed = $false
$NomCapturedError = $null
$NomFinalizerExit = 0
$NomPostgresBinaryVersion = $null
$NomNodeVersion = $null
$NomPnpmVersion = $null
$NomEngineProbeExit = $null
$NomEngineResults = $null
$NomLocalStateReport = $null
$NomSourceSnapshotStart = $null
$NomSourceSnapshotEnd = $null
$NomFreshServicesStarted = $false
$NomTerminalHealthPassed = $false
$NomFailureCleanupAttempted = $false
$NomFailureCleanupSucceeded = $null
$NomLocationPushed = $false
$NomRunRecord = $null
$NomFinalizeArguments = $null
$NomStages = [System.Collections.Generic.List[object]]::new()
$NomInheritedEnvironmentNames = @(
  'TEST_DATABASE_ADMIN_URL',
  'TEST_CONTROL_DATABASE_URL',
  'TEST_TENANT_DATABASE_URL',
  'TEST_SEED_DATABASE_ADMIN_URL',
  'DATABASE_ADMIN_URL',
  'DATABASE_CONTROL_URL',
  'DATABASE_SECRET_MASTER_KEY_B64',
  'AUTH_ENCRYPTION_KEY_B64',
  'DATABASE_SECRET_FILE',
  'DEMO_ACCESS_FILE',
  'NOMBRAMIENTOS_REQUIRE_SEED_AUDIT_LIVE',
  'NOMBRAMIENTOS_E2E_SESSION_COOKIES_B64',
  'KEY_LIFECYCLE_TEST_LOCALE',
  'NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64',
  'NOMBRAMIENTOS_REAL_STACK_HARNESS_URL',
  'NOMBRAMIENTOS_REAL_STACK_USER_AGENT',
  'API_SESSION_TTL_SECONDS',
  'DATABASE_POOL_MAX_PER_TENANT',
  'DATABASE_POOL_IDLE_MS'
)

function Add-NomStage {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$StartedAtUtc,
    [Parameter(Mandatory)][AllowNull()][Nullable[int]]$ExitCode,
    [Parameter(Mandatory)][string]$Status,
    [AllowNull()][object]$Counts = $null,
    [AllowNull()][string]$ErrorCode = $null
  )
  # Windows PowerShell coerces an omitted nullable [string] parameter to an
  # empty string. Normalize it explicitly so successful stages serialize the
  # contractually required JSON null instead of a spurious error code.
  $NomSafeErrorCode = if ([string]::IsNullOrWhiteSpace($ErrorCode)) { $null } else { $ErrorCode }
  $NomStages.Add([pscustomobject][ordered]@{
    name = $Name
    startedAtUtc = $StartedAtUtc
    completedAtUtc = [DateTime]::UtcNow.ToString('o')
    exitCode = $ExitCode
    status = $Status
    counts = $Counts
    errorCode = $NomSafeErrorCode
  })
}

function Get-NomCounter {
  param(
    [Parameter(Mandatory)][string]$Line
  )
  if ($Line -match '(?i)\b(todo|cancelled|canceled|pending)\b') { return $null }
  $NomPassed = if ($Line -match '(?<!\d)(\d+)\s+passed\b') { [int]$Matches[1] } else { 0 }
  $NomFailed = if ($Line -match '(?<!\d)(\d+)\s+failed\b') { [int]$Matches[1] } else { 0 }
  $NomSkipped = if ($Line -match '(?<!\d)(\d+)\s+skipped\b') { [int]$Matches[1] } else { 0 }
  $NomTotal = $NomPassed + $NomFailed + $NomSkipped
  $NomReportedTotals = [regex]::Matches($Line, '\((\d+)\)\s*$')
  if ($NomTotal -lt 1 -or $NomReportedTotals.Count -ne 1) { return $null }
  $NomReportedTotal = [int]$NomReportedTotals[0].Groups[1].Value
  if ($NomReportedTotal -ne $NomTotal) { return $null }
  return [pscustomobject][ordered]@{
    total = $NomTotal
    passed = $NomPassed
    failed = $NomFailed
    skipped = $NomSkipped
  }
}

function Get-NomTestCounts {
  param(
    # Test runners emit blank separator lines. Windows PowerShell applies the
    # Mandatory empty-string validation to collection elements during binding,
    # so explicitly admit those separators and let the parser validate only the
    # authoritative summary records below.
    [Parameter(Mandatory)][AllowEmptyString()][System.Collections.Generic.List[string]]$Lines,
    [Parameter(Mandatory)][ValidateSet('tap', 'vitest')][string]$Kind,
    [Parameter(Mandatory)][int]$ProcessExitCode,
    [int]$ExpectedFileCount = 0
  )
  $NomText = (($Lines -join "`n") -replace ([regex]::Escape([string][char]27) + '\[[0-9;]*[A-Za-z]'), '')
  $NomSuiteCounter = [pscustomobject][ordered]@{
    total = 1
    passed = if ($ProcessExitCode -eq 0) { 1 } else { 0 }
    failed = if ($ProcessExitCode -eq 0) { 0 } else { 1 }
    skipped = 0
  }
  if ($Kind -eq 'tap') {
    # Node selects TAP for non-interactive output and the spec reporter for a
    # terminal. Accept both exact summary prefixes so evidence is stable in CI
    # and in the local PowerShell host.
    $NomTests = [regex]::Matches($NomText, '(?m)^\s*(?:#|\u2139)\s+tests\s+(\d+)\s*$')
    $NomPassed = [regex]::Matches($NomText, '(?m)^\s*(?:#|\u2139)\s+pass\s+(\d+)\s*$')
    $NomFailed = [regex]::Matches($NomText, '(?m)^\s*(?:#|\u2139)\s+fail\s+(\d+)\s*$')
    $NomSkipped = [regex]::Matches($NomText, '(?m)^\s*(?:#|\u2139)\s+skipped\s+(\d+)\s*$')
    if ($NomTests.Count -eq 0 -or $NomPassed.Count -eq 0 -or $NomFailed.Count -eq 0) { return $null }
    $NomTestTotal = [int]$NomTests[$NomTests.Count - 1].Groups[1].Value
    $NomTestPassed = [int]$NomPassed[$NomPassed.Count - 1].Groups[1].Value
    $NomTestFailed = [int]$NomFailed[$NomFailed.Count - 1].Groups[1].Value
    $NomTestSkipped = if ($NomSkipped.Count -gt 0) { [int]$NomSkipped[$NomSkipped.Count - 1].Groups[1].Value } else { 0 }
    if ($NomTestTotal -ne ($NomTestPassed + $NomTestFailed + $NomTestSkipped) -or $ExpectedFileCount -lt 1) { return $null }
    $NomFileCounter = [pscustomobject][ordered]@{
      total = $ExpectedFileCount
      passed = if ($ProcessExitCode -eq 0) { $ExpectedFileCount } else { 0 }
      failed = if ($ProcessExitCode -eq 0) { 0 } else { $ExpectedFileCount }
      skipped = 0
    }
    return [pscustomobject][ordered]@{
      suites = $NomSuiteCounter
      files = $NomFileCounter
      tests = [pscustomobject][ordered]@{
        total = $NomTestTotal
        passed = $NomTestPassed
        failed = $NomTestFailed
        skipped = $NomTestSkipped
      }
    }
  }

  $NomFileLines = [regex]::Matches($NomText, '(?m)^\s*Test Files\s+(.+?)\s*$')
  $NomTestLines = [regex]::Matches($NomText, '(?m)^\s*Tests\s+(.+?)\s*$')
  if ($NomFileLines.Count -eq 0 -or $NomTestLines.Count -eq 0) { return $null }
  $NomFileCounter = Get-NomCounter -Line $NomFileLines[$NomFileLines.Count - 1].Groups[1].Value
  $NomTestCounter = Get-NomCounter -Line $NomTestLines[$NomTestLines.Count - 1].Groups[1].Value
  if ($null -eq $NomFileCounter -or $null -eq $NomTestCounter) { return $null }
  if ($NomFileCounter.total -lt 1 -or $NomTestCounter.total -lt 1) { return $null }
  return [pscustomobject][ordered]@{
    suites = $NomSuiteCounter
    files = $NomFileCounter
    tests = $NomTestCounter
  }
}

function Protect-NomProcessOutputLine {
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Line
  )

  # Native stderr is surfaced as a PowerShell ErrorRecord on Windows. Never
  # forward that original object: the host formatter can recursively expand
  # properties (including pg Client connection parameters) that were not in
  # the process's intended textual diagnostic. Normalize to plain text first,
  # strip terminal control sequences, and redact common credential/PII forms.
  $NomProtectedLine = $Line -replace (
    [regex]::Escape([string][char]27) + '\[[0-9;?]*[ -/]*[@-~]'
  ), ''
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '(?i)\b(postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mongodb(?:\+srv)?):\/\/[^\s:@\/]+:[^\s@\/]+@',
    '$1://[REDACTED]@'
  )
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '(?i)\b(?<name>(?:DATABASE|REDIS|SMTP|JWT|SESSION|COOKIE|AUTH|TOTP|MFA|INVITATION|RECOVERY)[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|URL|KEY)[A-Z0-9_]*)\s*=\s*(?:"(?:\\.|[^"])*"|''(?:\\.|[^''])*''|[^\s,;}]+)',
    '${name}=[REDACTED]'
  )
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '(?i)(?<prefix>["'']?(?:password|passphrase|secret|token|cookie|authorization|recovery[_-]?code|totp[_-]?secret|api[_-]?key|private[_-]?key|user(?:name)?|database|email|phone|mobile|display[_-]?name|full[_-]?name)["'']?\s*[:=]\s*)(?:"(?:\\.|[^"])*"|''(?:\\.|[^''])*''|[^,;}\]\r\n]+)',
    '${prefix}[REDACTED]'
  )
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
    '[REDACTED_EMAIL]'
  )
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '(?i)\b[A-Z]:\\Users\\[^\\\s"'']+',
    '[REDACTED_USER_PROFILE]'
  )
  $NomProtectedLine = [regex]::Replace(
    $NomProtectedLine,
    '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    '[REDACTED_ACCESS_KEY]'
  )
  return $NomProtectedLine
}

function Invoke-NomPnpmStage {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string[]]$Arguments,
    [ValidateSet('none', 'tap', 'vitest')][string]$SummaryKind = 'none',
    [int]$ExpectedFileCount = 0
  )
  $NomStartedAt = [DateTime]::UtcNow.ToString('o')
  $NomLines = [System.Collections.Generic.List[string]]::new()
  $NomExit = 1
  $NomPreviousErrorActionPreference = $ErrorActionPreference
  try {
    # pnpm writes its script banner to stderr even on exit 0. Under Windows
    # PowerShell 5, ErrorActionPreference=Stop turns that native stderr record
    # into a terminating NativeCommandError before LASTEXITCODE can be checked.
    # Capture both streams, but let the native exit code remain authoritative.
    $ErrorActionPreference = 'Continue'
    & $NomPnpm @Arguments 2>&1 | ForEach-Object {
      $NomLine = $_.ToString()
      $NomSafeLine = Protect-NomProcessOutputLine -Line $NomLine
      $NomLines.Add($NomSafeLine)
      Write-Output $NomSafeLine
    }
    $NomExit = $LASTEXITCODE
  }
  catch {
    Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode 1 -Status 'failed' -ErrorCode 'PROCESS_LAUNCH_FAILED'
    throw
  }
  finally {
    $ErrorActionPreference = $NomPreviousErrorActionPreference
  }
  $NomCounts = if ($SummaryKind -eq 'none') {
    $null
  } else {
    Get-NomTestCounts -Lines $NomLines -Kind $SummaryKind -ProcessExitCode $NomExit -ExpectedFileCount $ExpectedFileCount
  }
  if ($NomExit -ne 0) {
    Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode $NomExit -Status 'failed' -Counts $NomCounts -ErrorCode 'PROCESS_EXIT_NONZERO'
    throw "Verification stage failed: $Name"
  }
  if ($SummaryKind -ne 'none' -and $null -eq $NomCounts) {
    Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode 1 -Status 'failed' -ErrorCode 'TEST_SUMMARY_UNPARSEABLE'
    throw "Verification stage did not produce a complete test summary: $Name"
  }
  Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode $NomExit -Status 'passed' -Counts $NomCounts
}

function Invoke-NomActionStage {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Action
  )
  $NomStartedAt = [DateTime]::UtcNow.ToString('o')
  try {
    & $Action
    Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode 0 -Status 'passed'
  }
  catch {
    Add-NomStage -Name $Name -StartedAtUtc $NomStartedAt -ExitCode 1 -Status 'failed' -ErrorCode 'CHECK_FAILED'
    throw
  }
}

function Invoke-NomCapturedNativeCommand {
  param(
    [Parameter(Mandatory)][string]$NodePath,
    [Parameter(Mandatory)][string[]]$Arguments
  )
  $NomPreviousErrorActionPreference = $ErrorActionPreference
  $NomOutput = [System.Collections.Generic.List[string]]::new()
  $NomExitCode = 1
  try {
    # Windows PowerShell 5 promotes native stderr to NativeCommandError when
    # ErrorActionPreference is Stop. The finalizer deliberately writes useful
    # diagnostics to stderr on exceptional failures, so capture both streams
    # while keeping the native process exit code authoritative.
    $ErrorActionPreference = 'Continue'
    & $NodePath @Arguments 2>&1 | ForEach-Object {
      [void]$NomOutput.Add($_.ToString())
    }
    if ($null -ne $LASTEXITCODE -and [int]$LASTEXITCODE -ge 0) {
      $NomExitCode = [int]$LASTEXITCODE
    }
  }
  catch {
    [void]$NomOutput.Add($_.ToString())
    $NomExitCode = 1
  }
  finally {
    $ErrorActionPreference = $NomPreviousErrorActionPreference
  }
  return [pscustomobject][ordered]@{
    exitCode = $NomExitCode
    output = @($NomOutput)
  }
}

function Invoke-NomFinalizationCycle {
  param(
    [Parameter(Mandatory)][bool]$RunWasAlreadyFailed,
    [Parameter(Mandatory)][scriptblock]$PublishAction,
    [Parameter(Mandatory)][scriptblock]$RepairAndPersistAction
  )

  function Invoke-NomCheckedPublishAction {
    param([Parameter(Mandatory)][scriptblock]$Action)
    $NomPublishOutput = @(& $Action)
    $NomParsedExitCode = 0
    if ($NomPublishOutput.Count -ne 1 -or
      -not [int]::TryParse([string]$NomPublishOutput[0], [ref]$NomParsedExitCode) -or
      $NomParsedExitCode -lt 0) {
      throw 'The evidence finalizer did not return exactly one valid native exit code.'
    }
    return $NomParsedExitCode
  }

  try {
    $NomFirstPublishExit = Invoke-NomCheckedPublishAction -Action $PublishAction
  }
  catch {
    Write-Warning 'The first evidence publication attempt raised an exception; treating it as a finalizer failure.'
    $NomFirstPublishExit = 1
  }
  if ($NomFirstPublishExit -eq 0 -or $RunWasAlreadyFailed) {
    return $NomFirstPublishExit
  }

  # A failure discovered only during publication must transition the run to
  # failed, stop application processes, persist that actual cleanup outcome,
  # and publish again. A successful second publisher can never erase the first
  # failing outcome.
  try {
    & $RepairAndPersistAction | Out-Host
  }
  catch {
    Write-Warning 'Post-finalizer cleanup or failure-state persistence failed.'
    return 1
  }
  try {
    $NomSecondPublishExit = Invoke-NomCheckedPublishAction -Action $PublishAction
  }
  catch {
    Write-Warning 'The post-cleanup evidence republication raised an exception.'
    return 1
  }
  if ($NomSecondPublishExit -eq 0) { return 1 }
  return $NomSecondPublishExit
}

function Invoke-NomPdfRenderQa {
  param(
    [Parameter(Mandatory)][string]$PdfInfoPath,
    [Parameter(Mandatory)][string]$PdfToPpmPath,
    [Parameter(Mandatory)][string]$PdfPath,
    [Parameter(Mandatory)][string]$RenderDirectory
  )

  New-Item -ItemType Directory -Path $RenderDirectory -Force | Out-Null
  try {
    $NomPdfInfoResult = Invoke-NomCapturedNativeCommand -NodePath $PdfInfoPath -Arguments @($PdfPath)
    if ($NomPdfInfoResult.exitCode -ne 0) {
      throw 'pdfinfo could not inspect the generated PDF.'
    }
    $NomPdfInfoText = @($NomPdfInfoResult.output) -join "`n"
    $NomDeclaredPageMatches = [regex]::Matches($NomPdfInfoText, '(?im)^Pages:\s+([1-9]\d*)\s*$')
    $NomDeclaredPageCount = 0
    if ($NomDeclaredPageMatches.Count -ne 1 -or
      -not [int]::TryParse($NomDeclaredPageMatches[0].Groups[1].Value, [ref]$NomDeclaredPageCount) -or
      $NomDeclaredPageCount -lt 1) {
      throw 'pdfinfo did not report exactly one valid positive page count.'
    }

    $NomRenderPrefix = Join-Path $RenderDirectory 'report'
    $NomPdfRenderResult = Invoke-NomCapturedNativeCommand `
      -NodePath $PdfToPpmPath `
      -Arguments @('-png', '-r', '96', $PdfPath, $NomRenderPrefix)
    foreach ($NomDiagnostic in @($NomPdfRenderResult.output)) {
      Write-Host $NomDiagnostic
    }
    $NomPdfDiagnostics = @($NomPdfRenderResult.output) -join "`n"
    if ($NomPdfRenderResult.exitCode -ne 0 -or $NomPdfDiagnostics -match "Syntax Error|Couldn't create a font") {
      throw 'The generated PDF failed independent Poppler rendering.'
    }
    $NomRenderedPdfPages = @(Get-ChildItem -LiteralPath $RenderDirectory -Filter 'report-*.png' -File)
    if ($NomRenderedPdfPages.Count -ne $NomDeclaredPageCount) {
      throw 'The independently rendered PDF page count does not exactly match pdfinfo.'
    }
    if (@($NomRenderedPdfPages | Where-Object { $_.Length -lt 1KB }).Count -gt 0) {
      throw 'One or more independently rendered PDF pages are empty.'
    }
    return [pscustomobject][ordered]@{
      declaredPageCount = $NomDeclaredPageCount
      renderedPageCount = $NomRenderedPdfPages.Count
    }
  }
  finally {
    Get-ChildItem -LiteralPath $RenderDirectory -Filter 'report-*.png' -File -ErrorAction SilentlyContinue |
      Remove-Item -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $RenderDirectory -Force -ErrorAction SilentlyContinue
  }
}

function Get-NomSourceFingerprint {
  $NomFingerprintOutput = @(& $NomNode $NomEvidenceScript fingerprint-sources --workspace $NomRoot 2>&1)
  $NomFingerprintExit = $LASTEXITCODE
  $NomFingerprintLines = @($NomFingerprintOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -ne '' })
  if ($NomFingerprintExit -ne 0 -or $NomFingerprintLines.Count -ne 1) {
    throw 'Workspace source fingerprinting did not emit exactly one successful JSON record.'
  }
  $NomFingerprint = $NomFingerprintLines[0] | ConvertFrom-Json
  if ($NomFingerprint.schemaVersion -ne 1 -or $NomFingerprint.algorithm -ne 'sha256' -or [int]$NomFingerprint.fileCount -lt 1 -or [string]$NomFingerprint.sha256 -notmatch '^[a-f0-9]{64}$') {
    throw 'Workspace source fingerprinting returned an invalid record.'
  }
  return $NomFingerprint
}

function Assert-NomTerminalHealth {
  $NomServiceStatePath = Join-Path $NomRoot '.local\services.json'
  if (-not (Test-Path -LiteralPath $NomServiceStatePath -PathType Leaf)) {
    throw 'The fresh service process record is missing.'
  }
  $NomServiceState = Get-Content -LiteralPath $NomServiceStatePath -Raw | ConvertFrom-Json
  $NomProcessDescriptors = @(
    [pscustomobject]@{ Name = 'worker'; PidProperty = 'workerPid'; StartedProperty = 'workerStartedAt' },
    [pscustomobject]@{ Name = 'API'; PidProperty = 'apiPid'; StartedProperty = 'apiStartedAt' },
    [pscustomobject]@{ Name = 'web'; PidProperty = 'webPid'; StartedProperty = 'webStartedAt' }
  )
  foreach ($NomProcessDescriptor in $NomProcessDescriptors) {
    $NomProcessId = [int]$NomServiceState.PSObject.Properties[$NomProcessDescriptor.PidProperty].Value
    $NomRecordedStartText = [string]$NomServiceState.PSObject.Properties[$NomProcessDescriptor.StartedProperty].Value
    if ($NomProcessId -lt 1 -or [string]::IsNullOrWhiteSpace($NomRecordedStartText)) {
      throw "The recorded $($NomProcessDescriptor.Name) process identity is incomplete."
    }
    $NomProcess = Get-Process -Id $NomProcessId -ErrorAction Stop
    $NomRecordedStart = [DateTime]::Parse(
      $NomRecordedStartText,
      [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::RoundtripKind
    ).ToUniversalTime()
    $NomActualStart = $NomProcess.StartTime.ToUniversalTime()
    if ([Math]::Abs(($NomActualStart - $NomRecordedStart).TotalSeconds) -gt 2) {
      throw "The recorded $($NomProcessDescriptor.Name) PID belongs to a different process generation."
    }
  }
  $NomTerminalApi = Invoke-RestMethod -Uri 'http://127.0.0.1:4000/healthz' -TimeoutSec 5
  $NomTerminalWeb = Invoke-WebRequest -Uri 'http://127.0.0.1:3000/healthz' -TimeoutSec 5 -UseBasicParsing
  if ($NomTerminalApi.status -ne 'ok' -or $NomTerminalApi.worker.healthy -ne $true -or $NomTerminalWeb.StatusCode -ne 200) {
    throw 'Terminal API/web/worker health is not fully green.'
  }
}

New-Item -ItemType Directory -Path $NomScratchDirectory -Force | Out-Null
Remove-Item Env:NOMBRAMIENTOS_E2E_EVIDENCE_FILE -ErrorAction SilentlyContinue
$NomVerificationMode = if ($SkipE2E) { 'skip-e2e' } else { 'complete' }
& $NomNode $NomEvidenceScript initialize --output $NomFinalEvidencePath --started-at $NomRunStartedAt --lockfile (Join-Path $NomRoot 'pnpm-lock.yaml') --mode $NomVerificationMode | Write-Output
if ($LASTEXITCODE -ne 0) { throw 'Fail-closed verification evidence could not be initialized.' }

Push-Location $NomRoot
$NomLocationPushed = $true
try {
  # Closure QA is deliberately pinned to the protected workspace stack. Clear
  # inherited target/credential routing before any build or live test can use it.
  $env:NOMBRAMIENTOS_E2E_TARGET = 'workspace'
  $env:WEB_BASE_URL = 'http://localhost:3000'
  $env:NEXT_PUBLIC_API_URL = 'http://localhost:4000'
  $env:NOMBRAMIENTOS_WEB_HOST = '127.0.0.1'
  $env:NOMBRAMIENTOS_WEB_PORT = '3000'
  $env:API_HOST = '127.0.0.1'
  $env:API_PORT = '4000'
  $env:API_CORS_ORIGINS = 'http://localhost:3000'
  $env:API_COOKIE_SECURE = 'false'
  $env:DATABASE_LOCAL_INSTALL_FILE = Join-Path $NomRoot 'packages\database\.local\install.json'
  Remove-Item Env:NODE_ENV -ErrorAction SilentlyContinue
  foreach ($NomInheritedEnvironmentName in $NomInheritedEnvironmentNames) {
    Remove-Item -LiteralPath ("Env:" + $NomInheritedEnvironmentName) -ErrorAction SilentlyContinue
  }
  $NomInheritedEnvironmentStillSet = @($NomInheritedEnvironmentNames | Where-Object {
    Test-Path -LiteralPath ("Env:" + $_)
  })
  if ($NomInheritedEnvironmentStillSet.Count -gt 0) {
    throw 'Inherited verification routing or coverage overrides could not be cleared.'
  }
  $env:NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION = 'true'
  $env:NOMBRAMIENTOS_PRIVILEGE_LIVE = 'true'

  Invoke-NomActionStage -Name 'source-snapshot-start' -Action {
    $script:NomSourceSnapshotStart = Get-NomSourceFingerprint
  }

  Invoke-NomActionStage -Name 'initial-health' -Action {
    $NomHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:4000/healthz' -TimeoutSec 5
    if ($NomHealth.status -ne 'ok') { throw 'API health check failed.' }
  }
  Invoke-NomActionStage -Name 'live-prerequisites' -Action {
    if (-not (Test-Path -LiteralPath (Join-Path $NomRoot 'packages\database\.local\demo-access.json') -PathType Leaf)) {
      throw 'Real local integration prerequisites are missing; verification will not silently skip PostgreSQL.'
    }
    $NomPostgres = 'C:\Program Files\PostgreSQL\18\bin\postgres.exe'
    if (-not (Test-Path -LiteralPath $NomPostgres -PathType Leaf)) { throw 'The PostgreSQL 18 binary is missing.' }
    $NomPostgresVersionOutput = & $NomPostgres --version
    if ($LASTEXITCODE -ne 0 -or $NomPostgresVersionOutput -notmatch '(\d+\.\d+(?:\.\d+)?)') {
      throw 'The PostgreSQL binary version could not be established.'
    }
    $script:NomPostgresBinaryVersion = $Matches[1]
    if ($script:NomPostgresBinaryVersion -notmatch '^18(?:\.|$)') {
      throw 'The PostgreSQL binary is not major version 18.'
    }
    $NomNodeVersionOutput = ((& $NomNode --version) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $NomNodeVersionOutput -notmatch '^v24\.\d+\.\d+$') {
      throw 'Node must satisfy >=24.0.0 <25.'
    }
    $script:NomNodeVersion = $NomNodeVersionOutput
    $NomPnpmVersionOutput = ((& $NomPnpm --version) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $NomPnpmVersionOutput -cne '11.19.0') {
      throw 'pnpm must be exactly 11.19.0.'
    }
    $script:NomPnpmVersion = $NomPnpmVersionOutput
  }

  Invoke-NomPnpmStage -Name 'supply-chain' -Arguments @('run', 'security:supply-chain')
  Invoke-NomPnpmStage -Name 'dependency-audit' -Arguments @('audit', '--prod', '--audit-level', 'high')
  Invoke-NomPnpmStage -Name 'typecheck' -Arguments @('run', 'typecheck')
  Invoke-NomPnpmStage -Name 'lint' -Arguments @('run', 'lint')

  Invoke-NomActionStage -Name 'stop-services-before-build' -Action { & $NomStopScript -KeepDatabase }
  Invoke-NomPnpmStage -Name 'build' -Arguments @('run', 'build')
  Invoke-NomActionStage -Name 'start-fresh-services' -Action {
    & $NomStartScript
    $script:NomFreshServicesStarted = $true
  }
  Invoke-NomActionStage -Name 'fresh-health' -Action {
    $NomFreshHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:4000/healthz' -TimeoutSec 5
    if ($NomFreshHealth.status -ne 'ok' -or $NomFreshHealth.worker.healthy -ne $true) {
      throw 'Freshly built API/worker health check failed.'
    }
  }

  $NomDomainFiles = @(Get-ChildItem -LiteralPath (Join-Path $NomRoot 'packages\domain\test') -Filter '*.test.mjs' -File).Count
  $NomWebTestScript = (Get-Content -LiteralPath (Join-Path $NomRoot 'apps\web\package.json') -Raw | ConvertFrom-Json).scripts.'test:unit'
  $NomWebFiles = @([regex]::Matches($NomWebTestScript, '(?<!\S)(?:lib/)?[^\s]+\.test\.ts\b')).Count
  Invoke-NomPnpmStage -Name 'verification-contract' -Arguments @('run', 'test:verification') -SummaryKind 'tap' -ExpectedFileCount 3
  Invoke-NomPnpmStage -Name 'test-domain' -Arguments @('--filter', '@nombramientos/domain', 'test') -SummaryKind 'tap' -ExpectedFileCount $NomDomainFiles
  Invoke-NomPnpmStage -Name 'test-e2ee' -Arguments @('--filter', '@nombramientos/e2ee', 'test') -SummaryKind 'vitest'
  # The seed-history proof is an explicit destructive maintenance ceremony. It is
  # never part of ordinary closure verification and must not be enabled through
  # an inherited environment flag.
  Invoke-NomPnpmStage -Name 'test-database' -Arguments @(
    '--filter', '@nombramientos/database', 'test',
    '--exclude', 'test/seed-audit-history.live.test.ts'
  ) -SummaryKind 'vitest'
  Invoke-NomPnpmStage -Name 'test-api' -Arguments @('--filter', '@nombramientos/api', 'test') -SummaryKind 'vitest'
  Invoke-NomPnpmStage -Name 'test-web' -Arguments @('--filter', '@nombramientos/web', 'test:unit') -SummaryKind 'tap' -ExpectedFileCount $NomWebFiles

  if (-not $SkipE2E) {
    # The current probe is the only authority for this run's browser matrix.
    # An inherited value must never suppress Firefox before it is probed.
    Remove-Item Env:NOMBRAMIENTOS_E2E_FIREFOX -ErrorAction SilentlyContinue
    $NomProbeStartedAt = [DateTime]::UtcNow.ToString('o')
    $NomBrowserProbe = @(& $NomNode ./apps/web/scripts/check-playwright-engines.mjs 2>&1)
    $NomEngineProbeExit = $LASTEXITCODE
    $NomBrowserProbe | Write-Output
    try {
      $NomProbeJson = ($NomBrowserProbe | ForEach-Object { $_.ToString() } | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
      $NomEngineResults = @($NomProbeJson.results | ForEach-Object {
        [pscustomobject][ordered]@{
          name = [string]$_.name
          required = [bool]$_.required
          available = [bool]$_.available
          elapsedMs = [int]$_.elapsedMs
          code = if ($null -eq $_.code) { $null } else { [string]$_.code }
        }
      })
      $NomMandatoryUnavailable = @($NomEngineResults | Where-Object { $_.required -and -not $_.available })
      $NomFirefox = @($NomEngineResults | Where-Object { $_.name -eq 'firefox' })
      if ($NomEngineResults.Count -ne 3 -or $NomMandatoryUnavailable.Count -gt 0 -or $NomFirefox.Count -ne 1) {
        throw 'A mandatory Playwright engine (Chromium or WebKit) could not launch.'
      }
      if ($NomEngineProbeExit -eq 0 -and $NomFirefox[0].available) {
        $env:NOMBRAMIENTOS_E2E_FIREFOX = 'true'
        Add-NomStage -Name 'engine-probe' -StartedAtUtc $NomProbeStartedAt -ExitCode 0 -Status 'passed'
      }
      elseif ($NomEngineProbeExit -eq 2 -and -not $NomFirefox[0].available) {
        $env:NOMBRAMIENTOS_E2E_FIREFOX = 'false'
        Add-NomStage -Name 'engine-probe' -StartedAtUtc $NomProbeStartedAt -ExitCode 2 -Status 'accepted-optional'
        Write-Warning 'Firefox was excluded because this run''s native probe returned exit 2. Chromium and WebKit remain mandatory.'
      }
      else {
        throw 'The Playwright engine probe exit code contradicts its structured result.'
      }
    }
    catch {
      if (-not ($NomStages | Where-Object { $_.name -eq 'engine-probe' })) {
        Add-NomStage -Name 'engine-probe' -StartedAtUtc $NomProbeStartedAt -ExitCode 1 -Status 'failed' -ErrorCode 'ENGINE_PROBE_FAILED'
      }
      throw
    }

    $env:NOMBRAMIENTOS_E2E_EVIDENCE_FILE = $NomPlaywrightEvidencePath
    Invoke-NomPnpmStage -Name 'playwright-e2e' -Arguments @('run', 'test:e2e')

    $NomPolicyStartedAt = [DateTime]::UtcNow.ToString('o')
    $NomIncludeFirefox = if ($NomEngineProbeExit -eq 0) { 'true' } else { 'false' }
    & $NomNode $NomEvidenceScript validate-playwright --report $NomPlaywrightEvidencePath --allowlist $NomAllowlistPath --include-firefox $NomIncludeFirefox | Out-Null
    $NomPolicyExit = $LASTEXITCODE
    if ($NomPolicyExit -ne 0) {
      Add-NomStage -Name 'playwright-skip-policy' -StartedAtUtc $NomPolicyStartedAt -ExitCode $NomPolicyExit -Status 'failed' -ErrorCode 'SKIP_ALLOWLIST_MISMATCH'
      throw 'Playwright skips do not exactly match the reviewed allowlist.'
    }
    Add-NomStage -Name 'playwright-skip-policy' -StartedAtUtc $NomPolicyStartedAt -ExitCode 0 -Status 'passed'

    # pdf-lib can parse a PDF whose embedded font is rejected by independent
    # renderers. Render the browser artifact with Poppler and fail closed.
    $NomPdfStartedAt = [DateTime]::UtcNow.ToString('o')
    try {
      $NomPdfInfo = (Get-Command pdfinfo.exe -ErrorAction Stop).Source
      $NomPdfToPpm = (Get-Command pdftoppm.exe -ErrorAction Stop).Source
      $NomReportPdf = Join-Path $NomRoot 'docs\evidence\demo-cycle-summary.pdf'
      if (-not (Test-Path -LiteralPath $NomReportPdf -PathType Leaf)) { throw 'The E2E report PDF artifact is missing.' }
      $NomPdfRenderDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('nombramientos-pdf-qa-' + [guid]::NewGuid().ToString('N'))
      # Render every page and require Poppler's output count to equal the page
      # count independently declared by pdfinfo. A partial render can never pass.
      $NomPdfQaResult = Invoke-NomPdfRenderQa `
        -PdfInfoPath $NomPdfInfo `
        -PdfToPpmPath $NomPdfToPpm `
        -PdfPath $NomReportPdf `
        -RenderDirectory $NomPdfRenderDirectory
      if ($NomPdfQaResult.declaredPageCount -ne $NomPdfQaResult.renderedPageCount) {
        throw 'PDF page-count verification returned a contradictory result.'
      }
      Add-NomStage -Name 'pdf-render' -StartedAtUtc $NomPdfStartedAt -ExitCode 0 -Status 'passed'
    }
    catch {
      Add-NomStage -Name 'pdf-render' -StartedAtUtc $NomPdfStartedAt -ExitCode 1 -Status 'failed' -ErrorCode 'PDF_RENDER_FAILED'
      throw
    }
  }

  # Scan the freshly built standalone/dist outputs and any browser-generated
  # evidence only after their final bytes exist. This stage excludes local
  # runtime secrets and dependency/cache trees by construction.
  Invoke-NomPnpmStage -Name 'delivery-scan' -Arguments @('run', 'security:delivery')

  # This proves that unit, integration, browser and artifact QA did not drift
  # the protected Demo/Ozama/control state before terminal process checks.
  $NomStateStartedAt = [DateTime]::UtcNow.ToString('o')
  $NomStateExit = 1
  try {
    $NomStateOutput = @(& $NomPnpm --silent run db:verify:local-state 2>&1)
    $NomStateExit = $LASTEXITCODE
    $NomStateLines = @($NomStateOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -ne '' })
    if ($NomStateLines.Count -ne 1) { throw 'Local state verifier did not emit exactly one JSON line.' }
    $NomStateJson = $NomStateLines[0] | ConvertFrom-Json
    $NomLocalStateReport = $NomStateJson
    if ($NomStateExit -ne 0 -or $NomStateJson.schemaVersion -ne 2 -or $NomStateJson.mode -ne 'read-only' -or $NomStateJson.pass -ne $true) {
      throw 'Local state verifier reported drift or incomplete verification.'
    }
    Add-NomStage -Name 'local-state-verification' -StartedAtUtc $NomStateStartedAt -ExitCode 0 -Status 'passed'
    Write-Output 'Protected local state verification passed with sanitized structured evidence.'
  }
  catch {
    $NomStateFailureExit = if ($NomStateExit -eq 0) { 1 } else { $NomStateExit }
    Add-NomStage -Name 'local-state-verification' -StartedAtUtc $NomStateStartedAt -ExitCode $NomStateFailureExit -Status 'failed' -ErrorCode 'LOCAL_STATE_VERIFICATION_FAILED'
    throw
  }

  Invoke-NomActionStage -Name 'terminal-health' -Action {
    Assert-NomTerminalHealth
    $script:NomTerminalHealthPassed = $true
  }
  Invoke-NomActionStage -Name 'source-integrity-final' -Action {
    $script:NomSourceSnapshotEnd = Get-NomSourceFingerprint
    if ($null -eq $NomSourceSnapshotStart -or $NomSourceSnapshotStart.fileCount -ne $NomSourceSnapshotEnd.fileCount -or $NomSourceSnapshotStart.sha256 -cne $NomSourceSnapshotEnd.sha256) {
      throw 'Closure-relevant workspace sources changed during verification.'
    }
  }
}
catch {
  $NomRunFailed = $true
  $NomCapturedError = $_
}
finally {
  try {
  if ($NomRunFailed) {
    $NomFailureCleanupAttempted = $true
    try {
      & $NomStopScript -KeepDatabase
      $NomFailureCleanupSucceeded = $true
    }
    catch {
      $NomFailureCleanupSucceeded = $false
    }
  }
  $NomRunCompletedAt = [DateTime]::UtcNow.ToString('o')
  $NomRunRecord = [pscustomobject][ordered]@{
    schemaVersion = 1
    startedAtUtc = $NomRunStartedAt
    completedAtUtc = $NomRunCompletedAt
    skipE2E = [bool]$SkipE2E
    failed = $NomRunFailed
    liveIntegrationRequired = $env:NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION -eq 'true'
    privilegedLiveRequired = $env:NOMBRAMIENTOS_PRIVILEGE_LIVE -eq 'true'
    postgresqlBinaryVersion = $NomPostgresBinaryVersion
    nodeVersion = $NomNodeVersion
    pnpmVersion = $NomPnpmVersion
    engineProbeExitCode = $NomEngineProbeExit
    engines = $NomEngineResults
    localState = $NomLocalStateReport
    sourceIntegrity = [pscustomobject][ordered]@{
      start = $NomSourceSnapshotStart
      end = $NomSourceSnapshotEnd
    }
    serviceLifecycle = [pscustomobject][ordered]@{
      freshServicesStarted = $NomFreshServicesStarted
      terminalHealthPassed = $NomTerminalHealthPassed
      failureCleanupAttempted = $NomFailureCleanupAttempted
      failureCleanupSucceeded = $NomFailureCleanupSucceeded
    }
    stages = @($NomStages)
  }
  $NomFinalizeArguments = @(
    $NomEvidenceScript, 'finalize',
    '--input', $NomRunEvidencePath,
    '--output', $NomFinalEvidencePath,
    '--lockfile', (Join-Path $NomRoot 'pnpm-lock.yaml'),
    '--allowlist', $NomAllowlistPath,
    '--artifact-directory', (Join-Path $NomRoot 'docs\evidence'),
    '--workspace', $NomRoot
  )
  if (Test-Path -LiteralPath $NomPlaywrightEvidencePath -PathType Leaf) {
    $NomFinalizeArguments += @('--playwright', $NomPlaywrightEvidencePath)
  }
  $NomRunRecord | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $NomRunEvidencePath -Encoding utf8

  $NomPublishAction = {
    $NomCommandResult = Invoke-NomCapturedNativeCommand -NodePath $script:NomNode -Arguments $script:NomFinalizeArguments
    foreach ($NomDiagnostic in @($NomCommandResult.output)) {
      Write-Host $NomDiagnostic
    }
    [int]$NomCommandResult.exitCode
  }
  $NomRepairAndPersistAction = {
    $script:NomRunFailed = $true
    if (-not $script:NomFailureCleanupAttempted) {
      $script:NomFailureCleanupAttempted = $true
      try {
        & $script:NomStopScript -KeepDatabase
        $script:NomFailureCleanupSucceeded = $true
      }
      catch {
        $script:NomFailureCleanupSucceeded = $false
      }
    }
    $script:NomRunCompletedAt = [DateTime]::UtcNow.ToString('o')
    $script:NomRunRecord.completedAtUtc = $script:NomRunCompletedAt
    $script:NomRunRecord.failed = $true
    $script:NomRunRecord.serviceLifecycle.failureCleanupAttempted = $script:NomFailureCleanupAttempted
    $script:NomRunRecord.serviceLifecycle.failureCleanupSucceeded = $script:NomFailureCleanupSucceeded
    $script:NomRunRecord | ConvertTo-Json -Depth 12 |
      Set-Content -LiteralPath $script:NomRunEvidencePath -Encoding utf8
  }
  $NomFinalizerExit = Invoke-NomFinalizationCycle `
    -RunWasAlreadyFailed $NomRunFailed `
    -PublishAction $NomPublishAction `
    -RepairAndPersistAction $NomRepairAndPersistAction
  }
  catch {
    # NOM_PUBLICATION_OUTER_CATCH_BEGIN
    $NomRunFailed = $true
    $NomFinalizerExit = 1
    if ($null -eq $NomCapturedError) { $NomCapturedError = $_ }
    if (-not $NomFailureCleanupAttempted) {
      $NomFailureCleanupAttempted = $true
      try {
        & $NomStopScript -KeepDatabase
        $NomFailureCleanupSucceeded = $true
      }
      catch {
        $NomFailureCleanupSucceeded = $false
      }
    }
    # This is the last-resort path for PowerShell-side failures around
    # publication. If a run record and finalizer arguments exist, persist the
    # actual post-cleanup lifecycle and make one fail-closed republication
    # attempt. Its outcome can never reset NomFinalizerExit to success.
    try {
      if ($null -ne $NomRunRecord -and $null -ne $NomFinalizeArguments) {
        $NomRunCompletedAt = [DateTime]::UtcNow.ToString('o')
        $NomRunRecord.completedAtUtc = $NomRunCompletedAt
        $NomRunRecord.failed = $true
        $NomRunRecord.serviceLifecycle.failureCleanupAttempted = $NomFailureCleanupAttempted
        $NomRunRecord.serviceLifecycle.failureCleanupSucceeded = $NomFailureCleanupSucceeded
        $NomRunRecord | ConvertTo-Json -Depth 12 |
          Set-Content -LiteralPath $NomRunEvidencePath -Encoding utf8
        $NomCatchPublish = Invoke-NomCapturedNativeCommand -NodePath $NomNode -Arguments $NomFinalizeArguments
        foreach ($NomDiagnostic in @($NomCatchPublish.output)) {
          Write-Host $NomDiagnostic
        }
      }
    }
    catch {
      Write-Warning 'Post-cleanup failure evidence could not be republished; the initialized non-green artifact remains authoritative.'
    }
    # NOM_PUBLICATION_OUTER_CATCH_END
  }
  finally {
  Remove-Item Env:NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_PRIVILEGE_LIVE -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_E2E_FIREFOX -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_E2E_EVIDENCE_FILE -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_E2E_TARGET -ErrorAction SilentlyContinue
  Remove-Item Env:WEB_BASE_URL -ErrorAction SilentlyContinue
  Remove-Item Env:NEXT_PUBLIC_API_URL -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_WEB_HOST -ErrorAction SilentlyContinue
  Remove-Item Env:NOMBRAMIENTOS_WEB_PORT -ErrorAction SilentlyContinue
  Remove-Item Env:API_HOST -ErrorAction SilentlyContinue
  Remove-Item Env:API_PORT -ErrorAction SilentlyContinue
  Remove-Item Env:API_CORS_ORIGINS -ErrorAction SilentlyContinue
  Remove-Item Env:API_COOKIE_SECURE -ErrorAction SilentlyContinue
  Remove-Item Env:DATABASE_LOCAL_INSTALL_FILE -ErrorAction SilentlyContinue
  foreach ($NomInheritedEnvironmentName in $NomInheritedEnvironmentNames) {
    Remove-Item -LiteralPath ("Env:" + $NomInheritedEnvironmentName) -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath $NomRunEvidencePath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $NomPlaywrightEvidencePath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $NomScratchDirectory -Force -ErrorAction SilentlyContinue
  if ($NomLocationPushed) {
    try { Pop-Location } catch { }
    $NomLocationPushed = $false
  }
  if ($null -ne $NomRunLockStream) {
    try { $NomRunLockStream.Dispose() } catch { }
    $NomRunLockStream = $null
  }
  }
}

if ($null -ne $NomCapturedError) { throw $NomCapturedError }
if ($NomFinalizerExit -ne 0) { throw 'Final verification evidence could not be published safely.' }
if ($SkipE2E) {
  Write-Output 'Local verification completed without E2E; the final artifact is explicitly incomplete and is not closure evidence.'
}
else {
  Write-Output 'Local verification completed successfully; artifacts/verify-local-final.json is the sanitized closure evidence.'
}
