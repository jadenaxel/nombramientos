import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertSanitized,
  buildInProgressEvidence,
  buildFinalEvidence,
  collectArtifactEvidence,
  collectWorkspaceSourceFingerprint,
  deriveEngineDecision,
  sanitizeLocalStateEvidence,
  validatePlaywrightEvidence,
  writeJsonAtomic,
} from "./verify-local-evidence.mjs";
import VerifyEvidenceReporter from "../apps/web/scripts/verify-evidence-reporter.mjs";
import {
  classifyEngineLaunchError,
  engineLaunchErrorLine,
} from "../apps/web/scripts/playwright-engine-diagnostics.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const allowlist = JSON.parse(fs.readFileSync(path.join(root, "apps/web/e2e/intentional-skips.json"), "utf8"));

const availableEngines = (firefoxAvailable) => [
  { name: "chromium", required: true, available: true, elapsedMs: 10, code: null },
  { name: "firefox", required: false, available: firefoxAvailable, elapsedMs: 11, code: firefoxAvailable ? null : "UNKNOWN" },
  { name: "webkit", required: true, available: true, elapsedMs: 12, code: null },
];

function playwrightReport(projects) {
  const results = [];
  for (const entry of allowlist.entries) {
    for (const project of projects) {
      results.push({
        project,
        file: entry.file,
        line: 1,
        title: entry.title,
        status: project === allowlist.runProject ? "passed" : "skipped",
        durationMs: 1,
        skipReason: project === allowlist.runProject ? null : entry.reason,
      });
    }
  }
  for (const project of projects) {
    results.push({
      project,
      file: "apps/web/e2e/project-execution.spec.ts",
      line: 1,
      title: "executes at least one non-skipped test in every active project",
      status: "passed",
      durationMs: 1,
      skipReason: null,
    });
  }
  return {
    schemaVersion: 1,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:01:00.000Z",
    status: "passed",
    projects,
    plannedTestCount: results.length,
    counts: {
      total: results.length,
      passed: results.filter((entry) => entry.status === "passed").length,
      failed: 0,
      skipped: results.filter((entry) => entry.status === "skipped").length,
      timedOut: 0,
      interrupted: 0,
    },
    results,
  };
}

function passedStage(name) {
  const counts = (name.startsWith("test-") || name === "verification-contract") ? {
    suites: { total: 1, passed: 1, failed: 0, skipped: 0 },
    files: { total: 2, passed: 2, failed: 0, skipped: 0 },
    tests: { total: 3, passed: 3, failed: 0, skipped: 0 },
  } : null;
  return {
    name,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:00:01.000Z",
    exitCode: name === "engine-probe" ? 2 : 0,
    status: name === "engine-probe" ? "accepted-optional" : "passed",
    counts,
    errorCode: null,
  };
}

const fullStageNames = [
  "source-snapshot-start",
  "initial-health",
  "live-prerequisites",
  "supply-chain",
  "dependency-audit",
  "typecheck",
  "lint",
  "stop-services-before-build",
  "build",
  "start-fresh-services",
  "fresh-health",
  "verification-contract",
  "test-domain",
  "test-e2ee",
  "test-database",
  "test-api",
  "test-web",
  "engine-probe",
  "playwright-e2e",
  "playwright-skip-policy",
  "pdf-render",
  "delivery-scan",
  "local-state-verification",
  "terminal-health",
  "source-integrity-final",
];

function passingMigrationEvidence(expectedCount, head, digestCharacter) {
  return {
    expectedCount,
    appliedCount: expectedCount,
    pendingCount: 0,
    unexpectedCount: 0,
    checksumMismatchCount: 0,
    head,
    expectedHead: head,
    ledgerSha256: digestCharacter.repeat(64),
    mismatchCount: 0,
  };
}

function passingCatalogMetadata(digestCharacter, commentCount) {
  return {
    catalogSha256: digestCharacter.repeat(64),
    commentCount,
    sharedCommentCount: 0,
    securityLabelCount: 0,
    eventTriggerCount: 0,
    publicationCount: 0,
    subscriptionCount: 0,
    rewriteRuleCount: 0,
    mismatchCount: 0,
  };
}

function passingLocalStateEvidence() {
  const tenantMigrations = passingMigrationEvidence(38, "036_transactional_invitation_grantor_lock.sql", "b");
  const commonTenant = () => ({
    migrations: tenantMigrations,
    schemaInventoryMismatchCount: 0,
    tableInventoryMismatchCount: 0,
    ownershipMismatchCount: 0,
    runtimeGrantMismatchCount: 0,
    catalogMetadata: passingCatalogMetadata("d", 61),
    institutionalCatalog: {
      targetVersion: "2025.1.0",
      observedVersion: "2025.1.0",
      expectedDepartmentCount: 29,
      observedDepartmentCount: 29,
      missingDepartmentCount: 0,
      unexpectedDepartmentCount: 0,
      expectedOfficeCount: 67,
      observedOfficeCount: 67,
      missingOfficeCount: 0,
      unexpectedOfficeCount: 0,
      targetCatalogSha256: `sha256:${"c".repeat(64)}`,
      observedCatalogSha256: `sha256:${"c".repeat(64)}`,
      localExtensionCollisionCount: 0,
      invalidRowVersionCount: 0,
      blockingMismatchCount: 0,
      mismatchCount: 0,
    },
    mismatchCount: 0,
  });
  return {
    schemaVersion: 2,
    checkedAt: "2026-09-12T00:00:00.500Z",
    mode: "read-only",
    demoFixtureExpectation: "after",
    pass: true,
    mismatchCount: 0,
    server: {
      postgresMajor: 18,
      port: 55_432,
      loopback: true,
      controlDatabaseMatch: true,
      transactionReadOnly: true,
      transactionIsolation: "repeatable read",
      administratorMatch: true,
      mismatchCount: 0,
    },
    control: {
      migrations: passingMigrationEvidence(26, "026_invitation_enrollment_recovery_qualification.sql", "a"),
      tenantRouteCount: 2,
      routeMismatchCount: 0,
      ozamaIdentityOrAdminArtifactCount: 0,
      workerBacklog: {
        provisioningJobCount: 0,
        tenantExportJobCount: 0,
        totalCount: 0,
        mismatchCount: 0,
      },
      schemaInventoryMismatchCount: 0,
      roleMismatchCount: 0,
      catalogMetadata: passingCatalogMetadata("e", 10),
      mismatchCount: 0,
    },
    tenants: {
      demo: {
        kind: "demo",
        lifecycle: "active",
        setupState: "ready",
        maintenanceClass: "routable",
        ...commonTenant(),
        memberCount: 180,
        eligibleMemberCount: 150,
      },
      ozama: {
        kind: "real",
        lifecycle: "provisioning",
        setupState: "not_started",
        maintenanceClass: "pending_activation",
        ...commonTenant(),
        operationalTableCount: 47,
        operationalRowCount: 0,
      },
    },
  };
}

function createCurrentRunArtifacts(startedAtUtc, completedAtUtc) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-current-run-artifacts-"));
  const modifiedAt = new Date((Date.parse(startedAtUtc) + Date.parse(completedAtUtc)) / 2);
  for (const name of [
    "demo-cycle-summary.pdf",
    "demo-cycle-summary.xlsx",
    "demo-cycle-summary.csv",
    "demo-cycle-summary-history.csv",
  ]) {
    const filename = path.join(directory, name);
    fs.writeFileSync(filename, Buffer.alloc(700, name));
    fs.utimesSync(filename, modifiedAt, modifiedAt);
  }
  return directory;
}

function createSourceWorkspace() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-source-workspace-"));
  fs.mkdirSync(path.join(directory, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(directory, "scripts", "closure-source.mjs"), "export const value = 1;\n");
  return directory;
}

function createPassingClosureFixture() {
  const startedAtUtc = "2026-09-12T00:00:00.000Z";
  const completedAtUtc = "2026-09-12T00:10:00.000Z";
  const sourceDirectory = createSourceWorkspace();
  const sourceFingerprint = collectWorkspaceSourceFingerprint(sourceDirectory);
  const artifactDirectory = createCurrentRunArtifacts(startedAtUtc, completedAtUtc);
  const report = playwrightReport([
    "desktop-chromium-es",
    "mobile-chromium-es",
    "mobile-webkit-fr",
    "mobile-small",
  ]);
  const run = {
    schemaVersion: 1,
    startedAtUtc,
    completedAtUtc,
    skipE2E: false,
    failed: false,
    liveIntegrationRequired: true,
    privilegedLiveRequired: true,
    postgresqlBinaryVersion: "18.0",
    nodeVersion: process.version,
    pnpmVersion: "11.19.0",
    engineProbeExitCode: 2,
    engines: availableEngines(false),
    localState: passingLocalStateEvidence(),
    sourceIntegrity: { start: sourceFingerprint, end: sourceFingerprint },
    serviceLifecycle: {
      freshServicesStarted: true,
      terminalHealthPassed: true,
      failureCleanupAttempted: false,
      failureCleanupSucceeded: null,
    },
    stages: fullStageNames.map(passedStage),
  };
  return {
    run,
    options: {
      lockfile: path.join(root, "pnpm-lock.yaml"),
      playwrightReport: report,
      allowlist,
      artifactDirectory,
      workspaceRoot: sourceDirectory,
      terminalHealth: { api: true, web: true, worker: true, valid: true },
    },
    cleanup() {
      fs.rmSync(artifactDirectory, { recursive: true, force: true });
      fs.rmSync(sourceDirectory, { recursive: true, force: true });
    },
  };
}

test("verification publishes sanitized in-progress evidence before running any stage", () => {
  const evidence = buildInProgressEvidence({
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    skipE2E: false,
    lockfile: path.join(root, "pnpm-lock.yaml"),
  });
  assert.equal(evidence.result, "in-progress");
  assert.equal(evidence.closureEligible, false);
  assert.equal(evidence.completedAtUtc, null);
  assert.equal(evidence.stages.every(({ status }) => status === "not-run"), true);
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  assert.ok(source.indexOf("verify-local-evidence.mjs") < source.indexOf("initial-health"));
  assert.match(source, /initialize --output \$NomFinalEvidencePath/u);
  const archive = source.indexOf("Move-NomVerificationEvidenceToHistory `");
  assert.ok(archive > source.indexOf("Open-NomRunLock -Path"));
  assert.ok(archive < source.indexOf("Get-Command pnpm.cmd"));
  assert.ok(archive < source.indexOf("initialize --output $NomFinalEvidencePath"));
  assert.match(source, /artifacts\/verify-local-final\.json path/u);
  assert.match(source, /verify-local-final\.sha256-/u);
  assert.doesNotMatch(source, /\.invalidated/u);
  assert.doesNotMatch(source, /Remove-Item -LiteralPath \$NomDisplacedEvidencePath/u);
  assert.match(
    source,
    /-Name 'verification-contract'[\s\S]*?-ExpectedFileCount 3/u,
    "the verification stage must count all durable evidence contract files",
  );
});

test("PowerShell archives prior canonical evidence content-addressed, read-only, and without clobbering", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const helperStart = source.indexOf("function Get-NomEvidenceFileSha256");
  const helperEnd = source.indexOf("[System.IO.Directory]::CreateDirectory($NomArtifactsDirectory)", helperStart);
  assert.ok(helperStart >= 0 && helperEnd > helperStart);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-evidence-history-"));
  const artifacts = path.join(directory, "artifacts");
  const evidence = path.join(artifacts, "verify-local-final.json");
  const harness = path.join(directory, "history-harness.ps1");
  const bytes = Buffer.from('{"result":"passed","generation":"historical"}\n', "utf8");
  const digest = createHash("sha256").update(bytes).digest("hex");
  fs.mkdirSync(artifacts);
  fs.writeFileSync(evidence, bytes);
  const quote = (value) => value.replaceAll("'", "''");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${source.slice(helperStart, helperEnd)}
$Artifacts = '${quote(artifacts)}'
$Evidence = '${quote(evidence)}'
$Archived = Move-NomVerificationEvidenceToHistory -EvidencePath $Evidence -ArtifactsDirectory $Artifacts
$ArchivedInfo = Get-Item -LiteralPath $Archived -Force
$FirstBytes = [System.IO.File]::ReadAllBytes($Archived)
$FirstDigest = Get-NomEvidenceFileSha256 -LiteralPath $Archived
$WasReadOnly = $ArchivedInfo.IsReadOnly
[System.IO.File]::WriteAllBytes($Evidence, $FirstBytes)
$CollisionRejected = $false
try {
  Move-NomVerificationEvidenceToHistory -EvidencePath $Evidence -ArtifactsDirectory $Artifacts | Out-Null
}
catch {
  if ($_.Exception.Message -match 'destination already exists') { $CollisionRejected = $true } else { throw }
}
$SourcePreservedOnCollision = [System.IO.File]::Exists($Evidence)
$ArchiveUnchanged = ((Get-NomEvidenceFileSha256 -LiteralPath $Archived) -ceq $FirstDigest)
$ArchivedInfo.IsReadOnly = $false
[pscustomobject][ordered]@{
  archivedPath = $Archived
  digest = $FirstDigest
  wasReadOnly = $WasReadOnly
  collisionRejected = $CollisionRejected
  sourcePreservedOnCollision = $SourcePreservedOnCollision
  archiveUnchanged = $ArchiveUnchanged
} | ConvertTo-Json -Compress
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const record = JSON.parse(result.stdout.trim());
    assert.equal(path.basename(record.archivedPath), `verify-local-final.sha256-${digest}.json`);
    assert.equal(record.digest, digest);
    assert.equal(record.wasReadOnly, true);
    assert.equal(record.collisionRejected, true);
    assert.equal(record.sourcePreservedOnCollision, true);
    assert.equal(record.archiveUnchanged, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("closure verification excludes the destructive seed ceremony and scrubs inherited routing or coverage overrides", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const scrub = source.indexOf("foreach ($NomInheritedEnvironmentName in $NomInheritedEnvironmentNames)");
  const databaseStage = source.indexOf("-Name 'test-database'");
  assert.ok(scrub >= 0 && databaseStage > scrub, "environment scrub must precede the database stage");
  for (const name of [
    "TEST_CONTROL_DATABASE_URL",
    "TEST_TENANT_DATABASE_URL",
    "TEST_SEED_DATABASE_ADMIN_URL",
    "NOMBRAMIENTOS_REQUIRE_SEED_AUDIT_LIVE",
    "NOMBRAMIENTOS_E2E_SESSION_COOKIES_B64",
    "KEY_LIFECYCLE_TEST_LOCALE",
  ]) {
    assert.match(source.slice(0, databaseStage), new RegExp(`'${name}'`, "u"), name);
  }
  assert.match(
    source.slice(scrub, databaseStage),
    /Test-Path -LiteralPath \("Env:" \+ \$_\)[\s\S]*?Inherited verification routing or coverage overrides could not be cleared/u,
  );
  assert.doesNotMatch(source, /\$env:NOMBRAMIENTOS_REQUIRE_SEED_AUDIT_LIVE\s*=\s*['"]true['"]/u);
  assert.match(
    source.slice(databaseStage, source.indexOf("-Name 'test-api'", databaseStage)),
    /'--exclude',\s*'test\/seed-audit-history\.live\.test\.ts'/u,
  );

  const inProgress = buildInProgressEvidence({
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    skipE2E: false,
    lockfile: path.join(root, "pnpm-lock.yaml"),
  });
  assert.equal(
    inProgress.stages.find(({ name }) => name === "test-database")?.command,
    "pnpm --filter @nombramientos/database test --exclude test/seed-audit-history.live.test.ts",
  );
});

test("closure source fingerprints ignore generated output and detect source drift", () => {
  const directory = createSourceWorkspace();
  try {
    const first = collectWorkspaceSourceFingerprint(directory);
    fs.mkdirSync(path.join(directory, "artifacts"), { recursive: true });
    fs.writeFileSync(path.join(directory, "artifacts", "generated.json"), "{\"generation\":1}\n");
    const afterGeneratedOutput = collectWorkspaceSourceFingerprint(directory);
    assert.deepEqual(afterGeneratedOutput, first);
    fs.mkdirSync(path.join(directory, "apps", "web"), { recursive: true });
    fs.writeFileSync(path.join(directory, "apps", "web", "next-env.d.ts"), "import \"./.next/dev/types/routes.d.ts\";\n");
    const afterNextDevelopmentTypes = collectWorkspaceSourceFingerprint(directory);
    assert.deepEqual(afterNextDevelopmentTypes, first);
    fs.writeFileSync(path.join(directory, "apps", "web", "next-env.d.ts"), "import \"./.next/types/routes.d.ts\";\n");
    const afterNextProductionTypes = collectWorkspaceSourceFingerprint(directory);
    assert.deepEqual(afterNextProductionTypes, first);
    fs.writeFileSync(path.join(directory, "scripts", "closure-source.mjs"), "export const value = 2;\n");
    const afterSourceEdit = collectWorkspaceSourceFingerprint(directory);
    assert.equal(afterSourceEdit.fileCount, first.fileCount);
    assert.notEqual(afterSourceEdit.sha256, first.sha256);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the actual PowerShell Vitest parser rejects todo, cancelled, absent, and contradictory totals", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const parserStart = source.indexOf("function Get-NomCounter");
  const parserEnd = source.indexOf("function Invoke-NomPnpmStage", parserStart);
  assert.ok(parserStart >= 0 && parserEnd > parserStart);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-vitest-parser-"));
  const harness = path.join(directory, "parser-harness.ps1");
  fs.writeFileSync(harness, `${source.slice(parserStart, parserEnd)}
function Invoke-ParserCase {
  param([string]$FileSummary, [string]$TestSummary)
  $Lines = [System.Collections.Generic.List[string]]::new()
  [void]$Lines.Add("")
  [void]$Lines.Add("Test Files  $FileSummary")
  [void]$Lines.Add("")
  [void]$Lines.Add("Tests  $TestSummary")
  [void]$Lines.Add("")
  return Get-NomTestCounts -Lines $Lines -Kind 'vitest' -ProcessExitCode 0
}
$Valid = Invoke-ParserCase -FileSummary '2 passed (2)' -TestSummary '3 passed (3)'
if ($null -eq $Valid -or $Valid.files.total -ne 2 -or $Valid.tests.total -ne 3) { throw 'Valid Vitest summary was rejected.' }
if ($null -ne (Invoke-ParserCase -FileSummary '2 passed (2)' -TestSummary '2 passed | 1 todo (3)')) { throw 'todo was accepted.' }
if ($null -ne (Invoke-ParserCase -FileSummary '2 passed (2)' -TestSummary '2 passed | 1 cancelled (3)')) { throw 'cancelled was accepted.' }
if ($null -ne (Invoke-ParserCase -FileSummary '2 passed (2)' -TestSummary '3 passed (4)')) { throw 'Contradictory total was accepted.' }
if ($null -ne (Invoke-ParserCase -FileSummary '2 passed (2)' -TestSummary '3 passed')) { throw 'Absent total was accepted.' }
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the actual PowerShell stage serializer emits null for an omitted error code", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const serializerStart = source.indexOf("function Add-NomStage");
  const serializerEnd = source.indexOf("function Get-NomCounter", serializerStart);
  assert.ok(serializerStart >= 0 && serializerEnd > serializerStart);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-stage-serializer-"));
  const harness = path.join(directory, "stage-serializer-harness.ps1");
  fs.writeFileSync(harness, `${source.slice(serializerStart, serializerEnd)}
$NomStages = [System.Collections.Generic.List[object]]::new()
Add-NomStage -Name 'passed-stage' -StartedAtUtc '2026-09-12T00:00:00.000Z' -ExitCode 0 -Status 'passed'
Add-NomStage -Name 'failed-stage' -StartedAtUtc '2026-09-12T00:00:00.000Z' -ExitCode 1 -Status 'failed' -ErrorCode 'CHECK_FAILED'
@($NomStages) | ConvertTo-Json -Depth 4 -Compress
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const stages = JSON.parse(result.stdout.trim());
    assert.equal(stages[0].errorCode, null);
    assert.equal(stages[1].errorCode, "CHECK_FAILED");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the actual PowerShell pnpm-stage wrapper accepts native stderr when the process exits zero", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const stageStart = source.indexOf("function Add-NomStage");
  const stageEnd = source.indexOf("function Invoke-NomActionStage", stageStart);
  assert.ok(stageStart >= 0 && stageEnd > stageStart);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-native-stderr-"));
  const harness = path.join(directory, "native-stderr-harness.ps1");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${source.slice(stageStart, stageEnd)}
$NomPnpm = (Get-Command node.exe -ErrorAction Stop).Source
$NomStages = [System.Collections.Generic.List[object]]::new()
Invoke-NomPnpmStage -Name 'native-stderr' -Arguments @('-e', "process.stderr.write('banner\\n'); process.stdout.write('ok\\n')") | Out-Null
@($NomStages) | ConvertTo-Json -Depth 4 -Compress
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const stage = JSON.parse(result.stdout.trim());
    assert.equal(stage.status, "passed");
    assert.equal(stage.exitCode, 0);
    assert.equal(stage.errorCode, null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the PowerShell pnpm-stage wrapper emits only redacted plain text while preserving Vitest counts", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const stageStart = source.indexOf("function Add-NomStage");
  const stageEnd = source.indexOf("function Invoke-NomActionStage", stageStart);
  assert.ok(stageStart >= 0 && stageEnd > stageStart);
  const stageSource = source.slice(stageStart, stageEnd);
  assert.match(stageSource, /Write-Output \$NomSafeLine/u);
  assert.doesNotMatch(stageSource, /Write-Output \$_/u);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-native-redaction-"));
  const emitter = path.join(directory, "emit-sensitive-output.mjs");
  const harness = path.join(directory, "native-redaction-harness.ps1");
  const sensitiveMarkers = [
    "verification-password-fingerprint",
    "verification-owner-fingerprint",
    "verification-database-fingerprint",
    "verification-url-fingerprint",
    "private-profile-fingerprint",
    "private.person",
  ];
  fs.writeFileSync(emitter, `
const serviceUrl = "postgres" + "ql://verification-user:verification-url-fingerprint@127.0.0.1:55432/private";
const email = "private.person" + "@fortune500.example";
process.stdout.write([
  "\\u001b[31mpassword: 'verification-password-fingerprint'\\u001b[0m,",
  "user: 'verification-owner-fingerprint',",
  "database: 'verification-database-fingerprint',",
  "email: '" + email + "',",
  "profile: C:\\\\Users\\\\private-profile-fingerprint\\\\file.txt",
  "DATABASE_CONTROL_URL=" + serviceUrl,
  "Test Files  1 passed (1)",
  "Tests  1 passed (1)",
].join("\\n") + "\\n");
process.stderr.write(serviceUrl + "\\n");
`, "utf8");
  const quote = (value) => value.replaceAll("'", "''");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${stageSource}
$NomPnpm = (Get-Command node.exe -ErrorAction Stop).Source
$NomStages = [System.Collections.Generic.List[object]]::new()
Invoke-NomPnpmStage -Name 'native-redaction' -Arguments @('${quote(emitter)}') -SummaryKind 'vitest'
@($NomStages) | ConvertTo-Json -Depth 5 -Compress
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const combined = `${result.stdout}\n${result.stderr}`;
    for (const marker of sensitiveMarkers) assert.equal(combined.includes(marker), false, marker);
    assert.equal(combined.includes("\u001b"), false);
    assert.match(combined, /\[REDACTED\]/u);
    assert.doesNotMatch(combined, /\[REDACTED\]\]@/u);
    const stage = JSON.parse(result.stdout.trim().split(/\r?\n/u).at(-1));
    assert.equal(stage.status, "passed");
    assert.deepEqual(stage.counts.files, { total: 1, passed: 1, failed: 0, skipped: 0 });
    assert.deepEqual(stage.counts.tests, { total: 1, passed: 1, failed: 0, skipped: 0 });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the runner lock is exclusive and lifecycle, source, and tool gates are ordered fail-closed", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const lockStart = source.indexOf("function Open-NomRunLock");
  const lockEnd = source.indexOf(
    "[System.IO.Directory]::CreateDirectory($NomArtifactsDirectory)",
    lockStart,
  );
  assert.ok(lockStart >= 0 && lockEnd > lockStart);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-run-lock-test-"));
  const harness = path.join(directory, "lock-harness.ps1");
  const lockPath = path.join(directory, "runner.lock").replaceAll("'", "''");
  fs.writeFileSync(harness, `${source.slice(lockStart, lockEnd)}
$First = Open-NomRunLock -Path '${lockPath}'
try {
  $CollisionRejected = $false
  try {
    $Second = Open-NomRunLock -Path '${lockPath}'
    $Second.Dispose()
  }
  catch {
    if ($_.Exception.Message -match 'exclusive verification lock') { $CollisionRejected = $true } else { throw }
  }
  if (-not $CollisionRejected) { throw 'A concurrent runner acquired the exclusive lock.' }
}
finally {
  $First.Dispose()
  Remove-Item -LiteralPath '${lockPath}' -Force -ErrorAction SilentlyContinue
}
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }

  const lockAcquire = source.indexOf("Open-NomRunLock -Path $NomRunLockPath");
  const staleInvalidation = source.indexOf("Move-NomVerificationEvidenceToHistory `");
  const initialize = source.indexOf("initialize --output $NomFinalEvidencePath");
  const terminalHealth = source.indexOf("-Name 'terminal-health'");
  const sourceFinal = source.indexOf("-Name 'source-integrity-final'");
  const mainFailureCleanup = source.indexOf("if ($NomRunFailed) {", sourceFinal);
  const repairAction = source.indexOf("$NomRepairAndPersistAction =", mainFailureCleanup);
  const finalizerFailureStop = source.indexOf("& $script:NomStopScript -KeepDatabase", repairAction);
  const finalizer = source.indexOf("$NomFinalizerExit = Invoke-NomFinalizationCycle", finalizerFailureStop);
  const dispose = source.indexOf("$NomRunLockStream.Dispose()", finalizer);
  assert.ok(lockAcquire >= 0 && staleInvalidation > lockAcquire && initialize > staleInvalidation);
  assert.ok(terminalHealth > initialize && sourceFinal > terminalHealth && mainFailureCleanup > sourceFinal);
  assert.ok(repairAction > mainFailureCleanup && finalizerFailureStop > repairAction && finalizer > finalizerFailureStop && dispose > finalizer);
  assert.match(
    source.slice(mainFailureCleanup, source.indexOf("$NomRunCompletedAt", mainFailureCleanup)),
    /if \(\$NomRunFailed\) \{[\s\S]*?& \$NomStopScript -KeepDatabase/u,
    "even a partial start that throws before returning must be cleaned up",
  );
  assert.match(source, /\[System\.IO\.FileShare\]::None/u);
  assert.match(source, /Node must satisfy >=24\.0\.0 <25\./u);
  assert.match(source, /\$NomPnpmVersionOutput -cne '11\.19\.0'/u);
  assert.match(source, /--workspace', \$NomRoot/u);
});

test("PDF QA causally renders every page of a real three-page PDF and matches pdfinfo exactly", async () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const helperStart = source.indexOf("function Invoke-NomCapturedNativeCommand");
  const helperEnd = source.indexOf("function Get-NomSourceFingerprint", helperStart);
  const pdfStart = source.indexOf("function Invoke-NomPdfRenderQa", helperStart);
  assert.ok(helperStart >= 0 && pdfStart > helperStart && helperEnd > pdfStart);
  const pdfBlock = source.slice(pdfStart, helperEnd);
  assert.doesNotMatch(pdfBlock, /-singlefile/u);
  assert.match(pdfBlock, /pdfinfo did not report exactly one valid positive page count/u);
  assert.match(pdfBlock, /Get-ChildItem[^\n]+-Filter 'report-\*\.png'/u);
  assert.match(pdfBlock, /\$NomRenderedPdfPages\.Count -ne \$NomDeclaredPageCount/u);
  assert.match(pdfBlock, /Where-Object \{ \$_\.Length -lt 1KB \}/u);
  const evidenceSource = fs.readFileSync(path.join(root, "scripts/verify-local-evidence.mjs"), "utf8");
  const pdfCommand = evidenceSource.match(/"pdf-render":\s*"([^"]+)"/u)?.[1] ?? "";
  assert.doesNotMatch(pdfCommand, /-singlefile/u);
  assert.match(pdfCommand, /all pages/u);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-real-multipage-pdf-"));
  const pdfPath = path.join(directory, "three-pages.pdf");
  const renderDirectory = path.join(directory, "rendered");
  const harness = path.join(directory, "pdf-render-harness.ps1");
  const webRequire = createRequire(path.join(root, "apps/web/package.json"));
  const { PDFDocument, rgb } = webRequire("pdf-lib");
  const document = await PDFDocument.create();
  for (let pageNumber = 1; pageNumber <= 3; pageNumber += 1) {
    const page = document.addPage([360, 240]);
    for (let stripe = 0; stripe < 18; stripe += 1) {
      page.drawRectangle({
        x: 18 + stripe * 18,
        y: 24 + ((stripe * 31 + pageNumber * 17) % 170),
        width: 12,
        height: 22 + ((stripe * 13) % 44),
        color: rgb(
          ((stripe * 17 + pageNumber * 11) % 100) / 100,
          ((stripe * 29 + pageNumber * 7) % 100) / 100,
          ((stripe * 41 + pageNumber * 19) % 100) / 100,
        ),
      });
    }
  }
  fs.writeFileSync(pdfPath, await document.save());
  const quote = (value) => value.replaceAll("'", "''");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${source.slice(helperStart, helperEnd)}
$Result = Invoke-NomPdfRenderQa -PdfInfoPath (Get-Command pdfinfo -ErrorAction Stop).Source -PdfToPpmPath (Get-Command pdftoppm -ErrorAction Stop).Source -PdfPath '${quote(pdfPath)}' -RenderDirectory '${quote(renderDirectory)}'
if ($Result.declaredPageCount -ne 3 -or $Result.renderedPageCount -ne 3) { throw 'The real multipage PDF did not produce exactly three verified pages.' }
if (Test-Path -LiteralPath '${quote(renderDirectory)}') { throw 'The PDF QA temporary render directory was not cleaned.' }
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("a finalizer-only failure causally republishes post-cleanup JSON", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const helperStart = source.indexOf("function Invoke-NomCapturedNativeCommand");
  const helperEnd = source.indexOf("function Invoke-NomPdfRenderQa", helperStart);
  assert.ok(helperStart >= 0 && helperEnd > helperStart);
  assert.match(source, /\$NomFinalizerExit = Invoke-NomFinalizationCycle/u);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-finalizer-cycle-"));
  const harness = path.join(directory, "finalizer-cycle-harness.ps1");
  const fakeFinalizer = path.join(directory, "fake-finalizer.ps1");
  const statePath = path.join(directory, "state.json");
  const publishedPath = path.join(directory, "published.json");
  fs.writeFileSync(fakeFinalizer, `param(
  [Parameter(Mandatory)][string]$StatePath,
  [Parameter(Mandatory)][string]$PublishedPath
)
$ErrorActionPreference = 'Stop'
$State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$State.publishCalls = [int]$State.publishCalls + 1
[pscustomobject][ordered]@{
  result = 'failed'
  closureEligible = $false
  failed = [bool]$State.failed
  serviceLifecycle = [pscustomobject][ordered]@{
    failureCleanupAttempted = [bool]$State.cleanupAttempted
    failureCleanupSucceeded = if ($null -eq $State.cleanupSucceeded) { $null } else { [bool]$State.cleanupSucceeded }
  }
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $PublishedPath -Encoding utf8
$State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding utf8
[Console]::Error.WriteLine('simulated finalizer diagnostic on stderr')
if ($State.publishCalls -eq 1) { exit 23 }
exit 1
`, "utf8");
  const quote = (value) => value.replaceAll("'", "''");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${source.slice(helperStart, helperEnd)}
$StatePath = '${quote(statePath)}'
$PublishedPath = '${quote(publishedPath)}'
$FakeFinalizer = '${quote(fakeFinalizer)}'
[pscustomobject][ordered]@{
  publishCalls = 0
  failed = $false
  cleanupAttempted = $false
  cleanupSucceeded = $null
} | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding utf8
$PublishAction = {
  $FinalizerArguments = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $FakeFinalizer,
    '-StatePath', $StatePath, '-PublishedPath', $PublishedPath
  )
  $Result = Invoke-NomCapturedNativeCommand -NodePath (Get-Command powershell.exe -ErrorAction Stop).Source -Arguments $FinalizerArguments
  if (@($Result.output).Count -lt 1) { throw 'Native stderr was not captured.' }
  [int]$Result.exitCode
}
$RepairAndPersistAction = {
  $State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
  $State.failed = $true
  $State.cleanupAttempted = $true
  $State.cleanupSucceeded = $true
  $State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding utf8
}
$ExitCode = Invoke-NomFinalizationCycle -RunWasAlreadyFailed $false -PublishAction $PublishAction -RepairAndPersistAction $RepairAndPersistAction
if ($ExitCode -eq 0) { throw 'A successful republication erased the original finalizer failure.' }
$State = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$Published = Get-Content -LiteralPath $PublishedPath -Raw | ConvertFrom-Json
if ($State.publishCalls -ne 2) { throw 'The failed publication was not retried exactly once.' }
if ($Published.result -ne 'failed' -or $Published.closureEligible -ne $false) { throw 'Republication was not fail-closed.' }
if ($Published.failed -ne $true -or
  $Published.serviceLifecycle.failureCleanupAttempted -ne $true -or
  $Published.serviceLifecycle.failureCleanupSucceeded -ne $true) {
  throw 'The republished JSON does not contain the actual post-cleanup lifecycle.'
}
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const published = JSON.parse(fs.readFileSync(publishedPath, "utf8").replace(/^\uFEFF/u, ""));
    assert.equal(published.failed, true);
    assert.equal(published.serviceLifecycle.failureCleanupAttempted, true);
    assert.equal(published.serviceLifecycle.failureCleanupSucceeded, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the actual outer publication catch performs cleanup and overwrites canonical evidence with red post-failure JSON", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const helperStart = source.indexOf("function Invoke-NomCapturedNativeCommand");
  const helperEnd = source.indexOf("function Invoke-NomFinalizationCycle", helperStart);
  const catchStartMarker = "# NOM_PUBLICATION_OUTER_CATCH_BEGIN";
  const catchEndMarker = "# NOM_PUBLICATION_OUTER_CATCH_END";
  const catchStart = source.indexOf(catchStartMarker);
  const catchEnd = source.indexOf(catchEndMarker, catchStart);
  assert.ok(helperStart >= 0 && helperEnd > helperStart && catchStart >= 0 && catchEnd > catchStart);
  const catchBody = source.slice(catchStart + catchStartMarker.length, catchEnd);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-outer-publication-catch-"));
  const harness = path.join(directory, "outer-catch-harness.ps1");
  const fakeStop = path.join(directory, "fake-stop.ps1");
  const fakeFinalizer = path.join(directory, "fake-red-finalizer.ps1");
  const serviceMarker = path.join(directory, "fake-service.running");
  const runEvidence = path.join(directory, "run.json");
  const canonicalEvidence = path.join(directory, "verify-local-final.json");
  const brokenPersistence = path.join(directory, "missing-parent", "run.json");
  fs.writeFileSync(serviceMarker, "running\n");
  fs.writeFileSync(canonicalEvidence, JSON.stringify({ result: "passed", overallPass: true, closureEligible: true }));
  const quote = (value) => value.replaceAll("'", "''");
  fs.writeFileSync(fakeStop, `param([switch]$KeepDatabase)
if (-not $KeepDatabase) { throw 'The cleanup did not preserve PostgreSQL.' }
Remove-Item -LiteralPath '${quote(serviceMarker)}' -Force -ErrorAction Stop
`, "utf8");
  fs.writeFileSync(fakeFinalizer, `param(
  [Parameter(Mandatory)][string]$InputPath,
  [Parameter(Mandatory)][string]$OutputPath
)
$Run = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
[pscustomobject][ordered]@{
  result = 'failed'
  overallPass = $false
  closureEligible = $false
  failed = [bool]$Run.failed
  serviceLifecycle = $Run.serviceLifecycle
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding utf8
[Console]::Error.WriteLine('simulated red finalizer publication')
exit 1
`, "utf8");
  fs.writeFileSync(harness, `$ErrorActionPreference = 'Stop'
${source.slice(helperStart, helperEnd)}
$NomRunFailed = $false
$NomFinalizerExit = 0
$NomCapturedError = $null
$NomFailureCleanupAttempted = $false
$NomFailureCleanupSucceeded = $null
$NomStopScript = '${quote(fakeStop)}'
$NomRunEvidencePath = '${quote(runEvidence)}'
$NomNode = (Get-Command powershell.exe -ErrorAction Stop).Source
$NomFinalizeArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '${quote(fakeFinalizer)}', '-InputPath', $NomRunEvidencePath, '-OutputPath', '${quote(canonicalEvidence)}')
$NomRunRecord = [pscustomobject][ordered]@{
  schemaVersion = 1
  completedAtUtc = '2026-09-12T00:00:00.000Z'
  failed = $false
  serviceLifecycle = [pscustomobject][ordered]@{
    failureCleanupAttempted = $false
    failureCleanupSucceeded = $null
  }
}
try {
  $NomRunRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '${quote(brokenPersistence)}' -Encoding utf8 -ErrorAction Stop
}
catch {
${catchBody}
}
if ($NomFinalizerExit -eq 0) { throw 'The outer catch produced a false-green exit.' }
if (Test-Path -LiteralPath '${quote(serviceMarker)}') { throw 'The outer catch did not stop the fake application service.' }
$Run = Get-Content -LiteralPath $NomRunEvidencePath -Raw | ConvertFrom-Json
$Canonical = Get-Content -LiteralPath '${quote(canonicalEvidence)}' -Raw | ConvertFrom-Json
if ($Run.failed -ne $true -or $Run.serviceLifecycle.failureCleanupAttempted -ne $true -or $Run.serviceLifecycle.failureCleanupSucceeded -ne $true) { throw 'Post-cleanup run evidence was not persisted.' }
if ($Canonical.result -ne 'failed' -or $Canonical.overallPass -ne $false -or $Canonical.closureEligible -ne $false) { throw 'Canonical evidence was not overwritten with a red result.' }
if ($Canonical.failed -ne $true -or $Canonical.serviceLifecycle.failureCleanupAttempted -ne $true -or $Canonical.serviceLifecycle.failureCleanupSucceeded -ne $true) { throw 'Canonical red evidence omitted the real cleanup outcome.' }
`, "utf8");
  try {
    const executable = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const result = spawnSync(executable, ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness], { encoding: "utf8" });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(fs.existsSync(serviceMarker), false);
    const canonical = JSON.parse(fs.readFileSync(canonicalEvidence, "utf8").replace(/^\uFEFF/u, ""));
    assert.equal(canonical.result, "failed");
    assert.equal(canonical.overallPass, false);
    assert.equal(canonical.closureEligible, false);
    assert.equal(canonical.serviceLifecycle.failureCleanupSucceeded, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("unsupported Node or pnpm versions remain ineligible even when syntactically semantic", () => {
  const failedStage = passedStage("source-snapshot-start");
  failedStage.status = "failed";
  failedStage.exitCode = 1;
  failedStage.errorCode = "CHECK_FAILED";
  const run = {
    schemaVersion: 1,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:00:01.000Z",
    skipE2E: false,
    failed: true,
    postgresqlBinaryVersion: "18.0",
    nodeVersion: "v25.0.0",
    pnpmVersion: "11.19.0",
    stages: [failedStage],
  };
  let evidence = buildFinalEvidence(run, { lockfile: path.join(root, "pnpm-lock.yaml") });
  assert.equal(evidence.environment.valid, false);
  run.nodeVersion = process.version;
  run.pnpmVersion = "11.19.1";
  evidence = buildFinalEvidence(run, { lockfile: path.join(root, "pnpm-lock.yaml") });
  assert.equal(evidence.environment.valid, false);
});

test("current probe exit alone includes or excludes Firefox and mandatory failures abort", () => {
  assert.deepEqual(deriveEngineDecision(0, availableEngines(true)), {
    includeFirefox: true,
    exclusionReason: null,
  });
  assert.deepEqual(deriveEngineDecision(2, availableEngines(false)), {
    includeFirefox: false,
    exclusionReason: "current-run-native-probe-exit-2",
  });
  assert.throws(() => deriveEngineDecision(1, availableEngines(true)), /mandatory Playwright engine/u);
  const mandatoryFailure = availableEngines(false).map((entry) =>
    entry.name === "webkit" ? { ...entry, available: false, required: true } : entry);
  assert.throws(() => deriveEngineDecision(2, mandatoryFailure), /Mandatory webkit/u);
});

test("engine diagnostics classify opaque Windows spawn failures without leaking profile paths", () => {
  const nativeFailure = new Error("browserType.launch: spawn UNKNOWN\nsecond line");
  assert.equal(classifyEngineLaunchError(nativeFailure, "win32"), "WINDOWS_NATIVE_SPAWN_UNKNOWN");
  assert.equal(classifyEngineLaunchError(nativeFailure, "linux"), "ENGINE_LAUNCH_FAILED");

  const missingBinary = Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" });
  assert.equal(classifyEngineLaunchError(missingBinary, "win32"), "ENOENT");
  assert.equal(
    engineLaunchErrorLine(new Error("C:\\Users\\person\\browser.exe failed\nsecret"), "C:\\Users\\person"),
    "<profile>\\browser.exe failed",
  );
});

test("PowerShell clears inherited Firefox state before probing and branches only on 0 or 2", () => {
  const source = fs.readFileSync(path.join(root, "scripts/verify-local.ps1"), "utf8");
  const clear = source.indexOf("Remove-Item Env:NOMBRAMIENTOS_E2E_FIREFOX", source.indexOf("if (-not $SkipE2E)"));
  const probe = source.indexOf("check-playwright-engines.mjs", clear);
  const include = source.indexOf("$NomEngineProbeExit -eq 0", probe);
  const includeAssignment = source.indexOf("NOMBRAMIENTOS_E2E_FIREFOX = 'true'", include);
  const exclude = source.indexOf("$NomEngineProbeExit -eq 2", includeAssignment);
  const excludeAssignment = source.indexOf("NOMBRAMIENTOS_E2E_FIREFOX = 'false'", exclude);
  const mandatoryFailure = source.indexOf("mandatory Playwright engine", probe);
  assert.ok(clear >= 0 && probe > clear && include > probe && includeAssignment > include);
  assert.ok(exclude > includeAssignment && excludeAssignment > exclude && mandatoryFailure > probe);
});

test("reviewed skip allowlist expands from concrete tests across only active non-run projects", () => {
  assert.equal(allowlist.entries.length, 18);
  const skipSources = fs.readdirSync(path.join(root, "apps/web/e2e"))
    .filter((file) => file.endsWith(".ts"))
    .map((file) => fs.readFileSync(path.join(root, "apps/web/e2e", file), "utf8"))
    .join("\n");
  const skipCalls = [...skipSources.matchAll(/test\.skip\(testInfo\.project\.name !== "desktop-chromium-es", "([^"]+)"\)/gu)];
  assert.equal(skipCalls.length, 15);
  assert.deepEqual(
    [...new Set(skipCalls.map((match) => match[1]))].sort(),
    [...new Set(allowlist.entries.map((entry) => entry.reason))].sort(),
  );
  for (const entry of allowlist.entries) {
    const filename = path.join(root, entry.file);
    assert.equal(fs.existsSync(filename), true, entry.file);
    const source = fs.readFileSync(filename, "utf8");
    const skipCall = `test.skip(testInfo.project.name !== "desktop-chromium-es", "${entry.reason}")`;
    if (entry.file.endsWith("role-access.spec.ts")) {
      const profile = entry.title.split(" Demo identity", 1)[0];
      assert.match(source, new RegExp(`profile:\\s*"${profile}"`, "u"), entry.title);
      assert.ok(source.includes("test(`${expected.profile} Demo identity enforces role-specific UI and API boundaries`"), entry.title);
      assert.ok(source.includes(skipCall), `${entry.title}: ${entry.reason}`);
      continue;
    }
    const declaration = `test("${entry.title}"`;
    const declarationIndex = source.indexOf(declaration);
    assert.ok(declarationIndex >= 0, `${entry.file}: ${entry.title}`);
    const afterDeclaration = source.slice(declarationIndex + declaration.length);
    const nextTestOffset = afterDeclaration.search(/\n\s*test\(/u);
    const testBlock = nextTestOffset < 0 ? afterDeclaration : afterDeclaration.slice(0, nextTestOffset);
    assert.ok(testBlock.includes(skipCall), `${entry.title}: ${entry.reason}`);
  }
  const withoutFirefox = validatePlaywrightEvidence(playwrightReport([
    "desktop-chromium-es",
    "mobile-chromium-es",
    "mobile-webkit-fr",
    "mobile-small",
  ]), allowlist, false);
  assert.equal(withoutFirefox.valid, true);
  assert.equal(withoutFirefox.expectedSkipCount, 54);
  assert.equal(withoutFirefox.actualSkipCount, 54);

  const withFirefox = validatePlaywrightEvidence(playwrightReport([
    "desktop-chromium-es",
    "desktop-firefox-en",
    "mobile-chromium-es",
    "mobile-webkit-fr",
    "mobile-small",
  ]), allowlist, true);
  assert.equal(withFirefox.valid, true);
  assert.equal(withFirefox.expectedSkipCount, 72);
  assert.equal(withFirefox.actualSkipCount, 72);
});

test("skip validation fails closed on an unknown reason, missing result, or skipped run project", () => {
  const report = playwrightReport(["desktop-chromium-es", "mobile-webkit-fr"]);
  report.results.find((entry) => entry.status === "skipped").skipReason = "unreviewed";
  let validation = validatePlaywrightEvidence(report, allowlist, false);
  assert.equal(validation.valid, false);
  assert.equal(validation.unexpectedCount, 1);
  assert.equal(validation.missingCount, 1);

  const missing = playwrightReport(["desktop-chromium-es", "mobile-webkit-fr"]);
  missing.results.pop();
  validation = validatePlaywrightEvidence(missing, allowlist, false);
  assert.equal(validation.valid, false);

  const targetSkipped = playwrightReport(["desktop-chromium-es", "mobile-webkit-fr"]);
  targetSkipped.results[0].status = "skipped";
  targetSkipped.results[0].skipReason = allowlist.entries[0].reason;
  validation = validatePlaywrightEvidence(targetSkipped, allowlist, false);
  assert.equal(validation.valid, false);
  assert.equal(validation.runProjectFailureCount, 1);

  const incompleteMatrix = playwrightReport(["desktop-chromium-es"]);
  validation = validatePlaywrightEvidence(incompleteMatrix, allowlist, false);
  assert.equal(validation.valid, false);
  assert.equal(validation.projectMatrixMatches, false);
});

test("final evidence is structured, sanitized, closure-gated, and atomically replaceable", () => {
  const report = playwrightReport([
    "desktop-chromium-es",
    "mobile-chromium-es",
    "mobile-webkit-fr",
    "mobile-small",
  ]);
  const sourceDirectory = createSourceWorkspace();
  const sourceFingerprint = collectWorkspaceSourceFingerprint(sourceDirectory);
  const run = {
    schemaVersion: 1,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:10:00.000Z",
    skipE2E: false,
    failed: false,
    liveIntegrationRequired: true,
    privilegedLiveRequired: true,
    postgresqlBinaryVersion: "18.0",
    nodeVersion: process.version,
    pnpmVersion: "11.19.0",
    engineProbeExitCode: 2,
    engines: availableEngines(false),
    localState: passingLocalStateEvidence(),
    sourceIntegrity: { start: sourceFingerprint, end: sourceFingerprint },
    serviceLifecycle: {
      freshServicesStarted: true,
      terminalHealthPassed: true,
      failureCleanupAttempted: false,
      failureCleanupSucceeded: null,
    },
    stages: fullStageNames.map(passedStage),
  };
  const artifactDirectory = createCurrentRunArtifacts(run.startedAtUtc, run.completedAtUtc);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-verify-evidence-"));
  const output = path.join(directory, "final.json");
  try {
    const artifactEvidence = collectArtifactEvidence(
      artifactDirectory,
      run.startedAtUtc,
      run.completedAtUtc,
      true,
    );
    assert.equal(artifactEvidence.valid, true);
    const evidence = buildFinalEvidence(run, {
      lockfile: path.join(root, "pnpm-lock.yaml"),
      playwrightReport: report,
      allowlist,
      artifactDirectory,
      workspaceRoot: sourceDirectory,
      terminalHealth: { api: true, web: true, worker: true, valid: true },
    });
    assert.equal(evidence.result, "passed");
    assert.equal(evidence.overallPass, true);
    assert.equal(evidence.closureEligible, true);
    assert.equal(evidence.testSuites.length, 5);
    assert.equal(evidence.e2e.expectedSkipCount, 54);
    assert.equal(evidence.engines.includeFirefox, false);
    assert.equal(evidence.guarantees.stdoutPersisted, false);
    assert.equal(evidence.artifacts.currentRunFileCount, 4);
    assert.equal(evidence.localState.valid, true);
    assert.equal(evidence.environment.valid, true);
    assert.equal(evidence.sourceIntegrity.valid, true);
    assert.equal(evidence.serviceLifecycle.validForClosure, true);
    assert.match(evidence.environment.pnpmLockSha256, /^[a-f0-9]{64}$/u);

    fs.writeFileSync(path.join(sourceDirectory, "scripts", "closure-source.mjs"), "export const value = 2;\n");
    const driftedEvidence = buildFinalEvidence(run, {
      lockfile: path.join(root, "pnpm-lock.yaml"),
      playwrightReport: report,
      allowlist,
      artifactDirectory,
      workspaceRoot: sourceDirectory,
      terminalHealth: { api: true, web: true, worker: true, valid: true },
    });
    assert.equal(driftedEvidence.sourceIntegrity.valid, false);
    assert.equal(driftedEvidence.closureEligible, false);

    fs.writeFileSync(path.join(sourceDirectory, "scripts", "closure-source.mjs"), "export const value = 1;\n");
    const unhealthyEvidence = buildFinalEvidence(run, {
      lockfile: path.join(root, "pnpm-lock.yaml"),
      playwrightReport: report,
      allowlist,
      artifactDirectory,
      workspaceRoot: sourceDirectory,
      terminalHealth: { api: true, web: true, worker: false, valid: false },
    });
    assert.equal(unhealthyEvidence.sourceIntegrity.valid, true);
    assert.equal(unhealthyEvidence.serviceLifecycle.validForClosure, false);
    assert.equal(unhealthyEvidence.closureEligible, false);

    writeJsonAtomic(output, { generation: 1 });
    writeJsonAtomic(output, evidence);
    assert.deepEqual(JSON.parse(fs.readFileSync(output, "utf8")), evidence);
    assert.deepEqual(fs.readdirSync(directory), ["final.json"]);
  } finally {
    fs.rmSync(output, { force: true });
    fs.rmdirSync(directory);
    fs.rmSync(artifactDirectory, { recursive: true, force: true });
    fs.rmSync(sourceDirectory, { recursive: true, force: true });
  }
});

test("local state evidence is tied to its read-only stage and exact protected counts", () => {
  const stage = passedStage("local-state-verification");
  const evidence = sanitizeLocalStateEvidence(passingLocalStateEvidence(), stage);
  assert.equal(evidence.valid, true);
  assert.equal(evidence.server.administratorMatch, true);
  assert.equal(evidence.control.schemaInventoryMismatchCount, 0);
  assert.equal(evidence.control.roleMismatchCount, 0);
  assert.equal(evidence.control.catalogMetadata.commentCount, 10);
  assert.equal(evidence.control.catalogMetadata.valid, true);
  assert.equal(evidence.tenants.demo.schemaInventoryMismatchCount, 0);
  assert.equal(evidence.tenants.demo.catalogMetadata.commentCount, 61);
  assert.equal(evidence.tenants.demo.catalogMetadata.valid, true);
  assert.equal(evidence.tenants.demo.memberCount, 180);
  assert.equal(evidence.tenants.ozama.operationalRowCount, 0);

  const drifted = passingLocalStateEvidence();
  drifted.tenants.demo.eligibleMemberCount = 149;
  assert.equal(sanitizeLocalStateEvidence(drifted, stage).valid, false);

  const pendingWorkerJob = passingLocalStateEvidence();
  pendingWorkerJob.control.workerBacklog.provisioningJobCount = 1;
  pendingWorkerJob.control.workerBacklog.totalCount = 1;
  pendingWorkerJob.control.workerBacklog.mismatchCount = 1;
  pendingWorkerJob.control.mismatchCount = 1;
  pendingWorkerJob.mismatchCount = 1;
  assert.equal(sanitizeLocalStateEvidence(pendingWorkerJob, stage).valid, false);
});

test("local state evidence rejects schema-v2 field tampering even when aggregate flags remain green", () => {
  const stage = passedStage("local-state-verification");
  const cases = [
    ["server administrator", (report) => { report.server.administratorMatch = false; }],
    ["control schema inventory", (report) => { report.control.schemaInventoryMismatchCount = 1; }],
    ["control protected roles", (report) => { report.control.roleMismatchCount = 1; }],
    ["demo schema inventory", (report) => { report.tenants.demo.schemaInventoryMismatchCount = 1; }],
    ["Ozama schema inventory", (report) => { report.tenants.ozama.schemaInventoryMismatchCount = 1; }],
    ["catalog digest", (report) => { report.control.catalogMetadata.catalogSha256 = "invalid"; }],
    ["catalog comment count", (report) => { report.control.catalogMetadata.commentCount = 0; }],
    ["shared catalog comments", (report) => { report.control.catalogMetadata.sharedCommentCount = 1; }],
    ["catalog security labels", (report) => { report.control.catalogMetadata.securityLabelCount = 1; }],
    ["catalog event triggers", (report) => { report.control.catalogMetadata.eventTriggerCount = 1; }],
    ["catalog publications", (report) => { report.control.catalogMetadata.publicationCount = 1; }],
    ["catalog subscriptions", (report) => { report.control.catalogMetadata.subscriptionCount = 1; }],
    ["catalog rewrite rules", (report) => { report.control.catalogMetadata.rewriteRuleCount = 1; }],
    ["control catalog mismatch", (report) => { report.control.catalogMetadata.mismatchCount = 1; }],
    ["demo catalog mismatch", (report) => { report.tenants.demo.catalogMetadata.mismatchCount = 1; }],
    ["Ozama catalog mismatch", (report) => { report.tenants.ozama.catalogMetadata.mismatchCount = 1; }],
  ];

  for (const [label, tamper] of cases) {
    const report = passingLocalStateEvidence();
    tamper(report);
    assert.equal(sanitizeLocalStateEvidence(report, stage).valid, false, label);
  }
});

test("stage status, exit code, skip mode and non-empty counts are fail-closed", () => {
  const mismatchedExit = fullStageNames.map(passedStage);
  mismatchedExit.find(({ name }) => name === "typecheck").exitCode = 27;
  assert.throws(() => buildFinalEvidence({
    schemaVersion: 1,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:10:00.000Z",
    skipE2E: false,
    failed: false,
    stages: mismatchedExit,
  }, { lockfile: path.join(root, "pnpm-lock.yaml") }), /passed with a nonzero/u);

  const fixture = createPassingClosureFixture();
  try {
    assert.equal(buildFinalEvidence(fixture.run, fixture.options).closureEligible, true);
    fixture.run.stages.find(({ name }) => name === "verification-contract").counts = {
      suites: { total: 0, passed: 0, failed: 0, skipped: 0 },
      files: { total: 0, passed: 0, failed: 0, skipped: 0 },
      tests: { total: 0, passed: 0, failed: 0, skipped: 0 },
    };
    const evidence = buildFinalEvidence(fixture.run, fixture.options);
    assert.equal(evidence.overallPass, false);
    assert.equal(evidence.closureEligible, false);
  } finally {
    fixture.cleanup();
  }
});

test("final closure rejects a live suite skip as the only changed condition", () => {
  const fixture = createPassingClosureFixture();
  try {
    assert.equal(buildFinalEvidence(fixture.run, fixture.options).closureEligible, true);
    const database = fixture.run.stages.find((stage) => stage.name === "test-database");
    database.counts.tests = { total: 3, passed: 2, failed: 0, skipped: 1 };
    const evidence = buildFinalEvidence(fixture.run, fixture.options);
    assert.equal(evidence.closureEligible, false);
    assert.equal(evidence.result, "failed");
  } finally {
    fixture.cleanup();
  }
});

test("sanitizer rejects credentials and private profile paths", () => {
  assert.throws(() => assertSanitized({ diagnostic: "postgresql://owner:password@localhost/db" }), /sanitization/u);
  assert.throws(() => assertSanitized({ diagnostic: "C:\\Users\\private-user\\file" }), /sanitization/u);
  assert.throws(() => assertSanitized({ diagnostic: "password: credential-fingerprint" }), /sanitization/u);
  assert.throws(() => assertSanitized({ password: "credential-fingerprint" }), /sanitization/u);
  assert.throws(() => assertSanitized({ connectionParameters: { host: "localhost" } }), /sanitization/u);
});

test("a mandatory engine failure still produces sanitized failed evidence", () => {
  const stages = fullStageNames.slice(0, -3).map(passedStage);
  const engine = stages.find((stage) => stage.name === "engine-probe");
  engine.status = "failed";
  engine.exitCode = 1;
  engine.errorCode = "ENGINE_PROBE_FAILED";
  const evidence = buildFinalEvidence({
    schemaVersion: 1,
    startedAtUtc: "2026-09-12T00:00:00.000Z",
    completedAtUtc: "2026-09-12T00:10:00.000Z",
    skipE2E: false,
    failed: true,
    liveIntegrationRequired: true,
    privilegedLiveRequired: true,
    postgresqlBinaryVersion: "18.0",
    pnpmVersion: "11.19.0",
    engineProbeExitCode: 1,
    engines: availableEngines(false).map((entry) =>
      entry.name === "webkit" ? { ...entry, available: false, code: "UNKNOWN" } : entry),
    stages,
  }, { lockfile: path.join(root, "pnpm-lock.yaml") });
  assert.equal(evidence.result, "failed");
  assert.equal(evidence.closureEligible, false);
  assert.equal(evidence.engines.valid, false);
  assert.equal(evidence.engines.includeFirefox, null);
});

test("custom Playwright reporter persists only repository-relative structured results", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-playwright-evidence-"));
  const output = path.join(directory, "playwright.json");
  try {
    const reporter = new VerifyEvidenceReporter({ outputFile: output, repositoryRoot: root });
    reporter.onBegin(
      { projects: [{ name: "desktop-chromium-es" }] },
      { allTests: () => [{ id: "safe-test-id" }] },
    );
    reporter.onTestEnd({
      id: "safe-test-id",
      title: "structured evidence contract",
      location: { file: path.join(root, "apps/web/e2e/example.spec.ts"), line: 7 },
      annotations: [],
      parent: { project: () => ({ name: "desktop-chromium-es" }) },
    }, { status: "passed", duration: 4 });
    reporter.onEnd({ status: "passed" });
    const report = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(report.counts.total, 1);
    assert.equal(report.plannedTestCount, 1);
    assert.equal(report.results[0].file, "apps/web/e2e/example.spec.ts");
    assert.equal(report.results[0].status, "passed");
    assert.equal(JSON.stringify(report).includes(root), false);
  } finally {
    fs.rmSync(output, { force: true });
    fs.rmdirSync(directory);
  }
});

test("finalizer publishes failure evidence but exits nonzero when full closure is ineligible", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-finalizer-failure-"));
  const input = path.join(directory, "run.json");
  const output = path.join(directory, "final.json");
  try {
    fs.writeFileSync(input, JSON.stringify({
      schemaVersion: 1,
      startedAtUtc: "2026-09-12T00:00:00.000Z",
      completedAtUtc: "2026-09-12T00:00:01.000Z",
      skipE2E: false,
      failed: true,
      liveIntegrationRequired: true,
      privilegedLiveRequired: true,
      postgresqlBinaryVersion: "18.0",
      pnpmVersion: "11.19.0",
      engineProbeExitCode: null,
      engines: null,
      stages: [{
        name: "initial-health",
        startedAtUtc: "2026-09-12T00:00:00.000Z",
        completedAtUtc: "2026-09-12T00:00:01.000Z",
        exitCode: 1,
        status: "failed",
        counts: null,
        errorCode: "CHECK_FAILED",
      }],
    }));
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts/verify-local-evidence.mjs"),
      "finalize",
      "--input", input,
      "--output", output,
      "--lockfile", path.join(root, "pnpm-lock.yaml"),
      "--allowlist", path.join(root, "apps/web/e2e/intentional-skips.json"),
      "--artifact-directory", path.join(root, "docs/evidence"),
      "--workspace", root,
    ], { encoding: "utf8" });
    assert.equal(result.status, 1);
    const evidence = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(evidence.result, "failed");
    assert.equal(evidence.closureEligible, false);
  } finally {
    fs.rmSync(input, { force: true });
    fs.rmSync(output, { force: true });
    fs.rmdirSync(directory);
  }
});

test("an invalid finalization attempt replaces any prior green artifact with red evidence", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "nom-finalizer-invalid-"));
  const input = path.join(directory, "invalid.json");
  const output = path.join(directory, "final.json");
  try {
    fs.writeFileSync(input, "{}\n");
    fs.writeFileSync(output, JSON.stringify({ result: "passed", overallPass: true, sentinel: "stale" }));
    const result = spawnSync(process.execPath, [
      path.join(root, "scripts/verify-local-evidence.mjs"),
      "finalize",
      "--input", input,
      "--output", output,
      "--lockfile", path.join(root, "pnpm-lock.yaml"),
      "--allowlist", path.join(root, "apps/web/e2e/intentional-skips.json"),
      "--artifact-directory", path.join(root, "docs/evidence"),
      "--workspace", root,
    ], { encoding: "utf8" });
    assert.equal(result.status, 1);
    const evidence = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(evidence.result, "failed");
    assert.equal(evidence.overallPass, false);
    assert.equal(evidence.closureEligible, false);
    assert.equal("sentinel" in evidence, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
