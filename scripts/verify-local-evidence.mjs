import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const stageCommands = Object.freeze({
  "source-snapshot-start": "hash closure-relevant workspace sources before verification",
  "initial-health": "GET http://127.0.0.1:4000/healthz",
  "live-prerequisites": "verify local live-integration prerequisites",
  "supply-chain": "pnpm run security:supply-chain",
  "dependency-audit": "pnpm audit --prod --audit-level high",
  typecheck: "pnpm run typecheck",
  lint: "pnpm run lint",
  "stop-services-before-build": "scripts/stop-local.ps1 -KeepDatabase",
  build: "pnpm run build",
  "start-fresh-services": "scripts/start-local.ps1",
  "fresh-health": "GET http://127.0.0.1:4000/healthz (worker required)",
  "verification-contract": "pnpm run test:verification",
  "test-domain": "pnpm --filter @nombramientos/domain test",
  "test-e2ee": "pnpm --filter @nombramientos/e2ee test",
  "test-database": "pnpm --filter @nombramientos/database test --exclude test/seed-audit-history.live.test.ts",
  "test-api": "pnpm --filter @nombramientos/api test",
  "test-web": "pnpm --filter @nombramientos/web test:unit",
  "engine-probe": "node apps/web/scripts/check-playwright-engines.mjs",
  "playwright-e2e": "pnpm run test:e2e",
  "playwright-skip-policy": "validate Playwright results against apps/web/e2e/intentional-skips.json",
  "pdf-render": "pdftoppm -png -r 96 docs/evidence/demo-cycle-summary.pdf <temporary-report-prefix> (all pages)",
  "delivery-scan": "pnpm run security:delivery",
  "local-state-verification": "pnpm --silent run db:verify:local-state",
  "terminal-health": "verify recorded API/web/worker processes and terminal HTTP health",
  "source-integrity-final": "re-hash closure-relevant workspace sources before publication",
  "evidence-finalize": "atomically publish artifacts/verify-local-final.json",
});

const basePlaywrightProjects = Object.freeze([
  "desktop-chromium-es",
  "mobile-chromium-es",
  "mobile-webkit-fr",
  "mobile-small",
]);
const firefoxPlaywrightProject = "desktop-firefox-en";
const expectedControlCatalogCommentCount = 10;
const expectedTenantCatalogCommentCount = 61;
const requiredArtifactFiles = Object.freeze([
  "demo-cycle-summary.pdf",
  "demo-cycle-summary.xlsx",
  "demo-cycle-summary.csv",
  "demo-cycle-summary-history.csv",
]);
const sourceRootDirectories = Object.freeze([".github", "apps", "config", "packages", "scripts"]);
const sourceRootFiles = Object.freeze([
  ".dockerignore",
  ".env.example",
  ".gitignore",
  "compose.yaml",
  "Dockerfile",
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
]);
const ignoredSourceDirectoryNames = new Set([
  ".git",
  ".local",
  ".next",
  ".pnpm-store",
  "artifacts",
  "coverage",
  "dist",
  "node_modules",
  "playwright-report",
  "test-results",
  "tmp",
]);
const ignoredGeneratedSourceFileNames = new Set([
  "next-env.d.ts",
]);

function exactString(value, label) {
  if (typeof value !== "string" || !value) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function exactNonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${label} must be a non-negative integer`);
  return value;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/u, ""));
}

function entryKey(entry) {
  return `${entry.project}\u0000${entry.file}\u0000${entry.title}\u0000${entry.reason}`;
}

function testKey(entry) {
  return `${entry.project}\u0000${entry.file}\u0000${entry.title}`;
}

export function deriveEngineDecision(probeExitCode, results) {
  if (![0, 2].includes(probeExitCode)) {
    throw new Error("A mandatory Playwright engine failed its current-run probe");
  }
  if (!Array.isArray(results) || results.length !== 3) throw new Error("Engine probe did not report exactly three engines");
  const byName = new Map(results.map((result) => [result.name, result]));
  for (const requiredName of ["chromium", "webkit"]) {
    const result = byName.get(requiredName);
    if (!result || result.required !== true || result.available !== true) {
      throw new Error(`Mandatory ${requiredName} engine is unavailable`);
    }
  }
  const firefox = byName.get("firefox");
  if (!firefox || firefox.required !== false) throw new Error("Engine probe has no optional Firefox result");
  if (probeExitCode === 0 && firefox.available !== true) throw new Error("Probe exit 0 contradicts the Firefox result");
  if (probeExitCode === 2 && firefox.available !== false) throw new Error("Probe exit 2 contradicts the Firefox result");
  return {
    includeFirefox: probeExitCode === 0,
    exclusionReason: probeExitCode === 2 ? "current-run-native-probe-exit-2" : null,
  };
}

export function expectedPlaywrightProjects(includeFirefox) {
  if (typeof includeFirefox !== "boolean") throw new Error("The current-run Firefox decision is required");
  return includeFirefox
    ? [basePlaywrightProjects[0], firefoxPlaywrightProject, ...basePlaywrightProjects.slice(1)]
    : [...basePlaywrightProjects];
}

export function validatePlaywrightEvidence(report, allowlist, includeFirefox) {
  if (report?.schemaVersion !== 1 || !Array.isArray(report.projects) || !Array.isArray(report.results)) {
    throw new Error("Playwright evidence has an unsupported shape");
  }
  if (allowlist?.schemaVersion !== 1 || !Array.isArray(allowlist.entries)) {
    throw new Error("Playwright skip allowlist has an unsupported shape");
  }
  const runProject = exactString(allowlist.runProject, "allowlist.runProject");
  const reportedProjects = report.projects.map((project) => exactString(project, "project"));
  const projects = [...new Set(reportedProjects)].sort();
  const expectedProjects = expectedPlaywrightProjects(includeFirefox).sort();
  const projectMatrixMatches = reportedProjects.length === projects.length
    && projects.length === expectedProjects.length
    && projects.every((project, index) => project === expectedProjects[index]);
  if (!projects.includes(runProject)) throw new Error("Playwright evidence omits the allowlist run project");

  const entries = allowlist.entries.map((entry, index) => ({
    file: exactString(entry.file, `allowlist.entries[${index}].file`),
    title: exactString(entry.title, `allowlist.entries[${index}].title`),
    reason: exactString(entry.reason, `allowlist.entries[${index}].reason`),
  }));
  const entryIdentities = entries.map((entry) => `${entry.file}\u0000${entry.title}`);
  if (new Set(entryIdentities).size !== entryIdentities.length) throw new Error("Playwright skip allowlist contains duplicate tests");

  const results = report.results.map((result, index) => ({
    project: exactString(result.project, `results[${index}].project`),
    file: exactString(result.file, `results[${index}].file`),
    line: exactNonNegativeInteger(result.line, `results[${index}].line`),
    title: exactString(result.title, `results[${index}].title`),
    status: exactString(result.status, `results[${index}].status`),
    skipReason: result.skipReason,
  }));
  const acceptedStatuses = new Set(["passed", "failed", "skipped", "timedOut", "interrupted"]);
  const invalidStatusCount = results.filter((result) => !acceptedStatuses.has(result.status)).length;
  const outsideProjectCount = results.filter((result) => !projects.includes(result.project)).length;
  const unsafeFileCount = results.filter((result) =>
    !result.file.startsWith("apps/web/e2e/") || result.file.includes("..") || path.isAbsolute(result.file)).length;
  const duplicateResultCount = results.length - new Set(results.map(testKey)).size;
  const latestByTest = new Map(results.map((result) => [testKey(result), result]));
  const expected = entries.flatMap((entry) => projects
    .filter((project) => project !== runProject)
    .map((project) => ({ project, ...entry })));
  const expectedKeys = new Set(expected.map(entryKey));
  const actual = results
    .filter((result) => result.status === "skipped")
    .map((result) => ({
      project: result.project,
      file: result.file,
      title: result.title,
      reason: typeof result.skipReason === "string" ? result.skipReason : "",
    }));
  const actualKeys = new Set(actual.map(entryKey));
  const unexpected = actual.filter((entry) => !expectedKeys.has(entryKey(entry)));
  const missing = expected.filter((entry) => !actualKeys.has(entryKey(entry)));
  const runProjectFailures = entries.filter((entry) => {
    const result = latestByTest.get(`${runProject}\u0000${entry.file}\u0000${entry.title}`);
    return result?.status !== "passed";
  });
  const duplicates = actual.length - actualKeys.size;
  const testCounts = {
    total: results.length,
    passed: results.filter((entry) => entry.status === "passed").length,
    failed: results.filter((entry) => ["failed", "timedOut", "interrupted"].includes(entry.status)).length,
    skipped: results.filter((entry) => entry.status === "skipped").length,
  };
  const fileGroups = new Map();
  for (const result of results) {
    const key = `${result.project}\u0000${result.file}`;
    const statuses = fileGroups.get(key) ?? [];
    statuses.push(result.status);
    fileGroups.set(key, statuses);
  }
  const fileStatuses = [...fileGroups.values()].map((statuses) => {
    if (statuses.some((status) => ["failed", "timedOut", "interrupted"].includes(status))) return "failed";
    if (statuses.every((status) => status === "skipped")) return "skipped";
    return "passed";
  });
  const fileCounts = {
    total: fileStatuses.length,
    passed: fileStatuses.filter((status) => status === "passed").length,
    failed: fileStatuses.filter((status) => status === "failed").length,
    skipped: fileStatuses.filter((status) => status === "skipped").length,
  };
  const suiteCounts = {
    total: 1,
    passed: report.status === "passed" ? 1 : 0,
    failed: report.status === "passed" ? 0 : 1,
    skipped: 0,
  };
  const reportedCountsMatch = report.counts?.total === results.length
    && report.counts?.passed === testCounts.passed
    && report.counts?.failed === results.filter((entry) => entry.status === "failed").length
    && report.counts?.skipped === testCounts.skipped
    && report.counts?.timedOut === results.filter((entry) => entry.status === "timedOut").length
    && report.counts?.interrupted === results.filter((entry) => entry.status === "interrupted").length;
  const plannedCountMatches = Number.isInteger(report.plannedTestCount)
    && report.plannedTestCount > 0
    && report.plannedTestCount === results.length;
  const perProject = projects.map((project) => {
    const projectResults = results.filter((entry) => entry.project === project);
    return {
      project,
      total: projectResults.length,
      passed: projectResults.filter((entry) => entry.status === "passed").length,
      failed: projectResults.filter((entry) => ["failed", "timedOut", "interrupted"].includes(entry.status)).length,
      skipped: projectResults.filter((entry) => entry.status === "skipped").length,
    };
  });
  const everyProjectExecuted = perProject.every(({ total, passed, failed }) => total > 0 && passed > 0 && failed === 0);
  const valid = report.status === "passed"
    && projectMatrixMatches
    && unexpected.length === 0
    && missing.length === 0
    && runProjectFailures.length === 0
    && duplicates === 0
    && invalidStatusCount === 0
    && outsideProjectCount === 0
    && unsafeFileCount === 0
    && duplicateResultCount === 0
    && reportedCountsMatch
    && plannedCountMatches
    && everyProjectExecuted;
  return {
    valid,
    sourceEntries: entries.length,
    expectedSkipCount: expected.length,
    actualSkipCount: actual.length,
    activeProjects: projects,
    expectedProjects,
    projectMatrixMatches,
    runProject,
    perProject,
    unexpectedCount: unexpected.length,
    missingCount: missing.length,
    runProjectFailureCount: runProjectFailures.length,
    duplicateCount: duplicates,
    duplicateResultCount,
    invalidStatusCount,
    outsideProjectCount,
    unsafeFileCount,
    reportedCountsMatch,
    plannedCountMatches,
    everyProjectExecuted,
    counts: {
      suites: suiteCounts,
      files: fileCounts,
      tests: testCounts,
    },
    skips: actual
      .map((entry) => ({ ...entry, count: 1 }))
      .sort((left, right) => entryKey(left).localeCompare(entryKey(right))),
  };
}

function sha256(file) {
  return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

export function collectWorkspaceSourceFingerprint(workspaceRoot) {
  const root = path.resolve(exactString(workspaceRoot, "workspaceRoot"));
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && (ignoredSourceDirectoryNames.has(entry.name) || entry.name.startsWith(".local-"))) {
        continue;
      }
      const filename = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error("Closure source trees must not contain symbolic links");
      if (entry.isDirectory()) visit(filename);
      else if (entry.isFile()
        && !ignoredGeneratedSourceFileNames.has(entry.name)
        && !entry.name.endsWith(".tsbuildinfo")
        && !entry.name.endsWith(".log")) files.push(filename);
    }
  };
  for (const directoryName of sourceRootDirectories) {
    const directory = path.join(root, directoryName);
    if (fs.existsSync(directory)) visit(directory);
  }
  for (const filename of sourceRootFiles.map((name) => path.join(root, name))) {
    if (fs.existsSync(filename)) {
      const stat = fs.lstatSync(filename);
      if (stat.isSymbolicLink()) throw new Error("Closure root source files must not be symbolic links");
      if (stat.isFile()) files.push(filename);
    }
  }
  const orderedFiles = [...new Set(files.map((filename) => path.resolve(filename)))].sort((left, right) =>
    left.localeCompare(right, "en", { sensitivity: "case" }));
  if (orderedFiles.length < 1) throw new Error("No closure-relevant workspace sources were found");
  const hash = createHash("sha256");
  for (const filename of orderedFiles) {
    const relative = path.relative(root, filename).split(path.sep).join("/");
    if (!relative || relative.startsWith("../") || path.isAbsolute(relative)) {
      throw new Error("A closure source resolved outside the workspace");
    }
    const contents = fs.readFileSync(filename);
    hash.update(`${Buffer.byteLength(relative)}:${relative}:${contents.length}:`, "utf8");
    hash.update(contents);
  }
  return {
    schemaVersion: 1,
    algorithm: "sha256",
    fileCount: orderedFiles.length,
    sha256: hash.digest("hex"),
  };
}

export function collectArtifactEvidence(artifactDirectory, startedAtUtc, completedAtUtc, popplerRenderPass) {
  const directory = path.resolve(exactString(artifactDirectory, "artifactDirectory"));
  const startedAt = Date.parse(exactString(startedAtUtc, "startedAtUtc"));
  const completedAt = Date.parse(exactString(completedAtUtc, "completedAtUtc"));
  if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt) || completedAt < startedAt) {
    throw new Error("Artifact evidence timestamps are invalid");
  }
  const files = requiredArtifactFiles.map((name) => {
    const filename = path.join(directory, name);
    try {
      const stat = fs.statSync(filename);
      const minimumBytes = name.endsWith(".pdf") ? 500 : 100;
      const fresh = stat.isFile() && stat.mtimeMs >= startedAt - 5_000 && stat.mtimeMs <= completedAt + 5_000;
      return {
        path: `docs/evidence/${name}`,
        sha256: stat.isFile() ? sha256(filename) : null,
        bytes: stat.isFile() ? stat.size : null,
        modifiedAtUtc: stat.isFile() ? stat.mtime.toISOString() : null,
        present: stat.isFile() && stat.size >= minimumBytes,
        fresh,
      };
    } catch {
      return {
        path: `docs/evidence/${name}`,
        sha256: null,
        bytes: null,
        modifiedAtUtc: null,
        present: false,
        fresh: false,
      };
    }
  });
  const valid = popplerRenderPass === true
    && files.every((file) => file.present && file.fresh && /^[a-f0-9]{64}$/u.test(file.sha256 ?? ""));
  return {
    valid,
    popplerRenderPass: popplerRenderPass === true,
    requiredFileCount: requiredArtifactFiles.length,
    currentRunFileCount: files.filter((file) => file.present && file.fresh).length,
    files,
  };
}

function strictInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${label} must be a non-negative integer`);
  return value;
}

function sanitizeMigrationLedger(value, label, expectedCount, expectedHead) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const head = value.head === null || (typeof value.head === "string" && /^\d+_[a-z0-9_]+\.sql$/u.test(value.head))
    ? value.head
    : null;
  const reportedExpectedHead = typeof value.expectedHead === "string" && /^\d+_[a-z0-9_]+\.sql$/u.test(value.expectedHead)
    ? value.expectedHead
    : null;
  const ledgerSha256 = typeof value.ledgerSha256 === "string" && /^[a-f0-9]{64}$/u.test(value.ledgerSha256)
    ? value.ledgerSha256
    : null;
  const evidence = {
    expectedCount: strictInteger(value.expectedCount, `${label}.expectedCount`),
    appliedCount: strictInteger(value.appliedCount, `${label}.appliedCount`),
    pendingCount: strictInteger(value.pendingCount, `${label}.pendingCount`),
    unexpectedCount: strictInteger(value.unexpectedCount, `${label}.unexpectedCount`),
    checksumMismatchCount: strictInteger(value.checksumMismatchCount, `${label}.checksumMismatchCount`),
    head,
    expectedHead: reportedExpectedHead,
    ledgerSha256,
    mismatchCount: strictInteger(value.mismatchCount, `${label}.mismatchCount`),
  };
  return {
    ...evidence,
    valid: evidence.expectedCount === expectedCount
      && evidence.appliedCount === expectedCount
      && evidence.pendingCount === 0
      && evidence.unexpectedCount === 0
      && evidence.checksumMismatchCount === 0
      && evidence.head === expectedHead
      && evidence.expectedHead === expectedHead
      && evidence.ledgerSha256 !== null
      && evidence.mismatchCount === 0,
  };
}

function safeEnum(value, allowed) {
  return typeof value === "string" && allowed.includes(value) ? value : "invalid";
}

function sanitizeCatalogMetadata(value, label, expectedCommentCount) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const catalogSha256 = typeof value.catalogSha256 === "string" && /^[a-f0-9]{64}$/u.test(value.catalogSha256)
    ? value.catalogSha256
    : null;
  const evidence = {
    catalogSha256,
    commentCount: strictInteger(value.commentCount, `${label}.commentCount`),
    sharedCommentCount: strictInteger(value.sharedCommentCount, `${label}.sharedCommentCount`),
    securityLabelCount: strictInteger(value.securityLabelCount, `${label}.securityLabelCount`),
    eventTriggerCount: strictInteger(value.eventTriggerCount, `${label}.eventTriggerCount`),
    publicationCount: strictInteger(value.publicationCount, `${label}.publicationCount`),
    subscriptionCount: strictInteger(value.subscriptionCount, `${label}.subscriptionCount`),
    rewriteRuleCount: strictInteger(value.rewriteRuleCount, `${label}.rewriteRuleCount`),
    mismatchCount: strictInteger(value.mismatchCount, `${label}.mismatchCount`),
  };
  return {
    ...evidence,
    valid: evidence.catalogSha256 !== null
      && evidence.commentCount === expectedCommentCount
      && evidence.sharedCommentCount === 0
      && evidence.securityLabelCount === 0
      && evidence.eventTriggerCount === 0
      && evidence.publicationCount === 0
      && evidence.subscriptionCount === 0
      && evidence.rewriteRuleCount === 0
      && evidence.mismatchCount === 0,
  };
}

function sanitizeTenantState(value, label, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const migrations = sanitizeMigrationLedger(
    value.migrations,
    `${label}.migrations`,
    38,
    "036_transactional_invitation_grantor_lock.sql",
  );
  const institutionalCatalog = sanitizeInstitutionalCatalog(
    value.institutionalCatalog,
    `${label}.institutionalCatalog`,
  );
  const catalogMetadata = sanitizeCatalogMetadata(
    value.catalogMetadata,
    `${label}.catalogMetadata`,
    expectedTenantCatalogCommentCount,
  );
  const evidence = {
    kind: safeEnum(value.kind, ["demo", "real", "invalid"]),
    lifecycle: safeEnum(value.lifecycle, ["active", "suspended", "provisioning", "failed", "missing", "invalid"]),
    setupState: safeEnum(value.setupState, ["not_started", "in_progress", "ready", "invalid"]),
    maintenanceClass: safeEnum(value.maintenanceClass, ["routable", "pending_activation", "invalid"]),
    migrations,
    schemaInventoryMismatchCount: strictInteger(
      value.schemaInventoryMismatchCount,
      `${label}.schemaInventoryMismatchCount`,
    ),
    institutionalCatalog,
    catalogMetadata,
    tableInventoryMismatchCount: strictInteger(value.tableInventoryMismatchCount, `${label}.tableInventoryMismatchCount`),
    ownershipMismatchCount: strictInteger(value.ownershipMismatchCount, `${label}.ownershipMismatchCount`),
    runtimeGrantMismatchCount: strictInteger(value.runtimeGrantMismatchCount, `${label}.runtimeGrantMismatchCount`),
    ...(expected.kind === "demo" ? {
      memberCount: strictInteger(value.memberCount, `${label}.memberCount`),
      eligibleMemberCount: strictInteger(value.eligibleMemberCount, `${label}.eligibleMemberCount`),
    } : {
      operationalTableCount: strictInteger(value.operationalTableCount, `${label}.operationalTableCount`),
      operationalRowCount: strictInteger(value.operationalRowCount, `${label}.operationalRowCount`),
    }),
    mismatchCount: strictInteger(value.mismatchCount, `${label}.mismatchCount`),
  };
  const expectedCountsMatch = expected.kind === "demo"
    ? evidence.memberCount === 180 && evidence.eligibleMemberCount === 150
    : evidence.operationalTableCount === 47 && evidence.operationalRowCount === 0;
  return {
    ...evidence,
    valid: evidence.kind === expected.kind
      && evidence.lifecycle === expected.lifecycle
      && evidence.setupState === expected.setupState
      && evidence.maintenanceClass === expected.maintenanceClass
      && migrations.valid
      && evidence.schemaInventoryMismatchCount === 0
      && institutionalCatalog.valid
      && catalogMetadata.valid
      && evidence.tableInventoryMismatchCount === 0
      && evidence.ownershipMismatchCount === 0
      && evidence.runtimeGrantMismatchCount === 0
      && expectedCountsMatch
      && evidence.mismatchCount === 0,
  };
}

function sanitizeInstitutionalCatalog(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const targetVersion = semanticVersionOrNull(value.targetVersion);
  const observedVersion = semanticVersionOrNull(value.observedVersion);
  const targetCatalogSha256 = typeof value.targetCatalogSha256 === "string"
    && /^sha256:[a-f0-9]{64}$/u.test(value.targetCatalogSha256)
    ? value.targetCatalogSha256
    : null;
  const observedCatalogSha256 = typeof value.observedCatalogSha256 === "string"
    && /^sha256:[a-f0-9]{64}$/u.test(value.observedCatalogSha256)
    ? value.observedCatalogSha256
    : null;
  const evidence = {
    targetVersion,
    observedVersion,
    expectedDepartmentCount: strictInteger(value.expectedDepartmentCount, `${label}.expectedDepartmentCount`),
    observedDepartmentCount: strictInteger(value.observedDepartmentCount, `${label}.observedDepartmentCount`),
    missingDepartmentCount: strictInteger(value.missingDepartmentCount, `${label}.missingDepartmentCount`),
    unexpectedDepartmentCount: strictInteger(value.unexpectedDepartmentCount, `${label}.unexpectedDepartmentCount`),
    expectedOfficeCount: strictInteger(value.expectedOfficeCount, `${label}.expectedOfficeCount`),
    observedOfficeCount: strictInteger(value.observedOfficeCount, `${label}.observedOfficeCount`),
    missingOfficeCount: strictInteger(value.missingOfficeCount, `${label}.missingOfficeCount`),
    unexpectedOfficeCount: strictInteger(value.unexpectedOfficeCount, `${label}.unexpectedOfficeCount`),
    targetCatalogSha256,
    observedCatalogSha256,
    localExtensionCollisionCount: strictInteger(value.localExtensionCollisionCount, `${label}.localExtensionCollisionCount`),
    invalidRowVersionCount: strictInteger(value.invalidRowVersionCount, `${label}.invalidRowVersionCount`),
    blockingMismatchCount: strictInteger(value.blockingMismatchCount, `${label}.blockingMismatchCount`),
    mismatchCount: strictInteger(value.mismatchCount, `${label}.mismatchCount`),
  };
  return {
    ...evidence,
    valid: evidence.targetVersion !== null
      && evidence.observedVersion === evidence.targetVersion
      && evidence.expectedDepartmentCount > 0
      && evidence.observedDepartmentCount === evidence.expectedDepartmentCount
      && evidence.missingDepartmentCount === 0
      && evidence.unexpectedDepartmentCount === 0
      && evidence.expectedOfficeCount > 0
      && evidence.observedOfficeCount === evidence.expectedOfficeCount
      && evidence.missingOfficeCount === 0
      && evidence.unexpectedOfficeCount === 0
      && evidence.targetCatalogSha256 !== null
      && evidence.observedCatalogSha256 === evidence.targetCatalogSha256
      && evidence.localExtensionCollisionCount === 0
      && evidence.invalidRowVersionCount === 0
      && evidence.blockingMismatchCount === 0
      && evidence.mismatchCount === 0,
  };
}

export function sanitizeLocalStateEvidence(report, stage) {
  if (!report || typeof report !== "object" || Array.isArray(report)) throw new Error("Local state evidence is invalid");
  if (!stage || stage.name !== "local-state-verification") throw new Error("Local state stage is missing");
  const checkedAt = exactString(report.checkedAt, "localState.checkedAt");
  const checkedAtMs = Date.parse(checkedAt);
  const stageStartedAtMs = Date.parse(stage.startedAtUtc);
  const stageCompletedAtMs = Date.parse(stage.completedAtUtc);
  if (![checkedAtMs, stageStartedAtMs, stageCompletedAtMs].every(Number.isFinite)) {
    throw new Error("Local state timestamps are invalid");
  }
  const controlMigrations = sanitizeMigrationLedger(
    report.control?.migrations,
    "localState.control.migrations",
    26,
    "026_invitation_enrollment_recovery_qualification.sql",
  );
  const demo = sanitizeTenantState(report.tenants?.demo, "localState.tenants.demo", {
    kind: "demo",
    lifecycle: "active",
    setupState: "ready",
    maintenanceClass: "routable",
  });
  const ozama = sanitizeTenantState(report.tenants?.ozama, "localState.tenants.ozama", {
    kind: "real",
    lifecycle: "provisioning",
    setupState: "not_started",
    maintenanceClass: "pending_activation",
  });
  const server = {
    postgresMajor: strictInteger(report.server?.postgresMajor, "localState.server.postgresMajor"),
    port: strictInteger(report.server?.port, "localState.server.port"),
    loopback: report.server?.loopback === true,
    controlDatabaseMatch: report.server?.controlDatabaseMatch === true,
    transactionReadOnly: report.server?.transactionReadOnly === true,
    transactionIsolation: report.server?.transactionIsolation === "repeatable read" ? "repeatable read" : "unexpected",
    administratorMatch: report.server?.administratorMatch === true,
    mismatchCount: strictInteger(report.server?.mismatchCount, "localState.server.mismatchCount"),
  };
  const controlCatalogMetadata = sanitizeCatalogMetadata(
    report.control?.catalogMetadata,
    "localState.control.catalogMetadata",
    expectedControlCatalogCommentCount,
  );
  const control = {
    migrations: controlMigrations,
    tenantRouteCount: strictInteger(report.control?.tenantRouteCount, "localState.control.tenantRouteCount"),
    routeMismatchCount: strictInteger(report.control?.routeMismatchCount, "localState.control.routeMismatchCount"),
    ozamaIdentityOrAdminArtifactCount: strictInteger(
      report.control?.ozamaIdentityOrAdminArtifactCount,
      "localState.control.ozamaIdentityOrAdminArtifactCount",
    ),
    workerBacklog: {
      provisioningJobCount: strictInteger(
        report.control?.workerBacklog?.provisioningJobCount,
        "localState.control.workerBacklog.provisioningJobCount",
      ),
      tenantExportJobCount: strictInteger(
        report.control?.workerBacklog?.tenantExportJobCount,
        "localState.control.workerBacklog.tenantExportJobCount",
      ),
      totalCount: strictInteger(
        report.control?.workerBacklog?.totalCount,
        "localState.control.workerBacklog.totalCount",
      ),
      mismatchCount: strictInteger(
        report.control?.workerBacklog?.mismatchCount,
        "localState.control.workerBacklog.mismatchCount",
      ),
    },
    schemaInventoryMismatchCount: strictInteger(
      report.control?.schemaInventoryMismatchCount,
      "localState.control.schemaInventoryMismatchCount",
    ),
    roleMismatchCount: strictInteger(report.control?.roleMismatchCount, "localState.control.roleMismatchCount"),
    catalogMetadata: controlCatalogMetadata,
    mismatchCount: strictInteger(report.control?.mismatchCount, "localState.control.mismatchCount"),
  };
  const checkedWithinStage = checkedAtMs >= stageStartedAtMs - 5_000 && checkedAtMs <= stageCompletedAtMs + 5_000;
  const valid = report.schemaVersion === 2
    && report.mode === "read-only"
    && report.demoFixtureExpectation === "after"
    && report.pass === true
    && report.verificationIncomplete === undefined
    && strictInteger(report.mismatchCount, "localState.mismatchCount") === 0
    && server.postgresMajor === 18
    && server.port === 55_432
    && server.loopback
    && server.controlDatabaseMatch
    && server.transactionReadOnly
    && server.transactionIsolation === "repeatable read"
    && server.administratorMatch
    && server.mismatchCount === 0
    && controlMigrations.valid
    && control.tenantRouteCount === 2
    && control.routeMismatchCount === 0
    && control.ozamaIdentityOrAdminArtifactCount === 0
    && control.workerBacklog.provisioningJobCount === 0
    && control.workerBacklog.tenantExportJobCount === 0
    && control.workerBacklog.totalCount === 0
    && control.workerBacklog.mismatchCount === 0
    && control.schemaInventoryMismatchCount === 0
    && control.roleMismatchCount === 0
    && controlCatalogMetadata.valid
    && control.mismatchCount === 0
    && demo.valid
    && ozama.valid
    && checkedWithinStage;
  return {
    schemaVersion: report.schemaVersion === 2 ? 2 : null,
    checkedAt,
    checkedWithinStage,
    mode: report.mode === "read-only" ? "read-only" : "invalid",
    demoFixtureExpectation: safeEnum(report.demoFixtureExpectation, ["before", "after"]),
    pass: report.pass === true,
    mismatchCount: strictInteger(report.mismatchCount, "localState.mismatchCount"),
    server,
    control,
    tenants: { demo, ozama },
    valid,
  };
}

function semanticVersionOrNull(value) {
  return typeof value === "string" && /^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$/u.test(value)
    ? value
    : null;
}

function nodeVersionOrNull(value) {
  return typeof value === "string" && /^v\d+\.\d+\.\d+$/u.test(value)
    ? value
    : null;
}

function safeSourceFingerprint(value) {
  if (value?.schemaVersion !== 1
    || value.algorithm !== "sha256"
    || !Number.isInteger(value.fileCount)
    || value.fileCount < 1
    || typeof value.sha256 !== "string"
    || !/^[a-f0-9]{64}$/u.test(value.sha256)) return null;
  return {
    schemaVersion: 1,
    algorithm: "sha256",
    fileCount: value.fileCount,
    sha256: value.sha256,
  };
}

function sanitizeStage(stage) {
  const name = exactString(stage.name, "stage.name");
  if (!(name in stageCommands)) throw new Error(`Unknown verification stage: ${name}`);
  const validStatuses = new Set(["passed", "failed", "accepted-optional", "not-run", "skipped-by-option"]);
  if (!validStatuses.has(stage.status)) throw new Error(`Unsupported status for ${name}`);
  const exitCode = stage.exitCode === null ? null : Number(stage.exitCode);
  if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < 0)) throw new Error(`Invalid exit code for ${name}`);
  const optionalStageNames = new Set(["engine-probe"]);
  const e2eOnlyStageNames = new Set(["engine-probe", "playwright-e2e", "playwright-skip-policy", "pdf-render"]);
  if (stage.status === "passed" && exitCode !== 0) throw new Error(`${name} passed with a nonzero or missing exit code`);
  if (stage.status === "failed" && (exitCode === null || exitCode === 0)) throw new Error(`${name} failed without a nonzero exit code`);
  if (stage.status === "accepted-optional" && (!optionalStageNames.has(name) || exitCode !== 2)) {
    throw new Error(`${name} has an invalid accepted-optional result`);
  }
  if (stage.status === "skipped-by-option" && (!e2eOnlyStageNames.has(name) || exitCode !== null)) {
    throw new Error(`${name} has an invalid skipped-by-option result`);
  }
  if (stage.status === "not-run" && exitCode !== null) throw new Error(`${name} was not run but has an exit code`);
  const startedAtUtc = stage.startedAtUtc ?? null;
  const completedAtUtc = stage.completedAtUtc ?? null;
  const executed = ["passed", "failed", "accepted-optional"].includes(stage.status);
  if (executed) {
    if (!Number.isFinite(Date.parse(startedAtUtc)) || !Number.isFinite(Date.parse(completedAtUtc))) {
      throw new Error(`${name} has invalid execution timestamps`);
    }
    if (Date.parse(completedAtUtc) < Date.parse(startedAtUtc)) throw new Error(`${name} completed before it started`);
  } else if (startedAtUtc !== null || completedAtUtc !== null) {
    throw new Error(`${name} has timestamps despite not executing`);
  }
  const errorCode = typeof stage.errorCode === "string" && /^[A-Z][A-Z0-9_]{2,63}$/u.test(stage.errorCode)
    ? stage.errorCode
    : null;
  if (stage.status === "failed" && errorCode === null) throw new Error(`${name} failed without a safe error code`);
  if (stage.status !== "failed" && stage.errorCode !== null && stage.errorCode !== undefined) {
    throw new Error(`${name} has an error code despite not failing`);
  }
  let counts = null;
  if (stage.counts !== null && stage.counts !== undefined) {
    const sanitizeCounter = (counter, label) => ({
      total: exactNonNegativeInteger(Number(counter.total), `${label}.total`),
      passed: exactNonNegativeInteger(Number(counter.passed), `${label}.passed`),
      failed: exactNonNegativeInteger(Number(counter.failed), `${label}.failed`),
      skipped: exactNonNegativeInteger(Number(counter.skipped), `${label}.skipped`),
    });
    counts = {
      suites: sanitizeCounter(stage.counts.suites, `${name}.counts.suites`),
      files: sanitizeCounter(stage.counts.files, `${name}.counts.files`),
      tests: sanitizeCounter(stage.counts.tests, `${name}.counts.tests`),
    };
    for (const [label, counter] of Object.entries(counts)) {
      if (counter.total !== counter.passed + counter.failed + counter.skipped) {
        throw new Error(`${name}.counts.${label} is internally inconsistent`);
      }
    }
  }
  return {
    name,
    command: stageCommands[name],
    startedAtUtc,
    completedAtUtc,
    exitCode,
    status: stage.status,
    counts,
    errorCode,
  };
}

function assertSanitized(value) {
  const forbidden = [
    /(?:postgres(?:ql)?|https?):\/\/[^/\s:@]+:[^@\s/]+@/iu,
    /\b(?:DATABASE|REDIS|SMTP|JWT|SESSION|COOKIE)_[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|URL)\s*=/u,
    /\b(?:password|passphrase|secret|token|cookie|authorization|recovery[_-]?code|totp[_-]?secret|api[_-]?key|private[_-]?key)\s*[:=]\s*(?!null\b|undefined\b|\[redacted\]\b)[^\s,;}\]]+/iu,
    /\b(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16})\b/u,
    /[A-Z]:\\Users\\[^\\\s]+/iu,
  ];
  const forbiddenObjectKey = /^(?:password|passphrase|secret|token|cookie|authorization|recovery[_-]?code|totp[_-]?secret|api[_-]?key|private[_-]?key|_?connectionParameters)$/iu;
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (typeof current === "string" && forbidden.some((pattern) => pattern.test(current))) {
      throw new Error("Final verification evidence failed secret/path sanitization");
    }
    if (Array.isArray(current)) pending.push(...current);
    else if (current && typeof current === "object") {
      for (const [key, entry] of Object.entries(current)) {
        if (forbiddenObjectKey.test(key)) {
          throw new Error("Final verification evidence failed secret/path sanitization");
        }
        pending.push(entry);
      }
    }
  }
}

function writeJsonAtomic(outputFile, value) {
  assertSanitized(value);
  const directory = path.dirname(outputFile);
  fs.mkdirSync(directory, { recursive: true });
  const temporary = path.join(directory, `.${path.basename(outputFile)}.${process.pid}.${Date.now()}.tmp`);
  const displaced = path.join(directory, `.${path.basename(outputFile)}.${process.pid}.${Date.now()}.displaced`);
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  try {
    const descriptor = fs.openSync(temporary, "r+");
    try {
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    if (fs.existsSync(outputFile)) fs.renameSync(outputFile, displaced);
    // Both publication steps are same-directory renames. A crash between them
    // can leave the canonical path absent, but can never retain stale green.
    fs.renameSync(temporary, outputFile);
    try { fs.rmSync(displaced, { force: true }); } catch { /* hidden stale evidence is never authoritative */ }
  } finally {
    try { fs.rmSync(temporary, { force: true }); } catch { /* never mask the published result */ }
  }
}

export function buildInProgressEvidence({ startedAtUtc, skipE2E, lockfile }) {
  if (!Number.isFinite(Date.parse(exactString(startedAtUtc, "startedAtUtc")))) {
    throw new Error("startedAtUtc must be an ISO timestamp");
  }
  const evidence = {
    schemaVersion: 1,
    command: skipE2E ? "pnpm verify:local -SkipE2E" : "pnpm verify:local",
    startedAtUtc,
    completedAtUtc: null,
    result: "in-progress",
    overallPass: false,
    closureEligible: false,
    environment: {
      node: process.version,
      finalizerNode: process.version,
      pnpm: null,
      postgresqlBinary: null,
      pnpmLockSha256: sha256(lockfile),
      valid: false,
    },
    guarantees: {
      liveIntegrationRequired: false,
      privilegedLiveRequired: false,
      stdoutPersisted: false,
      stderrPersisted: false,
      repositoryRelativeTestPathsOnly: true,
      zeroNonE2ESkipsRequired: true,
    },
    stages: Object.entries(stageCommands).map(([name, command]) => ({
      name,
      command,
      startedAtUtc: null,
      completedAtUtc: null,
      exitCode: null,
      status: "not-run",
      counts: null,
      errorCode: null,
    })),
    testSuites: [],
    engines: null,
    e2e: null,
    artifacts: null,
    localState: null,
    sourceIntegrity: null,
    serviceLifecycle: null,
  };
  assertSanitized(evidence);
  return evidence;
}

export function buildFinalEvidence(run, options = {}) {
  if (run?.schemaVersion !== 1 || !Array.isArray(run.stages)) throw new Error("Run evidence has an unsupported shape");
  const skipE2E = run.skipE2E === true;
  const actualStages = run.stages.map(sanitizeStage);
  const suppliedStageNames = actualStages.map((stage) => stage.name);
  const byName = new Map(actualStages.map((stage) => [stage.name, stage]));
  if (byName.size !== actualStages.length) throw new Error("Verification stage names must be unique");

  const plannedNames = Object.keys(stageCommands).filter((name) => name !== "evidence-finalize");
  const expectedExecutionNames = skipE2E
    ? plannedNames.filter((name) => !["engine-probe", "playwright-e2e", "playwright-skip-policy", "pdf-render"].includes(name))
    : plannedNames;
  const stageOrderComplete = suppliedStageNames.length === expectedExecutionNames.length
    && suppliedStageNames.every((name, index) => name === expectedExecutionNames[index]);
  for (const name of plannedNames) {
    if (!byName.has(name)) {
      const e2eOnly = ["engine-probe", "playwright-e2e", "playwright-skip-policy", "pdf-render"].includes(name);
      actualStages.push({
        name,
        command: stageCommands[name],
        startedAtUtc: null,
        completedAtUtc: null,
        exitCode: null,
        status: skipE2E && e2eOnly ? "skipped-by-option" : "not-run",
        counts: null,
        errorCode: null,
      });
    }
  }

  let engineDecision = null;
  let engineProbeValid = false;
  if (Array.isArray(run.engines) && Number.isInteger(run.engineProbeExitCode)) {
    try {
      engineDecision = deriveEngineDecision(run.engineProbeExitCode, run.engines);
      engineProbeValid = true;
    } catch {
      engineDecision = null;
    }
  }
  const engineStage = byName.get("engine-probe");
  const engineStageMatchesDecision = engineProbeValid
    && engineStage?.exitCode === run.engineProbeExitCode
    && ((run.engineProbeExitCode === 0 && engineStage.status === "passed")
      || (run.engineProbeExitCode === 2 && engineStage.status === "accepted-optional"));
  let playwright = null;
  if (!skipE2E && options.playwrightReport && options.allowlist) {
    try {
      playwright = validatePlaywrightEvidence(
        options.playwrightReport,
        options.allowlist,
        engineDecision?.includeFirefox,
      );
    } catch {
      playwright = { valid: false, errorCode: "PLAYWRIGHT_EVIDENCE_INVALID" };
    }
  }

  const testStages = actualStages.filter((stage) => stage.name.startsWith("test-"));
  const countsAreComplete = (stage) => stage?.counts
    && stage.counts.suites.total > 0
    && stage.counts.files.total > 0
    && stage.counts.tests.total > 0
    && stage.counts.suites.failed === 0
    && stage.counts.suites.skipped === 0
    && stage.counts.files.failed === 0
    && stage.counts.files.skipped === 0
    && stage.counts.tests.failed === 0
    && stage.counts.tests.skipped === 0;
  const liveTestCountsAreComplete = testStages.length === 5
    && testStages.every(countsAreComplete)
    && countsAreComplete(byName.get("verification-contract"));
  const executedStagesPassed = actualStages.every((stage) => stage.status === "passed"
    || stage.status === "accepted-optional"
    || (skipE2E && stage.status === "skipped-by-option"));
  const environment = {
    node: nodeVersionOrNull(run.nodeVersion),
    finalizerNode: process.version,
    pnpm: semanticVersionOrNull(run.pnpmVersion),
    postgresqlBinary: semanticVersionOrNull(run.postgresqlBinaryVersion),
    pnpmLockSha256: sha256(options.lockfile),
  };
  const environmentValid = /^v24\.\d+\.\d+$/u.test(environment.node ?? "")
    && environment.finalizerNode === environment.node
    && environment.pnpm === "11.19.0"
    && /^18(?:\.|$)/u.test(environment.postgresqlBinary ?? "")
    && /^[a-f0-9]{64}$/u.test(environment.pnpmLockSha256);
  environment.valid = environmentValid;
  let currentSourceFingerprint = null;
  try {
    currentSourceFingerprint = collectWorkspaceSourceFingerprint(options.workspaceRoot);
  } catch {
    currentSourceFingerprint = null;
  }
  const sourceStart = safeSourceFingerprint(run.sourceIntegrity?.start);
  const sourceEnd = safeSourceFingerprint(run.sourceIntegrity?.end);
  const sourceCurrent = safeSourceFingerprint(currentSourceFingerprint);
  const sourceIntegrityValid = sourceStart !== null
    && sourceEnd !== null
    && sourceCurrent !== null
    && sourceStart.fileCount === sourceEnd.fileCount
    && sourceStart.fileCount === sourceCurrent.fileCount
    && sourceStart.sha256 === sourceEnd.sha256
    && sourceStart.sha256 === sourceCurrent.sha256;
  const sourceIntegrity = {
    start: sourceStart,
    end: sourceEnd,
    publication: sourceCurrent,
    valid: sourceIntegrityValid,
  };
  const finalizerHealth = {
    api: options.terminalHealth?.api === true,
    web: options.terminalHealth?.web === true,
    worker: options.terminalHealth?.worker === true,
    valid: options.terminalHealth?.valid === true,
  };
  const serviceLifecycle = {
    freshServicesStarted: run.serviceLifecycle?.freshServicesStarted === true,
    terminalHealthPassed: byName.get("terminal-health")?.status === "passed"
      && run.serviceLifecycle?.terminalHealthPassed === true,
    failureCleanupAttempted: run.serviceLifecycle?.failureCleanupAttempted === true,
    failureCleanupSucceeded: run.serviceLifecycle?.failureCleanupSucceeded === true
      ? true
      : (run.serviceLifecycle?.failureCleanupSucceeded === false ? false : null),
    successPolicy: "leave-api-web-worker-running-after-publication-health",
    failurePolicy: "stop-api-web-worker-and-keep-postgresql-running",
    publicationHealth: finalizerHealth,
  };
  const serviceLifecycleValid = serviceLifecycle.freshServicesStarted
    && serviceLifecycle.terminalHealthPassed
    && !serviceLifecycle.failureCleanupAttempted
    && finalizerHealth.api
    && finalizerHealth.web
    && finalizerHealth.worker
    && finalizerHealth.valid;
  let artifactEvidence;
  try {
    artifactEvidence = collectArtifactEvidence(
      options.artifactDirectory,
      run.startedAtUtc,
      run.completedAtUtc,
      byName.get("pdf-render")?.status === "passed",
    );
  } catch {
    artifactEvidence = {
      valid: false,
      popplerRenderPass: false,
      requiredFileCount: requiredArtifactFiles.length,
      currentRunFileCount: 0,
      files: [],
      errorCode: "ARTIFACT_EVIDENCE_INVALID",
    };
  }
  let localState;
  try {
    localState = sanitizeLocalStateEvidence(run.localState, byName.get("local-state-verification"));
  } catch {
    localState = { valid: false, errorCode: "LOCAL_STATE_EVIDENCE_INVALID" };
  }
  const closureEligible = !skipE2E
    && run.failed === false
    && run.liveIntegrationRequired === true
    && run.privilegedLiveRequired === true
    && stageOrderComplete
    && executedStagesPassed
    && liveTestCountsAreComplete
    && environmentValid
    && sourceIntegrityValid
    && serviceLifecycleValid
    && engineProbeValid
    && engineStageMatchesDecision
    && playwright?.valid === true
    && artifactEvidence.valid === true
    && localState.valid === true;
  const mandatoryFailure = run.failed === true
    || actualStages.some((stage) => stage.status === "failed")
    || (!skipE2E && !closureEligible);
  const result = closureEligible ? "passed" : (mandatoryFailure ? "failed" : "incomplete");
  actualStages.push({
    name: "evidence-finalize",
    command: stageCommands["evidence-finalize"],
    startedAtUtc: run.completedAtUtc,
    completedAtUtc: new Date().toISOString(),
    exitCode: 0,
    status: "passed",
    counts: null,
    errorCode: null,
  });
  const evidence = {
    schemaVersion: 1,
    command: skipE2E ? "pnpm verify:local -SkipE2E" : "pnpm verify:local",
    startedAtUtc: exactString(run.startedAtUtc, "run.startedAtUtc"),
    completedAtUtc: exactString(run.completedAtUtc, "run.completedAtUtc"),
    result,
    overallPass: closureEligible,
    closureEligible,
    environment,
    guarantees: {
      liveIntegrationRequired: run.liveIntegrationRequired === true,
      privilegedLiveRequired: run.privilegedLiveRequired === true,
      stdoutPersisted: false,
      stderrPersisted: false,
      repositoryRelativeTestPathsOnly: true,
      zeroNonE2ESkipsRequired: true,
    },
    stages: actualStages,
    testSuites: testStages.map((stage) => ({ name: stage.name.slice(5), ...stage.counts })),
    engines: !Array.isArray(run.engines) ? null : {
      probeExitCode: run.engineProbeExitCode,
      valid: engineProbeValid,
      stageMatchesDecision: engineStageMatchesDecision,
      includeFirefox: engineDecision?.includeFirefox ?? null,
      firefoxExclusionReason: engineDecision?.exclusionReason ?? null,
      results: run.engines.map((engine) => ({
        name: engine.name,
        required: engine.required === true,
        available: engine.available === true,
        elapsedMs: Number.isFinite(Number(engine.elapsedMs)) && Number(engine.elapsedMs) >= 0 ? Number(engine.elapsedMs) : null,
        code: typeof engine.code === "string" && /^[A-Za-z0-9_-]{1,64}$/u.test(engine.code) ? engine.code : null,
      })),
    },
    e2e: playwright,
    artifacts: artifactEvidence,
    localState,
    sourceIntegrity,
    serviceLifecycle: { ...serviceLifecycle, validForClosure: serviceLifecycleValid },
  };
  assertSanitized(evidence);
  return evidence;
}

function option(args, name, required = true) {
  const index = args.indexOf(name);
  if (index < 0 || index === args.length - 1) {
    if (required) throw new Error(`Missing ${name}`);
    return null;
  }
  return args[index + 1];
}

function exactBooleanOption(args, name) {
  const value = option(args, name);
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

async function main(args) {
  const command = args[0];
  if (command === "fingerprint-sources") {
    process.stdout.write(`${JSON.stringify(collectWorkspaceSourceFingerprint(option(args, "--workspace")))}\n`);
    return;
  }
  if (command === "initialize") {
    const mode = option(args, "--mode");
    if (mode !== "complete" && mode !== "skip-e2e") throw new Error("Unsupported verification mode");
    const evidence = buildInProgressEvidence({
      startedAtUtc: option(args, "--started-at"),
      skipE2E: mode === "skip-e2e",
      lockfile: option(args, "--lockfile"),
    });
    writeJsonAtomic(option(args, "--output"), evidence);
    process.stdout.write(`${JSON.stringify({ result: evidence.result, closureEligible: false })}\n`);
    return;
  }
  if (command === "validate-playwright") {
    const validation = validatePlaywrightEvidence(
      readJson(option(args, "--report")),
      readJson(option(args, "--allowlist")),
      exactBooleanOption(args, "--include-firefox"),
    );
    process.stdout.write(`${JSON.stringify(validation)}\n`);
    if (!validation.valid) process.exitCode = 1;
    return;
  }
  if (command === "finalize") {
    const output = option(args, "--output");
    writeJsonAtomic(output, {
      schemaVersion: 1,
      command: "verification-finalizer",
      startedAtUtc: null,
      completedAtUtc: new Date().toISOString(),
      result: "failed",
      overallPass: false,
      closureEligible: false,
      errorCode: "EVIDENCE_FINALIZATION_INCOMPLETE",
    });
    const input = readJson(option(args, "--input"));
    let terminalHealth = null;
    if (input.failed === false) {
      try {
        const apiResponse = await fetch("http://127.0.0.1:4000/healthz", { signal: AbortSignal.timeout(5_000) });
        const apiBody = apiResponse.ok ? await apiResponse.json() : null;
        const webResponse = await fetch("http://127.0.0.1:3000/healthz", {
          redirect: "error",
          signal: AbortSignal.timeout(5_000),
        });
        const webBody = webResponse.ok ? await webResponse.json() : null;
        terminalHealth = {
          api: apiResponse.ok && apiBody?.status === "ok",
          worker: apiBody?.worker?.healthy === true,
          web: webResponse.ok && webBody?.status === "ok",
        };
        terminalHealth.valid = terminalHealth.api && terminalHealth.worker && terminalHealth.web;
      } catch {
        terminalHealth = { api: false, worker: false, web: false, valid: false };
      }
    }
    const playwrightFile = option(args, "--playwright", false);
    const allowlistFile = option(args, "--allowlist", false);
    const evidence = buildFinalEvidence(input, {
      lockfile: option(args, "--lockfile"),
      playwrightReport: playwrightFile && fs.existsSync(playwrightFile) ? readJson(playwrightFile) : null,
      allowlist: allowlistFile && fs.existsSync(allowlistFile) ? readJson(allowlistFile) : null,
      artifactDirectory: option(args, "--artifact-directory"),
      workspaceRoot: option(args, "--workspace"),
      terminalHealth,
    });
    writeJsonAtomic(output, evidence);
    process.stdout.write(`${JSON.stringify({ result: evidence.result, closureEligible: evidence.closureEligible })}\n`);
    if (!input.skipE2E && !evidence.closureEligible) process.exitCode = 1;
    return;
  }
  throw new Error("Usage: verify-local-evidence.mjs <initialize|fingerprint-sources|validate-playwright|finalize> [options]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`Verification evidence error: ${error instanceof Error ? error.message : "unknown failure"}\n`);
    process.exitCode = 1;
  });
}

export { assertSanitized, writeJsonAtomic };
