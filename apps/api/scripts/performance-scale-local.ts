import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { arch, cpus, platform, release, totalmem } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { versions } from "node:process";
import { fileURLToPath } from "node:url";
import {
  DatabaseRuntime,
  MemorySecretProvider,
  runMigrations,
  sealAesGcmJson,
  tenantProvisionRequestHash,
  TenantProvisioner,
  type EncryptedEnvelope,
} from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { Pool, type PoolConfig } from "pg";
import { parseApiConfig, type ApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";
import {
  LOCAL_PERFORMANCE_POSTGRES_HOST,
  LOCAL_PERFORMANCE_POSTGRES_PORT,
  assertExactLocalPostgresUrl,
  assertSameExactLocalPostgresCluster,
  exactLocalPostgresPoolConfig,
} from "./local-performance-database-guards.js";
import {
  planPerformanceCleanup,
  planScaleControlCleanup,
  type PerformanceCleanupJob,
  type PerformanceCleanupPlan,
  type PerformanceCleanupRoute,
  type ScaleControlCleanupDatabase,
  type ScaleControlCleanupMarker,
  type ScaleControlCleanupPlan,
  type ScaleControlCleanupRole,
} from "./local-performance-cleanup-guards.js";
import { writeJsonEvidenceAtomic } from "./local-performance-evidence.js";
import {
  completeProtectedFingerprintSet,
  fingerprintProtectedDatabases,
  globalInventorySetsEqual,
  inspectGlobalEphemeralResources,
  protectedFingerprintSetsEqual,
  type DatabaseFingerprint,
  type EphemeralResourceInventory,
  type ProtectedDatabaseFingerprints,
} from "./local-performance-protected-state.js";

const CONTROL_DATABASE = "nombramientos_control";
const TEMPORARY_CONTROL_PREFIX = "nom_c_";
const ORIGIN = "http://127.0.0.1:3000";
const USER_AGENT = "nombramientos-ac37-scale-local";
const TENANT_COUNT = 10;
const PARTICIPANTS_PER_TENANT = 50;
const MEMBERS_PER_TENANT = 10_000;
const TOTAL_PARTICIPANTS = TENANT_COUNT * PARTICIPANTS_PER_TENANT;
const MEMBER_INSERT_BATCH = 500;
const ACKNOWLEDGEMENT_P95_BUDGET_MS = 1_500;
const SSE_PROPAGATION_P95_BUDGET_MS = 2_000;
const REPRESENTATIVE_READ_P95_BUDGET_MS = 2_000;
const REQUEST_TIMEOUT_MS = 20_000;
const SSE_COMPLETION_TIMEOUT_MS = 8_000;
const workspaceRoot = resolveWorkspaceRoot();
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const artifactFile = path.join(workspaceRoot, "artifacts", "performance-scale-local.json");
let executionStage = "configuration";

interface TestSession {
  readonly id: string;
  readonly identityId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly tenantIndex: number;
  readonly tenantId: string;
}

interface RoundFixture {
  readonly id: string;
  readonly cycleId: string;
  readonly candidateId: string;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
}

interface TenantFixture {
  readonly index: number;
  readonly label: string;
  readonly tenantId: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly secretReference: string;
  readonly provisioningKey: string;
  readonly provisioningRequestHash: string;
  readonly sessions: readonly TestSession[];
  readonly tenantKey: Buffer;
  readonly tenantKeyId: string;
  pool?: Pool;
  baseUrl?: string;
  round?: RoundFixture;
  memberSeedMs?: number;
  namesVerifiedUnused?: boolean;
  provisioningAttempted?: boolean;
  cleanupAuthorized?: boolean;
}

interface ScaleState {
  readonly control: Pool;
  readonly cluster: Pool;
  readonly secrets: MemorySecretProvider;
  readonly tenants: readonly TenantFixture[];
  readonly apps: FastifyInstance[];
  readonly databaseAdminUrl: string;
  readonly runId: string;
  readonly controlDatabaseName: string;
  readonly controlRuntimeRole: string;
  readonly controlRuntimePassword: string;
  controlNamesVerifiedUnused?: boolean;
  controlDatabaseCreationAttempted?: boolean;
  controlCreatedByRun?: boolean;
  controlCleanupAuthorized?: boolean;
  controlRuntimeRoleCreationAttempted?: boolean;
  controlRuntimeRoleCreatedByRun?: boolean;
  controlRuntimeRoleCleanupAuthorized?: boolean;
  protectedDatabaseFingerprints?: ProtectedDatabaseFingerprints;
  ephemeralResourcesBefore?: EphemeralResourceInventory;
  provisioner?: TenantProvisioner;
}

interface SubmissionPayload {
  readonly kind: "proposal";
  readonly expectedVersion: number;
  readonly envelope: EncryptedEnvelope;
  readonly contentHash: string;
}

interface RequestObservation {
  readonly tenantIndex: number;
  readonly latencyMs: number;
  readonly status: number;
  readonly errorCode: string | null;
  readonly valid: boolean;
  readonly receiptId: string | null;
}

interface LatencySummary {
  readonly count: number;
  readonly wallMs: number;
  readonly throughputRequestsPerSecond: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
}

interface WorkloadResult {
  readonly metrics: LatencySummary;
  readonly statusCounts: Readonly<Record<string, number>>;
  readonly errorCodeCounts: Readonly<Record<string, number>>;
  readonly unexpectedFailures: number;
  readonly responseValidationFailures: number;
}

interface IntegrityRow {
  readonly members: number;
  readonly electors: number;
  readonly submissions: number;
  readonly distinct_submission_electors: number;
  readonly distinct_submission_hashes: number;
  readonly receipts: number;
  readonly distinct_receipt_submissions: number;
  readonly distinct_receipt_electors: number;
  readonly returned_receipts: number;
  readonly idempotency_records: number;
  readonly audit_events: number;
  readonly outbox_events: number;
}

interface TenantReadSnapshot {
  readonly members: number;
  readonly cycles: number;
  readonly rounds: number;
  readonly round_version: number;
  readonly submissions: number;
  readonly receipts: number;
  readonly idempotency_records: number;
  readonly audit_events: number;
  readonly outbox_events: number;
}

interface CleanupResult {
  readonly controlRows: number;
  readonly databases: number;
  readonly roles: number;
  readonly operationalControlBefore: DatabaseFingerprint | null;
  readonly operationalControlAfter: DatabaseFingerprint | null;
  readonly operationalControlUnchanged: boolean;
  readonly protectedDatabasesBefore: ProtectedDatabaseFingerprints | null;
  readonly protectedDatabasesAfter: ProtectedDatabaseFingerprints | null;
  readonly protectedDatabasesUnchanged: boolean;
  readonly ephemeralResourcesBefore: EphemeralResourceInventory | null;
  readonly ephemeralResourcesAfter: EphemeralResourceInventory | null;
  readonly globalInventoryUnchanged: boolean;
  readonly pass: boolean;
}

interface SseProbe {
  readonly tenantIndex: number;
  readonly controller: AbortController;
  readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  readonly arrivals: Map<number, number>;
  readonly ready: Promise<void>;
  readonly complete: Promise<void>;
  readonly pump: Promise<void>;
}

interface SseOccurrenceRow {
  readonly sequence: string;
  readonly occurred_ms: number;
}

interface PerformanceReport {
  readonly schemaVersion: 3;
  readonly acceptanceCriterion: "AC-37";
  readonly startedAtUtc: string;
  completedAtUtc: string;
  status: "in-progress" | "passed" | "failed";
  inProgress: boolean;
  environment: Readonly<Record<string, unknown>>;
  readonly dataset: Readonly<Record<string, unknown>>;
  readonly thresholds: Readonly<Record<string, number>>;
  setup?: Readonly<Record<string, unknown>>;
  submissions?: Readonly<Record<string, unknown>>;
  propagation?: Readonly<Record<string, unknown>>;
  reads?: Readonly<Record<string, unknown>>;
  isolation?: Readonly<Record<string, unknown>>;
  cleanup?: CleanupResult;
  overallPass: boolean;
  deviations: string[];
}

async function main(): Promise<void> {
  if (process.argv.includes("--self-check")) {
    selfCheck();
    return;
  }
  const startedAt = new Date();
  writeReport({
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
    startedAtUtc: startedAt.toISOString(),
    completedAtUtc: startedAt.toISOString(),
    status: "in-progress",
    inProgress: true,
    environment: { state: "pending" },
    dataset: scaleDataset(),
    thresholds: scaleThresholds(),
    overallPass: false,
    deviations: ["run-in-progress"],
  });
  executionStage = "configuration-admin-url";
  const databaseAdminUrl = discoverLocalAdminUrl();
  executionStage = "configuration-api-parse";
  const config = parseApiConfig();
  executionStage = "configuration-control-url";
  assertNonDefaultLoopbackUrl(config.controlDatabaseUrl, CONTROL_DATABASE);
  assertSameWorkspaceCluster(databaseAdminUrl, config.controlDatabaseUrl);
  const state = createInitialState(databaseAdminUrl);
  const report: PerformanceReport = {
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
    startedAtUtc: startedAt.toISOString(),
    completedAtUtc: startedAt.toISOString(),
    status: "in-progress",
    inProgress: true,
    environment: environmentMetadata("pending", "pending"),
    dataset: scaleDataset(),
    thresholds: scaleThresholds(),
    overallPass: false,
    deviations: [
      "local-loopback-multi-listener-topology-differs-from-a-production-proxy-and-single-public-endpoint",
      "browser-side-initial-download-decryption-index-build-and-sub-300ms-local-search-not-measured-by-this-api-runner",
      "tls-wan-loss-horizontal-scaling-and-production-observability-not-measured-locally",
    ],
  };

  let executionFailure = false;
  const probes: SseProbe[] = [];
  try {
    executionStage = "protected-database-snapshots-before";
    state.protectedDatabaseFingerprints = await fingerprintProtectedDatabases(databaseAdminUrl);
    executionStage = "global-ephemeral-resource-inventory-before";
    state.ephemeralResourcesBefore = await inspectGlobalEphemeralResources(databaseAdminUrl);
    if (!state.ephemeralResourcesBefore.pass) throw new Error("Pre-existing ephemeral PostgreSQL resources block AC-37 scale execution");
    executionStage = "isolated-control-bootstrap";
    await initializeIsolatedControl(state);
    executionStage = "fixture-provisioning";
    const setupStarted = performance.now();
    await provisionAndSeed(databaseAdminUrl, state);
    const setupWallMs = performance.now() - setupStarted;
    executionStage = "api-listeners";
    await startApis(state, config);
    const postgresVersion = await readPostgresVersion(state.cluster);
    report.environment = environmentMetadata(postgresVersion, state.apps[0]?.version ?? "unknown");
    report.setup = {
      totalWallMs: roundMetric(setupWallMs),
      membersInserted: TENANT_COUNT * MEMBERS_PER_TENANT,
      memberRowsPerSecond: roundMetric((TENANT_COUNT * MEMBERS_PER_TENANT) / (setupWallMs / 1_000)),
      perTenant: state.tenants.map((tenant) => ({
        tenant: tenant.label,
        members: MEMBERS_PER_TENANT,
        memberSeedMs: roundMetric(tenant.memberSeedMs ?? 0),
      })),
      controlRuntimePrivilegeBoundary: {
        credentialClass: "run-scoped-ephemeral-control-runtime-role",
        administratorCredentialUsedByApi: false,
        login: true,
        superuser: false,
        createDatabase: false,
        createRole: false,
        bypassRls: false,
        inheritedMemberships: false,
        databasePrivileges: ["CONNECT"],
        schemaPrivileges: ["USAGE"],
        tablePrivileges: [
          "SELECT:tenants",
          "SELECT:platform_identities",
          "SELECT:tenant_memberships",
          "SELECT:auth_sessions",
          "UPDATE(last_seen_at):auth_sessions",
        ],
      },
      pass: state.tenants.every((tenant) => tenant.pool && tenant.round && tenant.baseUrl),
    };

    executionStage = "database-isolation";
    const databaseIsolation = await verifyDatabaseIsolation(databaseAdminUrl, state.tenants, state.secrets);

    executionStage = "sse-open";
    for (const tenant of state.tenants) probes.push(await openSseProbe(tenant));

    executionStage = "submission-burst";
    const propagationWindowStartedAt = performance.now();
    const submissionRun = await runSubmissionBurst(state.tenants);
    executionStage = "sse-completion";
    const propagationCompleted = await waitForSseProbes(probes);
    const propagationWallMs = performance.now() - propagationWindowStartedAt;
    executionStage = "submission-integrity";
    const integrity = await inspectAllIntegrity(state.tenants, submissionRun.observations);
    const submissionWorkload = workloadResult(submissionRun.observations, submissionRun.wallMs, 201);
    const acknowledgementBudgetPass = submissionWorkload.metrics.p95Ms < ACKNOWLEDGEMENT_P95_BUDGET_MS;
    const integrityPass = integrity.every((item) => exactIntegrity(item.row));
    const perTenantSubmission = state.tenants.map((tenant) => {
      const observations = submissionRun.observations.filter((item) => item.tenantIndex === tenant.index);
      const tenantIntegrity = integrity.find((item) => item.tenantIndex === tenant.index)?.row;
      return {
        tenant: tenant.label,
        ...workloadResult(observations, submissionRun.wallMs, 201),
        integrity: tenantIntegrity ? publicIntegrity(tenantIntegrity) : null,
      };
    });
    const submissionPass = acknowledgementBudgetPass
      && integrityPass
      && submissionWorkload.unexpectedFailures === 0
      && submissionWorkload.responseValidationFailures === 0;
    report.submissions = {
      transport: "real HTTP over loopback TCP",
      concurrency: TOTAL_PARTICIPANTS,
      uniqueRequests: TOTAL_PARTICIPANTS,
      ...submissionWorkload,
      perTenant: perTenantSubmission,
      aggregateIntegrity: aggregateIntegrity(integrity.map((item) => item.row)),
      acknowledgementBudgetPass,
      pass: submissionPass,
    };
    if (!acknowledgementBudgetPass) report.deviations.push("acknowledgement-p95-over-1500ms");
    if (!integrityPass) report.deviations.push("per-tenant-submission-integrity-mismatch");
    if (submissionWorkload.unexpectedFailures !== 0) report.deviations.push("unexpected-submission-failures");
    if (submissionWorkload.responseValidationFailures !== 0) report.deviations.push("invalid-submission-responses");

    executionStage = "sse-analysis";
    const propagation = await inspectSsePropagation(state.tenants, probes, propagationWallMs);
    const propagationBudgetPass = propagation.metrics.p95Ms < SSE_PROPAGATION_P95_BUDGET_MS;
    const propagationPass = propagationCompleted
      && propagation.integrityPass
      && propagationBudgetPass
      && propagation.metrics.count === TOTAL_PARTICIPANTS;
    report.propagation = {
      transport: "authenticated SSE over loopback TCP",
      streams: TENANT_COUNT,
      expectedEvents: TOTAL_PARTICIPANTS,
      timingBasis: "outbox occurred_at to client frame receipt; conservatively includes remaining transaction commit time",
      throughputWindow: "wall-clock from submission burst dispatch through SSE completion/timeout",
      measurementWallMs: roundMetric(propagationWallMs),
      metrics: propagation.metrics,
      perTenant: propagation.perTenant,
      allStreamsCompleted: propagationCompleted,
      integrityPass: propagation.integrityPass,
      budgetPass: propagationBudgetPass,
      pass: propagationPass,
    };
    if (!propagationCompleted) report.deviations.push("sse-streams-did-not-observe-all-participation-events-before-timeout");
    if (!propagation.integrityPass) report.deviations.push("sse-event-sequence-or-round-integrity-mismatch");
    if (!propagationBudgetPass) report.deviations.push("sse-propagation-p95-over-2000ms");

    executionStage = "read-snapshots-before";
    const beforeReads = await readAllSnapshots(state.tenants);
    executionStage = "read-burst";
    const readRun = await runReadBurst(state.tenants);
    executionStage = "read-snapshots-after";
    const afterReads = await readAllSnapshots(state.tenants);
    const stateUnchanged = JSON.stringify(beforeReads) === JSON.stringify(afterReads);
    const dashboard = workloadResult(readRun.dashboard, readRun.wallMs, 200);
    const members = workloadResult(readRun.members, readRun.wallMs, 200);
    const combined = workloadResult([...readRun.dashboard, ...readRun.members], readRun.wallMs, 200);
    const readBudgetPass = combined.metrics.p95Ms < REPRESENTATIVE_READ_P95_BUDGET_MS;
    const readPass = stateUnchanged
      && readBudgetPass
      && combined.unexpectedFailures === 0
      && combined.responseValidationFailures === 0;
    report.reads = {
      transport: "real HTTP GET over loopback TCP",
      concurrentParticipantSessions: TOTAL_PARTICIPANTS,
      requestsPerParticipant: 2,
      totalRequests: TOTAL_PARTICIPANTS * 2,
      dashboard,
      memberListAgainstTenThousandRows: members,
      combined,
      tenantBusinessStateUnchanged: stateUnchanged,
      budgetPass: readBudgetPass,
      pass: readPass,
    };
    if (!readBudgetPass) report.deviations.push("representative-read-p95-over-2000ms");
    if (!stateUnchanged) report.deviations.push("read-scenario-mutated-tenant-business-state");
    if (combined.unexpectedFailures !== 0) report.deviations.push("unexpected-read-failures");
    if (combined.responseValidationFailures !== 0) report.deviations.push("invalid-read-responses");

    executionStage = "http-isolation";
    const httpIsolation = await verifyHttpIsolation(state.tenants);
    const isolationPass = databaseIsolation["pass"] === true && httpIsolation["pass"] === true;
    report.isolation = {
      databaseCredentialRing: databaseIsolation,
      httpTenantIdAndForeignRoundRing: httpIsolation,
      pass: isolationPass,
    };
    if (!isolationPass) report.deviations.push("tenant-isolation-probe-failed");
  } catch {
    executionFailure = true;
    report.deviations.push(`workload-execution-failed-at-${sanitizeStage(executionStage)}`);
  } finally {
    await Promise.all(probes.map((probe) => closeSseProbe(probe)));
    try {
      executionStage = "cleanup";
      report.cleanup = await cleanupScaleFixture(state);
    } catch {
      executionFailure = true;
      report.cleanup = {
        controlRows: -1,
        databases: -1,
        roles: -1,
        operationalControlBefore: state.protectedDatabaseFingerprints?.control ?? null,
        operationalControlAfter: null,
        operationalControlUnchanged: false,
        protectedDatabasesBefore: state.protectedDatabaseFingerprints ?? null,
        protectedDatabasesAfter: null,
        protectedDatabasesUnchanged: false,
        ephemeralResourcesBefore: state.ephemeralResourcesBefore ?? null,
        ephemeralResourcesAfter: null,
        globalInventoryUnchanged: false,
        pass: false,
      };
      report.deviations.push("ephemeral-cleanup-failed");
    }
  }

  report.overallPass = !executionFailure
    && report.setup?.["pass"] === true
    && report.submissions?.["pass"] === true
    && report.propagation?.["pass"] === true
    && report.reads?.["pass"] === true
    && report.isolation?.["pass"] === true
    && report.cleanup?.pass === true;
  report.completedAtUtc = new Date().toISOString();
  report.status = report.overallPass ? "passed" : "failed";
  report.inProgress = false;
  executionStage = "artifact-write";
  writeReport(report);
  printSummary(report);
  if (!report.overallPass) process.exitCode = 1;
}

function createInitialState(databaseAdminUrl: string): ScaleState {
  const runId = randomUUID();
  const controlDatabaseName = expectedControlDatabaseName(runId);
  const controlRuntimeRole = expectedControlRuntimeRole(runId);
  const control = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", controlDatabaseName),
    application_name: "nombramientos-ac37-scale-ephemeral-control",
    max: 4,
  });
  const cluster = new Pool({
    ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-ac37-scale-cluster",
    max: 2,
  });
  const tenants = Array.from({ length: TENANT_COUNT }, (_, index) => temporaryTenant(index));
  return {
    control,
    cluster,
    secrets: new MemorySecretProvider(),
    tenants,
    apps: [],
    databaseAdminUrl,
    runId,
    controlDatabaseName,
    controlRuntimeRole,
    controlRuntimePassword: randomBytes(32).toString("base64url"),
  };
}

function expectedControlDatabaseName(runId: string): string {
  return `${TEMPORARY_CONTROL_PREFIX}${runId.replaceAll("-", "").toLowerCase()}`;
}

function expectedControlRuntimeRole(runId: string): string {
  return `nom_cr_${runId.replaceAll("-", "").toLowerCase()}`;
}

function expectedControlRuntimeRoleMarker(runId: string): string {
  return `nombramientos-ac37-scale-control-runtime:${runId.toLowerCase()}`;
}

async function initializeIsolatedControl(state: ScaleState): Promise<void> {
  assertGeneratedControlIdentity(state.runId, state.controlDatabaseName);
  assertGeneratedControlRuntimeIdentity(state.runId, state.controlRuntimeRole);
  const existing = await state.cluster.query<{ databases: number; roles: number }>(
    `SELECT
       (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
       (SELECT count(*)::int FROM pg_roles WHERE rolname=$2) AS roles`,
    [state.controlDatabaseName, state.controlRuntimeRole],
  );
  if (existing.rows[0]?.databases !== 0 || existing.rows[0]?.roles !== 0) {
    throw new Error("AC-37 scale temporary control database or runtime role name is already in use");
  }
  state.controlNamesVerifiedUnused = true;

  state.controlDatabaseCreationAttempted = true;
  await executeFormatted(
    state.cluster,
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
    [state.controlDatabaseName],
  );
  state.controlCreatedByRun = true;
  await state.control.query(
    `CREATE TABLE ac37_scale_run_metadata (
       singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
       run_id uuid NOT NULL UNIQUE,
       control_database text NOT NULL UNIQUE,
       control_runtime_role text NOT NULL UNIQUE,
       created_at timestamptz NOT NULL DEFAULT clock_timestamp()
     )`,
  );
  await state.control.query(
    "INSERT INTO ac37_scale_run_metadata(singleton,run_id,control_database,control_runtime_role) VALUES (true,$1,$2,$3)",
    [state.runId, state.controlDatabaseName, state.controlRuntimeRole],
  );
  await assertIsolatedControlTarget(state);
  // Destructive cleanup is authorized only after the database carries the exact
  // run marker written through the connection this process just created.
  state.controlCleanupAuthorized = true;
  state.controlRuntimeRoleCreationAttempted = true;
  await executeFormatted(
    state.cluster,
    `SELECT format(
       'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 30 PASSWORD %L',
       $1::text,$2::text
     ) AS sql`,
    [state.controlRuntimeRole, state.controlRuntimePassword],
  );
  state.controlRuntimeRoleCreatedByRun = true;
  await executeFormatted(
    state.cluster,
    "SELECT format('COMMENT ON ROLE %I IS %L',$1::text,$2::text) AS sql",
    [state.controlRuntimeRole, expectedControlRuntimeRoleMarker(state.runId)],
  );
  await assertControlRuntimeRoleTarget(state);
  state.controlRuntimeRoleCleanupAuthorized = true;
  await executeFormatted(
    state.cluster,
    "SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC',$1::text) AS sql",
    [state.controlDatabaseName],
  );
  await executeFormatted(
    state.cluster,
    "SELECT format('GRANT CONNECT ON DATABASE %I TO %I',$1::text,$2::text) AS sql",
    [state.controlDatabaseName, state.controlRuntimeRole],
  );
  await runMigrations(state.control, {
    scope: "control",
    directory: path.join(migrationsRoot, "control"),
  });
  const target = await state.control.query<{ database_name: string; migrations: number }>(
    `SELECT current_database() AS database_name,
            (SELECT count(*)::int FROM schema_migrations) AS migrations`,
  );
  const row = target.rows[0];
  if (!row || row.database_name !== state.controlDatabaseName || row.migrations < 1) {
    throw new Error("AC-37 scale isolated control database bootstrap verification failed");
  }
  await applyScaleControlRuntimeGrants(state);
  await assertScaleControlRuntimeGrants(state);
}

async function applyScaleControlRuntimeGrants(state: ScaleState): Promise<void> {
  assertGeneratedControlRuntimeTarget(state);
  await state.control.query("REVOKE ALL ON SCHEMA public FROM PUBLIC");
  await state.control.query("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC");
  for (const statement of [
    "REVOKE ALL ON SCHEMA public FROM %I",
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I",
    "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I",
    "REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM %I",
    "GRANT USAGE ON SCHEMA public TO %I",
  ]) {
    await executeFormatted(state.control, `SELECT format('${statement}',$1::text) AS sql`, [state.controlRuntimeRole]);
  }
  await executeFormatted(
    state.control,
    `SELECT format(
       'GRANT SELECT ON TABLE tenants,platform_identities,tenant_memberships,auth_sessions TO %I',
       $1::text
     ) AS sql`,
    [state.controlRuntimeRole],
  );
  await executeFormatted(
    state.control,
    "SELECT format('GRANT UPDATE(last_seen_at) ON TABLE auth_sessions TO %I',$1::text) AS sql",
    [state.controlRuntimeRole],
  );
}

async function assertScaleControlRuntimeGrants(state: ScaleState): Promise<void> {
  assertGeneratedControlRuntimeTarget(state);
  const result = await state.control.query<{
    connect: boolean;
    schema_usage: boolean;
    tenants_select: boolean;
    identities_select: boolean;
    memberships_select: boolean;
    sessions_select: boolean;
    last_seen_update: boolean;
    sessions_table_update: boolean;
    provisioning_select: boolean;
    tenants_insert: boolean;
    tenants_update: boolean;
    tenants_delete: boolean;
  }>(
    `SELECT
       has_database_privilege($1,current_database(),'CONNECT') AS connect,
       has_schema_privilege($1,'public','USAGE') AS schema_usage,
       has_table_privilege($1,'public.tenants','SELECT') AS tenants_select,
       has_table_privilege($1,'public.platform_identities','SELECT') AS identities_select,
       has_table_privilege($1,'public.tenant_memberships','SELECT') AS memberships_select,
       has_table_privilege($1,'public.auth_sessions','SELECT') AS sessions_select,
       has_column_privilege($1,'public.auth_sessions','last_seen_at','UPDATE') AS last_seen_update,
       has_table_privilege($1,'public.auth_sessions','UPDATE') AS sessions_table_update,
       has_table_privilege($1,'public.provisioning_jobs','SELECT') AS provisioning_select,
       has_table_privilege($1,'public.tenants','INSERT') AS tenants_insert,
       has_table_privilege($1,'public.tenants','UPDATE') AS tenants_update,
       has_table_privilege($1,'public.tenants','DELETE') AS tenants_delete`,
    [state.controlRuntimeRole],
  );
  const row = result.rows[0];
  if (!row
    || !row.connect
    || !row.schema_usage
    || !row.tenants_select
    || !row.identities_select
    || !row.memberships_select
    || !row.sessions_select
    || !row.last_seen_update
    || row.sessions_table_update
    || row.provisioning_select
    || row.tenants_insert
    || row.tenants_update
    || row.tenants_delete) {
    throw new Error("AC-37 scale control runtime privilege boundary is invalid");
  }
}

function scaleControlRuntimePoolConfig(state: ScaleState): PoolConfig {
  assertGeneratedControlRuntimeTarget(state);
  if (state.controlRuntimePassword.length < 32 || /[\u0000-\u001f\u007f]/u.test(state.controlRuntimePassword)) {
    throw new Error("AC-37 scale control runtime credential is invalid");
  }
  return {
    host: LOCAL_PERFORMANCE_POSTGRES_HOST,
    port: LOCAL_PERFORMANCE_POSTGRES_PORT,
    database: state.controlDatabaseName,
    user: state.controlRuntimeRole,
    password: state.controlRuntimePassword,
    ssl: false,
  };
}

function temporaryTenant(index: number): TenantFixture {
  const tenantId = randomUUID();
  const suffix = tenantId.replaceAll("-", "");
  const sessions = Array.from({ length: PARTICIPANTS_PER_TENANT }, () => temporarySession(index, tenantId));
  const provisioningKey = randomUUID();
  const tenantSlug = `ac37s-${suffix.slice(0, 24)}`;
  const displayName = `AC-37 scale synthetic tenant-${String(index + 1).padStart(2, "0")}`;
  return {
    index,
    label: `tenant-${String(index + 1).padStart(2, "0")}`,
    tenantId,
    databaseName: `nom_t_${suffix}`,
    ownerRole: `nom_o_${suffix}`,
    runtimeRole: `nom_r_${suffix}`,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
    provisioningKey,
    provisioningRequestHash: tenantProvisionRequestHash({
      idempotencyKey: provisioningKey,
      tenantId,
      slug: tenantSlug,
      displayName,
      kind: "demo",
      timezone: "America/La_Paz",
      locale: "es",
    }),
    sessions,
    tenantKey: randomBytes(32),
    tenantKeyId: `ac37s-key-${suffix.slice(0, 20)}`,
  };
}

function temporarySession(tenantIndex: number, tenantId: string): TestSession {
  return {
    id: randomUUID(),
    identityId: randomUUID(),
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
    tenantIndex,
    tenantId,
  };
}

function expectedTenantSlug(tenant: Pick<TenantFixture, "tenantId">): string {
  return `ac37s-${tenant.tenantId.replaceAll("-", "").slice(0, 24)}`;
}

function expectedTenantDisplayName(tenant: Pick<TenantFixture, "label">): string {
  return `AC-37 scale synthetic ${tenant.label}`;
}

function scaleProvisionRequest(tenant: TenantFixture) {
  return {
    idempotencyKey: tenant.provisioningKey,
    tenantId: tenant.tenantId,
    slug: expectedTenantSlug(tenant),
    displayName: expectedTenantDisplayName(tenant),
    kind: "demo" as const,
    timezone: "America/La_Paz",
    locale: "es" as const,
  };
}

async function provisionAndSeed(databaseAdminUrl: string, state: ScaleState): Promise<void> {
  await assertTemporaryNamesUnused(state);
  state.provisioner = new TenantProvisioner({
    admin: adminPoolConfig(databaseAdminUrl),
    control: state.control,
    secrets: state.secrets,
    catalog: temporaryCatalog,
    migrationsRoot,
  });
  try {
    for (const tenant of state.tenants) {
      executionStage = `tenant-provisioning-${tenant.label}`;
      if (tenant.namesVerifiedUnused !== true) {
        throw new Error("AC-37 scale provisioning attempt lacks its exact unused-name preflight");
      }
      // Record this exact attempt immediately before the provisioner can create
      // its durable job marker. Later, unattempted names are never dropped.
      tenant.provisioningAttempted = true;
      tenant.cleanupAuthorized = true;
      const provisioned = await state.provisioner.provision(scaleProvisionRequest(tenant));
      if (
        provisioned.database !== tenant.databaseName
        || provisioned.runtimeRole !== tenant.runtimeRole
        || provisioned.secretReference !== tenant.secretReference
      ) throw new Error("AC-37 scale provisioner metadata mismatch");
      tenant.pool = new Pool({
        ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", tenant.databaseName),
        application_name: `nombramientos-ac37-scale-fixture-${tenant.index + 1}`,
        max: 1,
      });
      await assertTenantTarget(tenant);
    }
    executionStage = "control-fixture";
    await insertControlFixture(state.control, state.tenants);
    for (const tenant of state.tenants) {
      executionStage = `member-and-round-fixture-${tenant.label}`;
      const seedStarted = performance.now();
      tenant.round = await insertTenantFixture(tenant);
      tenant.memberSeedMs = performance.now() - seedStarted;
      process.stdout.write(`AC-37 scale fixture ${tenant.index + 1}/${TENANT_COUNT}: ${MEMBERS_PER_TENANT} encrypted member rows ready\n`);
    }
  } finally {
    await state.provisioner.close();
    delete state.provisioner;
  }
}

async function assertTemporaryNamesUnused(state: ScaleState): Promise<void> {
  const tenantIds = state.tenants.map((tenant) => tenant.tenantId);
  const identityIds = state.tenants.flatMap((tenant) => tenant.sessions.map((session) => session.identityId));
  const sessionIds = state.tenants.flatMap((tenant) => tenant.sessions.map((session) => session.id));
  const databaseNames = state.tenants.map((tenant) => tenant.databaseName);
  const runtimeRoles = state.tenants.map((tenant) => tenant.runtimeRole);
  const tenantSlugs = state.tenants.map((tenant) => expectedTenantSlug(tenant));
  const secretReferences = state.tenants.map((tenant) => tenant.secretReference);
  const provisioningKeys = state.tenants.map((tenant) => tenant.provisioningKey);
  const control = await state.control.query<{ count: number }>(
    `SELECT (
       (SELECT count(*) FROM tenants
         WHERE id=ANY($1::uuid[]) OR database_name=ANY($2::text[]) OR runtime_role=ANY($3::text[])
            OR slug=ANY($7::text[]) OR runtime_secret_ref=ANY($8::text[]))
       + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=ANY($1::uuid[]) OR idempotency_key=ANY($4::uuid[]))
       + (SELECT count(*) FROM platform_identities WHERE id=ANY($5::uuid[]))
       + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=ANY($1::uuid[]) OR identity_id=ANY($5::uuid[]))
       + (SELECT count(*) FROM auth_sessions WHERE id=ANY($6::uuid[]) OR identity_id=ANY($5::uuid[]) OR active_tenant_id=ANY($1::uuid[]))
     )::int AS count`,
    [tenantIds, databaseNames, runtimeRoles, provisioningKeys, identityIds, sessionIds, tenantSlugs, secretReferences],
  );
  const cluster = await state.cluster.query<{ databases: number; roles: number }>(
    `SELECT
       (SELECT count(*)::int FROM pg_database WHERE datname=ANY($1::text[])) AS databases,
       (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
    [databaseNames, state.tenants.flatMap((tenant) => [tenant.ownerRole, tenant.runtimeRole])],
  );
  if (control.rows[0]?.count !== 0 || cluster.rows[0]?.databases !== 0 || cluster.rows[0]?.roles !== 0) {
    throw new Error("AC-37 scale exact temporary names are already in use");
  }
  for (const tenant of state.tenants) tenant.namesVerifiedUnused = true;
}

async function insertControlFixture(control: Pool, tenants: readonly TenantFixture[]): Promise<void> {
  const sessions = tenants.flatMap((tenant) => tenant.sessions);
  const ids = sessions.map((session) => session.identityId);
  const emails = sessions.map((session, index) => `ac37s-${index}-${session.identityId.replaceAll("-", "")}@invalid.example`);
  const tenantIds = sessions.map((session) => session.tenantId);
  const sessionIds = sessions.map((session) => session.id);
  const tokenHashes = sessions.map((session) => sha256(session.sessionToken));
  const csrfHashes = sessions.map((session) => sha256(session.csrfToken));
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,mfa_enabled,status)
       SELECT identity_id,email,email,'AC-37 scale synthetic participant','AC37_SCALE_DISABLED_LOGIN',false,'active'
         FROM unnest($1::uuid[],$2::text[]) AS fixture(identity_id,email)`,
      [ids, emails],
    );
    await client.query(
      `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
       SELECT tenant_id,identity_id,'active',true
         FROM unnest($1::uuid[],$2::uuid[]) AS fixture(tenant_id,identity_id)`,
      [tenantIds, ids],
    );
    await client.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash
       )
       SELECT session_id,token_hash,csrf_hash,identity_id,tenant_id,
              clock_timestamp() + interval '60 minutes',$6,$7
         FROM unnest($1::uuid[],$2::text[],$3::text[],$4::uuid[],$5::uuid[])
              AS fixture(session_id,token_hash,csrf_hash,identity_id,tenant_id)`,
      [sessionIds, tokenHashes, csrfHashes, ids, tenantIds, sha256(USER_AGENT), sha256("127.0.0")],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function insertTenantFixture(tenant: TenantFixture): Promise<RoundFixture> {
  const pool = requireTenantPool(tenant);
  const cycleId = randomUUID();
  const roundId = randomUUID();
  const candidateId = randomUUID();
  const candidateSetHash = `sha256:${sha256(candidateId)}`;
  const rulesHash = `sha256:${sha256(`ac37-scale|proposal|${tenant.index}|${PARTICIPANTS_PER_TENANT}`)}`;
  let candidateEnvelope: EncryptedEnvelope | undefined;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const roles = await client.query<{ bindings: number }>(
      `WITH inserted AS (
         INSERT INTO role_bindings(identity_id,role_id)
         SELECT identity_id,role.id
           FROM unnest($1::uuid[]) AS fixture(identity_id)
           CROSS JOIN roles role
          WHERE role.code='COMMITTEE_MEMBER'
         RETURNING 1
       ) SELECT count(*)::int AS bindings FROM inserted`,
      [tenant.sessions.map((session) => session.identityId)],
    );
    if (roles.rows[0]?.bindings !== PARTICIPANTS_PER_TENANT) throw new Error("AC-37 scale role binding count mismatch");

    for (let offset = 0; offset < MEMBERS_PER_TENANT; offset += MEMBER_INSERT_BATCH) {
      const size = Math.min(MEMBER_INSERT_BATCH, MEMBERS_PER_TENANT - offset);
      const rows: Array<{ id: string; stableCode: string; envelope: EncryptedEnvelope }> = [];
      for (let batchIndex = 0; batchIndex < size; batchIndex += 1) {
        const ordinal = offset + batchIndex;
        const memberId = ordinal === 0 ? candidateId : randomUUID();
        const envelope = sealAesGcmJson(
          { synthetic: true, ordinal, displayName: `AC-37 member ${tenant.index + 1}-${ordinal + 1}` },
          tenant.tenantKey,
          tenant.tenantKeyId,
          { tenantId: tenant.tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
        );
        if (ordinal === 0) candidateEnvelope = envelope;
        rows.push({
          id: memberId,
          stableCode: `AC37S-${String(tenant.index + 1).padStart(2, "0")}-${String(ordinal + 1).padStart(5, "0")}`,
          envelope,
        });
      }
      await client.query(
        `INSERT INTO members(id,stable_code,display_envelope,display_content_hash,eligibility_status,available)
         SELECT item.id::uuid,item.stable_code,item.display_envelope,item.display_content_hash,'eligible',true
           FROM jsonb_to_recordset($1::jsonb)
                AS item(id text,stable_code text,display_envelope jsonb,display_content_hash text)`,
        [JSON.stringify(rows.map((row) => ({
          id: row.id,
          stable_code: row.stableCode,
          display_envelope: row.envelope,
          display_content_hash: envelopeContentHash(row.envelope),
        })))],
      );
    }
    if (!candidateEnvelope) throw new Error("AC-37 scale candidate envelope is unavailable");
    const memberCount = await client.query<{ count: number }>("SELECT count(*)::int AS count FROM members");
    if (memberCount.rows[0]?.count !== MEMBERS_PER_TENANT) throw new Error("AC-37 scale member count mismatch");
    const office = await client.query<{ id: string }>("SELECT id::text FROM offices ORDER BY canonical_code LIMIT 1");
    const officeId = office.rows[0]?.id;
    if (!officeId) throw new Error("AC-37 scale temporary catalog has no office");
    await client.query(
      `INSERT INTO election_cycles(
         id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count
       ) VALUES ($1,'AC-37 scale synthetic cycle','active','es','America/La_Paz',DATE '2027-01-01',DATE '2027-12-31','ac37-scale-v1',$2)`,
      [cycleId, PARTICIPANTS_PER_TENANT],
    );
    await client.query("INSERT INTO vacancies(cycle_id,office_id,ordinal,status) VALUES ($1,$2,1,'pending')", [cycleId, officeId]);
    await client.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
         max_proposal_selections,max_ballot_selections,candidate_set_hash,rules_hash,version,opened_at
       ) VALUES ($1,$2,$3,'PROPUESTAS_ABIERTAS','proposal',1,1,1,1,$4,$5,1,clock_timestamp())`,
      [roundId, cycleId, officeId, candidateSetHash, rulesHash],
    );
    await client.query(
      `INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused)
       SELECT $1,identity_id,true,false FROM unnest($2::uuid[]) AS fixture(identity_id)`,
      [roundId, tenant.sessions.map((session) => session.identityId)],
    );
    await client.query(
      `INSERT INTO candidate_snapshots(
         round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
         member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
         eligibility_evaluated_on,eligibility_effective
       ) SELECT $1,$2,member.id,$3::jsonb,true,1,0,member.version,
                member.eligibility_department_id,member.eligibility_valid_until,
                (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
           FROM members member CROSS JOIN tenant_settings settings
          WHERE member.id=$2 AND settings.singleton=true`,
      [roundId, candidateId, candidateEnvelope],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return { id: roundId, cycleId, candidateId, candidateSetHash, rulesHash };
}

async function startApis(state: ScaleState, config: ApiConfig): Promise<void> {
  const controlRuntime = scaleControlRuntimePoolConfig(state);
  for (const tenant of state.tenants) {
    const database = new DatabaseRuntime({
      control: {
        ...controlRuntime,
        application_name: `nombramientos-ac37-scale-api-${tenant.index + 1}`,
        max: 2,
        ssl: false,
      },
      secretProvider: state.secrets,
      tenantPoolMax: 6,
      tenantPoolIdleMs: 30_000,
    });
    const app = await buildServer({ config, database, logger: false });
    state.apps.push(app);
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("AC-37 scale listener has no TCP address");
    tenant.baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
  }
}

async function runSubmissionBurst(
  tenants: readonly TenantFixture[],
): Promise<{ readonly observations: readonly RequestObservation[]; readonly wallMs: number }> {
  const jobs = tenants.flatMap((tenant) => tenant.sessions.map((session) => ({
    tenant,
    session,
    payload: createSubmissionPayload(tenant),
  })));
  if (new Set(jobs.map((job) => job.payload.contentHash)).size !== TOTAL_PARTICIPANTS) {
    throw new Error("AC-37 scale generated submission payloads are not globally unique");
  }
  const started = performance.now();
  const observations = await Promise.all(jobs.map(async (job) => submit(job.tenant, job.session, job.payload)));
  return { observations, wallMs: performance.now() - started };
}

function createSubmissionPayload(tenant: TenantFixture): SubmissionPayload {
  const round = requireRound(tenant);
  const envelope = sealAesGcmJson(
    { schema: "nombramientos-submission/v1", abstain: false, selections: [round.candidateId] },
    tenant.tenantKey,
    tenant.tenantKeyId,
    {
      tenantId: tenant.tenantId,
      cycleId: round.cycleId,
      roundId: round.id,
      purpose: "proposal",
      schemaVersion: 1,
      roundVersion: 1,
      candidateSetHash: round.candidateSetHash,
      rulesHash: round.rulesHash,
    },
  );
  return { kind: "proposal", expectedVersion: 1, envelope, contentHash: envelopeContentHash(envelope) };
}

async function submit(
  tenant: TenantFixture,
  session: TestSession,
  payload: SubmissionPayload,
): Promise<RequestObservation> {
  const started = performance.now();
  const round = requireRound(tenant);
  try {
    const response = await fetch(`${requireBaseUrl(tenant)}/v1/rounds/${round.id}/submissions`, {
      method: "POST",
      headers: requestHeaders(session, {
        "content-type": "application/json",
        "x-csrf-token": session.csrfToken,
        "idempotency-key": randomUUID(),
      }),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const body = await safeJson(response);
    const data = apiData(body);
    const receiptId = typeof data?.["receiptId"] === "string" ? data["receiptId"] : null;
    return {
      tenantIndex: tenant.index,
      latencyMs: performance.now() - started,
      status: response.status,
      errorCode: apiErrorCode(body),
      valid: response.status === 201
        && isUuid(receiptId)
        && data?.["roundId"] === round.id
        && data?.["roundVersion"] === 1
        && data?.["contentHash"] === payload.contentHash
        && data?.["status"] === "received",
      receiptId,
    };
  } catch {
    return networkFailure(tenant.index, performance.now() - started);
  }
}

async function openSseProbe(tenant: TenantFixture): Promise<SseProbe> {
  const pool = requireTenantPool(tenant);
  const round = requireRound(tenant);
  const cursorResult = await pool.query<{ sequence: string }>("SELECT COALESCE(max(sequence),0)::text AS sequence FROM outbox_events");
  const cursor = cursorResult.rows[0]?.sequence ?? "0";
  const controller = new AbortController();
  const response = await fetch(`${requireBaseUrl(tenant)}/v1/events?tenantId=${tenant.tenantId}&after=${cursor}`, {
    headers: requestHeaders(requireSession(tenant)),
    signal: controller.signal,
  });
  if (response.status !== 200 || !response.body || !response.headers.get("content-type")?.includes("text/event-stream")) {
    controller.abort();
    throw new Error("AC-37 scale SSE stream did not open");
  }
  const reader = response.body.getReader();
  const readyDeferred = deferred<void>();
  const completeDeferred = deferred<void>();
  const arrivals = new Map<number, number>();
  const pump = consumeSse(
    reader,
    round.id,
    arrivals,
    readyDeferred.resolve,
    completeDeferred.resolve,
  ).catch((error: unknown) => {
    if (!controller.signal.aborted) {
      readyDeferred.reject(error);
      completeDeferred.reject(error);
    }
  });
  const probe: SseProbe = {
    tenantIndex: tenant.index,
    controller,
    reader,
    arrivals,
    ready: readyDeferred.promise,
    complete: completeDeferred.promise,
    pump,
  };
  void probe.complete.catch(() => undefined);
  try {
    await withTimeout(probe.ready, SSE_COMPLETION_TIMEOUT_MS, "SSE ready timeout");
  } catch (error) {
    controller.abort();
    await reader.cancel().catch(() => undefined);
    await pump.catch(() => undefined);
    throw error;
  }
  return probe;
}

async function consumeSse(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  expectedRoundId: string,
  arrivals: Map<number, number>,
  markReady: () => void,
  markComplete: () => void,
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const result = await reader.read();
    if (result.done) return;
    buffer += decoder.decode(result.value, { stream: true }).replaceAll("\r\n", "\n");
    let boundary = buffer.indexOf("\n\n");
    while (boundary >= 0) {
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const parsed = parseSseFrame(frame);
      if (parsed.event === "ready") markReady();
      if (parsed.event === "round.participation" && parsed.id !== null && parsed.roundId === expectedRoundId) {
        if (!arrivals.has(parsed.id)) arrivals.set(parsed.id, Date.now());
        if (arrivals.size === PARTICIPANTS_PER_TENANT) markComplete();
      }
      boundary = buffer.indexOf("\n\n");
    }
  }
}

function parseSseFrame(frame: string): { readonly id: number | null; readonly event: string | null; readonly roundId: string | null } {
  let id: number | null = null;
  let event: string | null = null;
  let data = "";
  for (const line of frame.split("\n")) {
    if (line.startsWith("id: ")) {
      const parsed = Number(line.slice(4));
      id = Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
    } else if (line.startsWith("event: ")) {
      event = line.slice(7);
    } else if (line.startsWith("data: ")) {
      data += line.slice(6);
    }
  }
  let roundId: string | null = null;
  if (data) {
    try {
      const value: unknown = JSON.parse(data);
      if (isRecord(value) && isRecord(value["payload"]) && typeof value["payload"]["roundId"] === "string") {
        roundId = value["payload"]["roundId"];
      }
    } catch {
      roundId = null;
    }
  }
  return { id, event, roundId };
}

async function waitForSseProbes(probes: readonly SseProbe[]): Promise<boolean> {
  try {
    await withTimeout(Promise.all(probes.map((probe) => probe.complete)).then(() => undefined), SSE_COMPLETION_TIMEOUT_MS, "SSE completion timeout");
    return true;
  } catch {
    return false;
  }
}

async function closeSseProbe(probe: SseProbe): Promise<void> {
  probe.controller.abort();
  await probe.reader.cancel().catch(() => undefined);
  await probe.pump.catch(() => undefined);
}

async function inspectSsePropagation(
  tenants: readonly TenantFixture[],
  probes: readonly SseProbe[],
  propagationWallMs: number,
): Promise<{
  readonly metrics: LatencySummary;
  readonly perTenant: readonly Readonly<Record<string, unknown>>[];
  readonly integrityPass: boolean;
}> {
  const allLatencies: number[] = [];
  let integrityPass = true;
  const perTenant: Array<Readonly<Record<string, unknown>>> = [];
  for (const tenant of tenants) {
    const probe = probes.find((item) => item.tenantIndex === tenant.index);
    if (!probe) {
      integrityPass = false;
      perTenant.push({ tenant: tenant.label, observedEvents: 0, expectedEvents: PARTICIPANTS_PER_TENANT, pass: false });
      continue;
    }
    const sequences = [...probe.arrivals.keys()];
    const result = sequences.length === 0
      ? { rows: [] as SseOccurrenceRow[] }
      : await requireTenantPool(tenant).query<SseOccurrenceRow>(
          `SELECT sequence::text,(extract(epoch FROM occurred_at) * 1000)::double precision AS occurred_ms
             FROM outbox_events
            WHERE sequence=ANY($1::bigint[]) AND event_type='round.participation' AND aggregate_id=$2
            ORDER BY outbox_events.sequence`,
          [sequences.map(String), requireRound(tenant).id],
        );
    const tenantLatencies = result.rows.flatMap((row) => {
      const arrival = probe.arrivals.get(Number(row.sequence));
      return arrival === undefined ? [] : [arrival - row.occurred_ms];
    });
    const validLatencies = tenantLatencies.every((latency) => Number.isFinite(latency) && latency >= 0);
    const tenantIntegrity = sequences.length === PARTICIPANTS_PER_TENANT
      && result.rows.length === PARTICIPANTS_PER_TENANT
      && tenantLatencies.length === PARTICIPANTS_PER_TENANT
      && validLatencies;
    integrityPass &&= tenantIntegrity;
    if (validLatencies) allLatencies.push(...tenantLatencies);
    perTenant.push({
      tenant: tenant.label,
      observedEvents: sequences.length,
      persistedMatchingEvents: result.rows.length,
        metrics: latencySummary(tenantLatencies, propagationWallMs),
      pass: tenantIntegrity,
    });
  }
  return {
    metrics: latencySummary(allLatencies, propagationWallMs),
    perTenant,
    integrityPass,
  };
}

async function runReadBurst(tenants: readonly TenantFixture[]): Promise<{
  readonly dashboard: readonly RequestObservation[];
  readonly members: readonly RequestObservation[];
  readonly wallMs: number;
}> {
  const jobs = tenants.flatMap((tenant) => tenant.sessions.map((session) => ({ tenant, session })));
  const started = performance.now();
  const pairs = await Promise.all(jobs.map(async (job) => ({
    dashboard: await read(job.tenant, job.session, "/v1/dashboard", "dashboard"),
    members: await read(job.tenant, job.session, "/v1/members?limit=1", "members"),
  })));
  const dashboard = pairs.map((pair) => pair.dashboard);
  const members = pairs.map((pair) => pair.members);
  return { dashboard, members, wallMs: performance.now() - started };
}

async function read(
  tenant: TenantFixture,
  session: TestSession,
  route: string,
  kind: "dashboard" | "members",
): Promise<RequestObservation> {
  const started = performance.now();
  try {
    const response = await fetch(requireBaseUrl(tenant) + route, {
      method: "GET",
      headers: requestHeaders(session),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const body = await safeJson(response);
    const data = apiData(body);
    const valid = kind === "dashboard"
      ? response.status === 200
        && isRecord(data?.["tenant"])
        && data["tenant"]["id"] === tenant.tenantId
        && isRecord(data["metrics"])
      : response.status === 200
        && Array.isArray(data?.["items"])
        && data["items"].length === 1
        && data["total"] === MEMBERS_PER_TENANT;
    return {
      tenantIndex: tenant.index,
      latencyMs: performance.now() - started,
      status: response.status,
      errorCode: apiErrorCode(body),
      valid,
      receiptId: null,
    };
  } catch {
    return networkFailure(tenant.index, performance.now() - started);
  }
}

async function inspectAllIntegrity(
  tenants: readonly TenantFixture[],
  observations: readonly RequestObservation[],
): Promise<readonly { readonly tenantIndex: number; readonly row: IntegrityRow }[]> {
  return Promise.all(tenants.map(async (tenant) => {
    const receiptIds = observations
      .filter((item) => item.tenantIndex === tenant.index && item.receiptId !== null)
      .map((item) => item.receiptId as string);
    const round = requireRound(tenant);
    const result = await requireTenantPool(tenant).query<IntegrityRow>(
      `SELECT
         (SELECT count(*)::int FROM members) AS members,
         (SELECT count(*)::int FROM round_elector_snapshots WHERE round_id=$1) AS electors,
         (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$1) AS submissions,
         (SELECT count(DISTINCT elector_identity_id)::int FROM encrypted_submissions WHERE round_id=$1) AS distinct_submission_electors,
         (SELECT count(DISTINCT content_hash)::int FROM encrypted_submissions WHERE round_id=$1) AS distinct_submission_hashes,
         (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1) AS receipts,
         (SELECT count(DISTINCT submission_id)::int FROM participation_receipts WHERE round_id=$1) AS distinct_receipt_submissions,
         (SELECT count(DISTINCT elector_identity_id)::int FROM participation_receipts WHERE round_id=$1) AS distinct_receipt_electors,
         (SELECT count(*)::int FROM participation_receipts WHERE round_id=$1 AND id=ANY($2::uuid[])) AS returned_receipts,
         (SELECT count(*)::int FROM idempotency_records
           WHERE operation='round.proposal.submit' AND response_body->>'roundId'=$1::text) AS idempotency_records,
         (SELECT count(*)::int FROM audit_events WHERE action='round.submission.received' AND entity_id=$1::text) AS audit_events,
         (SELECT count(*)::int FROM outbox_events WHERE event_type='round.participation' AND aggregate_id=$1) AS outbox_events`,
      [round.id, receiptIds],
    );
    const row = result.rows[0];
    if (!row) throw new Error("AC-37 scale integrity query returned no row");
    return { tenantIndex: tenant.index, row };
  }));
}

function exactIntegrity(row: IntegrityRow): boolean {
  return row.members === MEMBERS_PER_TENANT
    && row.electors === PARTICIPANTS_PER_TENANT
    && row.submissions === PARTICIPANTS_PER_TENANT
    && row.distinct_submission_electors === PARTICIPANTS_PER_TENANT
    && row.distinct_submission_hashes === PARTICIPANTS_PER_TENANT
    && row.receipts === PARTICIPANTS_PER_TENANT
    && row.distinct_receipt_submissions === PARTICIPANTS_PER_TENANT
    && row.distinct_receipt_electors === PARTICIPANTS_PER_TENANT
    && row.returned_receipts === PARTICIPANTS_PER_TENANT
    && row.idempotency_records === PARTICIPANTS_PER_TENANT
    && row.audit_events === PARTICIPANTS_PER_TENANT
    && row.outbox_events === PARTICIPANTS_PER_TENANT;
}

function publicIntegrity(row: IntegrityRow): Readonly<Record<string, number | boolean>> {
  return {
    members: row.members,
    electors: row.electors,
    submissions: row.submissions,
    distinctSubmissionElectors: row.distinct_submission_electors,
    distinctSubmissionContentHashes: row.distinct_submission_hashes,
    receipts: row.receipts,
    distinctReceiptSubmissions: row.distinct_receipt_submissions,
    distinctReceiptElectors: row.distinct_receipt_electors,
    receiptsReturnedByApi: row.returned_receipts,
    idempotencyRecords: row.idempotency_records,
    auditEvents: row.audit_events,
    outboxEvents: row.outbox_events,
    pass: exactIntegrity(row),
  };
}

function aggregateIntegrity(rows: readonly IntegrityRow[]): Readonly<Record<string, number | boolean>> {
  const sum = (field: keyof IntegrityRow) => rows.reduce((total, row) => total + row[field], 0);
  return {
    tenants: rows.length,
    members: sum("members"),
    electors: sum("electors"),
    submissions: sum("submissions"),
    receipts: sum("receipts"),
    idempotencyRecords: sum("idempotency_records"),
    auditEvents: sum("audit_events"),
    outboxEvents: sum("outbox_events"),
    pass: rows.length === TENANT_COUNT && rows.every(exactIntegrity),
  };
}

async function readAllSnapshots(tenants: readonly TenantFixture[]): Promise<readonly TenantReadSnapshot[]> {
  return Promise.all(tenants.map(async (tenant) => tenantReadSnapshot(tenant)));
}

async function tenantReadSnapshot(tenant: TenantFixture): Promise<TenantReadSnapshot> {
  const result = await requireTenantPool(tenant).query<TenantReadSnapshot>(
    `SELECT
       (SELECT count(*)::int FROM members) AS members,
       (SELECT count(*)::int FROM election_cycles) AS cycles,
       (SELECT count(*)::int FROM rounds) AS rounds,
       (SELECT version::int FROM rounds WHERE id=$1) AS round_version,
       (SELECT count(*)::int FROM encrypted_submissions) AS submissions,
       (SELECT count(*)::int FROM participation_receipts) AS receipts,
       (SELECT count(*)::int FROM idempotency_records) AS idempotency_records,
       (SELECT count(*)::int FROM audit_events) AS audit_events,
       (SELECT count(*)::int FROM outbox_events) AS outbox_events`,
    [requireRound(tenant).id],
  );
  const row = result.rows[0];
  if (!row) throw new Error("AC-37 scale read snapshot returned no row");
  return row;
}

async function verifyDatabaseIsolation(
  databaseAdminUrl: string,
  tenants: readonly TenantFixture[],
  secrets: MemorySecretProvider,
): Promise<Readonly<Record<string, number | boolean | string>>> {
  let denied = 0;
  let unexpected = 0;
  for (const tenant of tenants) {
    const other = tenants[(tenant.index + 1) % tenants.length];
    if (!other) throw new Error("AC-37 scale database isolation ring is incomplete");
    const password = await secrets.getSecret(tenant.secretReference);
    const admin = new URL(databaseAdminUrl);
    const pool = new Pool({
      host: admin.hostname,
      port: Number(admin.port),
      database: other.databaseName,
      user: tenant.runtimeRole,
      password,
      ssl: false,
      max: 1,
      connectionTimeoutMillis: 3_000,
      application_name: "nombramientos-ac37-scale-isolation",
    });
    try {
      await pool.query("SELECT 1");
      unexpected += 1;
    } catch (error) {
      if (errorCode(error) === "42501") denied += 1;
      else unexpected += 1;
    } finally {
      await pool.end().catch(() => undefined);
    }
  }
  return {
    attempts: TENANT_COUNT,
    deniedWithSqlstate42501: denied,
    unexpectedOutcomes: unexpected,
    mapping: "runtime credential N against tenant database N+1",
    pass: denied === TENANT_COUNT && unexpected === 0,
  };
}

async function verifyHttpIsolation(tenants: readonly TenantFixture[]): Promise<Readonly<Record<string, number | boolean>>> {
  let foreignTenantDenied = 0;
  let foreignRoundHidden = 0;
  let unexpected = 0;
  for (const tenant of tenants) {
    const other = tenants[(tenant.index + 1) % tenants.length];
    if (!other) throw new Error("AC-37 scale HTTP isolation ring is incomplete");
    const session = requireSession(tenant);
    try {
      const wrongTenant = await fetch(`${requireBaseUrl(tenant)}/v1/events?tenantId=${other.tenantId}&after=0`, {
        headers: requestHeaders(session),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const wrongTenantBody = await safeJson(wrongTenant);
      if (wrongTenant.status === 403 && apiErrorCode(wrongTenantBody) === "PERMISSION_DENIED") foreignTenantDenied += 1;
      else unexpected += 1;
      const foreignRound = await fetch(
        `${requireBaseUrl(tenant)}/v1/rounds/${requireRound(other).id}/submissions/me`,
        { headers: requestHeaders(session), signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
      );
      const foreignRoundBody = await safeJson(foreignRound);
      if (foreignRound.status === 404 && apiErrorCode(foreignRoundBody) === "SUBMISSION_NOT_FOUND") foreignRoundHidden += 1;
      else unexpected += 1;
    } catch {
      unexpected += 1;
    }
  }
  return {
    foreignTenantAttempts: TENANT_COUNT,
    foreignTenantDenied,
    foreignRoundAttempts: TENANT_COUNT,
    foreignRoundHidden,
    unexpectedOutcomes: unexpected,
    pass: foreignTenantDenied === TENANT_COUNT && foreignRoundHidden === TENANT_COUNT && unexpected === 0,
  };
}

async function cleanupScaleFixture(state: ScaleState): Promise<CleanupResult> {
  let cleanupFailed = false;
  const clean = async (work: () => Promise<unknown>): Promise<void> => {
    try {
      await work();
    } catch {
      cleanupFailed = true;
    }
  };
  for (const app of state.apps.splice(0)) await clean(async () => app.close());
  for (const tenant of state.tenants) {
    if (tenant.pool) {
      const pool = tenant.pool;
      delete tenant.pool;
      await clean(async () => pool.end());
    }
  }
  if (state.provisioner) {
    const provisioner = state.provisioner;
    delete state.provisioner;
    await clean(async () => provisioner.close());
  }

  const cleanupTenants = state.tenants.filter((tenant) => (
    tenant.cleanupAuthorized === true && tenant.provisioningAttempted === true
  ));
  let cleanupPlan: PerformanceCleanupPlan | null = null;
  let controlCleanupPlan: ScaleControlCleanupPlan = { databases: [], roles: [] };
  let temporaryControlExists = false;
  try {
    assertCleanupScope(cleanupTenants);
    if (state.controlNamesVerifiedUnused === true) {
      controlCleanupPlan = await inspectScaleControlCleanupOwnership(state);
      temporaryControlExists = controlCleanupPlan.databases.includes(state.controlDatabaseName);
      if (temporaryControlExists) {
        if (cleanupTenants.length > 0) {
          if (
            state.controlCleanupAuthorized !== true
            || state.controlRuntimeRoleCleanupAuthorized !== true
          ) throw new Error("AC-37 scale tenant cleanup lacks complete control ownership markers");
          await assertIsolatedControlTarget(state);
          await assertControlRuntimeRoleTarget(state);
          const schema = await state.control.query<{ ready: boolean }>(
            `SELECT to_regclass('public.tenants') IS NOT NULL
                    AND to_regclass('public.provisioning_jobs') IS NOT NULL
                    AND to_regclass('public.platform_identities') IS NOT NULL
                    AND to_regclass('public.tenant_memberships') IS NOT NULL
                    AND to_regclass('public.auth_sessions') IS NOT NULL AS ready`,
          );
          if (schema.rows[0]?.ready !== true) throw new Error("AC-37 scale isolated control schema is incomplete");
          cleanupPlan = await inspectScaleCleanupOwnership(state.control, state.cluster, cleanupTenants);
        }
      } else if (cleanupTenants.length > 0) {
        throw new Error("AC-37 scale generated tenant cleanup lacks its isolated control database");
      }
    } else if (
      state.controlDatabaseCreationAttempted === true
      || state.controlCreatedByRun === true
      || state.controlRuntimeRoleCreationAttempted === true
      || state.controlRuntimeRoleCreatedByRun === true
      || cleanupTenants.length > 0
    ) {
      throw new Error("AC-37 scale generated tenants cannot exist before isolated control authorization");
    }
  } catch (error) {
    await Promise.allSettled([state.control.end(), state.cluster.end()]);
    throw error;
  }
  const tenantIds = cleanupPlan?.tenantIds ?? cleanupTenants.map((tenant) => tenant.tenantId);
  const identityIds = cleanupTenants.flatMap((tenant) => tenant.sessions.map((session) => session.identityId));
  const sessionIds = cleanupTenants.flatMap((tenant) => tenant.sessions.map((session) => session.id));
  const provisioningKeys = cleanupPlan?.provisioningKeys ?? cleanupTenants.map((tenant) => tenant.provisioningKey);
  let controlRows = 0;
  if (temporaryControlExists && cleanupTenants.length > 0) {
    await clean(async () => {
      await state.control.query(
        "DELETE FROM auth_sessions WHERE active_tenant_id=ANY($1::uuid[]) OR id=ANY($2::uuid[]) OR identity_id=ANY($3::uuid[])",
        [tenantIds, sessionIds, identityIds],
      );
      await state.control.query(
        "DELETE FROM tenant_memberships WHERE tenant_id=ANY($1::uuid[]) OR identity_id=ANY($2::uuid[])",
        [tenantIds, identityIds],
      );
      await state.control.query("DELETE FROM platform_identities WHERE id=ANY($1::uuid[])", [identityIds]);
      await state.control.query("DELETE FROM tenants WHERE id=ANY($1::uuid[])", [tenantIds]);
      await state.control.query(
        "DELETE FROM provisioning_jobs WHERE tenant_id=ANY($1::uuid[]) OR idempotency_key=ANY($2::uuid[])",
        [tenantIds, provisioningKeys],
      );
      const control = await state.control.query<{ count: number }>(
        `SELECT (
           (SELECT count(*) FROM auth_sessions WHERE active_tenant_id=ANY($1::uuid[]) OR id=ANY($2::uuid[]) OR identity_id=ANY($3::uuid[]))
           + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=ANY($1::uuid[]) OR identity_id=ANY($3::uuid[]))
           + (SELECT count(*) FROM platform_identities WHERE id=ANY($3::uuid[]))
           + (SELECT count(*) FROM tenants WHERE id=ANY($1::uuid[]))
           + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=ANY($1::uuid[]) OR idempotency_key=ANY($4::uuid[]))
         )::int AS count`,
        [tenantIds, sessionIds, identityIds, provisioningKeys],
      );
      controlRows = control.rows[0]?.count ?? -1;
      if (controlRows !== 0) throw new Error("AC-37 scale isolated control row cleanup verification failed");
    });
  }
  await clean(async () => state.control.end());
  for (const tenant of cleanupTenants) {
    if (cleanupPlan?.databases.includes(tenant.databaseName)) {
      await clean(async () => dropDatabase(state.cluster, tenant));
    }
  }
  for (const tenant of cleanupTenants) {
    if (cleanupPlan?.roles.includes(tenant.runtimeRole)) {
      await clean(async () => dropRole(state.cluster, tenant, "runtime"));
    }
    if (cleanupPlan?.roles.includes(tenant.ownerRole)) {
      await clean(async () => dropRole(state.cluster, tenant, "owner"));
    }
  }
  if (controlCleanupPlan.databases.includes(state.controlDatabaseName)) {
    await clean(async () => dropControlDatabase(state.cluster, state, controlCleanupPlan));
  }
  if (controlCleanupPlan.roles.includes(state.controlRuntimeRole)) {
    await clean(async () => dropControlRuntimeRole(state.cluster, state, controlCleanupPlan));
  }

  let databases = -1;
  let roles = -1;
  await clean(async () => {
    const cluster = await state.cluster.query<{ databases: number; roles: number }>(
      `SELECT
         (SELECT count(*)::int FROM pg_database WHERE datname=ANY($1::text[])) AS databases,
         (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
      [
        [state.controlDatabaseName, ...cleanupTenants.map((tenant) => tenant.databaseName)],
        [
          state.controlRuntimeRole,
          ...cleanupTenants.flatMap((tenant) => [tenant.ownerRole, tenant.runtimeRole]),
        ],
      ],
    );
    databases = cluster.rows[0]?.databases ?? -1;
    roles = cluster.rows[0]?.roles ?? -1;
    if (controlRows !== 0 || databases !== 0 || roles !== 0) throw new Error("AC-37 scale cleanup verification failed");
  });
  let protectedDatabasesAfter: ProtectedDatabaseFingerprints | null = null;
  try {
    protectedDatabasesAfter = await fingerprintProtectedDatabases(state.databaseAdminUrl);
  } catch {
    cleanupFailed = true;
  }
  let ephemeralResourcesAfter: EphemeralResourceInventory | null = null;
  try {
    ephemeralResourcesAfter = await inspectGlobalEphemeralResources(state.databaseAdminUrl);
  } catch {
    cleanupFailed = true;
  }
  const protectedDatabasesBefore = state.protectedDatabaseFingerprints ?? null;
  const protectedDatabasesUnchanged = protectedFingerprintSetsEqual(
    protectedDatabasesBefore,
    protectedDatabasesAfter,
  );
  const operationalControlBefore = protectedDatabasesBefore?.control ?? null;
  const operationalControlAfter = protectedDatabasesAfter?.control ?? null;
  const operationalControlUnchanged = operationalControlBefore !== null
    && operationalControlAfter !== null
    && JSON.stringify(operationalControlBefore) === JSON.stringify(operationalControlAfter);
  const ephemeralResourcesBefore = state.ephemeralResourcesBefore ?? null;
  const globalInventoryUnchanged = globalInventorySetsEqual(
    ephemeralResourcesBefore,
    ephemeralResourcesAfter,
  );
  if (
    !protectedDatabasesUnchanged
    || !operationalControlUnchanged
    || !globalInventoryUnchanged
    || ephemeralResourcesBefore?.pass !== true
    || ephemeralResourcesAfter?.pass !== true
  ) cleanupFailed = true;
  await clean(async () => state.cluster.end());
  const pass = !cleanupFailed
    && controlRows === 0
    && databases === 0
    && roles === 0
    && operationalControlUnchanged
    && protectedDatabasesUnchanged
    && globalInventoryUnchanged
    && ephemeralResourcesBefore?.pass === true
    && ephemeralResourcesAfter?.pass === true;
  if (!pass) throw new Error("AC-37 scale temporary fixture cleanup did not complete");
  return {
    controlRows,
    databases,
    roles,
    operationalControlBefore,
    operationalControlAfter,
    operationalControlUnchanged,
    protectedDatabasesBefore,
    protectedDatabasesAfter,
    protectedDatabasesUnchanged,
    ephemeralResourcesBefore,
    ephemeralResourcesAfter,
    globalInventoryUnchanged,
    pass,
  };
}

async function assertIsolatedControlTarget(state: ScaleState): Promise<void> {
  const target = await state.control.query<{
    database_name: string;
    run_id: string;
    marked_database: string;
    marked_runtime_role: string;
  }>(
    `SELECT current_database() AS database_name,run_id::text,control_database AS marked_database,
            control_runtime_role AS marked_runtime_role
       FROM ac37_scale_run_metadata
      WHERE singleton=true`,
  );
  const row = target.rows[0];
  if (
    target.rowCount !== 1
    || row?.database_name !== state.controlDatabaseName
    || row.run_id !== state.runId
    || row.marked_database !== state.controlDatabaseName
    || row.marked_runtime_role !== state.controlRuntimeRole
  ) {
    throw new Error("AC-37 scale isolated control connection target is invalid");
  }
}

async function assertControlRuntimeRoleTarget(state: ScaleState): Promise<void> {
  assertGeneratedControlRuntimeIdentity(state.runId, state.controlRuntimeRole);
  const result = await state.cluster.query<{
    name: string;
    login: boolean;
    superuser: boolean;
    create_database: boolean;
    create_role: boolean;
    inherit: boolean;
    replication: boolean;
    bypass_rls: boolean;
    connection_limit: number;
    valid_until_epoch: string;
    configuration: string;
    password_present: boolean;
    membership_count: number;
    marker: string;
  }>(
    `SELECT role.rolname::text AS name,role.rolcanlogin AS login,role.rolsuper AS superuser,
            role.rolcreatedb AS create_database,role.rolcreaterole AS create_role,
            role.rolinherit AS inherit,role.rolreplication AS replication,
            role.rolbypassrls AS bypass_rls,role.rolconnlimit::int AS connection_limit,
            COALESCE(extract(epoch FROM role.rolvaliduntil)::text,'') AS valid_until_epoch,
            ARRAY(SELECT setting FROM unnest(COALESCE(role.rolconfig,'{}'::text[])) setting ORDER BY setting)::text AS configuration,
            credential.rolpassword IS NOT NULL AS password_present,
            (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
              WHERE membership.member=role.oid OR membership.roleid=role.oid) AS membership_count,
            COALESCE(pg_catalog.shobj_description(role.oid,'pg_authid'),'')::text AS marker
       FROM pg_catalog.pg_roles role
       JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
      WHERE role.rolname=$1`,
    [state.controlRuntimeRole],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1
    || !row
    || row.name !== state.controlRuntimeRole
    || !row.login
    || row.superuser
    || row.create_database
    || row.create_role
    || row.inherit
    || row.replication
    || row.bypass_rls
    || row.connection_limit !== 30
    || row.valid_until_epoch !== ""
    || row.configuration !== "{}"
    || !row.password_present
    || row.membership_count !== 0
    || row.marker !== expectedControlRuntimeRoleMarker(state.runId)) {
    throw new Error("AC-37 scale control runtime role target is invalid");
  }
}

async function inspectScaleControlCleanupOwnership(state: ScaleState): Promise<ScaleControlCleanupPlan> {
  const [databases, roles] = await Promise.all([
    state.cluster.query<ScaleControlCleanupDatabase>(
      `SELECT database.datname::text AS name,pg_get_userbyid(database.datdba)::text AS owner,
              pg_encoding_to_char(database.encoding)::text AS encoding,
              database.datistemplate AS is_template,database.datallowconn AS allows_connections,
              database.datconnlimit::int AS connection_limit
         FROM pg_catalog.pg_database database WHERE database.datname=$1`,
      [state.controlDatabaseName],
    ),
    state.cluster.query<ScaleControlCleanupRole>(
      `SELECT role.rolname::text AS name,role.rolcanlogin AS login,role.rolsuper AS superuser,
              role.rolcreatedb AS create_database,role.rolcreaterole AS create_role,
              role.rolinherit AS inherit,role.rolreplication AS replication,
              role.rolbypassrls AS bypass_rls,role.rolconnlimit::int AS connection_limit,
              COALESCE(extract(epoch FROM role.rolvaliduntil)::text,'') AS valid_until_epoch,
              ARRAY(SELECT setting FROM unnest(COALESCE(role.rolconfig,'{}'::text[])) setting ORDER BY setting)::text AS configuration,
              credential.rolpassword IS NOT NULL AS password_present,
              (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
                WHERE membership.member=role.oid OR membership.roleid=role.oid) AS membership_count,
              pg_catalog.shobj_description(role.oid,'pg_authid')::text AS marker
         FROM pg_catalog.pg_roles role
         JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
        WHERE role.rolname=$1`,
      [state.controlRuntimeRole],
    ),
  ]);
  if ((databases.rowCount ?? 0) > 1 || (roles.rowCount ?? 0) > 1) {
    throw new Error("AC-37 scale control cleanup resource identity is ambiguous");
  }

  let markerTablePresent = false;
  let marker: ScaleControlCleanupMarker | null = null;
  if (databases.rows[0]) {
    const markerTable = await state.control.query<{ present: boolean }>(
      "SELECT to_regclass('public.ac37_scale_run_metadata') IS NOT NULL AS present",
    );
    markerTablePresent = markerTable.rows[0]?.present === true;
    if (markerTablePresent) {
      const markers = await state.control.query<ScaleControlCleanupMarker>(
        `SELECT run_id::text,control_database::text,control_runtime_role::text
           FROM ac37_scale_run_metadata WHERE singleton=true`,
      );
      if (markers.rowCount === 1) marker = markers.rows[0] ?? null;
    }
  }

  return planScaleControlCleanup({
    runId: state.runId,
    databaseName: state.controlDatabaseName,
    runtimeRole: state.controlRuntimeRole,
    namesVerifiedUnused: state.controlNamesVerifiedUnused === true,
    databaseCreationAttempted: state.controlDatabaseCreationAttempted === true,
    databaseCreatedByRun: state.controlCreatedByRun === true,
    roleCreationAttempted: state.controlRuntimeRoleCreationAttempted === true,
    roleCreatedByRun: state.controlRuntimeRoleCreatedByRun === true,
  }, {
    database: databases.rows[0] ?? null,
    markerTablePresent,
    marker,
    role: roles.rows[0] ?? null,
  });
}

async function inspectScaleCleanupOwnership(
  control: Pool,
  cluster: Pool,
  tenants: readonly TenantFixture[],
): Promise<PerformanceCleanupPlan> {
  const tenantIds = tenants.map(({ tenantId }) => tenantId);
  const tenantSlugs = tenants.map(expectedTenantSlug);
  const databaseNames = tenants.map(({ databaseName }) => databaseName);
  const runtimeRoles = tenants.map(({ runtimeRole }) => runtimeRole);
  const secretReferences = tenants.map(({ secretReference }) => secretReference);
  const provisioningKeys = tenants.map(({ provisioningKey }) => provisioningKey);
  const allRoles = tenants.flatMap(({ ownerRole, runtimeRole }) => [ownerRole, runtimeRole]);
  const [routes, jobs, databases, roles] = await Promise.all([
    control.query<PerformanceCleanupRoute>(
      `SELECT id::text,slug,display_name,kind,status,timezone,locale,database_host,database_port,
              database_name::text,runtime_role::text,runtime_secret_ref,credential_version,ssl_mode
         FROM tenants
        WHERE id=ANY($1::uuid[]) OR slug=ANY($2::text[]) OR database_name=ANY($3::text[])
           OR runtime_role=ANY($4::text[]) OR runtime_secret_ref=ANY($5::text[])`,
      [tenantIds, tenantSlugs, databaseNames, runtimeRoles, secretReferences],
    ),
    control.query<PerformanceCleanupJob>(
      `SELECT idempotency_key::text,tenant_id::text,requested_slug,request_hash,state,attempt_count
         FROM provisioning_jobs WHERE tenant_id=ANY($1::uuid[]) OR idempotency_key=ANY($2::uuid[])`,
      [tenantIds, provisioningKeys],
    ),
    cluster.query<{ name: string }>(
      "SELECT datname::text AS name FROM pg_database WHERE datname=ANY($1::text[]) ORDER BY datname",
      [databaseNames],
    ),
    cluster.query<{ name: string }>(
      "SELECT rolname::text AS name FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname",
      [allRoles],
    ),
  ]);
  return planPerformanceCleanup(tenants.map((tenant) => ({
    tenantId: tenant.tenantId,
    databaseName: tenant.databaseName,
    ownerRole: tenant.ownerRole,
    runtimeRole: tenant.runtimeRole,
    provisioningKey: tenant.provisioningKey,
    tenantSlug: expectedTenantSlug(tenant),
    displayName: expectedTenantDisplayName(tenant),
    secretReference: tenant.secretReference,
    requestHash: tenant.provisioningRequestHash,
    namesVerifiedUnused: tenant.namesVerifiedUnused === true,
    provisioningAttempted: tenant.provisioningAttempted === true,
  })), {
    routes: routes.rows,
    jobs: jobs.rows,
    databases: databases.rows.map(({ name }) => name),
    roles: roles.rows.map(({ name }) => name),
  }, TENANT_COUNT);
}

async function dropDatabase(cluster: Pool, tenant: TenantFixture): Promise<void> {
  assertGeneratedTenant(tenant);
  await executeFormatted(cluster, "SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql", [tenant.databaseName]);
}

async function dropRole(cluster: Pool, tenant: TenantFixture, kind: "owner" | "runtime"): Promise<void> {
  assertGeneratedTenant(tenant);
  const role = kind === "owner" ? tenant.ownerRole : tenant.runtimeRole;
  await executeFormatted(cluster, "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql", [role]);
}

async function dropControlDatabase(
  cluster: Pool,
  state: ScaleState,
  plan: ScaleControlCleanupPlan,
): Promise<void> {
  assertGeneratedControlIdentity(state.runId, state.controlDatabaseName);
  if (
    state.controlNamesVerifiedUnused !== true
    || state.controlDatabaseCreationAttempted !== true
    || state.controlCreatedByRun !== true
    || plan.databases.length !== 1
    || plan.databases[0] !== state.controlDatabaseName
  ) throw new Error("AC-37 scale control database is outside the exact cleanup plan");
  await executeFormatted(
    cluster,
    "SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql",
    [state.controlDatabaseName],
  );
}

async function dropControlRuntimeRole(
  cluster: Pool,
  state: ScaleState,
  plan: ScaleControlCleanupPlan,
): Promise<void> {
  assertGeneratedControlRuntimeIdentity(state.runId, state.controlRuntimeRole);
  if (
    state.controlNamesVerifiedUnused !== true
    || state.controlRuntimeRoleCreationAttempted !== true
    || state.controlRuntimeRoleCreatedByRun !== true
    || plan.roles.length !== 1
    || plan.roles[0] !== state.controlRuntimeRole
  ) throw new Error("AC-37 scale control runtime role is outside the exact cleanup plan");
  await executeFormatted(
    cluster,
    "SELECT format('DROP ROLE IF EXISTS %I',$1::text) AS sql",
    [state.controlRuntimeRole],
  );
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format an AC-37 scale cleanup statement");
  await pool.query(sql);
}

async function assertTenantTarget(tenant: TenantFixture): Promise<void> {
  const result = await requireTenantPool(tenant).query<{ database_name: string; tenant_id: string; kind: string }>(
    "SELECT current_database() AS database_name,tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
  );
  const row = result.rows[0];
  if (!row || row.database_name !== tenant.databaseName || row.tenant_id !== tenant.tenantId || row.kind !== "demo") {
    throw new Error("AC-37 scale temporary tenant target is invalid");
  }
}

function requestHeaders(session: TestSession, extra: Readonly<Record<string, string>> = {}): Record<string, string> {
  return {
    origin: ORIGIN,
    "user-agent": USER_AGENT,
    cookie: `nom_session=${session.sessionToken}; nom_csrf=${session.csrfToken}`,
    ...extra,
  };
}

function workloadResult(
  observations: readonly RequestObservation[],
  wallMs: number,
  expectedStatus: number,
): WorkloadResult {
  return {
    metrics: latencySummary(observations.map((observation) => observation.latencyMs), wallMs),
    statusCounts: countValues(observations.map((observation) => String(observation.status))),
    errorCodeCounts: countValues(observations.map((observation) => observation.errorCode ?? "none")),
    unexpectedFailures: observations.filter((observation) => observation.status !== expectedStatus).length,
    responseValidationFailures: observations.filter((observation) => !observation.valid).length,
  };
}

function latencySummary(latencies: readonly number[], wallMs: number): LatencySummary {
  const sorted = [...latencies].sort((left, right) => left - right);
  return {
    count: sorted.length,
    wallMs: roundMetric(wallMs),
    throughputRequestsPerSecond: wallMs <= 0 ? 0 : roundMetric(sorted.length / (wallMs / 1_000)),
    p50Ms: percentile(sorted, 0.50),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    maxMs: roundMetric(sorted.at(-1) ?? 0),
  };
}

function percentile(sorted: readonly number[], quantile: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.max(0, Math.ceil(sorted.length * quantile) - 1);
  return roundMetric(sorted[index] ?? 0);
}

function countValues(values: readonly string[]): Readonly<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function networkFailure(tenantIndex: number, latencyMs: number): RequestObservation {
  return { tenantIndex, latencyMs, status: 0, errorCode: "NETWORK_ERROR", valid: false, receiptId: null };
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function apiData(body: unknown): Record<string, unknown> | undefined {
  return isRecord(body) && isRecord(body["data"]) ? body["data"] : undefined;
}

function apiErrorCode(body: unknown): string | null {
  if (!isRecord(body) || !isRecord(body["error"]) || typeof body["error"]["code"] !== "string") return null;
  return sanitizeMetadata(body["error"]["code"]);
}

function envelopeContentHash(envelope: EncryptedEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${sha256(canonical)}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function errorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : null;
}

function requireTenantPool(tenant: TenantFixture): Pool {
  if (!tenant.pool) throw new Error("AC-37 scale tenant pool is unavailable");
  return tenant.pool;
}

function requireRound(tenant: TenantFixture): RoundFixture {
  if (!tenant.round) throw new Error("AC-37 scale tenant round is unavailable");
  return tenant.round;
}

function requireBaseUrl(tenant: TenantFixture): string {
  if (!tenant.baseUrl) throw new Error("AC-37 scale tenant listener is unavailable");
  return tenant.baseUrl;
}

function requireSession(tenant: TenantFixture): TestSession {
  const session = tenant.sessions[0];
  if (!session) throw new Error("AC-37 scale tenant has no session");
  return session;
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function withTimeout<T>(promise: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(label)), milliseconds);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function readPostgresVersion(cluster: Pool): Promise<string> {
  const result = await cluster.query<{ version: string }>("SELECT current_setting('server_version') AS version");
  return sanitizeMetadata(result.rows[0]?.version ?? "unknown");
}

function environmentMetadata(postgresVersion: string, fastifyVersion: string): Readonly<Record<string, unknown>> {
  const cpu = cpus()[0];
  return {
    dateUtc: new Date().toISOString(),
    hardware: {
      cpuModel: sanitizeMetadata(cpu?.model ?? "unknown"),
      logicalCpuCount: cpus().length,
      totalMemoryGiB: roundMetric(totalmem() / (1024 ** 3)),
    },
    operatingSystem: { platform: platform(), release: sanitizeMetadata(release()), arch: arch() },
    runtime: {
      node: process.version,
      v8: versions.v8,
      fastify: sanitizeMetadata(fastifyVersion),
      postgresql: postgresVersion,
    },
    network: {
      transport: "HTTP and SSE over loopback TCP",
      tls: false,
      proxy: false,
      listeners: TENANT_COUNT,
      postgresqlUsesNonDefaultPort: true,
    },
  };
}

function discoverLocalAdminUrl(): string {
  let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
  if (!candidate && existsSync(installFile)) {
    const value: unknown = JSON.parse(readFileSync(installFile, "utf8"));
    if (isRecord(value) && typeof value["DATABASE_ADMIN_URL"] === "string") candidate = value["DATABASE_ADMIN_URL"];
  }
  if (!candidate) throw new Error("Local PostgreSQL administrator configuration is unavailable");
  assertNonDefaultLoopbackUrl(candidate, "postgres");
  return new URL(candidate).toString();
}

function assertNonDefaultLoopbackUrl(value: string, expectedDatabase: string): void {
  assertExactLocalPostgresUrl(value, expectedDatabase);
}

function assertSameWorkspaceCluster(adminUrl: string, controlUrl: string): void {
  assertSameExactLocalPostgresCluster(adminUrl, "postgres", controlUrl, CONTROL_DATABASE);
}

function adminPoolConfig(databaseAdminUrl: string): PoolConfig {
  return { ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres"), max: 1 };
}

function resolveWorkspaceRoot(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(moduleDirectory, "../../.."),
    path.resolve(moduleDirectory, "../../../.."),
    process.cwd(),
    path.resolve(process.cwd(), "../.."),
  ];
  const root = candidates.find((candidate) => existsSync(path.join(candidate, "pnpm-workspace.yaml")));
  if (!root) throw new Error("AC-37 scale workspace root is unavailable");
  return root;
}

function sanitizeMetadata(value: string): string {
  return value.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
}

function sanitizeStage(value: string): string {
  return value.replace(/[^a-z0-9-]+/gi, "-").slice(0, 80);
}

function roundMetric(value: number): number {
  return Number(value.toFixed(3));
}

function writeReport(report: PerformanceReport): void {
  if (report.inProgress !== (report.status === "in-progress") || report.overallPass !== (report.status === "passed")) {
    throw new Error("Refusing to publish an internally inconsistent AC-37 scale report state");
  }
  const cleanup = report.cleanup;
  const cleanupClosureComplete = cleanup?.pass === true
    && cleanup.controlRows === 0
    && cleanup.databases === 0
    && cleanup.roles === 0
    && cleanup.operationalControlUnchanged
    && cleanup.protectedDatabasesBefore !== null
    && cleanup.protectedDatabasesAfter !== null
    && cleanup.protectedDatabasesUnchanged
    && completeProtectedFingerprintSet(cleanup.protectedDatabasesBefore)
    && completeProtectedFingerprintSet(cleanup.protectedDatabasesAfter)
    && cleanup.globalInventoryUnchanged
    && cleanup.ephemeralResourcesBefore?.pass === true
    && cleanup.ephemeralResourcesBefore.orphanDatabases === 0
    && cleanup.ephemeralResourcesBefore.orphanRoles === 0
    && cleanup.ephemeralResourcesAfter?.pass === true
    && cleanup.ephemeralResourcesAfter.orphanDatabases === 0
    && cleanup.ephemeralResourcesAfter.orphanRoles === 0;
  if (report.status === "passed" && (!report.overallPass || report.inProgress || !cleanupClosureComplete)) {
    throw new Error("Refusing to publish an inconsistent green AC-37 scale report");
  }
  writeJsonEvidenceAtomic(artifactFile, report);
}

function scaleDataset(): Readonly<Record<string, unknown>> {
  return {
    tenantCount: TENANT_COUNT,
    participantsPerTenant: PARTICIPANTS_PER_TENANT,
    authenticatedSessions: TOTAL_PARTICIPANTS,
    membersPerTenant: MEMBERS_PER_TENANT,
    membersTotal: TENANT_COUNT * MEMBERS_PER_TENANT,
    roundsPerTenant: 1,
    roundKind: "proposal",
    realConcurrentHttpMutations: TOTAL_PARTICIPANTS,
    realHttpReads: TOTAL_PARTICIPANTS * 2,
    concurrentReaderSessions: TOTAL_PARTICIPANTS,
    readsPerParticipant: 2,
    realConcurrentSseStreams: TENANT_COUNT,
    isolation: "one isolated ephemeral control database and least-privilege runtime role plus ten isolated ephemeral tenant databases and runtime roles with exact-name cleanup",
    protectedOperationalTenantsTouched: 0,
    topology: "ten loopback Fastify listeners sharing one PostgreSQL cluster and one run-scoped ephemeral control plane",
    topologyReason: "preserves the production IP rate limiter while localhost represents every synthetic user as 127.0.0.1",
  };
}

function scaleThresholds(): Readonly<Record<string, number>> {
  return {
    acknowledgementP95MsExclusive: ACKNOWLEDGEMENT_P95_BUDGET_MS,
    ssePropagationP95MsExclusive: SSE_PROPAGATION_P95_BUDGET_MS,
    representativeReadP95MsExclusive: REPRESENTATIVE_READ_P95_BUDGET_MS,
    unexpectedFailures: 0,
    requiredTenants: TENANT_COUNT,
    requiredParticipantsPerTenant: PARTICIPANTS_PER_TENANT,
    requiredMembersPerTenant: MEMBERS_PER_TENANT,
  };
}

function printSummary(report: PerformanceReport): void {
  const submissions = report.submissions?.["metrics"] as LatencySummary | undefined;
  const propagation = report.propagation?.["metrics"] as LatencySummary | undefined;
  const reads = report.reads?.["combined"] as WorkloadResult | undefined;
  process.stdout.write(`${[
    `AC-37 scale ${report.overallPass ? "PASS" : "FAIL"}`,
    `dataset: tenants=${TENANT_COUNT} participants=${PARTICIPANTS_PER_TENANT}/tenant members=${MEMBERS_PER_TENANT}/tenant`,
    submissions ? `acknowledgements: count=${submissions.count} p95=${submissions.p95Ms}ms budget=${ACKNOWLEDGEMENT_P95_BUDGET_MS}ms` : "acknowledgements: unavailable",
    propagation ? `SSE propagation: count=${propagation.count} p95=${propagation.p95Ms}ms budget=${SSE_PROPAGATION_P95_BUDGET_MS}ms` : "SSE propagation: unavailable",
    reads ? `representative reads: count=${reads.metrics.count} p95=${reads.metrics.p95Ms}ms` : "representative reads: unavailable",
    report.cleanup
      ? `cleanup: isolated-control-rows=${report.cleanup.controlRows} databases=${report.cleanup.databases} roles=${report.cleanup.roles} protected-databases-unchanged=${report.cleanup.protectedDatabasesUnchanged} global-orphans-before=${report.cleanup.ephemeralResourcesBefore?.orphanDatabases ?? "unknown"}/${report.cleanup.ephemeralResourcesBefore?.orphanRoles ?? "unknown"} global-orphans-after=${report.cleanup.ephemeralResourcesAfter?.orphanDatabases ?? "unknown"}/${report.cleanup.ephemeralResourcesAfter?.orphanRoles ?? "unknown"} pass=${report.cleanup.pass}`
      : "cleanup: unavailable",
    "artifact: artifacts/performance-scale-local.json",
  ].join("\n")}\n`);
}

function selfCheck(): void {
  const runId = randomUUID();
  const controlDatabaseName = expectedControlDatabaseName(runId);
  const fixtures = Array.from({ length: TENANT_COUNT }, (_, index) => {
    const tenant = temporaryTenant(index);
    tenant.namesVerifiedUnused = true;
    tenant.provisioningAttempted = true;
    tenant.cleanupAuthorized = true;
    return tenant;
  });
  const checks = [
    TENANT_COUNT === 10,
    PARTICIPANTS_PER_TENANT === 50,
    MEMBERS_PER_TENANT === 10_000,
    TOTAL_PARTICIPANTS === 500,
    ACKNOWLEDGEMENT_P95_BUDGET_MS === 1_500,
    SSE_PROPAGATION_P95_BUDGET_MS === 2_000,
    percentile([1, 2, 3, 4, 5], 0.95) === 5,
    /^nom_t_[0-9a-f]{32}$/.test(`nom_t_${"a".repeat(32)}`),
    !/^nom_t_[0-9a-f]{32}$/.test("nombramientos_control"),
    expectGuardPasses(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@127.0.0.1:55432/postgres", "postgres")),
    expectGuardPasses(() => assertNonDefaultLoopbackUrl("postgresql://nom_control:redacted@127.0.0.1:55432/nombramientos_control", CONTROL_DATABASE)),
    expectGuardPasses(() => assertSameWorkspaceCluster(
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres",
      "postgresql://nom_control:redacted@127.0.0.1:55432/nombramientos_control",
    )),
    expectGuardPasses(() => assertGeneratedControlIdentity(runId, controlDatabaseName)),
    expectGuardPasses(() => assertGeneratedControlRuntimeIdentity(runId, expectedControlRuntimeRole(runId))),
    expectGuardPasses(() => assertGeneratedControlTarget(runId, controlDatabaseName, true, true)),
    expectGuardPasses(() => assertCleanupScope(fixtures)),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@127.0.0.1:5432/postgres", "postgres")),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@127.0.0.1:5433/postgres", "postgres")),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@localhost:55432/postgres", "postgres")),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@db.example:55432/postgres", "postgres")),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@127.0.0.1:55432/postgres?host=db.example&port=5432", "postgres")),
    expectGuardRejects(() => assertNonDefaultLoopbackUrl("postgresql://nom_admin:redacted@127.0.0.1:55432/nombramientos_control", "postgres")),
    expectGuardRejects(() => assertCleanupScope([{ ...fixtures[0]!, databaseName: "nombramientos_demo" }])),
    expectGuardRejects(() => assertCleanupScope([{ ...fixtures[0]!, databaseName: "ozama" }])),
    expectGuardRejects(() => assertCleanupScope([{ ...fixtures[0]!, databaseName: CONTROL_DATABASE }])),
    expectGuardRejects(() => assertGeneratedControlTarget(runId, controlDatabaseName, false, true)),
    expectGuardRejects(() => assertGeneratedControlTarget(runId, controlDatabaseName, true, false)),
    expectGuardRejects(() => assertGeneratedControlTarget(runId, CONTROL_DATABASE, true, true)),
    expectGuardRejects(() => assertGeneratedControlTarget(runId, "nombramientos_demo", true, true)),
    expectGuardRejects(() => assertGeneratedControlTarget(runId, "ozama", true, true)),
    expectGuardRejects(() => assertGeneratedControlRuntimeIdentity(runId, "nom_control")),
    expectGuardRejects(() => assertGeneratedControlRuntimeIdentity(runId, `nom_cr_${"a".repeat(32)}`)),
  ];
  if (checks.some((check) => !check)) throw new Error("AC-37 scale self-check failed");
  process.stdout.write("AC-37 scale self-check PASS: exact 10x50x10000 scenario, budgets and cleanup guards\n");
}

function assertGeneratedControlIdentity(runId: string, databaseName: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(runId)) {
    throw new Error("AC-37 scale control run id is not a generated UUIDv4");
  }
  if (
    databaseName !== expectedControlDatabaseName(runId)
    || databaseName === CONTROL_DATABASE
    || databaseName === "nombramientos_demo"
    || databaseName === "ozama"
  ) throw new Error("AC-37 scale control database does not match its generated run identity");
}

function assertGeneratedControlRuntimeIdentity(runId: string, role: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(runId)) {
    throw new Error("AC-37 scale control runtime run id is not a generated UUIDv4");
  }
  if (
    role !== expectedControlRuntimeRole(runId)
    || !/^nom_cr_[0-9a-f]{32}$/u.test(role)
    || new Set(["nom_admin", "nom_control", "nombramientos_control", "nombramientos_demo", "ozama"]).has(role)
  ) throw new Error("AC-37 scale control runtime role does not match its generated run identity");
}

function assertGeneratedControlRuntimeTarget(state: ScaleState): void {
  assertGeneratedControlRuntimeIdentity(state.runId, state.controlRuntimeRole);
  if (state.controlRuntimeRoleCreatedByRun !== true || state.controlRuntimeRoleCleanupAuthorized !== true) {
    throw new Error("AC-37 scale control runtime cleanup lacks creation and marker authorization");
  }
}

function assertGeneratedControlTarget(
  runId: string,
  databaseName: string,
  createdByRun: boolean | undefined,
  cleanupAuthorized: boolean | undefined,
): void {
  assertGeneratedControlIdentity(runId, databaseName);
  if (createdByRun !== true || cleanupAuthorized !== true) {
    throw new Error("AC-37 scale control cleanup was not authorized by exact creation and run-marker checks");
  }
}

function assertCleanupScope(tenants: readonly TenantFixture[]): void {
  if (tenants.length > TENANT_COUNT) throw new Error("AC-37 scale cleanup exceeds the generated tenant count");
  const unique = (values: readonly string[]) => new Set(values).size === values.length;
  if (
    !unique(tenants.map((tenant) => tenant.tenantId))
    || !unique(tenants.map((tenant) => tenant.databaseName))
    || !unique(tenants.flatMap((tenant) => [tenant.ownerRole, tenant.runtimeRole]))
    || !unique(tenants.flatMap((tenant) => tenant.sessions.map((session) => session.id)))
    || !unique(tenants.flatMap((tenant) => tenant.sessions.map((session) => session.identityId)))
  ) throw new Error("AC-37 scale cleanup targets must be unique");
  for (const tenant of tenants) assertGeneratedTenant(tenant);
}

function assertGeneratedTenant(tenant: TenantFixture): void {
  if (
    tenant.cleanupAuthorized !== true
    || tenant.namesVerifiedUnused !== true
    || tenant.provisioningAttempted !== true
  ) throw new Error("AC-37 scale cleanup target was not authorized by its exact preflight attempt ledger");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(tenant.tenantId)) {
    throw new Error("AC-37 scale cleanup tenant id is not a generated UUIDv4");
  }
  const suffix = tenant.tenantId.replaceAll("-", "").toLowerCase();
  if (
    tenant.index < 0
    || tenant.index >= TENANT_COUNT
    || tenant.label !== `tenant-${String(tenant.index + 1).padStart(2, "0")}`
    || tenant.databaseName !== `nom_t_${suffix}`
    || tenant.ownerRole !== `nom_o_${suffix}`
    || tenant.runtimeRole !== `nom_r_${suffix}`
    || tenant.secretReference !== `tenant-db/${tenant.tenantId}/runtime/v1`
    || tenant.sessions.length !== PARTICIPANTS_PER_TENANT
    || tenant.sessions.some((session) => session.tenantId !== tenant.tenantId || session.tenantIndex !== tenant.index)
  ) throw new Error("AC-37 scale cleanup target does not match its generated fixture identity");
}

function expectGuardPasses(work: () => void): boolean {
  try { work(); return true; } catch { return false; }
}

function expectGuardRejects(work: () => void): boolean {
  try { work(); return false; } catch { return true; }
}

const temporaryCatalog = {
  version: "ac37-scale-v1",
  departments: [{
    canonicalCode: "ac37-scale-department",
    names: { es: "Departamento sintético", en: "Synthetic department", fr: "Département synthétique" },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "ac37-scale-office",
    departmentCode: "ac37-scale-department",
    names: { es: "Cargo sintético", en: "Synthetic office", fr: "Poste synthétique" },
    mechanism: "church_election_after_nominating_report",
    cardinality: { minimum: 1, maximum: 1 },
  }],
} as const;

main().catch(() => {
  process.stderr.write(`AC-37 scale FAIL at ${sanitizeStage(executionStage)}: the local runner could not complete safely; no sensitive diagnostic values were printed.\n`);
  process.exitCode = 1;
});
