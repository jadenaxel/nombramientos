import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { arch, cpus, platform, release, totalmem } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { versions } from "node:process";
import {
  DatabaseRuntime,
  MemorySecretProvider,
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
  assertExactLocalPostgresUrl,
  exactLocalPostgresPoolConfig,
} from "./local-performance-database-guards.js";
import {
  planPerformanceCleanup,
  type PerformanceCleanupJob,
  type PerformanceCleanupPlan,
  type PerformanceCleanupRoute,
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
const ORIGIN = "http://127.0.0.1:3000";
const USER_AGENT = "nombramientos-ac37-local-load";
const ELECTOR_COUNT = 100;
const READS_PER_ENDPOINT = 100;
const ACKNOWLEDGEMENT_P95_BUDGET_MS = 1_500;
const READ_P95_BUDGET_MS = 2_000;
const REQUEST_TIMEOUT_MS = 15_000;
const workspaceRoot = resolveWorkspaceRoot();
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const artifactFile = path.join(workspaceRoot, "artifacts", "performance-local.json");
let executionStage = "configuration";

function resolveWorkspaceRoot(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(moduleDirectory, "../../.."),
    path.resolve(moduleDirectory, "../../../.."),
    process.cwd(),
    path.resolve(process.cwd(), "../.."),
  ];
  const root = candidates.find((candidate) => existsSync(path.join(candidate, "pnpm-workspace.yaml")));
  if (!root) throw new Error("AC-37 workspace root is unavailable");
  return root;
}

interface TestSession {
  readonly id: string;
  readonly identityId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
}

interface RoundFixture {
  readonly id: string;
  readonly cycleId: string;
  readonly candidateId: string;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
}

interface SubmissionPayload {
  readonly kind: "proposal";
  readonly expectedVersion: number;
  readonly envelope: EncryptedEnvelope;
  readonly contentHash: string;
}

interface CleanupState {
  app?: FastifyInstance;
  provisioner?: TenantProvisioner;
  tenant?: Pool;
  readonly control: Pool;
  readonly cluster: Pool;
  readonly databaseAdminUrl: string;
  readonly tenantId: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly provisioningKey: string;
  readonly tenantSlug: string;
  readonly tenantDisplayName: string;
  readonly secretReference: string;
  readonly provisioningRequestHash: string;
  readonly identityIds: readonly string[];
  readonly sessionIds: readonly string[];
  readonly protectedDatabaseFingerprints: ProtectedDatabaseFingerprints;
  readonly ephemeralResourcesBefore: EphemeralResourceInventory;
  namesVerifiedUnused?: boolean;
  provisioningAttempted?: boolean;
  cleanupAuthorized?: boolean;
}

interface PerformanceFixture {
  baseUrl: string;
  readonly config: ApiConfig;
  readonly secrets: MemorySecretProvider;
  readonly tenant: Pool;
  readonly tenantId: string;
  readonly tenantKey: Buffer;
  readonly tenantKeyId: string;
  readonly sessions: readonly TestSession[];
  readonly round: RoundFixture;
  readonly cleanup: CleanupState;
}

interface RequestObservation {
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

interface IntegrityRow {
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

interface WorkloadResult {
  readonly metrics: LatencySummary;
  readonly statusCounts: Readonly<Record<string, number>>;
  readonly errorCodeCounts: Readonly<Record<string, number>>;
  readonly unexpectedFailures: number;
  readonly responseValidationFailures: number;
}

interface PerformanceReport {
  readonly schemaVersion: 3;
  readonly acceptanceCriterion: "AC-37";
  readonly startedAtUtc: string;
  completedAtUtc: string;
  status: "in-progress" | "passed" | "failed";
  inProgress: boolean;
  readonly environment: Readonly<Record<string, unknown>>;
  readonly dataset: Readonly<Record<string, unknown>>;
  readonly thresholds: Readonly<Record<string, number>>;
  submissions?: Readonly<Record<string, unknown>>;
  reads?: Readonly<Record<string, unknown>>;
  cleanup?: CleanupResult;
  overallPass: boolean;
  deviations: string[];
}

async function main(): Promise<void> {
  const startedAt = new Date();
  writeReport({
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
    startedAtUtc: startedAt.toISOString(),
    completedAtUtc: startedAt.toISOString(),
    status: "in-progress",
    inProgress: true,
    environment: { state: "pending" },
    dataset: performanceDataset(),
    thresholds: performanceThresholds(),
    overallPass: false,
    deviations: ["run-in-progress"],
  });
  executionStage = "configuration-admin-url";
  const databaseAdminUrl = discoverLocalAdminUrl();
  executionStage = "configuration-api-parse";
  const config = parseApiConfig();
  executionStage = "configuration-control-url";
  assertNonDefaultLoopbackUrl(config.controlDatabaseUrl, CONTROL_DATABASE);
  executionStage = "protected-database-snapshots-before";
  const protectedDatabaseFingerprints = await fingerprintProtectedDatabases(databaseAdminUrl);
  executionStage = "global-ephemeral-resource-inventory-before";
  const ephemeralResourcesBefore = await inspectGlobalEphemeralResources(databaseAdminUrl);
  if (!ephemeralResourcesBefore.pass) {
    throw new Error("Pre-existing ephemeral PostgreSQL resources block AC-37 execution");
  }
  const sessions = Array.from({ length: ELECTOR_COUNT }, () => temporarySession());
  executionStage = "fixture-provisioning";
  const fixture = await createFixture(
    databaseAdminUrl,
    config,
    sessions,
    protectedDatabaseFingerprints,
    ephemeralResourcesBefore,
  );
  executionStage = "environment-metadata";
  const postgresVersion = await readPostgresVersion(fixture.cleanup.cluster);
  const report: PerformanceReport = {
    schemaVersion: 3,
    acceptanceCriterion: "AC-37",
    startedAtUtc: startedAt.toISOString(),
    completedAtUtc: startedAt.toISOString(),
    status: "in-progress",
    inProgress: true,
    environment: environmentMetadata(postgresVersion, fixture.cleanup.app?.version ?? "unknown"),
    dataset: performanceDataset(),
    thresholds: performanceThresholds(),
    overallPass: false,
    deviations: [],
  };

  let executionFailure = false;
  try {
    executionStage = "submission-burst";
    const submissionRun = await runSubmissionBurst(fixture);
    const receiptIds = submissionRun.observations
      .map((observation) => observation.receiptId)
      .filter((value): value is string => value !== null);
    executionStage = "submission-integrity";
    const integrity = await inspectIntegrity(fixture.tenant, fixture.round.id, receiptIds);
    const integrityPass = exactIntegrity(integrity);
    const submissionWorkload = workloadResult(submissionRun.observations, submissionRun.wallMs, 201);
    const submissionBudgetPass = submissionWorkload.metrics.p95Ms < ACKNOWLEDGEMENT_P95_BUDGET_MS;
    report.submissions = {
      transport: "real loopback TCP HTTP",
      concurrency: ELECTOR_COUNT,
      uniqueRequests: ELECTOR_COUNT,
      ...submissionWorkload,
      integrity: {
        electors: integrity.electors,
        submissions: integrity.submissions,
        distinctSubmissionElectors: integrity.distinct_submission_electors,
        distinctSubmissionContentHashes: integrity.distinct_submission_hashes,
        receipts: integrity.receipts,
        distinctReceiptSubmissions: integrity.distinct_receipt_submissions,
        distinctReceiptElectors: integrity.distinct_receipt_electors,
        receiptsReturnedByApi: integrity.returned_receipts,
        idempotencyRecords: integrity.idempotency_records,
        auditEvents: integrity.audit_events,
        outboxEvents: integrity.outbox_events,
        pass: integrityPass,
      },
      budgetPass: submissionBudgetPass,
      pass: integrityPass
        && submissionBudgetPass
        && submissionWorkload.unexpectedFailures === 0
        && submissionWorkload.responseValidationFailures === 0,
    };
    if (!integrityPass) report.deviations.push("submission-integrity-mismatch");
    if (!submissionBudgetPass) report.deviations.push("acknowledgement-p95-not-under-1500ms");
    if (submissionWorkload.unexpectedFailures !== 0) report.deviations.push("unexpected-submission-failures");
    if (submissionWorkload.responseValidationFailures !== 0) report.deviations.push("invalid-submission-responses");

    executionStage = "read-snapshot-before";
    const beforeReads = await tenantReadSnapshot(fixture.tenant, fixture.round.id);
    executionStage = "listener-restart";
    await restartApi(fixture);
    executionStage = "read-burst";
    const readRun = await runReadBurst(fixture);
    executionStage = "read-snapshot-after";
    const afterReads = await tenantReadSnapshot(fixture.tenant, fixture.round.id);
    const noTenantMutation = JSON.stringify(beforeReads) === JSON.stringify(afterReads);
    const dashboard = workloadResult(readRun.dashboard, readRun.wallMs, 200);
    const members = workloadResult(readRun.members, readRun.wallMs, 200);
    const combined = workloadResult([...readRun.dashboard, ...readRun.members], readRun.wallMs, 200);
    const readBudgetPass = combined.metrics.p95Ms < READ_P95_BUDGET_MS;
    const readPass = readBudgetPass
      && noTenantMutation
      && combined.unexpectedFailures === 0
      && combined.responseValidationFailures === 0;
    report.reads = {
      transport: "real loopback TCP HTTP GET",
      concurrency: READS_PER_ENDPOINT * 2,
      totalRequests: READS_PER_ENDPOINT * 2,
      dashboard,
      memberList: members,
      combined,
      tenantBusinessStateUnchanged: noTenantMutation,
      note: "Session last-seen bookkeeping is outside the tenant business-state snapshot.",
      budgetPass: readBudgetPass,
      pass: readPass,
    };
    if (!readBudgetPass) report.deviations.push("read-p95-over-2000ms");
    if (!noTenantMutation) report.deviations.push("read-scenario-mutated-tenant-state");
    if (combined.unexpectedFailures !== 0) report.deviations.push("unexpected-read-failures");
    if (combined.responseValidationFailures !== 0) report.deviations.push("invalid-read-responses");
  } catch {
    executionFailure = true;
    report.deviations.push("workload-execution-failed");
  } finally {
    try {
      executionStage = "cleanup";
      report.cleanup = await cleanupFixture(fixture.cleanup);
    } catch {
      executionFailure = true;
      report.cleanup = {
        controlRows: -1,
        databases: -1,
        roles: -1,
        operationalControlBefore: protectedDatabaseFingerprints.control,
        operationalControlAfter: null,
        operationalControlUnchanged: false,
        protectedDatabasesBefore: protectedDatabaseFingerprints,
        protectedDatabasesAfter: null,
        protectedDatabasesUnchanged: false,
        ephemeralResourcesBefore,
        ephemeralResourcesAfter: null,
        globalInventoryUnchanged: false,
        pass: false,
      };
      report.deviations.push("ephemeral-cleanup-failed");
    }
  }

  const submissionsPass = report.submissions?.["pass"] === true;
  const readsPass = report.reads?.["pass"] === true;
  report.overallPass = !executionFailure && submissionsPass && readsPass && report.cleanup?.pass === true;
  report.completedAtUtc = new Date().toISOString();
  report.status = report.overallPass ? "passed" : "failed";
  report.inProgress = false;
  executionStage = "artifact-write";
  writeReport(report);
  printSummary(report);
  if (!report.overallPass) process.exitCode = 1;
}

async function createFixture(
  databaseAdminUrl: string,
  config: ApiConfig,
  sessions: readonly TestSession[],
  protectedDatabaseFingerprints: ProtectedDatabaseFingerprints,
  ephemeralResourcesBefore: EphemeralResourceInventory,
): Promise<PerformanceFixture> {
  const tenantId = randomUUID();
  const suffix = tenantId.replaceAll("-", "");
  const tenantSlug = `ac37-${suffix.slice(0, 24)}`;
  const tenantDisplayName = "AC-37 synthetic temporary tenant";
  const provisioningKey = randomUUID();
  const provisioningRequest = {
    idempotencyKey: provisioningKey,
    tenantId,
    slug: tenantSlug,
    displayName: tenantDisplayName,
    kind: "demo" as const,
    timezone: "America/La_Paz",
    locale: "es" as const,
  };
  const cleanup: CleanupState = {
    control: new Pool({
      ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", CONTROL_DATABASE),
      application_name: "nombramientos-ac37-control",
      max: 4,
    }),
    databaseAdminUrl,
    cluster: new Pool({
      ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres"),
      application_name: "nombramientos-ac37-cluster",
      max: 2,
    }),
    tenantId,
    databaseName: `nom_t_${suffix}`,
    ownerRole: `nom_o_${suffix}`,
    runtimeRole: `nom_r_${suffix}`,
    provisioningKey,
    tenantSlug,
    tenantDisplayName,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
    provisioningRequestHash: tenantProvisionRequestHash(provisioningRequest),
    identityIds: sessions.map((session) => session.identityId),
    sessionIds: sessions.map((session) => session.id),
    protectedDatabaseFingerprints,
    ephemeralResourcesBefore,
  };
  const secrets = new MemorySecretProvider();

  try {
    executionStage = "fixture-name-check";
    await assertTemporaryNamesUnused(cleanup);
    executionStage = "tenant-provisioning";
    cleanup.provisioner = new TenantProvisioner({
      admin: adminPoolConfig(databaseAdminUrl),
      control: cleanup.control,
      secrets,
      catalog: temporaryCatalog,
      migrationsRoot,
    });
    // The in-memory attempt ledger is set only after the exact global preflight
    // and immediately before provisioning can create its first durable marker.
    cleanup.provisioningAttempted = true;
    cleanup.cleanupAuthorized = true;
    const provisioned = await cleanup.provisioner.provision(provisioningRequest);
    if (
      provisioned.database !== cleanup.databaseName
      || provisioned.runtimeRole !== cleanup.runtimeRole
      || provisioned.tenantId !== tenantId
    ) {
      throw new Error("Temporary provisioner metadata mismatch");
    }
    await cleanup.provisioner.close();
    delete cleanup.provisioner;

    executionStage = "tenant-fixture-connection";
    cleanup.tenant = new Pool({
      ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres", cleanup.databaseName),
      application_name: "nombramientos-ac37-fixture",
      max: 4,
    });
    await assertTenantTarget(cleanup.tenant, tenantId);
    executionStage = "control-fixture";
    await insertControlFixture(cleanup.control, tenantId, sessions);
    const tenantKey = randomBytes(32);
    const tenantKeyId = `ac37-key-${suffix.slice(0, 24)}`;
    executionStage = "tenant-fixture";
    const round = await insertTenantFixture(cleanup.tenant, tenantId, sessions, tenantKey, tenantKeyId);
    executionStage = "api-listener";
    const baseUrl = await startApi(cleanup, config, secrets);
    return {
      baseUrl,
      config,
      secrets,
      tenant: cleanup.tenant,
      tenantId,
      tenantKey,
      tenantKeyId,
      sessions,
      round,
      cleanup,
    };
  } catch (setupError) {
    try {
      await cleanupFixture(cleanup);
    } catch {
      throw new Error("AC-37 setup and cleanup failed", { cause: setupError });
    }
    throw setupError;
  }
}

async function assertTemporaryNamesUnused(state: CleanupState): Promise<void> {
  const control = await state.control.query<{ count: number }>(
    `SELECT (
       (SELECT count(*) FROM tenants
         WHERE id=$1 OR slug=$5 OR database_name=$2 OR runtime_role=$3 OR runtime_secret_ref=$6)
       + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$4)
       + (SELECT count(*) FROM platform_identities WHERE id=ANY($7::uuid[]))
       + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=$1 OR identity_id=ANY($7::uuid[]))
       + (SELECT count(*) FROM auth_sessions WHERE active_tenant_id=$1 OR id=ANY($8::uuid[]) OR identity_id=ANY($7::uuid[]))
     )::int AS count`,
    [
      state.tenantId,
      state.databaseName,
      state.runtimeRole,
      state.provisioningKey,
      state.tenantSlug,
      state.secretReference,
      state.identityIds,
      state.sessionIds,
    ],
  );
  const cluster = await state.cluster.query<{ databases: number; roles: number }>(
    `SELECT
       (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
       (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
    [state.databaseName, [state.ownerRole, state.runtimeRole]],
  );
  if (control.rows[0]?.count !== 0 || cluster.rows[0]?.databases !== 0 || cluster.rows[0]?.roles !== 0) {
    throw new Error("AC-37 exact temporary names are already in use");
  }
  state.namesVerifiedUnused = true;
}

async function insertControlFixture(control: Pool, tenantId: string, sessions: readonly TestSession[]): Promise<void> {
  const ids = sessions.map((session) => session.identityId);
  const emails = sessions.map((session, index) => `ac37-${index}-${session.identityId.replaceAll("-", "")}@invalid.example`);
  const sessionIds = sessions.map((session) => session.id);
  const tokenHashes = sessions.map((session) => sha256(session.sessionToken));
  const csrfHashes = sessions.map((session) => sha256(session.csrfToken));
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,status
       )
       SELECT identity_id,email,email,'AC-37 synthetic elector','AC37_DISABLED_LOGIN',false,'active'
         FROM unnest($1::uuid[],$2::text[]) AS fixture(identity_id,email)`,
      [ids, emails],
    );
    await client.query(
      `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
       SELECT $1,identity_id,'active',true FROM unnest($2::uuid[]) AS fixture(identity_id)`,
      [tenantId, ids],
    );
    await client.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash
       )
       SELECT session_id,token_hash,csrf_hash,identity_id,$1,
              clock_timestamp() + interval '30 minutes',$6,$7
         FROM unnest($2::uuid[],$3::text[],$4::text[],$5::uuid[])
              AS fixture(session_id,token_hash,csrf_hash,identity_id)`,
      [tenantId, sessionIds, tokenHashes, csrfHashes, ids, sha256(USER_AGENT), sha256("127.0.0")],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function insertTenantFixture(
  tenant: Pool,
  tenantId: string,
  sessions: readonly TestSession[],
  tenantKey: Uint8Array,
  tenantKeyId: string,
): Promise<RoundFixture> {
  const memberId = randomUUID();
  const cycleId = randomUUID();
  const roundId = randomUUID();
  const candidateId = randomUUID();
  const candidateSetHash = `sha256:${sha256(candidateId)}`;
  const rulesHash = `sha256:${sha256("ac37|proposal|1|100")}`;
  const memberEnvelope = sealAesGcmJson(
    { synthetic: true, displayName: "AC-37 synthetic candidate" },
    tenantKey,
    tenantKeyId,
    { tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
  );
  const client = await tenant.connect();
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
      [sessions.map((session) => session.identityId)],
    );
    if (roles.rows[0]?.bindings !== ELECTOR_COUNT) throw new Error("AC-37 role binding count mismatch");
    await client.query(
      `INSERT INTO members(id,stable_code,display_envelope,display_content_hash,eligibility_status,available)
       VALUES ($1,$2,$3::jsonb,$4,'eligible',true)`,
      [memberId, `AC37-${memberId.slice(0, 8)}`, memberEnvelope, envelopeContentHash(memberEnvelope)],
    );
    const office = await client.query<{ id: string }>("SELECT id::text FROM offices ORDER BY canonical_code LIMIT 1");
    const officeId = office.rows[0]?.id;
    if (!officeId) throw new Error("AC-37 temporary catalog has no office");
    await client.query(
      `INSERT INTO election_cycles(
         id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count
       ) VALUES ($1,'AC-37 synthetic cycle','active','es','America/La_Paz',DATE '2027-01-01',DATE '2027-12-31','ac37-v1',$2)`,
      [cycleId, ELECTOR_COUNT],
    );
    await client.query(
      "INSERT INTO vacancies(cycle_id,office_id,ordinal,status) VALUES ($1,$2,1,'pending')",
      [cycleId, officeId],
    );
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
      [roundId, sessions.map((session) => session.identityId)],
    );
    await client.query(
      `INSERT INTO candidate_snapshots(
         round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
         member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
         eligibility_evaluated_on,eligibility_effective
       ) SELECT $1,$2,member.id,$4::jsonb,true,1,0,member.version,
                member.eligibility_department_id,member.eligibility_valid_until,
                (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
           FROM members member CROSS JOIN tenant_settings settings
          WHERE member.id=$3 AND settings.singleton=true`,
      [roundId, candidateId, memberId, memberEnvelope],
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

async function startApi(state: CleanupState, config: ApiConfig, secrets: MemorySecretProvider): Promise<string> {
  if (state.app) throw new Error("AC-37 API listener is already running");
  const database = new DatabaseRuntime({
    control: {
      ...exactLocalPostgresPoolConfig(config.controlDatabaseUrl, CONTROL_DATABASE),
      application_name: "nombramientos-ac37-api",
      max: 20,
      ssl: false,
    },
    secretProvider: secrets,
    tenantPoolMax: 20,
    tenantPoolIdleMs: 30_000,
  });
  const app = await buildServer({ config, database, logger: false });
  state.app = app;
  await app.listen({ host: "127.0.0.1", port: 0 });
  const address = app.server.address();
  if (!address || typeof address === "string") throw new Error("AC-37 listener has no TCP address");
  return `http://127.0.0.1:${(address as AddressInfo).port}`;
}

async function restartApi(fixture: PerformanceFixture): Promise<void> {
  if (!fixture.cleanup.app) throw new Error("AC-37 write listener is unavailable");
  await fixture.cleanup.app.close();
  delete fixture.cleanup.app;
  fixture.baseUrl = await startApi(fixture.cleanup, fixture.config, fixture.secrets);
}

async function runSubmissionBurst(
  fixture: PerformanceFixture,
): Promise<{ readonly observations: readonly RequestObservation[]; readonly wallMs: number }> {
  const payloads = fixture.sessions.map(() => createSubmissionPayload(fixture));
  if (new Set(payloads.map((payload) => payload.contentHash)).size !== ELECTOR_COUNT) {
    throw new Error("AC-37 generated submission payloads are not unique");
  }
  const started = performance.now();
  const observations = await Promise.all(fixture.sessions.map(async (session, index) => {
    const payload = payloads[index];
    if (!payload) throw new Error("AC-37 payload index mismatch");
    return submit(fixture, session, randomUUID(), payload);
  }));
  return { observations, wallMs: performance.now() - started };
}

async function runReadBurst(fixture: PerformanceFixture): Promise<{
  readonly dashboard: readonly RequestObservation[];
  readonly members: readonly RequestObservation[];
  readonly wallMs: number;
}> {
  const started = performance.now();
  const [dashboard, members] = await Promise.all([
    Promise.all(fixture.sessions.map(async (session) => read(fixture, session, "/v1/dashboard", "dashboard"))),
    Promise.all(fixture.sessions.map(async (session) => read(fixture, session, "/v1/members?limit=1", "members"))),
  ]);
  return { dashboard, members, wallMs: performance.now() - started };
}

function createSubmissionPayload(fixture: PerformanceFixture): SubmissionPayload {
  const envelope = sealAesGcmJson(
    { schema: "nombramientos-submission/v1", abstain: false, selections: [fixture.round.candidateId] },
    fixture.tenantKey,
    fixture.tenantKeyId,
    {
      tenantId: fixture.tenantId,
      cycleId: fixture.round.cycleId,
      roundId: fixture.round.id,
      purpose: "proposal",
      schemaVersion: 1,
      roundVersion: 1,
      candidateSetHash: fixture.round.candidateSetHash,
      rulesHash: fixture.round.rulesHash,
    },
  );
  return { kind: "proposal", expectedVersion: 1, envelope, contentHash: envelopeContentHash(envelope) };
}

async function submit(
  fixture: PerformanceFixture,
  session: TestSession,
  idempotencyKey: string,
  payload: SubmissionPayload,
): Promise<RequestObservation> {
  const started = performance.now();
  try {
    const response = await fetch(`${fixture.baseUrl}/v1/rounds/${fixture.round.id}/submissions`, {
      method: "POST",
      headers: requestHeaders(session, {
        "content-type": "application/json",
        "x-csrf-token": session.csrfToken,
        "idempotency-key": idempotencyKey,
      }),
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const body = await safeJson(response);
    const data = apiData(body);
    const receiptId = typeof data?.["receiptId"] === "string" ? data["receiptId"] : null;
    return {
      latencyMs: performance.now() - started,
      status: response.status,
      errorCode: apiErrorCode(body),
      valid: response.status === 201
        && isUuid(receiptId)
        && data?.["roundId"] === fixture.round.id
        && data?.["roundVersion"] === 1
        && data?.["contentHash"] === payload.contentHash
        && data?.["status"] === "received",
      receiptId,
    };
  } catch {
    return networkFailure(performance.now() - started);
  }
}

async function read(
  fixture: PerformanceFixture,
  session: TestSession,
  route: string,
  kind: "dashboard" | "members",
): Promise<RequestObservation> {
  const started = performance.now();
  try {
    const response = await fetch(fixture.baseUrl + route, {
      method: "GET",
      headers: requestHeaders(session),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const body = await safeJson(response);
    const data = apiData(body);
    const valid = kind === "dashboard"
      ? response.status === 200
        && isRecord(data?.["tenant"])
        && data["tenant"]["id"] === fixture.tenantId
        && isRecord(data["metrics"])
      : response.status === 200
        && Array.isArray(data?.["items"])
        && data["items"].length === 1
        && data["total"] === 1;
    return {
      latencyMs: performance.now() - started,
      status: response.status,
      errorCode: apiErrorCode(body),
      valid,
      receiptId: null,
    };
  } catch {
    return networkFailure(performance.now() - started);
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
    throughputRequestsPerSecond: roundMetric(sorted.length / (wallMs / 1_000)),
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

async function inspectIntegrity(tenant: Pool, roundId: string, receiptIds: readonly string[]): Promise<IntegrityRow> {
  const result = await tenant.query<IntegrityRow>(
    `SELECT
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
    [roundId, receiptIds],
  );
  const row = result.rows[0];
  if (!row) throw new Error("AC-37 integrity query returned no row");
  return row;
}

function exactIntegrity(row: IntegrityRow): boolean {
  return row.electors === ELECTOR_COUNT
    && row.submissions === ELECTOR_COUNT
    && row.distinct_submission_electors === ELECTOR_COUNT
    && row.distinct_submission_hashes === ELECTOR_COUNT
    && row.receipts === ELECTOR_COUNT
    && row.distinct_receipt_submissions === ELECTOR_COUNT
    && row.distinct_receipt_electors === ELECTOR_COUNT
    && row.returned_receipts === ELECTOR_COUNT
    && row.idempotency_records === ELECTOR_COUNT
    && row.audit_events === ELECTOR_COUNT
    && row.outbox_events === ELECTOR_COUNT;
}

async function tenantReadSnapshot(tenant: Pool, roundId: string): Promise<TenantReadSnapshot> {
  const result = await tenant.query<TenantReadSnapshot>(
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
    [roundId],
  );
  const row = result.rows[0];
  if (!row) throw new Error("AC-37 read-only snapshot returned no row");
  return row;
}

async function cleanupFixture(state: CleanupState): Promise<CleanupResult> {
  let cleanupFailed = false;
  const clean = async (work: () => Promise<unknown>): Promise<void> => {
    try {
      await work();
    } catch {
      cleanupFailed = true;
    }
  };
  if (state.app) {
    await clean(async () => state.app!.close());
    delete state.app;
  }
  if (state.tenant) {
    await clean(async () => state.tenant!.end());
    delete state.tenant;
  }
  if (state.provisioner) {
    await clean(async () => state.provisioner!.close());
    delete state.provisioner;
  }

  let cleanupPlan: PerformanceCleanupPlan | undefined;
  if (
    state.cleanupAuthorized === true
    && state.namesVerifiedUnused === true
    && state.provisioningAttempted === true
  ) {
    try {
      cleanupPlan = await inspectLocalCleanupOwnership(state);
      await state.control.query(
        "DELETE FROM auth_sessions WHERE active_tenant_id=$1 OR id=ANY($2::uuid[]) OR identity_id=ANY($3::uuid[])",
        [state.tenantId, state.sessionIds, state.identityIds],
      );
      await state.control.query(
        "DELETE FROM tenant_memberships WHERE tenant_id=$1 OR identity_id=ANY($2::uuid[])",
        [state.tenantId, state.identityIds],
      );
      await state.control.query("DELETE FROM platform_identities WHERE id=ANY($1::uuid[])", [state.identityIds]);
      await state.control.query("DELETE FROM tenants WHERE id=$1", [state.tenantId]);
      await state.control.query(
        "DELETE FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$2",
        [state.tenantId, state.provisioningKey],
      );
    } catch {
      cleanupFailed = true;
    }
    if (cleanupPlan?.databases.includes(state.databaseName)) {
      await clean(async () => dropDatabase(state.cluster, state.databaseName));
    }
    if (cleanupPlan?.roles.includes(state.runtimeRole)) {
      await clean(async () => dropRole(state.cluster, state.runtimeRole));
    }
    if (cleanupPlan?.roles.includes(state.ownerRole)) {
      await clean(async () => dropRole(state.cluster, state.ownerRole));
    }
  }

  let controlRows = -1;
  let databases = -1;
  let roles = -1;
  await clean(async () => {
    const control = await state.control.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM auth_sessions WHERE active_tenant_id=$1 OR id=ANY($2::uuid[]) OR identity_id=ANY($3::uuid[]))
         + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=$1 OR identity_id=ANY($3::uuid[]))
         + (SELECT count(*) FROM platform_identities WHERE id=ANY($3::uuid[]))
         + (SELECT count(*) FROM tenants WHERE id=$1)
         + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$4)
       )::int AS count`,
      [state.tenantId, state.sessionIds, state.identityIds, state.provisioningKey],
    );
    controlRows = control.rows[0]?.count ?? -1;
    const cluster = await state.cluster.query<{ databases: number; roles: number }>(
      `SELECT
         (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
         (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
      [state.databaseName, [state.ownerRole, state.runtimeRole]],
    );
    databases = cluster.rows[0]?.databases ?? -1;
    roles = cluster.rows[0]?.roles ?? -1;
    if (controlRows !== 0 || databases !== 0 || roles !== 0) throw new Error("AC-37 cleanup verification failed");
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
  const protectedDatabasesBefore = state.protectedDatabaseFingerprints;
  const protectedDatabasesUnchanged = protectedFingerprintSetsEqual(
    protectedDatabasesBefore,
    protectedDatabasesAfter,
  );
  const operationalControlBefore = protectedDatabasesBefore.control;
  const operationalControlAfter = protectedDatabasesAfter?.control ?? null;
  const operationalControlUnchanged = operationalControlAfter !== null
    && JSON.stringify(operationalControlBefore) === JSON.stringify(operationalControlAfter);
  const globalInventoryUnchanged = globalInventorySetsEqual(
    state.ephemeralResourcesBefore,
    ephemeralResourcesAfter,
  );
  if (
    !protectedDatabasesUnchanged
    || !operationalControlUnchanged
    || !globalInventoryUnchanged
    || state.ephemeralResourcesBefore.pass !== true
    || ephemeralResourcesAfter?.pass !== true
  ) cleanupFailed = true;
  await clean(async () => state.control.end());
  await clean(async () => state.cluster.end());
  const pass = !cleanupFailed
    && controlRows === 0
    && databases === 0
    && roles === 0
    && operationalControlUnchanged
    && protectedDatabasesUnchanged
    && globalInventoryUnchanged
    && state.ephemeralResourcesBefore.pass
    && ephemeralResourcesAfter?.pass === true;
  if (!pass) throw new Error("AC-37 temporary fixture cleanup did not complete");
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
    ephemeralResourcesBefore: state.ephemeralResourcesBefore,
    ephemeralResourcesAfter,
    globalInventoryUnchanged,
    pass,
  };
}

async function inspectLocalCleanupOwnership(state: CleanupState): Promise<PerformanceCleanupPlan> {
  const [routes, jobs, databases, roles] = await Promise.all([
    state.control.query<PerformanceCleanupRoute>(
      `SELECT id::text,slug,display_name,kind,status,timezone,locale,database_host,database_port,
              database_name::text,runtime_role::text,runtime_secret_ref,credential_version,ssl_mode
         FROM tenants
        WHERE id=$1 OR slug=$2 OR database_name=$3 OR runtime_role=$4 OR runtime_secret_ref=$5`,
      [state.tenantId, state.tenantSlug, state.databaseName, state.runtimeRole, state.secretReference],
    ),
    state.control.query<PerformanceCleanupJob>(
      `SELECT idempotency_key::text,tenant_id::text,requested_slug,request_hash,state,attempt_count
         FROM provisioning_jobs WHERE tenant_id=$1 OR idempotency_key=$2`,
      [state.tenantId, state.provisioningKey],
    ),
    state.cluster.query<{ name: string }>(
      "SELECT datname::text AS name FROM pg_database WHERE datname=$1 ORDER BY datname",
      [state.databaseName],
    ),
    state.cluster.query<{ name: string }>(
      "SELECT rolname::text AS name FROM pg_roles WHERE rolname=ANY($1::text[]) ORDER BY rolname",
      [[state.ownerRole, state.runtimeRole]],
    ),
  ]);
  return planPerformanceCleanup([{
    tenantId: state.tenantId,
    databaseName: state.databaseName,
    ownerRole: state.ownerRole,
    runtimeRole: state.runtimeRole,
    provisioningKey: state.provisioningKey,
    tenantSlug: state.tenantSlug,
    displayName: state.tenantDisplayName,
    secretReference: state.secretReference,
    requestHash: state.provisioningRequestHash,
    namesVerifiedUnused: state.namesVerifiedUnused === true,
    provisioningAttempted: state.provisioningAttempted === true,
  }], {
    routes: routes.rows,
    jobs: jobs.rows,
    databases: databases.rows.map(({ name }) => name),
    roles: roles.rows.map(({ name }) => name),
  }, 1);
}

async function dropDatabase(cluster: Pool, databaseName: string): Promise<void> {
  if (!/^nom_t_[0-9a-f]{32}$/.test(databaseName)) throw new Error("Refusing to drop a non-temporary database");
  await executeFormatted(cluster, "SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql", [databaseName]);
}

async function dropRole(cluster: Pool, role: string): Promise<void> {
  if (!/^nom_[or]_[0-9a-f]{32}$/.test(role)) throw new Error("Refusing to drop a non-temporary role");
  await executeFormatted(cluster, "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql", [role]);
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format an AC-37 cleanup statement");
  await pool.query(sql);
}

async function assertTenantTarget(tenant: Pool, tenantId: string): Promise<void> {
  const result = await tenant.query<{ database_name: string; tenant_id: string; kind: string }>(
    "SELECT current_database() AS database_name,tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
  );
  const row = result.rows[0];
  if (!row || row.database_name !== `nom_t_${tenantId.replaceAll("-", "")}` || row.tenant_id !== tenantId || row.kind !== "demo") {
    throw new Error("AC-37 temporary tenant target is invalid");
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
    network: { transport: "HTTP over loopback TCP", tls: false, proxy: false, postgresqlUsesNonDefaultPort: true },
  };
}

function writeReport(report: PerformanceReport): void {
  if (report.inProgress !== (report.status === "in-progress") || report.overallPass !== (report.status === "passed")) {
    throw new Error("Refusing to publish an internally inconsistent AC-37 report state");
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
    throw new Error("Refusing to publish an inconsistent green AC-37 report");
  }
  writeJsonEvidenceAtomic(artifactFile, report);
}

function performanceDataset(): Readonly<Record<string, unknown>> {
  return {
    isolation: "ephemeral tenant/database/owner-role/runtime-role; exact-name cleanup",
    tenantKind: "synthetic temporary demo-schema tenant",
    protectedTenantDatabasesTouched: 0,
    protectedControlDatabaseTemporaryRows: true,
    protectedControlDatabaseRestorationRequiredForPass: true,
    electors: ELECTOR_COUNT,
    authenticatedSessions: ELECTOR_COUNT,
    tenantRolePerElector: "COMMITTEE_MEMBER",
    rounds: 1,
    roundKind: "proposal",
    candidates: 1,
    uniqueConcurrentSubmissions: ELECTOR_COUNT,
    concurrentDashboardGets: READS_PER_ENDPOINT,
    concurrentMemberListGets: READS_PER_ENDPOINT,
  };
}

function performanceThresholds(): Readonly<Record<string, number>> {
  return {
    acknowledgementP95MsExclusive: ACKNOWLEDGEMENT_P95_BUDGET_MS,
    readP95MsExclusive: READ_P95_BUDGET_MS,
    unexpectedFailures: 0,
    requiredSubmissions: ELECTOR_COUNT,
    requiredReceipts: ELECTOR_COUNT,
  };
}

function printSummary(report: PerformanceReport): void {
  const submission = report.submissions?.["metrics"] as LatencySummary | undefined;
  const readCombined = report.reads?.["combined"] as WorkloadResult | undefined;
  const cleanup = report.cleanup;
  const lines = [
    `AC-37 ${report.overallPass ? "PASS" : "FAIL"}`,
    submission
      ? `submissions: count=${submission.count} throughput=${submission.throughputRequestsPerSecond}/s p50=${submission.p50Ms}ms p95=${submission.p95Ms}ms p99=${submission.p99Ms}ms`
      : "submissions: unavailable",
    readCombined
      ? `reads: count=${readCombined.metrics.count} throughput=${readCombined.metrics.throughputRequestsPerSecond}/s p50=${readCombined.metrics.p50Ms}ms p95=${readCombined.metrics.p95Ms}ms p99=${readCombined.metrics.p99Ms}ms`
      : "reads: unavailable",
    cleanup
      ? `cleanup: control=${cleanup.controlRows} databases=${cleanup.databases} roles=${cleanup.roles} protected-databases-unchanged=${cleanup.protectedDatabasesUnchanged} global-orphans-before=${cleanup.ephemeralResourcesBefore?.orphanDatabases ?? "unknown"}/${cleanup.ephemeralResourcesBefore?.orphanRoles ?? "unknown"} global-orphans-after=${cleanup.ephemeralResourcesAfter?.orphanDatabases ?? "unknown"}/${cleanup.ephemeralResourcesAfter?.orphanRoles ?? "unknown"} pass=${cleanup.pass}`
      : "cleanup: unavailable",
    "artifact: artifacts/performance-local.json",
  ];
  process.stdout.write(`${lines.join("\n")}\n`);
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

function adminPoolConfig(databaseAdminUrl: string): PoolConfig {
  return { ...exactLocalPostgresPoolConfig(databaseAdminUrl, "postgres"), max: 1 };
}

function temporarySession(): TestSession {
  return {
    id: randomUUID(),
    identityId: randomUUID(),
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
  };
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

function networkFailure(latencyMs: number): RequestObservation {
  return { latencyMs, status: 0, errorCode: "NETWORK_ERROR", valid: false, receiptId: null };
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function sanitizeMetadata(value: string): string {
  return value.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
}

function roundMetric(value: number): number {
  return Number(value.toFixed(3));
}

const temporaryCatalog = {
  version: "ac37-v1",
  departments: [{
    canonicalCode: "ac37-department",
    names: { es: "Departamento sintético", en: "Synthetic department", fr: "Département synthétique" },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "ac37-office",
    departmentCode: "ac37-department",
    names: { es: "Cargo sintético", en: "Synthetic office", fr: "Poste synthétique" },
    mechanism: "church_election_after_nominating_report",
    cardinality: { minimum: 1, maximum: 1 },
  }],
} as const;

main().catch(() => {
  process.stderr.write(`AC-37 FAIL at ${executionStage}: the local runner could not complete safely; no sensitive diagnostic values were printed.\n`);
  process.exitCode = 1;
});
