import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { closeSync, copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server as HttpServer } from "node:http";
import { Socket, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DatabaseRuntime,
  MemorySecretProvider,
  runMigrations,
  sealAesGcmJson,
  TenantProvisioner,
  type EncryptedEnvelope,
} from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { Pool, type PoolConfig } from "pg";
import { buildServer } from "../src/server.js";
import type { ApiConfig } from "../src/config.js";
import {
  PROTECTED_DATABASES,
  PROTECTED_TENANTS,
  REAL_BROWSER_STACK_CHECK_FLAG,
  REAL_BROWSER_STACK_MARKER,
  RESERVED_APPLICATION_PORTS,
  assertCleanupObservation,
  assertEphemeralNames,
  assertGlobalEphemeralResourcesAbsent,
  assertIsolatedHttpOrigin,
  assertProtectedTenantRoutes,
  assertReservedApplicationPortsFree,
  assertRunMarker,
  assertScenarioIntegrity,
  assertWorkspaceAdminUrl,
  createGlobalEphemeralResourceObservation,
  deriveEphemeralNames,
  digestProtectedDatabaseSnapshot,
  observeUnroutedTenantResources,
  requireEphemeralInvocation,
  requireReadOnlyCheckInvocation,
  type CleanupObservation,
  type EphemeralNames,
  type GlobalEphemeralResourceObservation,
  type ProtectedTenantRoute,
  type RegisteredTenantResourceRoute,
  type ReservedApplicationPortObservation,
  type RunMarkerRow,
  type ScenarioIntegrity,
  type UnroutedTenantResourceObservation,
} from "./real-browser-stack-guards.js";

const USER_AGENT = "nombramientos-real-browser-stack-e2e/1";
const CONTROL_MARKER_TABLE = "real_browser_stack_run_marker";
const TENANT_MARKER_TABLE = "real_browser_stack_tenant_marker";
const EPHEMERAL_TENANT_NAME = "Real browser-stack synthetic tenant";
const EPHEMERAL_TENANT_TIMEZONE = "America/La_Paz";
const workspaceRoot = resolveWorkspaceRoot();
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const artifactFile = path.join(workspaceRoot, "artifacts", "real-browser-stack-local.json");
const preflightArtifactFile = path.join(workspaceRoot, "artifacts", "real-browser-stack-preflight.json");
let executionStage = "invocation";

interface TestSession {
  readonly id: string;
  readonly identityId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly role: "CHURCH_ADMIN" | "COMMITTEE_MEMBER" | "TALLY_CUSTODIAN";
}

interface FixtureIds {
  readonly existingHomonymId: string;
  readonly updateTargetId: string;
  readonly createdHomonymId: string;
  readonly skippedMemberId: string;
  readonly cycleId: string;
  readonly roundId: string;
  readonly candidateIds: readonly [string, string];
  readonly candidateSetHash: `sha256:${string}`;
  readonly rulesHash: `sha256:${string}`;
}

interface ClusterCatalogFingerprint {
  readonly digest: `sha256:${string}`;
  readonly databaseCount: number;
  readonly roleCount: number;
  readonly membershipCount: number;
}

interface RunnerState {
  readonly names: EphemeralNames;
  readonly databaseAdminUrl: string;
  readonly cluster: Pool;
  readonly secrets: MemorySecretProvider;
  readonly sessions: {
    readonly admin: TestSession;
    readonly selectionVoter: TestSession;
    readonly abstentionVoter: TestSession;
    readonly custodianOne: TestSession;
    readonly custodianTwo: TestSession;
    /** Dedicated identity: WebAuthn rotates and revokes its sessions. */
    readonly passkey: TestSession;
  };
  readonly tenantKey: Buffer;
  readonly tenantKeyId: string;
  readonly ids: FixtureIds;
  protectedBefore?: Readonly<Record<string, string>>;
  clusterCatalogBefore?: ClusterCatalogFingerprint;
  control?: Pool;
  tenant?: Pool;
  provisioner?: TenantProvisioner;
  api?: FastifyInstance;
  browserHarness?: HttpServer;
  playwright?: ChildProcess;
  namesVerifiedUnused?: boolean;
  controlCreatedByRun?: boolean;
  cleanupDdlStarted?: boolean;
}

interface RunReport {
  readonly schemaVersion: 1;
  readonly marker: typeof REAL_BROWSER_STACK_MARKER;
  readonly runId: string;
  readonly ephemeralTargets: {
    readonly controlDatabase: string;
    readonly tenantId: string;
    readonly tenantDatabase: string;
    readonly ownerRole: string;
    readonly runtimeRole: string;
    readonly tenantSlug: string;
  };
  readonly isolation: "ephemeral-control-and-tenant";
  readonly transport: "browser-fetch-to-fastify-loopback-to-postgresql";
  startedAt: string;
  completedAt?: string;
  status: "in-progress" | "passed" | "failed";
  inProgress: boolean;
  scenarioPass: boolean;
  scenarioObservation: ScenarioObservation | null;
  cleanupPass: boolean;
  protectedDatabasesUnchanged: boolean | null;
  mutationStarted: boolean;
  cleanupDdlStarted: boolean;
  protectedFingerprints: {
    before: Readonly<Record<string, string>> | null;
    after: Readonly<Record<string, string>> | null;
  };
  operationalPorts: {
    readonly requiredFree: typeof RESERVED_APPLICATION_PORTS;
    before: readonly ReservedApplicationPortObservation[];
    after: readonly ReservedApplicationPortObservation[];
    api: number | null;
    browserHarness: number | null;
    reservedPortsUsedByScenario: boolean;
  };
  ephemeralCleanup: {
    databaseCount: number | null;
    roleCount: number | null;
    databasesAbsent: boolean;
    rolesAbsent: boolean;
  };
  globalEphemeralResources: {
    before: GlobalEphemeralResourceObservation | null;
    after: GlobalEphemeralResourceObservation | null;
  };
  clusterCatalog: {
    before: ClusterCatalogFingerprint | null;
    after: ClusterCatalogFingerprint | null;
  };
  runFailureStage?: string;
  runFailureCode?: string;
  cleanupFailureStage?: string;
  cleanupFailureCode?: string;
}

type ScenarioObservation = Omit<ScenarioIntegrity, "aggregate"> & {
  readonly aggregateSha256: `sha256:${string}`;
};

interface RealStackCleanupObservation extends CleanupObservation {
  readonly globalEphemeralResources: GlobalEphemeralResourceObservation;
  readonly clusterCatalogAfter: ClusterCatalogFingerprint;
}

interface PreflightReport {
  readonly schemaVersion: 1;
  readonly marker: typeof REAL_BROWSER_STACK_MARKER;
  readonly mode: "read-only-preflight";
  readonly startedAt: string;
  completedAt?: string;
  status: "in-progress" | "passed" | "failed";
  inProgress: boolean;
  pass: boolean;
  protectedDatabasesUnchanged: boolean | null;
  ephemeralControlDatabasesAbsent: boolean;
  orphanTenantResourcesAbsent: boolean;
  globalEphemeralResources: {
    before: GlobalEphemeralResourceObservation | null;
    after: GlobalEphemeralResourceObservation | null;
  };
  protectedFingerprints: {
    before: Readonly<Record<string, string>> | null;
    after: Readonly<Record<string, string>> | null;
  };
  clusterCatalog: {
    before: ClusterCatalogFingerprint | null;
    after: ClusterCatalogFingerprint | null;
  };
  operationalPorts: {
    readonly requiredFree: typeof RESERVED_APPLICATION_PORTS;
    before: readonly ReservedApplicationPortObservation[];
    after: readonly ReservedApplicationPortObservation[];
  };
  failureStage?: string;
  failureCode?: string;
}

async function main(): Promise<void> {
  executionStage = "invocation-guard";
  const argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === REAL_BROWSER_STACK_CHECK_FLAG) {
    requireReadOnlyCheckInvocation(argv);
    await runReadOnlyPreflight();
    return;
  }
  requireEphemeralInvocation(argv);
  const names = deriveEphemeralNames(randomUUID(), randomUUID());
  const report: RunReport = {
    schemaVersion: 1,
    marker: REAL_BROWSER_STACK_MARKER,
    runId: names.runId,
    ephemeralTargets: {
      controlDatabase: names.controlDatabase,
      tenantId: names.tenantId,
      tenantDatabase: names.tenantDatabase,
      ownerRole: names.ownerRole,
      runtimeRole: names.runtimeRole,
      tenantSlug: names.tenantSlug,
    },
    isolation: "ephemeral-control-and-tenant",
    transport: "browser-fetch-to-fastify-loopback-to-postgresql",
    startedAt: new Date().toISOString(),
    status: "in-progress",
    inProgress: true,
    scenarioPass: false,
    scenarioObservation: null,
    cleanupPass: false,
    protectedDatabasesUnchanged: null,
    mutationStarted: false,
    cleanupDdlStarted: false,
    protectedFingerprints: { before: null, after: null },
    operationalPorts: {
      requiredFree: RESERVED_APPLICATION_PORTS,
      before: [],
      after: [],
      api: null,
      browserHarness: null,
      reservedPortsUsedByScenario: false,
    },
    ephemeralCleanup: {
      databaseCount: null,
      roleCount: null,
      databasesAbsent: false,
      rolesAbsent: false,
    },
    globalEphemeralResources: { before: null, after: null },
    clusterCatalog: { before: null, after: null },
  };
  writeReport(report);
  let state: RunnerState | undefined;
  let runError: unknown;
  let cleanupError: unknown;
  try {
    executionStage = "reserved-application-ports-before";
    report.operationalPorts.before = await inspectReservedApplicationPorts();
    assertReservedApplicationPortsFree(report.operationalPorts.before);
    executionStage = "workspace-admin-config";
    const databaseAdminUrl = discoverAdminUrl();
    state = createState(databaseAdminUrl, names);
    executionStage = "workspace-cluster-identity";
    await assertWorkspaceCluster(state.cluster);
    executionStage = "global-ephemeral-inventory-before";
    report.globalEphemeralResources.before = await inspectGlobalEphemeralResources(state);
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.before);
    executionStage = "cluster-catalog-fingerprint-before";
    const clusterCatalogBefore = await fingerprintClusterCatalog(state.cluster);
    state.clusterCatalogBefore = clusterCatalogBefore;
    report.clusterCatalog.before = clusterCatalogBefore;
    executionStage = "protected-databases-idle-before";
    await assertProtectedDatabasesIdle(state.cluster);
    executionStage = "protected-fingerprint-before";
    state.protectedBefore = await fingerprintProtectedDatabases(databaseAdminUrl);
    report.protectedFingerprints.before = state.protectedBefore;
    executionStage = "unused-name-preflight";
    await assertGeneratedNamesUnused(state);
    state.namesVerifiedUnused = true;
    executionStage = "isolated-control-create";
    await createIsolatedControl(state);
    executionStage = "isolated-control-migrations";
    await runMigrations(requireControl(state), { scope: "control", directory: path.join(migrationsRoot, "control") });
    executionStage = "tenant-provision";
    await provisionTenant(state);
    executionStage = "fixture-seed";
    await seedFixture(state);
    executionStage = "fastify-listener";
    const apiBaseUrl = await startApi(state);
    report.operationalPorts.api = Number(new URL(apiBaseUrl).port);
    executionStage = "browser-harness-listener";
    const harnessBaseUrl = await startBrowserHarness(state, apiBaseUrl);
    report.operationalPorts.browserHarness = Number(new URL(harnessBaseUrl).port);
    report.operationalPorts.reservedPortsUsedByScenario = RESERVED_APPLICATION_PORTS.some(
      (port) => port === report.operationalPorts.api || port === report.operationalPorts.browserHarness,
    );
    executionStage = "playwright-browser-scenario";
    const exitCode = await runPlaywright(state, apiBaseUrl, harnessBaseUrl);
    if (exitCode !== 0) throw new Error("Real browser-stack Playwright scenario failed");
    executionStage = "scenario-postconditions";
    const scenarioIntegrity = await observeTenantScenario(state);
    report.scenarioObservation = sanitizeScenarioObservation(scenarioIntegrity);
    assertScenarioIntegrity(scenarioIntegrity, state.ids.candidateIds);
    report.scenarioPass = true;
  } catch (error) {
    runError = error;
    report.runFailureStage = executionStage;
    report.runFailureCode = safeFailureCode(error);
  } finally {
    executionStage = "cleanup";
    try {
      if (state) {
        const cleanupObservation = await cleanup(state);
        report.protectedFingerprints.after = cleanupObservation.protectedAfter;
        report.ephemeralCleanup.databaseCount = cleanupObservation.databases;
        report.ephemeralCleanup.roleCount = cleanupObservation.roles;
        report.ephemeralCleanup.databasesAbsent = cleanupObservation.databases === 0;
        report.ephemeralCleanup.rolesAbsent = cleanupObservation.roles === 0;
        report.globalEphemeralResources.after = cleanupObservation.globalEphemeralResources;
        report.clusterCatalog.after = cleanupObservation.clusterCatalogAfter;
      }
      executionStage = "reserved-application-ports-after";
      report.operationalPorts.after = await inspectReservedApplicationPorts();
      assertReservedApplicationPortsFree(report.operationalPorts.after);
      report.cleanupPass = true;
      if (report.protectedFingerprints.before && report.protectedFingerprints.after) {
        report.protectedDatabasesUnchanged = Object.keys(report.protectedFingerprints.before).every(
          (key) => report.protectedFingerprints.after?.[key] === report.protectedFingerprints.before?.[key],
        );
      }
    } catch (error) {
      cleanupError = error;
      report.cleanupFailureStage = executionStage;
      report.cleanupFailureCode = safeFailureCode(error);
    }
    report.completedAt = new Date().toISOString();
    report.mutationStarted = state?.controlCreatedByRun === true;
    report.cleanupDdlStarted = state?.cleanupDdlStarted === true;
    report.inProgress = false;
    report.status = runReportClosureEvidencePasses(report) ? "passed" : "failed";
    writeReport(report);
  }
  if (cleanupError) throw new Error("Real browser-stack cleanup failed closed", { cause: cleanupError });
  if (runError) throw runError;
  if (report.status !== "passed") {
    throw new Error("Real browser-stack run did not satisfy every postcondition");
  }
  process.stdout.write("Real browser-stack E2E PASS: passkey, step-up, import, ballot, tally, exact cleanup and protected fingerprints\n");
}

async function runReadOnlyPreflight(): Promise<void> {
  const report: PreflightReport = {
    schemaVersion: 1,
    marker: REAL_BROWSER_STACK_MARKER,
    mode: "read-only-preflight",
    startedAt: new Date().toISOString(),
    status: "in-progress",
    inProgress: true,
    pass: false,
    protectedDatabasesUnchanged: null,
    ephemeralControlDatabasesAbsent: false,
    orphanTenantResourcesAbsent: false,
    globalEphemeralResources: { before: null, after: null },
    protectedFingerprints: { before: null, after: null },
    clusterCatalog: { before: null, after: null },
    operationalPorts: { requiredFree: RESERVED_APPLICATION_PORTS, before: [], after: [] },
  };
  writeFailClosedPreflightSentinel(report);
  let state: RunnerState | undefined;
  try {
    executionStage = "preflight-reserved-application-ports-before";
    report.operationalPorts.before = await inspectReservedApplicationPorts();
    assertReservedApplicationPortsFree(report.operationalPorts.before);
    executionStage = "preflight-workspace-admin-config";
    const databaseAdminUrl = discoverAdminUrl();
    state = createState(databaseAdminUrl, deriveEphemeralNames(randomUUID(), randomUUID()));
    executionStage = "preflight-workspace-cluster-identity";
    await assertWorkspaceCluster(state.cluster);
    executionStage = "preflight-global-ephemeral-inventory-before";
    report.globalEphemeralResources.before = await inspectGlobalEphemeralResources(state);
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.before);
    executionStage = "preflight-cluster-catalog-fingerprint-before";
    const clusterCatalogBefore = await fingerprintClusterCatalog(state.cluster);
    report.clusterCatalog.before = clusterCatalogBefore;
    report.ephemeralControlDatabasesAbsent = true;
    report.orphanTenantResourcesAbsent = true;
    executionStage = "preflight-protected-databases-idle-before";
    await assertProtectedDatabasesIdle(state.cluster);
    executionStage = "preflight-protected-fingerprint-before";
    const protectedBefore = await fingerprintProtectedDatabases(databaseAdminUrl);
    report.protectedFingerprints.before = protectedBefore;
    executionStage = "preflight-unused-name-check";
    await assertGeneratedNamesUnused(state);
    executionStage = "preflight-protected-databases-idle-after";
    await assertProtectedDatabasesIdle(state.cluster);
    executionStage = "preflight-protected-fingerprint-after";
    const protectedAfter = await fingerprintProtectedDatabases(databaseAdminUrl);
    report.protectedFingerprints.after = protectedAfter;
    assertCleanupObservation({ databases: 0, roles: 0, protectedBefore, protectedAfter });
    executionStage = "preflight-global-ephemeral-inventory-after";
    report.globalEphemeralResources.after = await inspectGlobalEphemeralResources(state);
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.after);
    executionStage = "preflight-cluster-catalog-fingerprint-after";
    const clusterCatalogAfter = await fingerprintClusterCatalog(state.cluster);
    report.clusterCatalog.after = clusterCatalogAfter;
    assertClusterCatalogRestored(clusterCatalogBefore, clusterCatalogAfter);
    executionStage = "preflight-reserved-application-ports-after";
    report.operationalPorts.after = await inspectReservedApplicationPorts();
    assertReservedApplicationPortsFree(report.operationalPorts.after);
    report.pass = true;
    report.protectedDatabasesUnchanged = true;
  } catch (error) {
    report.failureStage = executionStage;
    report.failureCode = safeFailureCode(error);
    throw error;
  } finally {
    if (state) await state.cluster.end().catch(() => undefined);
    report.completedAt = new Date().toISOString();
    report.inProgress = false;
    report.status = preflightReportClosureEvidencePasses(report) ? "passed" : "failed";
    report.pass = report.status === "passed";
    writePreflightReport(report);
  }
  process.stdout.write("Real browser-stack read-only preflight PASS: identity, idle state, routes and protected fingerprints\n");
}

function createState(databaseAdminUrl: string, names: EphemeralNames): RunnerState {
  assertEphemeralNames(names);
  const candidateIds = [randomUUID(), randomUUID()] as const;
  return {
    names,
    databaseAdminUrl,
    cluster: new Pool({
      ...adminPoolConfig(databaseAdminUrl),
      application_name: "nombramientos-real-browser-stack-cluster",
      max: 2,
      connectionTimeoutMillis: 5_000,
    }),
    secrets: new MemorySecretProvider(),
    sessions: {
      admin: temporarySession("CHURCH_ADMIN"),
      selectionVoter: temporarySession("COMMITTEE_MEMBER"),
      abstentionVoter: temporarySession("COMMITTEE_MEMBER"),
      custodianOne: temporarySession("TALLY_CUSTODIAN"),
      custodianTwo: temporarySession("TALLY_CUSTODIAN"),
      passkey: temporarySession("CHURCH_ADMIN"),
    },
    tenantKey: randomBytes(32),
    tenantKeyId: randomUUID(),
    ids: {
      existingHomonymId: randomUUID(),
      updateTargetId: randomUUID(),
      createdHomonymId: randomUUID(),
      skippedMemberId: randomUUID(),
      cycleId: randomUUID(),
      roundId: randomUUID(),
      candidateIds,
      candidateSetHash: digestCanonical({ candidateIds: [...candidateIds].sort() }),
      rulesHash: digestCanonical({ allowAbstention: true, maxSelections: 1, minSelections: 0 }),
    },
  };
}

async function assertWorkspaceCluster(cluster: Pool): Promise<void> {
  const result = await cluster.query<{
    database_name: string; current_user: string; port: number; version: number; loopback: boolean;
  }>(
    `SELECT current_database() AS database_name,current_user,
            current_setting('port')::int AS port,
            current_setting('server_version_num')::int AS version,
            COALESCE(
              inet_server_addr() <<= inet '127.0.0.0/8'
              OR inet_server_addr() = inet '::1'
              OR inet_server_addr() <<= inet '::ffff:127.0.0.0/104',
              false
            ) AS loopback`,
  );
  const row = result.rows[0];
  if (!row) throw new Error("WORKSPACE_CLUSTER_RESULT_MISSING");
  if (row.database_name !== "postgres") throw new Error("WORKSPACE_CLUSTER_DATABASE_INVALID");
  if (row.current_user !== "nom_admin") throw new Error("WORKSPACE_CLUSTER_USER_INVALID");
  if (row.port !== 55_432) throw new Error("WORKSPACE_CLUSTER_PORT_INVALID");
  if (row.version < 180_000) throw new Error("WORKSPACE_CLUSTER_VERSION_UNSUPPORTED");
  if (!row.loopback) throw new Error("WORKSPACE_CLUSTER_ADDRESS_INVALID");
}

async function assertProtectedDatabasesIdle(cluster: Pool): Promise<void> {
  const result = await cluster.query<{ count: number }>(
    `SELECT count(*)::int AS count
       FROM pg_catalog.pg_stat_activity
      WHERE backend_type='client backend'
        AND pid <> pg_backend_pid()
        AND datname=ANY($1::text[])`,
    [Object.values(PROTECTED_DATABASES)],
  );
  if (result.rows[0]?.count !== 0) {
    throw new Error("Protected databases have active client sessions; stop API, web and worker before this run");
  }
}

async function inspectReservedApplicationPorts(): Promise<readonly ReservedApplicationPortObservation[]> {
  const observations: ReservedApplicationPortObservation[] = [];
  for (const port of RESERVED_APPLICATION_PORTS) {
    observations.push({ port, acceptingConnections: await acceptsLoopbackConnection(port) });
  }
  return observations;
}

async function acceptsLoopbackConnection(port: (typeof RESERVED_APPLICATION_PORTS)[number]): Promise<boolean> {
  return new Promise<boolean>((resolve, reject) => {
    const socket = new Socket();
    let settled = false;
    const finish = (result: boolean | Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (result instanceof Error) reject(result);
      else resolve(result);
    };
    socket.setTimeout(1_000, () => finish(new Error("RESERVED_APPLICATION_PORT_PROBE_TIMEOUT")));
    socket.once("connect", () => finish(true));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED") finish(false);
      else finish(new Error("RESERVED_APPLICATION_PORT_PROBE_FAILED", { cause: error }));
    });
    socket.connect(port, "127.0.0.1");
  });
}

async function assertGeneratedNamesUnused(state: RunnerState): Promise<void> {
  const result = await state.cluster.query<{ databases: number; roles: number }>(
    `SELECT
       (SELECT count(*)::int FROM pg_database WHERE datname=ANY($1::text[])) AS databases,
       (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
    [[state.names.controlDatabase, state.names.tenantDatabase], [state.names.ownerRole, state.names.runtimeRole]],
  );
  if (result.rows[0]?.databases !== 0 || result.rows[0]?.roles !== 0) {
    throw new Error("A generated ephemeral database or role name is already in use");
  }
}

async function inspectEphemeralControlDatabaseCount(cluster: Pool): Promise<number> {
  const result = await cluster.query<{ count: number }>(
    "SELECT count(*)::int AS count FROM pg_database WHERE left(datname,length('nom_e2e_c_'))='nom_e2e_c_'",
  );
  const count = result.rows[0]?.count;
  if (!Number.isInteger(count) || count === undefined || count < 0) {
    throw new Error("EPHEMERAL_CONTROL_DATABASE_INVENTORY_INVALID");
  }
  return count;
}

async function inspectUnroutedTenantResources(state: RunnerState): Promise<{
  readonly routes: readonly RegisteredTenantResourceRoute[];
  readonly inventory: { readonly databases: readonly string[]; readonly roles: readonly string[] };
  readonly observation: UnroutedTenantResourceObservation;
}> {
  const control = new Pool({
    ...adminPoolConfig(state.databaseAdminUrl, PROTECTED_DATABASES.control),
    application_name: "nombramientos-real-browser-stack-resource-preflight",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  let routes: readonly RegisteredTenantResourceRoute[];
  try {
    const result = await control.query<RegisteredTenantResourceRoute>(
      "SELECT id::text,database_name::text,runtime_role::text FROM tenants ORDER BY id",
    );
    routes = result.rows;
  } finally {
    await control.end();
  }
  const inventory = await state.cluster.query<{ databases: string[]; roles: string[] }>(
    `SELECT
       ARRAY(SELECT datname::text FROM pg_database WHERE datname ~ '^nom_t_[0-9a-f]{32}$' ORDER BY datname) AS databases,
       ARRAY(SELECT rolname::text FROM pg_roles WHERE rolname ~ '^nom_[or]_[0-9a-f]{32}$' ORDER BY rolname) AS roles`,
  );
  const row = inventory.rows[0];
  if (!row || !Array.isArray(row.databases) || !Array.isArray(row.roles)) {
    throw new Error("TENANT_RESOURCE_INVENTORY_UNAVAILABLE");
  }
  return {
    routes,
    inventory: row,
    observation: observeUnroutedTenantResources(routes, row),
  };
}

async function inspectGlobalEphemeralResources(state: RunnerState): Promise<GlobalEphemeralResourceObservation> {
  const ephemeralControlDatabaseCount = await inspectEphemeralControlDatabaseCount(state.cluster);
  const unrouted = await inspectUnroutedTenantResources(state);
  return createGlobalEphemeralResourceObservation(
    unrouted.inventory.databases.length,
    unrouted.inventory.roles.length,
    ephemeralControlDatabaseCount,
    unrouted.observation,
  );
}

async function createIsolatedControl(state: RunnerState): Promise<void> {
  if (state.namesVerifiedUnused !== true) throw new Error("Generated names were not proven unused");
  await executeFormatted(
    state.cluster,
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
    [state.names.controlDatabase],
  );
  state.controlCreatedByRun = true;
  state.control = new Pool({
    ...adminPoolConfig(state.databaseAdminUrl, state.names.controlDatabase),
    application_name: "nombramientos-real-browser-stack-control",
    max: 4,
    connectionTimeoutMillis: 5_000,
  });
  await state.control.query(
    `CREATE TABLE ${CONTROL_MARKER_TABLE} (
       singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
       marker text NOT NULL,
       run_id uuid NOT NULL UNIQUE,
       control_database text NOT NULL UNIQUE,
       tenant_id uuid NOT NULL UNIQUE,
       tenant_database text NOT NULL UNIQUE,
       owner_role text NOT NULL UNIQUE,
       runtime_role text NOT NULL UNIQUE,
       tenant_slug text NOT NULL UNIQUE,
       created_at timestamptz NOT NULL DEFAULT clock_timestamp()
     )`,
  );
  await state.control.query(
    `INSERT INTO ${CONTROL_MARKER_TABLE}(
       singleton,marker,run_id,control_database,tenant_id,tenant_database,owner_role,runtime_role,tenant_slug
     ) VALUES (true,$1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      REAL_BROWSER_STACK_MARKER,
      state.names.runId,
      state.names.controlDatabase,
      state.names.tenantId,
      state.names.tenantDatabase,
      state.names.ownerRole,
      state.names.runtimeRole,
      state.names.tenantSlug,
    ],
  );
  await verifyControlMarker(state);
}

async function provisionTenant(state: RunnerState): Promise<void> {
  const control = requireControl(state);
  state.provisioner = new TenantProvisioner({
    admin: adminPoolConfig(state.databaseAdminUrl),
    control,
    secrets: state.secrets,
    catalog: temporaryCatalog,
    migrationsRoot,
  });
  const result = await state.provisioner.provision({
    idempotencyKey: randomUUID(),
    tenantId: state.names.tenantId,
    slug: state.names.tenantSlug,
    displayName: EPHEMERAL_TENANT_NAME,
    kind: "demo",
    timezone: EPHEMERAL_TENANT_TIMEZONE,
    locale: "es",
  });
  if (result.reused
    || result.state !== "active"
    || result.tenantStatus !== "active"
    || result.tenantId !== state.names.tenantId
    || result.database !== state.names.tenantDatabase
    || result.runtimeRole !== state.names.runtimeRole
    || result.secretReference !== state.names.secretReference) {
    throw new Error("Provisioner returned a mismatched ephemeral tenant");
  }
  await state.provisioner.close();
  delete state.provisioner;
  const tenant = new Pool({
    ...adminPoolConfig(state.databaseAdminUrl, state.names.tenantDatabase),
    application_name: "nombramientos-real-browser-stack-fixture",
    max: 4,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const identity = await tenant.query<{ database_name: string; tenant_id: string; kind: string }>(
      "SELECT current_database() AS database_name,tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
    );
    const row = identity.rows[0];
    if (!row || row.database_name !== state.names.tenantDatabase || row.tenant_id !== state.names.tenantId || row.kind !== "demo") {
      throw new Error("Provisioned ephemeral tenant identity is invalid");
    }
    await tenant.query(
      `CREATE TABLE ${TENANT_MARKER_TABLE} (
         singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
         marker text NOT NULL,
         run_id uuid NOT NULL UNIQUE,
         tenant_id uuid NOT NULL UNIQUE,
         tenant_database text NOT NULL UNIQUE,
         created_at timestamptz NOT NULL DEFAULT clock_timestamp()
       )`,
    );
    await tenant.query(
      `INSERT INTO ${TENANT_MARKER_TABLE}(singleton,marker,run_id,tenant_id,tenant_database)
       VALUES (true,$1,$2,$3,$4)`,
      [REAL_BROWSER_STACK_MARKER, state.names.runId, state.names.tenantId, state.names.tenantDatabase],
    );
    await verifyTenantMarker(tenant, state.names);
    state.tenant = tenant;
  } finally {
    if (state.tenant !== tenant) await tenant.end();
  }
}

async function seedFixture(state: RunnerState): Promise<void> {
  const control = requireControl(state);
  const tenant = requireTenant(state);
  executionStage = "fixture-seed-control-sessions";
  await seedControlSessions(control, state);
  executionStage = "fixture-seed-round-hashes";
  const rules = { candidateIds: [...state.ids.candidateIds], minSelections: 0, maxSelections: 1, allowAbstention: true } as const;
  const candidateSetHash = digestCanonical({ candidateIds: [...rules.candidateIds].sort() });
  const rulesHash = digestCanonical({ allowAbstention: true, maxSelections: 1, minSelections: 0 });
  if (candidateSetHash !== state.ids.candidateSetHash || rulesHash !== state.ids.rulesHash) {
    throw new Error("Ephemeral round hashes are inconsistent");
  }

  const existingEnvelope = memberEnvelope(state, state.ids.existingHomonymId, "Ángela Núñez");
  const updateEnvelope = memberEnvelope(state, state.ids.updateTargetId, "Persona anterior");
  const client = await tenant.connect();
  try {
    await client.query("BEGIN");
    executionStage = "fixture-seed-tenant-settings";
    await client.query("UPDATE tenant_settings SET setup_state='ready',updated_at=clock_timestamp() WHERE singleton=true");
    for (const session of Object.values(state.sessions)) {
      executionStage = "fixture-seed-role-bindings";
      await client.query(
        `INSERT INTO role_bindings(identity_id,role_id)
         SELECT $1,id FROM roles WHERE code=$2`,
        [session.identityId, session.role],
      );
    }
    executionStage = "fixture-seed-device-key-grant";
    await client.query(
      `INSERT INTO device_key_grants(identity_id,device_id,version,tenant_key_id,kdf,wrap,status)
       VALUES ($1,$2,1,$3,$4::jsonb,$5::jsonb,'active')`,
      [
        state.sessions.admin.identityId,
        randomUUID(),
        state.tenantKeyId,
        JSON.stringify({ name: "PBKDF2", salt: randomBytes(16).toString("base64url"), iterations: 310_000, hash: "SHA-256" }),
        JSON.stringify({ algorithm: "AES-GCM", iv: randomBytes(12).toString("base64url"), ciphertext: randomBytes(48).toString("base64url"), aad: randomBytes(24).toString("base64url") }),
      ],
    );
    executionStage = "fixture-seed-members";
    await client.query(
      `INSERT INTO members(
         id,stable_code,profile_envelope,display_envelope,display_content_hash,
         profile_migration_required,eligibility_status,available
       ) VALUES
         ($1,'RB-HOM-001',NULL,$2::jsonb,$3,false,'eligible',true),
         ($4,'RB-UPD-001',NULL,$5::jsonb,$6,false,'eligible',true)`,
      [
        state.ids.existingHomonymId,
        existingEnvelope,
        envelopeContentHash(existingEnvelope),
        state.ids.updateTargetId,
        updateEnvelope,
        envelopeContentHash(updateEnvelope),
      ],
    );
    executionStage = "fixture-seed-office-lookup";
    const office = await client.query<{ id: string }>("SELECT id::text FROM offices WHERE canonical_code='real_browser_stack_office'");
    const officeId = office.rows[0]?.id;
    if (!officeId) throw new Error("Ephemeral fixture office is absent");
    executionStage = "fixture-seed-election-cycle";
    await client.query(
      `INSERT INTO election_cycles(
         id,name,status,locale,timezone,term_start,term_end,normative_version,eligible_reference_count
       ) VALUES ($1,'Real browser-stack cycle','active','es',$2,DATE '2027-01-01',DATE '2027-12-31',$3,2)`,
      [state.ids.cycleId, EPHEMERAL_TENANT_TIMEZONE, REAL_BROWSER_STACK_MARKER],
    );
    executionStage = "fixture-seed-vacancy";
    await client.query(
      "INSERT INTO vacancies(cycle_id,office_id,ordinal,status) VALUES ($1,$2,1,'pending')",
      [state.ids.cycleId, officeId],
    );
    executionStage = "fixture-seed-round";
    await client.query(
      `INSERT INTO rounds(
         id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
         max_proposal_selections,max_ballot_selections,candidate_set_hash,rules_hash,
         decision_rule,version,opened_at
       ) VALUES ($1,$2,$3,'VOTACION_ABIERTA','vote',1,1,1,1,$4,$5,'{"kind":"PLURALITY"}'::jsonb,1,clock_timestamp())`,
      [state.ids.roundId, state.ids.cycleId, officeId, candidateSetHash, rulesHash],
    );
    executionStage = "fixture-seed-elector-snapshots";
    await client.query(
      `INSERT INTO round_elector_snapshots(round_id,identity_id,can_submit,recused)
       VALUES ($1,$2,true,false),($1,$3,true,false)`,
      [state.ids.roundId, state.sessions.selectionVoter.identityId, state.sessions.abstentionVoter.identityId],
    );
    executionStage = "fixture-seed-candidate-snapshots";
    await client.query(
      `INSERT INTO candidate_snapshots(
         round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
         member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
         eligibility_evaluated_on,eligibility_effective
       ) SELECT $1::uuid,$2::uuid,first_member.id,$4::jsonb,true,1,0,first_member.version,
                first_member.eligibility_department_id,first_member.eligibility_valid_until,
                (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
           FROM members first_member CROSS JOIN tenant_settings settings
          WHERE first_member.id=$3 AND settings.singleton=true
         UNION ALL
         SELECT $1::uuid,$5::uuid,second_member.id,$7::jsonb,true,2,0,second_member.version,
                second_member.eligibility_department_id,second_member.eligibility_valid_until,
                (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
           FROM members second_member CROSS JOIN tenant_settings settings
          WHERE second_member.id=$6 AND settings.singleton=true`,
      [
        state.ids.roundId,
        state.ids.candidateIds[0],
        state.ids.existingHomonymId,
        existingEnvelope,
        state.ids.candidateIds[1],
        state.ids.updateTargetId,
        updateEnvelope,
      ],
    );
    executionStage = "fixture-seed-tenant-commit";
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function seedControlSessions(control: Pool, state: RunnerState): Promise<void> {
  const sessions = Object.entries(state.sessions);
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    for (const [label, session] of sessions) {
      const email = syntheticIdentityEmail(label, session.identityId);
      executionStage = "fixture-seed-control-identity";
      await client.query(
        `INSERT INTO platform_identities(
            id,email,normalized_email,display_name,password_hash,mfa_enabled,totp_secret_ciphertext,mfa_enrolled_at,status
          ) VALUES ($1,$2,$2,$3,$4,true,$5,clock_timestamp(),'active')`,
        [session.identityId, email, `Synthetic ${label}`, "REAL_BROWSER_STACK_LOGIN_DISABLED", "REAL_BROWSER_STACK_NO_TOTP"],
      );
      executionStage = "fixture-seed-control-membership";
      await client.query(
        `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
         VALUES ($1,$2,'active',true)`,
        [state.names.tenantId, session.identityId],
      );
      executionStage = "fixture-seed-control-auth-session";
      await client.query(
        `INSERT INTO auth_sessions(
           id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
           user_agent_hash,ip_prefix_hash,assurance_level,mfa_verified_at,
           auth_method,aal,phishing_resistant,recovery_limited
         ) VALUES (
           $1,$2,$3,$4,$5,clock_timestamp()+interval '30 minutes',$6,$7,
           'mfa',clock_timestamp(),'totp',2,false,false
         )`,
        [
          session.id,
          sha256(session.sessionToken),
          sha256(session.csrfToken),
          session.identityId,
          state.names.tenantId,
          sha256(USER_AGENT),
          sha256("127.0.0"),
        ],
      );
    }
    executionStage = "fixture-seed-control-commit";
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function startApi(state: RunnerState): Promise<string> {
  const corsOrigins = new Set<string>();
  const webauthnOrigins: string[] = [];
  const config: ApiConfig = {
    environment: "test",
    host: "127.0.0.1",
    port: 0,
    corsOrigins,
    secureCookies: false,
    sessionTtlSeconds: 1_800,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: webauthnOrigins,
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: randomBytes(32),
    controlDatabaseUrl: databaseUrl(state.databaseAdminUrl, state.names.controlDatabase),
    secretMasterKey: randomBytes(32),
    secretFile: path.join(tmpdir(), `nombramientos-real-browser-unused-${state.names.runId}.json`),
    tenantPoolMax: 4,
    tenantPoolIdleMs: 5_000,
  };
  const database = new DatabaseRuntime({
    control: {
      ...adminPoolConfig(state.databaseAdminUrl, state.names.controlDatabase),
      application_name: "nombramientos-real-browser-stack-api",
      max: 8,
      ssl: false,
    },
    secretProvider: state.secrets,
    tenantPoolMax: config.tenantPoolMax,
    tenantPoolIdleMs: config.tenantPoolIdleMs,
  });
  state.api = await buildServer({ config, database, logger: false });
  await state.api.listen({ host: "127.0.0.1", port: 0 });
  const address = state.api.server.address();
  if (!address || typeof address === "string") throw new Error("Fastify did not bind an ephemeral TCP port");
  // The socket remains IPv4-loopback-only. Browser-facing URLs use localhost
  // because WebAuthn does not permit an IP literal as an RP ID.
  const baseUrl = `http://localhost:${(address as AddressInfo).port}`;
  assertIsolatedHttpOrigin(baseUrl, "Fastify API");
  corsOrigins.add(baseUrl);
  return baseUrl;
}

async function startBrowserHarness(state: RunnerState, apiBaseUrl: string): Promise<string> {
  const apiOrigin = new URL(apiBaseUrl).origin;
  state.browserHarness = createServer((request, response) => {
    if (request.method !== "GET" || request.url !== "/") {
      response.writeHead(404, { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-security-policy": `default-src 'none'; connect-src ${apiOrigin}`,
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    });
    response.end(`<!doctype html><html><head><meta charset="utf-8"><title>${REAL_BROWSER_STACK_MARKER}</title></head><body data-marker="${REAL_BROWSER_STACK_MARKER}"></body></html>`);
  });
  state.browserHarness.listen(0, "127.0.0.1");
  await once(state.browserHarness, "listening");
  const address = state.browserHarness.address();
  if (!address || typeof address === "string") throw new Error("Browser harness did not bind an ephemeral TCP port");
  const baseUrl = `http://localhost:${(address as AddressInfo).port}`;
  assertIsolatedHttpOrigin(baseUrl, "browser harness");
  const apiConfig = state.api?.apiConfig;
  if (!apiConfig) throw new Error("Fastify configuration is unavailable");
  (apiConfig.corsOrigins as Set<string>).add(baseUrl);
  (apiConfig.webauthn.expectedOrigins as string[]).push(baseUrl);
  return baseUrl;
}

async function runPlaywright(state: RunnerState, apiBaseUrl: string, harnessBaseUrl: string): Promise<number> {
  const businessSessionEntries = Object.entries(state.sessions)
    .filter(([key]) => key !== "passkey")
    .map(([key, session]) => [key, {
      sessionToken: session.sessionToken,
      csrfToken: session.csrfToken,
    }]);
  const fixture = {
    schemaVersion: 1,
    marker: REAL_BROWSER_STACK_MARKER,
    runId: state.names.runId,
    apiBaseUrl,
    harnessBaseUrl,
    userAgent: USER_AGENT,
    tenantId: state.names.tenantId,
    tenant: {
      name: EPHEMERAL_TENANT_NAME,
      timezone: EPHEMERAL_TENANT_TIMEZONE,
    },
    tenantKey: state.tenantKey.toString("base64url"),
    tenantKeyId: state.tenantKeyId,
    members: {
      existingHomonymId: state.ids.existingHomonymId,
      updateTargetId: state.ids.updateTargetId,
      createdHomonymId: state.ids.createdHomonymId,
      skippedMemberId: state.ids.skippedMemberId,
    },
    round: {
      id: state.ids.roundId,
      cycleId: state.ids.cycleId,
      candidateIds: state.ids.candidateIds,
      candidateSetHash: state.ids.candidateSetHash,
      rulesHash: state.ids.rulesHash,
    },
    sessions: Object.fromEntries(businessSessionEntries),
  };
  const passkeyFixture = {
    schemaVersion: 1,
    marker: REAL_BROWSER_STACK_MARKER,
    runId: state.names.runId,
    apiBaseUrl,
    harnessBaseUrl,
    userAgent: USER_AGENT,
    tenantId: state.names.tenantId,
    passkey: {
      email: syntheticIdentityEmail("passkey", state.sessions.passkey.identityId),
      sessionToken: state.sessions.passkey.sessionToken,
      csrfToken: state.sessions.passkey.csrfToken,
    },
  };
  const webRoot = path.join(workspaceRoot, "apps", "web");
  const playwrightCli = path.join(webRoot, "node_modules", "@playwright", "test", "cli.js");
  if (!existsSync(playwrightCli)) throw new Error("The workspace Playwright CLI is unavailable");
  state.playwright = spawn(process.execPath, [
    playwrightCli,
    "test",
    "--config=playwright.real-stack.config.ts",
  ], {
    cwd: webRoot,
    env: {
      ...process.env,
      NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64: Buffer.from(JSON.stringify(fixture), "utf8").toString("base64url"),
      NOMBRAMIENTOS_REAL_STACK_PASSKEY_FIXTURE_B64: Buffer.from(JSON.stringify(passkeyFixture), "utf8").toString("base64url"),
      NOMBRAMIENTOS_REAL_STACK_HARNESS_URL: harnessBaseUrl,
      NOMBRAMIENTOS_REAL_STACK_USER_AGENT: USER_AGENT,
    },
    stdio: "inherit",
    windowsHide: true,
    shell: false,
  });
  const [code, signal] = await once(state.playwright, "exit") as [number | null, NodeJS.Signals | null];
  delete state.playwright;
  if (signal !== null) throw new Error("Playwright browser scenario was interrupted");
  return code ?? 1;
}

async function observeTenantScenario(state: RunnerState): Promise<ScenarioIntegrity> {
  const tenant = requireTenant(state);
  const result = await tenant.query<ScenarioIntegrity>(
    `SELECT
       (SELECT count(*)::int FROM member_import_jobs) AS import_jobs,
       (SELECT count(*)::int FROM member_import_jobs WHERE state='completed') AS completed_import_jobs,
       (SELECT count(*)::int FROM members) AS member_rows,
       COALESCE((SELECT version::int FROM members WHERE id=$1),-1) AS updated_member_version,
       (SELECT count(*)::int FROM members WHERE id=$2 AND stable_code='RB-HOM-002' AND archived_at IS NULL) AS created_homonym_rows,
       (SELECT count(*)::int FROM members WHERE id=$3 OR stable_code='RB-SKIP-001') AS skipped_member_rows,
       (SELECT count(*)::int FROM idempotency_records WHERE operation IN ('member.import.preview','member.import.commit')) AS import_idempotency_records,
       (SELECT count(*)::int FROM encrypted_submissions WHERE round_id=$4 AND kind='vote') AS vote_submissions,
       (SELECT count(*)::int FROM participation_receipts WHERE round_id=$4 AND kind='vote') AS vote_receipts,
       (SELECT count(DISTINCT elector_identity_id)::int FROM encrypted_submissions WHERE round_id=$4 AND kind='vote') AS distinct_vote_electors,
       (SELECT count(*)::int FROM idempotency_records WHERE operation='round.vote.submit') AS vote_idempotency_records,
       (SELECT count(*)::int FROM round_custody_sets WHERE round_id=$4) AS custody_sets,
       (SELECT count(*)::int FROM round_custodian_key_snapshots WHERE round_id=$4) AS custodian_snapshots,
       (SELECT count(*)::int FROM tally_manifests WHERE round_id=$4) AS manifests,
       (SELECT count(*)::int FROM tally_manifest_entries entry JOIN tally_manifests manifest ON manifest.id=entry.manifest_id WHERE manifest.round_id=$4) AS manifest_entries,
       (SELECT count(*)::int FROM custodian_attestations WHERE round_id=$4) AS attestations,
       (SELECT count(*)::int FROM tally_manifests WHERE round_id=$4 AND state='published') AS published_manifests,
       COALESCE((SELECT version::int FROM rounds WHERE id=$4),-1) AS round_version,
       COALESCE((SELECT phase FROM rounds WHERE id=$4),'ABSENT') AS round_phase,
       (SELECT agreed_aggregate FROM tally_manifests WHERE round_id=$4) AS aggregate`,
    [state.ids.updateTargetId, state.ids.createdHomonymId, state.ids.skippedMemberId, state.ids.roundId],
  );
  const row = result.rows[0];
  if (!row) throw new Error("Real browser-stack integrity query returned no row");
  return row;
}

function sanitizeScenarioObservation(integrity: ScenarioIntegrity): ScenarioObservation {
  const { aggregate, ...countsAndPhase } = integrity;
  return { ...countsAndPhase, aggregateSha256: digestCanonical(aggregate) };
}

async function cleanup(state: RunnerState): Promise<RealStackCleanupObservation> {
  const protectedBefore = state.protectedBefore;
  const clusterCatalogBefore = state.clusterCatalogBefore;
  const shutdownErrors: Error[] = [];
  const authorizationErrors: Error[] = [];
  const tenantWasFullyMarked = state.tenant !== undefined;
  if (state.playwright) {
    await captureCleanupFailure(shutdownErrors, "Playwright process did not stop", () => stopChildProcess(state.playwright!));
    delete state.playwright;
  }
  if (state.browserHarness) {
    await captureCleanupFailure(shutdownErrors, "Browser harness did not stop", () => closeHttpServer(state.browserHarness!));
    delete state.browserHarness;
  }
  if (state.api) {
    await captureCleanupFailure(shutdownErrors, "Fastify API did not stop", () => state.api!.close());
    delete state.api;
  }
  if (state.provisioner) {
    await captureCleanupFailure(shutdownErrors, "Tenant provisioner did not stop", () => state.provisioner!.close());
    delete state.provisioner;
  }
  if (state.tenant) {
    await captureCleanupFailure(authorizationErrors, "Ephemeral tenant marker did not authorize cleanup", () =>
      verifyTenantMarker(state.tenant!, state.names));
    await captureCleanupFailure(shutdownErrors, "Ephemeral tenant pool did not close", () => state.tenant!.end());
    delete state.tenant;
  }

  if (state.controlCreatedByRun === true) {
    await captureCleanupFailure(authorizationErrors, "Ephemeral control marker did not authorize cleanup", async () => {
      await verifyControlMarker(state);
      const tenantRoute = await requireControl(state).query<{
        id: string; slug: string; database_name: string; runtime_role: string; runtime_secret_ref: string;
      }>(
        `SELECT id::text,slug,database_name::text,runtime_role::text,runtime_secret_ref
           FROM tenants WHERE id=$1`,
        [state.names.tenantId],
      );
      const route = tenantRoute.rows[0];
      if ((tenantWasFullyMarked && !route)
        || (route && (route.id !== state.names.tenantId
          || route.slug !== state.names.tenantSlug
          || route.database_name !== state.names.tenantDatabase
          || route.runtime_role !== state.names.runtimeRole
          || route.runtime_secret_ref !== state.names.secretReference))) {
        throw new Error("Ephemeral tenant route mismatches its cleanup marker");
      }
    });
  }
  if (state.control) {
    await captureCleanupFailure(shutdownErrors, "Ephemeral control pool did not close", () => state.control!.end());
    delete state.control;
  }

  if (!protectedBefore) authorizationErrors.push(new Error("Protected before-fingerprints are absent"));
  if (!clusterCatalogBefore) authorizationErrors.push(new Error("Cluster catalog before-fingerprint is absent"));
  if (shutdownErrors.length > 0 || authorizationErrors.length > 0) {
    await captureCleanupFailure(shutdownErrors, "Workspace cluster pool did not close", () => state.cluster.end());
    throw new AggregateError([...authorizationErrors, ...shutdownErrors], "Cleanup refused before destructive DDL");
  }
  if (!protectedBefore || !clusterCatalogBefore) throw new Error("Cleanup fingerprints unexpectedly disappeared");

  try {
    if (state.controlCreatedByRun === true) {
      state.cleanupDdlStarted = true;
      await executeFormatted(
        state.cluster,
        "SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql",
        [state.names.tenantDatabase],
      );
      await executeFormatted(state.cluster, "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql", [state.names.runtimeRole]);
      await executeFormatted(state.cluster, "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql", [state.names.ownerRole]);
      await executeFormatted(
        state.cluster,
        "SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text) AS sql",
        [state.names.controlDatabase],
      );
    }

    const absent = await state.cluster.query<{ databases: number; roles: number }>(
      `SELECT
         (SELECT count(*)::int FROM pg_database WHERE datname=ANY($1::text[])) AS databases,
         (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
      [[state.names.controlDatabase, state.names.tenantDatabase], [state.names.ownerRole, state.names.runtimeRole]],
    );
    executionStage = "global-ephemeral-inventory-after";
    const globalEphemeralResources = await inspectGlobalEphemeralResources(state);
    assertGlobalEphemeralResourcesAbsent(globalEphemeralResources);
    executionStage = "protected-databases-idle-after";
    await assertProtectedDatabasesIdle(state.cluster);
    executionStage = "protected-fingerprint-after";
    const protectedAfter = await fingerprintProtectedDatabases(state.databaseAdminUrl);
    executionStage = "cluster-catalog-fingerprint-after";
    const clusterCatalogAfter = await fingerprintClusterCatalog(state.cluster);
    assertClusterCatalogRestored(clusterCatalogBefore, clusterCatalogAfter);
    const observation: RealStackCleanupObservation = {
      databases: absent.rows[0]?.databases ?? -1,
      roles: absent.rows[0]?.roles ?? -1,
      protectedBefore,
      protectedAfter,
      globalEphemeralResources,
      clusterCatalogAfter,
    };
    assertCleanupObservation(observation);
    return observation;
  } finally {
    await state.cluster.end();
  }
}

async function fingerprintClusterCatalog(pool: Pool): Promise<ClusterCatalogFingerprint> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const databases = await client.query(
      `SELECT database.datname AS name,owner.rolname AS owner,database.datistemplate AS is_template,
              database.datallowconn AS allow_connections,database.datconnlimit AS connection_limit,
              pg_encoding_to_char(database.encoding) AS encoding,database.datcollate AS collation,
              database.datctype AS character_type,COALESCE(database.datlocprovider::text,'') AS locale_provider,
              COALESCE(database.datlocale,'') AS locale,COALESCE(database.daticurules,'') AS icu_rules,
              tablespace.spcname AS tablespace,COALESCE(array_to_string(database.datacl,','),'') AS acl
         FROM pg_catalog.pg_database database
         JOIN pg_catalog.pg_roles owner ON owner.oid=database.datdba
         JOIN pg_catalog.pg_tablespace tablespace ON tablespace.oid=database.dattablespace
        ORDER BY database.datname`,
    );
    const roles = await client.query(
      `SELECT role.rolname AS name,role.rolsuper AS superuser,role.rolinherit AS inherit,
              role.rolcreaterole AS create_role,role.rolcreatedb AS create_database,
              role.rolcanlogin AS can_login,role.rolreplication AS replication,
              role.rolbypassrls AS bypass_rls,role.rolconnlimit AS connection_limit,
              credential.rolpassword IS NOT NULL AS has_password,
              COALESCE(role.rolvaliduntil::text,'') AS valid_until,
              COALESCE((SELECT jsonb_agg(setting ORDER BY setting)
                          FROM unnest(role.rolconfig) setting),'[]'::jsonb) AS configuration
         FROM pg_catalog.pg_roles role
         JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
        ORDER BY role.rolname`,
    );
    const memberships = await client.query(
      `SELECT granted.rolname AS granted_role,member.rolname AS member_role,
              grantor.rolname AS grantor_role,membership.admin_option,
              membership.inherit_option,membership.set_option
         FROM pg_catalog.pg_auth_members membership
         JOIN pg_catalog.pg_roles granted ON granted.oid=membership.roleid
         JOIN pg_catalog.pg_roles member ON member.oid=membership.member
         JOIN pg_catalog.pg_roles grantor ON grantor.oid=membership.grantor
        ORDER BY granted.rolname,member.rolname,grantor.rolname`,
    );
    const sharedComments = await client.query(
      `SELECT identified.type AS object_type,COALESCE(identified.schema,'') AS schema_name,
              COALESCE(identified.name,'') AS object_name,identified.identity,
              encode(pg_catalog.sha256(pg_catalog.convert_to(description.description,'UTF8')),'hex') AS description_sha256
         FROM pg_catalog.pg_shdescription description
         CROSS JOIN LATERAL pg_catalog.pg_identify_object(
           description.classoid,description.objoid,0
         ) identified
        ORDER BY object_type,schema_name,object_name,identified.identity,description_sha256`,
    );
    const sharedSecurityLabels = await client.query(
      `SELECT identified.type AS object_type,COALESCE(identified.schema,'') AS schema_name,
              COALESCE(identified.name,'') AS object_name,identified.identity,label.provider,
              encode(pg_catalog.sha256(pg_catalog.convert_to(label.label,'UTF8')),'hex') AS label_sha256
         FROM pg_catalog.pg_shseclabel label
         CROSS JOIN LATERAL pg_catalog.pg_identify_object(label.classoid,label.objoid,0) identified
        ORDER BY object_type,schema_name,object_name,identified.identity,label.provider,label_sha256`,
    );
    await client.query("COMMIT");
    const digest = createHash("sha256")
      .update(JSON.stringify({
        databases: databases.rows,
        roles: roles.rows,
        memberships: memberships.rows,
        sharedComments: sharedComments.rows,
        sharedSecurityLabels: sharedSecurityLabels.rows,
      }))
      .digest("hex");
    return {
      digest: `sha256:${digest}`,
      databaseCount: databases.rowCount ?? databases.rows.length,
      roleCount: roles.rowCount ?? roles.rows.length,
      membershipCount: memberships.rowCount ?? memberships.rows.length,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function assertClusterCatalogRestored(
  before: ClusterCatalogFingerprint,
  after: ClusterCatalogFingerprint,
): void {
  if (before.digest !== after.digest
    || before.databaseCount !== after.databaseCount
    || before.roleCount !== after.roleCount
    || before.membershipCount !== after.membershipCount) {
    throw new Error("Workspace cluster catalog was not restored exactly");
  }
}

async function verifyControlMarker(state: RunnerState): Promise<void> {
  const control = requireControl(state);
  const result = await control.query<RunMarkerRow>(
    `SELECT marker,run_id::text,control_database,tenant_id::text,tenant_database,owner_role,runtime_role,tenant_slug
       FROM ${CONTROL_MARKER_TABLE} WHERE singleton=true`,
  );
  assertRunMarker(result.rows[0], state.names, {
    ...(state.controlCreatedByRun === undefined ? {} : { controlCreatedByRun: state.controlCreatedByRun }),
    ...(state.namesVerifiedUnused === undefined ? {} : { namesVerifiedUnused: state.namesVerifiedUnused }),
  });
}

async function verifyTenantMarker(tenant: Pool, names: EphemeralNames): Promise<void> {
  const result = await tenant.query<{
    database_name: string; marker: string; run_id: string; tenant_id: string; tenant_database: string;
  }>(
    `SELECT current_database() AS database_name,marker,run_id::text,tenant_id::text,tenant_database
       FROM ${TENANT_MARKER_TABLE} WHERE singleton=true`,
  );
  const row = result.rows[0];
  if (!row
    || row.database_name !== names.tenantDatabase
    || row.marker !== REAL_BROWSER_STACK_MARKER
    || row.run_id !== names.runId
    || row.tenant_id !== names.tenantId
    || row.tenant_database !== names.tenantDatabase) {
    throw new Error("Ephemeral tenant cleanup marker is invalid");
  }
}

async function fingerprintProtectedDatabases(databaseAdminUrl: string): Promise<Readonly<Record<string, string>>> {
  const control = new Pool({
    ...adminPoolConfig(databaseAdminUrl, PROTECTED_DATABASES.control),
    application_name: "nombramientos-real-browser-protected-route-check",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  try {
    const routes = await control.query<ProtectedTenantRoute>(
      `SELECT id::text,slug,kind,status,database_name::text
         FROM tenants WHERE id=ANY($1::uuid[]) ORDER BY id`,
      [PROTECTED_TENANTS.map(({ id }) => id)],
    );
    assertProtectedTenantRoutes(routes.rows);
  } finally {
    await control.end();
  }
  const entries = await Promise.all(Object.entries(PROTECTED_DATABASES).map(async ([label, database]) => {
    const digest = await fingerprintDatabase(databaseAdminUrl, database);
    return [label, digest] as const;
  }));
  return Object.fromEntries(entries);
}

async function fingerprintDatabase(databaseAdminUrl: string, database: string): Promise<string> {
  const pool = new Pool({
    ...adminPoolConfig(databaseAdminUrl, database),
    application_name: "nombramientos-real-browser-readonly-fingerprint",
    max: 1,
    connectionTimeoutMillis: 5_000,
  });
  const client = await pool.connect();
  let transactionOpen = false;
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    transactionOpen = true;
    const identity = await client.query<{ database_name: string; current_user: string; port: number; loopback: boolean }>(
      `SELECT current_database() AS database_name,current_user,current_setting('port')::int AS port,
              COALESCE(
                inet_server_addr() <<= inet '127.0.0.0/8'
                OR inet_server_addr() = inet '::1'
                OR inet_server_addr() <<= inet '::ffff:127.0.0.0/104',
                false
              ) AS loopback`,
    );
    const identityRow = identity.rows[0];
    if (!identityRow
      || identityRow.database_name !== database
      || identityRow.current_user !== "nom_admin"
      || identityRow.port !== 55_432
      || !identityRow.loopback) {
      throw new Error("Protected fingerprint target identity is invalid");
    }
    if (database === PROTECTED_DATABASES.demo || database === PROTECTED_DATABASES.ozama) {
      const expected = database === PROTECTED_DATABASES.demo ? PROTECTED_TENANTS[0] : PROTECTED_TENANTS[1];
      const tenant = await client.query<{ tenant_id: string; kind: string }>(
        "SELECT tenant_id::text,kind FROM tenant_settings WHERE singleton=true",
      );
      if (tenant.rows[0]?.tenant_id !== expected.id || tenant.rows[0]?.kind !== expected.kind) {
        throw new Error("Protected tenant fingerprint identity is invalid");
      }
    }
    const relations = await client.query<{ qualified_name: string; schema_name: string; table_name: string }>(
      `SELECT format('%I.%I',namespace.nspname,relation.relname) AS qualified_name,
              namespace.nspname AS schema_name,relation.relname AS table_name
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('r','p','m')
        ORDER BY namespace.nspname,relation.relname`,
    );
    const fingerprints: Array<{ readonly table: string; readonly rows: string; readonly digest: string }> = [];
    for (const relation of relations.rows) {
      const result = await client.query<{ row_count: string; row_digest: string }>(
        `SELECT count(*)::text AS row_count,
                md5(COALESCE(string_agg(md5(to_jsonb(source_row)::text),'' ORDER BY md5(to_jsonb(source_row)::text)),'')) AS row_digest
           FROM ${relation.qualified_name} AS source_row`,
      );
      const row = result.rows[0];
      if (!row || !/^\d+$/u.test(row.row_count) || !/^[0-9a-f]{32}$/u.test(row.row_digest)) {
        throw new Error("Protected table fingerprint is invalid");
      }
      fingerprints.push({ table: `${relation.schema_name}.${relation.table_name}`, rows: row.row_count, digest: row.row_digest });
    }
    const sequences = await client.query(
      `SELECT schemaname AS schema_name,sequencename AS sequence,data_type,start_value::text,min_value::text,max_value::text,
              increment_by::text,cycle,cache_size::text,last_value::text
         FROM pg_catalog.pg_sequences
        WHERE schemaname NOT IN ('pg_catalog','information_schema')
          AND schemaname !~ '^pg_toast(?:_|$)' AND schemaname !~ '^pg_temp_'
        ORDER BY schemaname,sequencename`,
    );
    const databaseMetadata = await client.query(
      `SELECT database.datname AS database_name,owner.rolname AS owner,
              database.encoding::text,database.datcollate,database.datctype,
              database.datlocprovider,database.datlocale,database.daticurules,database.datcollversion,
              database.datistemplate,database.datallowconn,database.dathasloginevt,
              database.datconnlimit,tablespace.spcname AS tablespace
         FROM pg_catalog.pg_database database
         JOIN pg_catalog.pg_roles owner ON owner.oid=database.datdba
         JOIN pg_catalog.pg_tablespace tablespace ON tablespace.oid=database.dattablespace
        WHERE database.datname=current_database()`,
    );
    const databaseAcl = await client.query(
      `SELECT COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_database database
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(database.datacl,pg_catalog.acldefault('d',database.datdba))
         ) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE database.datname=current_database()
        ORDER BY grantee,acl.privilege_type,acl.is_grantable`,
    );
    const schemas = await client.query(
      `SELECT namespace.nspname AS schema_name,owner.rolname AS owner,
              CASE WHEN acl.grantee IS NULL THEN NULL
                   ELSE COALESCE(grantee.rolname,'PUBLIC') END AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_namespace namespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=namespace.nspowner
         LEFT JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner))
         ) acl ON true
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY schema_name,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const relationStructure = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,relation.relkind,relation.relpersistence,
              relation.relispartition,relation.relreplident,relation.relrowsecurity,
              relation.relforcerowsecurity,owner.rolname AS owner,
              access_method.amname AS access_method,tablespace.spcname AS tablespace,
              CASE WHEN relation.reloftype=0 THEN NULL
                   ELSE pg_catalog.format_type(relation.reloftype,NULL) END AS typed_table_type,
              COALESCE(array_to_string(ARRAY(
                SELECT option FROM unnest(COALESCE(relation.reloptions,ARRAY[]::text[])) option ORDER BY option
              ),E'\\n'),'') AS options,
              pg_catalog.pg_get_partkeydef(relation.oid) AS partition_key,
              pg_catalog.pg_get_expr(relation.relpartbound,relation.oid,true) AS partition_bound
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=relation.relowner
         LEFT JOIN pg_catalog.pg_am access_method ON access_method.oid=relation.relam
         LEFT JOIN pg_catalog.pg_tablespace tablespace ON tablespace.oid=relation.reltablespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('r','p','v','m','S','f')
        ORDER BY namespace.nspname,relation.relname,relation.relkind`,
    );
    const inheritance = await client.query(
      `SELECT child_namespace.nspname AS child_schema,child.relname AS child_relation,parent_namespace.nspname AS parent_schema,
              parent.relname AS parent_relation,inheritance.inhseqno,inheritance.inhdetachpending
         FROM pg_catalog.pg_inherits inheritance
         JOIN pg_catalog.pg_class child ON child.oid=inheritance.inhrelid
         JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid=child.relnamespace
         JOIN pg_catalog.pg_class parent ON parent.oid=inheritance.inhparent
         JOIN pg_catalog.pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace
        WHERE child_namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND child_namespace.nspname !~ '^pg_toast(?:_|$)' AND child_namespace.nspname !~ '^pg_temp_'
        ORDER BY child_namespace.nspname,child.relname,inheritance.inhseqno,parent_namespace.nspname,parent.relname`,
    );
    const relationAcl = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,relation.relkind,
              COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(
           relation.relacl,
           CASE WHEN relation.relkind='S'
             THEN pg_catalog.acldefault('s',relation.relowner)
             ELSE pg_catalog.acldefault('r',relation.relowner)
           END
         )) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('r','p','v','m','S','f')
        ORDER BY namespace.nspname,relation.relname,relation.relkind,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const columns = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,column_record.attnum,
              column_record.attname AS column_name,
              pg_catalog.format_type(column_record.atttypid,column_record.atttypmod) AS data_type,
              column_record.attnotnull,column_record.attidentity,column_record.attgenerated,
              column_record.attstorage,column_record.attcompression,column_record.attstattarget,
              collation_record.collname AS collation,
              pg_catalog.pg_get_expr(default_record.adbin,default_record.adrelid,true) AS default_expression
         FROM pg_catalog.pg_attribute column_record
         JOIN pg_catalog.pg_class relation ON relation.oid=column_record.attrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         LEFT JOIN pg_catalog.pg_attrdef default_record
           ON default_record.adrelid=column_record.attrelid AND default_record.adnum=column_record.attnum
         LEFT JOIN pg_catalog.pg_collation collation_record ON collation_record.oid=column_record.attcollation
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('r','p','v','m','f')
          AND column_record.attnum>0 AND NOT column_record.attisdropped
        ORDER BY namespace.nspname,relation.relname,column_record.attnum`,
    );
    const columnAcl = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,column_record.attname AS column_name,
              COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_attribute column_record
         JOIN pg_catalog.pg_class relation ON relation.oid=column_record.attrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(column_record.attacl) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('r','p','v','m','f')
          AND column_record.attnum>0 AND NOT column_record.attisdropped
          AND column_record.attacl IS NOT NULL
        ORDER BY namespace.nspname,relation.relname,column_record.attnum,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const constraints = await client.query(
      `SELECT namespace.nspname AS schema_name,COALESCE(relation.relname,'') AS relation_name,
              COALESCE(type_record.typname,'') AS type_name,constraint_record.conname,
              constraint_record.contype,constraint_record.condeferrable,constraint_record.condeferred,
              constraint_record.convalidated,constraint_record.connoinherit,
              pg_catalog.pg_get_constraintdef(constraint_record.oid,true) AS definition
         FROM pg_catalog.pg_constraint constraint_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=constraint_record.connamespace
         LEFT JOIN pg_catalog.pg_class relation ON relation.oid=constraint_record.conrelid
         LEFT JOIN pg_catalog.pg_type type_record ON type_record.oid=constraint_record.contypid
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,relation_name,type_name,constraint_record.conname,constraint_record.contype`,
    );
    const indexes = await client.query(
      `SELECT namespace.nspname AS schema_name,table_record.relname AS table_name,index_record.relname AS index_name,
              owner.rolname AS owner,index_state.indisunique,index_state.indisprimary,
              index_state.indisexclusion,index_state.indimmediate,index_state.indisclustered,
              index_state.indisvalid,index_state.indisready,index_state.indislive,
              index_state.indisreplident,pg_catalog.pg_get_indexdef(index_record.oid) AS definition
         FROM pg_catalog.pg_index index_state
         JOIN pg_catalog.pg_class index_record ON index_record.oid=index_state.indexrelid
         JOIN pg_catalog.pg_class table_record ON table_record.oid=index_state.indrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=table_record.relnamespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=index_record.relowner
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,table_record.relname,index_record.relname`,
    );
    const views = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS view_name,relation.relkind,relation.relispopulated,
              pg_catalog.pg_get_viewdef(relation.oid,true) AS definition
         FROM pg_catalog.pg_class relation
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND relation.relkind IN ('v','m')
        ORDER BY namespace.nspname,relation.relname,relation.relkind`,
    );
    const routines = await client.query(
      `SELECT namespace.nspname AS schema_name,format('%I.%I(%s)',namespace.nspname,routine.proname,
                replace(pg_catalog.pg_get_function_identity_arguments(routine.oid),', ',',')) AS signature,
              routine.prokind,language.lanname AS language,owner.rolname AS owner,
              routine.prosecdef,routine.proleakproof,routine.proisstrict,routine.proretset,
              routine.provolatile,routine.proparallel,routine.procost::text,routine.prorows::text,
              pg_catalog.pg_get_function_arguments(routine.oid) AS arguments,
              pg_catalog.pg_get_function_result(routine.oid) AS result,
              ARRAY(SELECT setting FROM unnest(COALESCE(routine.proconfig,ARRAY[]::text[])) setting ORDER BY setting) AS configuration,
              routine.prosrc,
              CASE WHEN routine.prokind='a' THEN NULL
                   ELSE pg_catalog.pg_get_functiondef(routine.oid) END AS definition
         FROM pg_catalog.pg_proc routine
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
         JOIN pg_catalog.pg_language language ON language.oid=routine.prolang
         JOIN pg_catalog.pg_roles owner ON owner.oid=routine.proowner
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,signature,routine.prokind`,
    );
    const routineAcl = await client.query(
      `SELECT namespace.nspname AS schema_name,format('%I.%I(%s)',namespace.nspname,routine.proname,
                replace(pg_catalog.pg_get_function_identity_arguments(routine.oid),', ',',')) AS signature,
              COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_proc routine
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))
         ) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,signature,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const triggers = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,trigger_record.tgname,
              trigger_record.tgenabled,trigger_record.tgisinternal,
              pg_catalog.pg_get_triggerdef(trigger_record.oid,true) AS definition
         FROM pg_catalog.pg_trigger trigger_record
         JOIN pg_catalog.pg_class relation ON relation.oid=trigger_record.tgrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,relation.relname,trigger_record.tgname`,
    );
    const types = await client.query(
      `SELECT namespace.nspname AS schema_name,type_record.typname AS type_name,type_record.typtype,type_record.typcategory,
              type_record.typnotnull,type_record.typdefault,owner.rolname AS owner,
              base_namespace.nspname AS base_schema,base_type.typname AS base_type,
              range_namespace.nspname AS range_subtype_schema,range_type.typname AS range_subtype,
              COALESCE((SELECT jsonb_agg(enum_record.enumlabel ORDER BY enum_record.enumsortorder)::text
                          FROM pg_catalog.pg_enum enum_record WHERE enum_record.enumtypid=type_record.oid),'[]') AS enum_labels
         FROM pg_catalog.pg_type type_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type_record.typnamespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=type_record.typowner
         LEFT JOIN pg_catalog.pg_type base_type ON base_type.oid=type_record.typbasetype
         LEFT JOIN pg_catalog.pg_namespace base_namespace ON base_namespace.oid=base_type.typnamespace
         LEFT JOIN pg_catalog.pg_range range_record ON range_record.rngtypid=type_record.oid
         LEFT JOIN pg_catalog.pg_type range_type ON range_type.oid=range_record.rngsubtype
         LEFT JOIN pg_catalog.pg_namespace range_namespace ON range_namespace.oid=range_type.typnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,type_record.typname,type_record.typtype`,
    );
    const typeAcl = await client.query(
      `SELECT namespace.nspname AS schema_name,type_record.typname AS type_name,COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_type type_record
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type_record.typnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(
           COALESCE(type_record.typacl,pg_catalog.acldefault('T',type_record.typowner))
         ) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,type_record.typname,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const policies = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,policy.polname,policy.polpermissive,policy.polcmd,
              ARRAY(SELECT COALESCE(role.rolname,'PUBLIC')
                      FROM unnest(policy.polroles) AS policy_role(role_oid)
                      LEFT JOIN pg_catalog.pg_roles role ON role.oid=policy_role.role_oid
                     ORDER BY COALESCE(role.rolname,'PUBLIC')) AS roles,
              pg_catalog.pg_get_expr(policy.polqual,policy.polrelid,true) AS using_expression,
              pg_catalog.pg_get_expr(policy.polwithcheck,policy.polrelid,true) AS check_expression
         FROM pg_catalog.pg_policy policy
         JOIN pg_catalog.pg_class relation ON relation.oid=policy.polrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        ORDER BY namespace.nspname,relation.relname,policy.polname`,
    );
    const defaultAcl = await client.query(
      `SELECT owner.rolname AS owner,COALESCE(namespace.nspname,'') AS schema_name,
              default_acl.defaclobjtype,COALESCE(grantee.rolname,'PUBLIC') AS grantee,
              acl.privilege_type::text,acl.is_grantable
         FROM pg_catalog.pg_default_acl default_acl
         JOIN pg_catalog.pg_roles owner ON owner.oid=default_acl.defaclrole
         LEFT JOIN pg_catalog.pg_namespace namespace ON namespace.oid=default_acl.defaclnamespace
         CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) acl
         LEFT JOIN pg_catalog.pg_roles grantee ON grantee.oid=acl.grantee
        WHERE default_acl.defaclnamespace=0 OR (
          namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
        )
        ORDER BY owner,schema_name,default_acl.defaclobjtype,grantee,acl.privilege_type,acl.is_grantable`,
    );
    const comments = await client.query(
      `WITH identified_comments AS (
         SELECT description.classoid,description.objoid,description.objsubid,description.description,
                identified.type AS object_type,identified.schema AS schema_name,
                identified.name AS object_name,identified.identity
           FROM pg_catalog.pg_description description
           CROSS JOIN LATERAL pg_catalog.pg_identify_object(
             description.classoid,description.objoid,description.objsubid
           ) identified
       )
       SELECT object_type,COALESCE(schema_name,'') AS schema_name,
              COALESCE(object_name,'') AS object_name,identity,
              encode(pg_catalog.sha256(pg_catalog.convert_to(description,'UTF8')),'hex') AS description_sha256
         FROM identified_comments comment_record
        WHERE (
          (comment_record.schema_name IS NOT NULL
            AND comment_record.schema_name NOT IN ('pg_catalog','information_schema')
            AND comment_record.schema_name !~ '^pg_toast(?:_|$)'
            AND comment_record.schema_name !~ '^pg_temp_')
          OR (comment_record.classoid='pg_catalog.pg_namespace'::regclass AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_namespace namespace
             WHERE namespace.oid=comment_record.objoid
               AND namespace.nspname NOT IN ('pg_catalog','information_schema')
               AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          ))
          OR comment_record.classoid IN (
            'pg_catalog.pg_event_trigger'::regclass,
            'pg_catalog.pg_publication'::regclass,
            'pg_catalog.pg_extension'::regclass
          )
        )
        ORDER BY object_type,schema_name,object_name,identity,description_sha256`,
    );
    const securityLabels = await client.query(
      `WITH identified_labels AS (
         SELECT label.classoid,label.objoid,label.objsubid,label.provider,label.label,
                identified.type AS object_type,identified.schema AS schema_name,
                identified.name AS object_name,identified.identity
           FROM pg_catalog.pg_seclabel label
           CROSS JOIN LATERAL pg_catalog.pg_identify_object(
             label.classoid,label.objoid,label.objsubid
           ) identified
       )
       SELECT object_type,COALESCE(schema_name,'') AS schema_name,
              COALESCE(object_name,'') AS object_name,identity,provider,
              encode(pg_catalog.sha256(pg_catalog.convert_to(label,'UTF8')),'hex') AS label_sha256
         FROM identified_labels label_record
        WHERE (
          (label_record.schema_name IS NOT NULL
            AND label_record.schema_name NOT IN ('pg_catalog','information_schema')
            AND label_record.schema_name !~ '^pg_toast(?:_|$)'
            AND label_record.schema_name !~ '^pg_temp_')
          OR (label_record.classoid='pg_catalog.pg_namespace'::regclass AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_namespace namespace
             WHERE namespace.oid=label_record.objoid
               AND namespace.nspname NOT IN ('pg_catalog','information_schema')
               AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          ))
          OR label_record.classoid IN (
            'pg_catalog.pg_event_trigger'::regclass,
            'pg_catalog.pg_publication'::regclass,
            'pg_catalog.pg_extension'::regclass
          )
        )
        ORDER BY object_type,schema_name,object_name,identity,provider,label_sha256`,
    );
    const eventTriggers = await client.query(
      `SELECT event_trigger.evtname,owner.rolname AS owner,event_trigger.evtevent::text AS event,
              event_trigger.evtenabled,event_trigger.evttags IS NULL AS all_command_tags,
              COALESCE(ARRAY(
                SELECT tag FROM unnest(event_trigger.evttags) tag ORDER BY tag
              ),ARRAY[]::text[]) AS command_tags,
              function_namespace.nspname AS function_schema,
              format('%I.%I(%s)',function_namespace.nspname,routine.proname,
                replace(pg_catalog.pg_get_function_identity_arguments(routine.oid),', ',',')) AS function_signature
         FROM pg_catalog.pg_event_trigger event_trigger
         JOIN pg_catalog.pg_roles owner ON owner.oid=event_trigger.evtowner
         JOIN pg_catalog.pg_proc routine ON routine.oid=event_trigger.evtfoid
         JOIN pg_catalog.pg_namespace function_namespace ON function_namespace.oid=routine.pronamespace
        ORDER BY event_trigger.evtname`,
    );
    const publications = await client.query(
      `SELECT publication.pubname,owner.rolname AS owner,publication.puballtables,
              publication.pubinsert,publication.pubupdate,publication.pubdelete,
              publication.pubtruncate,publication.pubviaroot,publication.pubgencols
         FROM pg_catalog.pg_publication publication
         JOIN pg_catalog.pg_roles owner ON owner.oid=publication.pubowner
        ORDER BY publication.pubname`,
    );
    const publicationSchemas = await client.query(
      `SELECT publication.pubname,namespace.nspname AS schema_name
         FROM pg_catalog.pg_publication_namespace publication_namespace
         JOIN pg_catalog.pg_publication publication ON publication.oid=publication_namespace.pnpubid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=publication_namespace.pnnspid
        ORDER BY publication.pubname,namespace.nspname`,
    );
    const publicationRelations = await client.query(
      `SELECT publication.pubname,namespace.nspname AS schema_name,relation.relname AS relation_name,
              publication_relation.prattrs IS NULL AS all_columns,
              COALESCE(ARRAY(
                SELECT attribute.attname::text
                  FROM unnest(publication_relation.prattrs::smallint[]) selected(attnum)
                  JOIN pg_catalog.pg_attribute attribute
                    ON attribute.attrelid=publication_relation.prrelid
                   AND attribute.attnum=selected.attnum
                 ORDER BY attribute.attname::text
              ),ARRAY[]::text[]) AS columns,
              pg_catalog.pg_get_expr(
                publication_relation.prqual,publication_relation.prrelid,true
              ) AS row_filter
         FROM pg_catalog.pg_publication_rel publication_relation
         JOIN pg_catalog.pg_publication publication ON publication.oid=publication_relation.prpubid
         JOIN pg_catalog.pg_class relation ON relation.oid=publication_relation.prrelid
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        ORDER BY publication.pubname,namespace.nspname,relation.relname`,
    );
    const effectivePublicationTables = await client.query(
      `SELECT publication_table.pubname,publication_table.schemaname,
              publication_table.tablename,ARRAY(
                SELECT column_name::text FROM unnest(publication_table.attnames) column_name
                 ORDER BY column_name::text
              ) AS columns,publication_table.rowfilter
         FROM pg_catalog.pg_publication_tables publication_table
        WHERE publication_table.schemaname NOT IN ('pg_catalog','information_schema')
          AND publication_table.schemaname !~ '^pg_toast(?:_|$)'
          AND publication_table.schemaname !~ '^pg_temp_'
        ORDER BY publication_table.pubname,publication_table.schemaname,publication_table.tablename`,
    );
    const subscriptions = await client.query(
      `SELECT subscription.subname,owner.rolname AS owner,subscription.subenabled,
              subscription.subbinary,subscription.substream,subscription.subtwophasestate,
              subscription.subdisableonerr,subscription.subpasswordrequired,
              subscription.subrunasowner,subscription.subfailover,
              encode(pg_catalog.sha256(pg_catalog.convert_to(subscription.subconninfo,'UTF8')),'hex') AS conninfo_sha256,
              subscription.subslotname,subscription.subsynccommit,
              ARRAY(SELECT publication FROM unnest(subscription.subpublications) publication ORDER BY publication) AS publications,
              subscription.suborigin,subscription.subskiplsn::text
         FROM pg_catalog.pg_subscription subscription
         JOIN pg_catalog.pg_roles owner ON owner.oid=subscription.subowner
        WHERE subscription.subdbid=(
          SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()
        )
        ORDER BY subscription.subname`,
    );
    const rewriteRules = await client.query(
      `SELECT namespace.nspname AS schema_name,relation.relname AS relation_name,
              rewrite.rulename,rewrite.ev_type,rewrite.ev_enabled,rewrite.is_instead,
              pg_catalog.pg_get_ruledef(rewrite.oid,true) AS definition
         FROM pg_catalog.pg_rewrite rewrite
         JOIN pg_catalog.pg_class relation ON relation.oid=rewrite.ev_class
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND NOT (rewrite.rulename='_RETURN' AND relation.relkind IN ('v','m'))
        ORDER BY namespace.nspname,relation.relname,rewrite.rulename`,
    );
    const extensions = await client.query(
      `SELECT extension.extname,extension.extversion,namespace.nspname AS schema_name,
              owner.rolname AS owner,extension.extrelocatable,
              extension.extconfig::text,extension.extcondition::text
         FROM pg_catalog.pg_extension extension
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=extension.extnamespace
         JOIN pg_catalog.pg_roles owner ON owner.oid=extension.extowner
        ORDER BY extension.extname`,
    );
    await client.query("ROLLBACK");
    transactionOpen = false;
    return digestProtectedDatabaseSnapshot({
      database,
      databaseMetadata: databaseMetadata.rows,
      databaseAcl: databaseAcl.rows,
      schemas: schemas.rows,
      relationStructure: relationStructure.rows,
      inheritance: inheritance.rows,
      relationAcl: relationAcl.rows,
      columns: columns.rows,
      columnAcl: columnAcl.rows,
      constraints: constraints.rows,
      indexes: indexes.rows,
      views: views.rows,
      routines: routines.rows,
      routineAcl: routineAcl.rows,
      triggers: triggers.rows,
      types: types.rows,
      typeAcl: typeAcl.rows,
      policies: policies.rows,
      defaultAcl: defaultAcl.rows,
      comments: comments.rows,
      securityLabels: securityLabels.rows,
      eventTriggers: eventTriggers.rows,
      publications: publications.rows,
      publicationSchemas: publicationSchemas.rows,
      publicationRelations: publicationRelations.rows,
      effectivePublicationTables: effectivePublicationTables.rows,
      subscriptions: subscriptions.rows,
      rewriteRules: rewriteRules.rows,
      extensions: extensions.rows,
      rowFingerprints: fingerprints,
      sequences: sequences.rows,
    });
  } finally {
    if (transactionOpen) await client.query("ROLLBACK").catch(() => undefined);
    client.release();
    await pool.end();
  }
}

function temporarySession(role: TestSession["role"]): TestSession {
  return {
    id: randomUUID(),
    identityId: randomUUID(),
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
    role,
  };
}

function syntheticIdentityEmail(label: string, identityId: string): string {
  return `real-browser-${label}-${identityId.replaceAll("-", "")}@invalid.example`;
}

function memberEnvelope(state: RunnerState, memberId: string, displayName: string): EncryptedEnvelope {
  return sealAesGcmJson(
    { displayName },
    state.tenantKey,
    state.tenantKeyId,
    { tenantId: state.names.tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
  );
}

function envelopeContentHash(envelope: EncryptedEnvelope): string {
  return `sha256:${sha256(JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  }))}`;
}

function digestCanonical(value: unknown): `sha256:${string}` {
  return `sha256:${sha256(canonicalJson(value))}`;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function safeFailureCode(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/^[A-Z][A-Z0-9_]{2,79}$/u.test(message)) return message;
  const code = error && typeof error === "object" ? (error as { readonly code?: unknown }).code : undefined;
  if (typeof code === "string" && /^SCN_[A-Z0-9_]{2,27}$/u.test(code)) return code;
  if (typeof code === "string" && /^[A-Z0-9]{2,10}$/u.test(code)) return `RUNTIME_${code}`;
  return "UNCLASSIFIED_FAILURE";
}

function discoverAdminUrl(): string {
  const configured = process.env["TEST_DATABASE_ADMIN_URL"];
  let candidate = configured;
  if (!candidate && existsSync(installFile)) {
    const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const value = (parsed as Record<string, unknown>)["DATABASE_ADMIN_URL"];
      if (typeof value === "string") candidate = value;
    }
  }
  if (!candidate) throw new Error("Workspace PostgreSQL administrator configuration is unavailable");
  return assertWorkspaceAdminUrl(candidate).toString();
}

function adminPoolConfig(databaseAdminUrl: string, database = "postgres"): PoolConfig {
  const value = assertWorkspaceAdminUrl(databaseAdminUrl);
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(database)) throw new Error("Database target name is invalid");
  return {
    host: value.hostname,
    port: Number(value.port),
    database,
    user: decodeURIComponent(value.username),
    password: decodeURIComponent(value.password),
    ssl: false,
    max: 1,
  };
}

function databaseUrl(databaseAdminUrl: string, database: string): string {
  const parsed = assertWorkspaceAdminUrl(databaseAdminUrl);
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(database)) throw new Error("Database target name is invalid");
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format an exact ephemeral DDL statement");
  await pool.query(sql);
}

function requireControl(state: RunnerState): Pool {
  if (!state.control) throw new Error("Ephemeral control pool is unavailable");
  return state.control;
}

function requireTenant(state: RunnerState): Pool {
  if (!state.tenant) throw new Error("Ephemeral tenant pool is unavailable");
  return state.tenant;
}

async function closeHttpServer(server: HttpServer): Promise<void> {
  if (!server.listening) return;
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function stopChildProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  if (await waitForChildExit(child, 5_000)) return;
  child.kill("SIGKILL");
  if (!await waitForChildExit(child, 5_000)) throw new Error("Child process remained active after forced termination");
}

async function waitForChildExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  return new Promise<boolean>((resolve) => {
    const timeout = setTimeout(() => {
      child.off("exit", onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = (): void => {
      clearTimeout(timeout);
      resolve(true);
    };
    child.once("exit", onExit);
  });
}

async function captureCleanupFailure(
  errors: Error[],
  message: string,
  operation: () => Promise<unknown>,
): Promise<void> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      operation(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error("Cleanup operation timed out")), 15_000);
      }),
    ]);
  } catch (cause) {
    errors.push(new Error(message, { cause }));
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function resolveWorkspaceRoot(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.resolve(moduleDirectory, "../../.."), path.resolve(moduleDirectory, "../../../.."), process.cwd()];
  const root = candidates.find((candidate) => existsSync(path.join(candidate, "pnpm-workspace.yaml")));
  if (!root) throw new Error("Workspace root is unavailable");
  return root;
}

function writeReport(report: RunReport): void {
  assertRunReportForPublication(report);
  writeJsonReport(artifactFile, report);
}

function writePreflightReport(report: PreflightReport): void {
  assertPreflightReportForPublication(report);
  writeJsonReport(preflightArtifactFile, report);
}

function writeFailClosedPreflightSentinel(report: PreflightReport): void {
  assertPreflightReportForPublication(report);
  try {
    mkdirSync(path.dirname(preflightArtifactFile), { recursive: true });
  } catch (cause) {
    throw new Error("ARTIFACT_DIRECTORY_CREATE_FAILED", { cause });
  }
  const payload = `${JSON.stringify(report, null, 2)}\n`;
  JSON.parse(payload);
  // The first write deliberately truncates historical evidence before writing.
  // A process crash can therefore leave a complete red sentinel or malformed
  // JSON, but can never leave the previous green preflight as current evidence.
  let descriptor: number;
  try {
    descriptor = openSync(preflightArtifactFile, "w");
  } catch (cause) {
    throw new Error("PREFLIGHT_SENTINEL_OPEN_FAILED", { cause });
  }
  try {
    writeFileSync(descriptor, payload, { encoding: "utf8" });
    fsyncSync(descriptor);
  } catch (cause) {
    throw new Error("PREFLIGHT_SENTINEL_WRITE_FAILED", { cause });
  } finally {
    closeSync(descriptor);
  }
}

function writeJsonReport(file: string, report: object): void {
  try {
    mkdirSync(path.dirname(file), { recursive: true });
  } catch (cause) {
    throw new Error("ARTIFACT_DIRECTORY_CREATE_FAILED", { cause });
  }
  const payload = `${JSON.stringify(report, null, 2)}\n`;
  JSON.parse(payload);
  const temporaryFile = `${file}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    try {
      writeFileSync(temporaryFile, payload, { encoding: "utf8", flag: "wx" });
    } catch (cause) {
      throw new Error("ARTIFACT_TEMP_WRITE_FAILED", { cause });
    }
    let descriptor: number;
    try {
      descriptor = openSync(temporaryFile, "r+");
    } catch (cause) {
      throw new Error("ARTIFACT_TEMP_OPEN_FAILED", { cause });
    }
    try {
      fsyncSync(descriptor);
    } catch (cause) {
      throw new Error("ARTIFACT_TEMP_SYNC_FAILED", { cause });
    } finally {
      closeSync(descriptor);
    }
    try {
      replaceArtifactFile(temporaryFile, file);
    } catch (cause) {
      throw new Error("ARTIFACT_REPLACE_FAILED", { cause });
    }
  } finally {
    if (existsSync(temporaryFile)) {
      try { unlinkSync(temporaryFile); } catch { /* stale temp is red evidence, never an authorization source */ }
    }
  }
}

function replaceArtifactFile(temporaryFile: string, destinationFile: string): void {
  try {
    renameSync(temporaryFile, destinationFile);
    return;
  } catch (error) {
    if (!existsSync(destinationFile)) throw error;
  }
  // Some Windows filesystems deny rename-over-existing even with Modify ACLs.
  // Invalidate the old destination before the fallback copy. A crash between
  // these operations leaves empty/malformed red evidence, never stale green.
  const invalidationDescriptor = openSync(destinationFile, "w");
  try {
    fsyncSync(invalidationDescriptor);
  } finally {
    closeSync(invalidationDescriptor);
  }
  copyFileSync(temporaryFile, destinationFile);
  const descriptor = openSync(destinationFile, "r+");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertRunReportForPublication(report: RunReport): void {
  const expected = deriveEphemeralNames(report.runId, report.ephemeralTargets.tenantId);
  for (const key of ["controlDatabase", "tenantDatabase", "ownerRole", "runtimeRole", "tenantSlug"] as const) {
    if (report.ephemeralTargets[key] !== expected[key]) throw new Error("REAL_STACK_REPORT_TARGET_INVALID");
  }
  const startedAt = Date.parse(report.startedAt);
  if (!Number.isFinite(startedAt)) throw new Error("REAL_STACK_REPORT_TIME_INVALID");
  if (report.inProgress) {
    if (report.status !== "in-progress" || report.completedAt !== undefined) {
      throw new Error("REAL_STACK_REPORT_STATE_INVALID");
    }
    return;
  }
  const completedAt = report.completedAt ? Date.parse(report.completedAt) : Number.NaN;
  if (!Number.isFinite(completedAt) || completedAt < startedAt || report.status === "in-progress") {
    throw new Error("REAL_STACK_REPORT_STATE_INVALID");
  }
  const passed = runReportClosureEvidencePasses(report);
  if ((report.status === "passed") !== passed) throw new Error("REAL_STACK_REPORT_STATE_INVALID");
}

function assertPreflightReportForPublication(report: PreflightReport): void {
  const startedAt = Date.parse(report.startedAt);
  if (!Number.isFinite(startedAt)) throw new Error("REAL_STACK_PREFLIGHT_REPORT_TIME_INVALID");
  if (report.inProgress) {
    if (report.status !== "in-progress" || report.pass || report.completedAt !== undefined) {
      throw new Error("REAL_STACK_PREFLIGHT_REPORT_STATE_INVALID");
    }
    return;
  }
  const completedAt = report.completedAt ? Date.parse(report.completedAt) : Number.NaN;
  if (!Number.isFinite(completedAt) || completedAt < startedAt || report.status === "in-progress") {
    throw new Error("REAL_STACK_PREFLIGHT_REPORT_STATE_INVALID");
  }
  const passed = preflightReportClosureEvidencePasses(report);
  if (report.pass !== passed || (report.status === "passed") !== passed) {
    throw new Error("REAL_STACK_PREFLIGHT_REPORT_STATE_INVALID");
  }
}

function preflightReportClosureEvidencePasses(report: PreflightReport): boolean {
  try {
    if (!report.pass
      || report.protectedDatabasesUnchanged !== true
      || !report.ephemeralControlDatabasesAbsent
      || !report.orphanTenantResourcesAbsent
      || !report.protectedFingerprints.before
      || !report.protectedFingerprints.after
      || !report.globalEphemeralResources.before
      || !report.globalEphemeralResources.after
      || !report.clusterCatalog.before
      || !report.clusterCatalog.after
      || report.operationalPorts.requiredFree.length !== RESERVED_APPLICATION_PORTS.length
      || report.operationalPorts.requiredFree.some((port, index) => port !== RESERVED_APPLICATION_PORTS[index])
      || report.failureStage !== undefined
      || report.failureCode !== undefined) return false;
    assertCleanupObservation({
      databases: 0,
      roles: 0,
      protectedBefore: report.protectedFingerprints.before,
      protectedAfter: report.protectedFingerprints.after,
    });
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.before);
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.after);
    assertClusterCatalogRestored(report.clusterCatalog.before, report.clusterCatalog.after);
    assertReservedApplicationPortsFree(report.operationalPorts.before);
    assertReservedApplicationPortsFree(report.operationalPorts.after);
    return true;
  } catch {
    return false;
  }
}

function runReportClosureEvidencePasses(report: RunReport): boolean {
  try {
    if (!report.scenarioPass
      || !report.scenarioObservation
      || !report.cleanupPass
      || report.protectedDatabasesUnchanged !== true
      || !report.mutationStarted
      || !report.cleanupDdlStarted
      || report.ephemeralCleanup.databaseCount !== 0
      || report.ephemeralCleanup.roleCount !== 0
      || !report.ephemeralCleanup.databasesAbsent
      || !report.ephemeralCleanup.rolesAbsent
      || !report.protectedFingerprints.before
      || !report.protectedFingerprints.after
      || !report.globalEphemeralResources.before
      || !report.globalEphemeralResources.after
      || !report.clusterCatalog.before
      || !report.clusterCatalog.after
      || report.operationalPorts.requiredFree.length !== RESERVED_APPLICATION_PORTS.length
      || report.operationalPorts.requiredFree.some((port, index) => port !== RESERVED_APPLICATION_PORTS[index])
      || report.operationalPorts.reservedPortsUsedByScenario
      || report.operationalPorts.api === null
      || report.operationalPorts.browserHarness === null
      || report.operationalPorts.api === report.operationalPorts.browserHarness
      || report.runFailureStage !== undefined
      || report.runFailureCode !== undefined
      || report.cleanupFailureStage !== undefined
      || report.cleanupFailureCode !== undefined) return false;
    assertCleanupObservation({
      databases: report.ephemeralCleanup.databaseCount,
      roles: report.ephemeralCleanup.roleCount,
      protectedBefore: report.protectedFingerprints.before,
      protectedAfter: report.protectedFingerprints.after,
    });
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.before);
    assertGlobalEphemeralResourcesAbsent(report.globalEphemeralResources.after);
    assertClusterCatalogRestored(report.clusterCatalog.before, report.clusterCatalog.after);
    assertReservedApplicationPortsFree(report.operationalPorts.before);
    assertReservedApplicationPortsFree(report.operationalPorts.after);
    assertIsolatedHttpOrigin(`http://localhost:${report.operationalPorts.api}`, "reported Fastify API");
    assertIsolatedHttpOrigin(
      `http://localhost:${report.operationalPorts.browserHarness}`,
      "reported browser harness",
    );
    return true;
  } catch {
    return false;
  }
}

const temporaryCatalog = {
  version: REAL_BROWSER_STACK_MARKER,
  departments: [{
    canonicalCode: "real_browser_stack_department",
    names: { es: "Departamento sintético", en: "Synthetic department", fr: "Département synthétique" },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "real_browser_stack_office",
    departmentCode: "real_browser_stack_department",
    names: { es: "Cargo sintético", en: "Synthetic office", fr: "Poste synthétique" },
    mechanism: "church_election",
    cardinality: { minimum: 1, maximum: 1 },
  }],
} as const;

main().catch((error) => {
  process.stderr.write(`Real browser-stack E2E FAIL at ${executionStage} (${safeFailureCode(error)}); sensitive diagnostics were suppressed.\n`);
  process.exitCode = 1;
});
