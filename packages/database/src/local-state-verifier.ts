import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Pool, PoolClient, QueryResultRow } from "pg";
import {
  readTenantCatalogEvidence,
  type TenantCatalogEvidence,
  type VersionedTenantCatalog,
} from "./catalog-reconciliation.js";
import { loadMigrationPlanEntries, type MigrationPlanEntry } from "./migrations.js";
import {
  TENANT_CONFIGURATION_TABLES,
  TENANT_OPERATIONAL_TABLES,
  tenantMaintenanceClass,
  type TenantMaintenanceClass,
} from "./tenant-maintenance-policy.js";
import {
  TENANT_RUNTIME_GRANT_CONTRACT,
  TENANT_SECURITY_DEFINER_FUNCTIONS,
} from "./runtime-grant-contract.js";

export const LOCAL_STATE_REPORT_SCHEMA_VERSION = 2;
export const WORKSPACE_POSTGRES_PORT = 55_432;
export const CONTROL_DATABASE_NAME = "nombramientos_control";
export const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
export const OZAMA_TENANT_ID = "0a2a0000-0000-4000-8000-000000000001";

const EXPECTED_CONTROL_MIGRATIONS = 26;
const EXPECTED_TENANT_MIGRATIONS = 38;
const EXPECTED_CONTROL_HEAD = "026_invitation_enrollment_recovery_qualification.sql";
const EXPECTED_TENANT_HEAD = "036_transactional_invitation_grantor_lock.sql";
const FORBIDDEN_OUTPUT_VALUE = /(?:postgres(?:ql)?:\/\/|tenant-db\/|nom_[or]_[0-9a-f]{32}|nom_t_[0-9a-f]{32}|(?:^|[^a-z0-9])(?:password|secret|token|totp)(?:$|[^a-z0-9])|[\w.+-]+@[\w.-]+\.[a-z]{2,})/iu;
const FORBIDDEN_OUTPUT_KEY = /(?:connection|string|databaseName|databaseHost|runtimeRole|ownerRole|secret|password|token|email|pii)/iu;

export type DemoFixtureExpectation = "before" | "after";

export interface QueryResultLike<Row extends QueryResultRow> {
  readonly rows: readonly Row[];
  readonly rowCount: number | null;
}

export interface ReadOnlyQueryClient {
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResultLike<Row>>;
}

const CATALOG_METADATA_STAGES = [
  "catalog-comments",
  "catalog-shared-comments",
  "catalog-security-labels",
  "catalog-shared-security-labels",
  "catalog-event-triggers",
  "catalog-publications",
  "catalog-publication-schemas",
  "catalog-publication-tables",
  "catalog-subscriptions",
  "catalog-rewrite-rules",
] as const;

export type LocalStateFailureStage = (typeof CATALOG_METADATA_STAGES)[number];

class LocalStateVerificationStageError extends Error {
  public readonly sqlState: string | undefined;

  public constructor(public readonly stage: LocalStateFailureStage, cause: unknown) {
    super("Local state verification stage failed");
    this.name = "LocalStateVerificationStageError";
    this.sqlState = safePostgresSqlState(cause);
  }
}

export interface MigrationLedgerEvidence {
  readonly expectedCount: number;
  readonly appliedCount: number;
  readonly pendingCount: number;
  readonly unexpectedCount: number;
  readonly checksumMismatchCount: number;
  readonly head: string | null;
  readonly expectedHead: string;
  readonly ledgerSha256: string;
  readonly mismatchCount: number;
}

export interface WorkerBacklogEvidence {
  readonly provisioningJobCount: number;
  readonly tenantExportJobCount: number;
  readonly totalCount: number;
  readonly mismatchCount: number;
}

export interface CatalogMetadataEvidence {
  readonly catalogSha256: string;
  readonly commentCount: number;
  readonly sharedCommentCount: number;
  readonly securityLabelCount: number;
  readonly eventTriggerCount: number;
  readonly publicationCount: number;
  readonly subscriptionCount: number;
  readonly rewriteRuleCount: number;
  readonly mismatchCount: number;
}

export interface LocalStateTenantEvidence {
  readonly kind: "demo" | "real" | "invalid";
  readonly lifecycle: string;
  readonly setupState: string;
  readonly maintenanceClass: TenantMaintenanceClass | "invalid";
  readonly migrations: MigrationLedgerEvidence;
  readonly schemaInventoryMismatchCount: number;
  readonly tableInventoryMismatchCount: number;
  readonly ownershipMismatchCount: number;
  readonly runtimeGrantMismatchCount: number;
  readonly catalogMetadata: CatalogMetadataEvidence;
  readonly institutionalCatalog: TenantCatalogEvidence;
  readonly memberCount?: number;
  readonly eligibleMemberCount?: number;
  readonly operationalTableCount?: number;
  readonly operationalRowCount?: number;
  readonly mismatchCount: number;
}

export interface LocalStateReport {
  readonly schemaVersion: typeof LOCAL_STATE_REPORT_SCHEMA_VERSION;
  readonly checkedAt: string;
  readonly mode: "read-only";
  readonly demoFixtureExpectation: DemoFixtureExpectation;
  readonly pass: boolean;
  readonly mismatchCount: number;
  readonly server: {
    readonly postgresMajor: number;
    readonly port: number;
    readonly loopback: boolean;
    readonly controlDatabaseMatch: boolean;
    readonly transactionReadOnly: boolean;
    readonly transactionIsolation: string;
    readonly administratorMatch: boolean;
    readonly mismatchCount: number;
  };
  readonly control: {
    readonly migrations: MigrationLedgerEvidence;
    readonly tenantRouteCount: number;
    readonly routeMismatchCount: number;
    readonly ozamaIdentityOrAdminArtifactCount: number;
    readonly workerBacklog: WorkerBacklogEvidence;
    readonly schemaInventoryMismatchCount: number;
    readonly roleMismatchCount: number;
    readonly catalogMetadata: CatalogMetadataEvidence;
    readonly mismatchCount: number;
  };
  readonly tenants: {
    readonly demo: LocalStateTenantEvidence;
    readonly ozama: LocalStateTenantEvidence;
  };
}

export interface RuntimeGrantSnapshot {
  readonly role: {
    readonly exists: boolean;
    readonly canLogin: boolean;
    readonly superuser: boolean;
    readonly createDatabase: boolean;
    readonly createRole: boolean;
    readonly replication: boolean;
    readonly bypassRls: boolean;
    readonly inherit: boolean;
    readonly connectionLimit: number;
    readonly hasPassword: boolean;
    readonly hasExpiration: boolean;
    readonly configurationCount: number;
    readonly membershipCount: number;
  };
  readonly database: {
    readonly runtimeConnect: boolean;
    readonly runtimeCreate: boolean;
    readonly runtimeTemporary: boolean;
    readonly publicConnect: boolean;
    readonly publicCreate: boolean;
    readonly publicTemporary: boolean;
  };
  readonly schema: {
    readonly runtimeUsage: boolean;
    readonly runtimeCreate: boolean;
    readonly publicUsage: boolean;
    readonly publicCreate: boolean;
  };
  readonly tablePrivileges: readonly string[];
  readonly columnPrivileges: readonly string[];
  readonly sequencePrivileges: readonly string[];
  readonly functionPrivileges: readonly string[];
  readonly grantOptionCount: number;
  readonly publicObjectPrivilegeCount: number;
  readonly foreignGranteePrivilegeCount: number;
  readonly securityDefinerFunctions: readonly {
    readonly signature: string;
    readonly publicExecute: boolean;
  }[];
}

export interface OwnershipSnapshot {
  readonly roleExists: boolean;
  readonly databaseOwned: boolean;
  readonly schemaOwnedByDatabaseOwner: boolean;
  readonly canLogin: boolean;
  readonly superuser: boolean;
  readonly createDatabase: boolean;
  readonly createRole: boolean;
  readonly replication: boolean;
  readonly bypassRls: boolean;
  readonly inherit: boolean;
  readonly connectionLimit: number;
  readonly hasPassword: boolean;
  readonly hasExpiration: boolean;
  readonly configurationCount: number;
  readonly membershipCount: number;
  readonly relationMismatchCount: number;
  readonly routineMismatchCount: number;
  readonly typeMismatchCount: number;
}

interface LocalStateVerifierOptions {
  readonly controlPool: Pick<Pool, "connect">;
  readonly tenantPool: (databaseName: string) => Pick<Pool, "connect">;
  readonly migrationsRoot: string;
  readonly demoFixtureExpectation: DemoFixtureExpectation;
  readonly catalog: VersionedTenantCatalog;
  readonly now?: () => Date;
}

interface ControlRouteRow extends QueryResultRow {
  readonly id: string;
  readonly slug: string;
  readonly display_name: string;
  readonly kind: string;
  readonly status: string;
  readonly timezone: string;
  readonly locale: string;
  readonly database_host: string;
  readonly database_port: number;
  readonly database_name: string;
  readonly runtime_role: string;
  readonly runtime_secret_ref: string;
  readonly credential_version: number;
  readonly ssl_mode: string;
  readonly latest_provisioning_state: string | null;
}

interface TenantIdentityRow extends QueryResultRow {
  readonly tenant_id: string;
  readonly display_name: string;
  readonly kind: string;
  readonly setup_state: string;
  readonly timezone: string;
  readonly locale: string;
  readonly database_name: string;
  readonly transaction_read_only: string;
  readonly transaction_isolation: string;
}

interface TenantSpecification {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly kind: "demo" | "real";
  readonly timezone: "America/Santo_Domingo";
  readonly locale: "es";
  readonly status: "active" | "provisioning";
  readonly latestProvisioningState: "active" | "pending_activation";
  readonly setupState: "ready" | "not_started";
  readonly maintenanceClass: TenantMaintenanceClass;
}

const DEMO_SPECIFICATION: TenantSpecification = {
  id: DEMO_TENANT_ID,
  slug: "iglesia-demostracion",
  displayName: "Iglesia Demostración",
  kind: "demo",
  timezone: "America/Santo_Domingo",
  locale: "es",
  status: "active",
  latestProvisioningState: "active",
  setupState: "ready",
  maintenanceClass: "routable",
};

const OZAMA_SPECIFICATION: TenantSpecification = {
  id: OZAMA_TENANT_ID,
  slug: "iglesia-adventista-ozama",
  displayName: "Iglesia Adventista Ozama",
  kind: "real",
  timezone: "America/Santo_Domingo",
  locale: "es",
  status: "provisioning",
  latestProvisioningState: "pending_activation",
  setupState: "not_started",
  maintenanceClass: "pending_activation",
};

export function assertLocalStateAdminUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Local state verification requires a valid PostgreSQL administrator URL");
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    throw new Error("Local state verification requires PostgreSQL");
  }
  if (parsed.hostname !== "127.0.0.1") {
    throw new Error("Local state verification requires exact IPv4 loopback PostgreSQL");
  }
  if (Number(parsed.port || "5432") !== WORKSPACE_POSTGRES_PORT) {
    throw new Error("Local state verification accepts workspace port 55432 only");
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    throw new Error("Local state verification refuses URL options and fragments");
  }
  if (decodeURIComponent(parsed.username) !== "nom_admin" || decodeURIComponent(parsed.password).length === 0) {
    throw new Error("Local state verification requires the protected nom_admin credential");
  }
  return parsed;
}

export function parseLocalStateVerificationArguments(
  args: readonly string[],
): { readonly demoFixtureExpectation: DemoFixtureExpectation } {
  let demoFixtureExpectation: DemoFixtureExpectation = "after";
  let seen = false;
  for (const argument of args) {
    const match = argument.match(/^--demo-fixture-state=(before|after)$/u);
    if (!match || seen) throw new Error("Unsupported or duplicate local state verification argument");
    demoFixtureExpectation = match[1] as DemoFixtureExpectation;
    seen = true;
  }
  return { demoFixtureExpectation };
}

export async function withReadOnlyTransaction<Result>(
  pool: Pick<Pool, "connect">,
  operation: (client: ReadOnlyQueryClient) => Promise<Result>,
): Promise<Result> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const guarded: ReadOnlyQueryClient = {
      query: async <Row extends QueryResultRow = QueryResultRow>(
        text: string,
        values: readonly unknown[] = [],
      ): Promise<QueryResultLike<Row>> => {
        assertReadOnlySql(text);
        return await client.query<Row>(text, [...values]);
      },
    };
    const result = await operation(guarded);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export function evaluateMigrationLedger(
  expected: readonly MigrationPlanEntry[],
  recorded: readonly MigrationPlanEntry[],
  expectedCount: number,
  expectedHead: string,
): MigrationLedgerEvidence {
  assertMigrationEntries(expected);
  assertMigrationEntries(recorded);
  const expectedByName = new Map(expected.map((entry) => [entry.name, entry.checksum]));
  const recordedByName = new Map(recorded.map((entry) => [entry.name, entry.checksum]));
  const pendingCount = [...expectedByName.keys()].filter((name) => !recordedByName.has(name)).length;
  const unexpectedCount = [...recordedByName.keys()].filter((name) => !expectedByName.has(name)).length;
  const checksumMismatchCount = [...expectedByName].filter(
    ([name, checksum]) => recordedByName.has(name) && recordedByName.get(name) !== checksum,
  ).length;
  const sortedRecorded = [...recorded].sort((left, right) => left.name.localeCompare(right.name));
  const rawHead = sortedRecorded.at(-1)?.name ?? null;
  const head = rawHead !== null && expectedByName.has(rawHead) ? rawHead : null;
  const mismatchCount = pendingCount
    + unexpectedCount
    + checksumMismatchCount
    + Number(expected.length !== expectedCount)
    + Number(recorded.length !== expectedCount)
    + Number(head !== expectedHead);
  return {
    expectedCount,
    appliedCount: recorded.length,
    pendingCount,
    unexpectedCount,
    checksumMismatchCount,
    head,
    expectedHead,
    ledgerSha256: migrationLedgerDigest(sortedRecorded),
    mismatchCount,
  };
}

export function evaluateRuntimeGrantSnapshot(snapshot: RuntimeGrantSnapshot): number {
  const expectedDatabase = new Set(TENANT_RUNTIME_GRANT_CONTRACT.database.runtime);
  const expectedPublicDatabase = new Set(TENANT_RUNTIME_GRANT_CONTRACT.database.public);
  const expectedSchema = new Set(TENANT_RUNTIME_GRANT_CONTRACT.schema.runtime);
  const expectedPublicSchema = new Set(TENANT_RUNTIME_GRANT_CONTRACT.schema.public);
  const expectedTables = flattenPrivilegeRecord(TENANT_RUNTIME_GRANT_CONTRACT.tables);
  const expectedColumns = flattenColumnPrivilegeRecord(TENANT_RUNTIME_GRANT_CONTRACT.columns);
  const expectedSequences = flattenPrivilegeRecord(TENANT_RUNTIME_GRANT_CONTRACT.sequences);
  const expectedFunctions = TENANT_RUNTIME_GRANT_CONTRACT.functions.map(
    (signature) => `${normalizeSignature(signature)}:EXECUTE`,
  );
  const expectedSecurityDefiners = TENANT_SECURITY_DEFINER_FUNCTIONS.map(normalizeSignature);
  const actualSecurityDefiners = snapshot.securityDefinerFunctions.map(({ signature }) => normalizeSignature(signature));

  return Number(!snapshot.role.exists)
    + Number(!snapshot.role.canLogin)
    + Number(snapshot.role.superuser)
    + Number(snapshot.role.createDatabase)
    + Number(snapshot.role.createRole)
    + Number(snapshot.role.replication)
    + Number(snapshot.role.bypassRls)
    + Number(!snapshot.role.inherit)
    + Number(snapshot.role.connectionLimit !== -1)
    + Number(!snapshot.role.hasPassword)
    + Number(snapshot.role.hasExpiration)
    + snapshot.role.configurationCount
    + snapshot.role.membershipCount
    + Number(snapshot.database.runtimeConnect !== expectedDatabase.has("CONNECT"))
    + Number(snapshot.database.runtimeCreate !== expectedDatabase.has("CREATE"))
    + Number(snapshot.database.runtimeTemporary !== expectedDatabase.has("TEMPORARY"))
    + Number(snapshot.database.publicConnect !== expectedPublicDatabase.has("CONNECT"))
    + Number(snapshot.database.publicCreate !== expectedPublicDatabase.has("CREATE"))
    + Number(snapshot.database.publicTemporary !== expectedPublicDatabase.has("TEMPORARY"))
    + Number(snapshot.schema.runtimeUsage !== expectedSchema.has("USAGE"))
    + Number(snapshot.schema.runtimeCreate !== expectedSchema.has("CREATE"))
    + Number(snapshot.schema.publicUsage !== expectedPublicSchema.has("USAGE"))
    + Number(snapshot.schema.publicCreate !== expectedPublicSchema.has("CREATE"))
    + symmetricDifferenceCount(expectedTables, snapshot.tablePrivileges)
    + symmetricDifferenceCount(expectedColumns, snapshot.columnPrivileges)
    + symmetricDifferenceCount(expectedSequences, snapshot.sequencePrivileges)
    + symmetricDifferenceCount(expectedFunctions, snapshot.functionPrivileges)
    + snapshot.grantOptionCount
    + snapshot.publicObjectPrivilegeCount
    + snapshot.foreignGranteePrivilegeCount
    + symmetricDifferenceCount(expectedSecurityDefiners, actualSecurityDefiners)
    + snapshot.securityDefinerFunctions.filter(({ publicExecute }) => publicExecute).length;
}

export function evaluateOwnershipSnapshot(snapshot: OwnershipSnapshot): number {
  return Number(!snapshot.roleExists)
    + Number(!snapshot.databaseOwned)
    + Number(!snapshot.schemaOwnedByDatabaseOwner)
    + Number(snapshot.canLogin)
    + Number(snapshot.superuser)
    + Number(snapshot.createDatabase)
    + Number(snapshot.createRole)
    + Number(snapshot.replication)
    + Number(snapshot.bypassRls)
    + Number(!snapshot.inherit)
    + Number(snapshot.connectionLimit !== -1)
    + Number(snapshot.hasPassword)
    + Number(snapshot.hasExpiration)
    + snapshot.configurationCount
    + snapshot.membershipCount
    + snapshot.relationMismatchCount
    + snapshot.routineMismatchCount
    + snapshot.typeMismatchCount;
}

export function evaluateDemoFixtureCounts(
  memberCount: number,
  eligibleMemberCount: number,
  expectation: DemoFixtureExpectation,
): number {
  const expectedMembers = expectation === "before" ? 181 : 180;
  const expectedEligible = expectation === "before" ? 151 : 150;
  return Number(memberCount !== expectedMembers) + Number(eligibleMemberCount !== expectedEligible);
}

export function evaluateOzamaOperationalState(
  operationalTableCount: number,
  operationalRowCount: number,
): number {
  return Number(operationalTableCount !== TENANT_OPERATIONAL_TABLES.length)
    + Number(operationalRowCount !== 0);
}

export function evaluateWorkerBacklog(
  provisioningJobCount: number,
  tenantExportJobCount: number,
): WorkerBacklogEvidence {
  const provisioning = nonNegativeInteger(provisioningJobCount);
  const exports = nonNegativeInteger(tenantExportJobCount);
  return {
    provisioningJobCount: provisioning,
    tenantExportJobCount: exports,
    totalCount: provisioning + exports,
    mismatchCount: Number(provisioning !== 0) + Number(exports !== 0),
  };
}

export async function verifyLocalState(options: LocalStateVerifierOptions): Promise<LocalStateReport> {
  const expectedControlMigrations = await loadMigrationPlanEntries(
    path.join(options.migrationsRoot, "control"),
  );
  const expectedTenantMigrations = await loadMigrationPlanEntries(
    path.join(options.migrationsRoot, "tenant"),
  );
  const expectedControlComments = await loadExpectedMigrationComments(
    path.join(options.migrationsRoot, "control"),
    expectedControlMigrations,
  );
  const expectedTenantComments = await loadExpectedMigrationComments(
    path.join(options.migrationsRoot, "tenant"),
    expectedTenantMigrations,
  );

  const controlSnapshot = await withReadOnlyTransaction(options.controlPool, async (client) => {
    const server = await readServerEvidence(client);
    const migrationRows = await readMigrationLedger(client);
    const routes = await readControlRoutes(client);
    const ozamaArtifacts = await readOzamaIdentityOrAdminArtifacts(client);
    const workerBacklog = await readWorkerBacklog(client);
    const schemaInventoryMismatchCount = await readUserSchemaInventoryMismatchCount(client);
    const roleMismatchCount = await readProtectedControlRoleMismatchCount(client);
    const catalogMetadata = await readCatalogMetadataEvidence(
      client,
      expectedControlComments,
      ["nom_admin", "nom_control"],
    );
    return {
      server,
      migrationRows,
      routes,
      ozamaArtifacts,
      workerBacklog,
      schemaInventoryMismatchCount,
      roleMismatchCount,
      catalogMetadata,
    };
  });

  const controlMigrations = evaluateMigrationLedger(
    expectedControlMigrations,
    controlSnapshot.migrationRows,
    EXPECTED_CONTROL_MIGRATIONS,
    EXPECTED_CONTROL_HEAD,
  );
  const routeMismatchCount = evaluateControlRoutes(controlSnapshot.routes);
  const controlMismatchCount = controlMigrations.mismatchCount
    + routeMismatchCount
    + controlSnapshot.ozamaArtifacts
    + controlSnapshot.workerBacklog.mismatchCount
    + controlSnapshot.schemaInventoryMismatchCount
    + controlSnapshot.roleMismatchCount
    + controlSnapshot.catalogMetadata.mismatchCount;

  const demoRoute = controlSnapshot.routes.find(({ id }) => id === DEMO_TENANT_ID);
  const ozamaRoute = controlSnapshot.routes.find(({ id }) => id === OZAMA_TENANT_ID);
  const demo = await verifyTenant(
    options.tenantPool(databaseNameFor(DEMO_TENANT_ID)),
    DEMO_SPECIFICATION,
    demoRoute,
    expectedTenantMigrations,
    expectedTenantComments,
    options.demoFixtureExpectation,
    options.catalog,
  );
  const ozama = await verifyTenant(
    options.tenantPool(databaseNameFor(OZAMA_TENANT_ID)),
    OZAMA_SPECIFICATION,
    ozamaRoute,
    expectedTenantMigrations,
    expectedTenantComments,
    options.demoFixtureExpectation,
    options.catalog,
  );

  const serverMismatchCount = Number(controlSnapshot.server.postgresMajor !== 18)
    + Number(controlSnapshot.server.port !== WORKSPACE_POSTGRES_PORT)
    + Number(!controlSnapshot.server.loopback)
    + Number(!controlSnapshot.server.controlDatabaseMatch)
    + Number(!controlSnapshot.server.transactionReadOnly)
    + Number(controlSnapshot.server.transactionIsolation !== "repeatable read")
    + Number(!controlSnapshot.server.administratorMatch);
  const mismatchCount = serverMismatchCount + controlMismatchCount + demo.mismatchCount + ozama.mismatchCount;
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  return {
    schemaVersion: LOCAL_STATE_REPORT_SCHEMA_VERSION,
    checkedAt,
    mode: "read-only",
    demoFixtureExpectation: options.demoFixtureExpectation,
    pass: mismatchCount === 0,
    mismatchCount,
    server: { ...controlSnapshot.server, mismatchCount: serverMismatchCount },
    control: {
      migrations: controlMigrations,
      tenantRouteCount: controlSnapshot.routes.length,
      routeMismatchCount,
      ozamaIdentityOrAdminArtifactCount: controlSnapshot.ozamaArtifacts,
      workerBacklog: controlSnapshot.workerBacklog,
      schemaInventoryMismatchCount: controlSnapshot.schemaInventoryMismatchCount,
      roleMismatchCount: controlSnapshot.roleMismatchCount,
      catalogMetadata: controlSnapshot.catalogMetadata,
      mismatchCount: controlMismatchCount,
    },
    tenants: { demo, ozama },
  };
}

export function serializeSanitizedLocalStateReport(report: LocalStateReport): string {
  assertSafeOutputValue(report, []);
  const serialized = JSON.stringify(report);
  // The immutable migration filename is public source metadata, not a
  // credential. Keep the broad serialized-value backstop while replacing only
  // the two exact, path-validated head literals that may contain a reserved
  // security word.
  const serializationProbe = serialized
    .replaceAll(JSON.stringify(EXPECTED_CONTROL_HEAD), '"control_migration_head.sql"')
    .replaceAll(JSON.stringify(EXPECTED_TENANT_HEAD), '"tenant_migration_head.sql"');
  if (FORBIDDEN_OUTPUT_VALUE.test(serializationProbe)) {
    throw new Error("Local state report failed output sanitization");
  }
  return serialized;
}

export function serializeSanitizedLocalStateFailure(
  now: Date = new Date(),
  stage?: LocalStateFailureStage,
  sqlState?: string,
): string {
  return JSON.stringify({
    schemaVersion: LOCAL_STATE_REPORT_SCHEMA_VERSION,
    checkedAt: now.toISOString(),
    mode: "read-only",
    pass: false,
    verificationIncomplete: true,
    errorCode: "LOCAL_STATE_VERIFICATION_FAILED",
    ...(stage ? { stage } : {}),
    ...(sqlState ? { sqlState } : {}),
  });
}

export function localStateFailureStage(error: unknown): LocalStateFailureStage | undefined {
  return error instanceof LocalStateVerificationStageError ? error.stage : undefined;
}

export function localStateFailureSqlState(error: unknown): string | undefined {
  return error instanceof LocalStateVerificationStageError ? error.sqlState : undefined;
}

async function verifyTenant(
  pool: Pick<Pool, "connect">,
  specification: TenantSpecification,
  route: ControlRouteRow | undefined,
  expectedMigrations: readonly MigrationPlanEntry[],
  expectedComments: readonly CatalogCommentFingerprint[],
  demoFixtureExpectation: DemoFixtureExpectation,
  catalog: VersionedTenantCatalog,
): Promise<LocalStateTenantEvidence> {
  return await withReadOnlyTransaction(pool, async (client) => {
    const identity = await readTenantIdentity(client);
    const migrations = evaluateMigrationLedger(
      expectedMigrations,
      await readMigrationLedger(client),
      EXPECTED_TENANT_MIGRATIONS,
      EXPECTED_TENANT_HEAD,
    );
    const ownershipMismatchCount = evaluateOwnershipSnapshot(
      await readOwnershipSnapshot(client, ownerRoleFor(specification.id)),
    );
    const runtimeGrantMismatchCount = evaluateRuntimeGrantSnapshot(
      await readRuntimeGrantSnapshot(client, runtimeRoleFor(specification.id)),
    );
    const schemaInventoryMismatchCount = await readUserSchemaInventoryMismatchCount(client);
    const tableInventoryMismatchCount = await readTenantTableInventoryMismatchCount(client);
    const catalogMetadata = await readCatalogMetadataEvidence(
      client,
      expectedComments,
      [ownerRoleFor(specification.id), runtimeRoleFor(specification.id)],
    );
    const institutionalCatalog = await readTenantCatalogEvidence(client, catalog);
    const maintenanceClass: LocalStateTenantEvidence["maintenanceClass"] = route
      ? tenantMaintenanceClass({
        kind: route.kind,
        status: route.status,
        latestProvisioningState: route.latest_provisioning_state,
      }) ?? "invalid"
      : "invalid";
    let mismatchCount = migrations.mismatchCount
      + ownershipMismatchCount
      + runtimeGrantMismatchCount
      + schemaInventoryMismatchCount
      + tableInventoryMismatchCount
      + catalogMetadata.mismatchCount
      + institutionalCatalog.mismatchCount
      + Number(identity.tenant_id !== specification.id)
      + Number(identity.display_name !== specification.displayName)
      + Number(identity.kind !== specification.kind)
      + Number(identity.setup_state !== specification.setupState)
      + Number(identity.timezone !== specification.timezone)
      + Number(identity.locale !== specification.locale)
      + Number(identity.database_name !== databaseNameFor(specification.id))
      + Number(identity.transaction_read_only !== "on")
      + Number(identity.transaction_isolation !== "repeatable read")
      + Number(maintenanceClass !== specification.maintenanceClass);

    const kind: LocalStateTenantEvidence["kind"] =
      identity.kind === "demo" || identity.kind === "real" ? identity.kind : "invalid";
    const base = {
      kind,
      lifecycle: safeLifecycle(route?.status),
      setupState: safeSetupState(identity.setup_state),
      maintenanceClass,
      migrations,
      schemaInventoryMismatchCount,
      tableInventoryMismatchCount,
      ownershipMismatchCount,
      runtimeGrantMismatchCount,
      catalogMetadata,
      institutionalCatalog,
    };
    if (specification.kind === "demo") {
      const counts = await readDemoFixtureCounts(client);
      mismatchCount += evaluateDemoFixtureCounts(
        counts.memberCount,
        counts.eligibleMemberCount,
        demoFixtureExpectation,
      );
      return { ...base, ...counts, mismatchCount };
    }
    const operational = await readOzamaOperationalState(client);
    mismatchCount += evaluateOzamaOperationalState(
      operational.operationalTableCount,
      operational.operationalRowCount,
    );
    return { ...base, ...operational, mismatchCount };
  });
}

async function readServerEvidence(client: ReadOnlyQueryClient): Promise<{
  readonly postgresMajor: number;
  readonly port: number;
  readonly loopback: boolean;
  readonly controlDatabaseMatch: boolean;
  readonly transactionReadOnly: boolean;
  readonly transactionIsolation: string;
  readonly administratorMatch: boolean;
}> {
  const result = await client.query<{
    server_version_num: number;
    port: number;
    server_loopback: boolean;
    database_name: string;
    transaction_read_only: string;
    transaction_isolation: string;
    current_user: string;
  }>(
    `SELECT current_setting('server_version_num')::int AS server_version_num,
            current_setting('port')::int AS port,
            CASE
              WHEN address.value IS NULL THEN false
              WHEN pg_catalog.family(address.value)=4
                THEN address.value <<= inet '127.0.0.0/8'
              WHEN pg_catalog.family(address.value)=6
                THEN address.value <<= inet '::1/128'
                  OR address.value <<= inet '::ffff:127.0.0.0/104'
              ELSE false
            END AS server_loopback,
            current_database() AS database_name,
            current_user,
            current_setting('transaction_read_only') AS transaction_read_only,
            current_setting('transaction_isolation') AS transaction_isolation
       FROM (SELECT inet_server_addr() AS value) address`,
  );
  const row = requireSingleRow(result, "server evidence");
  return {
    postgresMajor: Math.floor(row.server_version_num / 10_000),
    port: row.port,
    loopback: row.server_loopback,
    controlDatabaseMatch: row.database_name === CONTROL_DATABASE_NAME,
    transactionReadOnly: row.transaction_read_only === "on",
    transactionIsolation: row.transaction_isolation,
    administratorMatch: row.current_user === "nom_admin",
  };
}

async function readMigrationLedger(client: ReadOnlyQueryClient): Promise<readonly MigrationPlanEntry[]> {
  const result = await client.query<{ name: string; checksum: string }>(
    "SELECT name,checksum FROM public.schema_migrations ORDER BY name",
  );
  return result.rows.map(({ name, checksum }) => ({ name, checksum }));
}

async function readControlRoutes(client: ReadOnlyQueryClient): Promise<readonly ControlRouteRow[]> {
  const result = await client.query<ControlRouteRow>(
    `SELECT tenant.id::text,tenant.slug,tenant.display_name,tenant.kind,tenant.status,
            tenant.timezone,tenant.locale,tenant.database_host,
            tenant.database_port,tenant.database_name::text,tenant.runtime_role::text,
            tenant.runtime_secret_ref,tenant.credential_version,tenant.ssl_mode,
            latest_job.state AS latest_provisioning_state
       FROM public.tenants tenant
       LEFT JOIN LATERAL (
         SELECT job.state
           FROM public.provisioning_jobs job
          WHERE job.tenant_id=tenant.id
          ORDER BY job.updated_at DESC,job.created_at DESC,job.id DESC
          LIMIT 1
       ) latest_job ON true
      ORDER BY tenant.id`,
  );
  return result.rows;
}

async function readOzamaIdentityOrAdminArtifacts(client: ReadOnlyQueryClient): Promise<number> {
  const result = await client.query<{ artifacts: number }>(
    `SELECT (
       (SELECT count(*) FROM public.tenant_memberships WHERE tenant_id=$1)
       +(SELECT count(*) FROM public.tenant_invitations WHERE tenant_id=$1)
       +(SELECT count(*) FROM public.auth_sessions WHERE active_tenant_id=$1)
       +(SELECT count(*) FROM public.mfa_challenges WHERE tenant_id=$1)
       +(SELECT count(*) FROM public.platform_admin_bootstrap_tokens WHERE anchor_tenant_id=$1)
     )::int AS artifacts`,
    [OZAMA_TENANT_ID],
  );
  return nonNegativeInteger(requireSingleRow(result, "Ozama identity evidence").artifacts);
}

async function readWorkerBacklog(client: ReadOnlyQueryClient): Promise<WorkerBacklogEvidence> {
  const result = await client.query<{
    provisioning_jobs: number;
    tenant_export_jobs: number;
  }>(
    `SELECT
       (SELECT count(*)::int
          FROM public.provisioning_jobs
         WHERE state NOT IN ('active','pending_activation')) AS provisioning_jobs,
       (SELECT count(*)::int
          FROM public.tenant_export_jobs
         WHERE state <> 'ready') AS tenant_export_jobs`,
  );
  const row = requireSingleRow(result, "worker backlog evidence");
  return evaluateWorkerBacklog(row.provisioning_jobs, row.tenant_export_jobs);
}

async function readProtectedControlRoleMismatchCount(client: ReadOnlyQueryClient): Promise<number> {
  const result = await client.query<{
    role_name: string;
    can_login: boolean;
    superuser: boolean;
    create_database: boolean;
    create_role: boolean;
    replication: boolean;
    bypass_rls: boolean;
    inherit: boolean;
    connection_limit: number;
    has_password: boolean;
    has_expiration: boolean;
    configuration_count: number;
    membership_count: number;
  }>(
    `SELECT role.rolname AS role_name,role.rolcanlogin AS can_login,
            role.rolsuper AS superuser,role.rolcreatedb AS create_database,
            role.rolcreaterole AS create_role,role.rolreplication AS replication,
            role.rolbypassrls AS bypass_rls,role.rolinherit AS inherit,
            role.rolconnlimit AS connection_limit,credential.rolpassword IS NOT NULL AS has_password,
            role.rolvaliduntil IS NOT NULL AND role.rolvaliduntil <> 'infinity'::timestamptz AS has_expiration,
            COALESCE(cardinality(role.rolconfig),0)::int AS configuration_count,
            (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
              WHERE membership.member=role.oid OR membership.roleid=role.oid) AS membership_count
       FROM pg_catalog.pg_roles role
       JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
      WHERE role.rolname=ANY($1::text[])
      ORDER BY role.rolname`,
    [["nom_admin", "nom_control"]],
  );
  const expected = new Map([
    ["nom_admin", {
      canLogin: true,
      superuser: true,
      createDatabase: true,
      createRole: true,
      replication: true,
      bypassRls: true,
    }],
    ["nom_control", {
      canLogin: true,
      superuser: false,
      createDatabase: false,
      createRole: false,
      replication: false,
      bypassRls: false,
    }],
  ] as const);
  let mismatches = Number(result.rows.length !== expected.size);
  for (const [roleName, contract] of expected) {
    const role = result.rows.find(({ role_name }) => role_name === roleName);
    if (!role) {
      mismatches += 1;
      continue;
    }
    mismatches += Number(role.can_login !== contract.canLogin)
      + Number(role.superuser !== contract.superuser)
      + Number(role.create_database !== contract.createDatabase)
      + Number(role.create_role !== contract.createRole)
      + Number(role.replication !== contract.replication)
      + Number(role.bypass_rls !== contract.bypassRls)
      + Number(!role.inherit)
      + Number(role.connection_limit !== -1)
      + Number(!role.has_password)
      + Number(role.has_expiration)
      + nonNegativeInteger(role.configuration_count)
      + nonNegativeInteger(role.membership_count);
  }
  return mismatches;
}

function evaluateControlRoutes(routes: readonly ControlRouteRow[]): number {
  const specifications = [DEMO_SPECIFICATION, OZAMA_SPECIFICATION];
  let mismatches = Number(routes.length !== specifications.length);
  for (const specification of specifications) {
    const candidates = routes.filter(({ id }) => id === specification.id);
    if (candidates.length !== 1) {
      mismatches += 1;
      continue;
    }
    const route = candidates[0]!;
    mismatches += Number(route.kind !== specification.kind)
      + Number(route.slug !== specification.slug)
      + Number(route.display_name !== specification.displayName)
      + Number(route.status !== specification.status)
      + Number(route.timezone !== specification.timezone)
      + Number(route.locale !== specification.locale)
      + Number(route.latest_provisioning_state !== specification.latestProvisioningState)
      + Number(route.database_host !== "127.0.0.1")
      + Number(route.database_port !== WORKSPACE_POSTGRES_PORT)
      + Number(route.database_name !== databaseNameFor(specification.id))
      + Number(route.runtime_role !== runtimeRoleFor(specification.id))
      + Number(route.credential_version < 1)
      + Number(route.runtime_secret_ref !== `tenant-db/${specification.id}/runtime/v${route.credential_version}`)
      + Number(route.ssl_mode !== "disable");
  }
  return mismatches;
}

async function readTenantIdentity(client: ReadOnlyQueryClient): Promise<TenantIdentityRow> {
  const result = await client.query<TenantIdentityRow>(
    `SELECT settings.tenant_id::text,settings.display_name,settings.kind,settings.setup_state,
            settings.timezone,settings.locale,
            current_database() AS database_name,
            current_setting('transaction_read_only') AS transaction_read_only,
            current_setting('transaction_isolation') AS transaction_isolation
       FROM public.tenant_settings settings
      WHERE settings.singleton=true`,
  );
  return requireSingleRow(result, "tenant identity");
}

async function readUserSchemaInventoryMismatchCount(client: ReadOnlyQueryClient): Promise<number> {
  const result = await client.query<{ name: string }>(
    `SELECT namespace.nspname AS name
       FROM pg_catalog.pg_namespace namespace
      WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
        AND namespace.nspname !~ '^pg_toast'
        AND namespace.nspname !~ '^pg_temp_'
      ORDER BY namespace.nspname`,
  );
  return symmetricDifferenceCount(["public"], result.rows.map(({ name }) => name));
}

interface CatalogCommentFingerprint extends QueryResultRow {
  readonly kind: string;
  readonly identity: string;
  readonly description_sha256: string;
}

export function digestCatalogMetadataSnapshot(
  snapshot: Readonly<Record<string, unknown>>,
): string {
  return createHash("sha256").update(canonicalJson(snapshot), "utf8").digest("hex");
}

async function readCatalogMetadataEvidence(
  client: ReadOnlyQueryClient,
  expectedComments: readonly CatalogCommentFingerprint[],
  protectedRoleNames: readonly string[],
): Promise<CatalogMetadataEvidence> {
  const comments = await queryCatalogMetadataStage<CatalogCommentFingerprint>(
    client,
    "catalog-comments",
    `SELECT kind,identity,
            encode(pg_catalog.sha256(pg_catalog.convert_to(description,'UTF8')),'hex') AS description_sha256
       FROM (
       SELECT CASE relation.relkind
                WHEN 'i' THEN 'INDEX' WHEN 'I' THEN 'INDEX'
                WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE'
              END AS kind,
              format('%I.%I',namespace.nspname,relation.relname) AS identity,
              description.description
         FROM pg_catalog.pg_description description
         JOIN pg_catalog.pg_class relation
           ON description.classoid='pg_catalog.pg_class'::regclass
          AND description.objoid=relation.oid AND description.objsubid=0
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_depend dependency
             WHERE dependency.classid='pg_catalog.pg_class'::regclass
               AND dependency.objid=relation.oid AND dependency.deptype IN ('e','x')
          )
       UNION ALL
       SELECT 'COLUMN' AS kind,
              format('%I.%I.%I',namespace.nspname,relation.relname,attribute.attname) AS identity,
              description.description
         FROM pg_catalog.pg_description description
         JOIN pg_catalog.pg_class relation
           ON description.classoid='pg_catalog.pg_class'::regclass
          AND description.objoid=relation.oid AND description.objsubid>0
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
         JOIN pg_catalog.pg_attribute attribute
           ON attribute.attrelid=relation.oid AND attribute.attnum=description.objsubid
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND NOT attribute.attisdropped
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_depend dependency
             WHERE dependency.classid='pg_catalog.pg_class'::regclass
               AND dependency.objid=relation.oid AND dependency.deptype IN ('e','x')
          )
       UNION ALL
       SELECT 'CONSTRAINT' AS kind,
              format('%I.%I.%I',namespace.nspname,COALESCE(relation.relname,type_record.typname),constraint_record.conname) AS identity,
              description.description
         FROM pg_catalog.pg_description description
         JOIN pg_catalog.pg_constraint constraint_record
           ON description.classoid='pg_catalog.pg_constraint'::regclass
          AND description.objoid=constraint_record.oid AND description.objsubid=0
         JOIN pg_catalog.pg_namespace namespace ON namespace.oid=constraint_record.connamespace
         LEFT JOIN pg_catalog.pg_class relation ON relation.oid=constraint_record.conrelid
         LEFT JOIN pg_catalog.pg_type type_record ON type_record.oid=constraint_record.contypid
        WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
          AND namespace.nspname !~ '^pg_toast(?:_|$)' AND namespace.nspname !~ '^pg_temp_'
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_depend dependency
             WHERE dependency.classid='pg_catalog.pg_constraint'::regclass
               AND dependency.objid=constraint_record.oid AND dependency.deptype IN ('e','x')
          )
       UNION ALL
       SELECT 'OTHER:' || identified.type AS kind,identified.identity,description.description
         FROM pg_catalog.pg_description description
         CROSS JOIN LATERAL pg_catalog.pg_identify_object(
           description.classoid,description.objoid,description.objsubid
         ) identified
        WHERE description.classoid NOT IN (
                'pg_catalog.pg_class'::regclass,'pg_catalog.pg_constraint'::regclass,
                'pg_catalog.pg_namespace'::regclass,'pg_catalog.pg_extension'::regclass
              )
          AND identified.schema IS NOT NULL
          AND identified.schema NOT IN ('pg_catalog','information_schema')
          AND identified.schema !~ '^pg_toast(?:_|$)' AND identified.schema !~ '^pg_temp_'
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_depend dependency
             WHERE dependency.classid=description.classoid
               AND dependency.objid=description.objoid AND dependency.deptype IN ('e','x')
          )
     ) catalog_comments
      ORDER BY kind,identity,description_sha256`,
  );
  const sharedComments = await queryCatalogMetadataStage(
    client,
    "catalog-shared-comments",
    `SELECT identified.type AS object_type,COALESCE(identified.name,'') AS object_name,
            identified.identity,
            encode(pg_catalog.sha256(pg_catalog.convert_to(description.description,'UTF8')),'hex') AS description_sha256
       FROM pg_catalog.pg_shdescription description
       CROSS JOIN LATERAL pg_catalog.pg_identify_object(
         description.classoid,description.objoid,0
       ) identified
      WHERE (description.classoid='pg_catalog.pg_database'::regclass
             AND description.objoid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()))
         OR (description.classoid='pg_catalog.pg_authid'::regclass AND EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles role
            WHERE role.oid=description.objoid AND role.rolname=ANY($1::text[])
         ))
         OR (description.classoid='pg_catalog.pg_subscription'::regclass AND EXISTS (
           SELECT 1 FROM pg_catalog.pg_subscription subscription
            WHERE subscription.oid=description.objoid
              AND subscription.subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
         ))
      ORDER BY object_type,object_name,identified.identity,description_sha256`,
    [[...protectedRoleNames]],
  );
  const securityLabels = await queryCatalogMetadataStage(
    client,
    "catalog-security-labels",
    `SELECT object_type,COALESCE(schema_name,'') AS schema_name,
            COALESCE(object_name,'') AS object_name,identity,provider,
            encode(pg_catalog.sha256(pg_catalog.convert_to(label,'UTF8')),'hex') AS label_sha256
       FROM (
       SELECT label.classoid,label.objoid,label.objsubid,label.provider,label.label,
              identified.type AS object_type,identified.schema AS schema_name,
              identified.name AS object_name,identified.identity
         FROM pg_catalog.pg_seclabel label
         CROSS JOIN LATERAL pg_catalog.pg_identify_object(
           label.classoid,label.objoid,label.objsubid
         ) identified
     ) label_record
      WHERE ((label_record.schema_name IS NOT NULL
          AND label_record.schema_name NOT IN ('pg_catalog','information_schema')
          AND label_record.schema_name !~ '^pg_toast(?:_|$)' AND label_record.schema_name !~ '^pg_temp_')
         OR label_record.classoid IN (
           'pg_catalog.pg_event_trigger'::regclass,'pg_catalog.pg_publication'::regclass
         ))
        AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend dependency
           WHERE dependency.classid=label_record.classoid
             AND dependency.objid=label_record.objoid AND dependency.deptype IN ('e','x')
        )
      ORDER BY object_type,schema_name,object_name,identity,provider,label_sha256`,
  );
  const sharedSecurityLabels = await queryCatalogMetadataStage(
    client,
    "catalog-shared-security-labels",
    `SELECT identified.type AS object_type,COALESCE(identified.name,'') AS object_name,
            identified.identity,label.provider,
            encode(pg_catalog.sha256(pg_catalog.convert_to(label.label,'UTF8')),'hex') AS label_sha256
       FROM pg_catalog.pg_shseclabel label
       CROSS JOIN LATERAL pg_catalog.pg_identify_object(label.classoid,label.objoid,0) identified
      WHERE (label.classoid='pg_catalog.pg_database'::regclass
             AND label.objoid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()))
         OR (label.classoid='pg_catalog.pg_authid'::regclass AND EXISTS (
           SELECT 1 FROM pg_catalog.pg_roles role
            WHERE role.oid=label.objoid AND role.rolname=ANY($1::text[])
         ))
         OR (label.classoid='pg_catalog.pg_subscription'::regclass AND EXISTS (
           SELECT 1 FROM pg_catalog.pg_subscription subscription
            WHERE subscription.oid=label.objoid
              AND subscription.subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
         ))
      ORDER BY object_type,object_name,identified.identity,label.provider,label_sha256`,
    [[...protectedRoleNames]],
  );
  const eventTriggers = await queryCatalogMetadataStage(
    client,
    "catalog-event-triggers",
    `SELECT event_trigger.evtname,owner.rolname AS owner,event_trigger.evtevent::text AS event,
            event_trigger.evtenabled,event_trigger.evttags IS NULL AS all_command_tags,
            COALESCE(ARRAY(SELECT tag FROM unnest(event_trigger.evttags) tag ORDER BY tag),ARRAY[]::text[]) AS command_tags,
            format('%I.%I(%s)',namespace.nspname,routine.proname,
              replace(pg_catalog.pg_get_function_identity_arguments(routine.oid),', ',',')) AS function_signature
       FROM pg_catalog.pg_event_trigger event_trigger
       JOIN pg_catalog.pg_roles owner ON owner.oid=event_trigger.evtowner
       JOIN pg_catalog.pg_proc routine ON routine.oid=event_trigger.evtfoid
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
      ORDER BY event_trigger.evtname`,
  );
  const publications = await queryCatalogMetadataStage(
    client,
    "catalog-publications",
    `SELECT publication.pubname,owner.rolname AS owner,
            to_jsonb(publication)-'oid'-'pubowner' AS settings
       FROM pg_catalog.pg_publication publication
       JOIN pg_catalog.pg_roles owner ON owner.oid=publication.pubowner
      ORDER BY publication.pubname`,
  );
  const publicationSchemas = await queryCatalogMetadataStage(
    client,
    "catalog-publication-schemas",
    `SELECT publication.pubname,namespace.nspname AS schema_name
       FROM pg_catalog.pg_publication_namespace publication_namespace
       JOIN pg_catalog.pg_publication publication ON publication.oid=publication_namespace.pnpubid
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=publication_namespace.pnnspid
      ORDER BY publication.pubname,namespace.nspname`,
  );
  const publicationTables = await queryCatalogMetadataStage(
    client,
    "catalog-publication-tables",
    `SELECT publication_table.pubname,publication_table.schemaname,publication_table.tablename,
            ARRAY(SELECT column_name::text FROM unnest(publication_table.attnames) column_name ORDER BY column_name::text) AS columns,
            publication_table.rowfilter
       FROM pg_catalog.pg_publication_tables publication_table
      WHERE publication_table.schemaname NOT IN ('pg_catalog','information_schema')
        AND publication_table.schemaname !~ '^pg_toast(?:_|$)'
        AND publication_table.schemaname !~ '^pg_temp_'
      ORDER BY publication_table.pubname,publication_table.schemaname,publication_table.tablename`,
  );
  const subscriptions = await queryCatalogMetadataStage(
    client,
    "catalog-subscriptions",
    `SELECT subscription.subname,owner.rolname AS owner,
            encode(pg_catalog.sha256(pg_catalog.convert_to(subscription.subconninfo,'UTF8')),'hex') AS conninfo_sha256,
            to_jsonb(subscription)-'oid'-'subdbid'-'subowner'-'subconninfo' AS settings
       FROM pg_catalog.pg_subscription subscription
       JOIN pg_catalog.pg_roles owner ON owner.oid=subscription.subowner
      WHERE subscription.subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
      ORDER BY subscription.subname`,
  );
  const rewriteRules = await queryCatalogMetadataStage(
    client,
    "catalog-rewrite-rules",
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

  const commentDigest = digestCatalogMetadataSnapshot({ comments: comments.rows });
  const expectedCommentDigest = digestCatalogMetadataSnapshot({ comments: expectedComments });
  const snapshot = {
    comments: comments.rows,
    sharedComments: sharedComments.rows,
    securityLabels: securityLabels.rows,
    sharedSecurityLabels: sharedSecurityLabels.rows,
    eventTriggers: eventTriggers.rows,
    publications: publications.rows,
    publicationSchemas: publicationSchemas.rows,
    publicationTables: publicationTables.rows,
    subscriptions: subscriptions.rows,
    rewriteRules: rewriteRules.rows,
  };
  const labelCount = securityLabels.rows.length + sharedSecurityLabels.rows.length;
  const mismatchCount = Number(
    comments.rows.length !== expectedComments.length || commentDigest !== expectedCommentDigest,
  ) + sharedComments.rows.length + labelCount + eventTriggers.rows.length
    + publications.rows.length + subscriptions.rows.length + rewriteRules.rows.length;
  return {
    catalogSha256: digestCatalogMetadataSnapshot(snapshot),
    commentCount: comments.rows.length,
    sharedCommentCount: sharedComments.rows.length,
    securityLabelCount: labelCount,
    eventTriggerCount: eventTriggers.rows.length,
    publicationCount: publications.rows.length,
    subscriptionCount: subscriptions.rows.length,
    rewriteRuleCount: rewriteRules.rows.length,
    mismatchCount,
  };
}

async function queryCatalogMetadataStage<Row extends QueryResultRow = QueryResultRow>(
  client: ReadOnlyQueryClient,
  stage: LocalStateFailureStage,
  text: string,
  values?: readonly unknown[],
): Promise<QueryResultLike<Row>> {
  try {
    return await client.query<Row>(text, values);
  } catch (error) {
    throw new LocalStateVerificationStageError(stage, error);
  }
}

function safePostgresSqlState(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  const code = error.code;
  return typeof code === "string" && /^[0-9A-Z]{5}$/u.test(code) ? code : undefined;
}

async function readTenantTableInventoryMismatchCount(client: ReadOnlyQueryClient): Promise<number> {
  const result = await client.query<{ name: string }>(
    `SELECT format('%I.%I',table_record.schemaname,table_record.tablename) AS name
       FROM pg_catalog.pg_tables table_record
      WHERE table_record.schemaname NOT IN ('pg_catalog','information_schema')
        AND table_record.schemaname !~ '^pg_toast'
        AND table_record.schemaname !~ '^pg_temp_'
      ORDER BY table_record.schemaname,table_record.tablename`,
  );
  const expected = [
    "schema_migrations",
    ...TENANT_CONFIGURATION_TABLES,
    ...TENANT_OPERATIONAL_TABLES,
  ].map((name) => `public.${name}`);
  return symmetricDifferenceCount(expected, result.rows.map(({ name }) => name));
}

async function readDemoFixtureCounts(client: ReadOnlyQueryClient): Promise<{
  readonly memberCount: number;
  readonly eligibleMemberCount: number;
}> {
  const result = await client.query<{ members: number; eligible: number }>(
    `SELECT count(*)::int AS members,
            count(*) FILTER (WHERE eligibility_status='eligible' AND available)::int AS eligible
       FROM public.members`,
  );
  const row = requireSingleRow(result, "Demo fixture counts");
  return {
    memberCount: nonNegativeInteger(row.members),
    eligibleMemberCount: nonNegativeInteger(row.eligible),
  };
}

async function readOzamaOperationalState(client: ReadOnlyQueryClient): Promise<{
  readonly operationalTableCount: number;
  readonly operationalRowCount: number;
}> {
  const existing = await client.query<{ name: string }>(
    `SELECT table_record.tablename AS name
       FROM pg_catalog.pg_tables table_record
      WHERE table_record.schemaname='public'
        AND table_record.tablename=ANY($1::text[])
      ORDER BY table_record.tablename`,
    [[...TENANT_OPERATIONAL_TABLES]],
  );
  const allowed = new Set<string>(TENANT_OPERATIONAL_TABLES);
  let operationalRowCount = 0;
  for (const { name } of existing.rows) {
    if (!allowed.has(name)) throw new Error("Unexpected operational table identity");
    const count = await client.query<{ rows: number }>(
      `SELECT count(*)::int AS rows FROM public.${quoteIdentifier(name)}`,
    );
    operationalRowCount += nonNegativeInteger(requireSingleRow(count, "operational row count").rows);
  }
  return { operationalTableCount: existing.rows.length, operationalRowCount };
}

async function readOwnershipSnapshot(
  client: ReadOnlyQueryClient,
  ownerRole: string,
): Promise<OwnershipSnapshot> {
  const roleResult = await client.query<{
    role_exists: boolean;
    database_owned: boolean;
    schema_owned_by_database_owner: boolean;
    can_login: boolean;
    superuser: boolean;
    create_database: boolean;
    create_role: boolean;
    replication: boolean;
    bypass_rls: boolean;
    inherit: boolean;
    connection_limit: number;
    has_password: boolean;
    has_expiration: boolean;
    configuration_count: number;
    membership_count: number;
  }>(
    `SELECT target.oid IS NOT NULL AS role_exists,
            database.datdba=target.oid AS database_owned,
            COALESCE((
              SELECT schema_owner.rolname='pg_database_owner'
                FROM pg_catalog.pg_namespace namespace
                JOIN pg_catalog.pg_roles schema_owner ON schema_owner.oid=namespace.nspowner
               WHERE namespace.nspname='public'
            ),false) AS schema_owned_by_database_owner,
            COALESCE(target.rolcanlogin,true) AS can_login,
            COALESCE(target.rolsuper,true) AS superuser,
            COALESCE(target.rolcreatedb,true) AS create_database,
            COALESCE(target.rolcreaterole,true) AS create_role,
            COALESCE(target.rolreplication,true) AS replication,
            COALESCE(target.rolbypassrls,true) AS bypass_rls,
            COALESCE(target.rolinherit,false) AS inherit,
            COALESCE(target.rolconnlimit,0) AS connection_limit,
            COALESCE(credential.rolpassword IS NOT NULL,true) AS has_password,
            COALESCE(target.rolvaliduntil IS NOT NULL AND target.rolvaliduntil <> 'infinity'::timestamptz,true) AS has_expiration,
            CASE WHEN target.oid IS NULL THEN 1
                 ELSE COALESCE(cardinality(target.rolconfig),0) END::int AS configuration_count,
            (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
              WHERE membership.member=target.oid OR membership.roleid=target.oid) AS membership_count
       FROM pg_catalog.pg_database database
       LEFT JOIN pg_catalog.pg_roles target ON target.rolname=$1
       LEFT JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid
      WHERE database.datname=current_database()`,
    [ownerRole],
  );
  const role = requireSingleRow(roleResult, "tenant owner evidence");
  const relationResult = await client.query<{ mismatches: number }>(
    `SELECT count(*)::int AS mismatches
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
        AND namespace.nspname !~ '^pg_toast'
        AND namespace.nspname !~ '^pg_temp_'
        AND relation.relkind IN ('r','p','S','v','m','f')
        AND relation.relowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)
        AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend dependency
           WHERE dependency.classid='pg_class'::regclass
             AND dependency.objid=relation.oid
             AND dependency.deptype='e'
        )`,
    [ownerRole],
  );
  const routineResult = await client.query<{ mismatches: number }>(
    `SELECT count(*)::int AS mismatches
       FROM pg_catalog.pg_proc routine
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
      WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
        AND namespace.nspname !~ '^pg_toast'
        AND namespace.nspname !~ '^pg_temp_'
        AND routine.proowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)
        AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend dependency
           WHERE dependency.classid='pg_proc'::regclass
             AND dependency.objid=routine.oid
             AND dependency.deptype='e'
        )`,
    [ownerRole],
  );
  const typeResult = await client.query<{ mismatches: number }>(
    `SELECT count(*)::int AS mismatches
       FROM pg_catalog.pg_type type_record
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=type_record.typnamespace
       LEFT JOIN pg_catalog.pg_class type_relation ON type_relation.oid=type_record.typrelid
      WHERE namespace.nspname NOT IN ('pg_catalog','information_schema')
        AND namespace.nspname !~ '^pg_toast'
        AND namespace.nspname !~ '^pg_temp_'
        AND type_record.typisdefined
        AND type_record.typcategory<>'A'
        AND (type_record.typrelid=0 OR type_relation.relkind='c')
        AND type_record.typowner<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1)
        AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend dependency
           WHERE dependency.classid='pg_type'::regclass
             AND dependency.objid=type_record.oid
             AND dependency.deptype='e'
        )`,
    [ownerRole],
  );
  return {
    roleExists: role.role_exists,
    databaseOwned: role.database_owned,
    schemaOwnedByDatabaseOwner: role.schema_owned_by_database_owner,
    canLogin: role.can_login,
    superuser: role.superuser,
    createDatabase: role.create_database,
    createRole: role.create_role,
    replication: role.replication,
    bypassRls: role.bypass_rls,
    inherit: role.inherit,
    connectionLimit: role.connection_limit,
    hasPassword: role.has_password,
    hasExpiration: role.has_expiration,
    configurationCount: nonNegativeInteger(role.configuration_count),
    membershipCount: nonNegativeInteger(role.membership_count),
    relationMismatchCount: nonNegativeInteger(requireSingleRow(relationResult, "relation ownership").mismatches),
    routineMismatchCount: nonNegativeInteger(requireSingleRow(routineResult, "routine ownership").mismatches),
    typeMismatchCount: nonNegativeInteger(requireSingleRow(typeResult, "type ownership").mismatches),
  };
}

async function readRuntimeGrantSnapshot(
  client: ReadOnlyQueryClient,
  runtimeRole: string,
): Promise<RuntimeGrantSnapshot> {
  const roleResult = await client.query<{
    can_login: boolean;
    superuser: boolean;
    create_database: boolean;
    create_role: boolean;
    replication: boolean;
    bypass_rls: boolean;
    inherit: boolean;
    connection_limit: number;
    has_password: boolean;
    has_expiration: boolean;
    configuration_count: number;
    membership_count: number;
  }>(
    `SELECT role.rolcanlogin AS can_login,role.rolsuper AS superuser,
            role.rolcreatedb AS create_database,role.rolcreaterole AS create_role,
            role.rolreplication AS replication,role.rolbypassrls AS bypass_rls,
            role.rolinherit AS inherit,role.rolconnlimit AS connection_limit,
            credential.rolpassword IS NOT NULL AS has_password,
            role.rolvaliduntil IS NOT NULL AND role.rolvaliduntil <> 'infinity'::timestamptz AS has_expiration,
            COALESCE(cardinality(role.rolconfig),0)::int AS configuration_count,
            (SELECT count(*)::int FROM pg_catalog.pg_auth_members membership
              WHERE membership.member=role.oid OR membership.roleid=role.oid) AS membership_count
       FROM pg_catalog.pg_roles role
       JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid
      WHERE role.rolname=$1`,
    [runtimeRole],
  );
  const role = roleResult.rows[0];
  const database = requireSingleRow(await client.query<{
    runtime_connect: boolean;
    runtime_create: boolean;
    runtime_temporary: boolean;
    public_connect: boolean;
    public_create: boolean;
    public_temporary: boolean;
    runtime_grant_options: number;
    foreign_grants: number;
  }>(
    `SELECT COALESCE(bool_or(acl.grantee=target.oid AND acl.privilege_type='CONNECT'),false) AS runtime_connect,
            COALESCE(bool_or(acl.grantee=target.oid AND acl.privilege_type='CREATE'),false) AS runtime_create,
            COALESCE(bool_or(acl.grantee=target.oid AND acl.privilege_type='TEMPORARY'),false) AS runtime_temporary,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='CONNECT'),false) AS public_connect,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='CREATE'),false) AS public_create,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='TEMPORARY'),false) AS public_temporary,
            count(*) FILTER (WHERE acl.grantee=target.oid AND acl.is_grantable)::int AS runtime_grant_options,
            count(*) FILTER (WHERE acl.grantee<>0 AND acl.grantee<>database.datdba
              AND acl.grantee IS DISTINCT FROM target.oid)::int AS foreign_grants
       FROM pg_catalog.pg_database database
       CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl,pg_catalog.acldefault('d',database.datdba))) acl
       LEFT JOIN pg_catalog.pg_roles target ON target.rolname=$1
      WHERE database.datname=current_database()`,
    [runtimeRole],
  ), "runtime database privileges");
  const schema = requireSingleRow(await client.query<{
    runtime_usage: boolean;
    runtime_create: boolean;
    public_usage: boolean;
    public_create: boolean;
    runtime_grant_options: number;
    foreign_grants: number;
  }>(
    `SELECT COALESCE(bool_or(acl.grantee=target.oid AND acl.privilege_type='USAGE'),false) AS runtime_usage,
            COALESCE(bool_or(acl.grantee=target.oid AND acl.privilege_type='CREATE'),false) AS runtime_create,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='USAGE'),false) AS public_usage,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='CREATE'),false) AS public_create,
            count(*) FILTER (WHERE acl.grantee=target.oid AND acl.is_grantable)::int AS runtime_grant_options,
            count(*) FILTER (WHERE acl.grantee<>0 AND acl.grantee<>namespace.nspowner
              AND acl.grantee IS DISTINCT FROM target.oid)::int AS foreign_grants
       FROM pg_catalog.pg_namespace namespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner))) acl
       LEFT JOIN pg_catalog.pg_roles target ON target.rolname=$1
      WHERE namespace.nspname='public'`,
    [runtimeRole],
  ), "runtime schema privileges");
  const tableRows = await client.query<{
    object_name: string;
    privilege_type: string;
    is_grantable: boolean;
    is_public: boolean;
    is_runtime: boolean;
    is_foreign: boolean;
  }>(
    `SELECT relation.relname AS object_name,acl.privilege_type::text,acl.is_grantable,
            acl.grantee=0 AS is_public,
            acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_runtime,
            acl.grantee<>0 AND acl.grantee<>relation.relowner
              AND acl.grantee IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_foreign
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl,pg_catalog.acldefault('r',relation.relowner))) acl
      WHERE namespace.nspname='public' AND relation.relkind IN ('r','p','v','m','f')
      ORDER BY relation.relname,acl.privilege_type`,
    [runtimeRole],
  );
  const columnRows = await client.query<{
    table_name: string;
    column_name: string;
    privilege_type: string;
    is_grantable: boolean;
    is_public: boolean;
    is_runtime: boolean;
    is_foreign: boolean;
  }>(
    `SELECT relation.relname AS table_name,column_record.attname AS column_name,
            acl.privilege_type::text,acl.is_grantable,acl.grantee=0 AS is_public,
            acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_runtime,
            acl.grantee<>0 AND acl.grantee<>relation.relowner
              AND acl.grantee IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_foreign
       FROM pg_catalog.pg_attribute column_record
       JOIN pg_catalog.pg_class relation ON relation.oid=column_record.attrelid
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(column_record.attacl) acl
      WHERE namespace.nspname='public' AND relation.relkind IN ('r','p')
        AND column_record.attnum>0 AND NOT column_record.attisdropped
        AND column_record.attacl IS NOT NULL
      ORDER BY relation.relname,column_record.attname,acl.privilege_type`,
    [runtimeRole],
  );
  const sequenceRows = await client.query<{
    object_name: string;
    privilege_type: string;
    is_grantable: boolean;
    is_public: boolean;
    is_runtime: boolean;
    is_foreign: boolean;
  }>(
    `SELECT relation.relname AS object_name,acl.privilege_type::text,acl.is_grantable,
            acl.grantee=0 AS is_public,
            acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_runtime,
            acl.grantee<>0 AND acl.grantee<>relation.relowner
              AND acl.grantee IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_foreign
       FROM pg_catalog.pg_class relation
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl,pg_catalog.acldefault('s',relation.relowner))) acl
      WHERE namespace.nspname='public' AND relation.relkind='S'
      ORDER BY relation.relname,acl.privilege_type`,
    [runtimeRole],
  );
  const functionRows = await client.query<{
    signature: string;
    privilege_type: string;
    is_grantable: boolean;
    is_public: boolean;
    is_runtime: boolean;
    is_foreign: boolean;
  }>(
    `SELECT format('%I(%s)',routine.proname,replace(pg_catalog.oidvectortypes(routine.proargtypes),', ',',')) AS signature,
            acl.privilege_type::text,acl.is_grantable,acl.grantee=0 AS is_public,
            acl.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_runtime,
            acl.grantee<>0 AND acl.grantee<>routine.proowner
              AND acl.grantee IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1) AS is_foreign
       FROM pg_catalog.pg_proc routine
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
       CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))) acl
      WHERE namespace.nspname='public'
      ORDER BY signature,acl.privilege_type`,
    [runtimeRole],
  );
  const securityDefinerRows = await client.query<{ signature: string; public_execute: boolean }>(
    `SELECT format('%I(%s)',routine.proname,replace(pg_catalog.oidvectortypes(routine.proargtypes),', ',',')) AS signature,
            COALESCE(bool_or(acl.grantee=0 AND acl.privilege_type='EXECUTE'),false) AS public_execute
       FROM pg_catalog.pg_proc routine
       JOIN pg_catalog.pg_namespace namespace ON namespace.oid=routine.pronamespace
       LEFT JOIN LATERAL pg_catalog.aclexplode(COALESCE(routine.proacl,pg_catalog.acldefault('f',routine.proowner))) acl ON true
      WHERE namespace.nspname='public' AND routine.prosecdef
      GROUP BY routine.oid,routine.proname,routine.proargtypes
      ORDER BY signature`,
  );
  return {
    role: {
      exists: role !== undefined,
      canLogin: role?.can_login ?? false,
      superuser: role?.superuser ?? true,
      createDatabase: role?.create_database ?? true,
      createRole: role?.create_role ?? true,
      replication: role?.replication ?? true,
      bypassRls: role?.bypass_rls ?? true,
      inherit: role?.inherit ?? false,
      connectionLimit: role?.connection_limit ?? 0,
      hasPassword: role?.has_password ?? false,
      hasExpiration: role?.has_expiration ?? true,
      configurationCount: nonNegativeInteger(role?.configuration_count ?? 1),
      membershipCount: nonNegativeInteger(role?.membership_count ?? 1),
    },
    database: {
      runtimeConnect: database.runtime_connect,
      runtimeCreate: database.runtime_create,
      runtimeTemporary: database.runtime_temporary,
      publicConnect: database.public_connect,
      publicCreate: database.public_create,
      publicTemporary: database.public_temporary,
    },
    schema: {
      runtimeUsage: schema.runtime_usage,
      runtimeCreate: schema.runtime_create,
      publicUsage: schema.public_usage,
      publicCreate: schema.public_create,
    },
    tablePrivileges: tableRows.rows.filter(({ is_runtime }) => is_runtime)
      .map(({ object_name, privilege_type }) => `${object_name}:${privilege_type}`),
    columnPrivileges: columnRows.rows.filter(({ is_runtime }) => is_runtime).map(
      ({ table_name, column_name, privilege_type }) => `${table_name}.${column_name}:${privilege_type}`,
    ),
    sequencePrivileges: sequenceRows.rows.filter(({ is_runtime }) => is_runtime)
      .map(({ object_name, privilege_type }) => `${object_name}:${privilege_type}`),
    functionPrivileges: functionRows.rows.filter(({ is_runtime }) => is_runtime).map(
      ({ signature, privilege_type }) => `${normalizeSignature(signature)}:${privilege_type}`,
    ),
    grantOptionCount: database.runtime_grant_options
      + schema.runtime_grant_options
      + tableRows.rows.filter(({ is_grantable, is_runtime }) => is_grantable && is_runtime).length
      + columnRows.rows.filter(({ is_grantable, is_runtime }) => is_grantable && is_runtime).length
      + sequenceRows.rows.filter(({ is_grantable, is_runtime }) => is_grantable && is_runtime).length
      + functionRows.rows.filter(({ is_grantable, is_runtime }) => is_grantable && is_runtime).length,
    publicObjectPrivilegeCount: tableRows.rows.filter(({ is_public }) => is_public).length
      + columnRows.rows.filter(({ is_public }) => is_public).length
      + sequenceRows.rows.filter(({ is_public }) => is_public).length
      + functionRows.rows.filter(({ is_public }) => is_public).length,
    foreignGranteePrivilegeCount: database.foreign_grants
      + schema.foreign_grants
      + tableRows.rows.filter(({ is_foreign }) => is_foreign).length
      + columnRows.rows.filter(({ is_foreign }) => is_foreign).length
      + sequenceRows.rows.filter(({ is_foreign }) => is_foreign).length
      + functionRows.rows.filter(({ is_foreign }) => is_foreign).length,
    securityDefinerFunctions: securityDefinerRows.rows.map(({ signature, public_execute }) => ({
      signature,
      publicExecute: public_execute,
    })),
  };
}

function flattenPrivilegeRecord(
  record: Readonly<Record<string, readonly string[]>>,
): readonly string[] {
  return Object.entries(record).flatMap(([object, privileges]) => (
    privileges.map((privilege) => `${object}:${privilege}`)
  ));
}

function flattenColumnPrivilegeRecord(
  record: Readonly<Record<string, Readonly<Record<string, readonly string[]>>>>,
): readonly string[] {
  return Object.entries(record).flatMap(([table, columns]) => (
    Object.entries(columns).flatMap(([column, privileges]) => (
      privileges.map((privilege) => `${table}.${column}:${privilege}`)
    ))
  ));
}

function symmetricDifferenceCount(expected: readonly string[], actual: readonly string[]): number {
  const expectedSet = new Set(expected);
  const actualSet = new Set(actual);
  return [...expectedSet].filter((entry) => !actualSet.has(entry)).length
    + [...actualSet].filter((entry) => !expectedSet.has(entry)).length
    + (expected.length - expectedSet.size)
    + (actual.length - actualSet.size);
}

function migrationLedgerDigest(entries: readonly MigrationPlanEntry[]): string {
  return createHash("sha256")
    .update(entries.map(({ name, checksum }) => `${name}\0${checksum}\n`).join(""))
    .digest("hex");
}

async function loadExpectedMigrationComments(
  directory: string,
  migrations: readonly MigrationPlanEntry[],
): Promise<readonly CatalogCommentFingerprint[]> {
  const comments = new Map<string, CatalogCommentFingerprint>();
  const expression = /COMMENT\s+ON\s+(?:(CONSTRAINT)\s+([a-z][a-z0-9_]*)\s+ON\s+([a-z][a-z0-9_.]*)|(TABLE|VIEW|COLUMN|INDEX)\s+([a-z][a-z0-9_.]*))\s+IS\s+'((?:''|[^'])*)'\s*;/giu;
  const routineExpression = /COMMENT\s+ON\s+(FUNCTION|PROCEDURE)\s+([a-z][a-z0-9_.]*)\s*\(\s*([^()]*)\s*\)\s+IS\s+'((?:''|[^'])*)'\s*;/giu;
  for (const migration of migrations) {
    const sql = await readFile(path.join(directory, migration.name), "utf8");
    for (const match of sql.matchAll(expression)) {
      const constraintKind = match[1];
      const kind = (constraintKind ?? match[4])?.toUpperCase();
      const description = match[6]?.replaceAll("''", "'");
      if (!kind || description === undefined) {
        throw new Error("Migration comment could not be canonicalized");
      }
      let identity: string;
      if (constraintKind) {
        const constraint = match[2];
        const relation = match[3];
        if (!constraint || !relation) throw new Error("Migration constraint comment is invalid");
        identity = `${qualifyCatalogIdentity(relation, false)}.${constraint}`;
      } else {
        const target = match[5];
        if (!target) throw new Error("Migration comment target is invalid");
        identity = qualifyCatalogIdentity(target, kind === "COLUMN");
      }
      const record: CatalogCommentFingerprint = {
        kind,
        identity,
        description_sha256: createHash("sha256").update(description, "utf8").digest("hex"),
      };
      comments.set(`${kind}\0${identity}`, record);
    }
    for (const match of sql.matchAll(routineExpression)) {
      const routineKind = match[1]?.toLowerCase();
      const routineName = match[2];
      const rawArguments = match[3];
      const description = match[4]?.replaceAll("''", "'");
      if (!routineKind || !routineName || rawArguments === undefined || description === undefined) {
        throw new Error("Migration routine comment could not be canonicalized");
      }
      const arguments_ = rawArguments.trim() === ""
        ? ""
        : rawArguments.split(",").map(canonicalizeRoutineArgumentType).join(",");
      const kind = `OTHER:${routineKind}`;
      const identity = `${qualifyCatalogIdentity(routineName, false)}(${arguments_})`;
      const record: CatalogCommentFingerprint = {
        kind,
        identity,
        description_sha256: createHash("sha256").update(description, "utf8").digest("hex"),
      };
      comments.set(`${kind}\0${identity}`, record);
    }
  }
  return [...comments.values()].sort((left, right) => (
    left.kind.localeCompare(right.kind)
    || left.identity.localeCompare(right.identity)
    || left.description_sha256.localeCompare(right.description_sha256)
  ));
}

export async function expectedMigrationCommentFingerprint(
  directory: string,
  migrations: readonly MigrationPlanEntry[],
): Promise<{ readonly count: number; readonly digest: string }> {
  const comments = await loadExpectedMigrationComments(directory, migrations);
  return {
    count: comments.length,
    digest: digestCatalogMetadataSnapshot({ comments }),
  };
}

function canonicalizeRoutineArgumentType(argument: string): string {
  const normalized = argument.trim().toLowerCase();
  if (/^[a-z][a-z0-9_]*(?:\[\])*$/u.test(normalized)) {
    return `pg_catalog.${normalized}`;
  }
  if (/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*(?:\[\])*$/u.test(normalized)) {
    return normalized;
  }
  throw new Error("Migration routine comment has an unsupported argument type identity");
}

function qualifyCatalogIdentity(target: string, column: boolean): string {
  const parts = target.toLowerCase().split(".");
  const expectedUnqualifiedParts = column ? 2 : 1;
  const expectedQualifiedParts = expectedUnqualifiedParts + 1;
  if (parts.length === expectedUnqualifiedParts) return ["public", ...parts].join(".");
  if (parts.length === expectedQualifiedParts) return parts.join(".");
  throw new Error("Migration comment target has an unsupported identity");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Readonly<Record<string, unknown>>;
  return `{${Object.keys(record).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`,
  ).join(",")}}`;
}

function assertMigrationEntries(entries: readonly MigrationPlanEntry[]): void {
  const names = new Set<string>();
  for (const entry of entries) {
    if (!/^\d+_[a-z0-9_]+\.sql$/u.test(entry.name) || !/^[0-9a-f]{64}$/u.test(entry.checksum)) {
      throw new Error("Migration ledger contains an invalid entry");
    }
    if (names.has(entry.name)) throw new Error("Migration ledger contains a duplicate entry");
    names.add(entry.name);
  }
}

function assertReadOnlySql(sql: string): void {
  const normalized = sql.trim();
  if (!/^SELECT\b/iu.test(normalized)) {
    throw new Error("Local state verifier attempted a non-read-only statement");
  }
  // A single SELECT is the only statement shape accepted. Writable CTEs start
  // with WITH and multi-statement payloads require a semicolon, so both are
  // rejected here; PostgreSQL's READ ONLY transaction is the final authority
  // that also blocks writes attempted from a called function.
  if (normalized.includes(";")) throw new Error("Local state verifier attempted multiple statements");
}

function databaseNameFor(tenantId: string): string {
  return `nom_t_${tenantId.replaceAll("-", "")}`;
}

function runtimeRoleFor(tenantId: string): string {
  return `nom_r_${tenantId.replaceAll("-", "")}`;
}

function ownerRoleFor(tenantId: string): string {
  return `nom_o_${tenantId.replaceAll("-", "")}`;
}

function normalizeSignature(signature: string): string {
  return signature.replace(/\s+/gu, "").toLowerCase();
}

function safeLifecycle(value: string | undefined): string {
  return value === "active" || value === "suspended" || value === "provisioning" || value === "failed"
    ? value
    : value === undefined ? "missing" : "invalid";
}

function safeSetupState(value: string): string {
  return value === "not_started" || value === "in_progress" || value === "ready" ? value : "invalid";
}

function quoteIdentifier(value: string): string {
  if (!TENANT_OPERATIONAL_TABLES.includes(value as (typeof TENANT_OPERATIONAL_TABLES)[number])) {
    throw new Error("Unsafe operational table identifier");
  }
  return `"${value.replaceAll('"', '""')}"`;
}

function requireSingleRow<Row extends QueryResultRow>(
  result: QueryResultLike<Row>,
  label: string,
): Row {
  if (result.rows.length !== 1 || result.rowCount !== 1) {
    throw new Error(`Local state ${label} is unavailable`);
  }
  return result.rows[0]!;
}

function nonNegativeInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Local state count is invalid");
  return value;
}

function assertSafeOutputValue(value: unknown, pathSegments: readonly string[]): void {
  if (typeof value === "string") {
    if (FORBIDDEN_OUTPUT_VALUE.test(value) && !isExpectedMigrationHead(value, pathSegments)) {
      throw new Error("Local state report contains a forbidden value");
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertSafeOutputValue(entry, [...pathSegments, String(index)]));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_OUTPUT_KEY.test(key)) throw new Error("Local state report contains a forbidden field");
    assertSafeOutputValue(entry, [...pathSegments, key]);
  }
}

function isExpectedMigrationHead(value: string, pathSegments: readonly string[]): boolean {
  const field = pathSegments.at(-1);
  if (field !== "head" && field !== "expectedHead") return false;
  if (pathSegments.length === 3 && pathSegments[0] === "control" && pathSegments[1] === "migrations") {
    return value === EXPECTED_CONTROL_HEAD;
  }
  return pathSegments.length === 4
    && pathSegments[0] === "tenants"
    && (pathSegments[1] === "demo" || pathSegments[1] === "ozama")
    && pathSegments[2] === "migrations"
    && value === EXPECTED_TENANT_HEAD;
}
