import { createHash } from "node:crypto";

export const REAL_BROWSER_STACK_MARKER = "nombramientos-real-browser-stack-v1" as const;
export const REAL_BROWSER_STACK_FLAG = "--ephemeral-only" as const;
export const REAL_BROWSER_STACK_CHECK_FLAG = "--check" as const;
export const WORKSPACE_POSTGRES_PORT = 55_432;
export const RESERVED_APPLICATION_PORTS = [3_000, 4_000] as const;

export const PROTECTED_DATABASES = {
  control: "nombramientos_control",
  demo: "nom_t_d0000000000040008000000000000001",
  ozama: "nom_t_0a2a0000000040008000000000000001",
} as const;

export const PROTECTED_TENANTS = [{
  id: "d0000000-0000-4000-8000-000000000001",
  slug: "iglesia-demostracion",
  kind: "demo",
  status: "active",
  databaseName: PROTECTED_DATABASES.demo,
}, {
  id: "0a2a0000-0000-4000-8000-000000000001",
  slug: "iglesia-adventista-ozama",
  kind: "real",
  status: "provisioning",
  databaseName: PROTECTED_DATABASES.ozama,
}] as const;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/u;

export interface EphemeralNames {
  readonly runId: string;
  readonly controlDatabase: string;
  readonly tenantId: string;
  readonly tenantDatabase: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly tenantSlug: string;
  readonly secretReference: string;
}

export interface RunMarkerRow {
  readonly marker: string;
  readonly run_id: string;
  readonly control_database: string;
  readonly tenant_id: string;
  readonly tenant_database: string;
  readonly owner_role: string;
  readonly runtime_role: string;
  readonly tenant_slug: string;
}

export interface ProtectedTenantRoute {
  readonly id: string;
  readonly slug: string;
  readonly kind: string;
  readonly status: string;
  readonly database_name: string;
}

export interface RegisteredTenantResourceRoute {
  readonly id: string;
  readonly database_name: string;
  readonly runtime_role: string;
}

export interface TenantResourceInventory {
  readonly databases: readonly string[];
  readonly roles: readonly string[];
}

export interface UnroutedTenantResourceObservation {
  readonly databases: number;
  readonly roles: number;
}

export interface GlobalEphemeralResourceObservation {
  readonly matchedTenantDatabaseCount: number;
  readonly matchedTenantRoleCount: number;
  readonly ephemeralControlDatabaseCount: number;
  readonly unroutedTenantDatabaseCount: number;
  readonly unroutedTenantRoleCount: number;
  readonly orphanDatabaseCount: number;
  readonly orphanRoleCount: number;
  readonly databasesAbsent: boolean;
  readonly rolesAbsent: boolean;
}

export interface ScenarioIntegrity {
  readonly import_jobs: number;
  readonly completed_import_jobs: number;
  readonly member_rows: number;
  readonly updated_member_version: number;
  readonly created_homonym_rows: number;
  readonly skipped_member_rows: number;
  readonly import_idempotency_records: number;
  readonly vote_submissions: number;
  readonly vote_receipts: number;
  readonly distinct_vote_electors: number;
  readonly vote_idempotency_records: number;
  readonly custody_sets: number;
  readonly custodian_snapshots: number;
  readonly manifests: number;
  readonly manifest_entries: number;
  readonly attestations: number;
  readonly published_manifests: number;
  readonly round_version: number;
  readonly round_phase: string;
  readonly aggregate: unknown;
}

export interface CleanupObservation {
  readonly databases: number;
  readonly roles: number;
  readonly protectedBefore: Readonly<Record<string, string>>;
  readonly protectedAfter: Readonly<Record<string, string>>;
}

export interface ReservedApplicationPortObservation {
  readonly port: (typeof RESERVED_APPLICATION_PORTS)[number];
  readonly acceptingConnections: boolean;
}

export function requireEphemeralInvocation(argv: readonly string[]): void {
  if (argv.length !== 1 || argv[0] !== REAL_BROWSER_STACK_FLAG) {
    throw new Error(`Real browser-stack E2E requires the exact ${REAL_BROWSER_STACK_FLAG} flag`);
  }
}

export function requireReadOnlyCheckInvocation(argv: readonly string[]): void {
  if (argv.length !== 1 || argv[0] !== REAL_BROWSER_STACK_CHECK_FLAG) {
    throw new Error(`Real browser-stack preflight requires the exact ${REAL_BROWSER_STACK_CHECK_FLAG} flag`);
  }
}

export function deriveEphemeralNames(runId: string, tenantId: string): EphemeralNames {
  assertUuidV4(runId, "run id");
  assertUuidV4(tenantId, "tenant id");
  const runSuffix = runId.replaceAll("-", "");
  const tenantSuffix = tenantId.replaceAll("-", "");
  const names: EphemeralNames = {
    runId,
    controlDatabase: `nom_e2e_c_${runSuffix}`,
    tenantId,
    tenantDatabase: `nom_t_${tenantSuffix}`,
    ownerRole: `nom_o_${tenantSuffix}`,
    runtimeRole: `nom_r_${tenantSuffix}`,
    tenantSlug: `e2e-real-stack-${tenantSuffix.slice(0, 24)}`,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
  };
  assertEphemeralNames(names);
  return names;
}

export function assertEphemeralNames(names: EphemeralNames): void {
  assertUuidV4(names.runId, "run id");
  assertUuidV4(names.tenantId, "tenant id");
  const expected = deriveExpectedNames(names.runId, names.tenantId);
  for (const key of Object.keys(expected) as (keyof EphemeralNames)[]) {
    if (names[key] !== expected[key]) throw new Error(`Ephemeral ${key} does not match its UUID-derived value`);
  }
  const forbidden = new Set<string>([
    ...Object.values(PROTECTED_DATABASES),
    "postgres",
    "template0",
    "template1",
    "ozama",
    "nombramientos_demo",
  ]);
  for (const value of [names.controlDatabase, names.tenantDatabase, names.ownerRole, names.runtimeRole]) {
    if (forbidden.has(value)) throw new Error("Ephemeral cleanup target overlaps a protected name");
  }
  if (!/^nom_e2e_c_[0-9a-f]{32}$/u.test(names.controlDatabase)) {
    throw new Error("Ephemeral control database name is invalid");
  }
  if (!/^nom_[tor]_[0-9a-f]{32}$/u.test(names.tenantDatabase)
    || !/^nom_o_[0-9a-f]{32}$/u.test(names.ownerRole)
    || !/^nom_r_[0-9a-f]{32}$/u.test(names.runtimeRole)) {
    throw new Error("Ephemeral tenant database or role name is invalid");
  }
}

export function assertWorkspaceAdminUrl(value: string): URL {
  const parsed = new URL(value);
  const schemeEnd = value.indexOf("://");
  const remainder = schemeEnd < 0 ? "" : value.slice(schemeEnd + 3);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  const userInfoEnd = authority.lastIndexOf("@");
  const userInfo = userInfoEnd < 0 ? "" : authority.slice(0, userInfoEnd);
  const passwordStart = userInfo.indexOf(":");
  const rawUsername = passwordStart < 0 ? userInfo : userInfo.slice(0, passwordStart);
  const rawPassword = passwordStart < 0 ? "" : userInfo.slice(passwordStart + 1);
  const hostPort = userInfoEnd < 0 ? authority : authority.slice(userInfoEnd + 1);
  if (!new Set(["postgres:", "postgresql:"]).has(parsed.protocol)) {
    throw new Error("Real browser-stack E2E requires PostgreSQL");
  }
  if (value !== value.trim()
    || hostPort !== `127.0.0.1:${WORKSPACE_POSTGRES_PORT}`
    || parsed.hostname !== "127.0.0.1") {
    throw new Error("Real browser-stack E2E requires exact IPv4 loopback PostgreSQL");
  }
  if (parsed.port !== String(WORKSPACE_POSTGRES_PORT)) {
    throw new Error(`Real browser-stack E2E requires workspace PostgreSQL port ${WORKSPACE_POSTGRES_PORT}`);
  }
  if (parsed.pathname !== "/postgres") {
    throw new Error("Real browser-stack E2E administrator URL must target postgres");
  }
  if (parsed.search || parsed.hash) {
    throw new Error("Real browser-stack E2E administrator URL forbids query options and fragments");
  }
  if (rawUsername !== "nom_admin"
    || parsed.username !== "nom_admin"
    || rawPassword.length < 1
    || parsed.password.length < 1
    || userInfo.slice(passwordStart + 1).includes("@")) {
    throw new Error("Real browser-stack E2E requires the local nom_admin credential");
  }
  return parsed;
}

export function assertIsolatedHttpOrigin(value: string, label: string): URL {
  const parsed = new URL(value);
  const port = Number(parsed.port);
  if (parsed.protocol !== "http:"
    // WebAuthn's local-development secure-context exception is defined for
    // localhost. An IPv4 literal is deliberately not accepted as an RP
    // origin, even though the listener itself remains bound to 127.0.0.1.
    || parsed.hostname !== "localhost"
    || parsed.host !== `localhost:${parsed.port}`
    || parsed.origin !== value
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
    || parsed.username
    || parsed.password
    || !Number.isInteger(port)
    || port < 1
    || port > 65_535
    || port === WORKSPACE_POSTGRES_PORT
    || RESERVED_APPLICATION_PORTS.includes(port as (typeof RESERVED_APPLICATION_PORTS)[number])) {
    throw new Error(`${label} must use an exact isolated localhost HTTP origin`);
  }
  return parsed;
}

export function assertReservedApplicationPortsFree(
  observations: readonly ReservedApplicationPortObservation[],
): void {
  if (observations.length !== RESERVED_APPLICATION_PORTS.length) {
    throw new Error("RESERVED_APPLICATION_PORT_INVENTORY_INCOMPLETE");
  }
  for (const [index, expectedPort] of RESERVED_APPLICATION_PORTS.entries()) {
    const observation = observations[index];
    if (!observation
      || observation.port !== expectedPort
      || typeof observation.acceptingConnections !== "boolean") {
      throw new Error("RESERVED_APPLICATION_PORT_INVENTORY_INVALID");
    }
    if (observation.acceptingConnections) {
      throw new Error("RESERVED_APPLICATION_PORT_IN_USE");
    }
  }
}

export function assertRunMarker(
  row: RunMarkerRow | undefined,
  names: EphemeralNames,
  state: { readonly controlCreatedByRun?: boolean; readonly namesVerifiedUnused?: boolean },
): void {
  assertEphemeralNames(names);
  if (state.controlCreatedByRun !== true || state.namesVerifiedUnused !== true) {
    throw new Error("Ephemeral cleanup lacks creation and unused-name authorization");
  }
  if (!row) throw new Error("Ephemeral cleanup marker is absent");
  const expected: RunMarkerRow = {
    marker: REAL_BROWSER_STACK_MARKER,
    run_id: names.runId,
    control_database: names.controlDatabase,
    tenant_id: names.tenantId,
    tenant_database: names.tenantDatabase,
    owner_role: names.ownerRole,
    runtime_role: names.runtimeRole,
    tenant_slug: names.tenantSlug,
  };
  for (const key of Object.keys(expected) as (keyof RunMarkerRow)[]) {
    if (row[key] !== expected[key]) throw new Error(`Ephemeral cleanup marker mismatch: ${key}`);
  }
}

export function assertProtectedTenantRoutes(rows: readonly ProtectedTenantRoute[]): void {
  if (rows.length !== PROTECTED_TENANTS.length) {
    throw new Error("Protected Demo/Ozama control routes are incomplete");
  }
  for (const expected of PROTECTED_TENANTS) {
    const row = rows.find(({ id }) => id === expected.id);
    if (!row
      || row.slug !== expected.slug
      || row.kind !== expected.kind
      || row.status !== expected.status
      || row.database_name !== expected.databaseName) {
      throw new Error(`Protected tenant route mismatch: ${expected.slug}`);
    }
  }
}

export function assertNoUnroutedTenantResources(
  routes: readonly RegisteredTenantResourceRoute[],
  inventory: TenantResourceInventory,
): void {
  const observation = observeUnroutedTenantResources(routes, inventory);
  if (observation.databases !== 0 || observation.roles !== 0) {
    throw new Error("STALE_OR_UNROUTED_TENANT_RESOURCE_PRESENT");
  }
}

export function observeUnroutedTenantResources(
  routes: readonly RegisteredTenantResourceRoute[],
  inventory: TenantResourceInventory,
): UnroutedTenantResourceObservation {
  const registeredDatabases = new Set<string>();
  const registeredRoles = new Set<string>();
  for (const route of routes) {
    if (!UUID_V4.test(route.id)) throw new Error("REGISTERED_TENANT_RESOURCE_ROUTE_INVALID");
    const suffix = route.id.replaceAll("-", "");
    const database = `nom_t_${suffix}`;
    const ownerRole = `nom_o_${suffix}`;
    const runtimeRole = `nom_r_${suffix}`;
    if (route.database_name !== database || route.runtime_role !== runtimeRole) {
      throw new Error("REGISTERED_TENANT_RESOURCE_ROUTE_INVALID");
    }
    registeredDatabases.add(database);
    registeredRoles.add(ownerRole);
    registeredRoles.add(runtimeRole);
  }
  return {
    databases: inventory.databases.filter((database) => !registeredDatabases.has(database)).length,
    roles: inventory.roles.filter((role) => !registeredRoles.has(role)).length,
  };
}

export function createGlobalEphemeralResourceObservation(
  matchedTenantDatabaseCount: number,
  matchedTenantRoleCount: number,
  ephemeralControlDatabaseCount: number,
  unrouted: UnroutedTenantResourceObservation,
): GlobalEphemeralResourceObservation {
  for (const value of [
    matchedTenantDatabaseCount,
    matchedTenantRoleCount,
    ephemeralControlDatabaseCount,
    unrouted.databases,
    unrouted.roles,
  ]) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("GLOBAL_EPHEMERAL_RESOURCE_INVENTORY_INVALID");
    }
  }
  const orphanDatabaseCount = ephemeralControlDatabaseCount + unrouted.databases;
  return {
    matchedTenantDatabaseCount,
    matchedTenantRoleCount,
    ephemeralControlDatabaseCount,
    unroutedTenantDatabaseCount: unrouted.databases,
    unroutedTenantRoleCount: unrouted.roles,
    orphanDatabaseCount,
    orphanRoleCount: unrouted.roles,
    databasesAbsent: orphanDatabaseCount === 0,
    rolesAbsent: unrouted.roles === 0,
  };
}

export function assertGlobalEphemeralResourcesAbsent(
  observation: GlobalEphemeralResourceObservation,
): void {
  const expected = createGlobalEphemeralResourceObservation(
    observation.matchedTenantDatabaseCount,
    observation.matchedTenantRoleCount,
    observation.ephemeralControlDatabaseCount,
    {
      databases: observation.unroutedTenantDatabaseCount,
      roles: observation.unroutedTenantRoleCount,
    },
  );
  for (const key of Object.keys(expected) as (keyof GlobalEphemeralResourceObservation)[]) {
    if (observation[key] !== expected[key]) {
      throw new Error("GLOBAL_EPHEMERAL_RESOURCE_EVIDENCE_INCONSISTENT");
    }
  }
  if (observation.orphanDatabaseCount !== 0
    || observation.orphanRoleCount !== 0
    || !observation.databasesAbsent
    || !observation.rolesAbsent) {
    throw new Error("GLOBAL_EPHEMERAL_RESOURCE_PRESENT");
  }
}

export function digestProtectedDatabaseSnapshot(snapshot: Readonly<Record<string, unknown>>): `sha256:${string}` {
  const canonical = canonicalFingerprintJson(snapshot);
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

export function assertScenarioIntegrity(
  row: ScenarioIntegrity,
  expectedCandidateIds?: readonly [string, string],
): void {
  const exact: Readonly<Record<keyof Omit<ScenarioIntegrity, "round_phase" | "aggregate">, number>> = {
    import_jobs: 1,
    completed_import_jobs: 1,
    member_rows: 3,
    updated_member_version: 2,
    created_homonym_rows: 1,
    skipped_member_rows: 0,
    import_idempotency_records: 2,
    vote_submissions: 2,
    vote_receipts: 2,
    distinct_vote_electors: 2,
    vote_idempotency_records: 2,
    custody_sets: 1,
    custodian_snapshots: 2,
    manifests: 1,
    manifest_entries: 2,
    attestations: 2,
    published_manifests: 1,
    round_version: 4,
  };
  for (const [key, expected] of Object.entries(exact) as Array<[keyof typeof exact, number]>) {
    if (row[key] !== expected) {
      throw scenarioIntegrityError("SCN_COUNT", `Real browser-stack integrity mismatch: ${key}`);
    }
  }
  if (row.round_phase !== "RESULTADO_INTERNO") {
    throw scenarioIntegrityError("SCN_PHASE", "Real browser-stack round did not reach the internal-result phase");
  }
  assertPublishedAggregate(row.aggregate, expectedCandidateIds);
}

export function assertCleanupObservation(observation: CleanupObservation): void {
  if (observation.databases !== 0 || observation.roles !== 0) {
    throw new Error("Ephemeral database or role cleanup is incomplete");
  }
  const protectedNames = Object.keys(PROTECTED_DATABASES).sort();
  if (JSON.stringify(Object.keys(observation.protectedBefore).sort()) !== JSON.stringify(protectedNames)
    || JSON.stringify(Object.keys(observation.protectedAfter).sort()) !== JSON.stringify(protectedNames)) {
    throw new Error("Protected fingerprint set is incomplete");
  }
  for (const name of protectedNames) {
    const before = observation.protectedBefore[name];
    const after = observation.protectedAfter[name];
    if (!before || !SHA256.test(before) || after !== before) {
      throw new Error(`Protected database changed during isolated E2E: ${name}`);
    }
  }
}

function deriveExpectedNames(runId: string, tenantId: string): EphemeralNames {
  const runSuffix = runId.replaceAll("-", "");
  const tenantSuffix = tenantId.replaceAll("-", "");
  return {
    runId,
    controlDatabase: `nom_e2e_c_${runSuffix}`,
    tenantId,
    tenantDatabase: `nom_t_${tenantSuffix}`,
    ownerRole: `nom_o_${tenantSuffix}`,
    runtimeRole: `nom_r_${tenantSuffix}`,
    tenantSlug: `e2e-real-stack-${tenantSuffix.slice(0, 24)}`,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
  };
}

function assertUuidV4(value: string, label: string): void {
  if (!UUID_V4.test(value)) throw new Error(`Ephemeral ${label} is not a canonical UUIDv4`);
}

function canonicalFingerprintJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("PROTECTED_FINGERPRINT_VALUE_INVALID");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalFingerprintJson).join(",")}]`;
  if (typeof value !== "object") throw new Error("PROTECTED_FINGERPRINT_VALUE_INVALID");
  const record = value as Readonly<Record<string, unknown>>;
  return `{${Object.keys(record).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalFingerprintJson(record[key])}`
  )).join(",")}}`;
}

function assertPublishedAggregate(value: unknown, expectedCandidateIds?: readonly [string, string]): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw scenarioIntegrityError("SCN_AGGR", "Published aggregate is absent");
  }
  const aggregate = value as Record<string, unknown>;
  const candidates = aggregate["candidates"];
  const rule = aggregate["rule"];
  const decision = aggregate["decision"];
  if (aggregate["schemaVersion"] !== 1
    || aggregate["receivedBallots"] !== 2
    || aggregate["nonAbstainingBallots"] !== 1
    || aggregate["abstentions"] !== 1
    || aggregate["maxSelections"] !== 1
    || !Array.isArray(candidates)
    || candidates.length !== 2
    || !rule
    || typeof rule !== "object"
    || Array.isArray(rule)
    || JSON.stringify(rule) !== JSON.stringify({ kind: "PLURALITY" })
    || !decision
    || typeof decision !== "object"
    || Array.isArray(decision)
    || (decision as Record<string, unknown>)["status"] !== "SELECTED"
    || (decision as Record<string, unknown>)["reason"] !== "TOP_K"
    || (decision as Record<string, unknown>)["unfilledSeats"] !== 0
    || JSON.stringify((decision as Record<string, unknown>)["tiebreakCandidateIds"]) !== "[]") {
    throw scenarioIntegrityError("SCN_AGGR", "Published aggregate semantics are invalid");
  }
  const normalizedCandidates = candidates.map((candidate) => candidate as Record<string, unknown>);
  if (normalizedCandidates.some((candidate) => !candidate
    || typeof candidate !== "object"
    || Array.isArray(candidate)
    || typeof candidate["candidateId"] !== "string"
    || !Number.isInteger(candidate["votes"])
    || (candidate["votes"] as number) < 0)
    || normalizedCandidates.reduce((total, candidate) => total + (candidate["votes"] as number), 0) !== 1) {
    throw scenarioIntegrityError("SCN_CANDS", "Published aggregate candidate counts are invalid");
  }
  if (expectedCandidateIds) {
    const candidateIds = normalizedCandidates.map((candidate) => candidate["candidateId"]);
    const canonicalCandidateIds = [...expectedCandidateIds].sort(compareIdentifiers);
    const votesByCandidateId = new Map(normalizedCandidates.map((candidate) => [
      candidate["candidateId"] as string,
      candidate["votes"] as number,
    ]));
    const selected = (decision as Record<string, unknown>)["selectedCandidateIds"];
    if (JSON.stringify(candidateIds) !== JSON.stringify(canonicalCandidateIds)
      || votesByCandidateId.get(expectedCandidateIds[0]) !== 1
      || votesByCandidateId.get(expectedCandidateIds[1]) !== 0
      || JSON.stringify(selected) !== JSON.stringify([expectedCandidateIds[0]])) {
      throw scenarioIntegrityError("SCN_CANDS", "Published aggregate selected candidate is invalid");
    }
  }
}

function scenarioIntegrityError(code: "SCN_COUNT" | "SCN_PHASE" | "SCN_AGGR" | "SCN_CANDS", message: string): Error {
  return Object.assign(new Error(message), { code });
}

function compareIdentifiers(left: string, right: string): number {
  return left < right ? -1 : Number(left > right);
}
