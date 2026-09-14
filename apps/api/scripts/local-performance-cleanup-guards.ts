const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const TENANT_DATABASE = /^nom_t_[0-9a-f]{32}$/u;
const TENANT_OWNER_ROLE = /^nom_o_[0-9a-f]{32}$/u;
const TENANT_RUNTIME_ROLE = /^nom_r_[0-9a-f]{32}$/u;
const PROVISIONING_STATES = new Set([
  "requested",
  "roles_created",
  "database_created",
  "migrated",
  "seeded",
  "pending_activation",
  "active",
  "failed",
]);

export interface PerformanceCleanupIntent {
  readonly tenantId: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly provisioningKey: string;
  readonly tenantSlug: string;
  readonly displayName: string;
  readonly secretReference: string;
  readonly requestHash: string;
  readonly namesVerifiedUnused: boolean;
  readonly provisioningAttempted: boolean;
}

export interface PerformanceCleanupRoute {
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
}

export interface PerformanceCleanupJob {
  readonly idempotency_key: string;
  readonly tenant_id: string;
  readonly requested_slug: string;
  readonly request_hash: string;
  readonly state: string;
  readonly attempt_count: number;
}

export interface PerformanceCleanupEvidence {
  readonly routes: readonly PerformanceCleanupRoute[];
  readonly jobs: readonly PerformanceCleanupJob[];
  readonly databases: readonly string[];
  readonly roles: readonly string[];
}

export interface PerformanceCleanupPlan {
  readonly tenantIds: readonly string[];
  readonly provisioningKeys: readonly string[];
  readonly databases: readonly string[];
  readonly roles: readonly string[];
}

export interface ScaleControlCleanupIntent {
  readonly runId: string;
  readonly databaseName: string;
  readonly runtimeRole: string;
  readonly namesVerifiedUnused: boolean;
  readonly databaseCreationAttempted: boolean;
  readonly databaseCreatedByRun: boolean;
  readonly roleCreationAttempted: boolean;
  readonly roleCreatedByRun: boolean;
}

export interface ScaleControlCleanupDatabase {
  readonly name: string;
  readonly owner: string;
  readonly encoding: string;
  readonly is_template: boolean;
  readonly allows_connections: boolean;
  readonly connection_limit: number;
}

export interface ScaleControlCleanupMarker {
  readonly run_id: string;
  readonly control_database: string;
  readonly control_runtime_role: string;
}

export interface ScaleControlCleanupRole {
  readonly name: string;
  readonly login: boolean;
  readonly superuser: boolean;
  readonly create_database: boolean;
  readonly create_role: boolean;
  readonly inherit: boolean;
  readonly replication: boolean;
  readonly bypass_rls: boolean;
  readonly connection_limit: number;
  readonly valid_until_epoch: string;
  readonly configuration: string;
  readonly password_present: boolean;
  readonly membership_count: number;
  readonly marker: string | null;
}

export interface ScaleControlCleanupEvidence {
  readonly database: ScaleControlCleanupDatabase | null;
  readonly markerTablePresent: boolean;
  readonly marker: ScaleControlCleanupMarker | null;
  readonly role: ScaleControlCleanupRole | null;
}

export interface ScaleControlCleanupPlan {
  readonly databases: readonly string[];
  readonly roles: readonly string[];
}

/**
 * Authorizes only resources that were absent at the exact preflight and whose
 * provision attempt is recorded in memory. A provisioning job is the durable
 * marker for any database/role created before the final tenant route exists.
 */
export function planPerformanceCleanup(
  intents: readonly PerformanceCleanupIntent[],
  evidence: PerformanceCleanupEvidence,
  maximumIntents: number,
): PerformanceCleanupPlan {
  if (!Number.isSafeInteger(maximumIntents) || maximumIntents < 1 || intents.length > maximumIntents) {
    throw new Error("Performance cleanup intent count is invalid");
  }
  assertUnique(intents.map(({ tenantId }) => tenantId), "tenant ids");
  assertUnique(intents.map(({ databaseName }) => databaseName), "database names");
  assertUnique(intents.flatMap(({ ownerRole, runtimeRole }) => [ownerRole, runtimeRole]), "role names");
  assertUnique(intents.map(({ provisioningKey }) => provisioningKey), "provisioning keys");
  for (const intent of intents) assertCleanupIntent(intent);

  assertUnique(evidence.databases, "observed database names");
  assertUnique(evidence.roles, "observed role names");
  const expectedDatabases = new Set(intents.map(({ databaseName }) => databaseName));
  const expectedRoles = new Set(intents.flatMap(({ ownerRole, runtimeRole }) => [ownerRole, runtimeRole]));
  if (evidence.databases.some((name) => !expectedDatabases.has(name))) {
    throw new Error("Performance cleanup observed an unauthorized database");
  }
  if (evidence.roles.some((name) => !expectedRoles.has(name))) {
    throw new Error("Performance cleanup observed an unauthorized role");
  }

  const routeByTenant = new Map<string, PerformanceCleanupRoute>();
  for (const route of evidence.routes) {
    const matches = intents.filter((intent) => routeMatchesAnyIdentity(route, intent));
    if (matches.length !== 1) throw new Error("Performance cleanup tenant route ownership is ambiguous");
    const intent = matches[0]!;
    if (routeByTenant.has(intent.tenantId)) throw new Error("Performance cleanup tenant route is duplicated");
    assertExactRoute(route, intent);
    routeByTenant.set(intent.tenantId, route);
  }

  const jobByTenant = new Map<string, PerformanceCleanupJob>();
  for (const job of evidence.jobs) {
    const matches = intents.filter((intent) => (
      job.tenant_id === intent.tenantId || job.idempotency_key === intent.provisioningKey
    ));
    if (matches.length !== 1) throw new Error("Performance cleanup provisioning marker ownership is ambiguous");
    const intent = matches[0]!;
    if (jobByTenant.has(intent.tenantId)) throw new Error("Performance cleanup provisioning marker is duplicated");
    assertExactJob(job, intent);
    jobByTenant.set(intent.tenantId, job);
  }

  const observedDatabases = new Set(evidence.databases);
  const observedRoles = new Set(evidence.roles);
  for (const intent of intents) {
    const hasRoute = routeByTenant.has(intent.tenantId);
    const hasDatabaseOrRole = observedDatabases.has(intent.databaseName)
      || observedRoles.has(intent.ownerRole)
      || observedRoles.has(intent.runtimeRole);
    if ((hasRoute || hasDatabaseOrRole) && !jobByTenant.has(intent.tenantId)) {
      throw new Error("Performance cleanup resource lacks its exact provisioning marker");
    }
  }

  return {
    tenantIds: intents.map(({ tenantId }) => tenantId),
    provisioningKeys: intents.map(({ provisioningKey }) => provisioningKey),
    databases: [...evidence.databases].sort(),
    roles: [...evidence.roles].sort(),
  };
}

/**
 * Plans cleanup for the isolated scale control resources. The in-memory
 * created-by-run ledger covers the short interval before a durable marker can
 * exist; once either marker exists, every available ownership field must match.
 */
export function planScaleControlCleanup(
  intent: ScaleControlCleanupIntent,
  evidence: ScaleControlCleanupEvidence,
): ScaleControlCleanupPlan {
  if (!UUID_V4.test(intent.runId)) throw new Error("Scale control cleanup run UUID is invalid");
  const suffix = intent.runId.replaceAll("-", "");
  if (
    intent.databaseName !== `nom_c_${suffix}`
    || intent.runtimeRole !== `nom_cr_${suffix}`
    || intent.namesVerifiedUnused !== true
    || (intent.databaseCreatedByRun && !intent.databaseCreationAttempted)
    || (intent.roleCreatedByRun && !intent.roleCreationAttempted)
    || (intent.roleCreationAttempted && !intent.databaseCreatedByRun)
  ) throw new Error("Scale control cleanup intent does not match its exact creation ledger");

  if (evidence.database && !intent.databaseCreatedByRun) {
    throw new Error("Scale control database exists without created-by-run authorization");
  }
  if (evidence.database) {
    if (
      evidence.database.name !== intent.databaseName
      || evidence.database.owner !== "nom_admin"
      || evidence.database.encoding !== "UTF8"
      || evidence.database.is_template
      || !evidence.database.allows_connections
      || evidence.database.connection_limit !== -1
    ) throw new Error("Scale control database metadata is not owned by this run");
  }
  if (evidence.markerTablePresent && !evidence.marker) {
    throw new Error("Scale control marker table is present without its exact marker row");
  }
  if (evidence.marker) {
    if (!evidence.database || !evidence.markerTablePresent) {
      throw new Error("Scale control marker exists without its exact database");
    }
    if (
      evidence.marker.run_id !== intent.runId
      || evidence.marker.control_database !== intent.databaseName
      || evidence.marker.control_runtime_role !== intent.runtimeRole
    ) throw new Error("Scale control database marker is not owned by this run");
  }

  if (evidence.role && !intent.roleCreatedByRun) {
    throw new Error("Scale control role exists without created-by-run authorization");
  }
  if (evidence.role) {
    const expectedMarker = `nombramientos-ac37-scale-control-runtime:${intent.runId}`;
    if (
      evidence.role.name !== intent.runtimeRole
      || !evidence.role.login
      || evidence.role.superuser
      || evidence.role.create_database
      || evidence.role.create_role
      || evidence.role.inherit
      || evidence.role.replication
      || evidence.role.bypass_rls
      || evidence.role.connection_limit !== 30
      || evidence.role.valid_until_epoch !== ""
      || evidence.role.configuration !== "{}"
      || !evidence.role.password_present
      || evidence.role.membership_count !== 0
      || (evidence.role.marker !== null && evidence.role.marker !== expectedMarker)
    ) throw new Error("Scale control role metadata is not owned by this run");
  }

  return {
    databases: evidence.database ? [intent.databaseName] : [],
    roles: evidence.role ? [intent.runtimeRole] : [],
  };
}

function assertCleanupIntent(intent: PerformanceCleanupIntent): void {
  if (!UUID_V4.test(intent.tenantId) || !UUID_V4.test(intent.provisioningKey)) {
    throw new Error("Performance cleanup intent UUID is invalid");
  }
  const suffix = intent.tenantId.replaceAll("-", "");
  if (
    intent.databaseName !== `nom_t_${suffix}`
    || intent.ownerRole !== `nom_o_${suffix}`
    || intent.runtimeRole !== `nom_r_${suffix}`
    || !TENANT_DATABASE.test(intent.databaseName)
    || !TENANT_OWNER_ROLE.test(intent.ownerRole)
    || !TENANT_RUNTIME_ROLE.test(intent.runtimeRole)
    || intent.secretReference !== `tenant-db/${intent.tenantId}/runtime/v1`
    || !/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/u.test(intent.tenantSlug)
    || intent.displayName.length < 2
    || intent.displayName.length > 160
    || !SHA256_HEX.test(intent.requestHash)
    || intent.namesVerifiedUnused !== true
    || intent.provisioningAttempted !== true
  ) {
    throw new Error("Performance cleanup intent does not match its exact preflight ledger");
  }
}

function assertExactRoute(route: PerformanceCleanupRoute, intent: PerformanceCleanupIntent): void {
  if (
    route.id !== intent.tenantId
    || route.slug !== intent.tenantSlug
    || route.display_name !== intent.displayName
    || route.kind !== "demo"
    || route.status !== "active"
    || route.timezone !== "America/La_Paz"
    || route.locale !== "es"
    || route.database_host !== "127.0.0.1"
    || route.database_port !== 55_432
    || route.database_name !== intent.databaseName
    || route.runtime_role !== intent.runtimeRole
    || route.runtime_secret_ref !== intent.secretReference
    || route.credential_version !== 1
    || route.ssl_mode !== "disable"
  ) {
    throw new Error("Performance cleanup tenant route metadata is not owned by this run");
  }
}

function assertExactJob(job: PerformanceCleanupJob, intent: PerformanceCleanupIntent): void {
  if (
    job.idempotency_key !== intent.provisioningKey
    || job.tenant_id !== intent.tenantId
    || job.requested_slug !== intent.tenantSlug
    || job.request_hash !== intent.requestHash
    || !PROVISIONING_STATES.has(job.state)
    || !Number.isSafeInteger(job.attempt_count)
    || job.attempt_count < 1
  ) {
    throw new Error("Performance cleanup provisioning marker metadata is not owned by this run");
  }
}

function routeMatchesAnyIdentity(route: PerformanceCleanupRoute, intent: PerformanceCleanupIntent): boolean {
  return route.id === intent.tenantId
    || route.slug === intent.tenantSlug
    || route.database_name === intent.databaseName
    || route.runtime_role === intent.runtimeRole
    || route.runtime_secret_ref === intent.secretReference;
}

function assertUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) throw new Error(`Performance cleanup ${label} are not unique`);
}
