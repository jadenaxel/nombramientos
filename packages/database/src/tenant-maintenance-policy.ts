import type { Pool, PoolClient } from "pg";

export const TENANT_CONFIGURATION_TABLES = [
  "tenant_settings",
  "permissions",
  "roles",
  "role_permissions",
  "system_role_assignment_matrix",
  "initial_admin_activation_capability",
  "departments",
  "offices",
] as const;

// A pending-activation real tenant may contain only the configuration/catalog
// tables above. Keep this inventory as the single source of truth for every
// activation, backup and upgrade emptiness gate.
export const TENANT_OPERATIONAL_TABLES = [
  "tenant_invitation_acceptance_fences",
  "role_bindings",
  "device_key_grants",
  "members",
  "election_cycles",
  "vacancies",
  "rounds",
  "round_elector_snapshots",
  "candidate_snapshots",
  "encrypted_submissions",
  "participation_receipts",
  "member_import_jobs",
  "assignments",
  "report_versions",
  "idempotency_records",
  "outbox_events",
  "audit_events",
  "committee_memberships",
  "seed_manifests",
  "cycle_member_snapshots",
  "custodian_device_keys",
  "round_custody_sets",
  "round_custodian_key_snapshots",
  "tally_manifests",
  "tally_manifest_entries",
  "custodian_attestations",
  "cycle_sessions",
  "cycle_elector_roster",
  "office_processes",
  "proposal_manifests",
  "proposal_manifest_entries",
  "proposal_aggregates",
  "candidacies",
  "candidacy_reviews",
  "candidate_list_versions",
  "candidate_list_entries",
  "assignment_transitions",
  "member_photo_assets",
  "e2ee_key_devices",
  "e2ee_key_generations",
  "e2ee_key_grants",
  "e2ee_key_challenges",
  "member_eligibility_workflow_pauses",
  "session_attendance",
  "session_agenda_items",
  "session_decisions",
  "member_qualification_versions",
] as const;

/** Exact public table inventory accepted by provisioning and maintenance. */
export const TENANT_CANONICAL_TABLES: readonly string[] = Object.freeze([
  "schema_migrations",
  ...TENANT_CONFIGURATION_TABLES,
  ...TENANT_OPERATIONAL_TABLES,
].sort());

export type TenantMaintenanceClass = "routable" | "pending_activation" | "initial_admin_pending";

export interface TenantMaintenanceLifecycle {
  readonly kind: string;
  readonly status: string;
  readonly latestProvisioningState: string | null;
  readonly tenantMembershipCount?: number;
  readonly openInitialAdminInvitationCount?: number;
}

export interface TenantMaintenanceRoute {
  readonly id: string;
  readonly kind: "demo" | "real";
  readonly status: "active" | "suspended" | "provisioning";
  readonly maintenanceClass: TenantMaintenanceClass;
  readonly latestProvisioningState: string | null;
  readonly databaseHost: string;
  readonly databasePort: number;
  readonly databaseName: string;
  readonly runtimeRole: string;
  readonly runtimeSecretReference: string;
  readonly credentialVersion: number;
}

interface TenantMaintenanceControlRow {
  readonly id: string;
  readonly kind: string;
  readonly status: string;
  readonly database_host: string;
  readonly database_port: number;
  readonly database_name: string;
  readonly runtime_role: string;
  readonly runtime_secret_ref: string;
  readonly credential_version: number;
  readonly latest_provisioning_state: string | null;
  readonly tenant_membership_count: number;
  readonly open_initial_admin_invitation_count: number;
}

const maintenanceRouteSelect = `
  SELECT tenant.id::text,tenant.kind,tenant.status,tenant.database_host,tenant.database_port,
         tenant.database_name::text,tenant.runtime_role::text,tenant.runtime_secret_ref,
         tenant.credential_version,latest_job.state AS latest_provisioning_state,
         (SELECT count(*)::integer FROM tenant_memberships membership
           WHERE membership.tenant_id=tenant.id) AS tenant_membership_count,
         (SELECT count(*)::integer FROM tenant_invitations invitation
           WHERE invitation.tenant_id=tenant.id
             -- Backup must be possible before control migration 024 is
             -- installed. Converting the whole legacy row to JSON lets an
             -- absent future column evaluate to NULL instead of failing SQL
             -- parse/planning; it never infers initial-admin authority from
             -- roles, email or lifecycle.
             AND to_jsonb(invitation)->>'authority_kind'='initial_admin'
             AND invitation.status IN ('pending','accepting','compensating'))
           AS open_initial_admin_invitation_count
    FROM tenants tenant
    LEFT JOIN LATERAL (
      SELECT job.state
        FROM provisioning_jobs job
       WHERE job.tenant_id=tenant.id
       ORDER BY job.updated_at DESC,job.created_at DESC,job.id DESC
       LIMIT 1
    ) latest_job ON true`;

export function tenantMaintenanceClass(
  tenant: TenantMaintenanceLifecycle,
): TenantMaintenanceClass | null {
  if (tenant.kind !== "demo" && tenant.kind !== "real") return null;
  if (
    tenant.status === "active"
    && tenant.kind === "real"
    && tenant.latestProvisioningState === "active"
    && tenant.tenantMembershipCount === 0
    && tenant.openInitialAdminInvitationCount === 1
  ) {
    return "initial_admin_pending";
  }
  if (tenant.status === "active" || tenant.status === "suspended") return "routable";
  if (
    tenant.status === "provisioning"
    && tenant.kind === "real"
    && tenant.latestProvisioningState === "pending_activation"
  ) {
    return "pending_activation";
  }
  return null;
}

export async function resolveTenantMaintenanceRoute(
  control: Pick<Pool, "query">,
  tenantId: string,
): Promise<TenantMaintenanceRoute> {
  const result = await control.query<TenantMaintenanceControlRow>(
    `${maintenanceRouteSelect} WHERE tenant.id=$1`,
    [tenantId],
  );
  const row = result.rows[0];
  if (!row) throw new Error(`Tenant ${tenantId} was not found in the control plane`);
  const route = maintenanceRoute(row);
  if (!route) {
    throw new Error(
      `Tenant ${tenantId} is not eligible for maintenance in lifecycle ${row.status}`,
    );
  }
  return route;
}

/**
 * Serializes a maintenance operation with tenant provisioning and every
 * control-plane transition that locks the tenant row. The caller must already
 * be inside a control-database transaction so the xact advisory and row locks
 * remain held until the complete maintenance operation has finished.
 */
export async function lockTenantMaintenanceRoute(
  control: Pick<PoolClient, "query">,
  tenantId: string,
): Promise<TenantMaintenanceRoute> {
  await control.query(
    "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
    [tenantId],
  );
  const tenantLock = await control.query<{ id: string }>(
    "SELECT id::text FROM tenants WHERE id=$1 FOR UPDATE",
    [tenantId],
  );
  if (tenantLock.rowCount !== 1 || tenantLock.rows[0]?.id !== tenantId) {
    throw new Error(`Tenant ${tenantId} was not found in the control plane`);
  }
  await control.query(
    "SELECT id::text FROM provisioning_jobs WHERE tenant_id=$1 ORDER BY id FOR UPDATE",
    [tenantId],
  );
  return await resolveTenantMaintenanceRoute(control, tenantId);
}

export async function listTenantMaintenanceRoutes(
  control: Pick<Pool, "query">,
): Promise<readonly TenantMaintenanceRoute[]> {
  const result = await control.query<TenantMaintenanceControlRow>(
    `${maintenanceRouteSelect} ORDER BY tenant.id`,
  );
  return result.rows.flatMap((row) => {
    const route = maintenanceRoute(row);
    return route ? [route] : [];
  });
}

export async function assertTenantMaintenanceDatabase(
  client: Pick<PoolClient, "query">,
  tenant: Pick<TenantMaintenanceRoute, "id" | "kind" | "databaseName" | "maintenanceClass">,
): Promise<void> {
  const result = await client.query<{
    tenant_id: string;
    kind: string;
    setup_state: string;
    database_name: string;
  }>(
    `SELECT settings.tenant_id::text,settings.kind,settings.setup_state,
            current_database() AS database_name
       FROM tenant_settings settings
      WHERE settings.singleton=true`,
  );
  const settings = result.rows[0];
  if (
    result.rowCount !== 1
    || !settings
    || settings.tenant_id !== tenant.id
    || settings.kind !== tenant.kind
    || settings.database_name !== tenant.databaseName
  ) {
    throw new Error(`Tenant ${tenant.id} database identity does not match its control-plane route`);
  }
  if (
    tenant.maintenanceClass === "pending_activation"
    || tenant.maintenanceClass === "initial_admin_pending"
  ) {
    // A real tenant awaiting its first administrator is intentionally still in
    // onboarding (`not_started`). It nevertheless needs backup/restore and
    // schema maintenance before activation. `in_progress` remains excluded so
    // maintenance cannot overlap a partially completed onboarding transition.
    if (settings.setup_state !== "not_started" && settings.setup_state !== "ready") {
      throw new Error(
        `Pending-activation tenant ${tenant.id} setup_state must be not_started or ready for maintenance`,
      );
    }
    await assertNoTenantOperationalRows(client, tenant.id);
    return;
  }
  if (settings.setup_state !== "ready") {
    throw new Error(`Tenant ${tenant.id} setup_state must be ready for maintenance`);
  }
}

export async function assertNoTenantOperationalRows(
  client: Pick<PoolClient, "query">,
  tenantId: string,
): Promise<void> {
  const existing = await client.query<{ name: string }>(
    `SELECT tablename AS name
       FROM pg_catalog.pg_tables
      WHERE schemaname='public' AND tablename = ANY($1::text[])
      ORDER BY tablename`,
    [[...TENANT_OPERATIONAL_TABLES]],
  );
  const allowed = new Set<string>(TENANT_OPERATIONAL_TABLES);
  const nonEmpty: string[] = [];
  for (const { name } of existing.rows) {
    if (!allowed.has(name)) {
      throw new Error(`Unrecognized operational table returned while validating tenant ${tenantId}`);
    }
    const count = await client.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM public.${quoteIdentifier(name)}`,
    );
    const rows = count.rows[0]?.count;
    if (rows === undefined || !/^\d+$/u.test(rows)) {
      throw new Error(`Operational row count is unavailable for tenant ${tenantId}`);
    }
    if (rows !== "0") nonEmpty.push(`${name}=${rows}`);
  }
  if (nonEmpty.length > 0) {
    throw new Error(
      `Pending-activation tenant ${tenantId} contains operational rows: ${nonEmpty.join(", ")}`,
    );
  }
}

/**
 * Stronger, opt-in gate for security/grant reconciliation. Backup and recovery
 * deliberately keep using the tolerant emptiness check above so a partially
 * restored database remains recoverable; a grant closure must instead prove
 * that the complete canonical tenant schema is present and has no extra table.
 */
export async function assertCanonicalTenantTableInventory(
  client: Pick<PoolClient, "query">,
  tenantId: string,
): Promise<void> {
  const result = await client.query<{ name: string }>(
    `SELECT tablename AS name
       FROM pg_catalog.pg_tables
      WHERE schemaname='public'
      ORDER BY tablename`,
  );
  const expected = TENANT_CANONICAL_TABLES;
  const actual = result.rows.map(({ name }) => name).sort();
  if (
    actual.length !== expected.length
    || actual.some((name, index) => name !== expected[index])
  ) {
    throw new Error(`Tenant ${tenantId} does not have the exact canonical table inventory`);
  }
}

export function assertExpectedTenantComparisons(
  expectedTenantIds: readonly string[],
  comparedTenantIds: readonly string[],
): void {
  const expected = normalizedUniqueIds(expectedTenantIds, "expected");
  const compared = normalizedUniqueIds(comparedTenantIds, "compared");
  if (expected.length !== compared.length || expected.some((id, index) => id !== compared[index])) {
    const missing = expected.filter((id) => !compared.includes(id));
    const unexpected = compared.filter((id) => !expected.includes(id));
    throw new Error(
      `Restore neighbor comparison coverage mismatch (missing=${missing.join(",") || "none"}; unexpected=${unexpected.join(",") || "none"})`,
    );
  }
}

function maintenanceRoute(row: TenantMaintenanceControlRow): TenantMaintenanceRoute | null {
  const maintenanceClass = tenantMaintenanceClass({
    kind: row.kind,
    status: row.status,
    latestProvisioningState: row.latest_provisioning_state,
    tenantMembershipCount: row.tenant_membership_count,
    openInitialAdminInvitationCount: row.open_initial_admin_invitation_count,
  });
  if (!maintenanceClass) return null;
  if (row.kind !== "demo" && row.kind !== "real") return null;
  if (row.status !== "active" && row.status !== "suspended" && row.status !== "provisioning") {
    throw new Error(`Tenant ${row.id} has an invalid maintenance lifecycle`);
  }
  return {
    id: row.id,
    kind: row.kind,
    status: row.status,
    maintenanceClass,
    latestProvisioningState: row.latest_provisioning_state,
    databaseHost: row.database_host,
    databasePort: row.database_port,
    databaseName: row.database_name,
    runtimeRole: row.runtime_role,
    runtimeSecretReference: row.runtime_secret_ref,
    credentialVersion: row.credential_version,
  };
}

function normalizedUniqueIds(ids: readonly string[], label: string): readonly string[] {
  const sorted = [...ids].sort();
  if (new Set(sorted).size !== sorted.length) {
    throw new Error(`Restore neighbor ${label} tenant ids must be unique`);
  }
  return sorted;
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}
