import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { catalogPackage2025 } from "@nombramientos/catalog";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { tenantCatalogTarget } from "../src/catalog-reconciliation.js";
import { ControlPlaneStore } from "../src/control-store.js";
import { inspectMigrationPlan } from "../src/migrations.js";
import { TenantPoolResolver } from "../src/pools.js";
import { assertSyntheticSeedTarget } from "../src/seed-guards.js";
import { EncryptedFileSecretProvider } from "../src/secrets.js";
import { TenantStore } from "../src/tenant-store.js";
import { assertNoTenantOperationalRows } from "../src/tenant-maintenance-policy.js";
import type { TenantCredentialRecord, TenantExecutionContext } from "../src/types.js";
import { assertWorkspacePostgresUrl, withoutDatabase } from "../scripts/script-config.js";

const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const OZAMA_TENANT_ID = "0a2a0000-0000-4000-8000-000000000001";
const databasePackageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONTROL_DATABASE = "nombramientos_control";
const EMPTY_TENANT_DATABASE = "nom_t_0a2a0000000040008000000000000001";
const DEMO_TENANT_DATABASE = "nom_t_d0000000000040008000000000000001";
const DEMO_ADMIN_IDENTITY_ID = "d1000000-0000-4000-8000-000000000001";
// fixtureUuid("round:active-proposal") from the declared Demo reference fixture.
const DEMO_ACTIVE_PROPOSAL_ROUND_ID = "47f54489-57a8-48ed-8b28-9bd86ec82fce";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const CANONICAL_CATALOG_TARGET = tenantCatalogTarget(catalogPackage2025);

const local = discoverLocalUrls();
const controlUrl = exactOptionalAdminDatabaseUrl(process.env["TEST_CONTROL_DATABASE_URL"], CONTROL_DATABASE) ?? local?.control;
const tenantUrl = exactOptionalAdminDatabaseUrl(process.env["TEST_TENANT_DATABASE_URL"], EMPTY_TENANT_DATABASE) ?? local?.emptyTenant;
const demoUrl = local?.demoTenant;
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const integrationReady = Boolean(controlUrl && tenantUrl && await canReachDatabases([controlUrl, tenantUrl]));
const fullLiveReady = Boolean(integrationReady && demoUrl && await canReachDatabases([demoUrl]));
if (requireLiveIntegration && !fullLiveReady) {
  throw new Error(
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires reachable control, empty-tenant, and demo PostgreSQL databases",
  );
}
const integration = integrationReady ? describe : describe.skip;

integration("PostgreSQL 18 migrations", () => {
  it("verifies real databases are current without migrating persistent tenants", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    try {
      const [controlPlan, tenantPlan] = await Promise.all([
        inspectMigrationPlan(control, { scope: "control", directory: path.join(databasePackageRoot, "migrations", "control") }),
        inspectMigrationPlan(tenant, { scope: "tenant", directory: path.join(databasePackageRoot, "migrations", "tenant") }),
      ]);
      expect(controlPlan.pending, "Persistent control database has pending migrations; run the explicit upgrade command").toEqual([]);
      expect(tenantPlan.pending, "Persistent tenant database has pending migrations; run the explicit upgrade command").toEqual([]);
      const controlTables = await control.query<{ name: string }>(
        "SELECT to_regclass('public.tenants')::text AS name",
      );
      expect(controlTables.rows[0]?.name).toBe("tenants");
      const counts = await tenant.query<{
        members: number; cycles: number; submissions: number; departments: number; offices: number;
      }>(
        `SELECT
           (SELECT count(*)::int FROM members) AS members,
           (SELECT count(*)::int FROM election_cycles) AS cycles,
           (SELECT count(*)::int FROM encrypted_submissions) AS submissions,
           (SELECT count(*)::int FROM departments) AS departments,
           (SELECT count(*)::int FROM offices) AS offices`,
      );
      expect(counts.rows[0]).toEqual({
        members: 0,
        cycles: 0,
        submissions: 0,
        departments: CANONICAL_CATALOG_TARGET.departmentCount,
        offices: CANONICAL_CATALOG_TARGET.officeCount,
      });
    } finally {
      await Promise.allSettled([control.end(), tenant.end()]);
    }
  }, 30_000);

  it("never returns an outbox event outside the authorized tenant audience", async () => {
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    const client = await tenant.connect();
    try {
      await client.query("BEGIN");
      const baseline = await client.query<{ sequence: number }>(
        "SELECT COALESCE(max(sequence),0)::bigint AS sequence FROM outbox_events",
      );
      const cursor = Number(baseline.rows[0]?.sequence ?? 0);
      const authorized = await client.query<{ id: string }>(
        `INSERT INTO outbox_events(audience,event_type,aggregate_type,payload)
         VALUES ('tenant.authorized','round.phase','round','{}'::jsonb) RETURNING id`,
      );
      await client.query(
        `INSERT INTO outbox_events(audience,event_type,aggregate_type,payload)
         VALUES ('tenant.secret','internal.preference.delta','round','{}'::jsonb)`,
      );
      const events = await new TenantStore(client).listEvents(cursor, 100);
      expect(events.map((event) => event["id"])).toEqual([authorized.rows[0]?.id]);
      expect(events.every((event) => event["audience"] === "tenant.authorized")).toBe(true);
      await client.query("ROLLBACK");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
      await tenant.end();
    }
  });

  it("enforces the report catalog and audience policy at the database boundary", async () => {
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    const insertReport = async (reportType: string, audience: string): Promise<string | null> => {
      const client = await tenant.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `INSERT INTO report_versions(
             report_type,audience,locale,format,filters,state,requested_by_identity_id
           ) VALUES ($1,$2,'es','pdf','{}'::jsonb,'pending',$3)`,
          [reportType, audience, "10000000-0000-4000-8000-000000000001"],
        );
        await client.query("ROLLBACK");
        return null;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        return typeof error === "object" && error !== null && "code" in error ? String(error.code) : "unknown";
      } finally {
        client.release();
      }
    };
    try {
      await expect(insertReport("cycle_summary", "committee")).resolves.toBeNull();
      await expect(insertReport("invented_report", "committee")).resolves.toBe("23514");
      await expect(insertReport("office_round", "church")).resolves.toBe("23514");
      await expect(insertReport("roster_import_incidents", "auditor")).resolves.toBe("23514");
    } finally {
      await tenant.end();
    }
  });

  it.runIf(Boolean(local))("keeps tenant audit storage append-only for the runtime role", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    try {
      const databaseName = new URL(tenantUrl!).pathname.replace(/^\//, "");
      const roleResult = await control.query<{ runtime_role: string; status: string }>(
        "SELECT runtime_role,status FROM tenants WHERE id=$1 AND database_name=$2",
        [OZAMA_TENANT_ID, databaseName],
      );
      const runtimeRole = roleResult.rows[0]?.runtime_role;
      expect(runtimeRole).toBeTruthy();
      expect(roleResult.rows[0]?.status).toBe("provisioning");
      const privileges = await tenant.query<{
        can_select: boolean; can_insert: boolean; can_update: boolean; can_delete: boolean; can_truncate: boolean;
      }>(
        `SELECT
           has_table_privilege($1,'audit_events','SELECT') AS can_select,
           has_table_privilege($1,'audit_events','INSERT') AS can_insert,
           has_table_privilege($1,'audit_events','UPDATE') AS can_update,
           has_table_privilege($1,'audit_events','DELETE') AS can_delete,
           has_table_privilege($1,'audit_events','TRUNCATE') AS can_truncate`,
        [runtimeRole],
      );
      expect(privileges.rows[0]).toEqual({
        can_select: true,
        can_insert: true,
        can_update: false,
        can_delete: false,
        can_truncate: false,
      });
    } finally {
      await Promise.allSettled([control.end(), tenant.end()]);
    }
  });

  it.runIf(Boolean(local))("gives the control runtime only the operations used by the API", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    try {
      const role = local?.controlRuntimeRole;
      expect(role).toBeTruthy();
      const privileges = await control.query<{
        tenants_select: boolean; tenants_insert: boolean; provisioning_select: boolean; tenant_summary_select: boolean;
        identity_insert: boolean; identity_password_update: boolean; identity_login_update: boolean;
        membership_insert: boolean; invitation_insert: boolean; invitation_status_update: boolean;
        invitation_token_select: boolean; invitation_request_hash_select: boolean;
        invitation_idempotency_select: boolean; invitation_token_update: boolean;
        invitation_authority_update: boolean; invitation_attempt_update: boolean;
        invitation_accepted_at_update: boolean; invitation_consumed_at_update: boolean;
        invitation_reconciliation_lease_update: boolean;
        invitation_reconciliation_attempt_update: boolean;
        invitation_legacy_absent: boolean; invitation_insecure_bootstrap_absent: boolean;
        invitation_pre_attempt_bootstrap_absent: boolean; invitation_bootstrap_execute: boolean;
        invitation_private_execute: boolean; invitation_reconciliation_claim_execute: boolean;
        invitation_reconciliation_finish_execute: boolean;
        identity_mfa_secret_update: boolean; identity_mfa_required_update: boolean;
        recovery_select: boolean; recovery_insert: boolean; recovery_consume: boolean; recovery_delete: boolean;
        audit_insert: boolean; audit_update: boolean; audit_delete: boolean;
      }>(
        `SELECT
           has_table_privilege($1,'tenants','SELECT') AS tenants_select,
           has_table_privilege($1,'tenants','INSERT') AS tenants_insert,
           has_table_privilege($1,'provisioning_jobs','SELECT') AS provisioning_select,
           has_table_privilege($1,'platform_tenant_summaries','SELECT') AS tenant_summary_select,
           has_table_privilege($1,'platform_identities','INSERT') AS identity_insert,
           has_column_privilege($1,'platform_identities','password_hash','UPDATE') AS identity_password_update,
           has_column_privilege($1,'platform_identities','failed_login_count','UPDATE') AS identity_login_update,
           has_table_privilege($1,'tenant_memberships','INSERT') AS membership_insert,
           has_any_column_privilege($1,'tenant_invitations','INSERT') AS invitation_insert,
           has_column_privilege($1,'tenant_invitations','status','UPDATE') AS invitation_status_update,
           has_column_privilege($1,'tenant_invitations','token_hash','SELECT') AS invitation_token_select,
           has_column_privilege($1,'tenant_invitations','request_hash','SELECT') AS invitation_request_hash_select,
           has_column_privilege($1,'tenant_invitations','idempotency_key','SELECT') AS invitation_idempotency_select,
           has_column_privilege($1,'tenant_invitations','token_hash','UPDATE') AS invitation_token_update,
           has_column_privilege($1,'tenant_invitations','authority_kind','UPDATE') AS invitation_authority_update,
           has_column_privilege($1,'tenant_invitations','acceptance_attempt','UPDATE') AS invitation_attempt_update,
           has_column_privilege($1,'tenant_invitations','accepted_at','UPDATE') AS invitation_accepted_at_update,
           has_column_privilege($1,'tenant_invitations','consumed_at','UPDATE') AS invitation_consumed_at_update,
           has_column_privilege($1,'tenant_invitations','reconciliation_lease_token','UPDATE') AS invitation_reconciliation_lease_update,
           has_column_privilege($1,'tenant_invitations','reconciliation_attempt_count','UPDATE') AS invitation_reconciliation_attempt_update,
           has_column_privilege($1,'platform_identities','mfa_enrollment_secret_ciphertext','UPDATE') AS identity_mfa_secret_update,
           has_column_privilege($1,'platform_identities','mfa_required','UPDATE') AS identity_mfa_required_update,
           has_table_privilege($1,'mfa_recovery_codes','SELECT') AS recovery_select,
           has_table_privilege($1,'mfa_recovery_codes','INSERT') AS recovery_insert,
           has_column_privilege($1,'mfa_recovery_codes','consumed_at','UPDATE') AS recovery_consume,
           has_table_privilege($1,'mfa_recovery_codes','DELETE') AS recovery_delete,
           to_regprocedure(
             'complete_tenant_invitation_acceptance(uuid,uuid,uuid,uuid,text,text,text)'
           ) IS NULL AS invitation_legacy_absent,
           to_regprocedure(
             'complete_tenant_invitation_acceptance(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text)'
           ) IS NULL AS invitation_insecure_bootstrap_absent,
           to_regprocedure(
             'complete_tenant_invitation_acceptance(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text)'
           ) IS NULL AS invitation_pre_attempt_bootstrap_absent,
           has_function_privilege(
             $1,
             'complete_tenant_invitation_acceptance(uuid,uuid,uuid,integer,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text)',
             'EXECUTE'
           ) AS invitation_bootstrap_execute,
           has_function_privilege(
             $1,
             'complete_tenant_invitation_acceptance_021_private(uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text)',
             'EXECUTE'
           ) AS invitation_private_execute,
           has_function_privilege(
             $1,'claim_tenant_invitation_reconciliation(uuid)','EXECUTE'
           ) AS invitation_reconciliation_claim_execute,
           has_function_privilege(
             $1,
             'finish_tenant_invitation_reconciliation(uuid,uuid,uuid,integer,uuid,boolean,text)',
             'EXECUTE'
           ) AS invitation_reconciliation_finish_execute,
           has_table_privilege($1,'platform_audit_events','INSERT') AS audit_insert,
           has_table_privilege($1,'platform_audit_events','UPDATE') AS audit_update,
           has_table_privilege($1,'platform_audit_events','DELETE') AS audit_delete`,
        [role],
      );
      expect(privileges.rows[0]).toEqual({
        tenants_select: true,
        tenants_insert: false,
        provisioning_select: false,
        tenant_summary_select: true,
        identity_insert: false,
        identity_password_update: false,
        identity_login_update: true,
        membership_insert: false,
        invitation_insert: true,
        invitation_status_update: true,
        invitation_token_select: false,
        invitation_request_hash_select: false,
        invitation_idempotency_select: false,
        invitation_token_update: false,
        invitation_authority_update: false,
        invitation_attempt_update: false,
        invitation_accepted_at_update: false,
        invitation_consumed_at_update: false,
        invitation_reconciliation_lease_update: false,
        invitation_reconciliation_attempt_update: false,
        identity_mfa_secret_update: true,
        identity_mfa_required_update: false,
        recovery_select: true,
        recovery_insert: true,
        recovery_consume: true,
        recovery_delete: false,
        invitation_legacy_absent: true,
        invitation_insecure_bootstrap_absent: true,
        invitation_pre_attempt_bootstrap_absent: true,
        invitation_bootstrap_execute: true,
        invitation_private_execute: false,
        invitation_reconciliation_claim_execute: true,
        invitation_reconciliation_finish_execute: true,
        audit_insert: true,
        audit_update: false,
        audit_delete: false,
      });
    } finally {
      await control.end();
    }
  });

  it.runIf(Boolean(local))("lists sanitized lifecycle state through the control runtime projection", async () => {
    const runtime = new Pool({ connectionString: local!.controlRuntime, max: 1 });
    try {
      const tenants = await new ControlPlaneStore(runtime).listTenants();
      expect(tenants.find(({ id }) => id === OZAMA_TENANT_ID)).toMatchObject({
        kind: "real",
        status: "provisioning",
        provisioningState: "pending_activation",
        activationState: "pending_activation",
      });
      expect(JSON.stringify(tenants)).not.toMatch(
        /request_payload|requestHash|tokenHash|normalizedEmail|databaseName|runtimeRole|secretReference/iu,
      );
      await expect(runtime.query("SELECT request_payload FROM provisioning_jobs LIMIT 1"))
        .rejects.toMatchObject({ code: "42501" });
    } finally {
      await runtime.end();
    }
  });

  it.runIf(Boolean(local))("allows invitation role binding only through the guarded tenant functions", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    try {
      const databaseName = new URL(tenantUrl!).pathname.replace(/^\//, "");
      const roleResult = await control.query<{ runtime_role: string; status: string }>(
        "SELECT runtime_role,status FROM tenants WHERE id=$1 AND database_name=$2",
        [OZAMA_TENANT_ID, databaseName],
      );
      const runtimeRole = roleResult.rows[0]?.runtime_role;
      expect(runtimeRole).toBeTruthy();
      expect(roleResult.rows[0]?.status).toBe("provisioning");
      const privileges = await tenant.query<{
        role_insert: boolean; role_delete: boolean; apply_execute: boolean; cleanup_execute: boolean;
      }>(
        `SELECT
           has_table_privilege($1,'role_bindings','INSERT') AS role_insert,
           has_table_privilege($1,'role_bindings','DELETE') AS role_delete,
           has_function_privilege($1,'apply_tenant_invitation_roles(uuid,uuid,text[],uuid,integer)','EXECUTE') AS apply_execute,
           has_function_privilege($1,'cleanup_tenant_invitation_roles(uuid,uuid,uuid,integer)','EXECUTE') AS cleanup_execute`,
        [runtimeRole],
      );
      expect(privileges.rows[0]).toEqual({
        role_insert: false,
        role_delete: false,
        apply_execute: true,
        cleanup_execute: true,
      });
    } finally {
      await Promise.allSettled([control.end(), tenant.end()]);
    }
  });

  it.runIf(Boolean(local))("keeps platform audit subject UUIDs immutable across identity and tenant lifecycles", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    try {
      const mutableForeignKeys = await control.query<{ count: number }>(
        `SELECT count(*)::int AS count
           FROM pg_constraint constraint_record
           JOIN pg_class table_record ON table_record.oid=constraint_record.conrelid
          WHERE table_record.relname='platform_audit_events'
            AND constraint_record.contype='f'
            AND constraint_record.conkey && ARRAY[
              (SELECT attnum FROM pg_attribute WHERE attrelid=table_record.oid AND attname='actor_identity_id'),
              (SELECT attnum FROM pg_attribute WHERE attrelid=table_record.oid AND attname='tenant_id')
            ]::smallint[]`,
      );
      expect(mutableForeignKeys.rows[0]?.count).toBe(0);
    } finally {
      await control.end();
    }
  });

  it.runIf(Boolean(local && fullLiveReady))("keeps tenant databases, runtime roles, secret references, and CONNECT grants isolated", async () => {
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    try {
      const result = await control.query<{
        id: string; database_name: string; runtime_role: string;
        runtime_secret_ref: string; credential_version: number;
        public_connect_revoked: boolean; runtime_can_connect: boolean;
      }>(
        `SELECT tenant.id,tenant.database_name,tenant.runtime_role,
                tenant.runtime_secret_ref,tenant.credential_version,
                NOT EXISTS (
                  SELECT 1
                    FROM pg_catalog.pg_database database,
                         LATERAL aclexplode(COALESCE(database.datacl,acldefault('d',database.datdba))) privilege
                   WHERE database.datname=tenant.database_name
                     AND privilege.grantee=0
                     AND privilege.privilege_type='CONNECT'
                ) AS public_connect_revoked,
                has_database_privilege(tenant.runtime_role,tenant.database_name,'CONNECT') AS runtime_can_connect
           FROM tenants tenant
          WHERE tenant.id = ANY($1::uuid[])
          ORDER BY tenant.id`,
        [[DEMO_TENANT_ID, OZAMA_TENANT_ID]],
      );
      expect(result.rows).toHaveLength(2);
      const [first, second] = result.rows;
      expect({
        databaseNamesAreDistinct: first?.database_name !== second?.database_name,
        runtimeRolesAreDistinct: first?.runtime_role !== second?.runtime_role,
        secretReferencesAreDistinct: first?.runtime_secret_ref !== second?.runtime_secret_ref,
        deterministicMetadata: result.rows.every((row) => {
          const suffix = row.id.replaceAll("-", "");
          return row.database_name === `nom_t_${suffix}`
            && row.runtime_role === `nom_r_${suffix}`
            && row.runtime_secret_ref === `tenant-db/${row.id}/runtime/v${row.credential_version}`;
        }),
        publicConnectIsRevoked: result.rows.every((row) => row.public_connect_revoked),
        ownRuntimeCanConnect: result.rows.every((row) => row.runtime_can_connect),
      }).toEqual({
        databaseNamesAreDistinct: true,
        runtimeRolesAreDistinct: true,
        secretReferencesAreDistinct: true,
        deterministicMetadata: true,
        publicConnectIsRevoked: true,
        ownRuntimeCanConnect: true,
      });
    } finally {
      await control.end();
    }
  });

  it.runIf(Boolean(local && fullLiveReady))("keeps active Demo and pending Ozama database CONNECT grants isolated", async () => {
    const environment = local!;
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    const store = new ControlPlaneStore(control);
    const secrets = new EncryptedFileSecretProvider(environment.secretFile, environment.secretMasterKey);
    try {
      const demo = await store.getTenantCredential(DEMO_TENANT_ID);
      const demoPassword = await secrets.getSecret(demo.secretReference);
      const pendingOzama = await control.query<{
        status: string; database_name: string; demo_connect: boolean; control_connect: boolean;
      }>(
        `SELECT tenant.status,tenant.database_name,
                has_database_privilege(tenant.runtime_role,$2,'CONNECT') AS demo_connect,
                has_database_privilege(tenant.runtime_role,'nombramientos_control','CONNECT') AS control_connect
           FROM tenants tenant
          WHERE tenant.id=$1`,
        [OZAMA_TENANT_ID, demo.database],
      );
      const probes = await Promise.all([
        probeRuntimeConnection(runtimeUrl(environment.admin, demo, demoPassword, pendingOzama.rows[0]!.database_name)),
        probeRuntimeConnection(runtimeUrl(environment.admin, demo, demoPassword, "nombramientos_control")),
      ]);
      expect(probes).toEqual([
        { connected: false, code: "42501" },
        { connected: false, code: "42501" },
      ]);
      expect(pendingOzama.rows[0]).toMatchObject({
        status: "provisioning",
        demo_connect: false,
        control_connect: false,
      });
    } finally {
      await control.end();
    }
  });

  it.runIf(Boolean(local && fullLiveReady))("resolves and caches active Demo while rejecting pending or mismatched tenant credentials", async () => {
    const environment = local!;
    const control = new Pool({ connectionString: controlUrl, max: 1 });
    const store = new ControlPlaneStore(control);
    const secrets = new EncryptedFileSecretProvider(environment.secretFile, environment.secretMasterKey);
    const resolver = new TenantPoolResolver(
      (tenantId) => store.getTenantCredential(tenantId),
      secrets,
      1,
      60_000,
    );
    let mismatched: TenantPoolResolver | undefined;
    try {
      const demo = await store.getTenantCredential(DEMO_TENANT_ID);
      const demoContext = await inspectResolvedTenant(
        resolver,
        contextFor(DEMO_TENANT_ID, "10000000-0000-4000-8000-000000000011"),
      );
      const firstPool = await resolver.getPool(DEMO_TENANT_ID);
      const cacheStable = firstPool === await resolver.getPool(DEMO_TENANT_ID);
      const pendingOzama = await captureResolutionFailure(() => store.getTenantCredential(OZAMA_TENANT_ID));
      expect({ demo: demoContext, cacheStable, pendingOzama }).toEqual({
        demo: {
          databaseMatches: true,
          roleMatches: true,
          localContextMatches: true,
          tenantSettingsMatch: true,
        },
        cacheStable: true,
        pendingOzama: {
          rejected: true,
          message: "Active tenant credential was not found",
        },
      });

      const scratchMismatch: TenantCredentialRecord = {
        ...demo,
        tenantId: "40000000-0000-4000-8000-000000000099",
      };
      mismatched = new TenantPoolResolver(async () => scratchMismatch, secrets, 1, 60_000);
      const mismatch = await captureResolutionFailure(() => mismatched!.getPool(demo.tenantId));
      expect(mismatch).toEqual({
        rejected: true,
        message: "Tenant credential resolution returned a mismatched tenant",
      });
    } finally {
      await Promise.allSettled([resolver.close(), mismatched?.close(), control.end()]);
    }
  });

  it.runIf(Boolean(local && fullLiveReady))("keeps every Ozama operational table empty", async () => {
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    try {
      await expect(assertNoTenantOperationalRows(tenant, OZAMA_TENANT_ID)).resolves.toBeUndefined();
    } finally {
      await tenant.end();
    }
  });

  it.runIf(Boolean(local))("refuses the demo seed guard against the real Ozama database without writing", async () => {
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    try {
      const before = await tenant.query<{ count: number }>("SELECT count(*)::int AS count FROM members");
      const target = await tenant.query<{ database_name: string; tenant_id: string; kind: string }>(
        "SELECT current_database() AS database_name,tenant_id,kind FROM tenant_settings WHERE singleton=true",
      );
      const actual = target.rows[0];
      expect(actual).toBeTruthy();
      expect(() => assertSyntheticSeedTarget({
        databaseName: "nom_t_d0000000000040008000000000000001",
        tenantId: "d0000000-0000-4000-8000-000000000001",
        kind: "demo",
      }, {
        databaseName: actual!.database_name,
        tenantId: actual!.tenant_id,
        kind: actual!.kind,
      })).toThrow(/refusing all writes/i);
      const after = await tenant.query<{ count: number }>("SELECT count(*)::int AS count FROM members");
      expect(after.rows[0]?.count).toBe(before.rows[0]?.count);
      expect(after.rows[0]?.count).toBe(0);
    } finally {
      await tenant.end();
    }
  });

  it.runIf(Boolean(local))("commits an encrypted member-import plan once and makes cross-retry replay harmless", async () => {
    const tenant = new Pool({ connectionString: tenantUrl, max: 1 });
    const client = await tenant.connect();
    const identityId = "10000000-0000-4000-8000-000000000021";
    const sessionId = "10000000-0000-4000-8000-000000000022";
    const requestId = "10000000-0000-4000-8000-000000000023";
    const memberId = "d2000000-0000-4000-8000-000000009901";
    const tenantKeyId = "10000000-0000-4000-8000-000000000028";
    const keyGenerationId = "10000000-0000-4000-8000-000000000029";
    const keyDeviceId = "10000000-0000-4000-8000-000000000030";
    const sourceFingerprint = `sha256:${"b".repeat(64)}`;
    const envelope = {
      algorithm: "AES-256-GCM" as const,
      keyId: tenantKeyId,
      nonce: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAA",
      aad: "e30",
    };
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [OZAMA_TENANT_ID, identityId, sessionId, requestId],
      );
      await client.query(
        `INSERT INTO e2ee_key_devices(
           device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,status,activated_at
         ) VALUES ($1,$2,'Member import integration device','{}'::jsonb,$3,'active',clock_timestamp())`,
        [keyDeviceId, identityId, `sha256:${"e".repeat(64)}`],
      );
      await client.query(
        `INSERT INTO e2ee_key_generations(
           id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,created_by_identity_id
         ) VALUES ($1,$2,1,'active','{}'::jsonb,$3,$4)`,
        [keyGenerationId, tenantKeyId, `sha256:${"f".repeat(64)}`, identityId],
      );
      await client.query(
        `INSERT INTO e2ee_key_grants(
           generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,status,granted_by_identity_id
         ) VALUES ($1,$2,$3,'{}'::jsonb,$4,'initial','active',$2)`,
        [keyGenerationId, identityId, keyDeviceId, `sha256:${"9".repeat(64)}`],
      );
      const store = new TenantStore(client);
      const preview = await store.previewImport({
        identityId,
        idempotencyKey: "10000000-0000-4000-8000-000000000024",
        sourceFingerprint,
        sourceFileName: "roster.csv",
        sourceSheetName: `sheet-sha256:${"d".repeat(64)}`,
        columnMapping: { displayName: 0, eligible: 1 },
        rows: [{
          sourceRow: 2,
          id: memberId,
          shortId: "LIVE-IMPORT-ROLLBACK",
          eligible: true,
          decision: { action: "create", matchBasis: "none" },
          displayEnvelope: envelope,
          displayContentHash: `sha256:${"c".repeat(64)}`,
        }],
      });
      expect(preview).toMatchObject({ state: "previewed", counts: { create: 1, errors: 0 } });
      const importId = String(preview["importId"]);
      const committed = await store.commitImport({
        identityId,
        idempotencyKey: "10000000-0000-4000-8000-000000000025",
        importId,
        expectedRevision: Number(preview["revision"]),
      });
      expect(committed).toMatchObject({ state: "completed", created: 1, updated: 0, skipped: 0, total: 1 });
      const retriedCommit = await store.commitImport({
        identityId,
        idempotencyKey: "10000000-0000-4000-8000-000000000026",
        importId,
        expectedRevision: Number(preview["revision"]),
      });
      expect(retriedCommit).toMatchObject({ state: "completed", created: 1, replayed: true });
      const retriedPreview = await store.previewImport({
        identityId,
        idempotencyKey: "10000000-0000-4000-8000-000000000027",
        sourceFingerprint,
        sourceFileName: "roster.csv",
        sourceSheetName: `sheet-sha256:${"d".repeat(64)}`,
        columnMapping: { displayName: 0, eligible: 1 },
        rows: [{
          sourceRow: 2,
          id: memberId,
          shortId: "LIVE-IMPORT-ROLLBACK",
          eligible: true,
          decision: { action: "create", matchBasis: "none" },
          displayEnvelope: envelope,
          displayContentHash: `sha256:${"c".repeat(64)}`,
        }],
      });
      expect(retriedPreview).toMatchObject({ state: "completed", importId });
      const count = await client.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM members WHERE id=$1",
        [memberId],
      );
      expect(count.rows[0]?.count).toBe(1);
      await client.query("ROLLBACK");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
      await tenant.end();
    }
  });

  it.runIf(Boolean(demoUrl))("contains the declared fixture plus zero or one causally authorized E2E receipt", async () => {
    const demo = new Pool({ connectionString: demoUrl, max: 1 });
    try {
      const counts = await demo.query<{
        members: number; eligible: number; active_cycles: number; rounds: number;
        submissions: number; receipts: number; active_submissions: number;
        reference_vacancies: number; recommended: number;
        accepted: number; elected: number; responsibilities: number;
        responsible_people: number; frozen_members: number;
      }>(
        `WITH active_cycle AS (SELECT id FROM election_cycles WHERE status='active' LIMIT 1)
         SELECT
           (SELECT count(*)::int FROM members) AS members,
           (SELECT count(*)::int FROM members WHERE eligibility_status='eligible' AND available) AS eligible,
           (SELECT count(*)::int FROM election_cycles WHERE status='active') AS active_cycles,
           (SELECT count(*)::int FROM rounds) AS rounds,
           (SELECT count(*)::int FROM encrypted_submissions) AS submissions,
           (SELECT count(*)::int FROM participation_receipts) AS receipts,
           (SELECT count(*)::int FROM encrypted_submissions submission
             JOIN rounds round ON round.id=submission.round_id
            WHERE round.phase='PROPUESTAS_ABIERTAS' AND round.submission_kind='proposal') AS active_submissions,
           (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM active_cycle)) AS reference_vacancies,
           (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM active_cycle) AND status IN ('recommended','accepted','elected')) AS recommended,
           (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM active_cycle) AND status IN ('accepted','elected')) AS accepted,
           (SELECT count(*)::int FROM vacancies WHERE cycle_id=(SELECT id FROM active_cycle) AND status='elected') AS elected,
           (SELECT count(*)::int FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
             WHERE v.cycle_id=(SELECT id FROM active_cycle) AND a.effective AND a.independent) AS responsibilities,
           (SELECT count(DISTINCT a.member_id)::int FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
             WHERE v.cycle_id=(SELECT id FROM active_cycle) AND a.effective AND a.independent) AS responsible_people,
           (SELECT count(*)::int FROM cycle_member_snapshots WHERE cycle_id=(SELECT id FROM active_cycle)) AS frozen_members`,
      );
      const activeOrigin = await demo.query<{
        tenant_id: string;
        round_id: string;
        cycle_status: string;
        phase: string;
        submission_kind: string;
        round_version: number;
        active_proposal_round_count: number;
        permitted_active_origin_count: number;
        expected_admin_origin_count: number;
      }>(
        `SELECT settings.tenant_id::text AS tenant_id,
                round_state.id::text AS round_id,
                cycle.status AS cycle_status,
                round_state.phase,
                round_state.submission_kind,
                round_state.version AS round_version,
                (SELECT count(*)::int FROM rounds active_round
                  WHERE active_round.phase='PROPUESTAS_ABIERTAS'
                    AND active_round.submission_kind='proposal') AS active_proposal_round_count,
                (SELECT count(*)::int
                   FROM rounds active_round
                   JOIN round_elector_snapshots active_elector ON active_elector.round_id=active_round.id
                  WHERE active_round.phase='PROPUESTAS_ABIERTAS'
                    AND active_round.submission_kind='proposal'
                    AND active_elector.can_submit
                    AND NOT active_elector.recused) AS permitted_active_origin_count,
                (SELECT count(*)::int FROM round_elector_snapshots expected_elector
                  WHERE expected_elector.round_id=round_state.id
                    AND expected_elector.identity_id=$2
                    AND expected_elector.can_submit
                    AND NOT expected_elector.recused) AS expected_admin_origin_count
           FROM tenant_settings settings
           JOIN rounds round_state ON round_state.id=$1
           JOIN election_cycles cycle ON cycle.id=round_state.cycle_id
          WHERE settings.singleton`,
        [DEMO_ACTIVE_PROPOSAL_ROUND_ID, DEMO_ADMIN_IDENTITY_ID],
      );
      const activeEvidence = await demo.query<{
        submission_id: string;
        round_id: string;
        elector_identity_id: string;
        kind: string;
        content_hash: string;
        submission_round_version: number;
        receipt_id: string | null;
        receipt_received_at_canonical: string | null;
        response_received_at_canonical: string | null;
        exact_receipt: boolean;
        exact_elector: boolean;
        exact_audit_count: number;
        exact_idempotency_count: number;
        exact_outbox_count: number;
      }>(
        `SELECT submission.id::text AS submission_id,
                submission.round_id::text AS round_id,
                submission.elector_identity_id::text AS elector_identity_id,
                submission.kind,
                submission.content_hash,
                submission.round_version AS submission_round_version,
                receipt.id::text AS receipt_id,
                to_char(
                  receipt.received_at AT TIME ZONE 'UTC',
                  'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                ) AS receipt_received_at_canonical,
                (SELECT to_char(
                          (idempotency.response_body->>'receivedAt')::timestamptz AT TIME ZONE 'UTC',
                          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                        )
                   FROM idempotency_records idempotency
                  WHERE idempotency.identity_id=submission.elector_identity_id
                    AND idempotency.operation='round.proposal.submit'
                    AND idempotency.response_status=200
                    AND idempotency.response_body->>'status'='received'
                    AND idempotency.response_body->>'roundId'=submission.round_id::text
                    AND idempotency.response_body->>'receiptId'=receipt.id::text
                    AND idempotency.response_body->>'contentHash'=submission.content_hash
                    AND idempotency.response_body->>'roundVersion'=submission.round_version::text
                  ORDER BY idempotency.created_at,idempotency.idempotency_key
                  LIMIT 1) AS response_received_at_canonical,
                receipt.id IS NOT NULL
                  AND receipt.round_id=submission.round_id
                  AND receipt.elector_identity_id=submission.elector_identity_id
                  AND receipt.kind=submission.kind
                  AND receipt.content_hash=submission.content_hash AS exact_receipt,
                EXISTS(
                  SELECT 1 FROM round_elector_snapshots elector
                   WHERE elector.round_id=submission.round_id
                     AND elector.identity_id=submission.elector_identity_id
                     AND elector.can_submit
                     AND NOT elector.recused
                ) AS exact_elector,
                (SELECT count(*)::int FROM audit_events audit
                  WHERE audit.action='round.submission.received'
                    AND audit.entity_type='round'
                    AND audit.entity_id::text=submission.round_id::text
                    AND audit.actor_identity_id=submission.elector_identity_id
                    AND audit.result='success'
                    AND audit.request_id IS NOT NULL
                    AND audit.metadata=jsonb_build_object('kind',submission.kind,'receiptId',receipt.id)) AS exact_audit_count,
                (SELECT count(*)::int FROM idempotency_records idempotency
                  WHERE idempotency.identity_id=submission.elector_identity_id
                    AND idempotency.operation='round.proposal.submit'
                    AND idempotency.response_status=200
                    AND idempotency.request_hash ~ '^[0-9a-f]{64}$'
                    AND idempotency.idempotency_key::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                    AND (SELECT count(*) FROM jsonb_object_keys(idempotency.response_body))=6
                    AND idempotency.response_body->>'status'='received'
                    AND idempotency.response_body->>'roundId'=submission.round_id::text
                    AND idempotency.response_body->>'receiptId'=receipt.id::text
                    AND idempotency.response_body->>'contentHash'=submission.content_hash
                    AND idempotency.response_body->>'roundVersion'=submission.round_version::text
                    AND (idempotency.response_body->>'receivedAt')::timestamptz=receipt.received_at) AS exact_idempotency_count,
                (SELECT count(*)::int FROM outbox_events outbox
                  WHERE outbox.audience='tenant.authorized'
                    AND outbox.event_type='round.participation'
                    AND outbox.aggregate_type='round'
                    AND outbox.aggregate_id::text=submission.round_id::text
                    AND outbox.payload=jsonb_build_object('roundId',submission.round_id)) AS exact_outbox_count
           FROM encrypted_submissions submission
           LEFT JOIN participation_receipts receipt ON receipt.submission_id=submission.id
          WHERE submission.round_id=$1
            AND submission.elector_identity_id=$2
          ORDER BY submission.received_at,submission.id`,
        [DEMO_ACTIVE_PROPOSAL_ROUND_ID, DEMO_ADMIN_IDENTITY_ID],
      );
      const { submissions, receipts, active_submissions: activeSubmissions, ...stableCounts } = counts.rows[0]!;
      expect(stableCounts).toEqual({
        members: 180,
        eligible: 150,
        active_cycles: 1,
        rounds: 23,
        reference_vacancies: 40,
        recommended: 20,
        accepted: 15,
        elected: 10,
        responsibilities: 20,
        responsible_people: 16,
        frozen_members: 180,
      });
      expect(activeOrigin.rows).toEqual([{
        tenant_id: DEMO_TENANT_ID,
        round_id: DEMO_ACTIVE_PROPOSAL_ROUND_ID,
        cycle_status: "active",
        phase: "PROPUESTAS_ABIERTAS",
        submission_kind: "proposal",
        round_version: 1,
        active_proposal_round_count: 1,
        permitted_active_origin_count: 1,
        expected_admin_origin_count: 1,
      }]);
      expect(activeSubmissions).toBeGreaterThanOrEqual(0);
      expect(activeSubmissions).toBeLessThanOrEqual(1);
      expect(receipts).toBe(submissions);
      expect(activeEvidence.rows).toHaveLength(activeSubmissions);
      for (const evidence of activeEvidence.rows) {
        expect(evidence).toMatchObject({
          round_id: DEMO_ACTIVE_PROPOSAL_ROUND_ID,
          elector_identity_id: DEMO_ADMIN_IDENTITY_ID,
          kind: "proposal",
          submission_round_version: 1,
          exact_receipt: true,
          exact_elector: true,
          exact_audit_count: 1,
          exact_idempotency_count: 1,
          exact_outbox_count: 1,
        });
        expect(evidence.submission_id).toMatch(UUID_PATTERN);
        expect(evidence.receipt_id).toMatch(UUID_PATTERN);
        expect(evidence.content_hash).toMatch(SHA256_PATTERN);
        expect(evidence.receipt_received_at_canonical).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);
        expect(evidence.response_received_at_canonical).toBe(evidence.receipt_received_at_canonical);
      }
      expect(submissions - activeSubmissions).toBe(294);
    } finally {
      await demo.end();
    }
  });
});

function discoverLocalUrls(): {
  admin: string;
  control: string;
  emptyTenant: string;
  demoTenant: string;
  controlRuntime: string;
  controlRuntimeRole: string;
  secretFile: string;
  secretMasterKey: Uint8Array;
} | undefined {
  try {
    const install = JSON.parse(readFileSync(path.join(databasePackageRoot, ".local", "install.json"), "utf8")) as {
      DATABASE_ADMIN_URL?: string;
      DATABASE_CONTROL_URL?: string;
      DATABASE_SECRET_FILE?: string;
      DATABASE_SECRET_MASTER_KEY_B64?: string;
    };
    if (!install.DATABASE_ADMIN_URL || !install.DATABASE_CONTROL_URL
      || !install.DATABASE_SECRET_FILE || !install.DATABASE_SECRET_MASTER_KEY_B64) return undefined;
    const secretMasterKey = Buffer.from(install.DATABASE_SECRET_MASTER_KEY_B64, "base64url");
    if (secretMasterKey.byteLength !== 32) return undefined;
    const admin = assertWorkspacePostgresUrl(install.DATABASE_ADMIN_URL, "nom_admin", "postgres");
    const controlRuntime = assertWorkspacePostgresUrl(
      install.DATABASE_CONTROL_URL,
      "nom_control",
      CONTROL_DATABASE,
    );
    return {
      admin: admin.toString(),
      control: withoutDatabase(admin.toString(), CONTROL_DATABASE),
      emptyTenant: withoutDatabase(admin.toString(), EMPTY_TENANT_DATABASE),
      demoTenant: withoutDatabase(admin.toString(), DEMO_TENANT_DATABASE),
      controlRuntime: controlRuntime.toString(),
      controlRuntimeRole: decodeURIComponent(controlRuntime.username),
      secretFile: path.resolve(databasePackageRoot, install.DATABASE_SECRET_FILE),
      secretMasterKey,
    };
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error
        && ["ENOENT", "EACCES", "EPERM"].includes(String(error.code))) return undefined;
    throw error;
  }
}

function exactOptionalAdminDatabaseUrl(value: string | undefined, database: string): string | undefined {
  if (value === undefined) return undefined;
  return assertWorkspacePostgresUrl(value, "nom_admin", database).toString();
}

function runtimeUrl(
  adminUrl: string,
  credential: TenantCredentialRecord,
  password: string,
  database: string,
): string {
  const value = new URL(adminUrl);
  value.hostname = credential.host;
  value.port = String(credential.port);
  value.pathname = `/${database}`;
  value.username = credential.user;
  value.password = password;
  return value.toString();
}

async function probeRuntimeConnection(connectionString: string): Promise<{
  connected: boolean;
  code: string | null;
}> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 3_000 });
  try {
    await pool.query("SELECT 1");
    return { connected: true, code: null };
  } catch (error) {
    return {
      connected: false,
      code: typeof error === "object" && error !== null && "code" in error
        ? String(error.code)
        : "UNKNOWN",
    };
  } finally {
    await pool.end().catch(() => undefined);
  }
}

function contextFor(tenantId: string, requestId: string): TenantExecutionContext {
  return {
    tenantId,
    identityId: "20000000-0000-4000-8000-000000000001",
    sessionId: "30000000-0000-4000-8000-000000000001",
    requestId,
  };
}

async function inspectResolvedTenant(
  resolver: TenantPoolResolver,
  context: TenantExecutionContext,
): Promise<{
  databaseMatches: boolean;
  roleMatches: boolean;
  localContextMatches: boolean;
  tenantSettingsMatch: boolean;
}> {
  const record = await resolver.withTenant(context, async (client) => {
    const result = await client.query<{
      database_name: string; role_name: string; local_tenant_id: string;
      settings_tenant_id: string;
    }>(
      `SELECT current_database() AS database_name,current_user AS role_name,
              current_setting('app.tenant_id') AS local_tenant_id,
              tenant_id::text AS settings_tenant_id
         FROM tenant_settings WHERE singleton=true`,
    );
    return result.rows[0];
  });
  const suffix = context.tenantId.replaceAll("-", "");
  return {
    databaseMatches: record?.database_name === `nom_t_${suffix}`,
    roleMatches: record?.role_name === `nom_r_${suffix}`,
    localContextMatches: record?.local_tenant_id === context.tenantId,
    tenantSettingsMatch: record?.settings_tenant_id === context.tenantId,
  };
}

async function captureResolutionFailure(work: () => Promise<unknown>): Promise<{
  rejected: boolean;
  message: string | null;
}> {
  try {
    await work();
    return { rejected: false, message: null };
  } catch (error) {
    return { rejected: true, message: error instanceof Error ? error.message : "unknown" };
  }
}

async function canReachDatabases(urls: readonly (string | undefined)[]): Promise<boolean> {
  if (urls.some((url) => !url)) return false;
  const pools = urls.map((connectionString) => new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_500 }));
  try {
    await Promise.all(pools.map((pool) => pool.query("SELECT 1")));
    return true;
  } catch {
    return false;
  } finally {
    await Promise.allSettled(pools.map((pool) => pool.end()));
  }
}
