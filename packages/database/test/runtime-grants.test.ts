import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  TENANT_RUNTIME_APPEND_ONLY_TABLES,
  TENANT_RUNTIME_GRANT_CONTRACT,
  TENANT_RUNTIME_MUTABLE_TABLES,
  TENANT_RUNTIME_READ_ONLY_TABLES,
  TENANT_RUNTIME_SEQUENCES,
  TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS,
} from "../src/runtime-grant-contract.js";
import { TENANT_CANONICAL_TABLES } from "../src/tenant-maintenance-policy.js";
import {
  buildTenantSecurityTarget,
  TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT,
} from "../src/tenant-security-target.js";

const source = readFileSync(new URL("../src/provisioner.ts", import.meta.url), "utf8");
const reconcileSource = readFileSync(new URL("../scripts/reconcile-runtime-grants.ts", import.meta.url), "utf8");

describe("tenant runtime grant contract", () => {
  it("allows only the shared-session binding column, not blanket session updates", () => {
    const migration = readFileSync(new URL('../scripts/migrate-control.ts', import.meta.url), 'utf8');
    expect(migration).toMatch(/GRANT UPDATE\([^']*gestionchurch_source_session_id\) ON TABLE auth_sessions TO %I/u);
    expect(migration).not.toMatch(/GRANT UPDATE ON TABLE auth_sessions/u);
  });
  it.each(["departments", "offices", "report_versions"])(
    "allows the API runtime to mutate %s through the authorized store",
    (table) => {
      expect(TENANT_RUNTIME_MUTABLE_TABLES).toContain(table);
    },
  );

  it.each(["departments", "offices", "report_versions"])(
    "does not accidentally downgrade %s to the read-only table set",
    (table) => {
      expect(TENANT_RUNTIME_READ_ONLY_TABLES).not.toContain(table);
    },
  );

  it("limits tenant settings writes to the six fields used by the settings store", () => {
    expect(TENANT_RUNTIME_READ_ONLY_TABLES).toContain("tenant_settings");
    expect(TENANT_RUNTIME_MUTABLE_TABLES).not.toContain("tenant_settings");
    expect(TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS).toEqual([
      "display_name", "timezone", "locale", "jurisdiction", "version", "updated_at",
    ]);
  });

  it("exposes the system-role assignment matrix as read-only policy data", () => {
    expect(TENANT_RUNTIME_READ_ONLY_TABLES).toContain("system_role_assignment_matrix");
    expect(TENANT_RUNTIME_MUTABLE_TABLES).not.toContain("system_role_assignment_matrix");
    expect(TENANT_RUNTIME_APPEND_ONLY_TABLES).not.toContain("system_role_assignment_matrix");
  });

  it("keeps seed manifests private and makes function reconciliation convergent", () => {
    expect([
      ...TENANT_RUNTIME_READ_ONLY_TABLES,
      ...TENANT_RUNTIME_MUTABLE_TABLES,
      ...TENANT_RUNTIME_APPEND_ONLY_TABLES,
    ]).not.toContain("seed_manifests");
    expect(TENANT_RUNTIME_SEQUENCES).toHaveLength(2);
    expect(source).toContain("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public");
    expect(source).toContain("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC");
    expect(source).toContain("ON TABLE public.%I");
    expect(source).toContain("ON FUNCTION public.");
  });

  it("reconciles only maintenance-eligible, identity-verified deterministic local tenants", () => {
    expect(reconcileSource).toContain("lockTenantMaintenanceRoute(controlClient, tenantId)");
    expect(reconcileSource).toContain("reconcileTenantOwnershipAndRuntimeGrants(");
    expect(reconcileSource).toContain("assertTenantMaintenanceDatabase(tenantClient, tenant)");
    expect(reconcileSource).toContain("assertCanonicalTenantTableInventory(tenantClient, tenant.id)");
    expect(reconcileSource).toContain('controlClient.query("BEGIN")');
    expect(reconcileSource).toContain('controlClient.query("COMMIT")');
    expect(reconcileSource).toContain("tenant.runtimeSecretReference !== `tenant-db/${tenantId}/runtime/v${tenant.credentialVersion}`");
    expect(reconcileSource).toContain("tenant.databaseHost !== administrator.hostname");
    expect(reconcileSource).toContain("tenant.databasePort !== WORKSPACE_PORT");
    expect(reconcileSource).toContain("assertRouteUnchanged(tenant, confirmedRoute)");
    expect(reconcileSource).not.toContain("tenant.status !== \"active\"");
    expect(reconcileSource).not.toMatch(/new Pool\(\{\s*connectionString:/u);
  });

  it("uses one exact database and schema boundary for reconciliation and verification", () => {
    expect(TENANT_RUNTIME_GRANT_CONTRACT.database).toEqual({ runtime: ["CONNECT"], public: [] });
    expect(TENANT_RUNTIME_GRANT_CONTRACT.schema).toEqual({ runtime: ["USAGE"], public: [] });
    expect(source).toContain("REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC");
    expect(source).toContain("REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I");
    expect(source).toContain("REVOKE ALL PRIVILEGES ON SCHEMA public FROM %I");
    expect(source).toContain("ALTER ROLE %I RESET ALL");
    expect(source).toContain("normalizeOwnerRoleWithClient(client, ownerRole)");
    expect(source).toContain("VALID UNTIL %L PASSWORD NULL");
    expect(source).toContain("Tenant database does not satisfy the deterministic owner boundary");
    expect(source).toContain("Tenant owner role failed exact non-login ownership attestation");
    expect(source).toContain("lockTenantReconciliationBoundary(client)");
    expect(source).toContain("normalizeRuntimeRoleWithClient(client, runtimeRole)");
    expect(source).toContain("LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1");
    expect(source).toContain("runtime role with unexpected memberships");
    expect(source).toContain("NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS");
    expect(source).toContain("target.rolvaliduntil IS NOT NULL");
    expect(source).toContain("ALTER SCHEMA public OWNER TO pg_database_owner");
    expect(source).toContain('publicSchema.rows[0]?.owner !== "pg_database_owner"');
    expect(source).toContain("FROM pg_catalog.pg_type type_record");
    expect(source).toContain('const objectKind = typeRecord.kind === "d" ? "DOMAIN" : "TYPE"');
    expect(source).toContain("ALTER ${objectKind} public.%I OWNER TO %I");
    expect(source).toContain("A deterministic tenant database failed ownership and safety attestation");
    expect(source).toContain("A preexisting tenant database failed tenant identity attestation");
  });

  it("uses the same source contracts for the approved security target and live reconciler", () => {
    const target = buildTenantSecurityTarget("50000000-0000-4000-8000-000000000001");
    expect(target.inventory.exactTables).toEqual(TENANT_CANONICAL_TABLES);
    expect(Object.keys(TENANT_RUNTIME_GRANT_CONTRACT.tables).sort()).toEqual(
      TENANT_CANONICAL_TABLES.filter((table) => ![
        "schema_migrations",
        "seed_manifests",
        "initial_admin_activation_capability",
        "tenant_invitation_acceptance_fences",
      ].includes(table)).sort(),
    );
    expect(target.defaultPrivileges[0]).toMatchObject(TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT);
    expect(source).toContain("TENANT_OWNER_ROLE_SECURITY_CONTRACT");
    expect(source).toContain("TENANT_RUNTIME_ROLE_SECURITY_CONTRACT");
    expect(source).toContain("TENANT_OWNER_DEFAULT_PRIVILEGE_CONTRACT");
    expect(source).toContain("ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC");
  });

  it("attests the complete preexisting database identity and provisions grants atomically", () => {
    for (const evidence of [
      "database.datconnlimit AS connection_limit",
      "pg_catalog.pg_encoding_to_char(database.encoding) AS encoding",
      "database.datcollate IS NOT DISTINCT FROM template.datcollate",
      "database.datctype IS NOT DISTINCT FROM template.datctype",
      "database.datlocprovider IS NOT DISTINCT FROM template.datlocprovider",
      "database.datlocale IS NOT DISTINCT FROM template.datlocale",
      "database.daticurules IS NOT DISTINCT FROM template.daticurules",
      "database.datcollversion IS NOT DISTINCT FROM template.datcollversion",
      "database.dathasloginevt AS has_login_event",
      "tablespace.spcname AS tablespace",
      "TABLESPACE pg_default CONNECTION LIMIT -1",
    ]) expect(source).toContain(evidence);
    const seed = source.indexOf("await reconcileTenantCatalog(tenantPool");
    const atomicReconciliation = source.indexOf(
      "await reconcileTenantOwnershipAndRuntimeGrants(",
      seed,
    );
    const canonicalInventory = source.indexOf(
      "await assertCanonicalTenantTableInventory(tenantClient, request.tenantId)",
      atomicReconciliation,
    );
    expect(seed).toBeGreaterThan(0);
    expect(atomicReconciliation).toBeGreaterThan(seed);
    expect(canonicalInventory).toBeGreaterThan(atomicReconciliation);
  });

  it("joins safe pg_roles attributes to a boolean-only pg_authid credential projection", () => {
    const attestation = source.slice(
      source.indexOf("async function readTenantRoleAttestation"),
      source.indexOf("function tenantRoleMatchesExactContract"),
    );
    expect(attestation).toContain("FROM pg_catalog.pg_roles target");
    expect(attestation).toContain("JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid");
    expect(attestation).toContain("target.rolconfig");
    expect(attestation).not.toContain("credential.rolconfig");
    expect(attestation).toContain("credential.rolpassword IS NOT NULL AS has_password");
    expect(attestation.replace("credential.rolpassword IS NOT NULL AS has_password", ""))
      .not.toContain("rolpassword");
    expect(attestation).not.toMatch(/md5|sha(?:1|2|256|384|512)?|password_(?:verifier_)?digest/iu);
  });
});
