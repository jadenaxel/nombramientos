import type { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { reconcileTenantObjectOwnership } from "../src/provisioner.js";

const SUFFIX = "2".repeat(32);
const OWNER_ROLE = `nom_o_${SUFFIX}`;
const DATABASE = `nom_t_${SUFFIX}`;

describe("tenant owner-role reconciliation", () => {
  it("removes a historical owner password under locks and commits only after exact post-attestation", async () => {
    const harness = ownershipHarness();

    await expect(reconcileTenantObjectOwnership(harness.pool, OWNER_ROLE)).resolves.toBeUndefined();

    const begin = harness.statements.indexOf("BEGIN");
    const migrationLock = harness.statements.findIndex((statement) => statement.includes("nombramientos-schema-migrations:"));
    const tableLock = harness.statements.indexOf("LOCK TABLE public.tenant_settings IN SHARE MODE NOWAIT");
    const normalize = harness.statements.indexOf(
      `ALTER ROLE ${OWNER_ROLE} NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL infinity PASSWORD NULL`,
    );
    const reset = harness.statements.indexOf(`ALTER ROLE ${OWNER_ROLE} RESET ALL`);
    const schemaOwnership = harness.statements.indexOf("ALTER SCHEMA public OWNER TO pg_database_owner");
    const commit = harness.statements.indexOf("COMMIT");

    expect(begin).toBe(0);
    expect(migrationLock).toBeGreaterThan(begin);
    expect(tableLock).toBeGreaterThan(migrationLock);
    expect(normalize).toBeGreaterThan(tableLock);
    expect(reset).toBeGreaterThan(normalize);
    expect(schemaOwnership).toBeGreaterThan(reset);
    expect(commit).toBeGreaterThan(schemaOwnership);
    expect(harness.roleReads()).toBe(2);
    expect(harness.statements.some((statement) => statement.startsWith("ALTER DATABASE"))).toBe(false);
  });

  it("rolls back before object ownership when the owner role still has a password after normalization", async () => {
    const harness = ownershipHarness({ postNormalizationHasPassword: true });

    await expect(reconcileTenantObjectOwnership(harness.pool, OWNER_ROLE))
      .rejects.toThrow(/failed exact non-login ownership attestation/u);

    expect(harness.statements).toContain("ROLLBACK");
    expect(harness.statements).not.toContain("COMMIT");
    expect(harness.statements).not.toContain("ALTER SCHEMA public OWNER TO pg_database_owner");
  });

  it("does not mutate a role when the connected database owner boundary is different", async () => {
    const harness = ownershipHarness({ databaseOwner: "nom_admin" });

    await expect(reconcileTenantObjectOwnership(harness.pool, OWNER_ROLE))
      .rejects.toThrow(/deterministic owner boundary/u);

    expect(harness.roleReads()).toBe(0);
    expect(harness.statements.some((statement) => statement.startsWith("ALTER ROLE"))).toBe(false);
    expect(harness.statements).toContain("ROLLBACK");
  });
});

function ownershipHarness(options: {
  readonly databaseOwner?: string;
  readonly postNormalizationHasPassword?: boolean;
} = {}): {
  readonly pool: Pool;
  readonly statements: string[];
  readonly roleReads: () => number;
} {
  const statements: string[] = [];
  let roleReads = 0;
  const client = {
    query: async (sql: string, values: readonly unknown[] = []) => {
      const normalized = sql.trim().replace(/\s+/gu, " ");
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(normalized)) {
        statements.push(normalized);
        return result([]);
      }
      if (normalized.includes("pg_advisory_xact_lock")) {
        statements.push(normalized);
        return result([{}]);
      }
      if (normalized.includes("'LOCK TABLE %s IN SHARE MODE NOWAIT'")) {
        return result([{ sql: "LOCK TABLE public.tenant_settings IN SHARE MODE NOWAIT" }]);
      }
      if (normalized === "LOCK TABLE public.tenant_settings IN SHARE MODE NOWAIT") {
        statements.push(normalized);
        return result([]);
      }
      if (normalized.includes("database.datname AS database_name,owner.rolname AS database_owner")) {
        return result([{
          database_name: DATABASE,
          database_owner: options.databaseOwner ?? OWNER_ROLE,
        }]);
      }
      if (normalized.includes("JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid")) {
        const postNormalization = roleReads > 0;
        roleReads += 1;
        return result([exactOwnerAttestation(
          postNormalization ? (options.postNormalizationHasPassword ?? false) : true,
        )]);
      }
      if (normalized.startsWith("SELECT format(")) {
        return result([{ sql: renderPostgresFormat(sql, values) }]);
      }
      if (normalized.startsWith("ALTER ROLE ") || normalized.startsWith("ALTER DEFAULT PRIVILEGES ")) {
        statements.push(normalized);
        return result([]);
      }
      if (normalized === "ALTER SCHEMA public OWNER TO pg_database_owner") {
        statements.push(normalized);
        return result([]);
      }
      if (normalized.includes("FROM pg_catalog.pg_namespace namespace")
        && normalized.includes("owner.rolname AS owner")) {
        return result([{ owner: "pg_database_owner" }]);
      }
      if (normalized.includes("SELECT relation.relkind AS kind,relation.relname AS name")
        || normalized.includes("SELECT routine.prokind AS kind,routine.proname AS name")
        || normalized.includes("SELECT type_record.typtype AS kind,type_record.typname AS name")) {
        return result([]);
      }
      if (normalized.startsWith("SELECT count(*)::int AS objects FROM (")) {
        return result([{ objects: 0 }]);
      }
      throw new Error(`Unexpected ownership reconciliation query: ${normalized}`);
    },
    release: () => undefined,
  };
  return {
    pool: { connect: async () => client } as unknown as Pool,
    statements,
    roleReads: () => roleReads,
  };
}

function exactOwnerAttestation(hasPassword: boolean): Record<string, boolean | number> {
  return {
    can_login: false,
    superuser: false,
    create_database: false,
    create_role: false,
    replication: false,
    bypass_rls: false,
    inherit: true,
    connection_limit: -1,
    has_password: hasPassword,
    has_expiration: false,
    configuration_count: 0,
    membership_count: 0,
  };
}

function renderPostgresFormat(sql: string, values: readonly unknown[]): string {
  const template = sql.match(/format\('((?:''|[^'])*)'/u)?.[1]?.replaceAll("''", "'");
  if (template === undefined) throw new Error(`Unsupported PostgreSQL format query: ${sql}`);
  let valueIndex = 0;
  const rendered = template.replace(/%[ILs]/gu, (placeholder) => {
    const value = values[valueIndex];
    valueIndex += 1;
    if (value === undefined || value === null) throw new Error(`Missing value for ${placeholder}`);
    return String(value);
  });
  if (valueIndex !== values.length) throw new Error(`Unused PostgreSQL format values for: ${sql}`);
  return rendered;
}

function result<T>(rows: readonly T[]): { readonly rows: readonly T[]; readonly rowCount: number } {
  return { rows, rowCount: rows.length };
}
