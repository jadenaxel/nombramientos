import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { applyRuntimeGrants } from "../src/provisioner.js";
import {
  TENANT_RUNTIME_APPEND_ONLY_TABLES,
  TENANT_RUNTIME_FUNCTIONS,
  TENANT_RUNTIME_MUTABLE_TABLES,
  TENANT_RUNTIME_PURE_FUNCTIONS,
  TENANT_RUNTIME_READ_ONLY_TABLES,
  TENANT_SECURITY_DEFINER_FUNCTIONS,
  TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS,
} from "../src/runtime-grant-contract.js";

const WORKSPACE_PORT = 55_432;
const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const DEMO_SUFFIX = DEMO_TENANT_ID.replaceAll("-", "");
const DEMO_DATABASE = `nom_t_${DEMO_SUFFIX}`;
const DEMO_OWNER_ROLE = `nom_o_${DEMO_SUFFIX}`;
const DEMO_RUNTIME_ROLE = `nom_r_${DEMO_SUFFIX}`;
const RECORDING_RUNTIME_ROLE = `nom_r_${"1".repeat(32)}`;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const readOnlyTables = TENANT_RUNTIME_READ_ONLY_TABLES.filter((table) => table !== "tenant_settings");
const mutableTables = TENANT_RUNTIME_MUTABLE_TABLES;
const appendOnlyTables = TENANT_RUNTIME_APPEND_ONLY_TABLES;
const tenantSettingsUpdateColumns = [...TENANT_SETTINGS_RUNTIME_UPDATE_COLUMNS].sort();
const securityDefinerFunctions = [...TENANT_SECURITY_DEFINER_FUNCTIONS].sort();
const runtimeFunctions = [...TENANT_RUNTIME_FUNCTIONS].sort();
const runtimePureFunctions: string[] = [...TENANT_RUNTIME_PURE_FUNCTIONS].sort();

describe("tenant PostgreSQL privilege regression contract", () => {
  it("reconciles the exact runtime table, column, sequence, and function allowlists", async () => {
    const statements = await recordRuntimeGrantStatements(RECORDING_RUNTIME_ROLE);

    expect(tablePrivileges(statements, RECORDING_RUNTIME_ROLE)).toEqual(expectedTablePrivileges());
    expect(columnPrivileges(statements, RECORDING_RUNTIME_ROLE)).toEqual({
      tenant_settings: Object.fromEntries(tenantSettingsUpdateColumns.map((column) => [column, ["UPDATE"]])),
    });
    expect(tablePrivileges(statements, RECORDING_RUNTIME_ROLE)).not.toHaveProperty("schema_migrations");
    expect(tablePrivileges(statements, RECORDING_RUNTIME_ROLE)).not.toHaveProperty("seed_manifests");

    const grantedTablePrivileges = Object.values(tablePrivileges(statements, RECORDING_RUNTIME_ROLE)).flat();
    expect(grantedTablePrivileges).not.toContain("DELETE");
    expect(grantedTablePrivileges).not.toContain("TRUNCATE");
    expect(grantedTablePrivileges).not.toContain("TRIGGER");
    expect(grantedTablePrivileges).not.toContain("REFERENCES");

    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${RECORDING_RUNTIME_ROLE}`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ${RECORDING_RUNTIME_ROLE}`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM ${RECORDING_RUNTIME_ROLE}`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON DATABASE ${RECORDING_RUNTIME_ROLE.replace(/^nom_r_/u, "nom_t_")} FROM PUBLIC`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON DATABASE ${RECORDING_RUNTIME_ROLE.replace(/^nom_r_/u, "nom_t_")} FROM ${RECORDING_RUNTIME_ROLE}`,
    );
    expect(statements).toContain(
      `GRANT CONNECT ON DATABASE ${RECORDING_RUNTIME_ROLE.replace(/^nom_r_/u, "nom_t_")} TO ${RECORDING_RUNTIME_ROLE}`,
    );
    expect(statements).toContain("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC");
    expect(statements).toContain(`REVOKE ALL PRIVILEGES ON SCHEMA public FROM ${RECORDING_RUNTIME_ROLE}`);
    expect(statements).toContain(`GRANT USAGE ON SCHEMA public TO ${RECORDING_RUNTIME_ROLE}`);
    expect(statements).toContain("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    expect(statements).toContain("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC");
    expect(statements).toContain("REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC");
    expect(sequencePrivileges(statements, RECORDING_RUNTIME_ROLE)).toEqual({
      audit_events_sequence_seq: ["SELECT", "USAGE"],
      outbox_events_sequence_seq: ["SELECT", "USAGE"],
    });
    expect(functionPrivileges(statements, RECORDING_RUNTIME_ROLE)).toEqual([...runtimeFunctions].sort());
    expect(TENANT_RUNTIME_PURE_FUNCTIONS).toEqual(["is_valid_tally_decision_rule(jsonb)"]);
    expect(securityDefinerFunctions).not.toContain("is_valid_tally_decision_rule(jsonb)");
    const roleNormalization = statements.indexOf(
      `ALTER ROLE ${RECORDING_RUNTIME_ROLE} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL infinity`,
    );
    const firstAclMutation = statements.findIndex((statement) => statement.startsWith("REVOKE "));
    expect(roleNormalization).toBeGreaterThanOrEqual(0);
    expect(firstAclMutation).toBeGreaterThan(roleNormalization);
  });

  it("revokes PUBLIC from every SECURITY DEFINER function", () => {
    const migration = readFileSync(
      path.join(packageRoot, "migrations", "tenant", "027_security_definer_boundaries.sql"),
      "utf8",
    ) + readFileSync(
      path.join(packageRoot, "migrations", "tenant", "034_invitation_role_delegation.sql"),
      "utf8",
    ) + readFileSync(
      path.join(packageRoot, "migrations", "tenant", "035_system_role_assignment_matrix.sql"),
      "utf8",
    ) + readFileSync(
      path.join(packageRoot, "migrations", "tenant", "036_transactional_invitation_grantor_lock.sql"),
      "utf8",
    );
    const publicRevocations = [...migration.matchAll(
      /REVOKE\s+ALL(?:\s+PRIVILEGES)?\s+ON\s+FUNCTION\s+public\.([a-z_][a-z0-9_]*\s*\([^;]*?\))\s+FROM\s+PUBLIC\s*;/giu,
    )].map((match) => normalizeSignature(match[1] ?? "")).sort();

    expect([...new Set(publicRevocations)].sort()).toEqual(expect.arrayContaining(
      [...securityDefinerFunctions].sort(),
    ));
    expect(migration).toContain("DROP FUNCTION public.apply_tenant_invitation_roles(uuid,uuid,text[],uuid)");
    expect(migration).toContain("DROP FUNCTION public.cleanup_tenant_invitation_roles(uuid)");
    expect(migration).toMatch(
      /ALTER\s+DEFAULT\s+PRIVILEGES\s+IN\s+SCHEMA\s+public\s+REVOKE\s+EXECUTE\s+ON\s+FUNCTIONS\s+FROM\s+PUBLIC/iu,
    );
  });

  it("removes direct tenant privileges held by a foreign grantee", async () => {
    const foreignRole = "unexpected_reader";
    const databaseName = RECORDING_RUNTIME_ROLE.replace(/^nom_r_/u, "nom_t_");
    const statements = await recordRuntimeGrantStatements(RECORDING_RUNTIME_ROLE, [
      { object_kind: "database", object_name: databaseName, identity_arguments: null, role_name: foreignRole },
      { object_kind: "schema", object_name: "public", identity_arguments: null, role_name: foreignRole },
      { object_kind: "table", object_name: "members", identity_arguments: null, role_name: foreignRole },
      {
        object_kind: "sequence",
        object_name: "audit_events_sequence_seq",
        identity_arguments: null,
        role_name: foreignRole,
      },
      {
        object_kind: "function",
        object_name: "cleanup_tenant_invitation_roles",
        identity_arguments: "uuid",
        role_name: foreignRole,
      },
    ]);
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON DATABASE ${databaseName} FROM ${foreignRole} CASCADE`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON SCHEMA public FROM ${foreignRole} CASCADE`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON TABLE public.members FROM ${foreignRole} CASCADE`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON SEQUENCE public.audit_events_sequence_seq FROM ${foreignRole} CASCADE`,
    );
    expect(statements).toContain(
      `REVOKE ALL PRIVILEGES ON FUNCTION public.cleanup_tenant_invitation_roles(uuid) FROM ${foreignRole} CASCADE`,
    );
    expect(statements.some((statement) => statement.includes(`ON ALL TABLES`) && statement.endsWith(`FROM ${foreignRole} CASCADE`)))
      .toBe(false);
  });

  it("explicitly revokes PUBLIC, runtime and foreign column ACL drift before rebuilding the allowlist", async () => {
    const foreignRole = "unexpected_reader";
    const statements = await recordRuntimeGrantStatements(RECORDING_RUNTIME_ROLE, [], [
      { table_name: "members", column_name: "email", privilege_type: "SELECT", grantee: "PUBLIC" },
      { table_name: "members", column_name: "email", privilege_type: "UPDATE", grantee: RECORDING_RUNTIME_ROLE },
      { table_name: "members", column_name: "email", privilege_type: "REFERENCES", grantee: foreignRole },
    ]);
    expect(statements).toContain("REVOKE SELECT (email) ON TABLE public.members FROM PUBLIC CASCADE");
    expect(statements).toContain(
      `REVOKE UPDATE (email) ON TABLE public.members FROM ${RECORDING_RUNTIME_ROLE} CASCADE`,
    );
    expect(statements).toContain(
      `REVOKE REFERENCES (email) ON TABLE public.members FROM ${foreignRole} CASCADE`,
    );
    expect(columnPrivileges(statements, RECORDING_RUNTIME_ROLE)).toEqual({
      tenant_settings: Object.fromEntries(tenantSettingsUpdateColumns.map((column) => [column, ["UPDATE"]])),
    });
  });
});

const liveRequested = process.env["NOMBRAMIENTOS_PRIVILEGE_LIVE"] === "true";
const liveAdminUrl = liveRequested ? discoverLiveAdminUrl() : undefined;
const liveReady = liveAdminUrl ? await canReachDemo(liveAdminUrl) : false;
const live = liveRequested && liveReady ? describe.sequential : describe.skip;

live("tenant PostgreSQL privilege catalog on the local Demo fixture", () => {
  it("matches the allowlists and keeps every tenant object under a NOLOGIN NOSUPERUSER owner", async () => {
    const pool = new Pool({
      connectionString: withDatabase(liveAdminUrl!, DEMO_DATABASE),
      connectionTimeoutMillis: 2_000,
      max: 1,
    });
    const client = await pool.connect();
    try {
      await client.query("BEGIN TRANSACTION READ ONLY");

      const tableAcl = await client.query<{ table_name: string; privilege_type: string }>(
        `SELECT relation.relname AS table_name,privilege.privilege_type
           FROM pg_class relation
           JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
           CROSS JOIN LATERAL aclexplode(
             COALESCE(relation.relacl,acldefault('r',relation.relowner))
           ) privilege
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p')
            AND privilege.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
          ORDER BY relation.relname,privilege.privilege_type`,
        [DEMO_RUNTIME_ROLE],
      );
      expect(privilegeRows(tableAcl.rows, "table_name")).toEqual(expectedTablePrivileges());

      const columnAcl = await client.query<{
        table_name: string;
        column_name: string;
        privilege_type: string;
      }>(
        `SELECT relation.relname AS table_name,column_record.attname AS column_name,
                privilege.privilege_type
           FROM pg_attribute column_record
           JOIN pg_class relation ON relation.oid=column_record.attrelid
           JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
           CROSS JOIN LATERAL aclexplode(column_record.attacl) privilege
          WHERE namespace.nspname='public'
            AND relation.relkind IN ('r','p')
            AND column_record.attnum>0
            AND NOT column_record.attisdropped
            AND column_record.attacl IS NOT NULL
            AND privilege.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
          ORDER BY relation.relname,column_record.attname,privilege.privilege_type`,
        [DEMO_RUNTIME_ROLE],
      );
      expect(nestedColumnPrivilegeRows(columnAcl.rows)).toEqual({
        tenant_settings: Object.fromEntries(tenantSettingsUpdateColumns.map((column) => [column, ["UPDATE"]])),
      });

      const routines = await client.query<{
        signature: string;
        security_definer: boolean;
        public_execute: boolean;
        runtime_execute: boolean;
        runtime_direct_execute: boolean;
      }>(
        `SELECT format('%I(%s)',routine.proname,replace(oidvectortypes(routine.proargtypes),', ',',')) AS signature,
                routine.prosecdef AS security_definer,
                COALESCE(bool_or(
                  privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
                ),false) AS public_execute,
                has_function_privilege($1,routine.oid,'EXECUTE') AS runtime_execute,
                COALESCE(bool_or(
                  privilege.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
                  AND privilege.privilege_type='EXECUTE'
                ),false) AS runtime_direct_execute
           FROM pg_proc routine
           JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
           LEFT JOIN LATERAL aclexplode(
             COALESCE(routine.proacl,acldefault('f',routine.proowner))
           ) privilege ON true
          WHERE namespace.nspname='public' AND routine.prokind='f'
          GROUP BY routine.oid,routine.proname,routine.proargtypes,routine.prosecdef
          ORDER BY signature`,
        [DEMO_RUNTIME_ROLE],
      );
      expect(routines.rows.filter(({ security_definer: enabled }) => enabled).map(({ signature }) => signature))
        .toEqual(securityDefinerFunctions);
      expect(routines.rows.filter(({ public_execute: allowed }) => allowed)).toEqual([]);
      expect(routines.rows.filter(({ runtime_execute: allowed }) => allowed).map(({ signature }) => signature))
        .toEqual(runtimeFunctions);
      expect(routines.rows.filter(({ runtime_direct_execute: allowed }) => allowed).map(({ signature }) => signature))
        .toEqual(runtimeFunctions);
      expect(
        routines.rows
          .filter(({ signature }) => runtimePureFunctions.includes(signature))
          .map(({ signature, security_definer, public_execute, runtime_execute, runtime_direct_execute }) => ({
            signature,
            securityDefiner: security_definer,
            publicExecute: public_execute,
            runtimeExecute: runtime_execute,
            runtimeDirectExecute: runtime_direct_execute,
          })),
      ).toEqual(runtimePureFunctions.map((signature) => ({
        signature,
        securityDefiner: false,
        publicExecute: false,
        runtimeExecute: true,
        runtimeDirectExecute: true,
      })));

      const owner = await client.query<{
        database_name: string;
        owner_role: string;
        can_login: boolean;
        is_superuser: boolean;
      }>(
        `SELECT database.datname AS database_name,owner.rolname AS owner_role,
                owner.rolcanlogin AS can_login,owner.rolsuper AS is_superuser
           FROM pg_database database
           JOIN pg_roles owner ON owner.oid=database.datdba
          WHERE database.datname=current_database()`,
      );
      expect(owner.rows).toEqual([{
        database_name: DEMO_DATABASE,
        owner_role: DEMO_OWNER_ROLE,
        can_login: false,
        is_superuser: false,
      }]);

      const unexpectedOwners = await client.query<{ objects: number }>(
        `SELECT count(*)::int AS objects
           FROM (
             SELECT relation.oid
               FROM pg_class relation
               JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
              WHERE namespace.nspname='public'
                AND relation.relkind IN ('r','p','S','v','m','f')
                AND relation.relowner<>(SELECT oid FROM pg_roles WHERE rolname=$1)
                AND NOT EXISTS (
                  SELECT 1 FROM pg_depend dependency
                   WHERE dependency.classid='pg_class'::regclass
                     AND dependency.objid=relation.oid
                     AND dependency.deptype='e'
                )
             UNION ALL
             SELECT routine.oid
               FROM pg_proc routine
               JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace
              WHERE namespace.nspname='public'
                AND routine.proowner<>(SELECT oid FROM pg_roles WHERE rolname=$1)
                AND NOT EXISTS (
                  SELECT 1 FROM pg_depend dependency
                   WHERE dependency.classid='pg_proc'::regclass
                     AND dependency.objid=routine.oid
                     AND dependency.deptype='e'
                )
           ) unexpected`,
        [DEMO_OWNER_ROLE],
      );
      expect(unexpectedOwners.rows[0]?.objects).toBe(0);

      await client.query("ROLLBACK");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
      await pool.end();
    }
  }, 15_000);
});

function expectedTablePrivileges(): Record<string, string[]> {
  return Object.fromEntries([
    ...appendOnlyTables.map((table) => [table, ["INSERT", "SELECT"]] as const),
    ...mutableTables.map((table) => [table, ["INSERT", "SELECT", "UPDATE"]] as const),
    ...readOnlyTables.map((table) => [table, ["SELECT"]] as const),
    ["tenant_settings", ["SELECT"]] as const,
  ].sort(([left], [right]) => left.localeCompare(right)));
}

async function recordRuntimeGrantStatements(
  runtimeRole: string,
  foreignGrants: readonly {
    readonly object_kind: "database" | "schema" | "table" | "sequence" | "function" | "procedure";
    readonly object_name: string;
    readonly identity_arguments: string | null;
    readonly role_name: string;
  }[] = [],
  columnGrants: readonly {
    readonly table_name: string;
    readonly column_name: string;
    readonly privilege_type: "SELECT" | "INSERT" | "UPDATE" | "REFERENCES";
    readonly grantee: string;
  }[] = [],
): Promise<readonly string[]> {
  const statements: string[] = [];
  let foreignGrantReads = 0;
  let columnGrantReads = 0;
  const client = {
    query: async (sql: string, values: readonly unknown[] = []) => {
      const normalized = sql.trim().replace(/\s+/gu, " ");
      if (normalized === "SELECT current_database() AS database_name") {
        return {
          rows: [{ database_name: runtimeRole.replace(/^nom_r_/u, "nom_t_") }],
          rowCount: 1,
        };
      }
      if (normalized.includes("JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid")) {
        return {
          rows: [{
            can_login: true,
            superuser: false,
            create_database: false,
            create_role: false,
            replication: false,
            bypass_rls: false,
            inherit: true,
            connection_limit: -1,
            has_password: true,
            has_expiration: false,
            configuration_count: 0,
            membership_count: 0,
          }],
          rowCount: 1,
        };
      }
      if (normalized.startsWith("SELECT DISTINCT explicit_grant.object_kind")) {
        const rows = foreignGrantReads === 0 ? [...foreignGrants] : [];
        foreignGrantReads += 1;
        return {
          rows,
          rowCount: rows.length,
        };
      }
      if (normalized.startsWith("SELECT relation.relname AS table_name,column_record.attname AS column_name")) {
        const rows = columnGrantReads === 0 ? [...columnGrants] : [];
        columnGrantReads += 1;
        return { rows, rowCount: rows.length };
      }
      if (/^\s*SELECT\s+format\(/iu.test(sql)) {
        return { rows: [{ sql: renderPostgresFormat(sql, values) }], rowCount: 1 };
      }
      if (normalized !== "BEGIN" && normalized !== "COMMIT") statements.push(normalized);
      return { rows: [], rowCount: 0 };
    },
    release: () => undefined,
  };
  const pool = { connect: async () => client } as unknown as Pool;
  await applyRuntimeGrants(pool, runtimeRole);
  return statements;
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

function tablePrivileges(statements: readonly string[], runtimeRole: string): Record<string, string[]> {
  const rows: Array<{ table_name: string; privilege_type: string }> = [];
  for (const statement of statements) {
    const match = statement.match(
      new RegExp(`^GRANT ([A-Z,]+) ON TABLE public\\.([a-z0-9_]+) TO ${runtimeRole}$`, "u"),
    );
    if (!match) continue;
    for (const privilege of (match[1] ?? "").split(",")) {
      rows.push({ table_name: match[2] ?? "", privilege_type: privilege });
    }
  }
  return privilegeRows(rows, "table_name");
}

function columnPrivileges(
  statements: readonly string[],
  runtimeRole: string,
): Record<string, Record<string, string[]>> {
  const rows: Array<{ table_name: string; column_name: string; privilege_type: string }> = [];
  for (const statement of statements) {
    const match = statement.match(
      new RegExp(`^GRANT ([A-Z]+)\\(([^)]+)\\) ON TABLE public\\.([a-z0-9_]+) TO ${runtimeRole}$`, "u"),
    );
    if (!match) continue;
    for (const column of (match[2] ?? "").split(",")) {
      rows.push({ table_name: match[3] ?? "", column_name: column, privilege_type: match[1] ?? "" });
    }
  }
  return nestedColumnPrivilegeRows(rows);
}

function sequencePrivileges(statements: readonly string[], runtimeRole: string): Record<string, string[]> {
  const rows: Array<{ sequence_name: string; privilege_type: string }> = [];
  for (const statement of statements) {
    const match = statement.match(
      new RegExp(`^GRANT ([A-Z,]+) ON SEQUENCE (.+) TO ${runtimeRole}$`, "u"),
    );
    if (!match) continue;
    const privileges = (match[1] ?? "").split(",");
    for (const sequence of (match[2] ?? "").split(",")) {
      for (const privilege of privileges) {
        rows.push({ sequence_name: sequence.replace(/^public\./u, ""), privilege_type: privilege });
      }
    }
  }
  return privilegeRows(rows, "sequence_name");
}

function functionPrivileges(statements: readonly string[], runtimeRole: string): string[] {
  return statements.flatMap((statement) => {
    const match = statement.match(
      new RegExp(`^GRANT EXECUTE ON FUNCTION public\\.(.+) TO ${runtimeRole}$`, "u"),
    );
    return match ? [normalizeSignature(match[1] ?? "")] : [];
  }).sort();
}

function privilegeRows<Key extends string>(
  rows: readonly (Record<Key, string> & { privilege_type: string })[],
  key: Key,
): Record<string, string[]> {
  const privileges: Record<string, string[]> = {};
  for (const row of rows) {
    const name = row[key];
    (privileges[name] ??= []).push(row.privilege_type);
  }
  return Object.fromEntries(
    Object.entries(privileges)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([name, values]) => [name, [...new Set(values)].sort()]),
  );
}

function nestedColumnPrivilegeRows(rows: readonly {
  table_name: string;
  column_name: string;
  privilege_type: string;
}[]): Record<string, Record<string, string[]>> {
  const result: Record<string, Record<string, string[]>> = {};
  for (const row of rows) {
    const table = result[row.table_name] ??= {};
    (table[row.column_name] ??= []).push(row.privilege_type);
  }
  return Object.fromEntries(
    Object.entries(result)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([table, columns]) => [table, Object.fromEntries(
        Object.entries(columns)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([column, values]) => [column, [...new Set(values)].sort()]),
      )]),
  );
}

function normalizeSignature(signature: string): string {
  return signature.replace(/\s+/gu, "").toLowerCase();
}

function discoverLiveAdminUrl(): string | undefined {
  let candidate = process.env["TEST_DATABASE_ADMIN_URL"] ?? process.env["DATABASE_ADMIN_URL"];
  const installFile = path.join(packageRoot, ".local", "install.json");
  if (!candidate && existsSync(installFile)) {
    try {
      const installation = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: unknown };
      if (typeof installation.DATABASE_ADMIN_URL === "string") candidate = installation.DATABASE_ADMIN_URL;
    } catch {
      return undefined;
    }
  }
  if (!candidate) return undefined;
  try {
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachDemo(adminUrl: string): Promise<boolean> {
  const pool = new Pool({
    connectionString: withDatabase(adminUrl, DEMO_DATABASE),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
  try {
    const result = await pool.query<{ version: number; port: number; database_name: string }>(
      `SELECT current_setting('server_version_num')::int AS version,
              current_setting('port')::int AS port,current_database() AS database_name`,
    );
    return (result.rows[0]?.version ?? 0) >= 180_000
      && result.rows[0]?.port === WORKSPACE_PORT
      && result.rows[0]?.database_name === DEMO_DATABASE;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function withDatabase(adminUrl: string, database: string): string {
  if (!/^nom_t_[0-9a-f]{32}$/u.test(database)) throw new Error("Unsafe tenant fixture database name");
  const url = new URL(adminUrl);
  url.pathname = `/${database}`;
  return url.toString();
}
