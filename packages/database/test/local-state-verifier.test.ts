import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
  assertLocalStateAdminUrl,
  evaluateDemoFixtureCounts,
  evaluateMigrationLedger,
  evaluateOwnershipSnapshot,
  evaluateOzamaOperationalState,
  evaluateRuntimeGrantSnapshot,
  evaluateWorkerBacklog,
  digestCatalogMetadataSnapshot,
  expectedMigrationCommentFingerprint,
  parseLocalStateVerificationArguments,
  serializeSanitizedLocalStateFailure,
  serializeSanitizedLocalStateReport,
  withReadOnlyTransaction,
  type LocalStateReport,
  type RuntimeGrantSnapshot,
} from "../src/local-state-verifier.js";
import { loadMigrationPlanEntries } from "../src/migrations.js";
import {
  TENANT_RUNTIME_GRANT_CONTRACT,
  TENANT_SECURITY_DEFINER_FUNCTIONS,
} from "../src/runtime-grant-contract.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifierSource = readFileSync(path.join(packageRoot, "src", "local-state-verifier.ts"), "utf8");

describe("sanitized local state verifier contract", () => {
  it("accepts only an explicit workspace loopback PostgreSQL endpoint", () => {
    expect(assertLocalStateAdminUrl(adminUrl()).port)
      .toBe("55432");
    expect(() => assertLocalStateAdminUrl(adminUrl({ protocol: "postgres:", hostname: "[::1]" })))
      .toThrow(/IPv4 loopback/u);
    expect(() => assertLocalStateAdminUrl(adminUrl({ username: "operator" })))
      .toThrow(/nom_admin/u);
    expect(() => assertLocalStateAdminUrl(adminUrl({ password: "" })))
      .toThrow(/credential/u);
    expect(() => assertLocalStateAdminUrl(adminUrl({ hostname: "example.test" })))
      .toThrow(/loopback/u);
    expect(() => assertLocalStateAdminUrl(adminUrl({ port: "5432" })))
      .toThrow(/55432/u);
    expect(() => assertLocalStateAdminUrl(adminUrl({ protocol: "https:" })))
      .toThrow(/PostgreSQL/u);
    expect(() => assertLocalStateAdminUrl(adminUrlWithSearch("host", "example.test")))
      .toThrow(/options/u);
    expect(() => assertLocalStateAdminUrl(adminUrlWithSearch("port", "5432")))
      .toThrow(/options/u);
    expect(() => assertLocalStateAdminUrl(`${adminUrl()}#sslkey`))
      .toThrow(/fragments/u);
  });

  it("requires every stored tenant route to use the runtime-compatible literal IPv4 host", () => {
    expect(verifierSource).toContain('Number(route.database_host !== "127.0.0.1")');
    expect(verifierSource).not.toContain("SAFE_LOOPBACK_HOSTS");
  });

  it("joins safe pg_roles attributes to fail-closed boolean-only pg_authid credentials", () => {
    const probes = [
      {
        source: verifierSource.slice(
          verifierSource.indexOf("async function readProtectedControlRoleMismatchCount"),
          verifierSource.indexOf("function evaluateControlRoutes"),
        ),
        roleJoin: "FROM pg_catalog.pg_roles role",
        credentialJoin: "JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid",
        safeAlias: "role",
      },
      {
        source: verifierSource.slice(
          verifierSource.indexOf("async function readOwnershipSnapshot"),
          verifierSource.indexOf("async function readRuntimeGrantSnapshot"),
        ),
        roleJoin: "LEFT JOIN pg_catalog.pg_roles target ON target.rolname=$1",
        credentialJoin: "LEFT JOIN pg_catalog.pg_authid credential ON credential.oid=target.oid",
        safeAlias: "target",
      },
      {
        source: verifierSource.slice(
          verifierSource.indexOf("async function readRuntimeGrantSnapshot"),
          verifierSource.indexOf("function flattenPrivilegeRecord"),
        ),
        roleJoin: "FROM pg_catalog.pg_roles role",
        credentialJoin: "JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid",
        safeAlias: "role",
      },
    ];
    for (const probe of probes) {
      expect(probe.source).toContain(probe.roleJoin);
      expect(probe.source).toContain(probe.credentialJoin);
      expect(probe.source).toContain(`${probe.safeAlias}.rolconfig`);
      expect(probe.source).not.toContain("credential.rolconfig");
      expect(probe.source).toContain("credential.rolpassword IS NOT NULL");
      expect(probe.source.replace(/credential\.rolpassword IS NOT NULL/gu, ""))
        .not.toContain("rolpassword");
      expect(probe.source).not.toMatch(/md5|sha(?:1|2|256|384|512)?|password_(?:verifier_)?digest/iu);
    }
  });

  it("defaults to the post-repair fixture and accepts only an explicit safe before/after mode", () => {
    expect(parseLocalStateVerificationArguments([])).toEqual({ demoFixtureExpectation: "after" });
    expect(parseLocalStateVerificationArguments(["--demo-fixture-state=before"]))
      .toEqual({ demoFixtureExpectation: "before" });
    expect(parseLocalStateVerificationArguments(["--demo-fixture-state=after"]))
      .toEqual({ demoFixtureExpectation: "after" });
    expect(() => parseLocalStateVerificationArguments(["--demo-fixture-state=auto"]))
      .toThrow(/Unsupported/u);
    expect(() => parseLocalStateVerificationArguments([
      "--demo-fixture-state=before", "--demo-fixture-state=after",
    ])).toThrow(/duplicate/u);
  });

  it("derives exact migration inventories from disk and fails a changed ledger checksum", async () => {
    const control = await loadMigrationPlanEntries(path.join(packageRoot, "migrations", "control"));
    const tenant = await loadMigrationPlanEntries(path.join(packageRoot, "migrations", "tenant"));
    expect(control).toHaveLength(32);
    expect(control.at(-1)?.name).toBe("032_gestionchurch_explicit_operational_roles.sql");
    expect(tenant).toHaveLength(41);
    expect(tenant.at(-1)?.name).toBe("039_device_bound_http_sessions.sql");

    const green = evaluateMigrationLedger(tenant, tenant, 41, "039_device_bound_http_sessions.sql");
    expect(green).toMatchObject({
      pendingCount: 0,
      unexpectedCount: 0,
      checksumMismatchCount: 0,
      mismatchCount: 0,
    });
    expect(green.ledgerSha256).toMatch(/^[0-9a-f]{64}$/u);

    const drifted = tenant.map((entry, index) => index === 0
      ? { ...entry, checksum: "f".repeat(64) }
      : entry);
    expect(evaluateMigrationLedger(tenant, drifted, 41, "039_device_bound_http_sessions.sql"))
      .toMatchObject({ checksumMismatchCount: 1, mismatchCount: 1 });

    const unexpectedName = "999_runtime_password.sql";
    const unexpected = evaluateMigrationLedger(
      tenant,
      [...tenant, { name: unexpectedName, checksum: "e".repeat(64) }],
      41,
      "039_device_bound_http_sessions.sql",
    );
    expect(unexpected).toMatchObject({ unexpectedCount: 1, head: null });
    expect(JSON.stringify(unexpected)).not.toContain(unexpectedName);

    await expect(expectedMigrationCommentFingerprint(
      path.join(packageRoot, "migrations", "control"), control,
    )).resolves.toMatchObject({ count: 10, digest: expect.stringMatching(/^[0-9a-f]{64}$/u) });
    await expect(expectedMigrationCommentFingerprint(
      path.join(packageRoot, "migrations", "tenant"), tenant,
    )).resolves.toMatchObject({ count: 61, digest: expect.stringMatching(/^[0-9a-f]{64}$/u) });
  });

  it("detects ownership drift without exposing object or owner names", () => {
    expect(evaluateOwnershipSnapshot({
      roleExists: true,
      databaseOwned: true,
      schemaOwnedByDatabaseOwner: true,
      canLogin: false,
      superuser: false,
      createDatabase: false,
      createRole: false,
      replication: false,
      bypassRls: false,
      inherit: true,
      connectionLimit: -1,
      hasPassword: false,
      hasExpiration: false,
      configurationCount: 0,
      membershipCount: 0,
      relationMismatchCount: 0,
      routineMismatchCount: 0,
      typeMismatchCount: 0,
    })).toBe(0);
    expect(evaluateOwnershipSnapshot({
      roleExists: true,
      databaseOwned: false,
      schemaOwnedByDatabaseOwner: true,
      canLogin: true,
      superuser: false,
      createDatabase: false,
      createRole: false,
      replication: false,
      bypassRls: false,
      inherit: false,
      connectionLimit: 2,
      hasPassword: true,
      hasExpiration: true,
      configurationCount: 1,
      membershipCount: 0,
      relationMismatchCount: 2,
      routineMismatchCount: 1,
      typeMismatchCount: 1,
    })).toBe(11);
  });

  it("checks the exact shared runtime ACL contract and fails missing or extra grants", () => {
    const green = runtimeGrantSnapshot();
    expect(evaluateRuntimeGrantSnapshot(green)).toBe(0);
    expect(evaluateRuntimeGrantSnapshot({
      ...green,
      tablePrivileges: green.tablePrivileges.filter((entry) => entry !== "members:UPDATE"),
    })).toBe(1);
    expect(evaluateRuntimeGrantSnapshot({
      ...green,
      tablePrivileges: [...green.tablePrivileges, "members:DELETE"],
      role: { ...green.role, superuser: true },
    })).toBe(2);
    expect(evaluateRuntimeGrantSnapshot({ ...green, grantOptionCount: 1 })).toBe(1);
    expect(evaluateRuntimeGrantSnapshot({ ...green, publicObjectPrivilegeCount: 1 })).toBe(1);
    expect(evaluateRuntimeGrantSnapshot({ ...green, foreignGranteePrivilegeCount: 1 })).toBe(1);
    expect(evaluateRuntimeGrantSnapshot({
      ...green,
      role: { ...green.role, hasExpiration: true, configurationCount: 1, membershipCount: 1 },
    })).toBe(3);
    expect(verifierSource).toContain("FROM pg_catalog.pg_type type_record");
    expect(verifierSource).toContain("namespace.nspname NOT IN ('pg_catalog','information_schema')");
  });

  it("counts PUBLIC EXECUTE on every ordinary routine, not only SECURITY DEFINER routines", () => {
    expect(verifierSource).toMatch(
      /const functionRows[\s\S]*?acl\.grantee=0 AS is_public[\s\S]*?WHERE namespace\.nspname='public'[\s\S]*?functionRows\.rows\.filter\(\(\{ is_public \}\) => is_public\)\.length/u,
    );
    const functionInventory = verifierSource.slice(
      verifierSource.indexOf("const functionRows"),
      verifierSource.indexOf("const securityDefinerRows"),
    );
    expect(functionInventory).not.toContain("routine.prosecdef");
    expect(evaluateRuntimeGrantSnapshot({ ...runtimeGrantSnapshot(), publicObjectPrivilegeCount: 1 })).toBe(1);
  });

  it("digests and detects drift in comments, labels, event triggers, publications and subscriptions", () => {
    const snapshot = {
      comments: [{ kind: "TABLE", identity: "public.members", description_sha256: "a".repeat(64) }],
      securityLabels: [{ identity: "public.members", provider: "provider", label_sha256: "b".repeat(64) }],
      eventTriggers: [{ name: "ddl_guard", event: "ddl_command_start" }],
      publications: [{ name: "tenant_publication", settings: { insert: true } }],
      subscriptions: [{ name: "tenant_subscription", conninfo_sha256: "c".repeat(64) }],
    } as const;
    const digest = digestCatalogMetadataSnapshot(snapshot);
    expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    for (const key of ["comments", "securityLabels", "eventTriggers", "publications", "subscriptions"] as const) {
      expect(digestCatalogMetadataSnapshot({ ...snapshot, [key]: [] })).not.toBe(digest);
    }
    expect(verifierSource).toContain("FROM pg_catalog.pg_description description");
    expect(verifierSource).toContain("FROM pg_catalog.pg_seclabel label");
    expect(verifierSource).toContain("FROM pg_catalog.pg_event_trigger event_trigger");
    expect(verifierSource).toContain("FROM pg_catalog.pg_publication publication");
    expect(verifierSource).toContain("FROM pg_catalog.pg_subscription subscription");
    expect(verifierSource).toContain("AS conninfo_sha256");
    expect(verifierSource).not.toMatch(/subscription\.subconninfo\s+AS/iu);
  });

  it("keeps every catalog metadata probe inside the SELECT-only transaction guard", () => {
    const catalogQueries = [...verifierSource.matchAll(
      /queryCatalogMetadataStage(?:<[^>]+>)?\(\s*client,\s*"[^"]+",\s*`([^`]*)`/gu,
    )].map((match) => match[1]?.trim() ?? "");
    expect(catalogQueries).toHaveLength(10);
    for (const query of catalogQueries) {
      expect(query).toMatch(/^SELECT\b/iu);
      expect(query).not.toContain(";");
    }
  });

  it("enforces explicit Demo fixture states and the empty 50-table pre-activation contract", () => {
    expect(evaluateDemoFixtureCounts(180, 150, "after")).toBe(0);
    expect(evaluateDemoFixtureCounts(181, 151, "before")).toBe(0);
    expect(evaluateDemoFixtureCounts(181, 151, "after")).toBe(2);
    expect(evaluateOzamaOperationalState(50, 0)).toBe(0);
    expect(evaluateOzamaOperationalState(49, 1)).toBe(2);
  });

  it("treats only terminal provisioning and export states as a quiescent worker backlog", () => {
    expect(evaluateWorkerBacklog(0, 0)).toEqual({
      provisioningJobCount: 0,
      tenantExportJobCount: 0,
      totalCount: 0,
      mismatchCount: 0,
    });
    expect(evaluateWorkerBacklog(2, 3)).toEqual({
      provisioningJobCount: 2,
      tenantExportJobCount: 3,
      totalCount: 5,
      mismatchCount: 2,
    });
    expect(() => evaluateWorkerBacklog(-1, 0)).toThrow();
  });

  it("opens REPEATABLE READ READ ONLY and blocks mutations before they reach PostgreSQL", async () => {
    const statements: string[] = [];
    const query = vi.fn(async (sql: string) => {
      statements.push(sql);
      return { rows: [], rowCount: 0 };
    });
    const release = vi.fn();
    const pool = {
      connect: async () => ({ query, release }),
    } as unknown as Pick<Pool, "connect">;

    await withReadOnlyTransaction(pool, async (client) => {
      await client.query("SELECT 1");
      await client.query("SELECT 'CREATE'::text AS privilege_type");
    });
    expect(statements).toEqual([
      "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      "SELECT 1",
      "SELECT 'CREATE'::text AS privilege_type",
      "COMMIT",
    ]);
    expect(release).toHaveBeenCalledOnce();

    statements.length = 0;
    await expect(withReadOnlyTransaction(pool, async (client) => {
      await client.query("UPDATE members SET available=false");
    })).rejects.toThrow(/non-read-only|mutating/u);
    expect(statements).toEqual([
      "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      "ROLLBACK",
    ]);
  });

  it("emits one safe failure shape and refuses URLs, roles, secrets, tokens, and PII", () => {
    const failure = serializeSanitizedLocalStateFailure(new Date("2026-09-12T00:00:00.000Z"));
    expect(JSON.parse(failure)).toEqual({
      schemaVersion: 2,
      checkedAt: "2026-09-12T00:00:00.000Z",
      mode: "read-only",
      pass: false,
      verificationIncomplete: true,
      errorCode: "LOCAL_STATE_VERIFICATION_FAILED",
    });
    expect(failure).not.toMatch(/postgres(?:ql)?:\/\//iu);
    expect(JSON.parse(serializeSanitizedLocalStateFailure(
      new Date("2026-09-12T00:00:00.000Z"),
      "catalog-subscriptions",
      "42501",
    ))).toEqual({
      schemaVersion: 2,
      checkedAt: "2026-09-12T00:00:00.000Z",
      mode: "read-only",
      pass: false,
      verificationIncomplete: true,
      errorCode: "LOCAL_STATE_VERIFICATION_FAILED",
      stage: "catalog-subscriptions",
      sqlState: "42501",
    });
    expect(JSON.parse(serializeSanitizedLocalStateReport(safeReport()))).toMatchObject({
      mode: "read-only",
      pass: true,
      demoFixtureExpectation: "after",
    });

    const baseCurrentHeadReport = safeReport();
    const currentHeadReport: LocalStateReport = {
      ...baseCurrentHeadReport,
      control: {
        ...baseCurrentHeadReport.control,
        migrations: {
          ...baseCurrentHeadReport.control.migrations,
          head: "023_atomic_authentication_context_lock.sql",
          expectedHead: "023_atomic_authentication_context_lock.sql",
        },
      },
    };
    expect(JSON.parse(serializeSanitizedLocalStateReport(currentHeadReport)).control.migrations)
      .toMatchObject({
        head: "023_atomic_authentication_context_lock.sql",
        expectedHead: "023_atomic_authentication_context_lock.sql",
      });
    expect(() => serializeSanitizedLocalStateReport({
      ...currentHeadReport,
      control: {
        ...currentHeadReport.control,
        migrations: { ...currentHeadReport.control.migrations, head: "999_password_dump.sql" },
      },
    })).toThrow(/forbidden/u);

    expect(() => serializeSanitizedLocalStateReport({
      ...safeReport(),
      connectionString: adminUrl(),
    } as unknown as LocalStateReport)).toThrow(/forbidden/u);
    expect(() => serializeSanitizedLocalStateReport({
      ...safeReport(),
      ownerRole: `nom_o_${"a".repeat(32)}`,
    } as unknown as LocalStateReport)).toThrow(/forbidden/u);
  });

  it("wires a single-output fail-closed package command", () => {
    const packageJson = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    expect(packageJson.scripts?.["db:verify:local-state"])
      .toBe("node dist/scripts/verify-local-state.js");
    const script = readFileSync(path.join(packageRoot, "scripts", "verify-local-state.ts"), "utf8");
    expect(script.match(/process\.stdout\.write/gu)).toHaveLength(1);
    expect(script).toContain("serializeSanitizedLocalStateFailure");
    expect(script).toContain("if (!passed) process.exitCode = 1");
    expect(script).not.toMatch(/console\.(?:log|error|warn)/u);
    expect(script).not.toContain("connectionString");
    expect(script).not.toContain("withoutDatabase");
    expect(script).toContain("ssl: false");
    const verifier = readFileSync(path.join(packageRoot, "src", "local-state-verifier.ts"), "utf8");
    expect(verifier).toContain("acldefault('s',relation.relowner)");
    expect(verifier).not.toContain("acldefault('S',relation.relowner)");
    expect(verifier).toContain("address.value <<= inet '127.0.0.0/8'");
    expect(verifier).toContain("address.value <<= inet '::1/128'");
    expect(verifier).toContain("address.value <<= inet '::ffff:127.0.0.0/104'");
    expect(verifier).not.toContain("inet_server_addr()::text AS server_address");
  });
});

function adminUrl(overrides: {
  readonly protocol?: "postgres:" | "postgresql:" | "https:";
  readonly hostname?: string;
  readonly port?: string;
  readonly username?: string;
  readonly password?: string;
} = {}): string {
  const protocol = overrides.protocol ?? "postgresql:";
  const hostname = overrides.hostname ?? "127.0.0.1";
  const port = overrides.port ?? "55432";
  const url = new URL(`${protocol}//${hostname}:${port}/postgres`);
  url.username = overrides.username ?? "nom_admin";
  url.password = overrides.password ?? "safe-test-password";
  return url.toString();
}

function adminUrlWithSearch(name: string, value: string): string {
  const url = new URL(adminUrl());
  url.searchParams.set(name, value);
  return url.toString();
}

function runtimeGrantSnapshot(): RuntimeGrantSnapshot {
  return {
    role: {
      exists: true,
      canLogin: true,
      superuser: false,
      createDatabase: false,
      createRole: false,
      replication: false,
      bypassRls: false,
      inherit: true,
      connectionLimit: -1,
      hasPassword: true,
      hasExpiration: false,
      configurationCount: 0,
      membershipCount: 0,
    },
    database: {
      runtimeConnect: true,
      runtimeCreate: false,
      runtimeTemporary: false,
      publicConnect: false,
      publicCreate: false,
      publicTemporary: false,
    },
    schema: {
      runtimeUsage: true,
      runtimeCreate: false,
      publicUsage: false,
      publicCreate: false,
    },
    tablePrivileges: Object.entries(TENANT_RUNTIME_GRANT_CONTRACT.tables).flatMap(
      ([table, privileges]) => privileges.map((privilege) => `${table}:${privilege}`),
    ),
    columnPrivileges: Object.entries(TENANT_RUNTIME_GRANT_CONTRACT.columns).flatMap(
      ([table, columns]) => Object.entries(columns).flatMap(
        ([column, privileges]) => privileges.map((privilege) => `${table}.${column}:${privilege}`),
      ),
    ),
    sequencePrivileges: Object.entries(TENANT_RUNTIME_GRANT_CONTRACT.sequences).flatMap(
      ([sequence, privileges]) => privileges.map((privilege) => `${sequence}:${privilege}`),
    ),
    functionPrivileges: TENANT_RUNTIME_GRANT_CONTRACT.functions.map(
      (signature) => `${signature}:EXECUTE`,
    ),
    grantOptionCount: 0,
    publicObjectPrivilegeCount: 0,
    foreignGranteePrivilegeCount: 0,
    securityDefinerFunctions: TENANT_SECURITY_DEFINER_FUNCTIONS.map((signature) => ({
      signature,
      publicExecute: false,
    })),
  };
}

function safeReport(): LocalStateReport {
  const migration = {
    expectedCount: 1,
    appliedCount: 1,
    pendingCount: 0,
    unexpectedCount: 0,
    checksumMismatchCount: 0,
    head: "001_safe.sql",
    expectedHead: "001_safe.sql",
    ledgerSha256: "a".repeat(64),
    mismatchCount: 0,
  };
  const tenant = {
    kind: "demo" as const,
    lifecycle: "active",
    setupState: "ready",
    maintenanceClass: "routable" as const,
    migrations: migration,
    tableInventoryMismatchCount: 0,
    schemaInventoryMismatchCount: 0,
    ownershipMismatchCount: 0,
    runtimeGrantMismatchCount: 0,
    catalogMetadata: safeCatalogMetadata(),
    institutionalCatalog: safeInstitutionalCatalog(),
    mismatchCount: 0,
  };
  return {
    schemaVersion: 2,
    checkedAt: "2026-09-12T00:00:00.000Z",
    mode: "read-only",
    demoFixtureExpectation: "after",
    pass: true,
    mismatchCount: 0,
    server: {
      postgresMajor: 18,
      port: 55_432,
      loopback: true,
      controlDatabaseMatch: true,
      transactionReadOnly: true,
      transactionIsolation: "repeatable read",
      administratorMatch: true,
      mismatchCount: 0,
    },
    control: {
      migrations: migration,
      tenantRouteCount: 2,
      routeMismatchCount: 0,
      ozamaIdentityOrAdminArtifactCount: 0,
      workerBacklog: {
        provisioningJobCount: 0,
        tenantExportJobCount: 0,
        totalCount: 0,
        mismatchCount: 0,
      },
      schemaInventoryMismatchCount: 0,
      roleMismatchCount: 0,
      catalogMetadata: safeCatalogMetadata(),
      mismatchCount: 0,
    },
    tenants: { demo: tenant, ozama: { ...tenant, kind: "real", maintenanceClass: "pending_activation" } },
  };
}

function safeCatalogMetadata() {
  return {
    catalogSha256: "b".repeat(64),
    commentCount: 0,
    sharedCommentCount: 0,
    securityLabelCount: 0,
    eventTriggerCount: 0,
    publicationCount: 0,
    subscriptionCount: 0,
    rewriteRuleCount: 0,
    mismatchCount: 0,
  };
}

function safeInstitutionalCatalog() {
  return {
    targetVersion: "2025.1.0",
    observedVersion: "2025.1.0",
    expectedDepartmentCount: 29,
    observedDepartmentCount: 29,
    missingDepartmentCount: 0,
    unexpectedDepartmentCount: 0,
    expectedOfficeCount: 67,
    observedOfficeCount: 67,
    missingOfficeCount: 0,
    unexpectedOfficeCount: 0,
    targetCatalogSha256: `sha256:${"c".repeat(64)}`,
    observedCatalogSha256: `sha256:${"c".repeat(64)}`,
    localExtensionCollisionCount: 0,
    invalidRowVersionCount: 0,
    blockingMismatchCount: 0,
    mismatchCount: 0,
  };
}
