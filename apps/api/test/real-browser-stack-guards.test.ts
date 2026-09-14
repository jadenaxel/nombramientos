import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  PROTECTED_DATABASES,
  PROTECTED_TENANTS,
  REAL_BROWSER_STACK_CHECK_FLAG,
  REAL_BROWSER_STACK_FLAG,
  REAL_BROWSER_STACK_MARKER,
  RESERVED_APPLICATION_PORTS,
  assertCleanupObservation,
  assertEphemeralNames,
  assertGlobalEphemeralResourcesAbsent,
  assertIsolatedHttpOrigin,
  assertNoUnroutedTenantResources,
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
  type RunMarkerRow,
  type ScenarioIntegrity,
} from "../scripts/real-browser-stack-guards.js";

const RUN_ID = "7c042bb8-b6d1-40a8-89f8-c2ad08f25ab8";
const TENANT_ID = "46e6427b-5503-453f-9f83-e3913ad4e9fa";
const DIGEST = `sha256:${"a".repeat(64)}`;

describe("real browser-stack E2E guards", () => {
  it("requires the explicit ephemeral-only invocation", () => {
    expect(() => requireEphemeralInvocation([REAL_BROWSER_STACK_FLAG])).not.toThrow();
    for (const candidate of [[], ["--apply"], [REAL_BROWSER_STACK_FLAG, "--extra"]]) {
      expect(() => requireEphemeralInvocation(candidate)).toThrow(/exact --ephemeral-only/u);
    }
  });

  it("keeps the read-only preflight flag distinct from mutation authorization", () => {
    expect(() => requireReadOnlyCheckInvocation([REAL_BROWSER_STACK_CHECK_FLAG])).not.toThrow();
    expect(() => requireReadOnlyCheckInvocation([REAL_BROWSER_STACK_FLAG])).toThrow(/exact --check/u);
    expect(() => requireEphemeralInvocation([REAL_BROWSER_STACK_CHECK_FLAG])).toThrow(/exact --ephemeral-only/u);
  });

  it("derives every cleanup target exactly from fresh UUIDv4 markers", () => {
    const names = deriveEphemeralNames(RUN_ID, TENANT_ID);
    expect(names).toEqual({
      runId: RUN_ID,
      controlDatabase: "nom_e2e_c_7c042bb8b6d140a889f8c2ad08f25ab8",
      tenantId: TENANT_ID,
      tenantDatabase: "nom_t_46e6427b5503453f9f83e3913ad4e9fa",
      ownerRole: "nom_o_46e6427b5503453f9f83e3913ad4e9fa",
      runtimeRole: "nom_r_46e6427b5503453f9f83e3913ad4e9fa",
      tenantSlug: "e2e-real-stack-46e6427b5503453f9f83e391",
      secretReference: `tenant-db/${TENANT_ID}/runtime/v1`,
    });
    expect(() => assertEphemeralNames({ ...names, tenantDatabase: PROTECTED_DATABASES.demo })).toThrow();
    expect(() => deriveEphemeralNames("d0000000-0000-1000-8000-000000000001", TENANT_ID)).toThrow(/UUIDv4/u);
  });

  it("accepts only the local workspace administrator target", () => {
    expect(assertWorkspaceAdminUrl("postgresql://nom_admin:redacted@127.0.0.1:55432/postgres").port).toBe("55432");
    for (const candidate of [
      "postgresql://nom_admin:redacted@127.0.0.1:5432/postgres",
      "postgresql://nom_admin:redacted@localhost:55432/postgres",
      "postgresql://nom_admin:redacted@[::1]:55432/postgres",
      "postgresql://nom_admin:redacted@127.0.0.1.:55432/postgres",
      "postgresql://nom_admin:redacted@127.1:55432/postgres",
      "postgresql://nom_admin:redacted@2130706433:55432/postgres",
      "postgresql://nom_admin:redacted@db.example:55432/postgres",
      "postgresql://someone:redacted@127.0.0.1:55432/postgres",
      "postgresql://nom%5Fadmin:redacted@127.0.0.1:55432/postgres",
      "postgresql://ignored@nom_admin:redacted@127.0.0.1:55432/postgres",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/nombramientos_control",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/%70ostgres",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres?host=remote.example&port=5432",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres?host=%2Ftmp%2Fpostgresql",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres?options=-c%20search_path%3Dpublic",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres#sslkey",
      " postgresql://nom_admin:redacted@127.0.0.1:55432/postgres",
      "postgresql://nom_admin:redacted@127.0.0.1:55432/postgres ",
    ]) expect(() => assertWorkspaceAdminUrl(candidate)).toThrow();
  });

  it("rejects operational and PostgreSQL ports for both random HTTP listeners", () => {
    expect(assertIsolatedHttpOrigin("http://localhost:49152", "API").port).toBe("49152");
    for (const candidate of [
      "http://localhost:3000",
      "http://localhost:4000",
      "http://localhost:55432",
      "http://127.0.0.1:49152",
      "http://[::1]:49152",
      "http://localhost.:49152",
      "http://user:password@localhost:49152",
      "http://localhost:049152",
      "http://localhost:49152/",
      "http://localhost:49152/path",
      "http://localhost:49152?next=http://example.invalid",
      "http://localhost:49152#external",
      "https://localhost:49152",
    ]) expect(() => assertIsolatedHttpOrigin(candidate, "listener")).toThrow(/isolated localhost/u);
  });

  it("requires exact proof that both reserved application ports are free", () => {
    const free = RESERVED_APPLICATION_PORTS.map((port) => ({ port, acceptingConnections: false }));
    expect(() => assertReservedApplicationPortsFree(free)).not.toThrow();
    expect(() => assertReservedApplicationPortsFree(free.slice(0, 1))).toThrow(
      "RESERVED_APPLICATION_PORT_INVENTORY_INCOMPLETE",
    );
    expect(() => assertReservedApplicationPortsFree([...free].reverse())).toThrow(
      "RESERVED_APPLICATION_PORT_INVENTORY_INVALID",
    );
    expect(() => assertReservedApplicationPortsFree([
      free[0]!,
      { ...free[1]!, acceptingConnections: true },
    ])).toThrow("RESERVED_APPLICATION_PORT_IN_USE");
  });

  it("requires the exact in-database marker plus both in-memory cleanup facts", () => {
    const names = deriveEphemeralNames(RUN_ID, TENANT_ID);
    const marker: RunMarkerRow = {
      marker: REAL_BROWSER_STACK_MARKER,
      run_id: RUN_ID,
      control_database: names.controlDatabase,
      tenant_id: TENANT_ID,
      tenant_database: names.tenantDatabase,
      owner_role: names.ownerRole,
      runtime_role: names.runtimeRole,
      tenant_slug: names.tenantSlug,
    };
    expect(() => assertRunMarker(marker, names, { controlCreatedByRun: true, namesVerifiedUnused: true })).not.toThrow();
    expect(() => assertRunMarker(marker, names, { controlCreatedByRun: false, namesVerifiedUnused: true })).toThrow();
    expect(() => assertRunMarker({ ...marker, tenant_database: PROTECTED_DATABASES.ozama }, names, {
      controlCreatedByRun: true,
      namesVerifiedUnused: true,
    })).toThrow(/marker mismatch/u);
  });

  it("recognizes only the canonical Demo and Ozama routes", () => {
    const routes = PROTECTED_TENANTS.map((tenant) => ({
      id: tenant.id,
      slug: tenant.slug,
      kind: tenant.kind,
      status: tenant.status,
      database_name: tenant.databaseName,
    }));
    expect(() => assertProtectedTenantRoutes(routes)).not.toThrow();
    expect(() => assertProtectedTenantRoutes(routes.slice(0, 1))).toThrow(/incomplete/u);
    expect(() => assertProtectedTenantRoutes(routes.map((row) => row.kind === "real" ? { ...row, status: "active" } : row))).toThrow(/ozama/u);
  });

  it("rejects every UUID tenant database or role that is not backed by a control route", () => {
    const routes = PROTECTED_TENANTS.map((tenant) => ({
      id: tenant.id,
      database_name: tenant.databaseName,
      runtime_role: `nom_r_${tenant.id.replaceAll("-", "")}`,
    }));
    const databases = routes.map(({ database_name }) => database_name);
    const roles = routes.flatMap(({ id, runtime_role }) => [
      `nom_o_${id.replaceAll("-", "")}`,
      runtime_role,
    ]);
    expect(() => assertNoUnroutedTenantResources(routes, { databases, roles })).not.toThrow();
    expect(observeUnroutedTenantResources(routes, { databases, roles })).toEqual({ databases: 0, roles: 0 });

    const orphanSuffix = TENANT_ID.replaceAll("-", "");
    expect(() => assertNoUnroutedTenantResources(routes, {
      databases: [...databases, `nom_t_${orphanSuffix}`],
      roles,
    })).toThrow("STALE_OR_UNROUTED_TENANT_RESOURCE_PRESENT");
    expect(observeUnroutedTenantResources(routes, {
      databases: [...databases, `nom_t_${orphanSuffix}`],
      roles: [...roles, `nom_r_${orphanSuffix}`],
    })).toEqual({ databases: 1, roles: 1 });
    expect(() => assertNoUnroutedTenantResources(routes, {
      databases,
      roles: [...roles, `nom_o_${orphanSuffix}`],
    })).toThrow("STALE_OR_UNROUTED_TENANT_RESOURCE_PRESENT");
    expect(() => assertNoUnroutedTenantResources(routes, {
      databases,
      roles: [...roles, `nom_r_${orphanSuffix}`],
    })).toThrow("STALE_OR_UNROUTED_TENANT_RESOURCE_PRESENT");
    expect(() => assertNoUnroutedTenantResources([
      { ...routes[0]!, runtime_role: `nom_r_${orphanSuffix}` },
      routes[1]!,
    ], { databases, roles })).toThrow("REGISTERED_TENANT_RESOURCE_ROUTE_INVALID");
  });

  it("requires a globally consistent zero-orphan inventory before and after the run", () => {
    const clean = createGlobalEphemeralResourceObservation(2, 4, 0, { databases: 0, roles: 0 });
    expect(clean).toEqual({
      matchedTenantDatabaseCount: 2,
      matchedTenantRoleCount: 4,
      ephemeralControlDatabaseCount: 0,
      unroutedTenantDatabaseCount: 0,
      unroutedTenantRoleCount: 0,
      orphanDatabaseCount: 0,
      orphanRoleCount: 0,
      databasesAbsent: true,
      rolesAbsent: true,
    });
    expect(() => assertGlobalEphemeralResourcesAbsent(clean)).not.toThrow();
    expect(() => assertGlobalEphemeralResourcesAbsent(
      createGlobalEphemeralResourceObservation(2, 4, 1, { databases: 0, roles: 0 }),
    )).toThrow("GLOBAL_EPHEMERAL_RESOURCE_PRESENT");
    expect(() => assertGlobalEphemeralResourcesAbsent(
      createGlobalEphemeralResourceObservation(3, 5, 0, { databases: 1, roles: 1 }),
    )).toThrow("GLOBAL_EPHEMERAL_RESOURCE_PRESENT");
    expect(() => assertGlobalEphemeralResourcesAbsent({ ...clean, databasesAbsent: false })).toThrow(
      "GLOBAL_EPHEMERAL_RESOURCE_EVIDENCE_INCONSISTENT",
    );
  });

  it("changes the protected digest for structural, ownership, ACL and routine-body drift", () => {
    const snapshot = {
      databaseMetadata: [{ owner: "nom_admin" }],
      relationStructure: [{ relation: "members", owner: "nom_owner" }],
      columns: [{ column: "name", type: "text", nullable: false, default: null }],
      constraints: [{ name: "members_pk", definition: "PRIMARY KEY (id)" }],
      indexes: [{ name: "members_pk", definition: "CREATE UNIQUE INDEX members_pk ON members(id)" }],
      views: [{ name: "member_view", definition: "SELECT id FROM members" }],
      routines: [{ signature: "f()", prosrc: "SELECT 1", owner: "nom_owner" }],
      triggers: [{ name: "members_audit", definition: "EXECUTE FUNCTION audit()" }],
      relationAcl: [{ grantee: "nom_runtime", privilege: "SELECT" }],
      columnAcl: [],
      typeAcl: [],
      comments: [{ identity: "public.members", description_sha256: "a".repeat(64) }],
      securityLabels: [{ identity: "public.members", label_sha256: "b".repeat(64) }],
      eventTriggers: [{ name: "ddl_guard", event: "ddl_command_start" }],
      publications: [{ name: "tenant_publication", insert: true }],
      subscriptions: [{ name: "tenant_subscription", conninfo_sha256: "c".repeat(64) }],
      rowFingerprints: [{ table: "members", rows: "0", digest: "d41d8cd98f00b204e9800998ecf8427e" }],
    } as const;
    const digest = digestProtectedDatabaseSnapshot(snapshot);
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(digestProtectedDatabaseSnapshot({
      rowFingerprints: snapshot.rowFingerprints,
      typeAcl: snapshot.typeAcl,
      columnAcl: snapshot.columnAcl,
      relationAcl: snapshot.relationAcl,
      subscriptions: snapshot.subscriptions,
      publications: snapshot.publications,
      eventTriggers: snapshot.eventTriggers,
      securityLabels: snapshot.securityLabels,
      comments: snapshot.comments,
      triggers: snapshot.triggers,
      routines: snapshot.routines,
      views: snapshot.views,
      indexes: snapshot.indexes,
      constraints: snapshot.constraints,
      columns: snapshot.columns,
      relationStructure: snapshot.relationStructure,
      databaseMetadata: snapshot.databaseMetadata,
    })).toBe(digest);
    for (const drifted of [
      { ...snapshot, columns: [{ ...snapshot.columns[0], default: "clock_timestamp()" }] },
      { ...snapshot, constraints: [{ ...snapshot.constraints[0], definition: "UNIQUE (id)" }] },
      { ...snapshot, indexes: [{ ...snapshot.indexes[0], definition: "CREATE INDEX members_pk ON members(id)" }] },
      { ...snapshot, views: [{ ...snapshot.views[0], definition: "SELECT name FROM members" }] },
      { ...snapshot, routines: [{ ...snapshot.routines[0], prosrc: "SELECT 2" }] },
      { ...snapshot, triggers: [{ ...snapshot.triggers[0], definition: "EXECUTE FUNCTION other_audit()" }] },
      { ...snapshot, relationStructure: [{ ...snapshot.relationStructure[0], owner: "other_owner" }] },
      { ...snapshot, relationAcl: [{ ...snapshot.relationAcl[0], privilege: "UPDATE" }] },
      { ...snapshot, comments: [{ ...snapshot.comments[0], description_sha256: "d".repeat(64) }] },
      { ...snapshot, securityLabels: [{ ...snapshot.securityLabels[0], label_sha256: "e".repeat(64) }] },
      { ...snapshot, eventTriggers: [{ ...snapshot.eventTriggers[0], event: "sql_drop" }] },
      { ...snapshot, publications: [{ ...snapshot.publications[0], insert: false }] },
      { ...snapshot, subscriptions: [{ ...snapshot.subscriptions[0], conninfo_sha256: "f".repeat(64) }] },
    ]) expect(digestProtectedDatabaseSnapshot(drifted)).not.toBe(digest);
  });

  it("requires the complete import, ballot, custody and publication postconditions", () => {
    const integrity: ScenarioIntegrity = {
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
      round_phase: "RESULTADO_INTERNO",
      aggregate: {
        schemaVersion: 1,
        receivedBallots: 2,
        nonAbstainingBallots: 1,
        abstentions: 1,
        maxSelections: 1,
        candidates: [{ candidateId: TENANT_ID, votes: 1 }, { candidateId: RUN_ID, votes: 0 }],
        rule: { kind: "PLURALITY" },
        decision: { status: "SELECTED", reason: "TOP_K", selectedCandidateIds: [TENANT_ID], tiebreakCandidateIds: [], unfilledSeats: 0 },
      },
    };
    expect(() => assertScenarioIntegrity(integrity, [TENANT_ID, RUN_ID])).not.toThrow();
    expect(() => assertScenarioIntegrity({ ...integrity, vote_receipts: 1 })).toThrow(/vote_receipts/u);
    expect(() => assertScenarioIntegrity({ ...integrity, aggregate: { ...integrity.aggregate as object, abstentions: 0 } })).toThrow(/aggregate/u);
    expect(() => assertScenarioIntegrity({
      ...integrity,
      aggregate: {
        ...integrity.aggregate as object,
        candidates: [{ candidateId: TENANT_ID, votes: 0 }, { candidateId: RUN_ID, votes: 1 }],
      },
    }, [TENANT_ID, RUN_ID])).toThrow(/selected candidate/u);
  });

  it("fails cleanup unless every generated object is absent and all three fingerprints match", () => {
    const protectedBefore = { control: DIGEST, demo: DIGEST, ozama: DIGEST };
    expect(() => assertCleanupObservation({ databases: 0, roles: 0, protectedBefore, protectedAfter: { ...protectedBefore } })).not.toThrow();
    expect(() => assertCleanupObservation({ databases: 1, roles: 0, protectedBefore, protectedAfter: { ...protectedBefore } })).toThrow();
    expect(() => assertCleanupObservation({
      databases: 0,
      roles: 0,
      protectedBefore,
      protectedAfter: { ...protectedBefore, demo: `sha256:${"b".repeat(64)}` },
    })).toThrow(/demo/u);
  });

  it("seeds synthetic MFA identities with the completed-enrollment timestamp required by control migration 006", () => {
    const runner = readFileSync(path.resolve(import.meta.dirname, "../scripts/real-browser-stack-local.ts"), "utf8");
    const start = runner.indexOf("async function seedControlSessions");
    const end = runner.indexOf("async function startApi", start);
    const seed = runner.slice(start, end);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(seed).toMatch(
      /mfa_enabled,totp_secret_ciphertext,mfa_enrolled_at,status[\s\S]*?true,\$5,clock_timestamp\(\),'active'/u,
    );
  });

  it("casts UUID parameters explicitly across the candidate snapshot UNION", () => {
    const runner = readFileSync(path.resolve(import.meta.dirname, "../scripts/real-browser-stack-local.ts"), "utf8");
    const start = runner.indexOf("INSERT INTO candidate_snapshots");
    const end = runner.indexOf('executionStage = "fixture-seed-tenant-commit"', start);
    const statement = runner.slice(start, end);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(statement).toContain("SELECT $1::uuid,$2::uuid");
    expect(statement).toContain("SELECT $1::uuid,$5::uuid");
  });

  it("keeps the ephemeral catalog compatible with canonical persistence identifiers", () => {
    const runner = readFileSync(path.resolve(import.meta.dirname, "../scripts/real-browser-stack-local.ts"), "utf8");
    const start = runner.indexOf("const temporaryCatalog =");
    const end = runner.indexOf("main().catch", start);
    const catalog = runner.slice(start, end);
    const codes = [...catalog.matchAll(/(?:canonicalCode|departmentCode): "([^"]+)"/gu)]
      .map((match) => match[1]);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(codes).toHaveLength(3);
    for (const code of codes) expect(code).toMatch(/^[a-z][a-z0-9_]{0,126}$/u);
    expect(runner).toContain("canonical_code='real_browser_stack_office'");
  });

  it("publishes a fail-closed in-progress artifact before DB work and replaces it atomically", () => {
    const runner = readFileSync(path.resolve(import.meta.dirname, "../scripts/real-browser-stack-local.ts"), "utf8");
    const guards = readFileSync(path.resolve(import.meta.dirname, "../scripts/real-browser-stack-guards.ts"), "utf8");
    const reportStart = runner.indexOf("const report: RunReport");
    const initialPublication = runner.indexOf("writeReport(report);", reportStart);
    const configurationGuard = runner.indexOf('executionStage = "workspace-admin-config"', initialPublication);
    const firstDatabaseCheck = runner.indexOf('executionStage = "workspace-cluster-identity"', initialPublication);
    expect(reportStart).toBeGreaterThanOrEqual(0);
    expect(initialPublication).toBeGreaterThan(reportStart);
    expect(configurationGuard).toBeGreaterThan(initialPublication);
    expect(firstDatabaseCheck).toBeGreaterThan(initialPublication);
    const preflightStart = runner.indexOf("const report: PreflightReport");
    const preflightSentinel = runner.indexOf("writeFailClosedPreflightSentinel(report);", preflightStart);
    const preflightPortCheck = runner.indexOf('executionStage = "preflight-reserved-application-ports-before"', preflightSentinel);
    const preflightUrlCheck = runner.indexOf('executionStage = "preflight-workspace-admin-config"', preflightSentinel);
    expect(preflightStart).toBeGreaterThanOrEqual(0);
    expect(preflightSentinel).toBeGreaterThan(preflightStart);
    expect(preflightPortCheck).toBeGreaterThan(preflightSentinel);
    expect(preflightUrlCheck).toBeGreaterThan(preflightSentinel);
    expect(runner).toMatch(/status: "in-progress"/u);
    expect(runner).toMatch(/report\.inProgress = false/u);
    expect(runner).toMatch(
      /const scenarioIntegrity = await observeTenantScenario\(state\);[\s\S]*?report\.scenarioObservation = sanitizeScenarioObservation\(scenarioIntegrity\);[\s\S]*?assertScenarioIntegrity\(scenarioIntegrity, state\.ids\.candidateIds\);/u,
    );
    expect(runner).toMatch(/scenarioObservation: null/u);
    expect(runner).toMatch(/!report\.scenarioObservation/u);
    expect(runner).toMatch(/const \{ aggregate, \.\.\.countsAndPhase \} = integrity;[\s\S]*?aggregateSha256: digestCanonical\(aggregate\)/u);
    expect(runner).toMatch(/\^SCN_\[A-Z0-9_\]\{2,27\}\$/u);
    expect(runner).toMatch(/openSync\(preflightArtifactFile, "w"\)[\s\S]*?writeFileSync\(descriptor,[\s\S]*?fsyncSync\(descriptor\)/u);
    expect(runner).toMatch(/writeFileSync\(temporaryFile[\s\S]*?fsyncSync\(descriptor\)[\s\S]*?replaceArtifactFile\(temporaryFile, file\)/u);
    expect(runner).toMatch(/renameSync\(temporaryFile, destinationFile\)[\s\S]*?openSync\(destinationFile, "w"\)[\s\S]*?copyFileSync\(temporaryFile, destinationFile\)/u);
    expect(runner).not.toMatch(/writeFileSync\(file,/u);
    expect(runner).not.toMatch(/new Pool\(\{\s*connectionString:/u);
    expect(runner).toMatch(/host: value\.hostname[\s\S]*port: Number\(value\.port\)[\s\S]*ssl: false/u);
    for (const evidence of [
      "protectedFingerprints",
      "operationalPorts",
      "ephemeralCleanup",
      "databaseCount",
      "roleCount",
      "databasesAbsent",
      "rolesAbsent",
      "mutationStarted",
      "cleanupDdlStarted",
      "globalEphemeralResources",
      "clusterCatalog",
    ]) expect(runner).toContain(evidence);
    for (const evidence of ["orphanDatabaseCount", "orphanRoleCount"]) {
      expect(`${runner}\n${guards}`).toContain(evidence);
    }
    expect(runner).toMatch(/mode: "read-only-preflight"[\s\S]*globalEphemeralResources:/u);
    expect(runner).toContain("left(datname,length('nom_e2e_c_'))='nom_e2e_c_'");
    for (const catalogEvidence of [
      "pg_attribute",
      "format_type",
      "pg_attrdef",
      "pg_constraint",
      "pg_get_constraintdef",
      "pg_index",
      "pg_get_indexdef",
      "pg_get_viewdef",
      "pg_proc",
      "prosrc",
      "pg_get_functiondef",
      "pg_trigger",
      "pg_get_triggerdef",
      "pg_roles",
      "aclexplode",
      "pg_type",
      "pg_policy",
      "pg_default_acl",
      "database.datlocale",
    ]) expect(runner).toContain(catalogEvidence);
    const fingerprint = runner.slice(
      runner.indexOf("async function fingerprintDatabase"),
      runner.indexOf("function temporarySession"),
    );
    expect(fingerprint).toContain("pg_catalog.pg_collation collation_record");
    expect(fingerprint).not.toMatch(/pg_catalog\.pg_collation collation\b/u);
    expect(fingerprint).not.toContain("namespace.nspname='public'");
    expect(fingerprint).not.toContain("schemaname='public'");
    expect(fingerprint).toContain("namespace.nspname NOT IN ('pg_catalog','information_schema')");
    const schemaFingerprint = fingerprint.slice(
      fingerprint.indexOf("const schemas"),
      fingerprint.indexOf("const relationStructure"),
    );
    expect(schemaFingerprint).toContain("LEFT JOIN LATERAL pg_catalog.aclexplode");
    expect(schemaFingerprint).toContain("CASE WHEN acl.grantee IS NULL THEN NULL");
    const manualMetadataFingerprint = fingerprint.slice(
      fingerprint.indexOf("const comments"),
      fingerprint.indexOf("const eventTriggers"),
    );
    expect(manualMetadataFingerprint).not.toContain("dependency.deptype IN ('e','x')");
    expect(runner).toContain("FROM pg_catalog.pg_auth_members membership");
    const clusterFingerprint = runner.slice(
      runner.indexOf("async function fingerprintClusterCatalog"),
      runner.indexOf("function assertClusterCatalogRestored"),
    );
    expect(clusterFingerprint).toContain("FROM pg_catalog.pg_roles role");
    expect(clusterFingerprint).toContain("JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid");
    expect(clusterFingerprint).toContain("role.rolconfig");
    expect(clusterFingerprint).not.toContain("credential.rolconfig");
    expect(clusterFingerprint).toContain("credential.rolpassword IS NOT NULL AS has_password");
    expect(clusterFingerprint.replace("credential.rolpassword IS NOT NULL AS has_password", ""))
      .not.toContain("rolpassword");
    expect(clusterFingerprint).not.toMatch(/password_(?:verifier_)?digest|md5\(COALESCE\(role\.rolpassword/iu);
    expect(runner).toContain("assertClusterCatalogRestored(clusterCatalogBefore, clusterCatalogAfter)");
    for (const catalog of [
      "pg_description", "pg_shdescription", "pg_seclabel", "pg_shseclabel",
      "pg_event_trigger", "pg_publication", "pg_subscription", "pg_rewrite",
    ]) expect(runner).toContain(catalog);
    expect(runner).toContain("AS conninfo_sha256");
    expect(runner).not.toMatch(/subscription\.subconninfo\s+AS/iu);
  });

  it("invalidates both possible stale artifacts before a build can run", () => {
    const publisher = readFileSync(
      path.resolve(import.meta.dirname, "../scripts/real-browser-stack-prerun.mjs"),
      "utf8",
    );
    expect(publisher).toContain('const CHECK_FLAG = "--check"');
    expect(publisher).toContain('const RUN_FLAG = "--ephemeral-only"');
    expect(publisher).toContain('"real-browser-stack-preflight.json"');
    expect(publisher).toContain('"real-browser-stack-local.json"');
    expect(publisher).toMatch(/args\.length !== 1 \|\| !Object\.hasOwn\(targetByFlag, args\[0\]\)/u);
    expect(publisher).toMatch(/status: "in-progress"[\s\S]*?inProgress: true[\s\S]*?invalidatedBeforeBuild: true/u);
    const invalidate = publisher.indexOf('openSync(destinationFile, "w")');
    const temporaryWrite = publisher.indexOf("writeFileSync(temporaryFile, payload");
    const removeInvalid = publisher.indexOf("unlinkSync(destinationFile)");
    const atomicPublish = publisher.indexOf("renameSync(temporaryFile, destinationFile)");
    expect(invalidate).toBeGreaterThanOrEqual(0);
    expect(temporaryWrite).toBeGreaterThan(invalidate);
    expect(removeInvalid).toBeGreaterThan(temporaryWrite);
    expect(atomicPublish).toBeGreaterThan(removeInvalid);
    expect(publisher).toContain('openSync(destinationFile, "r+")');
    expect(publisher).not.toContain('openSync(destinationFile, "r")');
    expect(publisher).not.toMatch(/process\.env|connectionString|new Pool/u);
  });
});
