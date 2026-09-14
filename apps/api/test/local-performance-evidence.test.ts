import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  planPerformanceCleanup,
  planScaleControlCleanup,
  type PerformanceCleanupIntent,
  type PerformanceCleanupJob,
  type PerformanceCleanupRoute,
  type ScaleControlCleanupDatabase,
  type ScaleControlCleanupRole,
} from "../scripts/local-performance-cleanup-guards.js";
import { writeJsonEvidenceAtomic } from "../scripts/local-performance-evidence.js";
import {
  completeProtectedFingerprintSet,
  digestProtectedDatabaseSnapshot,
  globalInventorySetsEqual,
  protectedFingerprintSetsEqual,
  type EphemeralResourceInventory,
  type ProtectedDatabaseSnapshot,
  type ProtectedDatabaseFingerprints,
} from "../scripts/local-performance-protected-state.js";

function cleanupIntent(index: number): PerformanceCleanupIntent {
  const nibble = (index + 1).toString(16);
  const keyNibble = (15 - index).toString(16);
  const tenantId = `${nibble.repeat(8)}-${nibble.repeat(4)}-4${nibble.repeat(3)}-8${nibble.repeat(3)}-${nibble.repeat(12)}`;
  const provisioningKey = `${keyNibble.repeat(8)}-${keyNibble.repeat(4)}-4${keyNibble.repeat(3)}-8${keyNibble.repeat(3)}-${keyNibble.repeat(12)}`;
  const suffix = tenantId.replaceAll("-", "");
  return {
    tenantId,
    databaseName: `nom_t_${suffix}`,
    ownerRole: `nom_o_${suffix}`,
    runtimeRole: `nom_r_${suffix}`,
    provisioningKey,
    tenantSlug: `ac37s-${suffix.slice(0, 24)}`,
    displayName: `AC-37 scale synthetic tenant-${String(index + 1).padStart(2, "0")}`,
    secretReference: `tenant-db/${tenantId}/runtime/v1`,
    requestHash: nibble.repeat(64),
    namesVerifiedUnused: true,
    provisioningAttempted: true,
  };
}

function cleanupJob(intent: PerformanceCleanupIntent, state: string): PerformanceCleanupJob {
  return {
    idempotency_key: intent.provisioningKey,
    tenant_id: intent.tenantId,
    requested_slug: intent.tenantSlug,
    request_hash: intent.requestHash,
    state,
    attempt_count: 1,
  };
}

function cleanupRoute(intent: PerformanceCleanupIntent): PerformanceCleanupRoute {
  return {
    id: intent.tenantId,
    slug: intent.tenantSlug,
    display_name: intent.displayName,
    kind: "demo",
    status: "active",
    timezone: "America/La_Paz",
    locale: "es",
    database_host: "127.0.0.1",
    database_port: 55_432,
    database_name: intent.databaseName,
    runtime_role: intent.runtimeRole,
    runtime_secret_ref: intent.secretReference,
    credential_version: 1,
    ssl_mode: "disable",
  };
}

function controlDatabase(runId: string): ScaleControlCleanupDatabase {
  return {
    name: `nom_c_${runId.replaceAll("-", "")}`,
    owner: "nom_admin",
    encoding: "UTF8",
    is_template: false,
    allows_connections: true,
    connection_limit: -1,
  };
}

function controlRole(runId: string, marker: string | null): ScaleControlCleanupRole {
  return {
    name: `nom_cr_${runId.replaceAll("-", "")}`,
    login: true,
    superuser: false,
    create_database: false,
    create_role: false,
    inherit: false,
    replication: false,
    bypass_rls: false,
    connection_limit: 30,
    valid_until_epoch: "",
    configuration: "{}",
    password_present: true,
    membership_count: 0,
    marker,
  };
}

describe("local performance evidence publication", () => {
  it("atomically replaces the sentinel and leaves no unpublished temporary", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "nom-api-evidence-"));
    try {
      const filename = path.join(directory, "report.json");
      writeJsonEvidenceAtomic(filename, { status: "in-progress", overallPass: false });
      writeJsonEvidenceAtomic(filename, { status: "passed", overallPass: true });
      expect(JSON.parse(readFileSync(filename, "utf8"))).toEqual({ status: "passed", overallPass: true });
      expect(readdirSync(directory)).toEqual(["report.json"]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("uses fail-closed same-directory replacement with no copy fallback", () => {
    const source = readFileSync(new URL("../scripts/local-performance-evidence.ts", import.meta.url), "utf8");
    expect(source).toMatch(/replaceJsonEvidenceFileFailClosed\(temporary, filename, renameFile\)/u);
    expect(source).toMatch(/openSync\(filename, "w", 0o600\)/u);
    expect(source).toMatch(/unlinkSync\(filename\);\s*renameFile\(temporary, filename\)/u);
    expect(source).not.toMatch(/copyFileSync|writeFileSync\(filename/u);
  });

  it("handles Windows replacement failure and cannot retain stale green evidence", () => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "nom-api-evidence-replace-"));
    try {
      const filename = path.join(directory, "report.json");
      writeJsonEvidenceAtomic(filename, { status: "in-progress", overallPass: false });
      let attempts = 0;
      writeJsonEvidenceAtomic(filename, { status: "passed", overallPass: true }, (source, destination) => {
        attempts += 1;
        if (attempts === 1) throw new Error("simulated Windows replace denial");
        renameSync(source, destination);
      });
      expect(attempts).toBe(2);
      expect(JSON.parse(readFileSync(filename, "utf8"))).toEqual({ status: "passed", overallPass: true });
      expect(() => writeJsonEvidenceAtomic(filename, { status: "failed", overallPass: false }, () => {
        throw new Error("simulated persistent rename failure");
      })).toThrow(/simulated persistent rename failure/u);
      expect(existsSync(filename)).toBe(false);
      expect(readdirSync(directory)).toEqual([]);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each(["performance-local.ts", "performance-scale-local.ts"])(
    "%s publishes an in-progress sentinel before database discovery and never passes a connection string to pg",
    (script) => {
      const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), "utf8");
      const sentinelOffset = source.indexOf('status: "in-progress"');
      const discoveryOffset = source.indexOf("discoverLocalAdminUrl()");
      expect(sentinelOffset).toBeGreaterThanOrEqual(0);
      expect(discoveryOffset).toBeGreaterThan(sentinelOffset);
      expect(source).not.toMatch(/connectionString\s*:/u);
      expect(source).toMatch(/writeJsonEvidenceAtomic/u);
    },
  );

  it("enforces the exclusive 1500ms acknowledgement target", () => {
    for (const script of ["performance-local.ts", "performance-scale-local.ts"]) {
      const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), "utf8");
      expect(source).toMatch(/ACKNOWLEDGEMENT_P95_BUDGET_MS\s*=\s*1_500/u);
      expect(source).toMatch(/\.p95Ms\s*<\s*ACKNOWLEDGEMENT_P95_BUDGET_MS/u);
    }
  });

  it("uses an ordinary proposal/ballot appointment mechanism in synthetic performance catalogs", () => {
    for (const script of ["performance-local.ts", "performance-scale-local.ts"]) {
      const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), "utf8");
      expect(source).toMatch(/mechanism:\s*"church_election_after_nominating_report"/u);
      expect(source).not.toMatch(/mechanism:\s*"committee-election"/u);
    }
  });

  it("plans exact local cleanup after roles and database exist but the final tenant route does not", () => {
    const intent = cleanupIntent(0);
    const evidence = {
      routes: [],
      jobs: [cleanupJob(intent, "database_created")],
      databases: [intent.databaseName],
      roles: [intent.ownerRole, intent.runtimeRole],
    };
    const plan = planPerformanceCleanup([intent], evidence, 1);
    expect(plan).toEqual({
      tenantIds: [intent.tenantId],
      provisioningKeys: [intent.provisioningKey],
      databases: [intent.databaseName],
      roles: [intent.ownerRole, intent.runtimeRole].sort(),
    });
    expect(evidence.databases.filter((name) => !plan.databases.includes(name))).toEqual([]);
    expect(evidence.roles.filter((name) => !plan.roles.includes(name))).toEqual([]);
  });

  it("plans zero-orphan scale cleanup across complete and partial tenants plus a partially marked control", () => {
    const complete = cleanupIntent(0);
    const partial = cleanupIntent(1);
    const tenantEvidence = {
      routes: [cleanupRoute(complete)],
      jobs: [cleanupJob(complete, "active"), cleanupJob(partial, "database_created")],
      databases: [complete.databaseName, partial.databaseName],
      roles: [complete.ownerRole, complete.runtimeRole, partial.ownerRole, partial.runtimeRole],
    };
    const tenantPlan = planPerformanceCleanup([complete, partial], tenantEvidence, 10);

    const runId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const database = controlDatabase(runId);
    const runtimeRole = controlRole(runId, null);
    const controlPlan = planScaleControlCleanup({
      runId,
      databaseName: database.name,
      runtimeRole: runtimeRole.name,
      namesVerifiedUnused: true,
      databaseCreationAttempted: true,
      databaseCreatedByRun: true,
      roleCreationAttempted: true,
      roleCreatedByRun: true,
    }, {
      database,
      markerTablePresent: true,
      marker: {
        run_id: runId,
        control_database: database.name,
        control_runtime_role: runtimeRole.name,
      },
      role: runtimeRole,
    });

    const orphanDatabases = [database.name, ...tenantEvidence.databases].filter((name) => (
      !controlPlan.databases.includes(name) && !tenantPlan.databases.includes(name)
    ));
    const orphanRoles = [runtimeRole.name, ...tenantEvidence.roles].filter((name) => (
      !controlPlan.roles.includes(name) && !tenantPlan.roles.includes(name)
    ));
    expect(orphanDatabases).toEqual([]);
    expect(orphanRoles).toEqual([]);
  });

  it("authorizes a just-created scale control database before its marker table exists", () => {
    const runId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const database = controlDatabase(runId);
    expect(planScaleControlCleanup({
      runId,
      databaseName: database.name,
      runtimeRole: `nom_cr_${runId.replaceAll("-", "")}`,
      namesVerifiedUnused: true,
      databaseCreationAttempted: true,
      databaseCreatedByRun: true,
      roleCreationAttempted: false,
      roleCreatedByRun: false,
    }, {
      database,
      markerTablePresent: false,
      marker: null,
      role: null,
    })).toEqual({ databases: [database.name], roles: [] });
  });

  it("rejects partial cleanup resources without their durable marker or with mismatched ownership", () => {
    const intent = cleanupIntent(0);
    expect(() => planPerformanceCleanup([intent], {
      routes: [],
      jobs: [],
      databases: [intent.databaseName],
      roles: [intent.ownerRole],
    }, 1)).toThrow(/lacks its exact provisioning marker/u);
    expect(() => planPerformanceCleanup([intent], {
      routes: [{ ...cleanupRoute(intent), locale: "en" }],
      jobs: [cleanupJob(intent, "active")],
      databases: [intent.databaseName],
      roles: [intent.ownerRole, intent.runtimeRole],
    }, 1)).toThrow(/route metadata is not owned/u);

    const runId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const database = controlDatabase(runId);
    const runtimeRole = controlRole(runId, "marker-for-another-run");
    expect(() => planScaleControlCleanup({
      runId,
      databaseName: database.name,
      runtimeRole: runtimeRole.name,
      namesVerifiedUnused: true,
      databaseCreationAttempted: true,
      databaseCreatedByRun: true,
      roleCreationAttempted: true,
      roleCreatedByRun: true,
    }, {
      database,
      markerTablePresent: false,
      marker: null,
      role: runtimeRole,
    })).toThrow(/role metadata is not owned/u);
  });

  it.each(["performance-local.ts", "performance-scale-local.ts"])(
    "%s makes protected fingerprints and global orphan inventories part of cleanup",
    (script) => {
      const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), "utf8");
      expect(source).toMatch(/fingerprintProtectedDatabases\(databaseAdminUrl\)/u);
      expect(source).toMatch(/inspectGlobalEphemeralResources\(databaseAdminUrl\)/u);
      expect(source).toMatch(/ephemeralResourcesAfter\s*=\s*await inspectGlobalEphemeralResources\(state\.databaseAdminUrl\)/u);
      expect(source).toMatch(/protectedDatabasesUnchanged/u);
      expect(source).toMatch(/ephemeralResourcesBefore/u);
      expect(source).toMatch(/ephemeralResourcesAfter/u);
      expect(source).toMatch(/globalInventorySetsEqual/u);
      expect(source).toMatch(/globalInventoryUnchanged/u);
    },
  );

  it("requires a complete control, Demo and Ozama fingerprint set", () => {
    const fingerprint = (digest: string, rows: number) => ({
      fingerprintVersion: "protected-db-v3-full-cluster-role-structure-and-content" as const,
      digest: `sha256:${digest.repeat(64)}`,
      tables: 1,
      rows,
      schemaObjects: 3,
    });
    const fingerprints: ProtectedDatabaseFingerprints = {
      control: fingerprint("a", 0),
      demo: fingerprint("b", 1),
      ozama: fingerprint("c", 1),
    };
    expect(completeProtectedFingerprintSet(fingerprints)).toBe(true);
    expect(protectedFingerprintSetsEqual(fingerprints, structuredClone(fingerprints))).toBe(true);
    expect(protectedFingerprintSetsEqual(fingerprints, {
      ...fingerprints,
      demo: { ...fingerprints.demo, rows: 2 },
    })).toBe(false);
  });

  it("changes the protected digest for structural or ACL drift even with identical rows", () => {
    const snapshot: ProtectedDatabaseSnapshot = {
      database: "nom_t_protected",
      databaseMetadata: [{ database: "nom_t_protected", owner: "nom_admin", acl: "{}" }],
      associatedRoles: [{
        role: "nom_admin",
        superuser: true,
        bypass_rls: true,
        valid_until_epoch: "",
        configuration: "{}",
        password_present: true,
      }],
      associatedRoleMemberships: [],
      schemas: [{ schema: "public", owner: "nom_admin", acl: "{}" }],
      relations: [{ relation: "members", owner: "nom_owner", acl: "{nom_runtime=r}" }],
      columns: [{ relation: "members", column: "id", formatted_type: "uuid", not_null: true, default_expression: "" }],
      constraints: [{ relation: "members", constraint: "members_pkey", definition: "PRIMARY KEY (id)" }],
      indexes: [{ relation: "members", index: "members_pkey", definition: "CREATE UNIQUE INDEX members_pkey ON members USING btree (id)" }],
      views: [],
      routines: [{ name: "touch_member", source: "BEGIN RETURN NEW; END", definition: "CREATE FUNCTION touch_member() RETURNS trigger ..." }],
      triggers: [{ relation: "members", trigger: "members_touch", definition: "CREATE TRIGGER members_touch ..." }],
      policies: [],
      types: [{ name: "member_state", enum_labels: "{active,archived}", owner: "nom_owner", acl: "{}" }],
      sequences: [{ sequence: "audit_events_sequence_seq", last_value: "7", is_called: true }],
      defaultPrivileges: [],
      extensions: [{ extension: "plpgsql", version: "1.0", schema: "pg_catalog" }],
      descriptions: [],
      sharedDescriptions: [],
      securityLabels: [],
      sharedSecurityLabels: [],
      eventTriggers: [],
      publications: [],
      publicationRelations: [],
      publicationNamespaces: [],
      subscriptions: [],
      subscriptionRelations: [],
      rewriteRules: [],
      tableFingerprints: [{ table: "members", rows: 0, digest: "d41d8cd98f00b204e9800998ecf8427e" }],
    };
    const baseline = digestProtectedDatabaseSnapshot(snapshot);
    const schemaDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      columns: [{ ...snapshot.columns[0], default_expression: "gen_random_uuid()" }],
    });
    const aclDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      relations: [{ ...snapshot.relations[0], acl: "{public=r}" }],
    });
    const sequenceStateDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      sequences: [{ ...snapshot.sequences[0], is_called: false }],
    });
    const nonPublicSchemaDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      schemas: [...snapshot.schemas, { schema: "rogue", owner: "nom_admin", acl: "{}" }],
    });
    const superuserDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoles: [{ ...snapshot.associatedRoles[0], superuser: false }],
    });
    const bypassRlsDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoles: [{ ...snapshot.associatedRoles[0], bypass_rls: false }],
    });
    const passwordValidityDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoles: [{ ...snapshot.associatedRoles[0], valid_until_epoch: "1900000000" }],
    });
    const passwordPresenceDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoles: [{ ...snapshot.associatedRoles[0], password_present: false }],
    });
    const roleConfigurationDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoles: [{ ...snapshot.associatedRoles[0], configuration: "{statement_timeout=1s}" }],
    });
    const membershipDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      associatedRoleMemberships: [{
        granted_role: "nom_platform_admin",
        member_role: "nom_admin",
        grantor_role: "nom_admin",
        admin_option: true,
        inherit_option: true,
        set_option: true,
      }],
    });
    const descriptionDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      descriptions: [{ catalog: "pg_class", object_oid: "42", description: "changed" }],
    });
    const sharedDescriptionDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      sharedDescriptions: [{ catalog: "pg_database", object_oid: "43", description: "changed" }],
    });
    const securityLabelDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      securityLabels: [{ catalog: "pg_class", object_oid: "42", provider: "provider", label: "changed" }],
    });
    const sharedSecurityLabelDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      sharedSecurityLabels: [{ catalog: "pg_authid", object_oid: "44", provider: "provider", label: "changed" }],
    });
    const eventTriggerDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      eventTriggers: [{ name: "unexpected_ddl", event: "ddl_command_end", enabled: "O" }],
    });
    const publicationDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      publications: [{ publication: "unexpected_publication", all_tables: true }],
    });
    const subscriptionDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      subscriptions: [{ subscription: "unexpected_subscription", connection_info_digest: "0".repeat(64) }],
    });
    const rewriteRuleDrift = digestProtectedDatabaseSnapshot({
      ...snapshot,
      rewriteRules: [{ schema: "public", relation: "members", rule: "unexpected_rule", definition: "CREATE RULE ..." }],
    });
    expect(schemaDrift).not.toBe(baseline);
    expect(aclDrift).not.toBe(baseline);
    expect(sequenceStateDrift).not.toBe(baseline);
    expect(nonPublicSchemaDrift).not.toBe(baseline);
    expect(superuserDrift).not.toBe(baseline);
    expect(bypassRlsDrift).not.toBe(baseline);
    expect(passwordValidityDrift).not.toBe(baseline);
    expect(passwordPresenceDrift).not.toBe(baseline);
    expect(roleConfigurationDrift).not.toBe(baseline);
    expect(membershipDrift).not.toBe(baseline);
    expect(descriptionDrift).not.toBe(baseline);
    expect(sharedDescriptionDrift).not.toBe(baseline);
    expect(securityLabelDrift).not.toBe(baseline);
    expect(sharedSecurityLabelDrift).not.toBe(baseline);
    expect(eventTriggerDrift).not.toBe(baseline);
    expect(publicationDrift).not.toBe(baseline);
    expect(subscriptionDrift).not.toBe(baseline);
    expect(rewriteRuleDrift).not.toBe(baseline);
  });

  it("requires the complete sanitized global database, role and membership inventory to be unchanged", () => {
    const inventory = (overrides: Partial<EphemeralResourceInventory> = {}): EphemeralResourceInventory => ({
      inspectedDatabases: 0,
      inspectedRoles: 0,
      globalDatabaseCount: 4,
      globalRoleCount: 8,
      globalMembershipCount: 2,
      globalSharedDescriptionCount: 3,
      globalSharedSecurityLabelCount: 0,
      globalInventoryDigest: `sha256:${"a".repeat(64)}`,
      orphanDatabases: 0,
      orphanRoles: 0,
      pass: true,
      ...overrides,
    });
    const before = inventory();
    expect(globalInventorySetsEqual(before, structuredClone(before))).toBe(true);
    expect(globalInventorySetsEqual(before, inventory({ globalRoleCount: 9 }))).toBe(false);
    expect(globalInventorySetsEqual(before, inventory({ globalSharedDescriptionCount: 4 }))).toBe(false);
    expect(globalInventorySetsEqual(before, inventory({ globalSharedSecurityLabelCount: 1 }))).toBe(false);
    expect(globalInventorySetsEqual(before, inventory({
      globalInventoryDigest: `sha256:${"b".repeat(64)}`,
    }))).toBe(false);
    expect(globalInventorySetsEqual(null, before)).toBe(false);
  });

  it("feeds full structural and ownership catalogs into protected snapshots", () => {
    const source = readFileSync(new URL("../scripts/local-performance-protected-state.ts", import.meta.url), "utf8");
    for (const contract of [
      "pg_catalog.pg_attribute",
      "pg_catalog.format_type",
      "pg_catalog.pg_constraint",
      "pg_get_constraintdef",
      "pg_catalog.pg_index",
      "pg_get_indexdef",
      "pg_catalog.pg_views",
      "pg_catalog.pg_matviews",
      "pg_catalog.pg_proc",
      "routine.prosrc",
      "pg_get_functiondef",
      "pg_catalog.pg_trigger",
      "pg_get_triggerdef",
      "relation.relowner",
      "relation.relacl",
      "type.typacl",
      "database.datacl",
      "database.datlocale",
      "database.daticurules",
      "min_value::text",
      "max_value::text",
      "is_called",
      "pg_catalog.pg_authid",
      "pg_catalog.pg_auth_members",
      "pg_catalog.pg_description",
      "pg_catalog.pg_shdescription",
      "pg_catalog.pg_seclabel",
      "pg_catalog.pg_shseclabel",
      "pg_catalog.pg_event_trigger",
      "pg_catalog.pg_publication",
      "pg_catalog.pg_publication_rel",
      "pg_catalog.pg_publication_namespace",
      "pg_catalog.pg_subscription",
      "pg_catalog.pg_subscription_rel",
      "pg_catalog.pg_rewrite",
      "pg_get_ruledef",
      "connection_info_digest",
      "role.rolsuper",
      "role.rolbypassrls",
      "role.rolvaliduntil",
      "role.rolconfig",
    ]) expect(source).toContain(contract);
    expect(source).not.toContain("database.daticulocale");
    expect(source).not.toContain("minimum_value::text");
    expect(source).not.toContain("maximum_value::text");
    expect(source).toContain("pg_catalog.pg_collation collation_record");
    expect(source).not.toMatch(/pg_catalog\.pg_collation collation\b/u);
    expect(source).toContain("pg_catalog.pg_constraint constraint_record");
    expect(source).not.toMatch(/pg_catalog\.pg_constraint constraint\b/u);
    expect(source.match(/subconninfo/gu)).toHaveLength(1);
    expect(source).toMatch(/sha256\(pg_catalog\.convert_to\(COALESCE\(subscription\.subconninfo,''\),'UTF8'\)\)[\s\S]*?AS connection_info_digest/u);
    expect(source).not.toMatch(/subscription\.subconninfo\s+AS/iu);
  });

  it("inventories both performance and real-stack ephemeral control prefixes", () => {
    const source = readFileSync(new URL("../scripts/local-performance-protected-state.ts", import.meta.url), "utf8");
    expect(source).toMatch(/nom_c_/u);
    expect(source).toMatch(/nom_e2e_c_/u);
    expect(source).toMatch(/nom_t_/u);
    expect(source).toMatch(/nom_o_/u);
    expect(source).toMatch(/nom_r_/u);
    expect(source).toMatch(/nom_cr_/u);
  });

  it("never mutates cleanup targets before both unused-name and ownership authorization", () => {
    const source = readFileSync(new URL("../scripts/performance-local.ts", import.meta.url), "utf8");
    const unusedNamePreflight = source.indexOf("await assertTemporaryNamesUnused(cleanup)");
    const attemptLedger = source.indexOf("cleanup.provisioningAttempted = true");
    const provision = source.indexOf("cleanup.provisioner.provision(provisioningRequest)");
    const authorization = source.indexOf("cleanupPlan = await inspectLocalCleanupOwnership(state)");
    const deleteRows = source.indexOf('"DELETE FROM auth_sessions', authorization);
    const dropDatabase = source.indexOf("dropDatabase(state.cluster, state.databaseName)", authorization);
    expect(unusedNamePreflight).toBeGreaterThanOrEqual(0);
    expect(attemptLedger).toBeGreaterThan(unusedNamePreflight);
    expect(provision).toBeGreaterThan(attemptLedger);
    expect(authorization).toBeGreaterThanOrEqual(0);
    expect(deleteRows).toBeGreaterThan(authorization);
    expect(dropDatabase).toBeGreaterThan(deleteRows);
    expect(source.slice(0, authorization)).not.toMatch(/DELETE FROM auth_sessions/u);
  });

  it("plans all scale tenant and control DDL targets before performing cleanup", () => {
    const source = readFileSync(new URL("../scripts/performance-scale-local.ts", import.meta.url), "utf8");
    const controlPreflight = source.indexOf("state.controlNamesVerifiedUnused = true");
    const controlAttempt = source.indexOf("state.controlDatabaseCreationAttempted = true");
    const createControl = source.indexOf("CREATE DATABASE %I TEMPLATE template0");
    const controlPlan = source.indexOf("controlCleanupPlan = await inspectScaleControlCleanupOwnership(state)");
    const tenantPlan = source.indexOf("cleanupPlan = await inspectScaleCleanupOwnership", controlPlan);
    const deleteRows = source.indexOf('"DELETE FROM auth_sessions', controlPlan);
    const firstDrop = source.indexOf("dropDatabase(state.cluster, tenant)", controlPlan);
    expect(controlPreflight).toBeGreaterThanOrEqual(0);
    expect(controlAttempt).toBeGreaterThan(controlPreflight);
    expect(createControl).toBeGreaterThan(controlAttempt);
    expect(controlPlan).toBeGreaterThan(createControl);
    expect(tenantPlan).toBeGreaterThan(controlPlan);
    expect(deleteRows).toBeGreaterThan(tenantPlan);
    expect(firstDrop).toBeGreaterThan(deleteRows);
  });

  it("fingerprints every non-system schema instead of only public", () => {
    const source = readFileSync(new URL("../scripts/local-performance-protected-state.ts", import.meta.url), "utf8");
    expect(source).toContain("namespace.nspname NOT IN ('pg_catalog','information_schema')");
    expect(source).toContain("schemaname NOT IN ('pg_catalog','information_schema')");
    expect(source).not.toMatch(/namespace\.nspname='public'|schemaname='public'/u);
  });

  it("uses a generated least-privilege control runtime and a real SSE wall-clock window", () => {
    const source = readFileSync(new URL("../scripts/performance-scale-local.ts", import.meta.url), "utf8");
    expect(source).toMatch(/expectedControlRuntimeRole\(runId\)/u);
    expect(source).toMatch(/CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS/u);
    expect(source).toMatch(/GRANT UPDATE\(last_seen_at\) ON TABLE auth_sessions/u);
    expect(source).toMatch(/administratorCredentialUsedByApi:\s*false/u);
    expect(source).toMatch(/latencySummary\(allLatencies, propagationWallMs\)/u);
    expect(source).not.toMatch(/latencySummary\(allLatencies, Math\.max/u);
  });

  it("joins pg_roles configuration to boolean-only pg_authid credentials without verifier digests", () => {
    for (const script of ["local-performance-protected-state.ts", "performance-scale-local.ts"]) {
      const source = readFileSync(new URL(`../scripts/${script}`, import.meta.url), "utf8");
      expect(source).toContain("FROM pg_catalog.pg_roles role");
      expect(source).toContain("JOIN pg_catalog.pg_authid credential ON credential.oid=role.oid");
      expect(source).toContain("role.rolconfig");
      expect(source).not.toContain("credential.rolconfig");
      expect(source).toContain("credential.rolpassword IS NOT NULL AS password_present");
      expect(source.replaceAll("credential.rolpassword IS NOT NULL AS password_present", ""))
        .not.toContain("rolpassword");
      expect(source).not.toMatch(/password_(?:verifier_)?digest|md5\(COALESCE\(role\.rolpassword/iu);
    }
  });
});
