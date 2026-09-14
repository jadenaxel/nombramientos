import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  assertCompensatingAuditEvent,
  assertCompensatingOutboxEvent,
  assertDemoControlTarget,
  assertDemoFixtureManifest,
  assertDemoFixtureRepairAdminUrl,
  assertDemoFixtureRepairControlUrl,
  assertDemoFixtureSemanticSnapshot,
  assertDemoTenantTarget,
  assertExactRepairEvidence,
  assertForeignKeyReferencesAbsent,
  assertOfflineForDemoFixtureRepair,
  assertPreservedOperationalEvidence,
  assertReferenceStableCodes,
  DEMO_FIXTURE_MANIFEST,
  DEMO_FIXTURE_MEMBER_FOREIGN_KEYS,
  DEMO_FIXTURE_REFERENCE_STABLE_CODES,
  DEMO_FIXTURE_REPAIR_AUTHORIZATION,
  DEMO_FIXTURE_REPAIR_DATABASE,
  DEMO_FIXTURE_REPAIR_TARGET,
  encryptedEnvelopeHash,
  hashCanonical,
  parseDemoFixtureRepairArguments,
  type DemoFixtureSemanticSnapshot,
  type DemoRepairAuditRow,
  type DemoRepairIdempotencyRow,
  type DemoRepairMemberRow,
  type DemoRepairOutboxRow,
} from "../scripts/repair-demo-fixture-artifact-guards.js";

const envelope = {
  algorithm: "AES-256-GCM" as const,
  keyId: "tenant-key-generation-1",
  nonce: Buffer.alloc(12, 1).toString("base64url"),
  ciphertext: Buffer.alloc(32, 2).toString("base64url"),
  aad: Buffer.from(JSON.stringify({
    tenantId: "d0000000-0000-4000-8000-000000000001",
    memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    purpose: "member-display",
    schemaVersion: 1,
  })).toString("base64url"),
};
const displayHash = encryptedEnvelopeHash(envelope);
const member: DemoRepairMemberRow = {
  id: DEMO_FIXTURE_REPAIR_TARGET.memberId,
  stable_code: DEMO_FIXTURE_REPAIR_TARGET.stableCode,
  created_at: new Date(DEMO_FIXTURE_REPAIR_TARGET.createdAt),
  updated_at: new Date(DEMO_FIXTURE_REPAIR_TARGET.createdAt),
  version: 1,
  archived_at: null,
  profile_envelope: null,
  display_envelope: envelope,
  display_content_hash: displayHash,
  contact_envelope: null,
  contact_content_hash: null,
  profile_migration_required: false,
  eligibility_envelope: null,
  eligibility_status: "eligible",
  available: true,
};
const idempotencyCreatedAt = new Date(member.created_at.getTime() - 1);
const outbox: DemoRepairOutboxRow = {
  sequence: DEMO_FIXTURE_REPAIR_TARGET.outboxSequence,
  id: DEMO_FIXTURE_REPAIR_TARGET.outboxId,
  audience: "tenant.authorized",
  event_type: "member.changed",
  aggregate_type: "member",
  aggregate_id: DEMO_FIXTURE_REPAIR_TARGET.memberId,
  payload: { memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId, version: 1 },
  occurred_at: new Date(member.created_at.getTime() + 1),
  published_at: null,
};
const audit: DemoRepairAuditRow = {
  sequence: DEMO_FIXTURE_REPAIR_TARGET.auditSequence,
  id: "10000000-0000-4000-8000-000000000001",
  occurred_at: new Date(member.created_at.getTime() + 2),
  hash_version: 2,
  actor_identity_id: DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
  action: "member.created",
  entity_type: "member",
  entity_id: DEMO_FIXTURE_REPAIR_TARGET.memberId,
  result: "success",
  request_id: DEMO_FIXTURE_REPAIR_TARGET.sourceRequestId,
  metadata: { eligibilityStatus: "eligible", available: true, version: 1 },
  previous_hash: "b".repeat(64),
  event_hash: "a".repeat(64),
};
const idempotency: DemoRepairIdempotencyRow = {
  identity_id: DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
  operation: DEMO_FIXTURE_REPAIR_TARGET.idempotencyOperation,
  idempotency_key: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
  request_hash: hashCanonical({
    identityId: DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
    idempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
    memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    stableCode: DEMO_FIXTURE_REPAIR_TARGET.stableCode,
    displayEnvelope: envelope,
    displayContentHash: displayHash,
    eligibilityStatus: "eligible",
    available: true,
  }),
  response_status: 200,
  response_body: {
    id: DEMO_FIXTURE_REPAIR_TARGET.memberId,
    shortId: DEMO_FIXTURE_REPAIR_TARGET.stableCode,
    displayEnvelope: envelope,
    profileMigrationRequired: false,
    eligible: true,
    eligibilityStatus: "eligible",
    available: true,
    archived: false,
    archivedAt: null,
    currentResponsibilities: 0,
    version: 1,
    createdAt: DEMO_FIXTURE_REPAIR_TARGET.createdAt,
  },
  created_at: idempotencyCreatedAt,
  expires_at: new Date(idempotencyCreatedAt.getTime() + 86_400_000),
};

function semantic(stage: "before" | "after"): DemoFixtureSemanticSnapshot {
  return {
    members: stage === "before" ? "181" : "180",
    active_members: stage === "before" ? "181" : "180",
    eligible: stage === "before" ? "151" : "150",
    vacancies: "40",
    recommended: "20",
    accepted: "15",
    elected: "10",
    responsibilities: "20",
    responsible_people: "16",
    cycles: "3",
    reference_rounds: "20",
    seeded_submissions: "294",
    split_members: stage === "before" ? "181" : "180",
    contact_free_members: stage === "before" ? "181" : "180",
    split_cycle_snapshots: "180",
    missing_candidate_displays: "0",
    assignment_display_snapshots: "20",
    expired_seed_reports: "3",
    active_cycle_reference_eligible: "150",
  };
}

describe("targeted Demo fixture repair guards", () => {
  it("defaults to check and requires the exact non-secret authorization for apply", () => {
    expect(parseDemoFixtureRepairArguments([])).toEqual({ mode: "check" });
    expect(parseDemoFixtureRepairArguments(["--check"])).toEqual({ mode: "check" });
    expect(parseDemoFixtureRepairArguments([
      "--apply",
      `--authorization=${DEMO_FIXTURE_REPAIR_AUTHORIZATION}`,
    ])).toEqual({ mode: "apply" });
    expect(() => parseDemoFixtureRepairArguments(["--apply"])).toThrow(/authorization/u);
    expect(() => parseDemoFixtureRepairArguments(["--apply", "--authorization=yes"])).toThrow(/invalid/u);
  });

  it("accepts only the exact isolated administrator without pg URL precedence options", () => {
    expect(assertDemoFixtureRepairAdminUrl(fixtureAdminUrl()).port).toBe("55432");
    const exact = fixtureAdminUrl();
    for (const invalid of [
      fixtureAdminUrl({ host: "example.test" }),
      fixtureAdminUrl({ host: "localhost" }),
      fixtureAdminUrl({ host: "[::1]" }),
      fixtureAdminUrl({ host: "2130706433" }),
      fixtureAdminUrl({ port: 5432 }),
      fixtureAdminUrl({ user: "other" }),
      exact.replace("/postgres", "/nombramientos_control"),
      `${exact}?host=example.test`,
      `${exact}?port=5432`,
      `${exact}#external`,
      ` ${exact}`,
    ]) expect(() => assertDemoFixtureRepairAdminUrl(invalid), invalid).toThrow(/exact workspace administrator/u);
  });

  it("requires the exact nom_control workspace route without aliases or pg URL precedence options", () => {
    const exact = fixtureControlUrl();
    expect(assertDemoFixtureRepairControlUrl(exact).toString()).toBe(exact);
    for (const invalid of [
      undefined,
      fixtureControlUrl({ host: "localhost" }),
      fixtureControlUrl({ host: "[::1]" }),
      fixtureControlUrl({ host: "2130706433" }),
      fixtureControlUrl({ host: "127.0.0.1." }),
      fixtureControlUrl({ port: 5432 }),
      fixtureControlUrl({ user: "nom_admin" }),
      exact.replace("/nombramientos_control", "/postgres"),
      `${exact}?host=example.test`,
      `${exact}?port=5432`,
      `${exact}?options=-c%20search_path%3Dpublic`,
      `${exact}#external`,
      ` ${exact}`,
      `${exact} `,
    ]) expect(() => assertDemoFixtureRepairControlUrl(invalid), String(invalid)).toThrow(/exact workspace control/u);
  });

  it("binds observed control and tenant routes to literal IPv4 workspace endpoints", () => {

    const control = {
      id: "d0000000-0000-4000-8000-000000000001",
      slug: "iglesia-demostracion",
      kind: "demo",
      status: "active",
      database_host: "127.0.0.1",
      database_port: 55432,
      database_name: DEMO_FIXTURE_REPAIR_DATABASE,
      ssl_mode: "disable",
      control_database: "nombramientos_control",
      current_user: "nom_admin",
      server_address: "127.0.0.1",
      server_port: 55432,
    };
    expect(() => assertDemoControlTarget(control)).not.toThrow();
    expect(() => assertDemoControlTarget({ ...control, kind: "real" })).toThrow(/refusing all writes/u);
    for (const alias of ["localhost", "::1", "[::1]"]) {
      expect(() => assertDemoControlTarget({ ...control, database_host: alias }), alias).toThrow(/exact workspace/u);
      expect(() => assertDemoControlTarget({ ...control, server_address: alias }), alias).toThrow(/exact isolated/u);
    }
    const tenant = {
      database_name: DEMO_FIXTURE_REPAIR_DATABASE,
      tenant_id: control.id,
      kind: "demo",
      setup_state: "ready",
      current_user: "nom_admin",
      server_address: "127.0.0.1",
      server_port: 55432,
    };
    expect(() => assertDemoTenantTarget(tenant)).not.toThrow();
    for (const alias of ["localhost", "::1", "[::1]"]) {
      expect(() => assertDemoTenantTarget({ ...tenant, server_address: alias }), alias).toThrow(/exact isolated/u);
    }
  });

  it("requires stopped state, closed service ports, no competing sessions and the worker lease", () => {
    expect(() => assertOfflineForDemoFixtureRepair({
      serviceStateFilePresent: false,
      listeningPorts: [],
      unexpectedDatabaseSessions: [],
      workerLeaseAcquired: true,
    })).not.toThrow();
    expect(() => assertOfflineForDemoFixtureRepair({
      serviceStateFilePresent: false,
      listeningPorts: [4000],
      unexpectedDatabaseSessions: [],
      workerLeaseAcquired: true,
    })).toThrow(/ports/u);
    expect(() => assertOfflineForDemoFixtureRepair({
      serviceStateFilePresent: false,
      listeningPorts: [],
      unexpectedDatabaseSessions: [{ pid: 9, database: DEMO_FIXTURE_REPAIR_DATABASE, applicationName: "nombramientos-api" }],
      workerLeaseAcquired: true,
    })).toThrow(/sessions/u);
  });

  it("binds member, audit, outbox, idempotency response and both content/request hashes", () => {
    expect(() => assertExactRepairEvidence({ member, audit, outbox, idempotency })).not.toThrow();
    expect(() => assertExactRepairEvidence({
      member,
      audit,
      outbox,
      idempotency: { ...idempotency, request_hash: "0".repeat(64) },
    })).toThrow(/idempotency/u);
    expect(() => assertExactRepairEvidence({
      member: { ...member, display_content_hash: `sha256:${"0".repeat(64)}` },
      audit,
      outbox,
      idempotency,
    })).toThrow(/display_content_hash/u);
    expect(() => assertExactRepairEvidence({
      member,
      audit,
      outbox: { ...outbox, payload: { memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId, version: 2 } },
      idempotency,
    })).toThrow(/outbox/u);
  });

  it("preserves original operational evidence and validates exact compensations", () => {
    expect(() => assertPreservedOperationalEvidence({
      originalOutbox: outbox,
      observedOutbox: { ...outbox },
      originalIdempotency: idempotency,
      observedIdempotency: { ...idempotency },
    })).not.toThrow();
    expect(() => assertPreservedOperationalEvidence({
      originalOutbox: outbox,
      observedOutbox: { ...outbox, published_at: new Date() },
      originalIdempotency: idempotency,
      observedIdempotency: idempotency,
    })).toThrow(/outbox/u);

    const compensation = {
      ...outbox,
      sequence: "101",
      id: "20000000-0000-4000-8000-000000000001",
      occurred_at: new Date(audit.occurred_at.getTime() + 1),
    };
    expect(() => assertCompensatingOutboxEvent(compensation)).not.toThrow();
    expect(() => assertCompensatingAuditEvent({
      row: {
        ...audit,
        sequence: "184",
        id: "30000000-0000-4000-8000-000000000001",
        action: "test.fixture.repaired",
        request_id: "40000000-0000-4000-8000-000000000001",
        previous_hash: audit.event_hash,
        metadata: {
          reasonCode: "E2E_SERVICE_WORKER_MOCK_BYPASS",
          sourceAuditSequence: DEMO_FIXTURE_REPAIR_TARGET.auditSequence,
          sourceRequestId: DEMO_FIXTURE_REPAIR_TARGET.sourceRequestId,
          preservedOutboxId: DEMO_FIXTURE_REPAIR_TARGET.outboxId,
          preservedIdempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
          compensatingOutboxId: compensation.id,
          compensatingOutboxSequence: compensation.sequence,
          expectedFixtureMembers: 180,
          expectedEligibleMembers: 150,
        },
      },
      requestId: "40000000-0000-4000-8000-000000000001",
      previousHash: audit.event_hash,
      compensatingOutbox: compensation,
    })).not.toThrow();
  });

  it("requires all nine current FK projections, the full manifest and semantic 181→180 state", () => {
    const references = DEMO_FIXTURE_MEMBER_FOREIGN_KEYS.map((key) => ({
      table_name: key.split(".")[0]!,
      column_name: key.split(".")[1]!,
      count: "0",
    }));
    expect(() => assertForeignKeyReferencesAbsent(references)).not.toThrow();
    expect(() => assertForeignKeyReferencesAbsent(references.slice(1))).toThrow(/9 member foreign keys/u);
    expect(() => assertForeignKeyReferencesAbsent([{ ...references[0]!, count: "1" }, ...references.slice(1)])).toThrow(/contains a reference/u);
    expect(() => assertDemoFixtureManifest({
      seed_id: DEMO_FIXTURE_MANIFEST.seedId,
      version: DEMO_FIXTURE_MANIFEST.version,
      fixture_hash: DEMO_FIXTURE_MANIFEST.fixtureHash,
      metadata: DEMO_FIXTURE_MANIFEST.metadata,
      completed_at: new Date("2026-09-11T00:00:00.000Z"),
    })).not.toThrow();
    expect(() => assertReferenceStableCodes(DEMO_FIXTURE_REFERENCE_STABLE_CODES)).not.toThrow();
    expect(() => assertDemoFixtureSemanticSnapshot(semantic("before"), "before")).not.toThrow();
    expect(() => assertDemoFixtureSemanticSnapshot(semantic("after"), "after")).not.toThrow();
    expect(() => assertDemoFixtureSemanticSnapshot({ ...semantic("after"), eligible: "149" }, "after")).toThrow(/eligible/u);
  });

  it("keeps check as rollback-only and never deletes original audit, outbox or idempotency evidence", () => {
    const source = readFileSync(new URL("../scripts/repair-demo-fixture-artifact.mjs", import.meta.url), "utf8");
    const controlRouteAttestation = source.indexOf("assertDemoFixtureRepairControlUrl(environment.DATABASE_CONTROL_URL)");
    const firstClient = source.indexOf("const control = new Client");
    expect(controlRouteAttestation).toBeGreaterThanOrEqual(0);
    expect(controlRouteAttestation).toBeLessThan(firstClient);
    expect(source).toContain('command.mode === "check"');
    expect(source).toMatch(/command\.mode === "check"[\s\S]*?tenant\.query\("ROLLBACK"\)/u);
    expect(source).not.toMatch(/DELETE\s+FROM\s+(?:audit_events|outbox_events|idempotency_records)/iu);
    expect(source).toMatch(/DELETE\s+FROM\s+members/iu);
    expect(source).toMatch(/INSERT\s+INTO\s+outbox_events[\s\S]*?'member\.changed'/iu);
    expect(source).toContain("assertPreservedOperationalEvidence");
    expect(source).toContain("FROM audit_events ORDER BY audit_events.sequence");
  });
});

function fixtureAdminUrl(overrides: { readonly host?: string; readonly port?: number; readonly user?: string } = {}): string {
  const url = new URL("postgresql://127.0.0.1/postgres");
  url.username = overrides.user ?? "nom_admin";
  url.password = "local-test";
  url.hostname = overrides.host ?? "127.0.0.1";
  url.port = String(overrides.port ?? 55_432);
  return url.toString();
}

function fixtureControlUrl(overrides: { readonly host?: string; readonly port?: number; readonly user?: string } = {}): string {
  const url = new URL("postgresql://127.0.0.1/nombramientos_control");
  url.username = overrides.user ?? "nom_control";
  url.password = "local-test";
  url.hostname = overrides.host ?? "127.0.0.1";
  url.port = String(overrides.port ?? 55_432);
  return url.toString();
}
