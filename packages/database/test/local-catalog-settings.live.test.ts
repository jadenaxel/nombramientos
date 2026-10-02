import { createCipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bindDirectFixtureSession } from "./direct-device-session-fixture.js";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runMigrations } from "../src/migrations.js";
import { verifyTenantAuditEventChain, type TenantAuditEventRecord } from "../src/audit-anchors.js";
import { TenantStore } from "../src/tenant-store.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReach(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const TENANT_CONTENT_KEY_ID = "70000000-0000-4000-8000-000000000001";
const TENANT_KEY_GENERATION_ID = "70000000-0000-4000-8000-000000000002";
if (requireLive && !reachable) throw new Error("Local catalog/settings live test requires the PostgreSQL 18 workspace cluster");
const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly admin: Pool;
  readonly tenant: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly canonicalDepartmentId: string;
}

let fixture: Fixture | undefined;

live("versioned tenant settings and local catalog extensions", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("PostgreSQL administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("persists audited local CRUD, rejects stale writes, and protects canonical rows", async () => {
    const current = requireFixture();
    const client = await current.tenant.connect();
    const identityId = randomUUID();
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), randomUUID()],
      );
      const store = new TenantStore(client);
      const before = await store.getTenantSettings();
      const settings = await store.updateTenantSettings({
        identityId,
        idempotencyKey: randomUUID(),
        expectedVersion: Number(before["version"]),
        displayName: "Local test church",
        locale: "fr",
        timezone: "America/Santo_Domingo",
        jurisdiction: "Local test jurisdiction",
      });
      expect(settings).toMatchObject({
        displayName: "Local test church",
        locale: "fr",
        timezone: "America/Santo_Domingo",
        jurisdiction: "Local test jurisdiction",
        version: Number(before["version"]) + 1,
      });
      await expect(store.updateTenantSettings({
        identityId,
        idempotencyKey: randomUUID(),
        expectedVersion: Number(before["version"]),
        locale: "es",
      })).rejects.toMatchObject({ code: "VERSION_CONFLICT" });

      const department = await store.createLocalDepartment({
        identityId,
        idempotencyKey: randomUUID(),
        canonicalCode: `local.test-${randomUUID()}`,
        names: { es: "Ministerio local", en: "Local ministry", fr: "Ministère local" },
        sortOrder: 9_999,
        metadata: { source: "live-test" },
      });
      const departmentId = String(department["id"]);
      expect(department).toMatchObject({ localExtension: true, active: true, version: 1 });

      const office = await store.createLocalOffice({
        identityId,
        idempotencyKey: randomUUID(),
        departmentId,
        canonicalCode: `local.office-${randomUUID()}`,
        names: { es: "Cargo local", en: "Local office", fr: "Fonction locale" },
        appointmentMechanism: "church_election_after_nominating_report",
        cardinality: 2,
        metadata: { source: "live-test" },
      });
      expect(office).toMatchObject({ departmentId, localExtension: true, active: true, version: 1 });
      await expect(store.updateLocalOffice({
        identityId,
        idempotencyKey: randomUUID(),
        officeId: String(office["id"]),
        expectedVersion: 1,
        active: false,
      })).resolves.toMatchObject({ active: false, version: 2 });
      await expect(store.updateLocalDepartment({
        identityId,
        idempotencyKey: randomUUID(),
        departmentId,
        expectedVersion: 1,
        active: false,
      })).resolves.toMatchObject({ active: false, version: 2 });
      const activeCatalog = await store.getCatalog();
      expect(JSON.stringify(activeCatalog)).not.toContain(departmentId);
      expect(JSON.stringify(activeCatalog)).not.toContain(String(office["id"]));
      const managedCatalog = await store.getCatalog(true) as {
        departments: Array<Record<string, unknown>>; offices: Array<Record<string, unknown>>;
      };
      expect(managedCatalog.departments).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: departmentId, localExtension: true, active: false, version: 2 }),
      ]));
      expect(managedCatalog.offices).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: String(office["id"]), localExtension: true, active: false, version: 2 }),
      ]));
      await expect(store.updateLocalDepartment({
        identityId,
        idempotencyKey: randomUUID(),
        departmentId: current.canonicalDepartmentId,
        expectedVersion: 1,
        active: false,
      })).rejects.toMatchObject({ code: "CANONICAL_CATALOG_IMMUTABLE" });

      const evidence = await client.query<{ actions: string[]; event_types: string[] }>(
        `SELECT
           ARRAY(SELECT action FROM audit_events WHERE actor_identity_id=$1 ORDER BY sequence) AS actions,
           ARRAY(SELECT event_type FROM outbox_events
                  WHERE event_type IN ('tenant.settings.updated','catalog.department.created','catalog.department.updated','catalog.office.created','catalog.office.updated')
                  ORDER BY sequence) AS event_types`,
        [identityId],
      );
      const expectedEvents = [
        "tenant.settings.updated", "catalog.department.created", "catalog.department.updated",
        "catalog.office.created", "catalog.office.updated",
      ];
      expect(evidence.rows[0]?.actions).toEqual(expect.arrayContaining(expectedEvents));
      expect(evidence.rows[0]?.event_types).toEqual(expect.arrayContaining(expectedEvents));
      await client.query("COMMIT");

      const persisted = await current.tenant.query<{ active: boolean; version: number }>(
        "SELECT active,version FROM offices WHERE id=$1",
        [String(office["id"])],
      );
      expect(persisted.rows[0]).toEqual({ active: false, version: 2 });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  });

  it("archives and reactivates members durably while preserving history and rejecting effective workload", async () => {
    const current = requireFixture();
    const client = await current.tenant.connect();
    const identityId = randomUUID();
    const archivedMemberId = randomUUID();
    const assignedMemberId = randomUUID();
    const sensitiveReadRequestId = randomUUID();
    const officeId = randomUUID();
    const cycleId = randomUUID();
    const historicalAssignmentId = randomUUID();
    const historicalSnapshot = { memberId: archivedMemberId, displayEnvelope: testEnvelope("historical-member") };
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), sensitiveReadRequestId],
      );
      await grantRealTenantContentKey(client, identityId);
      const store = new TenantStore(client);
      await store.createMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId: archivedMemberId,
        stableCode: `ARCH-${archivedMemberId.slice(0, 8)}`,
        displayEnvelope: testEnvelope("archivable-member"),
        eligibilityStatus: "eligible",
        available: true,
      });
      await client.query(
        `UPDATE members
            SET eligibility_envelope=$2,contact_envelope=$3,contact_content_hash=$4
          WHERE id=$1`,
        [
          archivedMemberId,
          { privateNote: "eligibility-secret-that-must-never-leave-member-read" },
          { ciphertext: "contact-secret-that-must-never-enter-audit" },
          `sha256:${"c".repeat(64)}`,
        ],
      );
      await store.createMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId: assignedMemberId,
        stableCode: `LOAD-${assignedMemberId.slice(0, 8)}`,
        displayEnvelope: testEnvelope("assigned-member"),
        eligibilityStatus: "eligible",
        available: true,
      });
      await client.query(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,local_extension)
         VALUES ($1,$2,$3,$4,'church_election',2,true)`,
        [officeId, current.canonicalDepartmentId, `local.members-${officeId}`, { es: "Cargo", en: "Office", fr: "Fonction" }],
      );
      await client.query(
        `INSERT INTO election_cycles(id,name,status,locale,timezone,term_start,term_end,normative_version)
         VALUES ($1,'Member archive fixture','draft','es','America/Santo_Domingo','2027-01-01','2027-12-31','fixture-v1')`,
        [cycleId],
      );
      const historicalVacancyId = randomUUID();
      const effectiveVacancyId = randomUUID();
      await client.query(
        `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status)
         VALUES ($1,$3,$4,1,'elected'),($2,$3,$4,2,'elected')`,
        [historicalVacancyId, effectiveVacancyId, cycleId, officeId],
      );
      await client.query(
        `INSERT INTO assignments(
           id,vacancy_id,member_id,state,effective,cycle_id,office_id,member_snapshot,office_snapshot
         ) VALUES
           ($1,$2,$3,'FINALIZADA',false,$4,$5,$6,$7),
           ($8,$9,$10,'VIGENTE',true,$4,$5,$11,$7)`,
        [
          historicalAssignmentId,
          historicalVacancyId,
          archivedMemberId,
          cycleId,
          officeId,
          historicalSnapshot,
          { officeId, canonicalCode: `local.members-${officeId}`, names: { es: "Cargo" } },
          randomUUID(),
          effectiveVacancyId,
          assignedMemberId,
          { memberId: assignedMemberId, displayEnvelope: testEnvelope("effective-member") },
        ],
      );

      await expect(store.archiveMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId: archivedMemberId,
        expectedVersion: 1,
        reasonCode: "Personal circumstance written as prose",
      })).rejects.toMatchObject({ code: "INVALID_REASON_CODE" });
      const archiveKey = randomUUID();
      const archived = await store.archiveMember({
        identityId,
        idempotencyKey: archiveKey,
        memberId: archivedMemberId,
        expectedVersion: 1,
        reasonCode: "RECORD_LIFECYCLE_CHANGE",
      });
      expect(archived).toMatchObject({ id: archivedMemberId, version: 2, archived: true, available: false });
      await expect(store.archiveMember({
        identityId,
        idempotencyKey: archiveKey,
        memberId: archivedMemberId,
        expectedVersion: 1,
        reasonCode: "RECORD_LIFECYCLE_CHANGE",
      })).resolves.toMatchObject({ id: archivedMemberId, version: 2, archived: true, available: false });
      await expect(store.archiveMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId: assignedMemberId,
        expectedVersion: 1,
        reasonCode: "RECORD_LIFECYCLE_CHANGE",
      })).rejects.toMatchObject({ code: "MEMBER_HAS_EFFECTIVE_ASSIGNMENTS" });

      const readOutboxBefore = await client.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM outbox_events",
      );
      const ordinary = await store.listMembers(100);
      const managed = await store.listMembers(100, undefined, true);
      const ordinaryReadAudit = await client.query<{ count: number }>(
        `SELECT count(*)::int AS count FROM audit_events
          WHERE request_id=$1 AND action IN ('member.contact.read','member.private-note.read')`,
        [sensitiveReadRequestId],
      );
      expect(ordinaryReadAudit.rows[0]?.count).toBe(0);
      const privateAuthorized = await store.listMembers(100, undefined, true, true, true);
      expect(JSON.stringify(ordinary)).not.toContain("eligibility-secret-that-must-never-leave-member-read");
      expect(JSON.stringify(managed)).not.toContain("eligibility-secret-that-must-never-leave-member-read");
      expect(JSON.stringify(managed)).not.toContain("eligibilityEnvelope");
      expect((privateAuthorized["items"] as Array<Record<string, unknown>>).find(({ id }) => id === archivedMemberId))
        .toHaveProperty("eligibilityEnvelope", { privateNote: "eligibility-secret-that-must-never-leave-member-read" });
      expect((privateAuthorized["items"] as Array<Record<string, unknown>>).find(({ id }) => id === archivedMemberId))
        .toHaveProperty("contactEnvelope", { ciphertext: "contact-secret-that-must-never-enter-audit" });
      expect((ordinary["items"] as Array<Record<string, unknown>>).some(({ id }) => id === archivedMemberId)).toBe(false);
      expect(managed["items"]).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: archivedMemberId, archived: true, version: 2 }),
        expect.objectContaining({ id: assignedMemberId, archived: false, version: 1 }),
      ]));
      const sensitiveReadAudit = await client.query<{
        action: string; actor_identity_id: string | null; request_id: string | null;
        entity_type: string | null; entity_id: string | null; result: string;
        metadata: Record<string, unknown>; metadata_text: string;
      }>(
        `SELECT action,actor_identity_id,request_id,entity_type,entity_id,result,
                metadata,metadata::text AS metadata_text
           FROM audit_events
          WHERE request_id=$1 AND action IN ('member.contact.read','member.private-note.read')
          ORDER BY audit_events.sequence`,
        [sensitiveReadRequestId],
      );
      expect(sensitiveReadAudit.rows).toEqual([
        expect.objectContaining({
          action: "member.contact.read",
          actor_identity_id: identityId,
          request_id: sensitiveReadRequestId,
          entity_type: "member_roster",
          entity_id: "members",
          result: "success",
          metadata: { recordCount: 1 },
        }),
        expect.objectContaining({
          action: "member.private-note.read",
          actor_identity_id: identityId,
          request_id: sensitiveReadRequestId,
          entity_type: "member_roster",
          entity_id: "members",
          result: "success",
          metadata: { recordCount: 1 },
        }),
      ]);
      expect(sensitiveReadAudit.rows.map(({ metadata_text }) => metadata_text).join(" "))
        .not.toMatch(/eligibility-secret|contact-secret|ciphertext|nonce|aad|sha256|hash/iu);
      const readOutboxAfter = await client.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM outbox_events",
      );
      expect(readOutboxAfter.rows[0]?.count).toBe(readOutboxBefore.rows[0]?.count);
      const preservedBeforeCommit = await client.query<{ member_snapshot: Record<string, unknown> }>(
        "SELECT member_snapshot FROM assignments WHERE id=$1",
        [historicalAssignmentId],
      );
      expect(preservedBeforeCommit.rows[0]?.member_snapshot).toEqual(historicalSnapshot);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }

    const restarted = await current.tenant.connect();
    try {
      await restarted.query("BEGIN");
      await restarted.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), randomUUID()],
      );
      const store = new TenantStore(restarted);
      const persisted = await restarted.query<{
        archived: boolean; available: boolean; version: number; historical_assignments: number;
      }>(
        `SELECT archived_at IS NOT NULL AS archived,available,version,
                (SELECT count(*)::int FROM assignments WHERE member_id=$1) AS historical_assignments
           FROM members WHERE id=$1`,
        [archivedMemberId],
      );
      expect(persisted.rows[0]).toEqual({ archived: true, available: false, version: 2, historical_assignments: 1 });
      const reactivated = await store.reactivateMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId: archivedMemberId,
        expectedVersion: 2,
        reasonCode: "ARCHIVE_REVERSED",
      });
      expect(reactivated).toMatchObject({ id: archivedMemberId, version: 3, archived: false, archivedAt: null, available: false });
      const ordinary = await store.listMembers(100);
      expect(ordinary["items"]).toEqual(expect.arrayContaining([
        expect.objectContaining({ id: archivedMemberId, archived: false, eligible: false, version: 3 }),
      ]));
      const evidence = await restarted.query<{ actions: string[]; operations: string[]; metadata: string[] }>(
        `SELECT
           ARRAY(SELECT action FROM audit_events WHERE actor_identity_id=$1 AND entity_id=$2::text ORDER BY sequence) AS actions,
           ARRAY(SELECT payload->>'operation' FROM outbox_events WHERE aggregate_id=$2::uuid AND payload ? 'operation' ORDER BY sequence) AS operations,
           ARRAY(SELECT metadata::text FROM audit_events WHERE actor_identity_id=$1 AND entity_id=$2::text ORDER BY sequence) AS metadata`,
        [identityId, archivedMemberId],
      );
      expect(evidence.rows[0]?.actions).toEqual(expect.arrayContaining(["member.archived", "member.reactivated"]));
      expect(evidence.rows[0]?.operations).toEqual(expect.arrayContaining(["archived", "reactivated"]));
      expect(evidence.rows[0]?.metadata.join("\n")).toContain('"reasonCode": "RECORD_LIFECYCLE_CHANGE"');
      expect(evidence.rows[0]?.metadata.join("\n")).toContain('"reasonCode": "ARCHIVE_REVERSED"');
      expect(evidence.rows[0]?.metadata.join("\n")).not.toContain("Personal circumstance");
      await restarted.query("COMMIT");
    } catch (error) {
      await restarted.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      restarted.release();
    }
  });

  it("binds audit identifiers, sequence, and occurrence time into v2 hashes", async () => {
    const current = requireFixture();
    const client = await current.tenant.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, randomUUID(), randomUUID(), randomUUID()],
      );
      const store = new TenantStore(client);
      const before = await store.getTenantSettings();
      await store.updateTenantSettings({
        identityId: randomUUID(),
        idempotencyKey: randomUUID(),
        expectedVersion: Number(before["version"]),
        jurisdiction: "Audit v2 verification jurisdiction",
      });
      const head = await client.query<{ sequence: string; hash_version: number }>(
        "SELECT sequence::text,hash_version FROM audit_events ORDER BY audit_events.sequence DESC LIMIT 1",
      );
      expect(head.rows[0]?.hash_version).toBe(2);
      const rawAudit = await client.query<{
        sequence: string; id: string; occurred_at: Date; hash_version: 1 | 2;
        actor_identity_id: string | null; action: string; entity_type: string | null;
        entity_id: string | null; result: "success" | "denied" | "failure";
        request_id: string | null; metadata: Record<string, unknown>;
        previous_hash: string | null; event_hash: string;
      }>(
        `SELECT sequence::text,id::text,occurred_at,hash_version,actor_identity_id,action,
                entity_type,entity_id,result,request_id,metadata,previous_hash,event_hash
           FROM audit_events ORDER BY audit_events.sequence`,
      );
      const auditRecords: TenantAuditEventRecord[] = rawAudit.rows.map((event) => ({
        sequence: event.sequence, id: event.id, occurredAt: event.occurred_at.toISOString(),
        hashVersion: event.hash_version, actorIdentityId: event.actor_identity_id,
        action: event.action, entityType: event.entity_type, entityId: event.entity_id,
        result: event.result, requestId: event.request_id, metadata: event.metadata,
        previousHash: event.previous_hash, eventHash: event.event_hash,
      }));
      const verification = verifyTenantAuditEventChain(auditRecords);
      if (!verification.valid) {
        throw new Error(JSON.stringify({
          verification,
          chain: auditRecords.map(({ sequence, action, previousHash, eventHash }) => ({
            sequence, action, previousHash: previousHash?.slice(0, 12) ?? null, eventHash: eventHash.slice(0, 12),
          })),
        }));
      }
      await expect(store.listAudit(200)).resolves.toMatchObject({ verified: true });

      await client.query("SAVEPOINT tamper_timestamp");
      await client.query(
        "UPDATE audit_events SET occurred_at=occurred_at+interval '1 second' WHERE sequence=$1",
        [head.rows[0]?.sequence],
      );
      await expect(store.listAudit(200)).resolves.toMatchObject({ verified: false });
      await client.query("ROLLBACK TO SAVEPOINT tamper_timestamp");
      await expect(store.listAudit(200)).resolves.toMatchObject({ verified: true });

      await client.query("SAVEPOINT tamper_sequence");
      await client.query("ALTER TABLE audit_events ALTER COLUMN sequence DROP IDENTITY IF EXISTS");
      await client.query(
        "UPDATE audit_events SET sequence=sequence+1000 WHERE sequence=$1",
        [head.rows[0]?.sequence],
      );
      await expect(store.listAudit(200)).resolves.toMatchObject({ verified: false });
      await client.query("ROLLBACK TO SAVEPOINT tamper_sequence");
      await expect(store.listAudit(200)).resolves.toMatchObject({ verified: true });
      await client.query("ROLLBACK");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  });

  it("pauses an affected active workflow without rewriting frozen snapshots or denominators", async () => {
    const current = requireFixture();
    const client = await current.tenant.connect();
    const identityId = randomUUID();
    const memberId = randomUUID();
    const officeId = randomUUID();
    const cycleId = randomUUID();
    const processId = randomUUID();
    const roundId = randomUUID();
    const candidateId = randomUUID();
    const frozenEnvelope = testEnvelope("frozen-candidate-before-eligibility-change");
    const electorateHash = `sha256:${randomBytes(32).toString("hex")}`;
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), randomUUID()],
      );
      await grantRealTenantContentKey(client, identityId);
      const store = new TenantStore(client);
      await store.createMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId,
        stableCode: `PAUSE-${memberId.slice(0, 8)}`,
        displayEnvelope: testEnvelope("workflow-member"),
        eligibilityStatus: "eligible",
        available: true,
      });
      await client.query(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,local_extension)
         VALUES ($1,$2,$3,$4,'church_election',1,true)`,
        [officeId, current.canonicalDepartmentId, `local.pause-${officeId}`, { es: "Cargo", en: "Office", fr: "Fonction" }],
      );
      await client.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,term_start,term_end,normative_version,
           eligible_reference_count,created_by_identity_id
         ) VALUES ($1,'Eligibility pause fixture','active','es','America/Santo_Domingo',
                   '2028-01-01','2028-12-31','fixture-v1',37,$2)`,
        [cycleId, identityId],
      );
      await client.query(
        `INSERT INTO office_processes(
           id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
           decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,
           agenda_order,created_by_identity_id
         ) VALUES ($1,$2,$3,'VOTACION_ABIERTA',1,1,1,$4,
                   'EXCLUDED_FROM_CANDIDATE_TOTALS','NEW_BALLOT_ROUND',$5,'committee',1,$6)`,
        [processId, cycleId, officeId, { kind: "PLURALITY" }, { kind: "ALL_REQUIRED" }, identityId],
      );
      await client.query(
        `INSERT INTO rounds(
           id,cycle_id,office_id,phase,submission_kind,vacancies,max_selections,
           candidate_set_hash,rules_hash,process_id,workflow_stage,configuration_hash,
           electorate_hash,decision_rule
         ) VALUES ($1,$2,$3,'VOTACION_ABIERTA','vote',1,1,$4,$5,$6,'ballot',$7,$8,$9)`,
        [
          roundId, cycleId, officeId,
          `sha256:${randomBytes(32).toString("hex")}`,
          `sha256:${randomBytes(32).toString("hex")}`,
          processId,
          `sha256:${randomBytes(32).toString("hex")}`,
          electorateHash,
          { kind: "PLURALITY" },
        ],
      );
      await client.query(
        `INSERT INTO candidate_snapshots(
           round_id,candidate_id,member_id,display_envelope,eligible,visible_order,already_assigned_count,
           member_version_snapshot,eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
           eligibility_evaluated_on,eligibility_effective
         ) SELECT $1,$2,member.id,$4,true,1,0,member.version,
                  member.eligibility_department_id,member.eligibility_valid_until,
                  (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
             FROM members member CROSS JOIN tenant_settings settings
            WHERE member.id=$3 AND settings.singleton=true`,
        [roundId, candidateId, memberId, frozenEnvelope],
      );
      const changed = await store.updateMember({
        identityId,
        idempotencyKey: randomUUID(),
        memberId,
        expectedVersion: 1,
        eligibilityStatus: "ineligible",
        available: false,
      });
      expect(changed["pausedWorkflows"]).toEqual([
        expect.objectContaining({
          processId, roundId, previousProcessPhase: "VOTACION_ABIERTA",
          previousRoundPhase: "VOTACION_ABIERTA", reasonCode: "MEMBER_ELIGIBILITY_CHANGED",
        }),
      ]);
      const state = await client.query<{
        process_phase: string; process_version: number; round_phase: string; round_version: number;
        eligible_reference_count: number; electorate_hash: string; display_envelope: EncryptedEnvelope;
        snapshot_eligible: boolean; pauses: number; audit_actions: string[]; outbox_events: string[];
      }>(
        `SELECT process.phase AS process_phase,process.version AS process_version,
                round_state.phase AS round_phase,round_state.version AS round_version,
                cycle.eligible_reference_count,round_state.electorate_hash,snapshot.display_envelope,
                snapshot.eligible AS snapshot_eligible,
                (SELECT count(*)::int FROM member_eligibility_workflow_pauses pause
                  WHERE pause.process_id=process.id AND pause.member_id=$4 AND pause.resolved_at IS NULL) AS pauses,
                ARRAY(SELECT action FROM audit_events WHERE entity_id=process.id::text ORDER BY sequence) AS audit_actions,
                ARRAY(SELECT event_type FROM outbox_events WHERE aggregate_id=process.id ORDER BY sequence) AS outbox_events
           FROM office_processes process
           JOIN election_cycles cycle ON cycle.id=process.cycle_id
           JOIN rounds round_state ON round_state.process_id=process.id
           JOIN candidate_snapshots snapshot ON snapshot.round_id=round_state.id
          WHERE process.id=$1 AND round_state.id=$2 AND snapshot.candidate_id=$3`,
        [processId, roundId, candidateId, memberId],
      );
      expect(state.rows[0]).toMatchObject({
        process_phase: "PAUSADO",
        process_version: 2,
        round_phase: "PAUSADO",
        round_version: 2,
        eligible_reference_count: 37,
        electorate_hash: electorateHash,
        display_envelope: frozenEnvelope,
        snapshot_eligible: true,
        pauses: 1,
        audit_actions: expect.arrayContaining(["workflow.paused"]),
        outbox_events: expect.arrayContaining(["workflow.paused"]),
      });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  });

  it("moves report issuance through pending, durable ready or failed states with exact artifacts", async () => {
    const current = requireFixture();
    const identityId = randomUUID();
    const plaintextSentinel = "PLAINTEXT_REPORT_SENTINEL_NEVER_PERSIST";
    let readyReportId = "";
    let envelope!: EncryptedEnvelope;
    let artifactSha256 = "";
    let ciphertextSha256 = "";
    let plaintextBytes = 0;
    let correctionReportId = "";
    let correctionEnvelope!: EncryptedEnvelope;
    let correctionArtifactSha256 = "";
    let correctionCiphertextSha256 = "";
    let correctionPlaintextBytes = 0;
    const client = await current.tenant.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), randomUUID()],
      );
      await grantRealTenantContentKey(client, identityId);
      const store = new TenantStore(client);
      const rosterExportKey = randomUUID();
      const rosterSelectionSha256 = `sha256:${randomBytes(32).toString("hex")}`;
      const rosterAuthorizationInput = {
        identityId,
        idempotencyKey: rosterExportKey,
        format: "xlsx" as const,
        rowCount: 3,
        includeContact: false,
        filters: { status: "active" as const, queryApplied: true },
        selectionSha256: rosterSelectionSha256,
      };
      const rosterAuthorization = await store.authorizeMemberExport(rosterAuthorizationInput);
      expect(rosterAuthorization).toMatchObject({
        format: "xlsx",
        rowCount: 3,
        selectionSha256: rosterSelectionSha256,
      });
      expect(Date.parse(rosterAuthorization.expiresAt) - Date.parse(rosterAuthorization.authorizedAt)).toBe(5 * 60_000);
      await expect(store.authorizeMemberExport(rosterAuthorizationInput)).resolves.toEqual(rosterAuthorization);
      const rosterAudit = await client.query<{ action: string; metadata: Record<string, unknown> }>(
        "SELECT action,metadata FROM audit_events WHERE entity_id=$1 ORDER BY sequence",
        [rosterAuthorization.authorizationId],
      );
      expect(rosterAudit.rows).toEqual([expect.objectContaining({
        action: "member.roster_export.authorized",
        metadata: expect.objectContaining({
          format: "xlsx",
          rowCount: 3,
          filters: { status: "active", queryApplied: true },
          selectionSha256: rosterSelectionSha256,
        }),
      })]);
      const snapshotSha256 = `sha256:${randomBytes(32).toString("hex")}`;
      const pending = await store.generateReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportType: "cycle_summary",
        audience: "committee",
        locale: "es",
        format: "csv",
        filters: { snapshotSha256, snapshotAt: "2026-09-11T12:00:00.000Z" },
      });
      readyReportId = String(pending["id"]);
      const plaintext = Buffer.from(`${plaintextSentinel}\r\nrow,one\r\n`, "utf8");
      plaintextBytes = plaintext.byteLength;
      const aadObject = {
        tenantId: current.tenantId,
        reportId: readyReportId,
        requestVersion: 1,
        reportType: "cycle_summary",
        audience: "committee",
        locale: "es",
        format: "csv",
        filename: String(pending["filename"]),
        mediaType: String(pending["mediaType"]),
        snapshotSha256,
        purpose: "report-artifact",
        schemaVersion: 1,
        plaintextBytes,
      };
      const aadBytes = Buffer.from(JSON.stringify(aadObject), "utf8");
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", randomBytes(32), nonce);
      cipher.setAAD(aadBytes);
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
        cipher.getAuthTag(),
      ]);
      envelope = {
        algorithm: "AES-256-GCM",
        keyId: TENANT_CONTENT_KEY_ID,
        nonce: nonce.toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
        aad: aadBytes.toString("base64url"),
      };
      ciphertextSha256 = `sha256:${createHash("sha256").update(ciphertext).digest("hex")}`;
      artifactSha256 = `sha256:${createHash("sha256").update(JSON.stringify(envelope), "utf8").digest("hex")}`;
      expect(pending).toMatchObject({ id: readyReportId, state: "pending", version: 1, readyAt: null });
      const pendingRow = await client.query<{
        state: string; artifact_bytes: Buffer | null; ready_at: Date | null;
      }>("SELECT state,artifact_bytes,ready_at FROM report_versions WHERE id=$1", [readyReportId]);
      expect(pendingRow.rows[0]).toEqual({ state: "pending", artifact_bytes: null, ready_at: null });

      await expect(store.completeReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportId: readyReportId,
        expectedVersion: 1,
        envelope,
        artifactSha256,
        ciphertextSha256: `sha256:${"0".repeat(64)}`,
        plaintextBytes,
        rowCount: 1,
        generatedAt: "2026-09-11T12:01:00.000Z",
      })).rejects.toMatchObject({ code: "REPORT_CIPHERTEXT_DIGEST_MISMATCH" });
      const completionKey = randomUUID();
      const completionInput = {
        identityId,
        idempotencyKey: completionKey,
        reportId: readyReportId,
        expectedVersion: 1,
        envelope,
        artifactSha256,
        ciphertextSha256,
        plaintextBytes,
        rowCount: 1,
        generatedAt: "2026-09-11T12:01:00.000Z",
      };
      const ready = await store.completeReport(completionInput);
      expect(ready).toMatchObject({
        id: readyReportId, state: "ready", version: 2, artifactSha256, ciphertextSha256,
        plaintextBytes,
        manifest: { snapshotSha256, rowCount: 1, artifactSha256, ciphertextSha256 },
      });
      await expect(store.completeReport(completionInput)).resolves.toMatchObject({
        id: readyReportId, state: "ready", version: 2, artifactSha256, ciphertextSha256,
      });

      const correctionSnapshotSha256 = `sha256:${randomBytes(32).toString("hex")}`;
      const correctionFilters = {
        snapshotSha256: correctionSnapshotSha256,
        snapshotAt: "2026-09-12T12:03:00.000Z",
      };
      await client.query("SAVEPOINT invalid_correction_scope");
      try {
        await expect(store.correctReport({
          identityId,
          idempotencyKey: randomUUID(),
          previousReportId: readyReportId,
          expectedPreviousVersion: 2,
          reasonCode: "AUTHORIZED_CORRECTION",
          filters: { ...correctionFilters, cycleId: randomUUID() },
        })).rejects.toMatchObject({ code: "REPORT_CORRECTION_SCOPE_MISMATCH" });
      } finally {
        await client.query("ROLLBACK TO SAVEPOINT invalid_correction_scope");
        await client.query("RELEASE SAVEPOINT invalid_correction_scope");
      }

      const correctionKey = randomUUID();
      const correctionInput = {
        identityId,
        idempotencyKey: correctionKey,
        previousReportId: readyReportId,
        expectedPreviousVersion: 2,
        reasonCode: "SOURCE_DATA_CORRECTED",
        filters: correctionFilters,
      } as const;
      const correctionPending = await store.correctReport(correctionInput);
      correctionReportId = correctionPending.id;
      expect(correctionPending).toMatchObject({
        state: "pending",
        version: 1,
        reportType: "cycle_summary",
        audience: "committee",
        locale: "es",
        format: "csv",
        supersedesReportId: readyReportId,
        correctedByReportId: null,
        correctionReasonCode: "SOURCE_DATA_CORRECTED",
        lineageRootId: readyReportId,
        lineageRevision: 2,
      });
      await expect(store.correctReport(correctionInput)).resolves.toMatchObject({
        ...correctionPending,
        createdAt: correctionPending.createdAt.toISOString(),
      });

      await client.query("SAVEPOINT branched_correction");
      try {
        await expect(store.correctReport({ ...correctionInput, idempotencyKey: randomUUID() }))
          .rejects.toMatchObject({ code: "REPORT_ALREADY_CORRECTED" });
      } finally {
        await client.query("ROLLBACK TO SAVEPOINT branched_correction");
        await client.query("RELEASE SAVEPOINT branched_correction");
      }

      const correctionPlaintext = Buffer.from("CORRECTED_REPORT_CONTENT\r\nrow,two\r\n", "utf8");
      correctionPlaintextBytes = correctionPlaintext.byteLength;
      const correctionAadObject = {
        tenantId: current.tenantId,
        reportId: correctionReportId,
        requestVersion: 1,
        reportType: "cycle_summary",
        audience: "committee",
        locale: "es",
        format: "csv",
        filename: correctionPending.filename,
        mediaType: correctionPending.mediaType,
        snapshotSha256: correctionSnapshotSha256,
        supersedesReportId: readyReportId,
        correctionReasonCode: "SOURCE_DATA_CORRECTED",
        lineageRootId: readyReportId,
        lineageRevision: 2,
        purpose: "report-artifact",
        schemaVersion: 1,
        plaintextBytes: correctionPlaintextBytes,
      };
      const correctionAadBytes = Buffer.from(JSON.stringify(correctionAadObject), "utf8");
      const correctionNonce = randomBytes(12);
      const correctionCipher = createCipheriv("aes-256-gcm", randomBytes(32), correctionNonce);
      correctionCipher.setAAD(correctionAadBytes);
      const correctionCiphertext = Buffer.concat([
        correctionCipher.update(correctionPlaintext),
        correctionCipher.final(),
        correctionCipher.getAuthTag(),
      ]);
      correctionEnvelope = {
        algorithm: "AES-256-GCM",
        keyId: TENANT_CONTENT_KEY_ID,
        nonce: correctionNonce.toString("base64url"),
        ciphertext: correctionCiphertext.toString("base64url"),
        aad: correctionAadBytes.toString("base64url"),
      };
      correctionCiphertextSha256 = `sha256:${createHash("sha256").update(correctionCiphertext).digest("hex")}`;
      correctionArtifactSha256 = `sha256:${createHash("sha256").update(JSON.stringify(correctionEnvelope), "utf8").digest("hex")}`;
      const correctionReady = await store.completeReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportId: correctionReportId,
        expectedVersion: 1,
        envelope: correctionEnvelope,
        artifactSha256: correctionArtifactSha256,
        ciphertextSha256: correctionCiphertextSha256,
        plaintextBytes: correctionPlaintextBytes,
        rowCount: 1,
        generatedAt: "2026-09-12T12:04:00.000Z",
      });
      expect(correctionReady).toMatchObject({
        id: correctionReportId,
        state: "ready",
        version: 2,
        supersedesReportId: readyReportId,
        correctionReasonCode: "SOURCE_DATA_CORRECTED",
        lineageRootId: readyReportId,
        lineageRevision: 2,
        manifest: {
          supersedesReportId: readyReportId,
          correctionReasonCode: "SOURCE_DATA_CORRECTED",
          lineageRootId: readyReportId,
          lineageRevision: 2,
        },
      });

      await client.query("SAVEPOINT immutable_report_lineage");
      try {
        await expect(client.query("UPDATE report_versions SET lineage_revision=99 WHERE id=$1", [correctionReportId]))
          .rejects.toMatchObject({ code: "23514" });
      } finally {
        await client.query("ROLLBACK TO SAVEPOINT immutable_report_lineage");
        await client.query("RELEASE SAVEPOINT immutable_report_lineage");
      }
      const unchangedRoot = await client.query<{ artifact_sha256: string; ciphertext_sha256: string }>(
        "SELECT artifact_sha256,ciphertext_sha256 FROM report_versions WHERE id=$1",
        [readyReportId],
      );
      expect(unchangedRoot.rows[0]).toEqual({ artifact_sha256: artifactSha256, ciphertext_sha256: ciphertextSha256 });
      const correctionAudit = await client.query<{ action: string; metadata: Record<string, unknown>; metadata_text: string }>(
        "SELECT action,metadata,metadata::text AS metadata_text FROM audit_events WHERE entity_id=$1 ORDER BY sequence",
        [correctionReportId],
      );
      expect(correctionAudit.rows).toEqual(expect.arrayContaining([expect.objectContaining({
        action: "report.correction_requested",
        metadata: {
          previousReportId: readyReportId,
          lineageRootId: readyReportId,
          lineageRevision: 2,
          reasonCode: "SOURCE_DATA_CORRECTED",
        },
      })]));
      expect(correctionAudit.rows.map((row) => row.metadata_text).join(" ")).not.toContain("CORRECTED_REPORT_CONTENT");
      await expect(store.failReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportId: readyReportId,
        expectedVersion: 1,
        errorCode: "TOO_LATE",
      })).rejects.toMatchObject({ code: "REPORT_STATE_CONFLICT" });

      const pendingFailure = await store.generateReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportType: "cycle_summary",
        audience: "auditor",
        locale: "en",
        format: "pdf",
        filters: { snapshotSha256: `sha256:${randomBytes(32).toString("hex")}`, snapshotAt: "2026-09-11T12:02:00.000Z" },
      });
      const failed = await store.failReport({
        identityId,
        idempotencyKey: randomUUID(),
        reportId: String(pendingFailure["id"]),
        expectedVersion: 1,
        errorCode: "CLIENT_GENERATION_FAILED",
      });
      expect(failed).toMatchObject({ state: "failed", version: 2, errorCode: "CLIENT_GENERATION_FAILED" });
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }

    const restarted = await current.tenant.connect();
    try {
      await restarted.query("BEGIN");
      await restarted.query(
        `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
        [current.tenantId, identityId, randomUUID(), randomUUID()],
      );
      const store = new TenantStore(restarted);
      const artifact = await store.getReportArtifact(readyReportId, ["cycle_summary:committee"]);
      expect(artifact).toMatchObject({ artifactSha256, ciphertextSha256, plaintextBytes, reportType: "cycle_summary", audience: "committee", envelope });
      const correctionArtifact = await store.getReportArtifact(correctionReportId, ["cycle_summary:committee"]);
      expect(correctionArtifact).toMatchObject({
        artifactSha256: correctionArtifactSha256,
        ciphertextSha256: correctionCiphertextSha256,
        plaintextBytes: correctionPlaintextBytes,
        reportType: "cycle_summary",
        audience: "committee",
        envelope: correctionEnvelope,
        supersedesReportId: readyReportId,
        correctionReasonCode: "SOURCE_DATA_CORRECTED",
        lineageRootId: readyReportId,
        lineageRevision: 2,
      });
      const persisted = await restarted.query<{
        artifact_bytes_is_null: boolean; envelope_has_plaintext: boolean;
      }>(
        `SELECT artifact_bytes IS NULL AS artifact_bytes_is_null,
                artifact_envelope::text LIKE '%' || $2 || '%' AS envelope_has_plaintext
           FROM report_versions WHERE id=$1`,
        [readyReportId, plaintextSentinel],
      );
      expect(persisted.rows[0]).toEqual({ artifact_bytes_is_null: true, envelope_has_plaintext: false });
      const printKey = randomUUID();
      const printed = await store.recordReportPrint({
        identityId,
        idempotencyKey: printKey,
        reportId: readyReportId,
        artifactSha256,
        permittedReportScopes: ["cycle_summary:committee"],
      });
      expect(printed).toMatchObject({ id: readyReportId, artifactSha256 });
      await expect(store.recordReportPrint({
        identityId,
        idempotencyKey: printKey,
        reportId: readyReportId,
        artifactSha256,
        permittedReportScopes: ["cycle_summary:committee"],
      })).resolves.toMatchObject({ id: readyReportId, artifactSha256 });
      const history = await store.listReports(10, ["cycle_summary:committee", "cycle_summary:auditor"]);
      expect(history).toEqual(expect.arrayContaining([
        expect.objectContaining({
          id: readyReportId, state: "ready", version: 2, artifactSha256, ciphertextSha256,
          plaintextBytes, ciphertextBytes: plaintextBytes + 16, manifest: expect.objectContaining({ rowCount: 1 }),
          supersedesReportId: null, correctedByReportId: correctionReportId,
          lineageRootId: readyReportId, lineageRevision: 1,
        }),
        expect.objectContaining({
          id: correctionReportId, state: "ready", version: 2,
          artifactSha256: correctionArtifactSha256, ciphertextSha256: correctionCiphertextSha256,
          supersedesReportId: readyReportId, correctedByReportId: null,
          correctionReasonCode: "SOURCE_DATA_CORRECTED",
          lineageRootId: readyReportId, lineageRevision: 2,
        }),
        expect.objectContaining({ state: "failed", version: 2, errorCode: "CLIENT_GENERATION_FAILED" }),
      ]));
      const evidence = await restarted.query<{ actions: string[]; events: string[] }>(
        `SELECT
           ARRAY(SELECT action FROM audit_events WHERE entity_id=$1::text ORDER BY sequence) AS actions,
           ARRAY(SELECT event_type FROM outbox_events WHERE aggregate_id=$1::uuid ORDER BY sequence) AS events`,
        [readyReportId],
      );
      expect(evidence.rows[0]?.actions).toEqual(expect.arrayContaining(["report.ready", "report.downloaded", "report.printed"]));
      expect(evidence.rows[0]?.events).toEqual(expect.arrayContaining(["report.requested", "report.ready", "report.printed"]));
      expect(evidence.rows[0]?.events).not.toContain("report.downloaded");
      const downloadAudit = await restarted.query<{
        actor_identity_id: string | null; request_id: string | null;
        entity_type: string | null; entity_id: string | null;
        metadata: Record<string, unknown>; metadata_text: string;
      }>(
        `SELECT actor_identity_id,request_id,entity_type,entity_id,metadata,metadata::text AS metadata_text
           FROM audit_events
          WHERE entity_id=$1::text AND action='report.downloaded'
          ORDER BY audit_events.sequence`,
        [readyReportId],
      );
      expect(downloadAudit.rows).toEqual([
        expect.objectContaining({
          actor_identity_id: identityId,
          request_id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
          entity_type: "report",
          entity_id: readyReportId,
          metadata: {
            reportType: "cycle_summary",
            audience: "committee",
            format: "csv",
            version: 2,
            lineageRevision: 1,
          },
        }),
      ]);
      expect(downloadAudit.rows[0]?.metadata_text)
        .not.toMatch(/ciphertext|nonce|aad|artifactSha256|ciphertextSha256|sha256|identityId/iu);
      await restarted.query("COMMIT");
    } catch (error) {
      await restarted.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      restarted.release();
    }
  });
});

async function createFixture(connectionString: string): Promise<Fixture> {
  const admin = new Pool({ connectionString, max: 1 });
  const databaseName = `nom_test_catalog_${randomBytes(6).toString("hex")}`;
  let tenant: Pool | undefined;
  try {
    assertLocalCatalogDatabaseName(databaseName);
    const formatted = await admin.query<{ sql: string }>("SELECT format('CREATE DATABASE %I', $1::text) AS sql", [databaseName]);
    const createSql = formatted.rows[0]?.sql;
    if (!createSql) throw new Error("PostgreSQL did not format the local-catalog test database statement");
    await admin.query(createSql);
    const tenantUrl = new URL(connectionString);
    tenantUrl.pathname = `/${databaseName}`;
    tenant = new Pool({ connectionString: tenantUrl.toString(), max: 2 });
    const tenantId = randomUUID();
    await runMigrations(tenant, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
    await tenant.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version)
       VALUES ($1,'Fixture church','real','America/Santo_Domingo','es','ready','fixture-v1')`,
      [tenantId],
    );
    await tenant.query(
      `INSERT INTO e2ee_key_generations(
         id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,created_by_identity_id
       ) VALUES ($1,$2,1,'active','{}'::jsonb,$3,$4)`,
      [TENANT_KEY_GENERATION_ID, TENANT_CONTENT_KEY_ID, `sha256:${randomBytes(32).toString("hex")}`, randomUUID()],
    );
    const canonicalDepartmentId = randomUUID();
    await tenant.query(
      `INSERT INTO departments(id,canonical_code,names,local_extension,active,sort_order,version)
       VALUES ($1,'canonical.fixture',$2,false,true,1,1)`,
      [canonicalDepartmentId, { es: "Canónico", en: "Canonical", fr: "Canonique" }],
    );
    return { admin, tenant, databaseName, tenantId, canonicalDepartmentId };
  } catch (error) {
    return cleanupAfterFailure(
      error,
      () => cleanupLocalCatalogDatabase(admin, tenant, databaseName),
      "Local-catalog fixture setup",
    );
  }
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupLocalCatalogDatabase(current.admin, current.tenant, current.databaseName);
}

async function cleanupLocalCatalogDatabase(
  admin: Pool,
  tenant: Pool | undefined,
  databaseName: string,
): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: admin,
    targets: [{
      databaseName,
      databasePools: tenant ? [tenant] : [],
      assertSafeDatabaseName: assertLocalCatalogDatabaseName,
    }],
    label: "Temporary local-catalog database",
  });
}

function assertLocalCatalogDatabaseName(databaseName: string): void {
  if (!/^nom_test_catalog_[0-9a-f]{12}$/u.test(databaseName)) {
    throw new Error("Refusing to clean up a non-local-catalog-test database");
  }
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Local catalog/settings fixture is unavailable");
  return fixture;
}

function discoverAdminUrl(): string | undefined {
  if (!existsSync(installFile)) return undefined;
  const parsed = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: string };
  if (!parsed.DATABASE_ADMIN_URL) return undefined;
  try {
    return assertWorkspacePostgresUrl(parsed.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReach(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_000 });
  try {
    const result = await pool.query<{ version: string }>("SELECT current_setting('server_version') AS version");
    return result.rows[0]?.version.startsWith("18.") ?? false;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

function testEnvelope(label: string): EncryptedEnvelope {
  return {
    algorithm: "AES-256-GCM",
    keyId: TENANT_CONTENT_KEY_ID,
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: Buffer.from(label.padEnd(24, "-")).toString("base64url"),
    aad: Buffer.from(JSON.stringify({ purpose: "member-archive-live-test", label })).toString("base64url"),
  };
}

async function grantRealTenantContentKey(client: import("pg").PoolClient, identityId: string): Promise<void> {
  const deviceId = randomUUID();
  await client.query(
    `INSERT INTO e2ee_key_devices(
       device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,status,activated_at
     ) VALUES ($1,$2,'Local catalog test device','{}'::jsonb,$3,'active',clock_timestamp())`,
    [deviceId, identityId, `sha256:${randomBytes(32).toString("hex")}`],
  );
  await client.query(
    `INSERT INTO e2ee_key_grants(
       generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,status,granted_by_identity_id
     ) VALUES ($1,$2,$3,'{}'::jsonb,$4,'initial','active',$2)`,
    [TENANT_KEY_GENERATION_ID, identityId, deviceId, `sha256:${randomBytes(32).toString("hex")}`],
  );
  await bindDirectFixtureSession(client, deviceId);
}
