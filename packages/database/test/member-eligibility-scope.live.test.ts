import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bindDirectFixtureSession } from "./direct-device-session-fixture.js";
import type { PoolClient } from "pg";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { CoreWorkflowStore } from "../src/core-workflow-store.js";
import { CustodyStore } from "../src/custody-store.js";
import {
  acquireMemberEligibilityPolicySharedLock,
} from "../src/member-eligibility-guard.js";
import { runMigrations } from "../src/migrations.js";
import { TenantStore } from "../src/tenant-store.js";
import type { EncryptedEnvelope } from "../src/types.js";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const DEMO_DATABASE_NAME = "nom_t_d0000000000040008000000000000001";
const OZAMA_DATABASE_NAME = "nom_t_0a2a0000000040008000000000000001";
const PERSISTENT_DATABASE_NAMES = new Set([DEMO_DATABASE_NAME, OZAMA_DATABASE_NAME]);
const ELIGIBILITY_SCRATCH_DATABASE_PATTERN = /^nom_test_eligibility_([0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15})$/u;
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReach(adminUrl) : false;
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";

if (requireLive && !reachable) {
  throw new Error("Member eligibility scope test requires PostgreSQL 18 on isolated loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

describe("member eligibility scratch database guard", () => {
  it("accepts only its dedicated UUID-v4 namespace and can never match persistent tenant names", () => {
    const scratchName = eligibilityScratchDatabaseName(randomUUID());
    expect(() => assertEligibilityScratchDatabaseName(scratchName)).not.toThrow();
    expect(ELIGIBILITY_SCRATCH_DATABASE_PATTERN.test(scratchName)).toBe(true);

    for (const persistentName of PERSISTENT_DATABASE_NAMES) {
      expect(ELIGIBILITY_SCRATCH_DATABASE_PATTERN.test(persistentName)).toBe(false);
      expect(() => assertEligibilityScratchDatabaseName(persistentName)).toThrow(/non-scratch database/u);
    }
    expect(() => assertEligibilityScratchDatabaseName(`nom_t_${randomUUID().replaceAll("-", "")}`)).toThrow(/non-scratch database/u);
    expect(() => assertEligibilityScratchDatabaseName("nom_test_eligibility_d0000000000000008000000000000001")).toThrow(/UUID-v4/u);
  });
});

live("member department and tenant-date eligibility enforcement", () => {
  it("excludes the wrong department, snapshots the decision, pauses mutations, and blocks submission", async () => {
    if (!adminUrl) throw new Error("Local administrator URL is unavailable");
    const databaseName = eligibilityScratchDatabaseName(randomUUID());
    const admin = new Pool({ connectionString: adminUrl, max: 1, connectionTimeoutMillis: 5_000 });
    let tenant: Pool | undefined;
    await runWithCleanup(async () => {
      await createDatabase(admin, databaseName);
      const tenantUrl = new URL(adminUrl);
      tenantUrl.pathname = `/${databaseName}`;
      tenant = new Pool({ connectionString: tenantUrl.toString(), max: 4, connectionTimeoutMillis: 5_000 });
      const applied = await runMigrations(tenant, {
        scope: "tenant",
        directory: path.join(packageRoot, "migrations", "tenant"),
      });
      expect(applied).toContain("030_member_eligibility_scope.sql");
      expect(applied).toContain("031_member_eligibility_policy_guards.sql");

      const tenantId = randomUUID();
      const actorId = randomUUID();
      const tenantKeyId = randomUUID();
      const keyGenerationId = randomUUID();
      const keyDeviceId = randomUUID();
      const cycleId = randomUUID();
      const departmentA = randomUUID();
      const departmentB = randomUUID();
      const officeA = randomUUID();
      const processId = randomUUID();
      const restrictedElsewhere = randomUUID();
      const eligibleHere = randomUUID();
      const assignmentMember = randomUUID();
      await tenant.query(
        `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state,catalog_version)
         VALUES ($1,'Eligibility scratch','real','America/La_Paz','es','ready','eligibility-test-v1')`,
        [tenantId],
      );
      await tenant.query(
        `INSERT INTO e2ee_key_devices(
           device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,status,activated_at
         ) VALUES ($1,$2,'Eligibility test device','{}'::jsonb,$3,'active',clock_timestamp())`,
        [keyDeviceId, actorId, `sha256:${randomBytes(32).toString("hex")}`],
      );
      await tenant.query(
        `INSERT INTO e2ee_key_generations(
           id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,created_by_identity_id
         ) VALUES ($1,$2,1,'active','{}'::jsonb,$3,$4)`,
        [keyGenerationId, tenantKeyId, `sha256:${randomBytes(32).toString("hex")}`, actorId],
      );
      await tenant.query(
        `INSERT INTO e2ee_key_grants(
           generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,status,granted_by_identity_id
         ) VALUES ($1,$2,$3,'{}'::jsonb,$4,'initial','active',$2)`,
        [keyGenerationId, actorId, keyDeviceId, `sha256:${randomBytes(32).toString("hex")}`],
      );
      await tenant.query(
        `INSERT INTO departments(id,canonical_code,names,local_extension) VALUES
         ($1,'ELIGIBILITY_A',$3,true),($2,'ELIGIBILITY_B',$3,true)`,
        [departmentA, departmentB, { es: "Departamento", en: "Department", fr: "Département" }],
      );
      await tenant.query(
        `INSERT INTO offices(id,department_id,canonical_code,names,appointment_mechanism,cardinality,local_extension)
         VALUES ($1,$2,'ELIGIBILITY_OFFICE_A',$3,'church_election_after_nominating_report',1,true)`,
        [officeA, departmentA, { es: "Cargo", en: "Office", fr: "Fonction" }],
      );
      for (const [index, memberId, restriction] of [
        [1, restrictedElsewhere, departmentB],
        [2, eligibleHere, departmentA],
        [3, assignmentMember, null],
      ] as const) {
        const displayEnvelope = memberDisplayEnvelope(tenantId, memberId, tenantKeyId);
        await tenant.query(
          `INSERT INTO members(
             id,stable_code,display_envelope,display_content_hash,eligibility_status,available,
             eligibility_department_id,eligibility_valid_until
           ) VALUES ($1,$2,$3,$4,'eligible',true,$5,'2099-12-31')`,
          [memberId, `ELIGIBILITY-${index}`, displayEnvelope, envelopeHash(displayEnvelope), restriction],
        );
      }
      await tenant.query(
        `INSERT INTO election_cycles(
           id,name,status,locale,timezone,term_start,term_end,normative_version,created_by_identity_id
         ) VALUES ($1,'Eligibility cycle','active','es','America/La_Paz','2098-01-01','2099-12-31','eligibility-test-v1',$2)`,
        [cycleId, actorId],
      );
      for (const [memberId, restriction] of [
        [restrictedElsewhere, departmentB],
        [eligibleHere, departmentA],
      ] as const) {
        await tenant.query(
          `INSERT INTO cycle_member_snapshots(
             cycle_id,member_id,member_version,eligibility_status,available,display_envelope,
             eligibility_department_id_snapshot,eligibility_valid_until_snapshot,
             eligibility_evaluated_on,eligibility_effective
           ) SELECT $1,member.id,member.version,'eligible',true,member.display_envelope,$3,'2099-12-31',
                    (clock_timestamp() AT TIME ZONE settings.timezone)::date,true
               FROM members member CROSS JOIN tenant_settings settings
              WHERE member.id=$2 AND settings.singleton=true`,
          [cycleId, memberId, restriction],
        );
      }
      await tenant.query(
        `INSERT INTO cycle_elector_roster(
           cycle_id,identity_id,can_propose,can_vote,recused,active,configured_by_identity_id
         ) VALUES ($1,$2,true,true,false,true,$2)`,
        [cycleId, actorId],
      );
      await tenant.query(
        `INSERT INTO office_processes(
           id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
           decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,
           agenda_order,created_by_identity_id
         ) VALUES ($1,$2,$3,'CONFIGURADO',1,1,1,$4,'EXCLUDED_FROM_CANDIDATE_TOTALS',
                   'NEW_BALLOT_ROUND',$5,'committee',1,$6)`,
        [processId, cycleId, officeA, { kind: "PLURALITY" }, { kind: "ALL_REQUIRED" }, actorId],
      );
      await tenant.query(
        `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id)
         VALUES ($1,$2,$3,1,'pending',$4)`,
        [randomUUID(), cycleId, officeA, processId],
      );

      const prepared = await withStore(tenant, tenantId, actorId, (client) => new CoreWorkflowStore(client).createProposalRound({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        processId,
        expectedProcessVersion: 1,
      }));
      const roundId = String(prepared["roundId"]);
      const frozen = await tenant.query<{
        member_id: string;
        eligibility_department_id_snapshot: string | null;
        eligibility_valid_until_snapshot: string | null;
        eligibility_effective: boolean;
      }>(
        `SELECT member_id,eligibility_department_id_snapshot,
                to_char(eligibility_valid_until_snapshot,'YYYY-MM-DD') AS eligibility_valid_until_snapshot,
                eligibility_effective
           FROM candidate_snapshots WHERE round_id=$1`,
        [roundId],
      );
      expect(frozen.rows).toEqual([{
        member_id: eligibleHere,
        eligibility_department_id_snapshot: departmentA,
        eligibility_valid_until_snapshot: "2099-12-31",
        eligibility_effective: true,
      }]);

      const importedDisplay = memberDisplayEnvelope(tenantId, eligibleHere, tenantKeyId);
      const preview = await withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).previewImport({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        sourceFingerprint: `sha256:${"b".repeat(64)}`,
        sourceFileName: "roster.csv",
        sourceSheetName: `sheet-sha256:${"c".repeat(64)}`,
        columnMapping: { displayName: 0, eligible: 1 },
        rows: [{
          sourceRow: 2,
          id: eligibleHere,
          shortId: "ELIGIBILITY-2",
          eligible: false,
          decision: { action: "update", matchBasis: "stable_id" },
          expectedVersion: 1,
          displayEnvelope: importedDisplay,
          displayContentHash: envelopeHash(importedDisplay),
        }],
      }));
      const committed = await withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).commitImport({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        importId: String(preview["importId"]),
        expectedRevision: Number(preview["revision"]),
      }));
      expect(committed).toMatchObject({
        state: "completed",
        updated: 1,
        pausedProcessIds: [processId],
      });
      const imported = await tenant.query<{
        version: number; eligibility_status: string; available: boolean; audit_count: number;
      }>(
        `SELECT member.version,member.eligibility_status,member.available,
                (SELECT count(*)::int FROM audit_events audit
                  WHERE audit.action='member.import.updated' AND audit.entity_id=member.id::text) AS audit_count
           FROM members member WHERE member.id=$1`,
        [eligibleHere],
      );
      expect(imported.rows[0]).toEqual({
        version: 2,
        eligibility_status: "ineligible",
        available: false,
        audit_count: 1,
      });

      const mutation = await withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).updateMember({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        memberId: eligibleHere,
        expectedVersion: 2,
        eligibilityStatus: "eligible",
        available: true,
        departmentRestriction: departmentB,
      }));
      expect(mutation).toMatchObject({ version: 3, departmentRestriction: departmentB });
      expect((mutation["pausedWorkflows"] as unknown[]).length).toBe(1);
      const paused = await tenant.query<{ process_phase: string; round_phase: string; frozen_department: string }>(
        `SELECT process.phase AS process_phase,round_state.phase AS round_phase,
                snapshot.eligibility_department_id_snapshot AS frozen_department
           FROM office_processes process
           JOIN rounds round_state ON round_state.process_id=process.id
           JOIN candidate_snapshots snapshot ON snapshot.round_id=round_state.id
          WHERE process.id=$1`,
        [processId],
      );
      expect(paused.rows[0]).toEqual({
        process_phase: "PAUSADO",
        round_phase: "PAUSADO",
        frozen_department: departmentA,
      });

      const reopened = await tenant.query<{ version: number }>(
        `UPDATE rounds SET phase='PROPUESTAS_ABIERTAS',version=version+1 WHERE id=$1 RETURNING version`,
        [roundId],
      );
      await expect(withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).submit({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        roundId,
        expectedVersion: reopened.rows[0]?.version ?? 0,
        kind: "proposal",
        envelope: opaqueEnvelope(),
        contentHash: `sha256:${"a".repeat(64)}`,
      }))).rejects.toMatchObject({ code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" });

      const ballotReady = await tenant.query<{ version: number }>(
        `UPDATE rounds SET submission_kind='vote',phase='VOTACION_ABIERTA',version=version+1
          WHERE id=$1 RETURNING version`,
        [roundId],
      );
      await expect(withStore(tenant, tenantId, actorId, (client) => new CustodyStore(client).submitBallot({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        roundId,
        expectedVersion: ballotReady.rows[0]?.version ?? 0,
        envelope: {},
        contentHash: `sha256:${"d".repeat(64)}`,
      }))).rejects.toMatchObject({ code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" });

      const closed = await tenant.query<{ version: number }>(
        `UPDATE rounds SET phase='VOTACION_CERRADA',version=version+1 WHERE id=$1 RETURNING version`,
        [roundId],
      );
      await expect(withStore(tenant, tenantId, actorId, (client) => new CustodyStore(client).createManifest({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        roundId,
        expectedRoundVersion: closed.rows[0]?.version ?? 0,
        expectedCustodyVersion: 1,
      }))).rejects.toMatchObject({ code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" });

      const tallyRound = await tenant.query<{ version: number }>(
        `UPDATE rounds SET phase='ESCRUTINIO',version=version+1 WHERE id=$1 RETURNING version`,
        [roundId],
      );
      const tallyRoundVersion = tallyRound.rows[0]?.version ?? 0;
      const manifestId = randomUUID();
      await tenant.query(
        `INSERT INTO round_custody_sets(round_id,round_version,decision_rule,frozen_by_identity_id)
         VALUES ($1,$2,$3,$4)`,
        [roundId, tallyRoundVersion, { kind: "PLURALITY" }, actorId],
      );
      await tenant.query(
        `INSERT INTO tally_manifests(
           id,round_id,custody_version,round_version,decision_rule,manifest_hash,entry_count,
           state,version,created_by_identity_id
         ) VALUES ($1,$2,1,$3,$4,$5,1,'awaiting_attestations',1,$6)`,
        [manifestId, roundId, tallyRoundVersion, { kind: "PLURALITY" }, `sha256:${"e".repeat(64)}`, actorId],
      );
      await expect(withStore(tenant, tenantId, actorId, (client) => new CustodyStore(client).attestManifest({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        roundId,
        expectedManifestVersion: 1,
        aggregate: {},
        signature: "invalid-before-eligibility-guard",
      }))).rejects.toMatchObject({ code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" });
      await tenant.query(
        `UPDATE tally_manifests
            SET state='publishable',agreed_aggregate_hash=$2,agreed_aggregate=$3,version=2
          WHERE id=$1`,
        [manifestId, `sha256:${"f".repeat(64)}`, {}],
      );
      await expect(withStore(tenant, tenantId, actorId, (client) => new CustodyStore(client).publishAggregate({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        roundId,
        expectedRoundVersion: tallyRoundVersion,
        expectedManifestVersion: 2,
      }))).rejects.toMatchObject({ code: "ROUND_CANDIDATE_ELIGIBILITY_CHANGED" });

      const assignmentProcessId = randomUUID();
      const assignmentVacancyId = randomUUID();
      const assignmentId = randomUUID();
      const tenantDate = await tenant.query<{ civil_date: string }>(
        `SELECT to_char((clock_timestamp() AT TIME ZONE timezone)::date,'YYYY-MM-DD') AS civil_date
           FROM tenant_settings WHERE singleton=true`,
      );
      const evaluatedOn = tenantDate.rows[0]?.civil_date;
      expect(evaluatedOn).toMatch(/^\d{4}-\d{2}-\d{2}$/u);
      await tenant.query(
        `INSERT INTO office_processes(
           id,cycle_id,office_id,phase,vacancy_count,max_proposal_selections,max_ballot_selections,
           decision_rule,abstention_rule,tiebreak_policy,quorum_rule,aggregate_audience,
           agenda_order,procedure_sequence,created_by_identity_id
         ) VALUES ($1,$2,$3,'CERRADO',1,1,1,$4,'EXCLUDED_FROM_CANDIDATE_TOTALS',
                   'NEW_BALLOT_ROUND',$5,'committee',2,2,$6)`,
        [assignmentProcessId, cycleId, officeA, { kind: "PLURALITY" }, { kind: "ALL_REQUIRED" }, actorId],
      );
      await tenant.query(
        `INSERT INTO vacancies(id,cycle_id,office_id,ordinal,status,process_id)
         VALUES ($1,$2,$3,2,'accepted',$4)`,
        [assignmentVacancyId, cycleId, officeA, assignmentProcessId],
      );
      await tenant.query(
        `INSERT INTO assignments(
           id,vacancy_id,member_id,state,effective,cycle_id,office_id,process_id,
           member_snapshot,office_snapshot
         ) VALUES ($1,$2,$3,'ACEPTADA',true,$4,$5,$6,$7,$8)`,
        [
          assignmentId,
          assignmentVacancyId,
          assignmentMember,
          cycleId,
          officeA,
          assignmentProcessId,
          {
            memberId: assignmentMember,
            memberVersion: 1,
            displayEnvelope: memberDisplayEnvelope(tenantId, assignmentMember, tenantKeyId),
            eligibility: {
              departmentRestriction: null,
              validUntil: null,
              evaluatedOn,
              effective: true,
            },
          },
          {
            officeId: officeA,
            departmentId: departmentA,
            canonicalCode: "ELIGIBILITY_OFFICE_A",
            names: { es: "Cargo", en: "Office", fr: "Fonction" },
          },
        ],
      );
      await tenant.query(
        `UPDATE members SET
           eligibility_valid_until=(SELECT (clock_timestamp() AT TIME ZONE timezone)::date - 1
                                      FROM tenant_settings WHERE singleton=true),
           version=version+1,updated_at=clock_timestamp()
         WHERE id=$1`,
        [assignmentMember],
      );
      const presentationKey = randomUUID();
      const presentationInput = {
        identityId: actorId,
        idempotencyKey: presentationKey,
        assignmentId,
        expectedVersion: 1,
        envelope: opaqueEnvelope(),
      } as const;
      expect(presentationInput.envelope.keyId).not.toBe(tenantKeyId);
      const eligibilityPause = await withStore(
        tenant,
        tenantId,
        actorId,
        (client) => new CoreWorkflowStore(client).presentAssignment(presentationInput),
      );
      expect(eligibilityPause).toMatchObject({
        eligibilityPaused: true,
        code: "ASSIGNMENT_ELIGIBILITY_PAUSED",
        assignmentId,
        processId: assignmentProcessId,
        roundId: null,
        processVersion: 2,
      });
      const replayedEligibilityPause = await withStore(
        tenant,
        tenantId,
        actorId,
        (client) => new CoreWorkflowStore(client).presentAssignment(presentationInput),
      );
      expect(replayedEligibilityPause).toEqual(JSON.parse(JSON.stringify(eligibilityPause)));
      const persistedPause = await tenant.query<{
        assignment_state: string; assignment_version: number; process_phase: string;
        process_version: number; previous_process_phase: string; pause_count: number;
      }>(
        `SELECT assignment.state AS assignment_state,assignment.version AS assignment_version,
                process.phase AS process_phase,process.version AS process_version,
                pause.previous_process_phase,
                (SELECT count(*)::int FROM member_eligibility_workflow_pauses current_pause
                  WHERE current_pause.process_id=process.id AND current_pause.resolved_at IS NULL) AS pause_count
           FROM assignments assignment
           JOIN office_processes process ON process.id=assignment.process_id
           JOIN member_eligibility_workflow_pauses pause
             ON pause.process_id=process.id AND pause.member_id=assignment.member_id AND pause.resolved_at IS NULL
          WHERE assignment.id=$1`,
        [assignmentId],
      );
      expect(persistedPause.rows[0]).toEqual({
        assignment_state: "ACEPTADA",
        assignment_version: 1,
        process_phase: "PAUSADO",
        process_version: 2,
        previous_process_phase: "CERRADO",
        pause_count: 1,
      });

      let lockHolder: PoolClient | undefined;
      let blockedMutation: PoolClient | undefined;
      let lockHolderInTransaction = false;
      let blockedMutationInTransaction = false;
      let lockTestError: unknown;
      try {
        lockHolder = await tenant.connect();
        blockedMutation = await tenant.connect();
        await lockHolder.query("BEGIN");
        lockHolderInTransaction = true;
        await acquireMemberEligibilityPolicySharedLock(lockHolder);
        await blockedMutation.query("BEGIN");
        blockedMutationInTransaction = true;
        await blockedMutation.query("SET LOCAL lock_timeout='250ms'");
        await blockedMutation.query(
          `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
                  set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
          [tenantId, actorId, randomUUID(), randomUUID()],
        );
        await expect(new TenantStore(blockedMutation).updateTenantSettings({
          identityId: actorId,
          idempotencyKey: randomUUID(),
          expectedVersion: 1,
          timezone: "America/New_York",
        })).rejects.toMatchObject({ code: "55P03" });
      } catch (error) {
        lockTestError = error;
        throw error;
      } finally {
        const cleanupErrors: Error[] = [];
        if (lockHolderInTransaction && lockHolder) {
          try {
            await lockHolder.query("ROLLBACK");
          } catch (error) {
            cleanupErrors.push(new Error("Eligibility lock-holder rollback failed", { cause: error }));
          }
        }
        if (blockedMutationInTransaction && blockedMutation) {
          try {
            await blockedMutation.query("ROLLBACK");
          } catch (error) {
            cleanupErrors.push(new Error("Eligibility blocked-mutation rollback failed", { cause: error }));
          }
        }
        lockHolder?.release();
        blockedMutation?.release();
        if (cleanupErrors.length > 0) {
          throw new AggregateError(
            lockTestError === undefined ? cleanupErrors : [lockTestError, ...cleanupErrors],
            "Eligibility lock-concurrency test cleanup failed closed",
          );
        }
      }

      await expect(withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).updateTenantSettings({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        expectedVersion: 1,
        timezone: "America/New_York",
      }))).rejects.toMatchObject({ code: "TENANT_TIMEZONE_ELIGIBILITY_ACTIVE" });
      await expect(withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).updateLocalOffice({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        officeId: officeA,
        expectedVersion: 1,
        active: false,
      }))).rejects.toMatchObject({ code: "CATALOG_OFFICE_ELIGIBILITY_IN_USE" });
      await expect(withStore(tenant, tenantId, actorId, (client) => new TenantStore(client).updateLocalDepartment({
        identityId: actorId,
        idempotencyKey: randomUUID(),
        departmentId: departmentA,
        expectedVersion: 1,
        active: false,
      }))).rejects.toMatchObject({ code: "CATALOG_DEPARTMENT_ELIGIBILITY_IN_USE" });
    }, () => cleanupScratchDatabase(admin, tenant, databaseName),
    "Member eligibility live test");
  }, 90_000);
});

async function withStore<T>(
  tenant: Pool,
  tenantId: string,
  identityId: string,
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await tenant.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
              set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
      [tenantId, identityId, randomUUID(), randomUUID()],
    );
    await bindDirectFixtureSession(client);
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function memberDisplayEnvelope(tenantId: string, memberId: string, keyId: string): EncryptedEnvelope {
  return {
    ...opaqueEnvelope(keyId),
    aad: Buffer.from(JSON.stringify({ tenantId, memberId, purpose: "member-display", schemaVersion: 1 })).toString("base64url"),
  };
}

function opaqueEnvelope(keyId = "eligibility-test-stale-key-v1"): EncryptedEnvelope {
  return {
    algorithm: "AES-256-GCM",
    keyId,
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(32).toString("base64url"),
    aad: Buffer.from("{}").toString("base64url"),
  };
}

function envelopeHash(value: EncryptedEnvelope): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex")}`;
}

function discoverAdminUrl(): string | undefined {
  if (!existsSync(installFile)) return undefined;
  const value = JSON.parse(readFileSync(installFile, "utf8")) as { DATABASE_ADMIN_URL?: string };
  if (!value.DATABASE_ADMIN_URL) return undefined;
  try {
    return assertWorkspacePostgresUrl(value.DATABASE_ADMIN_URL, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReach(connectionString: string): Promise<boolean> {
  const pool = new Pool({ connectionString, max: 1, connectionTimeoutMillis: 1_500 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === 55_432;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

async function createDatabase(admin: Pool, databaseName: string): Promise<void> {
  assertEligibilityScratchDatabaseName(databaseName);
  const formatted = await admin.query<{ sql: string }>(
    "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L',$1::text,'UTF8') AS sql",
    [databaseName],
  );
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the scratch database statement");
  await admin.query(sql);
}

function eligibilityScratchDatabaseName(id: string): string {
  const compactId = id.replaceAll("-", "").toLowerCase();
  const databaseName = `nom_test_eligibility_${compactId}`;
  assertEligibilityScratchDatabaseName(databaseName);
  return databaseName;
}

function assertEligibilityScratchDatabaseName(databaseName: string): void {
  if (PERSISTENT_DATABASE_NAMES.has(databaseName) || !ELIGIBILITY_SCRATCH_DATABASE_PATTERN.test(databaseName)) {
    throw new Error("Refusing a non-scratch database name; expected the dedicated eligibility UUID-v4 namespace");
  }
}

async function cleanupScratchDatabase(admin: Pool, tenant: Pool | undefined, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: admin,
    targets: [{
      databaseName,
      databasePools: tenant ? [tenant] : [],
      assertSafeDatabaseName: assertEligibilityScratchDatabaseName,
    }],
    label: "Temporary member-eligibility database",
  });
}
