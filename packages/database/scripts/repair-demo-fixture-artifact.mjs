import { existsSync } from "node:fs";
import net from "node:net";
import path from "node:path";

import { Client } from "pg";

import { appendTenantAuditEventV2, tenantAuditEventRecordFromRow } from "../dist/src/audit-event-chain.js";
import { verifyTenantAuditEventChain } from "../dist/src/audit-anchors.js";
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
  DEMO_FIXTURE_EXPIRED_REPORT_IDS,
  DEMO_FIXTURE_MANIFEST,
  DEMO_FIXTURE_REFERENCE_STABLE_CODES,
  DEMO_FIXTURE_REPAIR_DATABASE,
  DEMO_FIXTURE_REPAIR_TARGET,
  parseDemoFixtureRepairArguments,
} from "../dist/scripts/repair-demo-fixture-artifact-guards.js";
import {
  loadLocalScriptEnvironment,
  resolveDatabasePackageRoot,
  withoutDatabase,
} from "../dist/scripts/script-config.js";

// One-off, fail-closed procedure documented in ../DEMO-FIXTURE-REPAIR.md.

const command = parseDemoFixtureRepairArguments(process.argv.slice(2));
const environment = loadLocalScriptEnvironment();
const installedAdminUrl = assertDemoFixtureRepairAdminUrl(environment.DATABASE_ADMIN_URL);
assertDemoFixtureRepairControlUrl(environment.DATABASE_CONTROL_URL);
const packageRoot = resolveDatabasePackageRoot(import.meta.url);
const workspaceRoot = path.resolve(packageRoot, "../..");
const serviceStateFile = path.join(workspaceRoot, ".local", "services.json");

const control = new Client({
  connectionString: withoutDatabase(installedAdminUrl.toString(), "nombramientos_control"),
  application_name: "nombramientos-demo-fixture-repair-control",
});
const tenant = new Client({
  connectionString: withoutDatabase(installedAdminUrl.toString(), DEMO_FIXTURE_REPAIR_DATABASE),
  application_name: "nombramientos-demo-fixture-repair-tenant",
});

let workerLeaseAcquired = false;
let transactionOpen = false;

try {
  const listeningPorts = await listeningLocalServicePorts();
  if (existsSync(serviceStateFile) || listeningPorts.length > 0) {
    assertOfflineForDemoFixtureRepair({
      serviceStateFilePresent: existsSync(serviceStateFile),
      listeningPorts,
      unexpectedDatabaseSessions: [],
      workerLeaseAcquired: true,
    });
  }

  await control.connect();
  await tenant.connect();
  await control.query("SET search_path TO pg_catalog,public");
  await tenant.query("SET search_path TO pg_catalog,public");

  const controlTarget = await control.query(
    `SELECT id::text,slug,kind,status,database_host,database_port,database_name::text,ssl_mode,
            current_database() AS control_database,current_user,host(inet_server_addr()) AS server_address,
            inet_server_port() AS server_port
       FROM tenants
      WHERE id=$1`,
    ["d0000000-0000-4000-8000-000000000001"],
  );
  if (controlTarget.rowCount !== 1) fail("exact Demo control-plane mapping did not match once");
  assertDemoControlTarget(controlTarget.rows[0]);

  const tenantTarget = await tenant.query(
    `SELECT current_database() AS database_name,tenant_id::text,kind,setup_state,current_user,
            host(inet_server_addr()) AS server_address,inet_server_port() AS server_port
       FROM tenant_settings
      WHERE singleton=true`,
  );
  if (tenantTarget.rowCount !== 1) fail("exact Demo tenant_settings row did not match once");
  assertDemoTenantTarget(tenantTarget.rows[0]);

  const workerLease = await control.query(
    "SELECT pg_try_advisory_lock(hashtextextended('tenant-provisioning-worker',0)) AS acquired",
  );
  workerLeaseAcquired = workerLease.rows[0]?.acquired === true;
  const controlPid = await backendPid(control);
  const tenantPid = await backendPid(tenant);
  await assertOffline(controlPid, tenantPid);

  await tenant.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
  transactionOpen = true;
  await tenant.query("SET LOCAL lock_timeout='2s'");
  await tenant.query("SET LOCAL statement_timeout='60s'");
  await tenant.query("SET LOCAL idle_in_transaction_session_timeout='120s'");
  await tenant.query("SELECT pg_advisory_xact_lock(hashtextextended('demo_fixture_repair',0))");
  await tenant.query("SELECT pg_advisory_xact_lock(hashtextextended('tenant_audit_chain',0))");
  await tenant.query(
    "LOCK TABLE members,idempotency_records,outbox_events,audit_events IN SHARE ROW EXCLUSIVE MODE NOWAIT",
  );
  await assertOffline(controlPid, tenantPid);

  const beforeChain = verifyTenantAuditEventChain(await auditChain());
  if (!beforeChain.valid) {
    fail(`audit chain is invalid before repair (${beforeChain.code}: ${beforeChain.message})`);
  }

  const memberResult = await tenant.query(
    `SELECT id::text,stable_code,created_at,updated_at,version,archived_at,
            profile_envelope,display_envelope,display_content_hash,
            contact_envelope,contact_content_hash,profile_migration_required,
            eligibility_envelope,eligibility_status,available
       FROM members
      WHERE id=$1::uuid AND stable_code=$2
      FOR UPDATE`,
    [DEMO_FIXTURE_REPAIR_TARGET.memberId, DEMO_FIXTURE_REPAIR_TARGET.stableCode],
  );
  if (memberResult.rowCount !== 1) fail("exact accidental member identity did not match once");

  const sourceAuditResult = await tenant.query(
    `SELECT sequence::text,id::text,occurred_at,hash_version,actor_identity_id::text,
            action,entity_type,entity_id,result,request_id::text,metadata,previous_hash,event_hash
       FROM audit_events
      WHERE sequence=$1::bigint
      FOR SHARE`,
    [DEMO_FIXTURE_REPAIR_TARGET.auditSequence],
  );
  if (sourceAuditResult.rowCount !== 1) fail("exact source audit sequence did not match once");

  const originalOutboxResult = await originalOutboxEvidence();
  if (originalOutboxResult.rowCount !== 1) fail("exact original outbox identity did not match once");

  const originalIdempotencyResult = await originalIdempotencyEvidence();
  if (originalIdempotencyResult.rowCount !== 1) fail("exact original idempotency identity did not match once");

  const member = memberResult.rows[0];
  const sourceAudit = sourceAuditResult.rows[0];
  const originalOutbox = originalOutboxResult.rows[0];
  const originalIdempotency = originalIdempotencyResult.rows[0];
  assertExactRepairEvidence({ member, audit: sourceAudit, outbox: originalOutbox, idempotency: originalIdempotency });

  const foreignKeys = await tenant.query(
    `SELECT c.conrelid::regclass::text AS table_name,a.attname AS column_name
       FROM pg_constraint c
       JOIN LATERAL unnest(c.conkey) AS key(attnum) ON true
       JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=key.attnum
      WHERE c.contype='f' AND c.confrelid='members'::regclass
      ORDER BY table_name,column_name`,
  );
  const references = [];
  for (const reference of foreignKeys.rows) {
    if (!/^[a-z_]+$/u.test(reference.table_name) || !/^[a-z_]+$/u.test(reference.column_name)) {
      fail("foreign-key metadata contains an unsafe identifier");
    }
    await tenant.query(`LOCK TABLE ${reference.table_name} IN SHARE ROW EXCLUSIVE MODE NOWAIT`);
    const count = await tenant.query(
      `SELECT count(*)::text AS count FROM ${reference.table_name} WHERE ${reference.column_name}=$1::uuid`,
      [DEMO_FIXTURE_REPAIR_TARGET.memberId],
    );
    references.push({ ...reference, count: count.rows[0]?.count ?? "missing" });
  }
  assertForeignKeyReferencesAbsent(references);

  await assertFixtureState("before");

  if (command.mode === "check") {
    await tenant.query("ROLLBACK");
    transactionOpen = false;
    process.stdout.write(`${JSON.stringify({
      mode: "check",
      ready: true,
      database: DEMO_FIXTURE_REPAIR_DATABASE,
      memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
      members: { before: 181, afterExpected: 180 },
      eligibleMembers: { before: 151, afterExpected: 150 },
      preservedEvidence: {
        auditSequence: DEMO_FIXTURE_REPAIR_TARGET.auditSequence,
        outboxSequence: DEMO_FIXTURE_REPAIR_TARGET.outboxSequence,
        idempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
      },
      wouldAppend: { auditAction: "test.fixture.repaired", outboxEventType: "member.changed" },
    })}\n`);
  } else {
    // Repeat the stopped-service observation immediately before the sole durable repair.
    // The held worker lease and table locks close database mutation races after this point.
    await assertOffline(controlPid, tenantPid);

    const removedMember = await tenant.query(
      `DELETE FROM members
        WHERE id=$1::uuid AND stable_code=$2
          AND date_trunc('milliseconds',created_at)=$3::timestamptz
          AND version=1 AND archived_at IS NULL
        RETURNING id::text`,
      [
        DEMO_FIXTURE_REPAIR_TARGET.memberId,
        DEMO_FIXTURE_REPAIR_TARGET.stableCode,
        DEMO_FIXTURE_REPAIR_TARGET.createdAt,
      ],
    );
    if (removedMember.rowCount !== 1) fail("member delete did not affect exactly the guarded synthetic row");

    const compensatingOutboxResult = await tenant.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized','member.changed','member',$1::uuid,$2::jsonb)
       RETURNING sequence::text,id::text,audience,event_type,aggregate_type,aggregate_id::text,
                 payload,occurred_at,published_at`,
      [DEMO_FIXTURE_REPAIR_TARGET.memberId, {
        memberId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
        version: 1,
      }],
    );
    if (compensatingOutboxResult.rowCount !== 1) fail("compensating outbox insert did not affect exactly one row");
    const compensatingOutbox = compensatingOutboxResult.rows[0];
    assertCompensatingOutboxEvent(compensatingOutbox);

    const repairRequest = await tenant.query("SELECT gen_random_uuid()::text AS id");
    const repairRequestId = repairRequest.rows[0]?.id;
    if (typeof repairRequestId !== "string") fail("repair request identity could not be reserved");
    await tenant.query("SELECT set_config('app.identity_id',$1,true),set_config('app.request_id',$2,true)", [
      DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
      repairRequestId,
    ]);
    await appendTenantAuditEventV2(tenant, {
      action: "test.fixture.repaired",
      entityType: "member",
      entityId: DEMO_FIXTURE_REPAIR_TARGET.memberId,
      result: "success",
      metadata: {
        reasonCode: "E2E_SERVICE_WORKER_MOCK_BYPASS",
        sourceAuditSequence: DEMO_FIXTURE_REPAIR_TARGET.auditSequence,
        sourceRequestId: DEMO_FIXTURE_REPAIR_TARGET.sourceRequestId,
        preservedOutboxId: DEMO_FIXTURE_REPAIR_TARGET.outboxId,
        preservedIdempotencyKey: DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
        compensatingOutboxId: compensatingOutbox.id,
        compensatingOutboxSequence: compensatingOutbox.sequence,
        expectedFixtureMembers: 180,
        expectedEligibleMembers: 150,
      },
    });

    const preservedOutboxResult = await originalOutboxEvidence();
    const preservedIdempotencyResult = await originalIdempotencyEvidence();
    if (preservedOutboxResult.rowCount !== 1 || preservedIdempotencyResult.rowCount !== 1) {
      fail("original operational evidence disappeared during repair");
    }
    assertPreservedOperationalEvidence({
      originalOutbox,
      observedOutbox: preservedOutboxResult.rows[0],
      originalIdempotency,
      observedIdempotency: preservedIdempotencyResult.rows[0],
    });

    const removedMemberCount = await tenant.query(
      "SELECT count(*)::text AS count FROM members WHERE id=$1::uuid OR stable_code=$2",
      [DEMO_FIXTURE_REPAIR_TARGET.memberId, DEMO_FIXTURE_REPAIR_TARGET.stableCode],
    );
    if (removedMemberCount.rows[0]?.count !== "0") fail("synthetic member identity remains after deletion");
    await assertFixtureState("after");

    const afterChain = verifyTenantAuditEventChain(await auditChain());
    if (!afterChain.valid) fail(`audit chain is invalid after repair (${afterChain.code})`);
    if (BigInt(afterChain.eventCount) !== BigInt(beforeChain.eventCount) + 1n) {
      fail("compensating audit event count did not advance exactly once");
    }
    const compensatingAuditResult = await tenant.query(
      `SELECT sequence::text,id::text,occurred_at,hash_version,actor_identity_id::text,
              action,entity_type,entity_id,result,request_id::text,metadata,previous_hash,event_hash
         FROM audit_events
        WHERE sequence=$1::bigint`,
      [afterChain.lastSequence],
    );
    if (compensatingAuditResult.rowCount !== 1) fail("compensating audit event was not the chain head");
    assertCompensatingAuditEvent({
      row: compensatingAuditResult.rows[0],
      requestId: repairRequestId,
      previousHash: beforeChain.headHash,
      compensatingOutbox,
    });
    if (afterChain.headHash !== compensatingAuditResult.rows[0].event_hash) {
      fail("compensating audit event hash is not the verified chain head");
    }

    await tenant.query("COMMIT");
    transactionOpen = false;
    process.stdout.write(`${JSON.stringify({
      mode: "apply",
      repaired: true,
      database: DEMO_FIXTURE_REPAIR_DATABASE,
      members: { total: "180", active: "180", eligible: "150" },
      originalEvidencePreserved: true,
      compensation: {
        auditSequence: afterChain.lastSequence,
        auditHeadHash: afterChain.headHash,
        outboxSequence: compensatingOutbox.sequence,
        outboxId: compensatingOutbox.id,
      },
    })}\n`);
  }
} catch (error) {
  if (transactionOpen) await tenant.query("ROLLBACK").catch(() => undefined);
  throw error;
} finally {
  if (workerLeaseAcquired) {
    await control.query(
      "SELECT pg_advisory_unlock(hashtextextended('tenant-provisioning-worker',0))",
    ).catch(() => undefined);
  }
  await tenant.end().catch(() => undefined);
  await control.end().catch(() => undefined);
}

async function assertFixtureState(stage) {
  const snapshot = await tenant.query(`
    WITH current_cycle AS (SELECT id,eligible_reference_count FROM election_cycles WHERE status='active' LIMIT 1)
    SELECT
      (SELECT count(*)::text FROM members) AS members,
      (SELECT count(*)::text FROM members WHERE archived_at IS NULL) AS active_members,
      (SELECT count(*)::text FROM members WHERE eligibility_status='eligible' AND available) AS eligible,
      (SELECT count(*)::text FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle)) AS vacancies,
      (SELECT count(*)::text FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status IN ('recommended','accepted','elected')) AS recommended,
      (SELECT count(*)::text FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status IN ('accepted','elected')) AS accepted,
      (SELECT count(*)::text FROM vacancies WHERE cycle_id=(SELECT id FROM current_cycle) AND status='elected') AS elected,
      (SELECT count(*)::text FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent) AS responsibilities,
      (SELECT count(DISTINCT a.member_id)::text FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent) AS responsible_people,
      (SELECT count(*)::text FROM election_cycles) AS cycles,
      (SELECT count(*)::text FROM rounds WHERE cycle_id=(SELECT id FROM current_cycle) AND phase='CERRADO') AS reference_rounds,
      (SELECT count(*)::text FROM encrypted_submissions) AS seeded_submissions,
      (SELECT count(*)::text FROM members
        WHERE NOT profile_migration_required AND profile_envelope IS NULL
          AND display_envelope IS NOT NULL AND display_content_hash IS NOT NULL) AS split_members,
      (SELECT count(*)::text FROM members WHERE contact_envelope IS NULL AND contact_content_hash IS NULL) AS contact_free_members,
      (SELECT count(*)::text FROM cycle_member_snapshots
        WHERE cycle_id=(SELECT id FROM current_cycle) AND profile_envelope IS NULL
          AND display_envelope IS NOT NULL AND NOT legacy_profile_redacted) AS split_cycle_snapshots,
      (SELECT count(*)::text FROM candidate_snapshots WHERE display_envelope IS NULL) AS missing_candidate_displays,
      (SELECT count(*)::text FROM assignments a JOIN vacancies v ON v.id=a.vacancy_id
        WHERE v.cycle_id=(SELECT id FROM current_cycle) AND a.effective AND a.independent
          AND a.member_snapshot->'displayEnvelope' IS NOT NULL
          AND NOT (a.member_snapshot ?| ARRAY['profileEnvelope','contactEnvelope'])) AS assignment_display_snapshots,
      (SELECT count(*)::text FROM report_versions
        WHERE id=ANY($1::uuid[]) AND state='expired' AND artifact_envelope IS NULL AND artifact_bytes IS NULL
          AND artifact_sha256 IS NULL AND ciphertext_sha256 IS NULL
          AND artifact_manifest IS NULL AND plaintext_bytes IS NULL) AS expired_seed_reports,
      (SELECT eligible_reference_count::text FROM current_cycle) AS active_cycle_reference_eligible
  `, [DEMO_FIXTURE_EXPIRED_REPORT_IDS]);
  if (snapshot.rowCount !== 1) fail(`Demo ${stage} semantic snapshot was unavailable`);
  assertDemoFixtureSemanticSnapshot(snapshot.rows[0], stage);

  const manifest = await tenant.query(
    "SELECT seed_id,version,fixture_hash,metadata,completed_at FROM seed_manifests WHERE seed_id=$1",
    [DEMO_FIXTURE_MANIFEST.seedId],
  );
  if (manifest.rowCount !== 1) fail("complete Demo seed manifest was unavailable");
  assertDemoFixtureManifest(manifest.rows[0]);

  const stableCodes = await tenant.query(
    "SELECT stable_code FROM members WHERE stable_code=ANY($1::text[]) ORDER BY stable_code",
    [DEMO_FIXTURE_REFERENCE_STABLE_CODES],
  );
  assertReferenceStableCodes(stableCodes.rows.map(({ stable_code }) => stable_code));
}

async function auditChain() {
  const result = await tenant.query(
    `SELECT sequence::text,id::text,occurred_at,hash_version,actor_identity_id::text,
            action,entity_type,entity_id,result,request_id::text,metadata,previous_hash,event_hash
       FROM audit_events ORDER BY audit_events.sequence`,
  );
  return result.rows.map(tenantAuditEventRecordFromRow);
}

async function originalOutboxEvidence() {
  return tenant.query(
    `SELECT sequence::text,id::text,audience,event_type,aggregate_type,aggregate_id::text,
            payload,occurred_at,published_at
       FROM outbox_events
      WHERE sequence=$1::bigint AND id=$2::uuid
      FOR SHARE`,
    [DEMO_FIXTURE_REPAIR_TARGET.outboxSequence, DEMO_FIXTURE_REPAIR_TARGET.outboxId],
  );
}

async function originalIdempotencyEvidence() {
  return tenant.query(
    `SELECT identity_id::text,operation,idempotency_key::text,request_hash,response_status,
            response_body,created_at,expires_at
       FROM idempotency_records
      WHERE identity_id=$1::uuid AND operation=$2 AND idempotency_key=$3::uuid
      FOR SHARE`,
    [
      DEMO_FIXTURE_REPAIR_TARGET.actorIdentityId,
      DEMO_FIXTURE_REPAIR_TARGET.idempotencyOperation,
      DEMO_FIXTURE_REPAIR_TARGET.idempotencyKey,
    ],
  );
}

async function assertOffline(controlPid, tenantPid) {
  const [listeningPorts, sessions] = await Promise.all([
    listeningLocalServicePorts(),
    control.query(
      `SELECT pid,datname AS database,application_name AS "applicationName"
         FROM pg_stat_activity
        WHERE backend_type='client backend'
          AND pid<>ALL($1::int[])
          AND datname=ANY($2::text[])
        ORDER BY pid`,
      [[controlPid, tenantPid], ["nombramientos_control", DEMO_FIXTURE_REPAIR_DATABASE]],
    ),
  ]);
  assertOfflineForDemoFixtureRepair({
    serviceStateFilePresent: existsSync(serviceStateFile),
    listeningPorts,
    unexpectedDatabaseSessions: sessions.rows,
    workerLeaseAcquired,
  });
}

async function backendPid(client) {
  const result = await client.query("SELECT pg_backend_pid() AS pid");
  const pid = result.rows[0]?.pid;
  if (!Number.isInteger(pid) || pid <= 0) fail("database backend identity was unavailable");
  return pid;
}

async function listeningLocalServicePorts() {
  const checks = await Promise.all(
    [3000, 4000].flatMap((port) => ["127.0.0.1", "::1"].map(async (host) => ({
      port,
      listening: await isListening(host, port),
    }))),
  );
  return [...new Set(checks.filter(({ listening }) => listening).map(({ port }) => port))];
}

function isListening(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    socket.setTimeout(500);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(undefined, new Error(
      `Fixture repair refused: service-port probe timed out for ${host}:${port}`,
    )));
    socket.once("error", (error) => {
      if (["ECONNREFUSED", "EADDRNOTAVAIL", "EAFNOSUPPORT"].includes(error.code)) finish(false);
      else finish(undefined, new Error(
        `Fixture repair refused: service-port probe was indeterminate for ${host}:${port} (${error.code ?? "unknown"})`,
      ));
    });
  });
}

function fail(message) {
  throw new Error(`Fixture repair refused: ${message}`);
}
