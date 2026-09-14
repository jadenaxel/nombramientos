import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { sealAesGcmJson } from "../src/crypto-envelope.js";
import { MemberQualificationStore } from "../src/member-qualification-store.js";
import { runMigrations } from "../src/migrations.js";
import { cleanupAfterFailure, cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Member qualification live tests require PostgreSQL 18 on isolated loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

interface Fixture {
  readonly cluster: Pool;
  readonly pool: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly identityId: string;
  readonly memberId: string;
  readonly otherMemberId: string;
  readonly tenantKeyId: string;
  readonly keyGenerationId: string;
  readonly keyDeviceId: string;
}

let fixture: Fixture | undefined;

live("independent append-only member qualifications", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 30_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 30_000);

  it("creates, replays, revises and reads encrypted qualification history without changing eligibility", async () => {
    const current = requireFixture();
    const qualificationId = randomUUID();
    const key = randomBytes(32);
    const canaryTitle = "PRIVATE_QUALIFICATION_TITLE_CANARY";
    const firstEnvelope = qualificationEnvelope({
      tenantId: current.tenantId,
      memberId: current.memberId,
      qualificationId,
      version: 1,
      type: "ordination",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      key,
      keyId: current.tenantKeyId,
      title: canaryTitle,
    });
    const createInput = {
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.memberId,
      qualificationId,
      type: "ordination" as const,
      status: "pending" as const,
      effectiveOn: "2026-09-12",
      expiresOn: null,
      detailsEnvelope: firstEnvelope,
      detailsContentHash: envelopeHash(firstEnvelope),
    };
    const created = await withStore(current, (store) => store.create(createInput));
    const replayed = await withStore(current, (store) => store.create(createInput));
    expect(replayed).toEqual(created);
    expect(created).toMatchObject({ qualificationId, version: 1, status: "pending", hasDetails: true });

    const secondEnvelope = qualificationEnvelope({
      tenantId: current.tenantId,
      memberId: current.memberId,
      qualificationId,
      version: 2,
      type: "ordination",
      status: "verified",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      key,
      keyId: current.tenantKeyId,
      title: canaryTitle,
    });
    const revised = await withStore(current, (store) => store.revise({
      ...createInput,
      idempotencyKey: randomUUID(),
      expectedVersion: 1,
      status: "verified",
      detailsEnvelope: secondEnvelope,
      detailsContentHash: envelopeHash(secondEnvelope),
    }));
    expect(revised).toMatchObject({ qualificationId, version: 2, status: "verified" });
    await expect(withStore(current, (store) => store.revise({
      ...createInput,
      idempotencyKey: randomUUID(),
      expectedVersion: 1,
      status: "revoked",
      detailsEnvelope: null,
      detailsContentHash: null,
    }))).rejects.toMatchObject({ code: "QUALIFICATION_VERSION_CONFLICT" });

    const list = await withStore(current, (store) => store.listForMember(current.memberId));
    expect(list).toMatchObject({ memberId: current.memberId, eligibilityInference: false });
    expect(list.items).toHaveLength(1);
    expect(list.items[0]).toMatchObject({ version: 2, status: "verified" });
    expect(list.items[0]?.revisions.map(({ version }) => version)).toEqual([2, 1]);
    expect(list.items[0]?.revisions[0]?.detailsEnvelope).toEqual(secondEnvelope);

    const evidence = await current.pool.query<{
      eligibility_status: string;
      available: boolean;
      stored: string;
      outbox: string;
      audit: string;
      idempotency: string;
      response_statuses: number[];
    }>(
      `SELECT member.eligibility_status,member.available,
              COALESCE((SELECT jsonb_agg(to_jsonb(value))::text FROM member_qualification_versions value),'[]') AS stored,
              COALESCE((SELECT jsonb_agg(event.payload)::text FROM outbox_events event
                         WHERE event.aggregate_type='member-qualification'),'[]') AS outbox,
              COALESCE((SELECT jsonb_agg(event.metadata)::text FROM audit_events event
                         WHERE event.entity_type='member-qualification'),'[]') AS audit,
              COALESCE((SELECT jsonb_agg(record.response_body)::text FROM idempotency_records record
                         WHERE record.operation LIKE 'member.qualification.%'),'[]') AS idempotency,
              COALESCE((SELECT array_agg(record.response_status ORDER BY record.operation)
                          FROM idempotency_records record
                         WHERE record.operation LIKE 'member.qualification.%'),ARRAY[]::integer[]) AS response_statuses
         FROM members member WHERE member.id=$1`,
      [current.memberId],
    );
    const row = evidence.rows[0]!;
    expect(row).toMatchObject({ eligibility_status: "eligible", available: true });
    for (const serialized of [row.stored, row.outbox, row.audit, row.idempotency]) {
      expect(serialized).not.toContain(canaryTitle);
    }
    expect(row.outbox).not.toContain("ciphertext");
    expect(row.audit).not.toContain("ciphertext");
    expect(row.idempotency).not.toContain("ciphertext");
    for (const serialized of [row.outbox, row.audit]) {
      expect(serialized).not.toContain('"memberId"');
      expect(serialized).not.toContain('"type"');
      expect(serialized).not.toContain('"status"');
      expect(serialized).not.toContain('"effectiveOn"');
      expect(serialized).not.toContain('"expiresOn"');
      expect(serialized).not.toContain('"hasDetails"');
    }
    expect(row.response_statuses).toEqual([201, 201]);
  }, 30_000);

  it("pins the accepted lifecycle rows until the qualification transaction commits", async () => {
    const current = requireFixture();
    const writer = await current.pool.connect();
    let rotator: PoolClient | undefined;
    let writerCommitted = false;
    let rotatorRolledBack = false;
    try {
      rotator = await current.pool.connect();
      await writer.query("BEGIN");
      await setContext(writer, current.tenantId, current.identityId);
      const qualificationId = randomUUID();
      const envelope = qualificationEnvelope({
        tenantId: current.tenantId,
        memberId: current.memberId,
        qualificationId,
        version: 1,
        type: "ordination",
        status: "pending",
        effectiveOn: "2026-09-12",
        expiresOn: null,
        key: randomBytes(32),
        keyId: current.tenantKeyId,
        title: "Concurrent lifecycle pin",
      });
      await new MemberQualificationStore(writer).create({
        identityId: current.identityId,
        idempotencyKey: randomUUID(),
        memberId: current.memberId,
        qualificationId,
        type: "ordination",
        status: "pending",
        effectiveOn: "2026-09-12",
        expiresOn: null,
        detailsEnvelope: envelope,
        detailsContentHash: envelopeHash(envelope),
      });

      await rotator.query("BEGIN");
      const statusChange = rotator.query(
        "UPDATE e2ee_key_generations SET status='retired',retired_at=clock_timestamp() WHERE id=$1",
        [current.keyGenerationId],
      );
      const first = await Promise.race([
        statusChange.then(() => "updated" as const),
        new Promise<"blocked">((resolve) => setTimeout(() => resolve("blocked"), 75)),
      ]);
      expect(first).toBe("blocked");

      await writer.query("COMMIT");
      writerCommitted = true;
      await expect(statusChange).resolves.toMatchObject({ rowCount: 1 });
      await rotator.query("ROLLBACK");
      rotatorRolledBack = true;
    } finally {
      if (!writerCommitted) await writer.query("ROLLBACK").catch(() => undefined);
      if (!rotatorRolledBack) await rotator?.query("ROLLBACK").catch(() => undefined);
      writer.release();
      rotator?.release();
    }
  }, 30_000);

  it("accepts only an active real lifecycle grant and rejects a retired generation for new writes", async () => {
    const current = requireFixture();
    const nextGenerationId = randomUUID();
    const nextTenantKeyId = randomUUID();
    const client = await current.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "UPDATE e2ee_key_grants SET status='retired',retired_at=clock_timestamp() WHERE generation_id=$1",
        [current.keyGenerationId],
      );
      await client.query(
        "UPDATE e2ee_key_generations SET status='retired',retired_at=clock_timestamp() WHERE id=$1",
        [current.keyGenerationId],
      );
      await client.query(
        `INSERT INTO e2ee_key_generations(
           id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,
           created_by_identity_id,rotated_from_generation_id,rotation_reason
         ) VALUES ($1,$2,2,'active','{}',$3,$4,$5,'SCHEDULED_ROTATION')`,
        [nextGenerationId, nextTenantKeyId, `sha256:${"c".repeat(64)}`, current.identityId, current.keyGenerationId],
      );
      await client.query(
        `INSERT INTO e2ee_key_grants(
           generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,
           status,granted_by_identity_id
         ) VALUES ($1,$2,$3,'{}',$4,'rotation','active',$2)`,
        [nextGenerationId, current.identityId, current.keyDeviceId, `sha256:${"d".repeat(64)}`],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }

    const oldQualificationId = randomUUID();
    const oldEnvelope = qualificationEnvelope({
      tenantId: current.tenantId,
      memberId: current.memberId,
      qualificationId: oldQualificationId,
      version: 1,
      type: "ordination",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      key: randomBytes(32),
      keyId: current.tenantKeyId,
      title: "Retired key",
    });
    await expect(withStore(current, (store) => store.create({
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.memberId,
      qualificationId: oldQualificationId,
      type: "ordination",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      detailsEnvelope: oldEnvelope,
      detailsContentHash: envelopeHash(oldEnvelope),
    }))).rejects.toMatchObject({ code: "ENVELOPE_KEY_MISMATCH" });

    const nextQualificationId = randomUUID();
    const nextEnvelope = qualificationEnvelope({
      tenantId: current.tenantId,
      memberId: current.memberId,
      qualificationId: nextQualificationId,
      version: 1,
      type: "ordination",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      key: randomBytes(32),
      keyId: nextTenantKeyId,
      title: "Current key",
    });
    await expect(withStore(current, (store) => store.create({
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.memberId,
      qualificationId: nextQualificationId,
      type: "ordination",
      status: "pending",
      effectiveOn: "2026-09-12",
      expiresOn: null,
      detailsEnvelope: nextEnvelope,
      detailsContentHash: envelopeHash(nextEnvelope),
    }))).resolves.toMatchObject({ qualificationId: nextQualificationId, version: 1 });
  }, 30_000);

  it("rejects update, deletion and truncation while keeping unknown members neutral", async () => {
    const current = requireFixture();
    const qualification = await current.pool.query<{ qualification_id: string }>(
      "SELECT qualification_id FROM member_qualification_versions LIMIT 1",
    );
    const qualificationId = qualification.rows[0]?.qualification_id;
    expect(qualificationId).toBeTruthy();
    await expect(current.pool.query(
      `INSERT INTO member_qualification_versions(
         qualification_id,version,member_id,qualification_type,status,effective_on,
         expires_on,details_envelope,details_content_hash,reviewer_identity_id,supersedes_version
       ) VALUES ($1,3,$2,'ordination','verified','2026-09-12',NULL,NULL,NULL,$3,2)`,
      [qualificationId, current.otherMemberId, current.identityId],
    )).rejects.toMatchObject({ code: "23503" });
    await expect(current.pool.query(
      "UPDATE member_qualification_versions SET status='revoked' WHERE qualification_id=$1",
      [qualificationId],
    )).rejects.toMatchObject({ code: "55000" });
    await expect(current.pool.query(
      "DELETE FROM member_qualification_versions WHERE qualification_id=$1",
      [qualificationId],
    )).rejects.toMatchObject({ code: "55000" });
    await expect(current.pool.query("TRUNCATE member_qualification_versions"))
      .rejects.toMatchObject({ code: "55000" });
    await expect(current.pool.query(
      `INSERT INTO member_qualification_versions(
         qualification_id,version,member_id,qualification_type,status,effective_on,
         expires_on,details_envelope,details_content_hash,reviewer_identity_id,supersedes_version
       ) VALUES ($1,1,$2,'training','pending','2026-09-12',NULL,$3,$4,$5,NULL)`,
      [
        randomUUID(),
        current.memberId,
        { algorithm: "AES-256-GCM" },
        `sha256:${"e".repeat(64)}`,
        current.identityId,
      ],
    )).rejects.toMatchObject({ code: "23514" });
    await expect(withStore(current, (store) => store.listForMember(randomUUID())))
      .rejects.toMatchObject({
        code: "MEMBER_QUALIFICATION_NOT_FOUND",
        message: "Member qualification record was not found",
      });
  });
});

async function createFixture(databaseAdminUrl: string): Promise<Fixture> {
  const databaseName = `nom_qual_test_${randomBytes(12).toString("hex")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-qualification-live-cluster",
    max: 1,
  });
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, databaseName),
    application_name: "nombramientos-qualification-live-tenant",
    max: 3,
  });
  const tenantId = randomUUID();
  const identityId = randomUUID();
  const memberId = randomUUID();
  const otherMemberId = randomUUID();
  const tenantKeyId = randomUUID();
  const keyGenerationId = randomUUID();
  const keyDeviceId = randomUUID();
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [databaseName]);
    await runMigrations(pool, { scope: "tenant", directory: path.join(packageRoot, "migrations", "tenant") });
    await pool.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
       VALUES ($1,'Qualification live temporary tenant','real','America/La_Paz','es','ready')`,
      [tenantId],
    );
    await pool.query(
      `INSERT INTO e2ee_key_devices(
         device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
         status,activated_at
       ) VALUES ($1,$2,'Qualification live device','{}',$3,'active',clock_timestamp())`,
      [keyDeviceId, identityId, `sha256:${"a".repeat(64)}`],
    );
    await pool.query(
      `INSERT INTO e2ee_key_generations(
         id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,
         created_by_identity_id
       ) VALUES ($1,$2,1,'active','{}',$3,$4)`,
      [keyGenerationId, tenantKeyId, `sha256:${"b".repeat(64)}`, identityId],
    );
    await pool.query(
      `INSERT INTO e2ee_key_grants(
         generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,
         status,granted_by_identity_id
       ) VALUES ($1,$2,$3,'{}',$4,'initial','active',$2)`,
      [keyGenerationId, identityId, keyDeviceId, `sha256:${"c".repeat(64)}`],
    );
    const displayEnvelope = sealAesGcmJson(
      { displayName: "Synthetic qualification member" },
      randomBytes(32),
      "qualification-display-key-v1",
      { tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
    );
    await pool.query(
      `INSERT INTO members(id,stable_code,display_envelope,display_content_hash)
       VALUES ($1,$2,$3,$5),($4,$6,$3,$5)`,
      [
        memberId,
        `QUAL-${memberId.slice(0, 12)}`,
        displayEnvelope,
        otherMemberId,
        envelopeHash(displayEnvelope),
        `QUAL-${otherMemberId.slice(0, 12)}`,
      ],
    );
    return {
      cluster,
      pool,
      databaseName,
      tenantId,
      identityId,
      memberId,
      otherMemberId,
      tenantKeyId,
      keyGenerationId,
      keyDeviceId,
    };
  } catch (error) {
    return cleanupAfterFailure(error, () => cleanupQualificationDatabase(cluster, pool, databaseName), "Qualification fixture setup");
  }
}

async function withStore<T>(current: Fixture, work: (store: MemberQualificationStore) => Promise<T>): Promise<T> {
  const client = await current.pool.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, current.tenantId, current.identityId);
    const value = await work(new MemberQualificationStore(client));
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function qualificationEnvelope(input: {
  readonly tenantId: string;
  readonly memberId: string;
  readonly qualificationId: string;
  readonly version: number;
  readonly type: "ordination";
  readonly status: "pending" | "verified";
  readonly effectiveOn: string;
  readonly expiresOn: null;
  readonly key: Buffer;
  readonly keyId: string;
  readonly title: string;
}) {
  return sealAesGcmJson(
    { title: input.title, issuer: "PRIVATE_QUALIFICATION_ISSUER_CANARY" },
    input.key,
    input.keyId,
    {
      tenantId: input.tenantId,
      memberId: input.memberId,
      qualificationId: input.qualificationId,
      purpose: "member-qualification-details",
      schemaVersion: 1,
      version: input.version,
      type: input.type,
      status: input.status,
      effectiveOn: input.effectiveOn,
      expiresOn: input.expiresOn,
    },
  );
}

function envelopeHash(envelope: object): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`;
}

async function setContext(client: PoolClient, tenantId: string, identityId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [tenantId, identityId, randomUUID(), randomUUID()],
  );
}

async function cleanupFixture(current: Fixture): Promise<void> {
  await cleanupQualificationDatabase(current.cluster, current.pool, current.databaseName);
}

async function cleanupQualificationDatabase(cluster: Pool, pool: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [pool], assertSafeDatabaseName: assertQualificationDatabaseName }],
    label: "Temporary qualification database",
  });
}

function assertQualificationDatabaseName(databaseName: string): void {
  if (!/^nom_qual_test_[0-9a-f]{24}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-qualification-test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const result = await pool.query<{ sql: string }>(query, [...values]);
  const sql = result.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the qualification test statement");
  await pool.query(sql);
}

function requireFixture(): Fixture {
  if (!fixture) throw new Error("Qualification live fixture is unavailable");
  return fixture;
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed
        && typeof parsed.DATABASE_ADMIN_URL === "string") {
        candidate = parsed.DATABASE_ADMIN_URL;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({ connectionString: databaseUrl(databaseAdminUrl, "postgres"), connectionTimeoutMillis: 1_500, max: 1 });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!isLoopback(url.hostname) || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Qualification tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}
