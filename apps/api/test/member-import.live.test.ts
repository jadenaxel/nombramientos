import { createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DatabaseRuntime,
  TenantProvisioner,
  sealAesGcmJson,
  type EncryptedEnvelope,
  type WritableSecretProvider,
} from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import { Pool, type PoolConfig } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";
import {
  cleanupStageError,
  closePoolOwnerAndConfirmDrained,
  collectCleanupFailure,
  dropEphemeralDatabase,
  dropEphemeralRole,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";

const ORIGIN = "http://localhost:3000";
const USER_AGENT = "nombramientos-ac08-import-live-test";
const CONTROL_DATABASE = "nombramientos_control";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const migrationsRoot = path.join(workspaceRoot, "packages", "database", "migrations");
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverLocalAdminUrl();
const liveReady = adminUrl ? await canReachControl(adminUrl) : false;
const AC08_TEST_CATALOG = {
  version: "ac08-isolated",
  departments: [{
    canonicalCode: "ac08_department",
    names: { es: "Departamento AC-08", en: "AC-08 department", fr: "Département AC-08" },
    parentDepartmentCode: null,
  }],
  offices: [{
    canonicalCode: "ac08_office",
    departmentCode: "ac08_department",
    names: { es: "Cargo AC-08", en: "AC-08 office", fr: "Fonction AC-08" },
    mechanism: "church_election",
    cardinality: { minimum: 1, maximum: 1 },
  }],
} as const;

if (requireLiveIntegration && !liveReady) {
  throw new Error("NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires the reachable local PostgreSQL 18 workspace cluster");
}

const live = liveReady ? describe : describe.skip;

live("AC-08 live encrypted member import", () => {
  let fixture: ImportFixture | undefined;

  beforeAll(async () => {
    if (!adminUrl) throw new Error("The local administrator connection is unavailable");
    fixture = await createFixture(adminUrl);
  }, 60_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 60_000);

  it("previews explicit create/update/skip decisions, commits once, and preserves encrypted homonyms", async () => {
    const current = requireFixture(fixture);
    const createDisplayEnvelope = sealDisplay(current, current.createdMemberId, {
      displayName: "José Núñez",
      membershipStatus: "active",
    });
    const createContactEnvelope = sealContact(current, current.createdMemberId, {
      email: "homonimo@invalid.example",
    });
    const updateDisplayEnvelope = sealDisplay(current, current.updatedMemberId, {
      displayName: "María Álvarez",
      membershipStatus: "active",
    });
    const updateContactEnvelope = sealContact(current, current.updatedMemberId, {
      email: "maria.actualizada@invalid.example",
    });
    const payload = {
      sourceFingerprint: `sha256:${createHash("sha256").update(current.tenantId).digest("hex")}`,
      sourceFileName: "roster.csv",
      sourceSheetName: `sheet-sha256:${createHash("sha256").update("Padrón con tildes").digest("hex")}`,
      columnMapping: { sourceId: 0, displayName: 1, email: 2, eligible: 3 },
      rows: [
        {
          sourceRow: 2,
          id: current.createdMemberId,
          shortId: "AC08-NEW",
          eligible: true,
          decision: { action: "create", matchBasis: "normalized_name" },
          displayEnvelope: createDisplayEnvelope,
          displayContentHash: envelopeHash(createDisplayEnvelope),
          contactEnvelope: createContactEnvelope,
          contactContentHash: envelopeHash(createContactEnvelope),
        },
        {
          sourceRow: 3,
          id: current.updatedMemberId,
          shortId: "AC08-UPDATE",
          eligible: false,
          decision: { action: "update", matchBasis: "email" },
          expectedVersion: 1,
          displayEnvelope: updateDisplayEnvelope,
          displayContentHash: envelopeHash(updateDisplayEnvelope),
          contactEnvelope: updateContactEnvelope,
          contactContentHash: envelopeHash(updateContactEnvelope),
        },
        {
          sourceRow: 4,
          id: current.skippedMemberId,
          eligible: false,
          decision: { action: "skip", matchBasis: "normalized_name" },
        },
      ],
    } as const;
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain("José");
    expect(serialized).not.toContain("Núñez");
    expect(serialized).not.toContain("María");
    expect(serialized).not.toContain("Álvarez");
    expect(serialized).not.toContain("Padrón con tildes");

    const firstKey = randomUUID();
    const first = await requestImport(current, "/v1/members/import/preview", payload, firstKey);
    expect(first.statusCode, first.body).toBe(201);
    const firstData = first.json<{ data: ImportPreview }>().data;
    current.importId = firstData.importId;
    current.idempotencyKeys.push(firstKey);
    expect(firstData).toMatchObject({
      state: "previewed",
      revision: 1,
      counts: { create: 1, update: 1, skip: 1, errors: 0 },
    });
    expect(firstData.rows.map(({ status }) => status)).toEqual(["ready", "ready", "ready"]);

    const sameRequest = await requestImport(current, "/v1/members/import/preview", payload, firstKey);
    expect(sameRequest.statusCode).toBe(201);
    expect(sameRequest.json<{ data: ImportPreview }>().data.revision).toBe(firstData.revision);

    const refreshedKey = randomUUID();
    const refreshed = await requestImport(current, "/v1/members/import/preview", payload, refreshedKey);
    current.idempotencyKeys.push(refreshedKey);
    const refreshedData = refreshed.json<{ data: ImportPreview }>().data;
    expect(refreshedData.revision).toBe(firstData.revision + 1);
    const storedPreview = await current.tenant.query<{
      source_file_name: string; source_sheet_name: string; preview_text: string; errors: number;
    }>(
      `SELECT source_file_name,source_sheet_name,preview_envelopes::text AS preview_text,
              jsonb_array_length(error_report)::int AS errors
         FROM member_import_jobs WHERE id=$1`,
      [refreshedData.importId],
    );
    expect(storedPreview.rows[0]).toMatchObject({ source_file_name: "roster.csv", errors: 0 });
    expect(storedPreview.rows[0]?.source_sheet_name).toMatch(/^sheet-sha256:[0-9a-f]{64}$/);
    expect(storedPreview.rows[0]?.preview_text).not.toMatch(/José|Núñez|María|Álvarez|Padrón con tildes/);

    const staleKey = randomUUID();
    const stale = await requestImport(current, "/v1/members/import/commit", {
      importId: firstData.importId,
      expectedRevision: firstData.revision,
    }, staleKey);
    expect(stale.statusCode).toBe(409);
    expect(stale.json<{ error: { code: string } }>().error.code).toBe("IMPORT_PREVIEW_STALE");

    const commitKey = randomUUID();
    const committed = await requestImport(current, "/v1/members/import/commit", {
      importId: refreshedData.importId,
      expectedRevision: refreshedData.revision,
    }, commitKey);
    current.idempotencyKeys.push(commitKey);
    expect(committed.statusCode).toBe(200);
    expect(committed.json<{ data: ImportSummary }>().data).toMatchObject({
      state: "completed",
      created: 1,
      updated: 1,
      skipped: 1,
      rejected: 0,
      total: 3,
    });

    const replayKey = randomUUID();
    const replayed = await requestImport(current, "/v1/members/import/commit", {
      importId: refreshedData.importId,
      expectedRevision: refreshedData.revision,
    }, replayKey);
    current.idempotencyKeys.push(replayKey);
    expect(replayed.statusCode).toBe(200);
    expect(replayed.json<{ data: ImportSummary }>().data).toMatchObject({ created: 1, updated: 1, skipped: 1, replayed: true });

    const history = await current.app.inject({
      method: "GET",
      url: "/v1/members/imports?limit=10",
      headers: {
        origin: ORIGIN,
        "user-agent": USER_AGENT,
        cookie: `nom_session=${current.sessionToken}; nom_csrf=${current.csrfToken}`,
      },
    });
    expect(history.statusCode).toBe(200);
    const historyBody = history.json<{ data: { items: Array<Record<string, unknown>> } }>();
    expect(historyBody.data.items[0]).toMatchObject({
      id: refreshedData.importId,
      sourceFileName: "roster.csv",
      state: "completed",
      rowCount: 3,
      errorCount: 0,
      errors: [],
      errorsTruncated: false,
      revision: refreshedData.revision,
      summary: { created: 1, updated: 1, skipped: 1, rejected: 0, total: 3 },
    });
    expect(JSON.stringify(historyBody)).not.toMatch(/José|Núñez|María|Álvarez|Padrón con tildes/);

    const persisted = await current.tenant.query<{
      id: string;
      stable_code: string;
      version: number;
      display_envelope: EncryptedEnvelope;
      contact_envelope: EncryptedEnvelope;
      display_text: string;
      contact_text: string;
    }>(
      `SELECT id::text,stable_code,version,display_envelope,contact_envelope,
              display_envelope::text AS display_text,contact_envelope::text AS contact_text
         FROM members ORDER BY stable_code`,
    );
    expect(persisted.rows.map(({ stable_code }) => stable_code)).toEqual(["AC08-HOMONYM", "AC08-NEW", "AC08-UPDATE"]);
    expect(persisted.rows.find(({ id }) => id === current.updatedMemberId)?.version).toBe(2);
    expect(persisted.rows.some(({ id }) => id === current.skippedMemberId)).toBe(false);
    for (const row of persisted.rows) {
      expect(row.display_text).not.toMatch(/José|Núñez|María|Álvarez/);
      expect(row.contact_text).not.toMatch(/homonimo|maria\.actualizada|original@/);
    }
    const homonyms = persisted.rows
      .map((row) => ({ id: row.id, display: openDisplay(row.display_envelope, current.contentKey) }))
      .filter(({ display }) => normalize(display.displayName) === "jose nunez");
    expect(homonyms).toHaveLength(2);
    expect(new Set(homonyms.map(({ id }) => id)).size).toBe(2);
    expect(persisted.rows.map((row) => openContact(row.contact_envelope, current.contentKey).email)).toEqual(
      expect.arrayContaining(["original@invalid.example", "homonimo@invalid.example", "maria.actualizada@invalid.example"]),
    );
  }, 30_000);

  it("enforces the live contact projection, export permission, and split-record invariant", async () => {
    const current = requireFixture(fixture);
    const readerHeaders = {
      origin: ORIGIN,
      "user-agent": USER_AGENT,
      cookie: `nom_session=${current.readerSessionToken}; nom_csrf=${current.readerCsrfToken}`,
    };
    const storedContact = await current.tenant.query<{ ciphertext: string }>(
      "SELECT contact_envelope->>'ciphertext' AS ciphertext FROM members WHERE contact_envelope IS NOT NULL ORDER BY id",
    );
    expect(storedContact.rows.length).toBeGreaterThan(0);

    const restricted = await current.app.inject({ method: "GET", url: "/v1/members?limit=25", headers: readerHeaders });
    expect(restricted.statusCode, restricted.body).toBe(200);
    expect(restricted.json<{ data: { items: Array<Record<string, unknown>> } }>().data.items.length).toBeGreaterThan(0);
    expect(restricted.body).toContain("displayEnvelope");
    expect(restricted.body).not.toContain("contactEnvelope");
    for (const { ciphertext } of storedContact.rows) expect(restricted.body).not.toContain(ciphertext);

    const authorized = await current.app.inject({
      method: "GET",
      url: "/v1/members?limit=25",
      headers: {
        origin: ORIGIN,
        "user-agent": USER_AGENT,
        cookie: `nom_session=${current.sessionToken}; nom_csrf=${current.csrfToken}`,
      },
    });
    expect(authorized.statusCode, authorized.body).toBe(200);
    expect(authorized.body).toContain("contactEnvelope");
    for (const { ciphertext } of storedContact.rows) expect(authorized.body).toContain(ciphertext);

    const exportDenied = await current.app.inject({
      method: "POST",
      url: "/v1/members/export-authorizations",
      headers: {
        ...readerHeaders,
        "x-csrf-token": current.readerCsrfToken,
        "idempotency-key": randomUUID(),
      },
      payload: {
        format: "csv",
        rowCount: 1,
        includeContact: true,
        filters: { status: "all", queryApplied: false },
        selectionSha256: `sha256:${"a".repeat(64)}`,
      },
    });
    expect(exportDenied.statusCode, exportDenied.body).toBe(403);
    expect(exportDenied.body).not.toContain("contactEnvelope");
    for (const { ciphertext } of storedContact.rows) expect(exportDenied.body).not.toContain(ciphertext);

    const display = sealDisplay(current, randomUUID(), { displayName: "Invalid mixed fixture" });
    await expect(current.tenant.query(
      "INSERT INTO members(id,stable_code,eligibility_status,available) VALUES ($1,$2,'eligible',true)",
      [randomUUID(), `NO-DISPLAY-${randomUUID()}`],
    )).rejects.toMatchObject({ code: "23514" });
    await expect(current.tenant.query(
      `INSERT INTO members(
         id,stable_code,profile_envelope,display_envelope,display_content_hash,profile_migration_required,
         eligibility_status,available
       ) VALUES ($1,$2,$3,$4,$5,true,'eligible',true)`,
      [randomUUID(), `MIXED-${randomUUID()}`, display, display, envelopeHash(display)],
    )).rejects.toMatchObject({ code: "23514" });
    const migration = await current.tenant.query("SELECT 1 FROM schema_migrations WHERE name='025_member_contact_boundary.sql'");
    expect(migration.rowCount).toBe(1);
  }, 30_000);
});

interface ImportPreview {
  readonly importId: string;
  readonly state: "previewed" | "completed";
  readonly revision: number;
  readonly counts: { readonly create: number; readonly update: number; readonly skip: number; readonly errors: number };
  readonly rows: readonly { readonly status: "ready" | "error" }[];
}

interface ImportSummary {
  readonly state: "completed";
  readonly created: number;
  readonly updated: number;
  readonly skipped: number;
  readonly rejected: number;
  readonly total: number;
  readonly replayed?: boolean;
}

interface ImportFixture {
  readonly app: FastifyInstance;
  readonly database: DatabaseRuntime;
  readonly maintenance: Pool;
  readonly control: Pool;
  readonly tenant: Pool;
  readonly secrets: MemorySecrets;
  readonly tenantId: string;
  readonly databaseName: string;
  readonly ownerRole: string;
  readonly runtimeRole: string;
  readonly identityId: string;
  readonly sessionId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly readerIdentityId: string;
  readonly readerSessionToken: string;
  readonly readerCsrfToken: string;
  readonly contentKey: Buffer;
  readonly tenantKeyId: string;
  readonly updatedMemberId: string;
  readonly homonymMemberId: string;
  readonly createdMemberId: string;
  readonly skippedMemberId: string;
  readonly idempotencyKeys: string[];
  importId?: string;
}

class MemorySecrets implements WritableSecretProvider {
  readonly #values = new Map<string, string>();

  public async getSecret(reference: string): Promise<string> {
    const value = this.#values.get(reference);
    if (!value) throw new Error("AC-08 scratch secret is unavailable");
    return value;
  }

  public async putSecret(reference: string, value: string): Promise<void> {
    this.#values.set(reference, value);
  }

  public async hasSecret(reference: string): Promise<boolean> {
    return this.#values.has(reference);
  }

  public clear(): void {
    this.#values.clear();
  }
}

async function createFixture(databaseAdminUrl: string): Promise<ImportFixture> {
  const tenantId = randomUUID();
  const suffix = tenantId.replaceAll("-", "");
  const databaseName = `nom_t_${suffix}`;
  const ownerRole = `nom_o_${suffix}`;
  const runtimeRole = `nom_r_${suffix}`;
  const identityId = randomUUID();
  const readerIdentityId = randomUUID();
  const sessionId = randomUUID();
  const readerSessionId = randomUUID();
  const sessionToken = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(32).toString("base64url");
  const readerSessionToken = randomBytes(32).toString("base64url");
  const readerCsrfToken = randomBytes(32).toString("base64url");
  const contentKey = randomBytes(32);
  const tenantKeyId = randomUUID();
  const admin = poolConfig(databaseAdminUrl);
  const maintenance = new Pool({ ...admin, application_name: "nombramientos-ac08-maintenance", max: 1 });
  const control = new Pool({ ...admin, database: CONTROL_DATABASE, application_name: "nombramientos-ac08-control", max: 1 });
  const secrets = new MemorySecrets();
  let tenant: Pool | undefined;
  let app: FastifyInstance | undefined;
  let database: DatabaseRuntime | undefined;
  let provisionerClosed = false;
  const provisioner = new TenantProvisioner({
    admin,
    control,
    secrets,
    migrationsRoot,
    catalog: AC08_TEST_CATALOG,
  });
  try {
    await provisioner.provision({
      idempotencyKey: randomUUID(),
      tenantId,
      slug: `ac08-${suffix.slice(0, 12)}`,
      displayName: "AC-08 isolated import",
      kind: "real",
      timezone: "America/La_Paz",
      locale: "es",
    });
    await control.query(
      "UPDATE tenants SET status='active',activated_at=clock_timestamp() WHERE id=$1",
      [tenantId],
    );
    tenant = new Pool({ ...admin, database: databaseName, application_name: "nombramientos-ac08-tenant", max: 1 });
    await control.query(
      `INSERT INTO platform_identities(id,email,normalized_email,display_name,password_hash,mfa_enabled,status)
       VALUES ($1,$2,$2,'AC-08 Import Manager','AC08_DISABLED_NON_LOGIN_IDENTITY',false,'active')`,
      [identityId, `ac08-${suffix}@invalid.example`],
    );
    await control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [tenantId, identityId],
    );
    await control.query(
      `INSERT INTO platform_identities(
         id,email,normalized_email,display_name,password_hash,mfa_enabled,totp_secret_ciphertext,mfa_enrolled_at,status
       ) VALUES ($1,$2,$2,'AC-08 Restricted Reader','AC08_DISABLED_NON_LOGIN_IDENTITY',true,'AC08_TEST_TOTP_CIPHERTEXT',clock_timestamp(),'active')`,
      [readerIdentityId, `ac08-reader-${suffix}@invalid.example`],
    );
    await control.query(
      "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
      [tenantId, readerIdentityId],
    );
    await tenant.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       SELECT $1,id FROM roles WHERE code='CHURCH_ADMIN'`,
      [identityId],
    );
    await tenant.query(
      `INSERT INTO role_bindings(identity_id,role_id)
       SELECT $1,id FROM roles WHERE code='COMMITTEE_SECRETARY'`,
      [readerIdentityId],
    );
    const keyDeviceId = randomUUID();
    const keyGenerationId = randomUUID();
    await tenant.query(
      `INSERT INTO e2ee_key_devices(
         device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,status,activated_at
       ) VALUES ($1,$2,'AC-08 import device','{}'::jsonb,$3,'active',clock_timestamp())`,
      [keyDeviceId, identityId, `sha256:${randomBytes(32).toString("hex")}`],
    );
    await tenant.query(
      `INSERT INTO e2ee_key_generations(
         id,tenant_key_id,generation,status,recovery_public_key,recovery_key_fingerprint,created_by_identity_id
       ) VALUES ($1,$2,1,'active','{}'::jsonb,$3,$4)`,
      [keyGenerationId, tenantKeyId, `sha256:${randomBytes(32).toString("hex")}`, identityId],
    );
    await tenant.query(
      `INSERT INTO e2ee_key_grants(
         generation_id,identity_id,device_id,envelope,envelope_hash,grant_kind,status,granted_by_identity_id
       ) VALUES ($1,$2,$3,'{}'::jsonb,$4,'initial','active',$2)`,
      [keyGenerationId, identityId, keyDeviceId, `sha256:${randomBytes(32).toString("hex")}`],
    );
    await control.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash
       ) VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes',$6,$7)`,
      [sessionId, sha256(sessionToken), sha256(csrfToken), identityId, tenantId, sha256(USER_AGENT), sha256("127.0.0")],
    );
    await control.query(
      `INSERT INTO auth_sessions(
         id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash,
         assurance_level,mfa_verified_at
       ) VALUES ($1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes',$6,$7,'mfa',clock_timestamp())`,
      [readerSessionId, sha256(readerSessionToken), sha256(readerCsrfToken), readerIdentityId, tenantId, sha256(USER_AGENT), sha256("127.0.0")],
    );

    const updatedMemberId = randomUUID();
    const homonymMemberId = randomUUID();
    const createdMemberId = randomUUID();
    const skippedMemberId = randomUUID();
    const updatedDisplayEnvelope = sealAesGcmJson(
      { displayName: "María Álvarez", membershipStatus: "active" },
      contentKey,
      tenantKeyId,
      { tenantId, memberId: updatedMemberId, purpose: "member-display", schemaVersion: 1 },
    );
    const updatedContactEnvelope = sealAesGcmJson(
      { email: "maria@invalid.example" },
      contentKey,
      tenantKeyId,
      { tenantId, memberId: updatedMemberId, purpose: "member-contact", schemaVersion: 1 },
    );
    const homonymDisplayEnvelope = sealAesGcmJson(
      { displayName: "José Núñez", membershipStatus: "active" },
      contentKey,
      tenantKeyId,
      { tenantId, memberId: homonymMemberId, purpose: "member-display", schemaVersion: 1 },
    );
    const homonymContactEnvelope = sealAesGcmJson(
      { email: "original@invalid.example" },
      contentKey,
      tenantKeyId,
      { tenantId, memberId: homonymMemberId, purpose: "member-contact", schemaVersion: 1 },
    );
    await tenant.query(
      `INSERT INTO members(
         id,stable_code,display_envelope,display_content_hash,contact_envelope,contact_content_hash,
         eligibility_status,available
       ) VALUES
         ($1,'AC08-UPDATE',$2,$3,$4,$5,'eligible',true),
         ($6,'AC08-HOMONYM',$7,$8,$9,$10,'eligible',true)`,
      [
        updatedMemberId,
        updatedDisplayEnvelope,
        envelopeHash(updatedDisplayEnvelope),
        updatedContactEnvelope,
        envelopeHash(updatedContactEnvelope),
        homonymMemberId,
        homonymDisplayEnvelope,
        envelopeHash(homonymDisplayEnvelope),
        homonymContactEnvelope,
        envelopeHash(homonymContactEnvelope),
      ],
    );

    const config = parseApiConfig();
    database = new DatabaseRuntime({
      control: { connectionString: config.controlDatabaseUrl, application_name: "nombramientos-ac08-api", max: 2, ssl: false },
      secretProvider: secrets,
      tenantPoolMax: 1,
      tenantPoolIdleMs: 5_000,
    });
    app = await buildServer({ config, database, logger: false, closeDatabaseOnShutdown: false });
    await provisioner.close();
    provisionerClosed = true;
    return {
      app,
      database,
      maintenance,
      control,
      tenant,
      secrets,
      tenantId,
      databaseName,
      ownerRole,
      runtimeRole,
      identityId,
      sessionId,
      sessionToken,
      csrfToken,
      readerIdentityId,
      readerSessionToken,
      readerCsrfToken,
      contentKey,
      tenantKeyId,
      updatedMemberId,
      homonymMemberId,
      createdMemberId,
      skippedMemberId,
      idempotencyKeys: [],
    };
  } catch (error) {
    const failures = [cleanupStageError("AC-08 fixture setup", error)];
    await collectCleanupFailure(failures, "AC-08 API close after setup failure", async () => app?.close());
    if (database) {
      await collectCleanupFailure(failures, "AC-08 runtime close after setup failure", async () => {
        await closePoolOwnerAndConfirmDrained(
          [{ pool: database!.controlPool, label: "AC-08 runtime control pool" }],
          async () => database!.close(),
          "AC-08 database runtime close",
        );
      });
    }
    if (tenant) {
      await collectCleanupFailure(failures, "AC-08 tenant pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(tenant!, "AC-08 fixture tenant pool");
      });
    }
    if (!provisionerClosed) {
      await collectCleanupFailure(failures, "AC-08 provisioner close after setup failure", async () => provisioner.close());
    }
    try {
      await collectCleanupFailure(failures, "AC-08 scratch cleanup after setup failure", async () => {
        await cleanupScratchResources(maintenance, control, {
          tenantId, databaseName, ownerRole, runtimeRole, identityId, readerIdentityId,
        });
      });
    } finally {
      await collectCleanupFailure(failures, "AC-08 control pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(control, "AC-08 control pool");
      });
      await collectCleanupFailure(failures, "AC-08 maintenance pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(maintenance, "AC-08 maintenance pool");
      });
    }
    secrets.clear();
    contentKey.fill(0);
    throw new AggregateError(failures, "AC-08 fixture setup failed closed");
  }
}

async function cleanupFixture(fixture: ImportFixture): Promise<void> {
  const failures: Error[] = [];
  let runtimeTenantPool: Pool | undefined;
  await collectCleanupFailure(failures, "AC-08 runtime tenant pool lookup", async () => {
    runtimeTenantPool = await fixture.database.tenantPools.getPool(fixture.tenantId);
  });
  await collectCleanupFailure(failures, "AC-08 API close", async () => fixture.app.close());
  await collectCleanupFailure(failures, "AC-08 database runtime close", async () => {
    await closePoolOwnerAndConfirmDrained(
      [
        { pool: fixture.database.controlPool, label: "AC-08 runtime control pool" },
        ...(runtimeTenantPool ? [{ pool: runtimeTenantPool, label: "AC-08 runtime tenant pool" }] : []),
      ],
      async () => fixture.database.close(),
      "AC-08 database runtime close",
    );
  });
  await collectCleanupFailure(failures, "AC-08 fixture tenant pool close", async () => {
    await endPoolAndConfirmDrained(fixture.tenant, "AC-08 fixture tenant pool");
  });
  try {
    await collectCleanupFailure(failures, "AC-08 scratch resource cleanup", async () => {
      await cleanupScratchResources(fixture.maintenance, fixture.control, fixture);
    });
    await collectCleanupFailure(failures, "AC-08 scratch residue attestation", async () => {
      const remaining = await fixture.control.query<{ count: number }>(
        `SELECT (
           (SELECT count(*) FROM tenants WHERE id=$1)
           + (SELECT count(*) FROM provisioning_jobs WHERE tenant_id=$1)
           + (SELECT count(*) FROM tenant_memberships WHERE tenant_id=$1 OR identity_id=ANY($2::uuid[]))
           + (SELECT count(*) FROM auth_sessions WHERE identity_id=ANY($2::uuid[]))
           + (SELECT count(*) FROM platform_identities WHERE id=ANY($2::uuid[]))
         )::int AS count`,
        [fixture.tenantId, [fixture.identityId, fixture.readerIdentityId]],
      );
      const cluster = await fixture.maintenance.query<{ databases: number; roles: number }>(
        `SELECT
           (SELECT count(*)::int FROM pg_database WHERE datname=$1) AS databases,
           (SELECT count(*)::int FROM pg_roles WHERE rolname=ANY($2::text[])) AS roles`,
        [fixture.databaseName, [fixture.ownerRole, fixture.runtimeRole]],
      );
      if (remaining.rows[0]?.count !== 0 || cluster.rows[0]?.databases !== 0 || cluster.rows[0]?.roles !== 0) {
        throw new Error("AC-08 scratch fixture cleanup was incomplete");
      }
    });
  } finally {
    await collectCleanupFailure(failures, "AC-08 control pool close", async () => {
      await endPoolAndConfirmDrained(fixture.control, "AC-08 control pool");
    });
    await collectCleanupFailure(failures, "AC-08 maintenance pool close", async () => {
      await endPoolAndConfirmDrained(fixture.maintenance, "AC-08 maintenance pool");
    });
  }
  fixture.secrets.clear();
  fixture.contentKey.fill(0);
  if (failures.length > 0) throw new AggregateError(failures, "AC-08 scratch fixture cleanup failed closed");
}

async function cleanupScratchResources(
  maintenance: Pool,
  control: Pool,
  fixture: Pick<ImportFixture, "tenantId" | "databaseName" | "ownerRole" | "runtimeRole" | "identityId" | "readerIdentityId">,
): Promise<void> {
  assertImportEphemeralNames(fixture);
  const identities = [fixture.identityId, fixture.readerIdentityId];
  const client = await control.connect();
  try {
    await client.query("BEGIN");
    const route = await client.query<{ database_name: string; runtime_role: string }>(
      "SELECT database_name::text,runtime_role::text FROM tenants WHERE id=$1 FOR UPDATE",
      [fixture.tenantId],
    );
    const row = route.rows[0];
    if (row && (row.database_name !== fixture.databaseName || row.runtime_role !== fixture.runtimeRole)) {
      throw new Error("Refusing AC-08 cleanup for mismatched tenant metadata");
    }
    await client.query("DELETE FROM auth_sessions WHERE identity_id=ANY($1::uuid[])", [identities]);
    await client.query("DELETE FROM tenant_memberships WHERE tenant_id=$1 OR identity_id=ANY($2::uuid[])", [fixture.tenantId, identities]);
    await client.query("DELETE FROM platform_identities WHERE id=ANY($1::uuid[])", [identities]);
    await client.query("DELETE FROM tenants WHERE id=$1", [fixture.tenantId]);
    await client.query("DELETE FROM provisioning_jobs WHERE tenant_id=$1", [fixture.tenantId]);
    await client.query("COMMIT");
  } catch (error) {
    const failures = [cleanupStageError("AC-08 control transaction", error)];
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      failures.push(cleanupStageError("AC-08 control rollback", rollbackError));
    }
    throw new AggregateError(failures, "AC-08 control cleanup failed closed");
  } finally {
    client.release();
  }

  const failures: Error[] = [];
  await collectCleanupFailure(failures, "AC-08 database drop", async () => dropEphemeralDatabase(
    maintenance,
    fixture.databaseName,
    { pattern: /^nom_t_[0-9a-f]{32}$/u, label: "AC-08 scratch database" },
  ));
  await collectCleanupFailure(failures, "AC-08 runtime role drop", async () => dropEphemeralRole(
    maintenance,
    fixture.runtimeRole,
    { pattern: /^nom_r_[0-9a-f]{32}$/u, label: "AC-08 runtime role" },
  ));
  await collectCleanupFailure(failures, "AC-08 owner role drop", async () => dropEphemeralRole(
    maintenance,
    fixture.ownerRole,
    { pattern: /^nom_o_[0-9a-f]{32}$/u, label: "AC-08 owner role" },
  ));
  if (failures.length > 0) throw new AggregateError(failures, "AC-08 PostgreSQL cleanup failed closed");
}

function assertImportEphemeralNames(
  fixture: Pick<ImportFixture, "tenantId" | "databaseName" | "ownerRole" | "runtimeRole">,
): void {
  const suffix = fixture.tenantId.replaceAll("-", "");
  if (
    !/^[0-9a-f]{32}$/u.test(suffix)
    || fixture.databaseName !== `nom_t_${suffix}`
    || fixture.ownerRole !== `nom_o_${suffix}`
    || fixture.runtimeRole !== `nom_r_${suffix}`
  ) {
    throw new Error("Refusing cleanup outside the exact AC-08 scratch tenant boundary");
  }
}

async function requestImport(fixture: ImportFixture, url: string, payload: unknown, idempotencyKey: string) {
  const response = await fixture.app.inject({
    method: "POST",
    url,
    headers: {
      origin: ORIGIN,
      "user-agent": USER_AGENT,
      cookie: `nom_session=${fixture.sessionToken}; nom_csrf=${fixture.csrfToken}`,
      "x-csrf-token": fixture.csrfToken,
      "idempotency-key": idempotencyKey,
      "content-type": "application/json",
    },
    payload: JSON.stringify(payload),
  });
  return response;
}

function sealDisplay(fixture: ImportFixture, memberId: string, display: Readonly<Record<string, unknown>>): EncryptedEnvelope {
  return sealAesGcmJson(display, fixture.contentKey, fixture.tenantKeyId, {
    tenantId: fixture.tenantId,
    memberId,
    purpose: "member-display",
    schemaVersion: 1,
  });
}

function sealContact(fixture: ImportFixture, memberId: string, contact: Readonly<Record<string, unknown>>): EncryptedEnvelope {
  return sealAesGcmJson(contact, fixture.contentKey, fixture.tenantKeyId, {
    tenantId: fixture.tenantId,
    memberId,
    purpose: "member-contact",
    schemaVersion: 1,
  });
}

function openDisplay(envelope: EncryptedEnvelope, key: Buffer): { displayName: string } {
  return openEnvelope(envelope, key) as { displayName: string };
}

function openContact(envelope: EncryptedEnvelope, key: Buffer): { email: string } {
  return openEnvelope(envelope, key) as { email: string };
}

function openEnvelope(envelope: EncryptedEnvelope, key: Buffer): unknown {
  const encrypted = Buffer.from(envelope.ciphertext, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(Buffer.from(envelope.aad, "base64url"));
  decipher.setAuthTag(encrypted.subarray(-16));
  const clear = Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]);
  return JSON.parse(clear.toString("utf8")) as unknown;
}

function envelopeHash(envelope: EncryptedEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function normalize(value: string): string {
  return value.normalize("NFKD").replace(/\p{M}/gu, "").toLocaleLowerCase("es");
}

function requireFixture(fixture: ImportFixture | undefined): ImportFixture {
  if (!fixture) throw new Error("AC-08 import fixture is unavailable");
  return fixture;
}

function discoverLocalAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const value: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (value && typeof value === "object" && "DATABASE_ADMIN_URL" in value && typeof value.DATABASE_ADMIN_URL === "string") {
        candidate = value.DATABASE_ADMIN_URL;
      }
    }
    if (!candidate) return undefined;
    return assertExactWorkspaceAdminUrl(candidate);
  } catch {
    return undefined;
  }
}

async function canReachControl(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({ ...poolConfig(databaseAdminUrl), database: CONTROL_DATABASE, connectionTimeoutMillis: 1_500, max: 1 });
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await endPoolAndConfirmDrained(pool, "AC-08 reachability pool");
  }
}

function poolConfig(databaseAdminUrl: string): PoolConfig {
  const parsed = new URL(databaseAdminUrl);
  if (parsed.port !== "55432" || !["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname)) {
    throw new Error("AC-08 live test refuses PostgreSQL outside the workspace loopback cluster on port 55432");
  }
  return {
    host: parsed.hostname === "[::1]" ? "::1" : parsed.hostname,
    port: 55432,
    database: decodeURIComponent(parsed.pathname.replace(/^\//, "")) || "postgres",
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    ssl: false,
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
