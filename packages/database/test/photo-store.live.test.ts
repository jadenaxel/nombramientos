import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bindDirectFixtureSession } from "./direct-device-session-fixture.js";
import {
  createTenantKeyGrantEnvelope,
  exportCustodianSigningPublicKey,
  exportTenantDevicePublicKey,
  generateCustodianSigningKeyPair,
  generateTenantDeviceKeyPair,
  openTenantKeyGrantEnvelope,
  verifyTenantKeyGrantEnvelope,
  type CustodianPrivateKey,
  type TenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";
import { Pool, type PoolClient } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { runMigrations } from "../src/migrations.js";
import { PhotoStore, type PhotoAssetMetadata } from "../src/photo-store.js";
import { cleanupTemporaryDatabases } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;

if (requireLive && !reachable) {
  throw new Error("Photo live tests require PostgreSQL 18 on the isolated loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

type TenantContentKey = Uint8Array<ArrayBuffer>;

interface TenantFixture {
  readonly pool: Pool;
  readonly databaseName: string;
  readonly tenantId: string;
  readonly memberId: string;
  readonly tenantKeyId: string;
  readonly generationId: string;
  readonly deviceId: string;
}

interface LiveFixture {
  readonly cluster: Pool;
  readonly first: TenantFixture;
  readonly second: TenantFixture;
  readonly identityId: string;
  readonly photoContentKey: TenantContentKey;
  readonly sensitiveContentKeys: TenantContentKey[];
  readonly devicePrivateKeys: CustodianPrivateKey[];
  readonly privacyLeakProbes: PrivacyLeakProbes;
}

interface PrivacyLeakProbes {
  readonly clearImage: string;
  readonly exif: string;
  readonly originalFilename: string;
  readonly contentKey: string;
}

let fixture: LiveFixture | undefined;

live("AC-04/31 tenant-isolated E2EE member photographs", () => {
  beforeAll(async () => {
    if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
    fixture = await createFixture(adminUrl);
  }, 30_000);

  afterAll(async () => {
    const current = fixture;
    fixture = undefined;
    if (current) await cleanupFixture(current);
  }, 30_000);

  it("creates, reads, replaces and archives authentic ciphertext with idempotency and immutable history", async () => {
    const current = requireFixture();
    const firstKey = current.photoContentKey;
    const firstPhotoId = randomUUID();
    const firstEncrypted = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: firstPhotoId,
      version: 1,
      key: firstKey,
      keyId: current.first.tenantKeyId,
      plaintextProbe: encodePrivacyLeakProbes(current.privacyLeakProbes),
    });
    for (const [kind, marker] of Object.entries(current.privacyLeakProbes)) {
      expect(
        firstEncrypted.plaintext.includes(Buffer.from(marker, "utf8")),
        `The encrypted photo fixture must contain the ${kind} cleartext probe`,
      ).toBe(true);
    }
    const firstIdempotency = randomUUID();
    const firstInput = {
      identityId: current.identityId,
      idempotencyKey: firstIdempotency,
      memberId: current.first.memberId,
      photoId: firstPhotoId,
      expectedVersion: 0,
      version: 1,
      mediaType: "image/jpeg" as const,
      width: 512,
      height: 512,
      plaintextBytes: firstEncrypted.plaintext.byteLength,
      envelope: firstEncrypted.envelope,
      contentHash: firstEncrypted.contentHash,
    };
    const created = await withPhotoStore(current.first, current.identityId, (store) => store.putPhoto(firstInput));
    const replayed = await withPhotoStore(current.first, current.identityId, (store) => store.putPhoto(firstInput));
    expect(replayed).toEqual(created);
    expect(created).toMatchObject({ id: firstPhotoId, memberId: current.first.memberId, version: 1, archivedAt: null });

    const read = await withPhotoStore(current.first, current.identityId, (store) =>
      store.getActivePhoto(current.first.memberId));
    expect(openEnvelope(read.envelope, firstKey)).toEqual(firstEncrypted.plaintext);
    expect(() => openEnvelope(read.envelope, randomBytes(32))).toThrow();

    const secondPhotoId = randomUUID();
    const secondEncrypted = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: secondPhotoId,
      version: 2,
      key: current.photoContentKey,
      keyId: current.first.tenantKeyId,
    });
    const replaced = await withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
      ...firstInput,
      idempotencyKey: randomUUID(),
      photoId: secondPhotoId,
      expectedVersion: 1,
      version: 2,
      plaintextBytes: secondEncrypted.plaintext.byteLength,
      envelope: secondEncrypted.envelope,
      contentHash: secondEncrypted.contentHash,
    }));
    expect(replaced).toMatchObject({ id: secondPhotoId, version: 2, archivedAt: null });

    await expect(withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
      ...firstInput,
      idempotencyKey: randomUUID(),
      photoId: randomUUID(),
      expectedVersion: 1,
      version: 2,
    }))).rejects.toMatchObject({ statusCode: 409, code: "PHOTO_VERSION_CONFLICT" });

    const archiveIdempotency = randomUUID();
    const archiveInput = {
      identityId: current.identityId,
      idempotencyKey: archiveIdempotency,
      memberId: current.first.memberId,
      expectedVersion: 2,
    };
    const archived = await withPhotoStore(current.first, current.identityId, (store) => store.archivePhoto(archiveInput));
    const archiveReplay = await withPhotoStore(current.first, current.identityId, (store) => store.archivePhoto(archiveInput));
    expect(archiveReplay).toEqual(archived);
    expect(archived.archivedAt).toEqual(expect.any(String));
    await expect(withPhotoStore(current.first, current.identityId, (store) =>
      store.getActivePhoto(current.first.memberId))).rejects.toMatchObject({ statusCode: 404, code: "PHOTO_NOT_FOUND" });

    const writeContext = await withPhotoStore(current.first, current.identityId, (store) =>
      store.getPhotoWriteContext(current.first.memberId));
    expect(writeContext).toEqual({ expectedVersion: 0, nextVersion: 3 });
    const thirdPhotoId = randomUUID();
    const thirdEncrypted = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: thirdPhotoId,
      version: 3,
      key: current.photoContentKey,
      keyId: current.first.tenantKeyId,
    });
    const recreated = await withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
      ...firstInput,
      idempotencyKey: randomUUID(),
      photoId: thirdPhotoId,
      expectedVersion: 0,
      version: 3,
      plaintextBytes: thirdEncrypted.plaintext.byteLength,
      envelope: thirdEncrypted.envelope,
      contentHash: thirdEncrypted.contentHash,
    }));
    expect(recreated).toMatchObject({ id: thirdPhotoId, version: 3, archivedAt: null });
    await withPhotoStore(current.first, current.identityId, (store) => store.archivePhoto({
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.first.memberId,
      expectedVersion: 3,
    }));

    const rows = await current.first.pool.query<{
      version: number;
      archived: boolean;
      original_metadata_columns: number;
    }>(
      `SELECT photo.version,(photo.archived_at IS NOT NULL) AS archived,
              (SELECT count(*)::int FROM information_schema.columns
                WHERE table_schema='public' AND table_name='member_photo_assets'
                  AND column_name = ANY(ARRAY['original_filename','original_bytes','exif','gps','content_key','private_key']))
                AS original_metadata_columns
         FROM member_photo_assets photo
        ORDER BY photo.version`,
    );
    expect(rows.rows).toEqual([
      { version: 1, archived: true, original_metadata_columns: 0 },
      { version: 2, archived: true, original_metadata_columns: 0 },
      { version: 3, archived: true, original_metadata_columns: 0 },
    ]);
  }, 30_000);

  it("keeps foreign object identifiers neutral and stores no clear image, EXIF, filename or key in DB/event metadata", async () => {
    const current = requireFixture();
    await expect(withPhotoStore(current.second, current.identityId, (store) =>
      store.getActivePhoto(current.first.memberId))).rejects.toMatchObject({
      statusCode: 404,
      code: "PHOTO_NOT_FOUND",
      message: "Photograph was not found",
    });
    await expect(withPhotoStore(current.second, current.identityId, (store) =>
      store.getActivePhoto(randomUUID()))).rejects.toMatchObject({
      statusCode: 404,
      code: "PHOTO_NOT_FOUND",
      message: "Photograph was not found",
    });

    const evidence = await current.first.pool.query<{
      serialized_photos: string;
      serialized_events: string;
      serialized_idempotency: string;
      serialized_audits: string;
      audit_actions: string[];
      read_audits: Array<{
        action: string; actorIdentityId: string | null; requestId: string | null;
        entityType: string | null; entityId: string | null; metadata: Record<string, unknown>;
      }>;
    }>(
      `SELECT
         COALESCE((SELECT jsonb_agg(to_jsonb(photo))::text FROM member_photo_assets photo),'[]') AS serialized_photos,
         COALESCE((SELECT jsonb_agg(event.payload)::text FROM outbox_events event
                    WHERE event.aggregate_type='member-photo'),'[]') AS serialized_events,
         COALESCE((SELECT jsonb_agg(record.response_body)::text FROM idempotency_records record
                    WHERE record.operation LIKE 'member.photo.%'),'[]') AS serialized_idempotency,
         COALESCE((SELECT jsonb_agg(audit.metadata)::text FROM audit_events audit
                    WHERE audit.entity_type='member-photo'),'[]') AS serialized_audits,
         COALESCE((SELECT array_agg(audit.action ORDER BY audit.sequence) FROM audit_events audit
                    WHERE audit.entity_type='member-photo'),ARRAY[]::text[]) AS audit_actions,
         COALESCE((SELECT jsonb_agg(jsonb_build_object(
                      'action',audit.action,
                      'actorIdentityId',audit.actor_identity_id,
                      'requestId',audit.request_id,
                      'entityType',audit.entity_type,
                      'entityId',audit.entity_id,
                      'metadata',audit.metadata
                    ) ORDER BY audit.sequence)
                   FROM audit_events audit WHERE audit.action='member.photo.read'),'[]') AS read_audits`,
    );
    const row = evidence.rows[0];
    expect(row).toBeTruthy();
    const serializedSurfaces = [
      ["photo rows", row?.serialized_photos],
      ["outbox metadata", row?.serialized_events],
      ["idempotency responses", row?.serialized_idempotency],
      ["audit metadata", row?.serialized_audits],
    ] as const;
    for (const [kind, clearMarker] of Object.entries(current.privacyLeakProbes)) {
      for (const [surface, serialized] of serializedSurfaces) {
        expect(
          serialized?.includes(clearMarker) ?? false,
          `${surface} must not contain the ${kind} cleartext probe`,
        ).toBe(false);
      }
    }
    expect(row?.serialized_events.includes("ciphertext") ?? false, "Outbox metadata must not contain ciphertext").toBe(false);
    expect(row?.serialized_events.includes("nonce") ?? false, "Outbox metadata must not contain a nonce").toBe(false);
    expect(row?.serialized_idempotency.includes("ciphertext") ?? false, "Idempotency responses must not contain ciphertext").toBe(false);
    expect(row?.serialized_audits.includes("ciphertext") ?? false, "Audit metadata must not contain ciphertext").toBe(false);
    expect(row?.audit_actions).toEqual([
      "member.photo.created",
      "member.photo.read",
      "member.photo.replaced",
      "member.photo.archived",
      "member.photo.created",
      "member.photo.archived",
    ]);
    expect(row?.read_audits).toEqual([
      expect.objectContaining({
        action: "member.photo.read",
        actorIdentityId: current.identityId,
        requestId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        entityType: "member-photo",
        entityId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        metadata: { memberId: current.first.memberId, version: 1 },
      }),
    ]);
    expect(photoPrivacyViolations({
      ciphertext: "opaque",
      nested: {
        nonce: "opaque",
        aad: "opaque",
        contentHash: "opaque",
        digest: `sha256:${"0".repeat(64)}`,
      },
    })).toEqual([
      "$readAudits.ciphertext:forbidden-key",
      "$readAudits.nested.nonce:forbidden-key",
      "$readAudits.nested.aad:forbidden-key",
      "$readAudits.nested.contentHash:forbidden-key",
      "$readAudits.nested.digest:forbidden-value",
    ]);
    expect(photoPrivacyViolations({ requestId: "aaaaaaaa-aada-4aaa-8aaa-aaaaaaaaaaaa" })).toEqual([]);
    expect(photoPrivacyViolations(row?.read_audits)).toEqual([]);
  });

  it("rejects ciphertext mutation, deletion and unarchival even for direct SQL", async () => {
    const current = requireFixture();
    const first = await current.first.pool.query<{ id: string }>(
      "SELECT id FROM member_photo_assets ORDER BY version LIMIT 1",
    );
    const photoId = first.rows[0]?.id;
    expect(photoId).toBeTruthy();
    await expect(current.first.pool.query(
      "UPDATE member_photo_assets SET content_hash=$2 WHERE id=$1",
      [photoId, `sha256:${"0".repeat(64)}`],
    )).rejects.toMatchObject({ code: "55000" });
    await expect(current.first.pool.query(
      "UPDATE member_photo_assets SET archived_at=NULL,archived_by_identity_id=NULL WHERE id=$1",
      [photoId],
    )).rejects.toMatchObject({ code: "55000" });
    await expect(current.first.pool.query("DELETE FROM member_photo_assets WHERE id=$1", [photoId]))
      .rejects.toMatchObject({ code: "55000" });
  });

  it("uses only real lifecycle grants, preserves historical reads after rotation and rejects stale, arbitrary or revoked keys", async () => {
    const current = requireFixture();
    const legacy = await current.first.pool.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM device_key_grants WHERE identity_id=$1",
      [current.identityId],
    );
    expect(legacy.rows[0]?.count).toBe(0);

    const historicalPhotoId = randomUUID();
    const historical = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: historicalPhotoId,
      version: 4,
      key: current.photoContentKey,
      keyId: current.first.tenantKeyId,
    });
    const historicalInput = {
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.first.memberId,
      photoId: historicalPhotoId,
      expectedVersion: 0,
      version: 4,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: historical.plaintext.byteLength,
      envelope: historical.envelope,
      contentHash: historical.contentHash,
    } as const;
    const historicalCreated = await withPhotoStore(current.first, current.identityId, (store) =>
      store.putPhoto(historicalInput));

    const nextGenerationId = randomUUID();
    const nextTenantKeyId = randomUUID();
    const nextTenantContentKey = randomTenantContentKey();
    current.sensitiveContentKeys.push(nextTenantContentKey);
    const rotationDeviceKey = requireDevicePrivateKey(current, 0);
    const rotationEnvelope = await createTenantKeyGrantEnvelope({
      tenantId: current.first.tenantId,
      tenantKeyId: nextTenantKeyId,
      generation: 2,
      identityId: current.identityId,
      deviceId: current.first.deviceId,
      tenantKey: nextTenantContentKey,
      recipient: rotationDeviceKey,
    });
    await assertGrantRoundTrip({
      envelope: rotationEnvelope,
      recipient: rotationDeviceKey,
      tenantId: current.first.tenantId,
      tenantKeyId: nextTenantKeyId,
      generation: 2,
      identityId: current.identityId,
      deviceId: current.first.deviceId,
      expectedKey: nextTenantContentKey,
    });
    const rotationRecoverySigningKey = await generateCustodianSigningKeyPair();
    const rotationRecoveryPublicKey = await exportCustodianSigningPublicKey(rotationRecoverySigningKey);
    const rotationClient = await current.first.pool.connect();
    try {
      await rotationClient.query("BEGIN");
      await rotationClient.query(
        `UPDATE e2ee_key_grants
            SET status='retired',version=version+1,retired_at=clock_timestamp()
          WHERE generation_id=$1 AND status='active'`,
        [current.first.generationId],
      );
      await rotationClient.query(
        `UPDATE e2ee_key_generations
            SET status='retired',retired_at=clock_timestamp()
          WHERE id=$1 AND status='active'`,
        [current.first.generationId],
      );
      await rotationClient.query(
        `INSERT INTO e2ee_key_generations(
           id,tenant_key_id,generation,status,recovery_public_key,
           recovery_key_fingerprint,created_by_identity_id,rotated_from_generation_id
         ) VALUES ($1,$2,2,'active',$3,$4,$5,$6)`,
        [
          nextGenerationId,
          nextTenantKeyId,
          rotationRecoveryPublicKey,
          rotationRecoveryPublicKey.fingerprint,
          current.identityId,
          current.first.generationId,
        ],
      );
      await rotationClient.query(
        `INSERT INTO e2ee_key_grants(
           generation_id,identity_id,device_id,envelope,envelope_hash,
           grant_kind,status,granted_by_identity_id
         ) VALUES ($1,$2,$3,$4,$5,'rotation','active',$2)`,
        [
          nextGenerationId,
          current.identityId,
          current.first.deviceId,
          rotationEnvelope,
          rotationEnvelope.envelopeHash,
        ],
      );
      await rotationClient.query("COMMIT");
    } catch (error) {
      await rotationClient.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      rotationClient.release();
    }
    await assertPersistedGrantHash(current.first.pool, nextGenerationId);

    const historicalRead = await withPhotoStore(current.first, current.identityId, (store) =>
      store.getActivePhoto(current.first.memberId));
    expect(historicalRead.envelope.keyId).toBe(current.first.tenantKeyId);
    expect(openEnvelope(historicalRead.envelope, current.photoContentKey)).toEqual(historical.plaintext);
    await expect(withPhotoStore(current.first, current.identityId, (store) =>
      store.putPhoto(historicalInput))).resolves.toEqual(JSON.parse(JSON.stringify(historicalCreated)));

    for (const rejectedKeyId of [current.first.tenantKeyId, randomUUID()]) {
      const rejectedPhotoId = randomUUID();
      const rejected = encryptedPhoto({
        tenantId: current.first.tenantId,
        memberId: current.first.memberId,
        photoId: rejectedPhotoId,
        version: 5,
        key: nextTenantContentKey,
        keyId: rejectedKeyId,
      });
      await expect(withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
        identityId: current.identityId,
        idempotencyKey: randomUUID(),
        memberId: current.first.memberId,
        photoId: rejectedPhotoId,
        expectedVersion: 4,
        version: 5,
        mediaType: "image/jpeg",
        width: 512,
        height: 512,
        plaintextBytes: rejected.plaintext.byteLength,
        envelope: rejected.envelope,
        contentHash: rejected.contentHash,
      }))).rejects.toMatchObject({ statusCode: 409, code: "ENVELOPE_KEY_MISMATCH" });
    }

    const currentPhotoId = randomUUID();
    const currentEncrypted = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: currentPhotoId,
      version: 5,
      key: nextTenantContentKey,
      keyId: nextTenantKeyId,
    });
    await withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.first.memberId,
      photoId: currentPhotoId,
      expectedVersion: 4,
      version: 5,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: currentEncrypted.plaintext.byteLength,
      envelope: currentEncrypted.envelope,
      contentHash: currentEncrypted.contentHash,
    }));

    await current.first.pool.query(
      `UPDATE e2ee_key_grants
          SET status='revoked',version=version+1,revoked_at=clock_timestamp(),
              revoked_by_identity_id=$2,revoke_reason='ACCESS_REMOVED'
        WHERE generation_id=$1 AND identity_id=$2 AND status='active'`,
      [nextGenerationId, current.identityId],
    );
    const afterRevocationId = randomUUID();
    const afterRevocation = encryptedPhoto({
      tenantId: current.first.tenantId,
      memberId: current.first.memberId,
      photoId: afterRevocationId,
      version: 6,
      key: nextTenantContentKey,
      keyId: nextTenantKeyId,
    });
    await expect(withPhotoStore(current.first, current.identityId, (store) => store.putPhoto({
      identityId: current.identityId,
      idempotencyKey: randomUUID(),
      memberId: current.first.memberId,
      photoId: afterRevocationId,
      expectedVersion: 5,
      version: 6,
      mediaType: "image/jpeg",
      width: 512,
      height: 512,
      plaintextBytes: afterRevocation.plaintext.byteLength,
      envelope: afterRevocation.envelope,
      contentHash: afterRevocation.contentHash,
    }))).rejects.toMatchObject({ statusCode: 409, code: "KEY_GRANT_REQUIRED" });
  }, 30_000);
});

async function createFixture(databaseAdminUrl: string): Promise<LiveFixture> {
  const suffix = randomUUID().replaceAll("-", "");
  const firstName = `nom_photo_test_a_${suffix}`;
  const secondName = `nom_photo_test_b_${suffix}`;
  const cluster = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    application_name: "nombramientos-photo-live-cluster",
    max: 1,
  });
  const first = tenantFixture(databaseAdminUrl, firstName);
  const second = tenantFixture(databaseAdminUrl, secondName);
  const identityId = randomUUID();
  const photoContentKey = randomTenantContentKey();
  const secondTenantContentKey = randomTenantContentKey();
  const current: LiveFixture = {
    cluster,
    first,
    second,
    identityId,
    photoContentKey,
    sensitiveContentKeys: [photoContentKey, secondTenantContentKey],
    devicePrivateKeys: [],
    privacyLeakProbes: createPrivacyLeakProbes(photoContentKey),
  };
  try {
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [firstName]);
    await executeFormatted(cluster, "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql", [secondName]);
    const initialization = await Promise.allSettled([
      initializeTenant(first, identityId, photoContentKey),
      initializeTenant(second, identityId, secondTenantContentKey),
    ]);
    for (const result of initialization) {
      if (result.status === "fulfilled") current.devicePrivateKeys.push(result.value);
    }
    const initializationFailures = initialization.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : []);
    if (initializationFailures.length > 0) {
      throw new AggregateError(initializationFailures, "Photo tenant fixture initialization failed");
    }
    return current;
  } catch (setupError) {
    try {
      await cleanupFixture(current);
    } catch (cleanupError) {
      throw new AggregateError(
        [setupError, cleanupError],
        "Photo live fixture setup failed and cleanup could not be verified",
      );
    }
    throw setupError;
  }
}

function createPrivacyLeakProbes(photoContentKey: TenantContentKey): PrivacyLeakProbes {
  return {
    clearImage: `CLEAR_IMAGE_BYTES_PROBE_${randomUUID()}`,
    exif: `EXIF_GPSLatitude_PROBE_${randomUUID()}`,
    originalFilename: `ORIGINAL_FILENAME_PROBE_${randomUUID()}.jpg`,
    contentKey: Buffer.from(photoContentKey).toString("base64url"),
  };
}

function photoPrivacyViolations(value: unknown): string[] {
  const forbiddenKeys = new Set(["ciphertext", "nonce", "aad", "contenthash", "sha256"]);
  const violations: string[] = [];
  const visit = (candidate: unknown, location: string): void => {
    if (typeof candidate === "string") {
      const normalizedValue = candidate.replaceAll(/[^a-z0-9]/giu, "").toLowerCase();
      if (forbiddenKeys.has(normalizedValue) || /^sha256:[0-9a-f]{64}$/iu.test(candidate)) {
        violations.push(`${location}:forbidden-value`);
      }
      return;
    }
    if (Array.isArray(candidate)) {
      candidate.forEach((entry, index) => visit(entry, `${location}[${index}]`));
      return;
    }
    if (!candidate || typeof candidate !== "object") return;
    for (const [key, entry] of Object.entries(candidate)) {
      const normalizedKey = key.replaceAll(/[^a-z0-9]/giu, "").toLowerCase();
      if (forbiddenKeys.has(normalizedKey)) violations.push(`${location}.${key}:forbidden-key`);
      visit(entry, `${location}.${key}`);
    }
  };
  visit(value, "$readAudits");
  return violations;
}

function encodePrivacyLeakProbes(probes: PrivacyLeakProbes): Buffer {
  return Buffer.from(Object.values(probes).join("\n"), "utf8");
}

function tenantFixture(admin: string, databaseName: string): TenantFixture {
  return {
    databaseName,
    tenantId: randomUUID(),
    memberId: randomUUID(),
    tenantKeyId: randomUUID(),
    generationId: randomUUID(),
    deviceId: randomUUID(),
    pool: new Pool({
      connectionString: databaseUrl(admin, databaseName),
      application_name: `nombramientos-${databaseName}`,
      max: 3,
    }),
  };
}

async function initializeTenant(
  tenant: TenantFixture,
  identityId: string,
  tenantContentKey: TenantContentKey,
): Promise<CustodianPrivateKey> {
  await runMigrations(tenant.pool, {
    scope: "tenant",
    directory: path.join(packageRoot, "migrations", "tenant"),
  });
  const displayEnvelope = {
    algorithm: "AES-256-GCM",
    keyId: "photo-display-fixture-key",
    nonce: randomBytes(12).toString("base64url"),
    ciphertext: randomBytes(32).toString("base64url"),
    aad: Buffer.from(JSON.stringify({
      tenantId: tenant.tenantId,
      memberId: tenant.memberId,
      purpose: "member-display",
      schemaVersion: 1,
    })).toString("base64url"),
  };
  const [devicePrivateKey, recoverySigningKey] = await Promise.all([
    generateTenantDeviceKeyPair({ tenantId: tenant.tenantId, deviceId: tenant.deviceId }),
    generateCustodianSigningKeyPair(),
  ]);
  const [devicePublicKey, recoveryPublicKey] = await Promise.all([
    exportTenantDevicePublicKey(devicePrivateKey),
    exportCustodianSigningPublicKey(recoverySigningKey),
  ]);
  const grantEnvelope = await createTenantKeyGrantEnvelope({
    tenantId: tenant.tenantId,
    tenantKeyId: tenant.tenantKeyId,
    generation: 1,
    identityId,
    deviceId: tenant.deviceId,
    tenantKey: tenantContentKey,
    recipient: devicePrivateKey,
  });
  await assertGrantRoundTrip({
    envelope: grantEnvelope,
    recipient: devicePrivateKey,
    tenantId: tenant.tenantId,
    tenantKeyId: tenant.tenantKeyId,
    generation: 1,
    identityId,
    deviceId: tenant.deviceId,
    expectedKey: tenantContentKey,
  });
  const client = await tenant.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO tenant_settings(tenant_id,display_name,kind,timezone,locale,setup_state)
       VALUES ($1,'Photo live temporary tenant','real','America/Santo_Domingo','es','ready')`,
      [tenant.tenantId],
    );
    await client.query(
      `INSERT INTO e2ee_key_devices(
         device_id,identity_id,label,wrapping_public_key,wrapping_key_fingerprint,
         status,activated_at
       ) VALUES ($1,$2,'Ephemeral photo test device',$3,$4,'active',clock_timestamp())`,
      [
        tenant.deviceId,
        identityId,
        devicePublicKey,
        devicePublicKey.fingerprint,
      ],
    );
    await client.query(
      `INSERT INTO e2ee_key_generations(
         id,tenant_key_id,generation,status,recovery_public_key,
         recovery_key_fingerprint,created_by_identity_id
       ) VALUES ($1,$2,1,'active',$3,$4,$5)`,
      [
        tenant.generationId,
        tenant.tenantKeyId,
        recoveryPublicKey,
        recoveryPublicKey.fingerprint,
        identityId,
      ],
    );
    await client.query(
      `INSERT INTO e2ee_key_grants(
         generation_id,identity_id,device_id,envelope,envelope_hash,
         grant_kind,status,granted_by_identity_id
       ) VALUES ($1,$2,$3,$4,$5,'initial','active',$2)`,
      [
        tenant.generationId,
        identityId,
        tenant.deviceId,
        grantEnvelope,
        grantEnvelope.envelopeHash,
      ],
    );
    await client.query(
      `INSERT INTO members(id,stable_code,display_envelope,display_content_hash)
       VALUES ($1,$2,$3,$4)`,
      [
        tenant.memberId,
        `PHOTO-${tenant.memberId.slice(0, 12)}`,
        displayEnvelope,
        `sha256:${createHash("sha256").update(JSON.stringify(displayEnvelope)).digest("hex")}`,
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  await assertPersistedGrantHash(tenant.pool, tenant.generationId);
  return devicePrivateKey;
}

async function assertGrantRoundTrip(input: {
  readonly envelope: TenantKeyGrantEnvelope;
  readonly recipient: CustodianPrivateKey;
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly identityId: string;
  readonly deviceId: string;
  readonly expectedKey: TenantContentKey;
}): Promise<void> {
  const verified = await verifyTenantKeyGrantEnvelope(input.envelope);
  if (verified.envelopeHash !== input.envelope.envelopeHash) {
    throw new Error("Tenant key grant canonical hash verification failed");
  }
  const opened = await openTenantKeyGrantEnvelope({
    envelope: verified,
    recipient: input.recipient,
    expected: {
      tenantId: input.tenantId,
      tenantKeyId: input.tenantKeyId,
      generation: input.generation,
      identityId: input.identityId,
      deviceId: input.deviceId,
    },
  });
  try {
    if (
      opened.keyBytes.byteLength !== 32
      || !Buffer.from(opened.keyBytes).equals(Buffer.from(input.expectedKey))
      || opened.tenantKeyId !== input.tenantKeyId
    ) {
      throw new Error("Tenant key grant did not recover the exact 32-byte content key");
    }
  } finally {
    opened.keyBytes.fill(0);
  }
}

async function assertPersistedGrantHash(pool: Pool, generationId: string): Promise<void> {
  const result = await pool.query<{ envelope: unknown; envelope_hash: string }>(
    `SELECT envelope,envelope_hash
       FROM e2ee_key_grants
      WHERE generation_id=$1
      ORDER BY created_at,id
      LIMIT 1`,
    [generationId],
  );
  const row = result.rows[0];
  if (!row) throw new Error("Persisted tenant key grant is unavailable");
  const verified = await verifyTenantKeyGrantEnvelope(row.envelope);
  if (verified.envelopeHash !== row.envelope_hash) {
    throw new Error("Persisted tenant key grant hash is not canonical");
  }
}

function requireDevicePrivateKey(current: LiveFixture, index: number): CustodianPrivateKey {
  const key = current.devicePrivateKeys[index];
  if (!key) throw new Error("Photo live fixture device private key is unavailable");
  return key;
}

function randomTenantContentKey(): TenantContentKey {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

async function withPhotoStore<T>(
  tenant: TenantFixture,
  identityId: string,
  work: (store: PhotoStore) => Promise<T>,
): Promise<T> {
  const client = await tenant.pool.connect();
  try {
    await client.query("BEGIN");
    await setContext(client, tenant.tenantId, identityId);
    const value = await work(new PhotoStore(client));
    await client.query("COMMIT");
    return value;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function setContext(client: PoolClient, tenantId: string, identityId: string): Promise<void> {
  await client.query(
    `SELECT set_config('app.tenant_id',$1,true),set_config('app.identity_id',$2,true),
            set_config('app.session_id',$3,true),set_config('app.request_id',$4,true)`,
    [tenantId, identityId, randomUUID(), randomUUID()],
  );
  await bindDirectFixtureSession(client);
}

function encryptedPhoto(input: {
  readonly tenantId: string;
  readonly memberId: string;
  readonly photoId: string;
  readonly version: number;
  readonly key: TenantContentKey;
  readonly keyId: string;
  readonly plaintextProbe?: Buffer;
}) {
  const plaintext = jpegFixture(512, 512, input.plaintextProbe);
  const nonce = randomBytes(12);
  const aad = Buffer.from(JSON.stringify({
    tenantId: input.tenantId,
    memberId: input.memberId,
    photoId: input.photoId,
    purpose: "member-photo",
    schemaVersion: 1,
    version: input.version,
    mediaType: "image/jpeg",
    width: 512,
    height: 512,
    plaintextBytes: plaintext.byteLength,
  }), "utf8");
  const cipher = createCipheriv("aes-256-gcm", input.key, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const envelope = {
    algorithm: "AES-256-GCM" as const,
    keyId: input.keyId,
    nonce: nonce.toString("base64url"),
    ciphertext: encrypted.toString("base64url"),
    aad: aad.toString("base64url"),
  };
  const contentHash = `sha256:${createHash("sha256").update(JSON.stringify(envelope)).digest("hex")}`;
  return { plaintext, envelope, contentHash };
}

function openEnvelope(
  envelope: { readonly nonce: string; readonly ciphertext: string; readonly aad: string },
  key: TenantContentKey,
): Buffer {
  const encrypted = Buffer.from(envelope.ciphertext, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64url"));
  decipher.setAAD(Buffer.from(envelope.aad, "base64url"));
  decipher.setAuthTag(encrypted.subarray(encrypted.length - 16));
  return Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]);
}

function jpegFixture(width: number, height: number, plaintextProbe?: Buffer): Buffer {
  const bytes = Buffer.from([
    0xff, 0xd8,
    0xff, 0xc0, 0x00, 0x11, 0x08,
    (height >> 8) & 0xff, height & 0xff,
    (width >> 8) & 0xff, width & 0xff,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    0xff, 0xd9,
  ]);
  return Buffer.concat([bytes, randomBytes(256), plaintextProbe ?? Buffer.alloc(0)]);
}

async function cleanupFixture(current: LiveFixture): Promise<void> {
  for (const contentKey of current.sensitiveContentKeys) contentKey.fill(0);
  await cleanupTemporaryDatabases({
    maintenancePool: current.cluster,
    targets: [
      {
        databaseName: current.first.databaseName,
        databasePools: [current.first.pool],
        assertSafeDatabaseName: assertPhotoDatabaseName,
        label: "first photo tenant",
      },
      {
        databaseName: current.second.databaseName,
        databasePools: [current.second.pool],
        assertSafeDatabaseName: assertPhotoDatabaseName,
        label: "second photo tenant",
      },
    ],
    label: "Temporary photo databases",
  });
}

function assertPhotoDatabaseName(databaseName: string): void {
  if (!/^nom_photo_test_[ab]_[0-9a-f]{32}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-photo-test database");
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the photo test statement");
  await pool.query(sql);
}

function requireFixture(): LiveFixture {
  if (!fixture) throw new Error("Photo live fixture is unavailable");
  return fixture;
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed) {
        const configured = parsed.DATABASE_ADMIN_URL;
        if (typeof configured === "string") candidate = configured;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
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
    throw new Error("Photo tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function isLoopback(hostname: string): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(hostname);
}
