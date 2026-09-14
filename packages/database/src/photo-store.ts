import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import {
  assertWritableTenantContentKey,
  ContentKeyWriteGuardError,
} from "./content-key-write-guard.js";
import {
  appendSensitiveReadAuditEvent,
  SENSITIVE_READ_AUDIT_ACTIONS,
} from "./sensitive-read-audit.js";
import type { EncryptedEnvelope } from "./types.js";

export const PHOTO_MEDIA_TYPE = "image/jpeg" as const;

export interface PhotoAssetMetadata {
  readonly id: string;
  readonly memberId: string;
  readonly version: number;
  readonly mediaType: typeof PHOTO_MEDIA_TYPE;
  readonly width: number;
  readonly height: number;
  readonly plaintextBytes: number;
  readonly contentHash: string;
  readonly createdAt: string;
  readonly archivedAt: string | null;
}

export interface PhotoAsset extends PhotoAssetMetadata {
  readonly envelope: EncryptedEnvelope;
}

export interface PhotoWriteContext {
  readonly expectedVersion: number;
  readonly nextVersion: number;
}

export class PhotoStoreError extends Error {
  public constructor(
    public readonly statusCode: 404 | 409,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "PhotoStoreError";
  }
}

interface PhotoRow {
  readonly id: string;
  readonly member_id: string;
  readonly version: number;
  readonly media_type: typeof PHOTO_MEDIA_TYPE;
  readonly width: number;
  readonly height: number;
  readonly plaintext_bytes: number;
  readonly envelope: EncryptedEnvelope;
  readonly content_hash: string;
  readonly created_at: Date;
  readonly archived_at: Date | null;
}

export class PhotoStore {
  public constructor(private readonly client: PoolClient) {}

  public async putPhoto(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly memberId: string;
    readonly photoId: string;
    readonly expectedVersion: number;
    readonly version: number;
    readonly mediaType: typeof PHOTO_MEDIA_TYPE;
    readonly width: number;
    readonly height: number;
    readonly plaintextBytes: number;
    readonly envelope: EncryptedEnvelope;
    readonly contentHash: string;
  }): Promise<PhotoAssetMetadata> {
    const cipherBytes = Buffer.from(input.envelope.ciphertext, "base64url").byteLength;
    if (cipherBytes !== input.plaintextBytes + 16) {
      throw new PhotoStoreError(409, "PHOTO_CIPHERTEXT_LENGTH_INVALID", "Photograph ciphertext length is invalid");
    }
    return this.executeIdempotent(input.identityId, "member.photo.put", input.idempotencyKey, input, async () => {
      try {
        await assertWritableTenantContentKey(this.client, {
          identityId: input.identityId,
          envelopes: [input.envelope],
        });
      } catch (error) {
        if (error instanceof ContentKeyWriteGuardError) {
          throw new PhotoStoreError(error.statusCode, error.code, error.message);
        }
        throw error;
      }
      await this.assertMemberExists(input.memberId, true);
      const current = await this.client.query<{ id: string; version: number; archived_at: Date | null }>(
        `SELECT id,version,archived_at
           FROM member_photo_assets
          WHERE member_id=$1
          ORDER BY version DESC
          FOR UPDATE`,
        [input.memberId],
      );
      const active = current.rows.find((row) => row.archived_at === null);
      const actualVersion = active?.version ?? 0;
      if (actualVersion !== input.expectedVersion) {
        throw new PhotoStoreError(409, "PHOTO_VERSION_CONFLICT", "Photograph version is stale");
      }
      const nextVersion = (current.rows[0]?.version ?? 0) + 1;
      if (input.version !== nextVersion) {
        throw new PhotoStoreError(409, "PHOTO_VERSION_CONFLICT", "Photograph version is stale");
      }
      if (active) {
        await this.client.query(
          `UPDATE member_photo_assets
              SET archived_by_identity_id=$2,archived_at=clock_timestamp()
            WHERE id=$1 AND archived_at IS NULL`,
          [active.id, input.identityId],
        );
      }
      let inserted;
      try {
        inserted = await this.client.query<PhotoRow>(
          `INSERT INTO member_photo_assets(
             id,member_id,version,media_type,width,height,plaintext_bytes,cipher_bytes,
             envelope,content_hash,created_by_identity_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
           RETURNING id,member_id,version,media_type,width,height,plaintext_bytes,envelope,
                     content_hash,created_at,archived_at`,
          [
            input.photoId,
            input.memberId,
            nextVersion,
            input.mediaType,
            input.width,
            input.height,
            input.plaintextBytes,
            cipherBytes,
            input.envelope,
            input.contentHash,
            input.identityId,
          ],
        );
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new PhotoStoreError(409, "PHOTO_ID_CONFLICT", "Photograph identifier is already in use");
        }
        throw error;
      }
      const row = inserted.rows[0];
      if (!row) throw new Error("Photograph insert did not return its metadata");
      const metadata = toMetadata(row);
      await this.emit("member.photo.changed", input.photoId, {
        memberId: input.memberId,
        photoId: input.photoId,
        version: nextVersion,
        mediaType: input.mediaType,
        width: input.width,
        height: input.height,
        plaintextBytes: input.plaintextBytes,
        contentHash: input.contentHash,
      });
      await this.appendAudit(
        active ? "member.photo.replaced" : "member.photo.created",
        input.photoId,
        "success",
        {
          memberId: input.memberId,
          previousPhotoId: active?.id ?? null,
          version: nextVersion,
          mediaType: input.mediaType,
          width: input.width,
          height: input.height,
          plaintextBytes: input.plaintextBytes,
          contentHash: input.contentHash,
        },
      );
      return metadata;
    });
  }

  public async getActivePhoto(memberId: string): Promise<PhotoAsset> {
    const result = await this.client.query<PhotoRow>(
      `SELECT photo.id,photo.member_id,photo.version,photo.media_type,photo.width,photo.height,
              photo.plaintext_bytes,photo.envelope,photo.content_hash,photo.created_at,photo.archived_at
         FROM members member
         JOIN member_photo_assets photo ON photo.member_id=member.id AND photo.archived_at IS NULL
        WHERE member.id=$1 AND member.archived_at IS NULL`,
      [memberId],
    );
    const row = result.rows[0];
    if (!row) throw new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found");
    await appendSensitiveReadAuditEvent(this.client, {
      action: SENSITIVE_READ_AUDIT_ACTIONS.memberPhoto,
      entityType: "member-photo",
      entityId: row.id,
      metadata: { memberId, version: row.version },
    });
    return { ...toMetadata(row), envelope: row.envelope };
  }

  public async getPhotoWriteContext(memberId: string): Promise<PhotoWriteContext> {
    await this.assertMemberExists(memberId, false);
    const result = await this.client.query<{ latest_version: number; active_version: number }>(
      `SELECT COALESCE(MAX(version),0)::int AS latest_version,
              COALESCE(MAX(version) FILTER (WHERE archived_at IS NULL),0)::int AS active_version
         FROM member_photo_assets
        WHERE member_id=$1`,
      [memberId],
    );
    const row = result.rows[0];
    return {
      expectedVersion: row?.active_version ?? 0,
      nextVersion: (row?.latest_version ?? 0) + 1,
    };
  }

  public async archivePhoto(input: {
    readonly identityId: string;
    readonly idempotencyKey: string;
    readonly memberId: string;
    readonly expectedVersion: number;
  }): Promise<PhotoAssetMetadata> {
    return this.executeIdempotent(input.identityId, "member.photo.archive", input.idempotencyKey, input, async () => {
      await this.assertMemberExists(input.memberId, true);
      const current = await this.client.query<PhotoRow>(
        `SELECT id,member_id,version,media_type,width,height,plaintext_bytes,envelope,
                content_hash,created_at,archived_at
           FROM member_photo_assets
          WHERE member_id=$1 AND archived_at IS NULL
          FOR UPDATE`,
        [input.memberId],
      );
      const row = current.rows[0];
      if (!row) throw new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found");
      if (row.version !== input.expectedVersion) {
        throw new PhotoStoreError(409, "PHOTO_VERSION_CONFLICT", "Photograph version is stale");
      }
      const archived = await this.client.query<{ archived_at: Date }>(
        `UPDATE member_photo_assets
            SET archived_by_identity_id=$2,archived_at=clock_timestamp()
          WHERE id=$1 AND archived_at IS NULL
          RETURNING archived_at`,
        [row.id, input.identityId],
      );
      const archivedAt = archived.rows[0]?.archived_at;
      if (!archivedAt) throw new PhotoStoreError(409, "PHOTO_VERSION_CONFLICT", "Photograph changed concurrently");
      await this.emit("member.photo.archived", row.id, {
        memberId: input.memberId,
        photoId: row.id,
        version: row.version,
      });
      await this.appendAudit("member.photo.archived", row.id, "success", {
        memberId: input.memberId,
        version: row.version,
        contentHash: row.content_hash,
      });
      return { ...toMetadata(row), archivedAt: archivedAt.toISOString() };
    });
  }

  private async assertMemberExists(memberId: string, writeLock: boolean): Promise<void> {
    const member = await this.client.query(
      `SELECT 1 FROM members WHERE id=$1 AND archived_at IS NULL ${writeLock ? "FOR UPDATE" : "FOR SHARE"}`,
      [memberId],
    );
    if (member.rowCount !== 1) {
      throw new PhotoStoreError(404, "PHOTO_NOT_FOUND", "Photograph was not found");
    }
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = hashCanonical(request);
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body
           FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3
          FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw new PhotoStoreError(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different input");
      }
      if (row.response_body === null) {
        throw new PhotoStoreError(409, "IDEMPOTENCY_IN_PROGRESS", "The original operation is still in progress");
      }
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records
          SET response_status=200,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async emit(
    eventType: string,
    photoId: string,
    payload: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized',$1,'member-photo',$2,$3)`,
      [eventType, photoId, payload],
    );
  }

  private async appendAudit(
    action: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, {
      action, entityType: "member-photo", entityId, result, metadata,
    });
  }
}

function toMetadata(row: PhotoRow): PhotoAssetMetadata {
  return {
    id: row.id,
    memberId: row.member_id,
    version: row.version,
    mediaType: row.media_type,
    width: row.width,
    height: row.height,
    plaintextBytes: row.plaintext_bytes,
    contentHash: row.content_hash,
    createdAt: row.created_at.toISOString(),
    archivedAt: row.archived_at?.toISOString() ?? null,
  };
}

function hashCanonical(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}
