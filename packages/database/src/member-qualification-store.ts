import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import type {
  MemberQualificationStatus,
  MemberQualificationType,
} from "@nombramientos/domain";
export {
  MEMBER_QUALIFICATION_STATUSES,
  MEMBER_QUALIFICATION_TYPES,
} from "@nombramientos/domain";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";
import {
  assertWritableTenantContentKey,
  ContentKeyWriteGuardError,
} from "./content-key-write-guard.js";
import type { EncryptedEnvelope } from "./types.js";

export interface MemberQualificationMetadata {
  readonly qualificationId: string;
  readonly memberId: string;
  readonly version: number;
  readonly type: MemberQualificationType;
  readonly status: MemberQualificationStatus;
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
  readonly hasDetails: boolean;
  readonly reviewerIdentityId: string;
  readonly recordedAt: string;
}

export interface MemberQualificationRevision extends MemberQualificationMetadata {
  readonly detailsEnvelope: EncryptedEnvelope | null;
  readonly detailsContentHash: string | null;
}

export interface MemberQualificationRecord extends MemberQualificationRevision {
  readonly revisions: readonly MemberQualificationRevision[];
}

export interface MemberQualificationList {
  readonly memberId: string;
  readonly eligibilityInference: false;
  readonly items: readonly MemberQualificationRecord[];
}

export class MemberQualificationStoreError extends Error {
  public constructor(
    public readonly statusCode: 404 | 409,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "MemberQualificationStoreError";
  }
}

interface QualificationRow {
  readonly qualification_id: string;
  readonly member_id: string;
  readonly version: number;
  readonly qualification_type: MemberQualificationType;
  readonly status: MemberQualificationStatus;
  readonly effective_on: string;
  readonly expires_on: string | null;
  readonly details_envelope: EncryptedEnvelope | null;
  readonly details_content_hash: string | null;
  readonly reviewer_identity_id: string;
  readonly recorded_at: Date;
}

interface QualificationWriteInput {
  readonly identityId: string;
  readonly idempotencyKey: string;
  readonly memberId: string;
  readonly qualificationId: string;
  readonly type: MemberQualificationType;
  readonly status: MemberQualificationStatus;
  readonly effectiveOn: string;
  readonly expiresOn: string | null;
  readonly detailsEnvelope: EncryptedEnvelope | null;
  readonly detailsContentHash: string | null;
}

export class MemberQualificationStore {
  public constructor(private readonly client: PoolClient) {}

  public async listForMember(memberId: string): Promise<MemberQualificationList> {
    await this.assertMemberExists(memberId, false);
    const result = await this.client.query<QualificationRow>(
      `SELECT qualification_id,member_id,version,qualification_type,status,
              effective_on::text AS effective_on,expires_on::text AS expires_on,
              details_envelope,details_content_hash,reviewer_identity_id,recorded_at
         FROM member_qualification_versions
        WHERE member_id=$1
        ORDER BY qualification_id,version DESC`,
      [memberId],
    );
    const grouped = new Map<string, MemberQualificationRevision[]>();
    for (const row of result.rows) {
      const revision = toRevision(row);
      const revisions = grouped.get(row.qualification_id) ?? [];
      revisions.push(revision);
      grouped.set(row.qualification_id, revisions);
    }
    const items = [...grouped.values()]
      .map((revisions) => ({ ...revisions[0]!, revisions }))
      .sort((left, right) => right.recordedAt.localeCompare(left.recordedAt)
        || left.qualificationId.localeCompare(right.qualificationId));
    await this.appendAudit("member.qualification.listed", memberId, "success", {
      eligibilityInference: false,
    });
    return { memberId, eligibilityInference: false, items };
  }

  public async create(input: QualificationWriteInput): Promise<MemberQualificationMetadata> {
    return this.executeIdempotent(
      input.identityId,
      "member.qualification.create",
      input.idempotencyKey,
      input,
      async () => {
        await this.assertMemberExists(input.memberId, true);
        await this.assertDetailsKey(input.identityId, input.detailsEnvelope);
        let result;
        try {
          result = await this.client.query<QualificationRow>(
            `INSERT INTO member_qualification_versions(
               qualification_id,version,member_id,qualification_type,status,effective_on,
               expires_on,details_envelope,details_content_hash,reviewer_identity_id,supersedes_version
             ) VALUES ($1,1,$2,$3,$4,$5::date,$6::date,$7,$8,$9,NULL)
             RETURNING qualification_id,member_id,version,qualification_type,status,
                       effective_on::text AS effective_on,expires_on::text AS expires_on,
                       details_envelope,details_content_hash,reviewer_identity_id,recorded_at`,
            [
              input.qualificationId, input.memberId, input.type, input.status,
              input.effectiveOn, input.expiresOn, input.detailsEnvelope,
              input.detailsContentHash, input.identityId,
            ],
          );
        } catch (error) {
          if (isUniqueViolation(error)) {
            throw new MemberQualificationStoreError(
              409,
              "QUALIFICATION_ID_CONFLICT",
              "Qualification identifier is already in use",
            );
          }
          throw error;
        }
        const row = result.rows[0];
        if (!row) throw new Error("Qualification insert did not return a row");
        await this.recordChange("member.qualification.created", row);
        return toMetadata(row);
      },
    );
  }

  public async revise(input: QualificationWriteInput & {
    readonly expectedVersion: number;
  }): Promise<MemberQualificationMetadata> {
    return this.executeIdempotent(
      input.identityId,
      "member.qualification.revise",
      input.idempotencyKey,
      input,
      async () => {
        await this.assertMemberExists(input.memberId, true);
        await this.assertDetailsKey(input.identityId, input.detailsEnvelope);
        const current = await this.client.query<{ member_id: string; version: number }>(
          `SELECT member_id,version
             FROM member_qualification_versions
            WHERE qualification_id=$1
            ORDER BY version DESC
            LIMIT 1`,
          [input.qualificationId],
        );
        const previous = current.rows[0];
        if (!previous || previous.member_id !== input.memberId) {
          throw qualificationNotFound();
        }
        if (previous.version !== input.expectedVersion) {
          throw new MemberQualificationStoreError(
            409,
            "QUALIFICATION_VERSION_CONFLICT",
            "Qualification version is stale",
          );
        }
        const nextVersion = previous.version + 1;
        let result;
        try {
          result = await this.client.query<QualificationRow>(
            `INSERT INTO member_qualification_versions(
               qualification_id,version,member_id,qualification_type,status,effective_on,
               expires_on,details_envelope,details_content_hash,reviewer_identity_id,supersedes_version
             ) VALUES ($1,$2,$3,$4,$5,$6::date,$7::date,$8,$9,$10,$11)
             RETURNING qualification_id,member_id,version,qualification_type,status,
                       effective_on::text AS effective_on,expires_on::text AS expires_on,
                       details_envelope,details_content_hash,reviewer_identity_id,recorded_at`,
            [
              input.qualificationId, nextVersion, input.memberId, input.type, input.status,
              input.effectiveOn, input.expiresOn, input.detailsEnvelope,
              input.detailsContentHash, input.identityId, previous.version,
            ],
          );
        } catch (error) {
          if (isUniqueViolation(error)) {
            throw new MemberQualificationStoreError(
              409,
              "QUALIFICATION_VERSION_CONFLICT",
              "Qualification changed concurrently",
            );
          }
          throw error;
        }
        const row = result.rows[0];
        if (!row) throw new Error("Qualification revision did not return a row");
        await this.recordChange("member.qualification.revised", row);
        return toMetadata(row);
      },
    );
  }

  private async recordChange(action: string, row: QualificationRow): Promise<void> {
    const metadata = toEventMetadata(row);
    await this.client.query(
      `INSERT INTO outbox_events(audience,event_type,aggregate_type,aggregate_id,payload)
       VALUES ('tenant.authorized','member.qualification.changed','member-qualification',$1,$2)`,
      [row.qualification_id, metadata],
    );
    await this.appendAudit(action, row.qualification_id, "success", metadata);
  }

  private async assertMemberExists(memberId: string, writeLock: boolean): Promise<void> {
    const result = await this.client.query(
      `SELECT 1 FROM members WHERE id=$1 ${writeLock ? "FOR UPDATE" : ""}`,
      [memberId],
    );
    if (result.rowCount !== 1) throw qualificationNotFound();
  }

  /**
   * Pins the exact tenant-key generation used by an encrypted write until the
   * surrounding transaction commits. Real tenants use the lifecycle tables;
   * the legacy password-wrapped table exists only for the synthetic Demo.
   */
  private async assertDetailsKey(
    identityId: string,
    envelope: EncryptedEnvelope | null,
  ): Promise<void> {
    try {
      await assertWritableTenantContentKey(this.client, {
        identityId,
        envelopes: [envelope],
      });
    } catch (error) {
      if (error instanceof ContentKeyWriteGuardError) {
        throw new MemberQualificationStoreError(error.statusCode, error.code, error.message);
      }
      throw error;
    }
  }

  private async executeIdempotent<T>(
    identityId: string,
    operation: string,
    idempotencyKey: string,
    request: unknown,
    work: () => Promise<T>,
  ): Promise<T> {
    const requestHash = createHash("sha256").update(stableJson(request)).digest("hex");
    const inserted = await this.client.query(
      `INSERT INTO idempotency_records(identity_id,operation,idempotency_key,request_hash)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [identityId, operation, idempotencyKey, requestHash],
    );
    if (inserted.rowCount === 0) {
      const existing = await this.client.query<{ request_hash: string; response_body: T | null }>(
        `SELECT request_hash,response_body FROM idempotency_records
          WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3 FOR UPDATE`,
        [identityId, operation, idempotencyKey],
      );
      const row = existing.rows[0];
      if (!row || row.request_hash !== requestHash) {
        throw new MemberQualificationStoreError(
          409,
          "IDEMPOTENCY_CONFLICT",
          "Idempotency key was reused with different input",
        );
      }
      if (row.response_body === null) {
        throw new MemberQualificationStoreError(
          409,
          "IDEMPOTENCY_IN_PROGRESS",
          "The original operation is still in progress",
        );
      }
      return row.response_body;
    }
    const response = await work();
    await this.client.query(
      `UPDATE idempotency_records SET response_status=201,response_body=$4
        WHERE identity_id=$1 AND operation=$2 AND idempotency_key=$3`,
      [identityId, operation, idempotencyKey, response],
    );
    return response;
  }

  private async appendAudit(
    action: string,
    entityId: string,
    result: "success" | "denied" | "failure",
    metadata: Readonly<Record<string, unknown>>,
  ): Promise<void> {
    await appendTenantAuditEventV2(this.client, {
      action,
      entityType: "member-qualification",
      entityId,
      result,
      metadata,
    });
  }
}

function toMetadata(row: QualificationRow): MemberQualificationMetadata {
  return {
    qualificationId: row.qualification_id,
    memberId: row.member_id,
    version: row.version,
    type: row.qualification_type,
    status: row.status,
    effectiveOn: row.effective_on,
    expiresOn: row.expires_on,
    hasDetails: row.details_envelope !== null,
    reviewerIdentityId: row.reviewer_identity_id,
    recordedAt: row.recorded_at.toISOString(),
  };
}

function toRevision(row: QualificationRow): MemberQualificationRevision {
  return {
    ...toMetadata(row),
    detailsEnvelope: row.details_envelope,
    detailsContentHash: row.details_content_hash,
  };
}

function toEventMetadata(row: QualificationRow): Readonly<Record<string, unknown>> {
  return {
    qualificationId: row.qualification_id,
    version: row.version,
    eligibilityInference: false,
  };
}

function qualificationNotFound(): MemberQualificationStoreError {
  return new MemberQualificationStoreError(
    404,
    "MEMBER_QUALIFICATION_NOT_FOUND",
    "Member qualification record was not found",
  );
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
