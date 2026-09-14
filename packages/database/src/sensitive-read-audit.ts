import type { PoolClient } from "pg";
import { appendTenantAuditEventV2 } from "./audit-event-chain.js";

/**
 * Stable action codes for GET operations that actually materialize sensitive
 * tenant data.  Keeping the vocabulary here prevents route/store drift and
 * gives the metadata boundary one small, reviewable allow-list.
 */
export const SENSITIVE_READ_AUDIT_ACTIONS = Object.freeze({
  memberContact: "member.contact.read",
  memberPrivateNote: "member.private-note.read",
  candidacyReviewMaterial: "candidacy.review-material.read",
  candidacyPrivateNote: "candidacy.private-note.read",
  workflowReportSnapshot: "workflow-report.snapshot.read",
  reportArtifact: "report.downloaded",
  memberPhoto: "member.photo.read",
} as const);

export type SensitiveReadAuditAction =
  typeof SENSITIVE_READ_AUDIT_ACTIONS[keyof typeof SENSITIVE_READ_AUDIT_ACTIONS];

interface SensitiveReadAuditInput {
  readonly action: SensitiveReadAuditAction;
  readonly entityType: string;
  readonly entityId: string;
  readonly metadata: Readonly<Record<string, unknown>>;
}

const CONTRACTS: Readonly<Record<SensitiveReadAuditAction, {
  readonly entityType: string;
  readonly metadataKeys: readonly string[];
}>> = Object.freeze({
  [SENSITIVE_READ_AUDIT_ACTIONS.memberContact]: {
    entityType: "member_roster",
    metadataKeys: ["recordCount"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.memberPrivateNote]: {
    entityType: "member_roster",
    metadataKeys: ["recordCount"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.candidacyReviewMaterial]: {
    entityType: "office_process",
    metadataKeys: ["photoRecordCount", "rationaleRecordCount", "processVersion"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.candidacyPrivateNote]: {
    entityType: "office_process",
    metadataKeys: ["recordCount", "processVersion"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.workflowReportSnapshot]: {
    entityType: "election_cycle",
    metadataKeys: ["reportType", "audience", "cycleVersion", "classification"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.reportArtifact]: {
    entityType: "report",
    metadataKeys: ["reportType", "audience", "format", "version", "lineageRevision"],
  },
  [SENSITIVE_READ_AUDIT_ACTIONS.memberPhoto]: {
    entityType: "member-photo",
    metadataKeys: ["memberId", "version"],
  },
});

/**
 * Appends only a known sensitive-read event with an exact scalar metadata
 * shape. Actor and request identifiers come from the transaction-local tenant
 * context inside appendTenantAuditEventV2; callers must not duplicate them in
 * metadata. Callers batch a page/snapshot into one event instead of one event
 * per row. A repeated HTTP request is a new read and is intentionally recorded
 * again; a failed transaction rolls its read event back atomically. No outbox
 * event is emitted for a read.
 */
export async function appendSensitiveReadAuditEvent(
  client: PoolClient,
  input: SensitiveReadAuditInput,
): Promise<void> {
  const contract = CONTRACTS[input.action];
  if (input.entityType !== contract.entityType) {
    throw new Error(`Sensitive read audit entity type is invalid for ${input.action}`);
  }
  if (input.entityId.length < 1 || input.entityId.length > 160) {
    throw new Error("Sensitive read audit entity identifier is invalid");
  }
  const actualKeys = Object.keys(input.metadata).sort();
  const expectedKeys = [...contract.metadataKeys].sort();
  if (actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error(`Sensitive read audit metadata is invalid for ${input.action}`);
  }
  for (const [key, value] of Object.entries(input.metadata)) {
    validateMetadataValue(key, value);
  }
  if (input.action === SENSITIVE_READ_AUDIT_ACTIONS.candidacyReviewMaterial
    && input.metadata["photoRecordCount"] === 0
    && input.metadata["rationaleRecordCount"] === 0) {
    throw new Error("Sensitive read audit review material is not materialized");
  }
  await appendTenantAuditEventV2(client, {
    action: input.action,
    entityType: input.entityType,
    entityId: input.entityId,
    result: "success",
    metadata: input.metadata,
  });
}

function validateMetadataValue(key: string, value: unknown): void {
  if (key === "recordCount" || key === "photoRecordCount" || key === "rationaleRecordCount") {
    return requireInteger(key, value, 0);
  }
  if (key === "processVersion" || key === "cycleVersion" || key === "version" || key === "lineageRevision") {
    return requireInteger(key, value, 1);
  }
  if (key === "memberId") {
    if (typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) return;
    throw new Error("Sensitive read audit memberId is invalid");
  }
  if (key === "reportType") {
    if (typeof value === "string" && /^[a-z][a-z0-9_]{1,63}$/u.test(value)) return;
    throw new Error("Sensitive read audit reportType is invalid");
  }
  if (key === "audience") {
    if (value === "committee" || value === "auditor" || value === "church") return;
    throw new Error("Sensitive read audit audience is invalid");
  }
  if (key === "format") {
    if (value === "pdf" || value === "xlsx" || value === "csv" || value === "html") return;
    throw new Error("Sensitive read audit format is invalid");
  }
  if (key === "classification") {
    if (value === "internal" || value === "congregational-personal") return;
    throw new Error("Sensitive read audit classification is invalid");
  }
  throw new Error(`Sensitive read audit metadata key is unsupported: ${key}`);
}

function requireInteger(key: string, value: unknown, minimum: number): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`Sensitive read audit ${key} is invalid`);
  }
}
