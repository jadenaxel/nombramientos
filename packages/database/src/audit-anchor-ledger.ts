import { z } from "zod";
import {
  createTrustedAuditAnchorReceipt,
  verifyAnchoredAuditTrail,
  type AnchoredAuditTrailVerification,
  type AuditPublicKeyRing,
  type SignedAuditAnchor,
  type SignedAuditCheckpoint,
  type TenantAuditEventRecord,
  type TrustedAuditAnchorReceipt,
} from "./audit-anchors.js";

export const LOCAL_AUDIT_LEDGER_FORMAT = "nombramientos-local-audit-anchor-ledger" as const;
export const LOCAL_AUDIT_RECEIPT_FORMAT = "nombramientos-local-audit-anchor-receipt" as const;
export const LOCAL_AUDIT_STORAGE_ASSURANCE = "development-emulation-not-worm" as const;

const identifier = z.string().min(1).max(256).refine((value) => value.trim() === value);
const decimal = z.string().regex(/^[1-9][0-9]*$/);
const eventHash = z.string().regex(/^[0-9a-f]{64}$/);
const artifactHash = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const signature = z.string().regex(/^[A-Za-z0-9_-]{86}$/);
const timestamp = z.string().datetime({ offset: true });

const checkpointSchema = z.object({
  format: z.literal("nombramientos.audit-checkpoint.v1"),
  tenantId: identifier,
  streamId: identifier,
  checkpointId: identifier,
  capturedAt: timestamp,
  firstSequence: decimal,
  lastSequence: decimal,
  eventCount: decimal,
  headHash: eventHash,
  previousCheckpointHash: artifactHash.nullable(),
  signingKeyId: identifier,
  algorithm: z.literal("Ed25519"),
  checkpointHash: artifactHash,
  signature,
}).strict();

const anchorSchema = z.object({
  format: z.literal("nombramientos.audit-anchor.v1"),
  tenantId: identifier,
  streamId: identifier,
  anchorId: identifier,
  anchorSequence: decimal,
  anchoredAt: timestamp,
  checkpointHash: artifactHash,
  previousAnchorHash: artifactHash.nullable(),
  signingKeyId: identifier,
  algorithm: z.literal("Ed25519"),
  anchorHash: artifactHash,
  signature,
}).strict();

export const localAuditLedgerSchema = z.object({
  format: z.literal(LOCAL_AUDIT_LEDGER_FORMAT),
  version: z.literal(1),
  storageAssurance: z.literal(LOCAL_AUDIT_STORAGE_ASSURANCE),
  tenantId: identifier,
  streamId: identifier,
  checkpoints: z.array(checkpointSchema),
  anchors: z.array(anchorSchema),
}).strict().superRefine((value, context) => {
  if (value.checkpoints.length !== value.anchors.length) {
    context.addIssue({ code: "custom", message: "Ledger checkpoint and anchor counts must match" });
  }
});

export const localAuditReceiptSchema = z.object({
  format: z.literal(LOCAL_AUDIT_RECEIPT_FORMAT),
  version: z.literal(1),
  storageAssurance: z.literal(LOCAL_AUDIT_STORAGE_ASSURANCE),
  publishedAt: timestamp,
  ledgerFile: z.string().regex(/^ledger-[0-9]{20,}-[0-9a-f]{64}\.json$/),
  tenantId: identifier,
  streamId: identifier,
  anchorSequence: decimal,
  checkpointHash: artifactHash,
  anchorHash: artifactHash,
}).strict();

export type LocalAuditLedger = z.infer<typeof localAuditLedgerSchema>;
export type LocalAuditReceipt = z.infer<typeof localAuditReceiptSchema>;

export function assertIsolatedAuditAdminUrl(value: string): URL {
  const url = new URL(value);
  const schemeEnd = value.indexOf("://");
  const remainder = schemeEnd < 0 ? "" : value.slice(schemeEnd + 3);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (
    value !== value.trim()
    || !["postgres:", "postgresql:"].includes(url.protocol)
    || hostPort !== "127.0.0.1:55432"
    || url.hostname !== "127.0.0.1"
    || url.port !== "55432"
    || url.pathname !== "/postgres"
    || url.search !== ""
    || url.hash !== ""
    || decodeURIComponent(url.username) !== "nom_admin"
    || decodeURIComponent(url.password).length === 0
  ) {
    throw new Error("Audit tooling requires the exact protected nom_admin loopback 127.0.0.1:55432 endpoint; 5432 is refused");
  }
  return url;
}

export function createLocalAuditLedger(tenantId: string, streamId: string): LocalAuditLedger {
  return localAuditLedgerSchema.parse({
    format: LOCAL_AUDIT_LEDGER_FORMAT,
    version: 1,
    storageAssurance: LOCAL_AUDIT_STORAGE_ASSURANCE,
    tenantId,
    streamId,
    checkpoints: [],
    anchors: [],
  });
}

export function appendLocalAuditEvidence(
  ledger: LocalAuditLedger,
  checkpoint: SignedAuditCheckpoint,
  anchor: SignedAuditAnchor,
): LocalAuditLedger {
  const parsed = localAuditLedgerSchema.parse(ledger);
  if (checkpoint.tenantId !== parsed.tenantId || checkpoint.streamId !== parsed.streamId) {
    throw new Error("Checkpoint tenant or stream does not match the local ledger");
  }
  if (anchor.tenantId !== parsed.tenantId || anchor.streamId !== parsed.streamId) {
    throw new Error("Anchor tenant or stream does not match the local ledger");
  }
  if (anchor.checkpointHash !== checkpoint.checkpointHash) {
    throw new Error("Anchor does not reference the checkpoint being appended");
  }
  const previousCheckpoint = parsed.checkpoints.at(-1);
  const previousAnchor = parsed.anchors.at(-1);
  if (checkpoint.previousCheckpointHash !== (previousCheckpoint?.checkpointHash ?? null)) {
    throw new Error("Checkpoint does not append to the local ledger head");
  }
  if (anchor.previousAnchorHash !== (previousAnchor?.anchorHash ?? null)) {
    throw new Error("Anchor does not append to the independent anchor head");
  }
  if (BigInt(anchor.anchorSequence) !== BigInt(parsed.anchors.length + 1)) {
    throw new Error("Anchor sequence does not append contiguously");
  }
  return localAuditLedgerSchema.parse({
    ...parsed,
    checkpoints: [...parsed.checkpoints, checkpoint],
    anchors: [...parsed.anchors, anchor],
  });
}

export function ledgerGenerationFilename(anchor: SignedAuditAnchor): string {
  const digest = anchor.anchorHash.match(/^sha256:([0-9a-f]{64})$/)?.[1];
  if (!digest || !decimal.safeParse(anchor.anchorSequence).success) {
    throw new Error("Cannot derive a generation filename from an invalid anchor");
  }
  return `ledger-${anchor.anchorSequence.padStart(20, "0")}-${digest}.json`;
}

export function createLocalAuditReceipt(
  anchor: SignedAuditAnchor,
  ledgerFile: string,
  publishedAt: string,
): LocalAuditReceipt {
  const trusted = createTrustedAuditAnchorReceipt(anchor);
  return localAuditReceiptSchema.parse({
    format: LOCAL_AUDIT_RECEIPT_FORMAT,
    version: 1,
    storageAssurance: LOCAL_AUDIT_STORAGE_ASSURANCE,
    publishedAt,
    ledgerFile,
    ...trusted,
  });
}

export function receiptGenerationFilename(receipt: LocalAuditReceipt): string {
  const digest = receipt.anchorHash.match(/^sha256:([0-9a-f]{64})$/)?.[1];
  if (!digest || !decimal.safeParse(receipt.anchorSequence).success) {
    throw new Error("Cannot derive a generation filename from an invalid receipt");
  }
  return `receipt-${receipt.anchorSequence.padStart(20, "0")}-${digest}.json`;
}

export function parseLocalAuditLedger(value: unknown): LocalAuditLedger {
  return localAuditLedgerSchema.parse(value);
}

export function parseLocalAuditReceipt(value: unknown): LocalAuditReceipt {
  return localAuditReceiptSchema.parse(value);
}

export function trustedReceiptFromLocal(receipt: LocalAuditReceipt): TrustedAuditAnchorReceipt {
  return {
    tenantId: receipt.tenantId,
    streamId: receipt.streamId,
    anchorSequence: receipt.anchorSequence,
    checkpointHash: receipt.checkpointHash,
    anchorHash: receipt.anchorHash,
  };
}

export function verifyLocalAuditLedger(input: {
  readonly events: readonly TenantAuditEventRecord[];
  readonly ledger: LocalAuditLedger;
  readonly receipt: LocalAuditReceipt;
  readonly checkpointPublicKeys: AuditPublicKeyRing;
  readonly anchorPublicKeys: AuditPublicKeyRing;
}): AnchoredAuditTrailVerification {
  const latestAnchor = input.ledger.anchors.at(-1);
  if (latestAnchor === undefined) {
    return {
      valid: false,
      code: "ANCHOR_MISSING",
      message: "The local ledger contains no independent anchor",
    };
  }
  if (input.receipt.ledgerFile !== ledgerGenerationFilename(latestAnchor)) {
    return {
      valid: false,
      code: "TRUSTED_ANCHOR_MISMATCH",
      message: "The local receipt does not name the supplied immutable ledger generation",
    };
  }
  if (input.ledger.tenantId !== input.receipt.tenantId || input.ledger.streamId !== input.receipt.streamId) {
    return {
      valid: false,
      code: "TRUSTED_ANCHOR_MISMATCH",
      message: "The local receipt belongs to another tenant or audit stream",
    };
  }
  return verifyAnchoredAuditTrail({
    events: input.events,
    checkpoints: input.ledger.checkpoints,
    anchors: input.ledger.anchors,
    trustedAnchor: trustedReceiptFromLocal(input.receipt),
    checkpointPublicKeys: input.checkpointPublicKeys,
    anchorPublicKeys: input.anchorPublicKeys,
  });
}
