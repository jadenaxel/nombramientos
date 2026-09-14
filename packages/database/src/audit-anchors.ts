import {
  createHash,
  sign as signEd25519,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";

const CHECKPOINT_FORMAT = "nombramientos.audit-checkpoint.v1" as const;
const ANCHOR_FORMAT = "nombramientos.audit-anchor.v1" as const;
const CHECKPOINT_HASH_DOMAIN = "nombramientos:audit-checkpoint:v1\0";
const CHECKPOINT_SIGNATURE_DOMAIN = "nombramientos:audit-checkpoint-signature:v1\0";
const ANCHOR_HASH_DOMAIN = "nombramientos:audit-anchor:v1\0";
const ANCHOR_SIGNATURE_DOMAIN = "nombramientos:audit-anchor-signature:v1\0";
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const EVENT_HASH_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^[1-9][0-9]*$/;

export interface TenantAuditEventMaterial {
  readonly actorIdentityId: string | null;
  readonly action: string;
  readonly entityType: string | null;
  readonly entityId: string | null;
  readonly result: "success" | "denied" | "failure";
  readonly requestId: string | null;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export interface TenantAuditEventRecord extends TenantAuditEventMaterial {
  /** PostgreSQL bigint represented as a lossless decimal string. */
  readonly sequence: string;
  /** Required for hashVersion 2; absent records are interpreted as legacy v1. */
  readonly id?: string;
  /** Canonical ISO-8601 timestamp required for hashVersion 2. */
  readonly occurredAt?: string;
  /** Absent is legacy v1 for backwards-compatible offline ledgers. */
  readonly hashVersion?: 1 | 2;
  readonly previousHash: string | null;
  /** Existing audit_events hash format: lowercase SHA-256 hex without a prefix. */
  readonly eventHash: string;
}

export interface SignedAuditCheckpoint {
  readonly format: typeof CHECKPOINT_FORMAT;
  readonly tenantId: string;
  readonly streamId: string;
  readonly checkpointId: string;
  readonly capturedAt: string;
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly eventCount: string;
  readonly headHash: string;
  readonly previousCheckpointHash: string | null;
  readonly signingKeyId: string;
  readonly algorithm: "Ed25519";
  readonly checkpointHash: string;
  readonly signature: string;
}

export interface SignedAuditAnchor {
  readonly format: typeof ANCHOR_FORMAT;
  readonly tenantId: string;
  readonly streamId: string;
  readonly anchorId: string;
  readonly anchorSequence: string;
  readonly anchoredAt: string;
  readonly checkpointHash: string;
  readonly previousAnchorHash: string | null;
  readonly signingKeyId: string;
  readonly algorithm: "Ed25519";
  readonly anchorHash: string;
  readonly signature: string;
}

/**
 * Copy of the latest independent anchor retained outside the database/backup
 * being checked. Restoring this receipt from the same backup defeats rollback
 * detection, so production must obtain it from an independently retained store.
 */
export interface TrustedAuditAnchorReceipt {
  readonly tenantId: string;
  readonly streamId: string;
  readonly anchorSequence: string;
  readonly checkpointHash: string;
  readonly anchorHash: string;
}

export type AuditPublicKeyRing = ReadonlyMap<string, KeyObject>;

export type AuditVerificationFailureCode =
  | "EVENT_CHAIN_EMPTY"
  | "EVENT_SEQUENCE_INVALID"
  | "EVENT_SEQUENCE_GAP"
  | "EVENT_LINK_MISMATCH"
  | "EVENT_HASH_INVALID"
  | "EVENT_HASH_MISMATCH"
  | "CHECKPOINT_MISSING"
  | "CHECKPOINT_INVALID"
  | "CHECKPOINT_CHAIN_MISMATCH"
  | "CHECKPOINT_HASH_MISMATCH"
  | "CHECKPOINT_SIGNATURE_INVALID"
  | "CHECKPOINT_EVENT_MISSING"
  | "CHECKPOINT_EVENT_MISMATCH"
  | "EVENT_TAIL_UNANCHORED"
  | "ANCHOR_MISSING"
  | "ANCHOR_COVERAGE_MISMATCH"
  | "ANCHOR_INVALID"
  | "ANCHOR_CHAIN_MISMATCH"
  | "ANCHOR_HASH_MISMATCH"
  | "ANCHOR_SIGNATURE_INVALID"
  | "TRUSTED_ANCHOR_MISMATCH";

export interface AuditVerificationFailure {
  readonly valid: false;
  readonly code: AuditVerificationFailureCode;
  readonly message: string;
}

export interface AuditEventChainVerificationSuccess {
  readonly valid: true;
  readonly eventCount: string;
  readonly firstSequence: string;
  readonly lastSequence: string;
  readonly headHash: string;
}

export type AuditEventChainVerification =
  | AuditEventChainVerificationSuccess
  | AuditVerificationFailure;

export interface AnchoredAuditTrailVerificationSuccess
  extends AuditEventChainVerificationSuccess {
  readonly checkpointCount: number;
  readonly anchorCount: number;
  readonly latestCheckpointHash: string;
  readonly latestAnchorHash: string;
}

export type AnchoredAuditTrailVerification =
  | AnchoredAuditTrailVerificationSuccess
  | AuditVerificationFailure;

export interface CreateAuditCheckpointInput {
  readonly tenantId: string;
  readonly streamId: string;
  readonly checkpointId: string;
  readonly capturedAt: string;
  readonly events: readonly TenantAuditEventRecord[];
  readonly previousCheckpoint?: SignedAuditCheckpoint | null;
  readonly signingKeyId: string;
  readonly privateKey: KeyObject;
}

export interface CreateAuditAnchorInput {
  readonly checkpoint: SignedAuditCheckpoint;
  readonly anchorId: string;
  readonly anchoredAt: string;
  readonly previousAnchor?: SignedAuditAnchor | null;
  readonly signingKeyId: string;
  readonly privateKey: KeyObject;
}

export interface VerifyAnchoredAuditTrailInput {
  readonly events: readonly TenantAuditEventRecord[];
  readonly checkpoints: readonly SignedAuditCheckpoint[];
  readonly anchors: readonly SignedAuditAnchor[];
  readonly trustedAnchor: TrustedAuditAnchorReceipt;
  readonly checkpointPublicKeys: AuditPublicKeyRing;
  readonly anchorPublicKeys: AuditPublicKeyRing;
}

/**
 * Creates an event compatible with the canonical hash currently written to the
 * tenant audit_events table. This helper is pure and does not write a database.
 */
export function appendTenantAuditEvent(
  previous: TenantAuditEventRecord | null,
  material: TenantAuditEventMaterial,
): TenantAuditEventRecord {
  const sequence = previous === null
    ? 1n
    : requirePositiveDecimal(previous.sequence, "previous event sequence") + 1n;
  const previousHash = previous?.eventHash ?? null;
  if (previousHash !== null && !EVENT_HASH_PATTERN.test(previousHash)) {
    throw new Error("Previous audit event hash must be lowercase SHA-256 hex");
  }
  return {
    ...material,
    sequence: sequence.toString(),
    previousHash,
    eventHash: computeTenantAuditEventHash({ ...material, previousHash }),
  };
}

/** Recomputes the exact canonical hash material used by TenantStore. */
export function computeTenantAuditEventHash(
  input: TenantAuditEventMaterial & { readonly previousHash: string | null },
): string {
  return createHash("sha256")
    .update(canonicalJson({
      previousHash: input.previousHash,
      action: input.action,
      entityType: input.entityType,
      entityId: input.entityId,
      result: input.result,
      metadata: input.metadata,
      actor: {
        identity_id: input.actorIdentityId,
        request_id: input.requestId,
      },
    }))
    .digest("hex");
}

/** Computes the v2 event digest that binds database identity and ordering. */
export function computeTenantAuditEventHashV2(
  input: TenantAuditEventMaterial & {
    readonly id: string;
    readonly sequence: string;
    readonly occurredAt: string;
    readonly previousHash: string | null;
  },
): string {
  requireIdentifier(input.id, "audit event id");
  requirePositiveDecimal(input.sequence, "audit event sequence");
  requireCanonicalTimestamp(input.occurredAt, "audit event occurredAt");
  return createHash("sha256")
    .update(canonicalJson({
      hashVersion: 2,
      id: input.id,
      sequence: input.sequence,
      occurredAt: input.occurredAt,
      previousHash: input.previousHash,
      action: input.action,
      entityType: input.entityType,
      entityId: input.entityId,
      result: input.result,
      metadata: input.metadata,
      actor: {
        identity_id: input.actorIdentityId,
        request_id: input.requestId,
      },
    }))
    .digest("hex");
}

export function verifyTenantAuditEventChain(
  events: readonly TenantAuditEventRecord[],
): AuditEventChainVerification {
  if (events.length === 0) {
    return failure("EVENT_CHAIN_EMPTY", "The audit chain contains no events to checkpoint");
  }

  let previousSequence = 0n;
  let previousHash: string | null = null;
  for (const event of events) {
    const sequence = parsePositiveDecimal(event.sequence);
    if (sequence === null) {
      return failure("EVENT_SEQUENCE_INVALID", `Audit event sequence ${event.sequence} is not a positive decimal`);
    }
    if (sequence <= previousSequence) {
      return failure(
        "EVENT_SEQUENCE_GAP",
        `Audit event sequence ${event.sequence} is not strictly greater than its predecessor`,
      );
    }
    if (event.previousHash !== previousHash) {
      const expected = previousHash === null ? "null" : `${previousHash.slice(0, 12)}…`;
      const stored = event.previousHash === null ? "null" : `${event.previousHash.slice(0, 12)}…`;
      return failure(
        "EVENT_LINK_MISMATCH",
        `Audit event ${event.sequence} does not link to its predecessor (expected ${expected}, stored ${stored})`,
      );
    }
    if (!EVENT_HASH_PATTERN.test(event.eventHash)) {
      return failure("EVENT_HASH_INVALID", `Audit event ${event.sequence} has an invalid hash encoding`);
    }
    let calculatedHash: string;
    try {
      if ((event.hashVersion ?? 1) === 2) {
        if (!event.id || !event.occurredAt) {
          return failure("EVENT_HASH_INVALID", `Audit event ${event.sequence} is missing v2 identity material`);
        }
        calculatedHash = computeTenantAuditEventHashV2({
          id: event.id,
          sequence: event.sequence,
          occurredAt: event.occurredAt,
          actorIdentityId: event.actorIdentityId,
          action: event.action,
          entityType: event.entityType,
          entityId: event.entityId,
          result: event.result,
          requestId: event.requestId,
          metadata: event.metadata,
          previousHash: event.previousHash,
        });
      } else if ((event.hashVersion ?? 1) === 1) {
        calculatedHash = computeTenantAuditEventHash({
          actorIdentityId: event.actorIdentityId,
          action: event.action,
          entityType: event.entityType,
          entityId: event.entityId,
          result: event.result,
          requestId: event.requestId,
          metadata: event.metadata,
          previousHash: event.previousHash,
        });
      } else {
        return failure("EVENT_HASH_INVALID", `Audit event ${event.sequence} uses an unsupported hash version`);
      }
    } catch {
      return failure("EVENT_HASH_INVALID", `Audit event ${event.sequence} contains non-canonical JSON material`);
    }
    if (event.eventHash !== calculatedHash) {
      return failure("EVENT_HASH_MISMATCH", `Audit event ${event.sequence} content does not match its hash`);
    }
    previousHash = event.eventHash;
    previousSequence = sequence;
  }

  const first = events[0]!;
  const last = events.at(-1)!;
  return {
    valid: true,
    eventCount: events.length.toString(),
    firstSequence: first.sequence,
    lastSequence: last.sequence,
    headHash: last.eventHash,
  };
}

export function createSignedAuditCheckpoint(
  input: CreateAuditCheckpointInput,
): SignedAuditCheckpoint {
  requireIdentifier(input.tenantId, "tenantId");
  requireIdentifier(input.streamId, "streamId");
  requireIdentifier(input.checkpointId, "checkpointId");
  requireIdentifier(input.signingKeyId, "signingKeyId");
  requireCanonicalTimestamp(input.capturedAt, "capturedAt");
  requireEd25519Key(input.privateKey, "private");

  const chain = verifyTenantAuditEventChain(input.events);
  if (!chain.valid) throw new Error(`${chain.code}: ${chain.message}`);

  const previous = input.previousCheckpoint ?? null;
  if (previous !== null) {
    if (previous.tenantId !== input.tenantId || previous.streamId !== input.streamId) {
      throw new Error("Previous checkpoint belongs to another tenant or audit stream");
    }
    if (checkpointHash(previous) !== previous.checkpointHash) {
      throw new Error("Previous checkpoint hash is invalid");
    }
    if (
      requirePositiveDecimal(previous.lastSequence, "previous checkpoint lastSequence") >=
      requirePositiveDecimal(chain.lastSequence, "lastSequence")
    ) {
      throw new Error("A checkpoint must advance beyond its predecessor");
    }
  }

  const unsigned = {
    format: CHECKPOINT_FORMAT,
    tenantId: input.tenantId,
    streamId: input.streamId,
    checkpointId: input.checkpointId,
    capturedAt: input.capturedAt,
    firstSequence: chain.firstSequence,
    lastSequence: chain.lastSequence,
    eventCount: chain.eventCount,
    headHash: chain.headHash,
    previousCheckpointHash: previous?.checkpointHash ?? null,
    signingKeyId: input.signingKeyId,
    algorithm: "Ed25519" as const,
  };
  const digest = checkpointHash(unsigned);
  return {
    ...unsigned,
    checkpointHash: digest,
    signature: signDigest(CHECKPOINT_SIGNATURE_DOMAIN, digest, input.privateKey),
  };
}

export function createSignedAuditAnchor(input: CreateAuditAnchorInput): SignedAuditAnchor {
  requireIdentifier(input.anchorId, "anchorId");
  requireIdentifier(input.signingKeyId, "signingKeyId");
  requireCanonicalTimestamp(input.anchoredAt, "anchoredAt");
  requireEd25519Key(input.privateKey, "private");
  if (checkpointHash(input.checkpoint) !== input.checkpoint.checkpointHash) {
    throw new Error("Cannot anchor a checkpoint with an invalid hash");
  }

  const previous = input.previousAnchor ?? null;
  if (previous !== null) {
    if (
      previous.tenantId !== input.checkpoint.tenantId ||
      previous.streamId !== input.checkpoint.streamId
    ) {
      throw new Error("Previous anchor belongs to another tenant or audit stream");
    }
    if (anchorHash(previous) !== previous.anchorHash) {
      throw new Error("Previous anchor hash is invalid");
    }
  }

  const anchorSequence = previous === null
    ? 1n
    : requirePositiveDecimal(previous.anchorSequence, "previous anchor sequence") + 1n;
  const unsigned = {
    format: ANCHOR_FORMAT,
    tenantId: input.checkpoint.tenantId,
    streamId: input.checkpoint.streamId,
    anchorId: input.anchorId,
    anchorSequence: anchorSequence.toString(),
    anchoredAt: input.anchoredAt,
    checkpointHash: input.checkpoint.checkpointHash,
    previousAnchorHash: previous?.anchorHash ?? null,
    signingKeyId: input.signingKeyId,
    algorithm: "Ed25519" as const,
  };
  const digest = anchorHash(unsigned);
  return {
    ...unsigned,
    anchorHash: digest,
    signature: signDigest(ANCHOR_SIGNATURE_DOMAIN, digest, input.privateKey),
  };
}

export function createTrustedAuditAnchorReceipt(
  anchor: SignedAuditAnchor,
): TrustedAuditAnchorReceipt {
  return {
    tenantId: anchor.tenantId,
    streamId: anchor.streamId,
    anchorSequence: anchor.anchorSequence,
    checkpointHash: anchor.checkpointHash,
    anchorHash: anchor.anchorHash,
  };
}

export function verifyAnchoredAuditTrail(
  input: VerifyAnchoredAuditTrailInput,
): AnchoredAuditTrailVerification {
  const eventChain = verifyTenantAuditEventChain(input.events);
  if (!eventChain.valid) return eventChain;
  if (input.checkpoints.length === 0) {
    return failure("CHECKPOINT_MISSING", "The audit trail has no signed checkpoint");
  }

  let previousCheckpointHash: string | null = null;
  let previousCheckpointSequence = 0n;
  let previousCheckpointEventCount = 0n;
  let tenantId: string | null = null;
  let streamId: string | null = null;
  const eventCoverage = new Map<string, { readonly hash: string; readonly count: bigint }>();
  for (const [index, event] of input.events.entries()) {
    eventCoverage.set(event.sequence, { hash: event.eventHash, count: BigInt(index + 1) });
  }
  for (const checkpoint of input.checkpoints) {
    if (
      checkpoint.format !== CHECKPOINT_FORMAT ||
      checkpoint.algorithm !== "Ed25519" ||
      !isIdentifier(checkpoint.tenantId) ||
      !isIdentifier(checkpoint.streamId) ||
      !isIdentifier(checkpoint.checkpointId) ||
      !isIdentifier(checkpoint.signingKeyId) ||
      !isCanonicalTimestamp(checkpoint.capturedAt) ||
      parsePositiveDecimal(checkpoint.firstSequence) === null ||
      !EVENT_HASH_PATTERN.test(checkpoint.headHash)
    ) {
      return failure("CHECKPOINT_INVALID", "A checkpoint contains invalid identity, format, time, or hash fields");
    }
    const lastSequence = parsePositiveDecimal(checkpoint.lastSequence);
    const eventCount = parsePositiveDecimal(checkpoint.eventCount);
    if (
      lastSequence === null ||
      eventCount === null ||
      checkpoint.firstSequence !== eventChain.firstSequence
    ) {
      return failure("CHECKPOINT_INVALID", `Checkpoint ${checkpoint.checkpointId} has invalid coverage`);
    }
    if (lastSequence <= previousCheckpointSequence || eventCount <= previousCheckpointEventCount) {
      return failure("CHECKPOINT_CHAIN_MISMATCH", "Checkpoint coverage is not strictly increasing");
    }
    if (checkpoint.previousCheckpointHash !== previousCheckpointHash) {
      return failure("CHECKPOINT_CHAIN_MISMATCH", `Checkpoint ${checkpoint.checkpointId} does not link to its predecessor`);
    }
    if (tenantId !== null && (checkpoint.tenantId !== tenantId || checkpoint.streamId !== streamId)) {
      return failure("CHECKPOINT_CHAIN_MISMATCH", "Checkpoint tenant or stream changed inside the chain");
    }
    tenantId ??= checkpoint.tenantId;
    streamId ??= checkpoint.streamId;

    let calculatedHash: string;
    try {
      calculatedHash = checkpointHash(checkpoint);
    } catch {
      return failure("CHECKPOINT_INVALID", `Checkpoint ${checkpoint.checkpointId} is not canonically serializable`);
    }
    if (!SHA256_PATTERN.test(checkpoint.checkpointHash) || checkpoint.checkpointHash !== calculatedHash) {
      return failure("CHECKPOINT_HASH_MISMATCH", `Checkpoint ${checkpoint.checkpointId} content does not match its hash`);
    }
    if (!verifyDigest(
      CHECKPOINT_SIGNATURE_DOMAIN,
      checkpoint.checkpointHash,
      checkpoint.signature,
      checkpoint.signingKeyId,
      input.checkpointPublicKeys,
    )) {
      return failure("CHECKPOINT_SIGNATURE_INVALID", `Checkpoint ${checkpoint.checkpointId} has no valid Ed25519 signature`);
    }
    const coveredEvent = eventCoverage.get(checkpoint.lastSequence);
    if (!coveredEvent) {
      return failure("CHECKPOINT_EVENT_MISSING", `Checkpoint ${checkpoint.checkpointId} covers an unavailable audit event`);
    }
    if (coveredEvent.hash !== checkpoint.headHash || coveredEvent.count !== eventCount) {
      return failure("CHECKPOINT_EVENT_MISMATCH", `Checkpoint ${checkpoint.checkpointId} does not match the covered event head`);
    }

    previousCheckpointHash = checkpoint.checkpointHash;
    previousCheckpointSequence = lastSequence;
    previousCheckpointEventCount = eventCount;
  }

  if (
    previousCheckpointSequence.toString() !== eventChain.lastSequence ||
    previousCheckpointEventCount !== BigInt(input.events.length)
  ) {
    return failure("EVENT_TAIL_UNANCHORED", "The latest audit events are not covered by the latest checkpoint");
  }
  if (input.anchors.length === 0) {
    return failure("ANCHOR_MISSING", "The checkpoint chain has no independent anchor");
  }
  if (input.anchors.length !== input.checkpoints.length) {
    return failure("ANCHOR_COVERAGE_MISMATCH", "Every checkpoint must have exactly one ordered independent anchor");
  }

  let previousAnchorHash: string | null = null;
  for (const [index, anchor] of input.anchors.entries()) {
    const checkpoint = input.checkpoints[index]!;
    const expectedSequence = BigInt(index + 1);
    const anchorSequence = parsePositiveDecimal(anchor.anchorSequence);
    if (
      anchor.format !== ANCHOR_FORMAT ||
      anchor.algorithm !== "Ed25519" ||
      !isIdentifier(anchor.anchorId) ||
      !isIdentifier(anchor.signingKeyId) ||
      !isCanonicalTimestamp(anchor.anchoredAt) ||
      anchorSequence !== expectedSequence
    ) {
      return failure("ANCHOR_INVALID", "An anchor contains invalid identity, format, time, or sequence fields");
    }
    if (anchor.tenantId !== tenantId || anchor.streamId !== streamId) {
      return failure("ANCHOR_CHAIN_MISMATCH", "Anchor tenant or stream does not match the checkpoint chain");
    }
    if (anchor.previousAnchorHash !== previousAnchorHash) {
      return failure("ANCHOR_CHAIN_MISMATCH", `Anchor ${anchor.anchorId} does not link to its predecessor`);
    }
    if (anchor.checkpointHash !== checkpoint.checkpointHash) {
      return failure("ANCHOR_COVERAGE_MISMATCH", `Anchor ${anchor.anchorId} references the wrong checkpoint`);
    }
    let calculatedHash: string;
    try {
      calculatedHash = anchorHash(anchor);
    } catch {
      return failure("ANCHOR_INVALID", `Anchor ${anchor.anchorId} is not canonically serializable`);
    }
    if (!SHA256_PATTERN.test(anchor.anchorHash) || anchor.anchorHash !== calculatedHash) {
      return failure("ANCHOR_HASH_MISMATCH", `Anchor ${anchor.anchorId} content does not match its hash`);
    }
    if (!verifyDigest(
      ANCHOR_SIGNATURE_DOMAIN,
      anchor.anchorHash,
      anchor.signature,
      anchor.signingKeyId,
      input.anchorPublicKeys,
    )) {
      return failure("ANCHOR_SIGNATURE_INVALID", `Anchor ${anchor.anchorId} has no valid Ed25519 signature`);
    }
    previousAnchorHash = anchor.anchorHash;
  }

  const latestCheckpoint = input.checkpoints.at(-1)!;
  const latestAnchor = input.anchors.at(-1)!;
  const trusted = input.trustedAnchor;
  if (
    trusted.tenantId !== latestAnchor.tenantId ||
    trusted.streamId !== latestAnchor.streamId ||
    trusted.anchorSequence !== latestAnchor.anchorSequence ||
    trusted.checkpointHash !== latestAnchor.checkpointHash ||
    trusted.anchorHash !== latestAnchor.anchorHash
  ) {
    return failure(
      "TRUSTED_ANCHOR_MISMATCH",
      "The supplied history does not reach the independently retained trusted anchor",
    );
  }

  return {
    ...eventChain,
    checkpointCount: input.checkpoints.length,
    anchorCount: input.anchors.length,
    latestCheckpointHash: latestCheckpoint.checkpointHash,
    latestAnchorHash: latestAnchor.anchorHash,
  };
}

function checkpointHash(checkpoint: Omit<SignedAuditCheckpoint, "checkpointHash" | "signature">): string {
  return hashCanonical(CHECKPOINT_HASH_DOMAIN, {
    format: checkpoint.format,
    tenantId: checkpoint.tenantId,
    streamId: checkpoint.streamId,
    checkpointId: checkpoint.checkpointId,
    capturedAt: checkpoint.capturedAt,
    firstSequence: checkpoint.firstSequence,
    lastSequence: checkpoint.lastSequence,
    eventCount: checkpoint.eventCount,
    headHash: checkpoint.headHash,
    previousCheckpointHash: checkpoint.previousCheckpointHash,
    signingKeyId: checkpoint.signingKeyId,
    algorithm: checkpoint.algorithm,
  });
}

function anchorHash(anchor: Omit<SignedAuditAnchor, "anchorHash" | "signature">): string {
  return hashCanonical(ANCHOR_HASH_DOMAIN, {
    format: anchor.format,
    tenantId: anchor.tenantId,
    streamId: anchor.streamId,
    anchorId: anchor.anchorId,
    anchorSequence: anchor.anchorSequence,
    anchoredAt: anchor.anchoredAt,
    checkpointHash: anchor.checkpointHash,
    previousAnchorHash: anchor.previousAnchorHash,
    signingKeyId: anchor.signingKeyId,
    algorithm: anchor.algorithm,
  });
}

function hashCanonical(domain: string, value: unknown): string {
  return `sha256:${createHash("sha256").update(domain).update(canonicalJson(value)).digest("hex")}`;
}

function signDigest(domain: string, digest: string, privateKey: KeyObject): string {
  return signEd25519(null, Buffer.from(`${domain}${digest}`, "utf8"), privateKey).toString("base64url");
}

function verifyDigest(
  domain: string,
  digest: string,
  signature: string,
  keyId: string,
  keys: AuditPublicKeyRing,
): boolean {
  const key = keys.get(keyId);
  if (key === undefined || key.type !== "public" || key.asymmetricKeyType !== "ed25519") return false;
  const decoded = decodeCanonicalBase64Url(signature);
  if (decoded === null || decoded.byteLength !== 64) return false;
  try {
    return verifyEd25519(null, Buffer.from(`${domain}${digest}`, "utf8"), key, decoded);
  } catch {
    return false;
  }
}

function decodeCanonicalBase64Url(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.toString("base64url") === value ? decoded : null;
}

function requireEd25519Key(key: KeyObject, kind: "private" | "public"): void {
  if (key.type !== kind || key.asymmetricKeyType !== "ed25519") {
    throw new Error(`Audit ${kind} key must be Ed25519`);
  }
}

function requireIdentifier(value: string, name: string): void {
  if (!isIdentifier(value)) throw new Error(`${name} must be a non-empty identifier`);
}

function isIdentifier(value: string): boolean {
  return typeof value === "string" && value.length > 0 && value.length <= 256 && value.trim() === value;
}

function requireCanonicalTimestamp(value: string, name: string): void {
  if (!isCanonicalTimestamp(value)) throw new Error(`${name} must be a canonical ISO-8601 timestamp`);
}

function isCanonicalTimestamp(value: string): boolean {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function requirePositiveDecimal(value: string, name: string): bigint {
  const parsed = parsePositiveDecimal(value);
  if (parsed === null) throw new Error(`${name} must be a positive decimal string`);
  return parsed;
}

function parsePositiveDecimal(value: string): bigint | null {
  if (typeof value !== "string" || !DECIMAL_PATTERN.test(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function canonicalJson(value: unknown, ancestors = new Set<object>()): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Canonical JSON rejects non-finite numbers");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (typeof value !== "object") throw new Error("Canonical JSON accepts JSON values only");
  if (ancestors.has(value)) throw new Error("Canonical JSON rejects cyclic structures");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => canonicalJson(item, ancestors)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Canonical JSON accepts plain records only");
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key], ancestors)}`)
      .join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function failure(code: AuditVerificationFailureCode, message: string): AuditVerificationFailure {
  return { valid: false, code, message };
}
