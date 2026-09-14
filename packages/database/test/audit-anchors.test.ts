import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  appendTenantAuditEvent,
  computeTenantAuditEventHashV2,
  createSignedAuditAnchor,
  createSignedAuditCheckpoint,
  createTrustedAuditAnchorReceipt,
  verifyAnchoredAuditTrail,
  verifyTenantAuditEventChain,
  type AuditPublicKeyRing,
  type SignedAuditAnchor,
  type SignedAuditCheckpoint,
  type TenantAuditEventMaterial,
  type TenantAuditEventRecord,
  type TrustedAuditAnchorReceipt,
} from "../src/audit-anchors.js";
import { tenantAuditEventRecordFromRow } from "../src/audit-event-chain.js";

const TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const STREAM_ID = "tenant-audit";

interface Fixture {
  readonly events: readonly TenantAuditEventRecord[];
  readonly checkpoints: readonly SignedAuditCheckpoint[];
  readonly anchors: readonly SignedAuditAnchor[];
  readonly trustedAnchor: TrustedAuditAnchorReceipt;
  readonly checkpointPublicKeys: AuditPublicKeyRing;
  readonly anchorPublicKeys: AuditPublicKeyRing;
}

describe("signed audit checkpoints and independent anchors", () => {
  it("accepts legitimate PostgreSQL sequence gaps while preserving the hash links", () => {
    const fixture = createFixture();
    const gapped = fixture.events.map((event, index) => ({
      ...event,
      sequence: String((index + 1) * 2),
    }));
    expect(verifyTenantAuditEventChain(gapped)).toMatchObject({
      valid: true,
      eventCount: "6",
      firstSequence: "2",
      lastSequence: "12",
    });
  });

  it("verifies a complete event, checkpoint, signature, and anchor chain", () => {
    const fixture = createFixture();
    expect(verify(fixture)).toEqual({
      valid: true,
      eventCount: "6",
      firstSequence: "1",
      lastSequence: "6",
      headHash: fixture.events.at(-1)!.eventHash,
      checkpointCount: 2,
      anchorCount: 2,
      latestCheckpointHash: fixture.checkpoints.at(-1)!.checkpointHash,
      latestAnchorHash: fixture.anchors.at(-1)!.anchorHash,
    });
  });

  it("detects altered event content", () => {
    const fixture = createFixture();
    const altered = [...fixture.events];
    altered[2] = {
      ...altered[2]!,
      metadata: { ...altered[2]!.metadata, reason: "rewritten after the fact" },
    };
    expect(verify(fixture, { events: altered })).toMatchObject({
      valid: false,
      code: "EVENT_HASH_MISMATCH",
    });
  });

  it("verifies legacy v1 and identity-bound v2 events in one chain", () => {
    const legacy = appendTenantAuditEvent(null, fixtureMaterial(1));
    const current = appendV2Event(legacy, 2);
    expect(verifyTenantAuditEventChain([legacy, current])).toMatchObject({
      valid: true,
      eventCount: "2",
      headHash: current.eventHash,
    });
  });

  it("preserves PostgreSQL identity fields when a v2 row enters the verifier", () => {
    const first = appendV2Event(null, 1);
    const row = tenantAuditEventRecordFromRow({
      sequence: first.sequence,
      id: first.id!,
      occurred_at: new Date(first.occurredAt!),
      hash_version: first.hashVersion!,
      actor_identity_id: first.actorIdentityId,
      action: first.action,
      entity_type: first.entityType,
      entity_id: first.entityId,
      result: first.result,
      request_id: first.requestId,
      metadata: { ...first.metadata },
      previous_hash: first.previousHash,
      event_hash: first.eventHash,
    });
    expect(row).toEqual(first);
    expect(verifyTenantAuditEventChain([row])).toMatchObject({ valid: true, eventCount: "1" });
  });

  it("detects v2 timestamp, sequence, and identifier tampering", () => {
    const first = appendV2Event(null, 1);
    const second = appendV2Event(first, 2);
    for (const tampered of [
      { ...second, occurredAt: "2026-09-11T12:09:59.000Z" },
      { ...second, sequence: "9" },
      { ...second, id: "90000000-0000-4000-8000-000000000099" },
    ]) {
      expect(verifyTenantAuditEventChain([first, tampered])).toMatchObject({
        valid: false,
        code: "EVENT_HASH_MISMATCH",
      });
    }
  });

  it("detects a rewritten history even when every event hash is recalculated", () => {
    const fixture = createFixture();
    const rewritten: TenantAuditEventRecord[] = [];
    for (const [index, event] of fixture.events.entries()) {
      rewritten.push(appendTenantAuditEvent(rewritten.at(-1) ?? null, {
        actorIdentityId: event.actorIdentityId,
        action: event.action,
        entityType: event.entityType,
        entityId: event.entityId,
        result: event.result,
        requestId: event.requestId,
        metadata: index === 1 ? { ...event.metadata, rewritten: true } : event.metadata,
      }));
    }
    expect(verify(fixture, { events: rewritten })).toMatchObject({
      valid: false,
      code: "CHECKPOINT_EVENT_MISMATCH",
    });
  });

  it("detects deletion of an intermediate event", () => {
    const fixture = createFixture();
    const deleted = fixture.events.filter((event) => event.sequence !== "3");
    expect(verify(fixture, { events: deleted })).toMatchObject({
      valid: false,
      code: "EVENT_LINK_MISMATCH",
    });
  });

  it("detects event-chain truncation against the latest checkpoint", () => {
    const fixture = createFixture();
    expect(verify(fixture, { events: fixture.events.slice(0, -1) })).toMatchObject({
      valid: false,
      code: "CHECKPOINT_EVENT_MISSING",
    });
  });

  it("detects reordered events", () => {
    const fixture = createFixture();
    const reordered = [
      fixture.events[0]!,
      fixture.events[2]!,
      fixture.events[1]!,
      ...fixture.events.slice(3),
    ];
    expect(verify(fixture, { events: reordered })).toMatchObject({
      valid: false,
      code: "EVENT_LINK_MISMATCH",
    });
  });

  it("detects restoration of an internally valid old chain using the later trusted anchor", () => {
    const fixture = createFixture();
    expect(verify(fixture, {
      events: fixture.events.slice(0, 3),
      checkpoints: fixture.checkpoints.slice(0, 1),
      anchors: fixture.anchors.slice(0, 1),
    })).toMatchObject({
      valid: false,
      code: "TRUSTED_ANCHOR_MISMATCH",
    });
  });

  it("detects a manipulated checkpoint signature", () => {
    const fixture = createFixture();
    const checkpoints = [...fixture.checkpoints];
    checkpoints[1] = {
      ...checkpoints[1]!,
      signature: corruptSignature(checkpoints[1]!.signature),
    };
    expect(verify(fixture, { checkpoints })).toMatchObject({
      valid: false,
      code: "CHECKPOINT_SIGNATURE_INVALID",
    });
  });

  it("detects manipulated anchor content", () => {
    const fixture = createFixture();
    const anchors = [...fixture.anchors];
    anchors[1] = {
      ...anchors[1]!,
      anchoredAt: "2026-09-11T12:09:00.000Z",
    };
    expect(verify(fixture, { anchors })).toMatchObject({
      valid: false,
      code: "ANCHOR_HASH_MISMATCH",
    });
  });

  it("detects a manipulated anchor signature", () => {
    const fixture = createFixture();
    const anchors = [...fixture.anchors];
    anchors[1] = {
      ...anchors[1]!,
      signature: corruptSignature(anchors[1]!.signature),
    };
    expect(verify(fixture, { anchors })).toMatchObject({
      valid: false,
      code: "ANCHOR_SIGNATURE_INVALID",
    });
  });

  it("detects removal of an anchor from the independent chain", () => {
    const fixture = createFixture();
    expect(verify(fixture, { anchors: fixture.anchors.slice(1) })).toMatchObject({
      valid: false,
      code: "ANCHOR_COVERAGE_MISMATCH",
    });
  });

  it("rejects signatures when the configured public key is not the signer", () => {
    const fixture = createFixture();
    const unrelated = generateKeyPairSync("ed25519");
    expect(verify(fixture, {
      checkpointPublicKeys: new Map([["audit-checkpoint-key-2026-09", unrelated.publicKey]]),
    })).toMatchObject({
      valid: false,
      code: "CHECKPOINT_SIGNATURE_INVALID",
    });
  });
});

function createFixture(): Fixture {
  const checkpointKeys = generateKeyPairSync("ed25519");
  const anchorKeys = generateKeyPairSync("ed25519");
  const checkpointKeyId = "audit-checkpoint-key-2026-09";
  const anchorKeyId = "audit-anchor-key-2026-09";
  const events: TenantAuditEventRecord[] = [];

  for (let index = 1; index <= 6; index += 1) {
    events.push(appendTenantAuditEvent(events.at(-1) ?? null, {
      actorIdentityId: "10000000-0000-4000-8000-000000000001",
      action: `member.fixture-${index}.updated`,
      entityType: "member",
      entityId: `20000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
      result: "success",
      requestId: `30000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
      metadata: { fixture: true, ordinal: index },
    }));
  }

  const checkpointOne = createSignedAuditCheckpoint({
    tenantId: TENANT_ID,
    streamId: STREAM_ID,
    checkpointId: "checkpoint-0001",
    capturedAt: "2026-09-11T12:03:00.000Z",
    events: events.slice(0, 3),
    signingKeyId: checkpointKeyId,
    privateKey: checkpointKeys.privateKey,
  });
  const anchorOne = createSignedAuditAnchor({
    checkpoint: checkpointOne,
    anchorId: "anchor-0001",
    anchoredAt: "2026-09-11T12:03:01.000Z",
    signingKeyId: anchorKeyId,
    privateKey: anchorKeys.privateKey,
  });
  const checkpointTwo = createSignedAuditCheckpoint({
    tenantId: TENANT_ID,
    streamId: STREAM_ID,
    checkpointId: "checkpoint-0002",
    capturedAt: "2026-09-11T12:06:00.000Z",
    events,
    previousCheckpoint: checkpointOne,
    signingKeyId: checkpointKeyId,
    privateKey: checkpointKeys.privateKey,
  });
  const anchorTwo = createSignedAuditAnchor({
    checkpoint: checkpointTwo,
    anchorId: "anchor-0002",
    anchoredAt: "2026-09-11T12:06:01.000Z",
    previousAnchor: anchorOne,
    signingKeyId: anchorKeyId,
    privateKey: anchorKeys.privateKey,
  });

  return {
    events,
    checkpoints: [checkpointOne, checkpointTwo],
    anchors: [anchorOne, anchorTwo],
    trustedAnchor: createTrustedAuditAnchorReceipt(anchorTwo),
    checkpointPublicKeys: new Map([[checkpointKeyId, checkpointKeys.publicKey]]),
    anchorPublicKeys: new Map([[anchorKeyId, anchorKeys.publicKey]]),
  };
}

function fixtureMaterial(index: number): TenantAuditEventMaterial {
  return {
    actorIdentityId: "10000000-0000-4000-8000-000000000001",
    action: `member.v2-fixture-${index}.updated`,
    entityType: "member",
    entityId: `20000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
    result: "success",
    requestId: `30000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
    metadata: { fixture: true, ordinal: index },
  };
}

function appendV2Event(previous: TenantAuditEventRecord | null, index: number): TenantAuditEventRecord {
  const material = fixtureMaterial(index);
  const sequence = previous === null ? "1" : (BigInt(previous.sequence) + 1n).toString();
  const id = `40000000-0000-4000-8000-${index.toString().padStart(12, "0")}`;
  const occurredAt = `2026-09-11T12:0${index}:00.000Z`;
  const previousHash = previous?.eventHash ?? null;
  return {
    ...material,
    id,
    sequence,
    occurredAt,
    hashVersion: 2,
    previousHash,
    eventHash: computeTenantAuditEventHashV2({ ...material, id, sequence, occurredAt, previousHash }),
  };
}

function verify(
  fixture: Fixture,
  overrides: Partial<Fixture> = {},
) {
  return verifyAnchoredAuditTrail({
    events: overrides.events ?? fixture.events,
    checkpoints: overrides.checkpoints ?? fixture.checkpoints,
    anchors: overrides.anchors ?? fixture.anchors,
    trustedAnchor: overrides.trustedAnchor ?? fixture.trustedAnchor,
    checkpointPublicKeys: overrides.checkpointPublicKeys ?? fixture.checkpointPublicKeys,
    anchorPublicKeys: overrides.anchorPublicKeys ?? fixture.anchorPublicKeys,
  });
}

function corruptSignature(signature: string): string {
  const bytes = Buffer.from(signature, "base64url");
  bytes[0] = bytes[0]! ^ 0x80;
  return bytes.toString("base64url");
}
