import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  appendLocalAuditEvidence,
  assertIsolatedAuditAdminUrl,
  createLocalAuditLedger,
  createLocalAuditReceipt,
  ledgerGenerationFilename,
  LOCAL_AUDIT_STORAGE_ASSURANCE,
  parseLocalAuditLedger,
  parseLocalAuditReceipt,
  receiptGenerationFilename,
  verifyLocalAuditLedger,
} from "../src/audit-anchor-ledger.js";
import {
  appendTenantAuditEvent,
  createSignedAuditAnchor,
  createSignedAuditCheckpoint,
  type TenantAuditEventRecord,
} from "../src/audit-anchors.js";

const TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const STREAM_ID = "tenant-audit";

describe("local development audit ledger", () => {
  it("appends immutable generations and verifies the latest receipt", () => {
    const sample = createLedgerFixture();
    const roundTripped = parseLocalAuditLedger(JSON.parse(JSON.stringify(sample.ledger)) as unknown);
    const receipt = parseLocalAuditReceipt(JSON.parse(JSON.stringify(sample.receipt)) as unknown);
    expect(roundTripped.storageAssurance).toBe(LOCAL_AUDIT_STORAGE_ASSURANCE);
    expect(ledgerGenerationFilename(roundTripped.anchors.at(-1)!)).toBe(receipt.ledgerFile);
    expect(receiptGenerationFilename(receipt)).toMatch(/^receipt-0{19}2-[0-9a-f]{64}\.json$/);
    expect(verifyLocalAuditLedger({
      events: sample.events,
      ledger: roundTripped,
      receipt,
      checkpointPublicKeys: new Map([[sample.checkpointKeyId, sample.checkpointKeys.publicKey]]),
      anchorPublicKeys: new Map([[sample.anchorKeyId, sample.anchorKeys.publicKey]]),
    })).toMatchObject({ valid: true, eventCount: "4", checkpointCount: 2, anchorCount: 2 });
  });

  it("rejects cross-stream and non-contiguous appends", () => {
    const sample = createLedgerFixture();
    const first = parseLocalAuditLedger({
      ...sample.ledger,
      checkpoints: sample.ledger.checkpoints.slice(0, 1),
      anchors: sample.ledger.anchors.slice(0, 1),
    });
    const secondCheckpoint = sample.ledger.checkpoints[1]!;
    const secondAnchor = sample.ledger.anchors[1]!;
    expect(() => appendLocalAuditEvidence(first, {
      ...secondCheckpoint,
      previousCheckpointHash: null,
    }, secondAnchor)).toThrow(/checkpoint does not append/i);
    expect(() => appendLocalAuditEvidence(first, secondCheckpoint, {
      ...secondAnchor,
      streamId: "other-audit",
    })).toThrow(/tenant or stream/i);
  });

  it("rejects path traversal and any claim of WORM assurance in local artifacts", () => {
    const sample = createLedgerFixture();
    expect(() => parseLocalAuditReceipt({
      ...sample.receipt,
      ledgerFile: "../ledger.json",
    })).toThrow();
    expect(() => parseLocalAuditLedger({
      ...sample.ledger,
      storageAssurance: "worm",
    })).toThrow();
  });

  it("accepts only nom_admin on isolated loopback port 55432", () => {
    const accepted = assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@127.0.0.1:55432/postgres");
    expect(accepted.hostname).toBe("127.0.0.1");
    expect(accepted.port).toBe("55432");
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@127.0.0.1:5432/postgres")).toThrow(/5432/i);
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@db.example:55432/postgres")).toThrow(/loopback/i);
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_runtime:fixture@127.0.0.1:55432/postgres")).toThrow(/nom_admin/i);
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@127.0.0.1:55432/postgres?host=db.example")).toThrow(/exact/u);
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@localhost:55432/postgres")).toThrow(/exact/u);
    expect(() => assertIsolatedAuditAdminUrl("postgresql://nom_admin:fixture@2130706433:55432/postgres")).toThrow(/exact/u);
  });
});

function createLedgerFixture() {
  const checkpointKeys = generateKeyPairSync("ed25519");
  const anchorKeys = generateKeyPairSync("ed25519");
  const checkpointKeyId = "40000000-0000-4000-8000-000000000001";
  const anchorKeyId = "40000000-0000-4000-8000-000000000002";
  const events: TenantAuditEventRecord[] = [];
  for (let index = 1; index <= 4; index += 1) {
    events.push(appendTenantAuditEvent(events.at(-1) ?? null, {
      actorIdentityId: null,
      action: `fixture.${index}`,
      entityType: "fixture",
      entityId: String(index),
      result: "success",
      requestId: null,
      metadata: { index },
    }));
  }
  const checkpointOne = createSignedAuditCheckpoint({
    tenantId: TENANT_ID,
    streamId: STREAM_ID,
    checkpointId: "checkpoint-one",
    capturedAt: "2026-09-11T01:00:00.000Z",
    events: events.slice(0, 2),
    signingKeyId: checkpointKeyId,
    privateKey: checkpointKeys.privateKey,
  });
  const anchorOne = createSignedAuditAnchor({
    checkpoint: checkpointOne,
    anchorId: "anchor-one",
    anchoredAt: "2026-09-11T01:00:01.000Z",
    signingKeyId: anchorKeyId,
    privateKey: anchorKeys.privateKey,
  });
  const checkpointTwo = createSignedAuditCheckpoint({
    tenantId: TENANT_ID,
    streamId: STREAM_ID,
    checkpointId: "checkpoint-two",
    capturedAt: "2026-09-11T01:00:02.000Z",
    events,
    previousCheckpoint: checkpointOne,
    signingKeyId: checkpointKeyId,
    privateKey: checkpointKeys.privateKey,
  });
  const anchorTwo = createSignedAuditAnchor({
    checkpoint: checkpointTwo,
    anchorId: "anchor-two",
    anchoredAt: "2026-09-11T01:00:03.000Z",
    previousAnchor: anchorOne,
    signingKeyId: anchorKeyId,
    privateKey: anchorKeys.privateKey,
  });
  let ledger = createLocalAuditLedger(TENANT_ID, STREAM_ID);
  ledger = appendLocalAuditEvidence(ledger, checkpointOne, anchorOne);
  ledger = appendLocalAuditEvidence(ledger, checkpointTwo, anchorTwo);
  const receipt = createLocalAuditReceipt(
    anchorTwo,
    ledgerGenerationFilename(anchorTwo),
    "2026-09-11T01:00:04.000Z",
  );
  return { events, ledger, receipt, checkpointKeys, anchorKeys, checkpointKeyId, anchorKeyId };
}
