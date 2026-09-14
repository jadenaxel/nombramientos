import assert from "node:assert/strict";
import test from "node:test";

import {
  createTenantKeyGrantEnvelope,
  exportTenantDevicePublicKey,
  generateTenantContentKey,
  generateTenantDeviceKeyPair,
  importCustodianPublicKey,
  openTenantKeyGrantEnvelope,
  type CustodianPrivateKey,
  type TenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";

import { encryptJson } from "./crypto-client.ts";
import {
  delegateHistoricalTenantKeys,
  historicalApprovalFailureIsRetryable,
  historicalApprovalFailureStopsBatch,
  withWipedKeyBytes,
} from "./historical-key-delegation.ts";
import { openJsonEnvelope } from "./historical-envelope.ts";
import type {
  ApproveGrantIntent,
  KeyLifecycleDevice,
  KeyLifecycleGeneration,
  KeyLifecycleGrant,
  LocalTenantDevice,
} from "./key-lifecycle-client.ts";
import { TenantCryptoKeyring } from "./tenant-keyring.ts";

const tenantId = "10000000-0000-4000-8000-000000000001";
const actorIdentityId = "10000000-0000-4000-8000-000000000002";
const actorDeviceId = "10000000-0000-4000-8000-000000000003";
const targetIdentityId = "10000000-0000-4000-8000-000000000004";
const targetDeviceId = "10000000-0000-4000-8000-000000000005";
const retiredTenantKeyId = "10000000-0000-4000-8000-000000000006";
const currentTenantKeyId = "10000000-0000-4000-8000-000000000007";
const secondRetiredTenantKeyId = "10000000-0000-4000-8000-000000000008";

function apiFailure(status: number, code: string): Error & { readonly status: number; readonly code: string } {
  return Object.assign(new Error(code), { status, code });
}

test("onboarding posterior a rotación reenvuelve una generación retirada y abre historia y contenido vigente antiguo", async () => {
  const actorPrivate = await generateTenantDeviceKeyPair({ tenantId, deviceId: actorDeviceId });
  const targetPrivate = await generateTenantDeviceKeyPair({ tenantId, deviceId: targetDeviceId });
  const [actor, target] = await Promise.all([
    devicePair(actorPrivate, actorIdentityId, actorDeviceId, "Authorized administrator"),
    devicePair(targetPrivate, targetIdentityId, targetDeviceId, "New browser"),
  ]);
  const retiredKey = generateTenantContentKey(retiredTenantKeyId);
  const currentKey = generateTenantContentKey(currentTenantKeyId);
  try {
    const [actorRetiredEnvelope, targetCurrentEnvelope] = await Promise.all([
      createTenantKeyGrantEnvelope({
        tenantId,
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: actorIdentityId,
        deviceId: actorDeviceId,
        tenantKey: retiredKey.keyBytes,
        recipient: await importCustodianPublicKey(actor.server.wrappingPublicKey),
      }),
      createTenantKeyGrantEnvelope({
        tenantId,
        tenantKeyId: currentTenantKeyId,
        generation: 2,
        identityId: targetIdentityId,
        deviceId: targetDeviceId,
        tenantKey: currentKey.keyBytes,
        recipient: await importCustodianPublicKey(target.server.wrappingPublicKey),
      }),
    ]);
    const actorRetiredGrant = grant({
      grantId: "20000000-0000-4000-8000-000000000001",
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      identityId: actorIdentityId,
      deviceId: actorDeviceId,
      envelope: actorRetiredEnvelope,
      status: "retired",
    });
    const targetCurrentGrant = grant({
      grantId: "20000000-0000-4000-8000-000000000002",
      tenantKeyId: currentTenantKeyId,
      generation: 2,
      identityId: targetIdentityId,
      deviceId: targetDeviceId,
      envelope: targetCurrentEnvelope,
      status: "active",
    });
    let delegated: ApproveGrantIntent | undefined;
    const result = await delegateHistoricalTenantKeys({
      tenantId,
      actorIdentityId,
      target: target.server,
      generations: [generation(retiredTenantKeyId, 1, "retired"), generation(currentTenantKeyId, 2, "active")],
      devices: [actor.server, target.server],
      ownGrants: [actorRetiredGrant],
      managedGrants: [actorRetiredGrant, targetCurrentGrant],
      localDevices: [actor.local],
      approve: async (intent) => { delegated = intent; },
    });
    assert.deepEqual(result, {
      targetDeviceId,
      complete: true,
      covered: 1,
      total: 1,
      generations: [{ tenantKeyId: retiredTenantKeyId, generation: 1, status: "delegated" }],
    });
    assert.ok(delegated);
    assert.equal(delegated.tenantKeyId, retiredTenantKeyId);
    assert.equal(delegated.generation, 1);
    assert.equal(delegated.envelope.aad.identityId, targetIdentityId);
    assert.equal(delegated.envelope.aad.deviceFingerprint, target.server.wrappingKeyFingerprint);

    const [oldAes, currentAes] = await Promise.all([
      importAes(retiredKey.keyBytes, ["encrypt", "decrypt"]),
      importAes(currentKey.keyBytes, ["encrypt", "decrypt"]),
    ]);
    const snapshotAad = { purpose: "cycle-member-display", schemaVersion: 1, tenantId, memberId: actorIdentityId };
    const currentOldAad = { purpose: "member-display", schemaVersion: 1, tenantId, memberId: actorIdentityId };
    const currentAad = { purpose: "member-display", schemaVersion: 1, tenantId, memberId: targetIdentityId };
    const [snapshot, currentContentStillOnOldKey, currentContent] = await Promise.all([
      encryptJson(oldAes, retiredTenantKeyId, snapshotAad, { displayName: "Frozen snapshot" }),
      encryptJson(oldAes, retiredTenantKeyId, currentOldAad, { displayName: "Unchanged current member" }),
      encryptJson(currentAes, currentTenantKeyId, currentAad, { displayName: "New member" }),
    ]);

    const [openedRetired, openedCurrent] = await Promise.all([
      openTenantKeyGrantEnvelope({
        envelope: delegated.envelope,
        recipient: targetPrivate,
        expected: {
          tenantId,
          tenantKeyId: retiredTenantKeyId,
          generation: 1,
          identityId: targetIdentityId,
          deviceId: targetDeviceId,
        },
      }),
      openTenantKeyGrantEnvelope({
        envelope: targetCurrentEnvelope,
        recipient: targetPrivate,
        expected: {
          tenantId,
          tenantKeyId: currentTenantKeyId,
          generation: 2,
          identityId: targetIdentityId,
          deviceId: targetDeviceId,
        },
      }),
    ]);
    try {
      const keyring = new TenantCryptoKeyring();
      const targetCurrent = await importAes(openedCurrent.keyBytes, ["decrypt"]);
      const targetRetired = await importAes(openedRetired.keyBytes, ["decrypt"]);
      assert.equal(targetCurrent.extractable, false);
      assert.equal(targetRetired.extractable, false);
      keyring.rememberCurrent(tenantId, currentTenantKeyId, targetCurrent);
      keyring.rememberHistorical(tenantId, retiredTenantKeyId, targetRetired);
      const resolver = { keyFor: (keyId: string, requestedTenantId: string) => keyring.keyFor(requestedTenantId, keyId) };
      assert.deepEqual(await openJsonEnvelope({ resolver, tenantId, envelope: snapshot.envelope, aad: snapshotAad }), { displayName: "Frozen snapshot" });
      assert.deepEqual(await openJsonEnvelope({ resolver, tenantId, envelope: currentContentStillOnOldKey.envelope, aad: currentOldAad }), { displayName: "Unchanged current member" });
      assert.deepEqual(await openJsonEnvelope({ resolver, tenantId, envelope: currentContent.envelope, aad: currentAad }), { displayName: "New member" });
    } finally {
      openedRetired.keyBytes.fill(0);
      openedCurrent.keyBytes.fill(0);
    }
  } finally {
    retiredKey.keyBytes.fill(0);
    currentKey.keyBytes.fill(0);
  }
});

test("reporta cobertura parcial por generación y nunca sustituye un grant histórico ausente", async () => {
  const actorPrivate = await generateTenantDeviceKeyPair({ tenantId, deviceId: actorDeviceId });
  const targetPrivate = await generateTenantDeviceKeyPair({ tenantId, deviceId: targetDeviceId });
  const [actor, target] = await Promise.all([
    devicePair(actorPrivate, actorIdentityId, actorDeviceId, "Authorized administrator"),
    devicePair(targetPrivate, targetIdentityId, targetDeviceId, "New browser"),
  ]);
  const key = generateTenantContentKey(retiredTenantKeyId);
  try {
    const envelope = await createTenantKeyGrantEnvelope({
      tenantId,
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      identityId: actorIdentityId,
      deviceId: actorDeviceId,
      tenantKey: key.keyBytes,
      recipient: await importCustodianPublicKey(actor.server.wrappingPublicKey),
    });
    const ownGrant = grant({
      grantId: "20000000-0000-4000-8000-000000000003",
      tenantKeyId: retiredTenantKeyId,
      generation: 1,
      identityId: actorIdentityId,
      deviceId: actorDeviceId,
      envelope,
      status: "retired",
    });
    const approvals: ApproveGrantIntent[] = [];
    const result = await delegateHistoricalTenantKeys({
      tenantId,
      actorIdentityId,
      target: target.server,
      generations: [
        generation(retiredTenantKeyId, 1, "retired"),
        generation("30000000-0000-4000-8000-000000000001", 2, "retired"),
        generation(currentTenantKeyId, 3, "active"),
      ],
      devices: [actor.server, target.server],
      ownGrants: [ownGrant],
      managedGrants: [ownGrant],
      localDevices: [actor.local],
      approve: async (intent) => { approvals.push(intent); },
    });
    assert.equal(result.complete, false);
    assert.equal(result.covered, 1);
    assert.equal(result.total, 2);
    assert.deepEqual(result.generations.map(({ generation: number, status }) => [number, status]), [
      [1, "delegated"],
      [2, "unavailable"],
    ]);
    assert.equal(result.generations[1]?.unavailableReason, "source-unavailable");
    assert.equal(approvals.length, 1);
    assert.equal(approvals[0]?.tenantKeyId, retiredTenantKeyId);

    const neverOpenedAfterRateLimit = grant({
      grantId: "20000000-0000-4000-8000-000000000004",
      tenantKeyId: secondRetiredTenantKeyId,
      generation: 2,
      identityId: actorIdentityId,
      deviceId: actorDeviceId,
      envelope,
      status: "retired",
    });
    let rejectedApprovals = 0;
    const rejected = await delegateHistoricalTenantKeys({
      tenantId,
      actorIdentityId,
      target: target.server,
      generations: [
        generation(retiredTenantKeyId, 1, "retired"),
        generation(secondRetiredTenantKeyId, 2, "retired"),
      ],
      devices: [actor.server, target.server],
      ownGrants: [ownGrant, neverOpenedAfterRateLimit],
      managedGrants: [ownGrant, neverOpenedAfterRateLimit],
      localDevices: [actor.local],
      approve: async () => {
        rejectedApprovals += 1;
        throw apiFailure(429, "RATE_LIMITED");
      },
    });
    assert.equal(rejectedApprovals, 1);
    assert.deepEqual(
      rejected.generations.map(({ unavailableReason }) => unavailableReason),
      ["approval-failed", "approval-failed"],
    );

    assert.equal(historicalApprovalFailureIsRetryable(apiFailure(429, "RATE_LIMITED")), true);
    assert.equal(historicalApprovalFailureIsRetryable(apiFailure(503, "SERVICE_UNAVAILABLE")), true);
    assert.equal(historicalApprovalFailureIsRetryable(new Error("network unavailable")), true);
    assert.equal(historicalApprovalFailureStopsBatch(apiFailure(429, "RATE_LIMITED")), true);
    assert.equal(historicalApprovalFailureStopsBatch(apiFailure(503, "SERVICE_UNAVAILABLE")), true);
    assert.equal(historicalApprovalFailureStopsBatch(new Error("network unavailable")), true);
    assert.equal(historicalApprovalFailureStopsBatch(apiFailure(409, "CHALLENGE_EXPIRED")), false);
    for (const fatal of [
      apiFailure(428, "KEY_LIFECYCLE_STEP_UP_REQUIRED"),
      apiFailure(403, "MFA_ASSURANCE_REQUIRED"),
      apiFailure(403, "AUTHORIZED_ADMIN_GRANT_REQUIRED"),
      apiFailure(409, "CURRENT_KEY_GRANT_REQUIRED"),
      apiFailure(409, "TENANT_KEY_PERMANENTLY_LOST"),
    ]) assert.equal(historicalApprovalFailureIsRetryable(fatal), false, fatal.code);

    const concurrentDuplicate = await delegateHistoricalTenantKeys({
      tenantId,
      actorIdentityId,
      target: target.server,
      generations: [generation(retiredTenantKeyId, 1, "retired")],
      devices: [actor.server, target.server],
      ownGrants: [ownGrant],
      managedGrants: [ownGrant],
      localDevices: [actor.local],
      approve: async () => { throw apiFailure(409, "DEVICE_GRANT_ALREADY_EXISTS"); },
    });
    assert.equal(concurrentDuplicate.complete, true);
    assert.equal(concurrentDuplicate.covered, 1);
    assert.equal(concurrentDuplicate.generations[0]?.status, "already-covered");

    let stepUpAttempts = 0;
    await assert.rejects(
      delegateHistoricalTenantKeys({
        tenantId,
        actorIdentityId,
        target: target.server,
        generations: [generation(retiredTenantKeyId, 1, "retired")],
        devices: [actor.server, target.server],
        ownGrants: [ownGrant],
        managedGrants: [ownGrant],
        localDevices: [actor.local],
        approve: async () => {
          stepUpAttempts += 1;
          throw apiFailure(428, "KEY_LIFECYCLE_STEP_UP_REQUIRED");
        },
      }),
      (error: unknown) => error instanceof Error
        && "code" in error
        && error.code === "KEY_LIFECYCLE_STEP_UP_REQUIRED",
    );
    assert.equal(stepUpAttempts, 1);
  } finally {
    key.keyBytes.fill(0);
  }
});

test("zeroiza bytes transitorios tanto en éxito como en excepción", async () => {
  const successful = new Uint8Array(32).fill(7);
  assert.equal(await withWipedKeyBytes(successful, async (bytes) => bytes[0]), 7);
  assert.deepEqual([...successful], new Array(32).fill(0));

  const failing = new Uint8Array(32).fill(9);
  await assert.rejects(
    withWipedKeyBytes(failing, async () => { throw new Error("simulated import failure"); }),
    /simulated import failure/u,
  );
  assert.deepEqual([...failing], new Array(32).fill(0));
});

test("descarta un source corrupto, usa el siguiente determinísticamente y muta una sola vez", async () => {
  const corruptDeviceId = "10000000-0000-4000-8000-000000000008";
  const validDeviceId = "10000000-0000-4000-8000-000000000009";
  const [corruptPrivate, validPrivate, targetPrivate] = await Promise.all([
    generateTenantDeviceKeyPair({ tenantId, deviceId: corruptDeviceId }),
    generateTenantDeviceKeyPair({ tenantId, deviceId: validDeviceId }),
    generateTenantDeviceKeyPair({ tenantId, deviceId: targetDeviceId }),
  ]);
  const [corruptSource, validSource, target] = await Promise.all([
    devicePair(corruptPrivate, actorIdentityId, corruptDeviceId, "Corrupt source"),
    devicePair(validPrivate, actorIdentityId, validDeviceId, "Valid source"),
    devicePair(targetPrivate, targetIdentityId, targetDeviceId, "New browser"),
  ]);
  const retiredKey = generateTenantContentKey(retiredTenantKeyId);
  try {
    const [corruptEnvelope, validEnvelope] = await Promise.all([
      createTenantKeyGrantEnvelope({
        tenantId,
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: actorIdentityId,
        deviceId: corruptDeviceId,
        tenantKey: retiredKey.keyBytes,
        recipient: await importCustodianPublicKey(corruptSource.server.wrappingPublicKey),
      }),
      createTenantKeyGrantEnvelope({
        tenantId,
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: actorIdentityId,
        deviceId: validDeviceId,
        tenantKey: retiredKey.keyBytes,
        recipient: await importCustodianPublicKey(validSource.server.wrappingPublicKey),
      }),
    ]);
    const corrupted = {
      ...corruptEnvelope,
      envelopeHash: `sha256:${"0".repeat(64)}` as const,
    } satisfies TenantKeyGrantEnvelope;
    const sources = [
      grant({
        grantId: "00000000-0000-4000-8000-000000000001",
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: actorIdentityId,
        deviceId: corruptDeviceId,
        envelope: corrupted,
        status: "retired",
      }),
      grant({
        grantId: "00000000-0000-4000-8000-000000000002",
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: actorIdentityId,
        deviceId: validDeviceId,
        envelope: validEnvelope,
        status: "retired",
      }),
    ];
    const approvals: ApproveGrantIntent[] = [];
    const result = await delegateHistoricalTenantKeys({
      tenantId,
      actorIdentityId,
      target: target.server,
      generations: [generation(retiredTenantKeyId, 1, "retired")],
      devices: [corruptSource.server, validSource.server, target.server],
      ownGrants: [...sources].reverse(),
      managedGrants: sources,
      localDevices: [corruptSource.local, validSource.local],
      approve: async (intent) => { approvals.push(intent); },
    });
    assert.equal(result.complete, true);
    assert.equal(approvals.length, 1);
    const delegated = approvals[0];
    assert.ok(delegated);
    const opened = await openTenantKeyGrantEnvelope({
      envelope: delegated.envelope,
      recipient: targetPrivate,
      expected: {
        tenantId,
        tenantKeyId: retiredTenantKeyId,
        generation: 1,
        identityId: targetIdentityId,
        deviceId: targetDeviceId,
      },
    });
    try {
      assert.deepEqual(Buffer.from(opened.keyBytes), Buffer.from(retiredKey.keyBytes));
    } finally {
      opened.keyBytes.fill(0);
    }
  } finally {
    retiredKey.keyBytes.fill(0);
  }
});

async function devicePair(
  privateKey: CustodianPrivateKey,
  identityId: string,
  deviceId: string,
  label: string,
): Promise<{ local: LocalTenantDevice; server: KeyLifecycleDevice }> {
  const wrappingPublicKey = await exportTenantDevicePublicKey(privateKey);
  const createdAt = "2026-09-12T12:00:00.000Z";
  return {
    local: {
      storageVersion: 1,
      tenantId,
      identityId,
      deviceId,
      label,
      recipientId: privateKey.recipientId,
      fingerprint: privateKey.fingerprint,
      publicKey: privateKey.publicKey,
      keyPair: privateKey.keyPair,
      createdAt,
    },
    server: {
      deviceId,
      identityId,
      label,
      wrappingPublicKey,
      wrappingKeyFingerprint: wrappingPublicKey.fingerprint,
      status: "active",
      version: 1,
      registeredAt: createdAt,
      activatedAt: createdAt,
      revokedAt: null,
    },
  };
}

function generation(
  tenantKeyId: string,
  number: number,
  status: KeyLifecycleGeneration["status"],
): KeyLifecycleGeneration {
  return {
    tenantKeyId,
    generation: number,
    status,
    recoveryKeyFingerprint: `sha256:${"a".repeat(64)}`,
    createdAt: "2026-09-12T12:00:00.000Z",
    retiredAt: status === "retired" ? "2026-09-12T13:00:00.000Z" : null,
    lostAt: status === "lost" ? "2026-09-12T13:00:00.000Z" : null,
    activeGrantCount: status === "active" ? 1 : 0,
  };
}

function grant(input: {
  grantId: string;
  tenantKeyId: string;
  generation: number;
  identityId: string;
  deviceId: string;
  envelope: TenantKeyGrantEnvelope;
  status: KeyLifecycleGrant["status"];
}): KeyLifecycleGrant {
  return {
    ...input,
    envelopeHash: input.envelope.envelopeHash,
    grantKind: "admin_approved",
    version: 1,
    grantedByIdentityId: actorIdentityId,
    createdAt: "2026-09-12T12:00:00.000Z",
    retiredAt: input.status === "retired" ? "2026-09-12T13:00:00.000Z" : null,
    revokedAt: input.status === "revoked" ? "2026-09-12T13:00:00.000Z" : null,
  };
}

function importAes(bytes: Uint8Array<ArrayBuffer>, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, usages);
}
