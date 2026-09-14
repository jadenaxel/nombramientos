import {
  createTenantKeyGrantEnvelope,
  importCustodianPublicKey,
  openTenantKeyGrantEnvelope,
  type CustodianPrivateKey,
  type TenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";

import type {
  ApproveGrantIntent,
  KeyLifecycleDevice,
  KeyLifecycleGeneration,
  KeyLifecycleGrant,
  LocalTenantDevice,
} from "./key-lifecycle-client.ts";

export type HistoricalDelegationGenerationResult = {
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly status: "already-covered" | "delegated" | "unavailable";
  readonly unavailableReason?: "source-unavailable" | "approval-failed";
};

export type HistoricalDelegationResult = {
  readonly targetDeviceId: string;
  readonly complete: boolean;
  readonly covered: number;
  readonly total: number;
  readonly generations: readonly HistoricalDelegationGenerationResult[];
};

const RETRYABLE_APPROVAL_CONFLICTS = new Set([
  "CHALLENGE_EXPIRED",
  "CHALLENGE_ALREADY_USED",
  "CHALLENGE_NOT_PENDING",
  "DEVICE_GRANT_ALREADY_EXISTS",
  "VERSION_CONFLICT",
  "KEY_STATE_CHANGED",
]);

export function historicalApprovalFailureIsRetryable(error: unknown): boolean {
  const failure = approvalFailure(error);
  if (!failure) return true;
  const { status } = failure;
  if (status === 408 || status === 429 || status >= 500) return true;
  return status === 409 && RETRYABLE_APPROVAL_CONFLICTS.has(failure.code);
}

export function historicalApprovalFailureStopsBatch(error: unknown): boolean {
  const failure = approvalFailure(error);
  if (!failure) return true;
  return failure.status === 408 || failure.status === 429 || failure.status >= 500;
}

function approvalFailure(error: unknown): { readonly status: number; readonly code: string } | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const failure = error as { readonly status?: unknown; readonly code?: unknown };
  if (!Number.isInteger(failure.status) || typeof failure.code !== "string") return undefined;
  return { status: failure.status as number, code: failure.code };
}

export async function withWipedKeyBytes<T>(
  keyBytes: Uint8Array<ArrayBuffer>,
  work: (transientKeyBytes: Uint8Array<ArrayBuffer>) => Promise<T>,
): Promise<T> {
  try {
    return await work(keyBytes);
  } finally {
    keyBytes.fill(0);
  }
}

/**
 * Rewraps retired tenant keys directly between browser-held device keys.
 * Plain key bytes exist only for the open/seal interval and are wiped before
 * the challenge-bound API call. Nothing is added to or exported from the vault.
 */
export async function delegateHistoricalTenantKeys(input: {
  readonly tenantId: string;
  readonly actorIdentityId: string;
  readonly target: KeyLifecycleDevice;
  readonly generations: readonly KeyLifecycleGeneration[];
  readonly devices: readonly KeyLifecycleDevice[];
  readonly ownGrants: readonly KeyLifecycleGrant[];
  readonly managedGrants: readonly KeyLifecycleGrant[];
  readonly localDevices: readonly LocalTenantDevice[];
  readonly approve: (intent: ApproveGrantIntent) => Promise<unknown>;
}): Promise<HistoricalDelegationResult> {
  const retiredGenerations = input.generations
    .filter((generation) => generation.status === "retired")
    .sort((left, right) => left.generation - right.generation);
  const results: HistoricalDelegationGenerationResult[] = [];
  let targetRecipient: Awaited<ReturnType<typeof importCustodianPublicKey>> | undefined;
  let approvalChannelUnavailable = false;

  for (const generation of retiredGenerations) {
    const existing = input.managedGrants.some((grant) =>
      grant.identityId === input.target.identityId
      && grant.deviceId === input.target.deviceId
      && grant.tenantKeyId === generation.tenantKeyId
      && grant.generation === generation.generation
      && grant.status === "retired");
    if (existing) {
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "already-covered",
      });
      continue;
    }

    const sources = input.ownGrants.flatMap((grant) => {
      if (
        grant.identityId !== input.actorIdentityId
        || grant.tenantKeyId !== generation.tenantKeyId
        || grant.generation !== generation.generation
        || grant.status !== "retired"
      ) return [];
      const registeredDevice = input.devices.find((device) =>
        device.deviceId === grant.deviceId
        && device.identityId === input.actorIdentityId
        && device.status === "active");
      const localDevice = input.localDevices.find((device) =>
        device.tenantId === input.tenantId
        && device.identityId === input.actorIdentityId
        && device.deviceId === grant.deviceId);
      return registeredDevice && localDevice ? [{ grant, localDevice }] : [];
    }).sort((left, right) => left.grant.grantId.localeCompare(right.grant.grantId));

    if (sources.length === 0) {
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "unavailable",
        unavailableReason: "source-unavailable",
      });
      continue;
    }

    if (approvalChannelUnavailable) {
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "unavailable",
        unavailableReason: "approval-failed",
      });
      continue;
    }

    let envelope: TenantKeyGrantEnvelope | undefined;
    for (const source of sources) {
      try {
        const opened = await openTenantKeyGrantEnvelope({
          envelope: source.grant.envelope,
          recipient: localPrivateKey(source.localDevice),
          expected: {
            tenantId: input.tenantId,
            tenantKeyId: generation.tenantKeyId,
            generation: generation.generation,
            identityId: input.actorIdentityId,
            deviceId: source.localDevice.deviceId,
          },
        });
        envelope = await withWipedKeyBytes(opened.keyBytes, async (tenantKey) => {
          targetRecipient ??= await importCustodianPublicKey(input.target.wrappingPublicKey);
          return createTenantKeyGrantEnvelope({
            tenantId: input.tenantId,
            tenantKeyId: generation.tenantKeyId,
            generation: generation.generation,
            identityId: input.target.identityId,
            deviceId: input.target.deviceId,
            tenantKey,
            recipient: targetRecipient,
          });
        });
        break;
      } catch {
        // Another authorized local device may still hold an intact grant for
        // the same generation. No mutation is attempted until resealing works.
      }
    }
    if (!envelope) {
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "unavailable",
        unavailableReason: "source-unavailable",
      });
      continue;
    }

    try {
      await input.approve({
        targetIdentityId: input.target.identityId,
        targetDeviceId: input.target.deviceId,
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        envelope,
      });
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "delegated",
      });
    } catch (error) {
      const failure = approvalFailure(error);
      if (failure?.status === 409 && failure.code === "DEVICE_GRANT_ALREADY_EXISTS") {
        results.push({
          tenantKeyId: generation.tenantKeyId,
          generation: generation.generation,
          status: "already-covered",
        });
        continue;
      }
      // Authentication, MFA/step-up, authorization and permanent state errors
      // require a global user action. Re-throw them so the view can expose its
      // reauthentication CTA instead of mislabelling them as partial coverage.
      if (!historicalApprovalFailureIsRetryable(error)) throw error;
      approvalChannelUnavailable ||= historicalApprovalFailureStopsBatch(error);
      results.push({
        tenantKeyId: generation.tenantKeyId,
        generation: generation.generation,
        status: "unavailable",
        unavailableReason: "approval-failed",
      });
    }
  }

  const covered = results.filter(({ status }) => status !== "unavailable").length;
  return {
    targetDeviceId: input.target.deviceId,
    complete: covered === retiredGenerations.length,
    covered,
    total: retiredGenerations.length,
    generations: results,
  };
}

function localPrivateKey(device: LocalTenantDevice): CustodianPrivateKey {
  return Object.freeze({
    recipientId: device.recipientId,
    fingerprint: device.fingerprint,
    publicKey: device.publicKey,
    keyPair: device.keyPair,
  });
}
