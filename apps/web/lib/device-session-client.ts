import { openDeviceSessionChallenge, type DeviceSessionEnrollmentContext } from "@nombramientos/e2ee";
import { apiRequest, ApiError, type AuthenticatedSession } from "./api.ts";
import type { LocalTenantDevice } from "./key-lifecycle-client.ts";
import {
  activateDeviceSigner, base64Url, createLocalDeviceSigner, DeviceSessionClientError,
  readLocalDeviceSigner, saveLocalDeviceSigner, setDeviceProofContext, signDeviceClaims,
  type DeviceSigningPublicJwk, type LocalDeviceSigner,
} from "./device-session-proof.ts";

export type DeviceSessionState = {
  binding: null | { sessionId: string; sourceSessionId: string | null; deviceId: string; identityId: string; signingFingerprint: string;
    publicJwk: DeviceSigningPublicJwk; boundAt: string; lastSeenAt: string; status: string; deviceStatus: "pending" | "active" | "revoked"; hasActiveGrant: boolean };
  enrollmentRequired: boolean;
  session: { sessionId: string; tenantId: string; identityId: string; sourceSessionId: string | null };
};
export const DEVICE_SESSION_READY_EVENT = "nombramientos:device-session-ready";
export const deviceSessionApi = {
  state: () => apiRequest<DeviceSessionState>("/v1/device-session"),
};

export async function loadDeviceSessionState(session: AuthenticatedSession): Promise<DeviceSessionState> {
  const state = await deviceSessionApi.state();
  if (state.session.tenantId !== session.tenant.id || state.session.identityId !== session.user.id) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
  if (state.binding && (state.binding.sessionId !== state.session.sessionId || state.binding.sourceSessionId !== state.session.sourceSessionId
    || state.binding.identityId !== state.session.identityId)) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
  setDeviceProofContext(state.session);
  return state;
}

/** Routine SSO resume proves the already-persisted signer; it never creates a grant. */
export async function resumeRecognizedDevice(session: AuthenticatedSession, devices: LocalTenantDevice[]): Promise<DeviceSessionState | undefined> {
  const state = await loadDeviceSessionState(session);
  const candidates = state.binding ? devices.filter((device) => device.deviceId === state.binding?.deviceId) : devices;
  for (const device of candidates) {
    const signer = await readLocalDeviceSigner(device);
    if (!signer) continue;
    if (state.binding) {
      if (state.binding.signingFingerprint !== signer.fingerprint || state.binding.status !== "active") throw new DeviceSessionClientError("DEVICE_SESSION_LOCAL_KEY_INVALID");
      activateDeviceSigner(state.session, signer);
      return state;
    }
    try { return await enrollDeviceSession(session, device, false); }
    catch (error) {
      // A retired browser record must not hide a still-authorized local device.
      if (!(error instanceof ApiError) || !["DEVICE_REVOKED", "DEVICE_NOT_FOUND", "DEVICE_SESSION_DEVICE_UNAVAILABLE"].includes(error.code)) throw error;
    }
  }
  return undefined;
}

/** Explicit first upgrade/enrollment. Existing immutable signer is never replaced. */
export async function enrollDeviceSession(session: AuthenticatedSession, device: LocalTenantDevice, allowCreate: boolean): Promise<DeviceSessionState> {
  const state = await loadDeviceSessionState(session);
  if (device.tenantId !== state.session.tenantId || device.identityId !== state.session.identityId
    || (state.binding && state.binding.deviceId !== device.deviceId)) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
  let signer = await readLocalDeviceSigner(device);
  if (!signer) {
    if (!allowCreate || state.binding) throw new DeviceSessionClientError("DEVICE_SESSION_LOCAL_KEY_REQUIRED");
    signer = await createLocalDeviceSigner(device);
    // Persist before the server commits enrollment, so a lost response does not
    // create an inaccessible immutable registration. No private bytes are exported.
    signer = await saveLocalDeviceSigner(signer);
  }
  const challenge = await apiRequest<{ challengeId: string; context: DeviceSessionEnrollmentContext; enc: string; ciphertext: string; expiresAt: string; issuedAt: number }>("/v1/device-session/enrollment/challenge", {
    method: "POST", body: JSON.stringify({ deviceId: device.deviceId, publicJwk: signer.publicJwk }),
  });
  const expected: DeviceSessionEnrollmentContext = { purpose: "nombramientos.device-session-enrollment", version: 1,
    tenantId: state.session.tenantId, identityId: state.session.identityId, sessionId: state.session.sessionId,
    sourceSessionId: state.session.sourceSessionId, deviceId: device.deviceId, signingFingerprint: signer.fingerprint,
    challengeId: challenge.challengeId, expiresAt: challenge.expiresAt };
  if (!Number.isSafeInteger(challenge.issuedAt) || !Number.isFinite(Date.parse(challenge.expiresAt))
    || Date.parse(challenge.expiresAt) <= challenge.issuedAt * 1_000
    || Date.parse(challenge.expiresAt) > challenge.issuedAt * 1_000 + 121_000) throw new DeviceSessionClientError("DEVICE_SESSION_CHALLENGE_INVALID");
  const secret = await openDeviceSessionChallenge({ recipient: {
    recipientId: device.recipientId, fingerprint: device.fingerprint, publicKey: device.publicKey, keyPair: device.keyPair,
  }, challenge, expected, nowMs: challenge.issuedAt * 1_000 });
  try {
    const proof = await signDeviceClaims(signer, { purpose: expected.purpose, challengeId: challenge.challengeId,
      context: expected, iat: challenge.issuedAt });
    await apiRequest("/v1/device-session/enrollment/complete", { method: "POST",
      body: JSON.stringify({ challengeId: challenge.challengeId, secret: base64Url(secret), proof }) });
  } finally { secret.fill(0); }
  const bound = await loadDeviceSessionState(session);
  assertBoundSigner(bound, signer);
  activateDeviceSigner(bound.session, signer);
  if (typeof window !== "undefined") window.dispatchEvent(new Event(DEVICE_SESSION_READY_EVENT));
  return bound;
}

function assertBoundSigner(state: DeviceSessionState, signer: LocalDeviceSigner): void {
  if (!state.binding || state.binding.deviceId !== signer.deviceId || state.binding.signingFingerprint !== signer.fingerprint
    || state.binding.status !== "active" || state.binding.identityId !== signer.identityId) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
}
