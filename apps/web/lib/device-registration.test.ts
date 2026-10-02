import assert from "node:assert/strict";
import test from "node:test";
import { ensureDeviceRegistration } from "./device-registration.ts";
import type { KeyLifecycleDevice, KeyLifecycleState, LocalTenantDevice } from "./key-lifecycle-client.ts";

const local: Pick<LocalTenantDevice, "deviceId" | "identityId" | "fingerprint"> = { identityId: "identity-a", deviceId: "device-a", fingerprint: "sha256:aa" };
const registered = { deviceId: local.deviceId, identityId: local.identityId, wrappingKeyFingerprint: local.fingerprint, status: "pending" } as KeyLifecycleDevice;
const state = (devices: KeyLifecycleDevice[]) => ({ devices } as KeyLifecycleState);

test("an existing same-scope wrapping device is reused without registration or key replacement", async () => {
  let calls = 0;
  assert.equal(await ensureDeviceRegistration(local, { state: async () => state([registered]), register: async () => { calls++; } }), registered);
  assert.equal(calls, 0);
});
test("uncertain registration reconciles only the exact saved identity and fingerprint", async () => {
  let reads = 0, calls = 0;
  assert.equal(await ensureDeviceRegistration(local, { state: async () => state(reads++ ? [registered] : []), register: async () => { calls++; throw new Error("ACK_LOST"); } }), registered);
  assert.equal(calls, 1);
  assert.equal(reads, 2);
});
test("no authoritative confirmation remains a failure and never blindly retries", async () => {
  const failure = new Error("ACK_LOST"); let calls = 0;
  await assert.rejects(ensureDeviceRegistration(local, { state: async () => state([]), register: async () => { calls++; throw failure; } }), (error) => error === failure);
  assert.equal(calls, 1);
  await assert.rejects(ensureDeviceRegistration(local, { state: async () => state([]), register: async () => undefined }), /DEVICE_SESSION_REGISTRATION_UNCONFIRMED/u);
});
test("conflicting ownership, fingerprint and revoked records cannot be adopted", async () => {
  for (const change of [{ identityId: "identity-b" }, { wrappingKeyFingerprint: "sha256:bb" }, { status: "revoked" }]) {
    await assert.rejects(ensureDeviceRegistration(local, { state: async () => state([{ ...registered, ...change } as KeyLifecycleDevice]), register: async () => assert.fail("no mutation") }), /DEVICE_SESSION_LOCAL_KEY_INVALID/u);
  }
});
