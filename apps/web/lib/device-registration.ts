import type { KeyLifecycleDevice, KeyLifecycleState, LocalTenantDevice } from "./key-lifecycle-client.ts";
import { DeviceSessionClientError } from "./device-session-proof.ts";

/** A missing acknowledgement is not permission to generate a replacement key.
 * Reconcile the same saved device against authoritative tenant-scoped metadata. */
type RegisteredLocalDevice = Pick<LocalTenantDevice, "deviceId" | "identityId" | "fingerprint">;
export async function ensureDeviceRegistration(device: RegisteredLocalDevice, operations: {
  state: () => Promise<KeyLifecycleState>;
  register: () => Promise<unknown>;
}): Promise<KeyLifecycleDevice> {
  const existing = matchingDevice(await operations.state(), device);
  if (existing) return existing;
  let registrationError: unknown;
  try { await operations.register(); }
  catch (error) { registrationError = error; }
  try {
    const confirmed = matchingDevice(await operations.state(), device);
    if (confirmed) return confirmed;
  } catch (error) { throw registrationError ?? error; }
  throw registrationError ?? new DeviceSessionClientError("DEVICE_SESSION_REGISTRATION_UNCONFIRMED");
}

function matchingDevice(state: KeyLifecycleState, local: RegisteredLocalDevice): KeyLifecycleDevice | undefined {
  const registered = state.devices.find((device) => device.deviceId === local.deviceId);
  if (!registered) return undefined;
  if (registered.identityId !== local.identityId || registered.wrappingKeyFingerprint !== local.fingerprint
    || registered.status === "revoked") throw new DeviceSessionClientError("DEVICE_SESSION_LOCAL_KEY_INVALID");
  return registered;
}
