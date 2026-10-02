import {
  generateTenantDeviceKeyPair,
  type CustodianPrivateKey,
  type ExportedCustodianPublicKey,
  type ExportedCustodianSigningPublicKey,
  type TenantKeyGrantEnvelope,
  type TenantKeyRecoveryAuthorization,
} from "@nombramientos/e2ee";

import { apiRequest, ApiError, idempotencyKey } from "./api.ts";

export type KeyLifecycleOperation =
  | "device.register"
  | "grant.initialize"
  | "grant.approve"
  | "grant.revoke"
  | "key.rotate"
  | "key.recover"
  | "key.declare_lost";

export type KeyLifecycleDevice = {
  deviceId: string;
  identityId: string;
  label: string;
  wrappingPublicKey: ExportedCustodianPublicKey;
  wrappingKeyFingerprint: `sha256:${string}`;
  status: "pending" | "active" | "revoked";
  version: number;
  registeredAt: string;
  activatedAt: string | null;
  revokedAt: string | null;
};

export type KeyLifecycleGeneration = {
  tenantKeyId: string;
  generation: number;
  status: "active" | "retired" | "lost";
  recoveryKeyFingerprint: `sha256:${string}`;
  createdAt: string;
  retiredAt: string | null;
  lostAt: string | null;
  activeGrantCount: number;
};

export type KeyLifecycleGrant = {
  grantId: string;
  tenantKeyId: string;
  generation: number;
  identityId: string;
  deviceId: string;
  envelope: TenantKeyGrantEnvelope;
  envelopeHash: `sha256:${string}`;
  grantKind: "initial" | "admin_approved" | "rotation" | "recovery";
  status: "active" | "retired" | "revoked";
  version: number;
  grantedByIdentityId: string;
  createdAt: string;
  retiredAt: string | null;
  revokedAt: string | null;
};

export type KeyLifecycleState = {
  tenantKind: "demo" | "real";
  currentGeneration: KeyLifecycleGeneration | null;
  generations: KeyLifecycleGeneration[];
  devices: KeyLifecycleDevice[];
  ownGrants: KeyLifecycleGrant[];
  managedGrants?: KeyLifecycleGrant[];
};

export type RegisterDeviceIntent = {
  deviceId: string;
  label: string;
  wrappingPublicKey: ExportedCustodianPublicKey;
};

export type InitializeGrantIntent = {
  deviceId: string;
  tenantKeyId: string;
  envelope: TenantKeyGrantEnvelope;
  recoveryPublicKey: ExportedCustodianSigningPublicKey;
};

export type ApproveGrantIntent = {
  targetIdentityId: string;
  targetDeviceId: string;
  tenantKeyId: string;
  generation: number;
  envelope: TenantKeyGrantEnvelope;
};

export type RevokeGrantIntent = {
  grantId: string;
  expectedVersion: number;
  reasonCode: string;
  confirmLastActiveGrant: boolean;
};

export type RotateKeyIntent = {
  expectedTenantKeyId: string;
  expectedGeneration: number;
  newTenantKeyId: string;
  reasonCode: string;
  recoveryPublicKey: ExportedCustodianSigningPublicKey;
  grants: Array<{
    targetIdentityId: string;
    targetDeviceId: string;
    envelope: TenantKeyGrantEnvelope;
  }>;
};

export type RecoverKeyIntent = {
  tenantKeyId: string;
  targetIdentityId: string;
  targetDeviceId: string;
  envelope: TenantKeyGrantEnvelope;
  authorization: TenantKeyRecoveryAuthorization;
};

export type DeclareKeyLostIntent = {
  tenantKeyId: string;
  confirmation: "PERMANENTLY_LOSE_TENANT_KEY";
  reasonCode: string;
};

export type KeyLifecycleIntentByOperation = {
  "device.register": RegisterDeviceIntent;
  "grant.initialize": InitializeGrantIntent;
  "grant.approve": ApproveGrantIntent;
  "grant.revoke": RevokeGrantIntent;
  "key.rotate": RotateKeyIntent;
  "key.recover": RecoverKeyIntent;
  "key.declare_lost": DeclareKeyLostIntent;
};

export type LocalTenantDevice = {
  readonly storageVersion: 1;
  readonly tenantId: string;
  readonly identityId: string;
  readonly deviceId: string;
  readonly label: string;
  readonly recipientId: string;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKey: CryptoKey;
  readonly keyPair: CryptoKeyPair;
  readonly createdAt: string;
};

const MUTATION_PATH: Record<KeyLifecycleOperation, string> = {
  "device.register": "/v1/key-lifecycle/devices",
  "grant.initialize": "/v1/key-lifecycle/grants/initialize",
  "grant.approve": "/v1/key-lifecycle/grants",
  "grant.revoke": "/v1/key-lifecycle/grants/revoke",
  "key.rotate": "/v1/key-lifecycle/rotations",
  "key.recover": "/v1/key-lifecycle/recoveries",
  "key.declare_lost": "/v1/key-lifecycle/loss-declarations",
};

const DEVICE_DATABASE = "nombramientos-e2ee-devices";
const DEVICE_DATABASE_VERSION = 1;
const DEVICE_STORE = "devices";

export const keyLifecycleApi = {
  state: () => apiRequest<KeyLifecycleState>("/v1/key-lifecycle"),
  mutate: async <Operation extends KeyLifecycleOperation>(
    operation: Operation,
    request: KeyLifecycleIntentByOperation[Operation],
  ): Promise<unknown> => {
    const challengeIdempotencyKey = idempotencyKey();
    const challenge = await retryIdempotent(() => apiRequest<{ challengeId: string; expiresAt: string }>("/v1/key-lifecycle/challenges", {
      method: "POST", body: JSON.stringify({ operation, request }), idempotent: true,
      idempotencyKey: challengeIdempotencyKey,
    }));
    const mutationIdempotencyKey = idempotencyKey();
    return retryIdempotent(() => apiRequest(MUTATION_PATH[operation], {
      method: "POST", body: JSON.stringify({ ...request, challengeId: challenge.challengeId }), idempotent: true,
      idempotencyKey: mutationIdempotencyKey,
    }));
  },
};

export async function createLocalTenantDevice(input: {
  tenantId: string;
  identityId: string;
  label: string;
  deviceId?: string;
}): Promise<{ device: LocalTenantDevice; privateKey: CustodianPrivateKey }> {
  const deviceId = input.deviceId ?? crypto.randomUUID();
  const privateKey = await generateTenantDeviceKeyPair({ tenantId: input.tenantId, deviceId });
  const device: LocalTenantDevice = Object.freeze({
    storageVersion: 1,
    tenantId: input.tenantId,
    identityId: input.identityId,
    deviceId,
    label: input.label.trim(),
    recipientId: privateKey.recipientId,
    fingerprint: privateKey.fingerprint,
    publicKey: privateKey.publicKey,
    keyPair: privateKey.keyPair,
    createdAt: new Date().toISOString(),
  });
  return { device, privateKey };
}

export function localDevicePrivateKey(device: LocalTenantDevice): CustodianPrivateKey {
  return Object.freeze({
    recipientId: device.recipientId,
    fingerprint: device.fingerprint,
    publicKey: device.publicKey,
    keyPair: device.keyPair,
  });
}

export async function saveLocalTenantDevice(device: LocalTenantDevice): Promise<void> {
  const database = await openDeviceDatabase();
  try {
    await transactionDone(database, "readwrite", (store) => store.put(device, storageKey(device)));
  } finally {
    database.close();
  }
}

export async function listLocalTenantDevices(tenantId: string, identityId: string): Promise<LocalTenantDevice[]> {
  const database = await openDeviceDatabase();
  try {
    const records = await requestResult<unknown[]>(database.transaction(DEVICE_STORE, "readonly").objectStore(DEVICE_STORE).getAll());
    return records.filter(isStoredDevice).filter((device) => device.tenantId === tenantId && device.identityId === identityId);
  } finally {
    database.close();
  }
}

export async function removeLocalTenantDevice(device: LocalTenantDevice): Promise<void> {
  const database = await openDeviceDatabase();
  try {
    await transactionDone(database, "readwrite", (store) => store.delete(storageKey(device)));
  } finally {
    database.close();
  }
}

export function fingerprintConfirmation(fingerprint: string): string {
  return fingerprint.replace(/^sha256:/u, "").slice(-8).toUpperCase();
}

export function formatFingerprint(fingerprint: string): string {
  const digest = fingerprint.replace(/^sha256:/u, "").toUpperCase();
  return digest.match(/.{1,4}/gu)?.join(" ") ?? digest;
}

function storageKey(device: Pick<LocalTenantDevice, "tenantId" | "identityId" | "deviceId">): string {
  return `${device.tenantId}:${device.identityId}:${device.deviceId}`;
}

function openDeviceDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") return Promise.reject(new Error("INDEXED_DB_UNAVAILABLE"));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DEVICE_DATABASE, DEVICE_DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(DEVICE_STORE)) request.result.createObjectStore(DEVICE_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("INDEXED_DB_OPEN_FAILED"));
    request.onblocked = () => reject(new Error("INDEXED_DB_BLOCKED"));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("INDEXED_DB_REQUEST_FAILED"));
  });
}

function transactionDone(
  database: IDBDatabase,
  mode: IDBTransactionMode,
  mutate: (store: IDBObjectStore) => IDBRequest,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(DEVICE_STORE, mode);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("INDEXED_DB_TRANSACTION_FAILED"));
    transaction.onabort = () => reject(transaction.error ?? new Error("INDEXED_DB_TRANSACTION_ABORTED"));
    mutate(transaction.objectStore(DEVICE_STORE));
  });
}

function isStoredDevice(value: unknown): value is LocalTenantDevice {
  if (!value || typeof value !== "object") return false;
  const record = value as Partial<LocalTenantDevice>;
  return record.storageVersion === 1
    && typeof record.tenantId === "string"
    && typeof record.identityId === "string"
    && typeof record.deviceId === "string"
    && typeof record.label === "string"
    && typeof record.recipientId === "string"
    && typeof record.fingerprint === "string"
    && record.publicKey instanceof CryptoKey
    && record.keyPair?.privateKey instanceof CryptoKey
    && record.keyPair?.publicKey instanceof CryptoKey;
}

async function retryIdempotent<T>(request: () => Promise<T>): Promise<T> {
  try {
    return await request();
  } catch (error) {
    if (error instanceof ApiError && (error.status < 500 || error.code.endsWith("_UNCERTAIN"))) throw error;
    return request();
  }
}
