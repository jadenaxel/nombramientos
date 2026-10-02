/** Application proof profile: ES256 compact JWS with server-issued, single-use claims.
 * This is not an OAuth access token and does not change custody or account roles. */
export type DeviceSigningPublicJwk = Readonly<{ kty: "EC"; crv: "P-256"; x: string; y: string }>;
export type LocalDeviceSigner = Readonly<{
  storageVersion: 1;
  tenantId: string;
  identityId: string;
  deviceId: string;
  publicJwk: DeviceSigningPublicJwk;
  fingerprint: `sha256:${string}`;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  createdAt: string;
}>;
export type DeviceProofContext = Readonly<{ sessionId: string; tenantId: string; identityId: string; sourceSessionId?: string | null }>;
export type DeviceRequestClaims = Readonly<{
  purpose: "nombramientos.device-session-request";
  version: 1;
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  nonce: string;
  sessionId: string;
  sourceSessionId: string | null;
  tenantId: string;
  identityId: string;
  deviceId: string;
  signingFingerprint: string;
  path: string;
  bodyHash: string;
  idempotencyKey: string;
}>;

export class DeviceSessionClientError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; this.name = "DeviceSessionClientError"; }
}

const DATABASE = "nombramientos-device-signers";
const STORE = "signers";
let active: { context: DeviceProofContext; signer?: LocalDeviceSigner } | undefined;

export function setDeviceProofContext(context?: DeviceProofContext): void {
  if (!context) { active = undefined; return; }
  if (active?.context.sessionId === context.sessionId
    && active.context.tenantId === context.tenantId && active.context.identityId === context.identityId) {
    if (context.sourceSessionId !== undefined) active = (active.context.sourceSessionId ?? null) === context.sourceSessionId
      ? { ...active, context } : { context };
    return;
  }
  active = { context };
}
export function currentDeviceProofContext(): DeviceProofContext | undefined { return active?.context; }
export function currentDeviceSigner(): LocalDeviceSigner | undefined { return active?.signer; }
export function activateDeviceSigner(context: DeviceProofContext, signer: LocalDeviceSigner): void {
  if (context.tenantId !== signer.tenantId || context.identityId !== signer.identityId) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
  active = { context, signer };
}
export function clearDeviceSigner(): void { if (active) active = { context: active.context }; }

/** Keep the exact prepared transfer headers, but never reuse a one-use proof. */
export function deviceRequestRetryHeaders(prepared: Headers): Headers {
  const headers = new Headers(prepared);
  headers.delete("x-device-proof");
  return headers;
}

export function deviceRequestRequiresProof(path: string, method: string): boolean {
  if (!path.startsWith("/v1/")) return false;
  const pathname = path.split("?", 1)[0];
  if (pathname?.startsWith("/v1/platform/")) return false;
  if (pathname === "/v1/session" && method === "GET") return false;
  if (pathname === "/v1/auth/logout" && method === "POST") return false;
  if (method === "GET" && pathname === "/v1/device-session") return false;
  if (method === "POST" && ["/v1/device-session/enrollment/challenge", "/v1/device-session/enrollment/complete", "/v1/device-session/proofs"].includes(pathname ?? "")) return false;
  if (pathname === "/v1/integrations/gestionchurch/session" && method === "POST") return false;
  if (pathname === "/v1/key-lifecycle" && method === "GET") return false;
  return !(method === "POST" && ["/v1/key-lifecycle/challenges", "/v1/key-lifecycle/devices"].includes(pathname ?? ""));
}

export async function hashDeviceRequestBody(body: BodyInit | null | undefined): Promise<`sha256:${string}`> {
  // The caller supplies exact transfer bytes (including generated multipart boundaries).
  const bytes = body == null ? new Uint8Array() : typeof body === "string" ? new TextEncoder().encode(body)
    : body instanceof ArrayBuffer ? new Uint8Array(body)
      : ArrayBuffer.isView(body) ? new Uint8Array(body.buffer, body.byteOffset, body.byteLength)
        : body instanceof Blob ? new Uint8Array(await body.arrayBuffer())
          : body instanceof URLSearchParams ? new TextEncoder().encode(body.toString())
            : undefined;
  if (!bytes) throw new DeviceSessionClientError("DEVICE_SESSION_BODY_UNSUPPORTED");
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes));
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function validateDeviceRequestClaims(input: {
  claims: DeviceRequestClaims; publicJwk: DeviceSigningPublicJwk; signer: LocalDeviceSigner;
  context: DeviceProofContext; method: string; path: string; url: string; bodyHash: string; idempotencyKey: string;
  issuedAt: number;
}): void {
  const { claims, signer, context } = input;
  if (claims.purpose !== "nombramientos.device-session-request" || claims.version !== 1
    || claims.sessionId !== context.sessionId || claims.tenantId !== context.tenantId || claims.identityId !== context.identityId
    || claims.sourceSessionId !== (context.sourceSessionId ?? null)
    || claims.deviceId !== signer.deviceId || claims.signingFingerprint !== signer.fingerprint
    || claims.htm !== input.method || claims.path !== input.path || claims.htu !== input.url
    || claims.bodyHash !== input.bodyHash || claims.idempotencyKey !== input.idempotencyKey
    || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(input.issuedAt) || claims.iat !== input.issuedAt
    || typeof claims.jti !== "string" || claims.jti.length < 16
    || typeof claims.nonce !== "string" || claims.nonce.length < 32
    || input.publicJwk.kty !== signer.publicJwk.kty || input.publicJwk.crv !== signer.publicJwk.crv
    || input.publicJwk.x !== signer.publicJwk.x || input.publicJwk.y !== signer.publicJwk.y) throw new DeviceSessionClientError("DEVICE_SESSION_CONTEXT_MISMATCH");
}

export async function signDeviceClaims(signer: LocalDeviceSigner, claims: Readonly<Record<string, unknown>>): Promise<string> {
  const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "dpop+jwt", jwk: signer.publicJwk })));
  const payload = base64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const bytes = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, new TextEncoder().encode(`${header}.${payload}`));
  if (bytes.byteLength !== 64) throw new DeviceSessionClientError("DEVICE_SESSION_SIGNATURE_INVALID");
  return `${header}.${payload}.${base64Url(new Uint8Array(bytes))}`;
}

export async function createLocalDeviceSigner(input: Pick<LocalDeviceSigner, "tenantId" | "identityId" | "deviceId">): Promise<LocalDeviceSigner> {
  if (!crypto?.subtle) throw new DeviceSessionClientError("DEVICE_SESSION_CRYPTO_UNAVAILABLE");
  // A separate signing key; never reuse the HPKE wrapping or ballot-custody key.
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (!exported.x || !exported.y) throw new DeviceSessionClientError("DEVICE_SESSION_SIGNATURE_INVALID");
  const publicJwk: DeviceSigningPublicJwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
  // RFC 7638 EC JWK thumbprint: lexicographically sorted required members.
  const fingerprint = await hashDeviceRequestBody(JSON.stringify({ crv: "P-256", kty: "EC", x: exported.x, y: exported.y }));
  return Object.freeze({ storageVersion: 1, tenantId: input.tenantId, identityId: input.identityId, deviceId: input.deviceId,
    publicJwk, fingerprint, privateKey: pair.privateKey,
    publicKey: pair.publicKey, createdAt: new Date().toISOString() });
}

export async function saveLocalDeviceSigner(signer: LocalDeviceSigner): Promise<LocalDeviceSigner> {
  const database = await openDatabase();
  try { return await new Promise<LocalDeviceSigner>((resolve, reject) => {
    const transaction = database.transaction(STORE, "readwrite");
    let selected = signer;
    transaction.oncomplete = () => resolve(selected);
    transaction.onerror = transaction.onabort = () => reject(new DeviceSessionClientError("DEVICE_SESSION_STORAGE_UNAVAILABLE"));
    const store = transaction.objectStore(STORE);
    const existing = store.get(storageKey(signer));
    existing.onsuccess = () => {
      if (existing.result) {
        try { assertStoredSigner(existing.result, signer); selected = existing.result as LocalDeviceSigner; }
        catch { transaction.abort(); }
      } else store.add(signer, storageKey(signer));
    };
  }); } finally { database.close(); }
}
export async function readLocalDeviceSigner(input: Pick<LocalDeviceSigner, "tenantId" | "identityId" | "deviceId">): Promise<LocalDeviceSigner | undefined> {
  const database = await openDatabase();
  try { return await new Promise((resolve, reject) => {
    const request = database.transaction(STORE, "readonly").objectStore(STORE).get(storageKey(input));
    request.onerror = () => reject(new DeviceSessionClientError("DEVICE_SESSION_STORAGE_UNAVAILABLE"));
    request.onsuccess = () => {
      const record = request.result as LocalDeviceSigner | undefined;
      if (!record) { resolve(undefined); return; }
      try { assertStoredSigner(record, input); }
      catch (error) { reject(error); return; }
      resolve(record);
    };
  }); } finally { database.close(); }
}
function assertStoredSigner(record: LocalDeviceSigner, input: Pick<LocalDeviceSigner, "tenantId" | "identityId" | "deviceId">): void {
  if (record.storageVersion !== 1 || record.tenantId !== input.tenantId || record.identityId !== input.identityId
    || record.deviceId !== input.deviceId || !(record.privateKey instanceof CryptoKey)
    || record.privateKey.extractable || record.privateKey.algorithm.name !== "ECDSA"
    || (record.privateKey.algorithm as EcKeyAlgorithm).namedCurve !== "P-256"
    || !record.privateKey.usages.includes("sign") || record.publicJwk?.kty !== "EC" || record.publicJwk.crv !== "P-256") throw new DeviceSessionClientError("DEVICE_SESSION_LOCAL_KEY_INVALID");
}
function storageKey(input: Pick<LocalDeviceSigner, "tenantId" | "identityId" | "deviceId">): string {
  return `${input.tenantId}:${input.identityId}:${input.deviceId}`;
}
function openDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") return Promise.reject(new DeviceSessionClientError("DEVICE_SESSION_STORAGE_UNAVAILABLE"));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = request.onblocked = () => reject(new DeviceSessionClientError("DEVICE_SESSION_STORAGE_UNAVAILABLE"));
  });
}
export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
