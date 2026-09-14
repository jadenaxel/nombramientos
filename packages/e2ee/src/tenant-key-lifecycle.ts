import { E2eeError } from "./errors.js";
import {
  asRecord,
  assertExactKeys,
  canonicalize,
  decodeBase64Url,
  encodeBase64Url,
  getSubtleCrypto,
  isSha256Digest,
  sha256,
  utf8,
} from "./internal.js";
import {
  assertCustodianPrivateKey,
  assertCustodianPublicKey,
  exportCustodianPublicKey,
  generateCustodianKeyPair,
  importCustodianPublicKey,
  type CustodianPrivateKey,
  type CustodianPublicKey,
  type ExportedCustodianPublicKey,
} from "./keys.js";
import {
  exportCustodianSigningPrivateKey,
  exportCustodianSigningPublicKey,
  generateCustodianSigningKeyPair,
  importCustodianSigningPrivateKey,
  importCustodianSigningPublicKey,
  SIGNING_ALGORITHM,
  type CustodianSigningPrivateKey,
  type CustodianSigningPublicKey,
  type ExportedCustodianSigningPrivateKey,
  type ExportedCustodianSigningPublicKey,
} from "./signing.js";
import { HPKE_SUITE, hpkeSuite, type HpkeSuiteDescriptor } from "./suite.js";

export const TENANT_KEY_BYTES = 32 as const;
export const TENANT_KEY_GRANT_FORMAT = "nombramientos.tenant-key-grant" as const;
export const TENANT_KEY_GRANT_VERSION = 1 as const;
export const TENANT_KEY_RECOVERY_PURPOSE = "nombramientos.tenant-key-recovery" as const;
export const TENANT_KEY_RECOVERY_BACKUP_FORMAT = "nombramientos.tenant-key-recovery-backup" as const;
export const TENANT_KEY_RECOVERY_BACKUP_VERSION = 1 as const;
export const TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS = 600_000 as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TENANT_KEY_INFO = utf8("NOMBRAMIENTOS-E2EE\u0000tenant-key-grant\u0000v1");

export interface GeneratedTenantContentKey {
  readonly tenantKeyId: string;
  readonly keyBytes: Uint8Array<ArrayBuffer>;
}

export interface TenantKeyGrantAad {
  readonly purpose: "nombramientos.tenant-key-grant";
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly identityId: string;
  readonly deviceId: string;
  readonly deviceFingerprint: `sha256:${string}`;
}

export interface TenantKeyGrantEnvelope {
  readonly format: typeof TENANT_KEY_GRANT_FORMAT;
  readonly version: typeof TENANT_KEY_GRANT_VERSION;
  readonly suite: HpkeSuiteDescriptor;
  readonly aad: TenantKeyGrantAad;
  readonly recipientId: string;
  readonly recipientFingerprint: `sha256:${string}`;
  readonly enc: string;
  readonly ciphertext: string;
  readonly envelopeHash: `sha256:${string}`;
}

export interface TenantKeyRecoveryContext {
  readonly purpose: typeof TENANT_KEY_RECOVERY_PURPOSE;
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly recoveryNonce: string;
  readonly targetIdentityId: string;
  readonly targetDeviceId: string;
  readonly targetDeviceFingerprint: `sha256:${string}`;
  readonly envelopeHash: `sha256:${string}`;
}

export interface TenantKeyRecoveryAuthorization {
  readonly context: TenantKeyRecoveryContext;
  readonly recoveryKeyFingerprint: `sha256:${string}`;
  readonly signature: string;
}

export interface EncryptedTenantKeyRecoveryBackup {
  readonly format: typeof TENANT_KEY_RECOVERY_BACKUP_FORMAT;
  readonly version: typeof TENANT_KEY_RECOVERY_BACKUP_VERSION;
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly createdAt: string;
  readonly recoveryKeyFingerprint: `sha256:${string}`;
  readonly kdf: {
    readonly name: "PBKDF2";
    readonly hash: "SHA-256";
    readonly iterations: typeof TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS;
    readonly salt: string;
  };
  readonly cipher: {
    readonly name: "AES-GCM";
    readonly keyLength: 256;
    readonly iv: string;
  };
  readonly ciphertext: string;
}

interface TenantKeyRecoveryBundle {
  readonly format: "nombramientos.tenant-key-recovery-material";
  readonly version: 1;
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly createdAt: string;
  readonly tenantKey: string;
  readonly recoverySigningKey: ExportedCustodianSigningPrivateKey;
}

export function tenantDeviceRecipientId(tenantId: string, deviceId: string): string {
  return `tenant:${assertUuid(tenantId, "tenantId")}:device:${assertUuid(deviceId, "deviceId")}`;
}

export async function generateTenantDeviceKeyPair(input: {
  readonly tenantId: string;
  readonly deviceId: string;
}): Promise<CustodianPrivateKey> {
  return generateCustodianKeyPair(tenantDeviceRecipientId(input.tenantId, input.deviceId));
}

export async function exportTenantDevicePublicKey(
  key: CustodianPublicKey,
): Promise<ExportedCustodianPublicKey> {
  return exportCustodianPublicKey(key);
}

export function generateTenantContentKey(tenantKeyId = crypto.randomUUID()): GeneratedTenantContentKey {
  assertUuid(tenantKeyId, "tenantKeyId");
  const keyBytes = crypto.getRandomValues(new Uint8Array(TENANT_KEY_BYTES));
  return Object.freeze({ tenantKeyId, keyBytes });
}

export async function createTenantKeyGrantEnvelope(input: {
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly identityId: string;
  readonly deviceId: string;
  readonly tenantKey: Uint8Array<ArrayBuffer>;
  readonly recipient: CustodianPublicKey;
}): Promise<TenantKeyGrantEnvelope> {
  if (!(input.tenantKey instanceof Uint8Array) || input.tenantKey.byteLength !== TENANT_KEY_BYTES) {
    throw new E2eeError("INVALID_KEY", "La clave de contenido debe contener exactamente 32 bytes.");
  }
  await assertCustodianPublicKey(input.recipient);
  const expectedRecipientId = tenantDeviceRecipientId(input.tenantId, input.deviceId);
  if (input.recipient.recipientId !== expectedRecipientId) {
    throw new E2eeError("INVALID_RECIPIENT", "La clave pública no corresponde al dispositivo destinatario.");
  }
  const aad = validateTenantKeyGrantAad({
    purpose: "nombramientos.tenant-key-grant",
    schemaVersion: 1,
    tenantId: input.tenantId,
    tenantKeyId: input.tenantKeyId,
    generation: input.generation,
    identityId: input.identityId,
    deviceId: input.deviceId,
    deviceFingerprint: input.recipient.fingerprint,
  });
  try {
    const sealed = await hpkeSuite.seal(
      { recipientPublicKey: input.recipient.publicKey, info: TENANT_KEY_INFO },
      input.tenantKey,
      utf8(canonicalize(aad)),
    );
    const body = {
      format: TENANT_KEY_GRANT_FORMAT,
      version: TENANT_KEY_GRANT_VERSION,
      suite: HPKE_SUITE,
      aad,
      recipientId: input.recipient.recipientId,
      recipientFingerprint: input.recipient.fingerprint,
      enc: encodeBase64Url(sealed.enc),
      ciphertext: encodeBase64Url(sealed.ct),
    } as const;
    return Object.freeze({
      ...body,
      envelopeHash: (await sha256(canonicalize(body))) as `sha256:${string}`,
    });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("ENCRYPTION_FAILED", "No se pudo sellar la clave de tenant para el dispositivo.", { cause: error });
  }
}

export async function verifyTenantKeyGrantEnvelope(value: unknown): Promise<TenantKeyGrantEnvelope> {
  const envelope = asRecord(value, "sobre de concesión", "INVALID_ENVELOPE");
  assertExactKeys(
    envelope,
    ["format", "version", "suite", "aad", "recipientId", "recipientFingerprint", "enc", "ciphertext", "envelopeHash"],
    "sobre de concesión",
    "INVALID_ENVELOPE",
  );
  if (envelope["format"] !== TENANT_KEY_GRANT_FORMAT || envelope["version"] !== TENANT_KEY_GRANT_VERSION) {
    throw new E2eeError("INVALID_ENVELOPE", "Formato o versión de concesión no soportado.");
  }
  assertHpkeSuite(envelope["suite"]);
  const aad = validateTenantKeyGrantAad(envelope["aad"]);
  const recipientId = assertString(envelope["recipientId"], "recipientId");
  if (recipientId !== tenantDeviceRecipientId(aad.tenantId, aad.deviceId)) {
    throw new E2eeError("INVALID_RECIPIENT", "recipientId no corresponde al tenant y dispositivo del AAD.");
  }
  if (!isSha256Digest(envelope["recipientFingerprint"]) || envelope["recipientFingerprint"] !== aad.deviceFingerprint) {
    throw new E2eeError("KEY_FINGERPRINT_MISMATCH", "La huella destinataria no corresponde al AAD.");
  }
  const enc = assertString(envelope["enc"], "enc");
  const ciphertext = assertString(envelope["ciphertext"], "ciphertext");
  decodeBase64Url(enc, "enc", "INVALID_ENVELOPE", hpkeSuite.kem.encSize);
  const cipherBytes = decodeBase64Url(ciphertext, "ciphertext", "INVALID_ENVELOPE");
  if (cipherBytes.byteLength !== TENANT_KEY_BYTES + 16) {
    throw new E2eeError("INVALID_ENVELOPE", "La concesión HPKE no contiene una clave de contenido de 32 bytes.");
  }
  if (!isSha256Digest(envelope["envelopeHash"])) {
    throw new E2eeError("INVALID_ENVELOPE", "envelopeHash no es un digest SHA-256 canónico.");
  }
  const body = {
    format: TENANT_KEY_GRANT_FORMAT,
    version: TENANT_KEY_GRANT_VERSION,
    suite: HPKE_SUITE,
    aad,
    recipientId,
    recipientFingerprint: envelope["recipientFingerprint"],
    enc,
    ciphertext,
  } as const;
  if (await sha256(canonicalize(body)) !== envelope["envelopeHash"]) {
    throw new E2eeError("ENVELOPE_HASH_MISMATCH", "La huella de la concesión no corresponde a su contenido.");
  }
  return Object.freeze({ ...body, envelopeHash: envelope["envelopeHash"] });
}

export async function openTenantKeyGrantEnvelope(input: {
  readonly envelope: unknown;
  readonly recipient: CustodianPrivateKey;
  readonly expected: Omit<TenantKeyGrantAad, "purpose" | "schemaVersion" | "deviceFingerprint">;
}): Promise<GeneratedTenantContentKey> {
  const envelope = await verifyTenantKeyGrantEnvelope(input.envelope);
  await assertCustodianPrivateKey(input.recipient);
  const expectedAad = validateTenantKeyGrantAad({
    ...input.expected,
    purpose: "nombramientos.tenant-key-grant",
    schemaVersion: 1,
    deviceFingerprint: input.recipient.fingerprint,
  });
  if (canonicalize(expectedAad) !== canonicalize(envelope.aad)) {
    throw new E2eeError("AAD_MISMATCH", "La concesión no corresponde exactamente al tenant, usuario, dispositivo y generación esperados.");
  }
  if (
    envelope.recipientId !== input.recipient.recipientId
    || envelope.recipientFingerprint !== input.recipient.fingerprint
  ) {
    throw new E2eeError("RECIPIENT_NOT_FOUND", "La clave privada no es destinataria de esta concesión.");
  }
  try {
    const plaintext = await hpkeSuite.open(
      {
        recipientKey: input.recipient.keyPair,
        enc: decodeBase64Url(envelope.enc, "enc", "INVALID_ENVELOPE", hpkeSuite.kem.encSize),
        info: TENANT_KEY_INFO,
      },
      decodeBase64Url(envelope.ciphertext, "ciphertext", "INVALID_ENVELOPE"),
      utf8(canonicalize(envelope.aad)),
    );
    const keyBytes = new Uint8Array(plaintext);
    if (keyBytes.byteLength !== TENANT_KEY_BYTES) {
      throw new E2eeError("DECRYPTION_FAILED", "La concesión descifrada no contiene una clave de 32 bytes.");
    }
    return Object.freeze({ tenantKeyId: envelope.aad.tenantKeyId, keyBytes });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("DECRYPTION_FAILED", "La concesión fue alterada o la clave privada no corresponde.", { cause: error });
  }
}

export async function createEncryptedTenantKeyRecoveryBackup(input: {
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly tenantKey: Uint8Array<ArrayBuffer>;
  readonly passphrase: string;
  readonly recoverySigningKey?: CustodianSigningPrivateKey;
  readonly createdAt?: string;
}): Promise<{
  readonly backup: EncryptedTenantKeyRecoveryBackup;
  readonly recoverySigningKey: CustodianSigningPrivateKey;
  readonly recoveryPublicKey: ExportedCustodianSigningPublicKey;
}> {
  assertPassphrase(input.passphrase);
  const tenantId = assertUuid(input.tenantId, "tenantId");
  const tenantKeyId = assertUuid(input.tenantKeyId, "tenantKeyId");
  const generation = assertGeneration(input.generation);
  if (!(input.tenantKey instanceof Uint8Array) || input.tenantKey.byteLength !== TENANT_KEY_BYTES) {
    throw new E2eeError("KEY_BACKUP_INVALID", "La copia requiere una clave de tenant de 32 bytes.");
  }
  const createdAt = input.createdAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(createdAt))) {
    throw new E2eeError("KEY_BACKUP_INVALID", "createdAt no es una fecha válida.");
  }
  const recoverySigningKey = input.recoverySigningKey ?? await generateCustodianSigningKeyPair();
  const [recoverySigningExport, recoveryPublicKey] = await Promise.all([
    exportCustodianSigningPrivateKey(recoverySigningKey),
    exportCustodianSigningPublicKey(recoverySigningKey),
  ]);
  const bundle: TenantKeyRecoveryBundle = {
    format: "nombramientos.tenant-key-recovery-material",
    version: 1,
    tenantId,
    tenantKeyId,
    generation,
    createdAt,
    tenantKey: encodeBase64Url(input.tenantKey),
    recoverySigningKey: recoverySigningExport,
  };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveRecoveryBackupKey(input.passphrase, salt);
  const metadata = {
    format: TENANT_KEY_RECOVERY_BACKUP_FORMAT,
    version: TENANT_KEY_RECOVERY_BACKUP_VERSION,
    tenantId,
    tenantKeyId,
    generation,
    createdAt,
    recoveryKeyFingerprint: recoverySigningKey.fingerprint,
  } as const;
  try {
    const ciphertext = await getSubtleCrypto().encrypt(
      { name: "AES-GCM", iv, additionalData: utf8(canonicalize(metadata)), tagLength: 128 },
      key,
      utf8(canonicalize(bundle)),
    );
    const backup: EncryptedTenantKeyRecoveryBackup = Object.freeze({
      ...metadata,
      kdf: {
        name: "PBKDF2" as const,
        hash: "SHA-256" as const,
        iterations: TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS,
        salt: encodeBase64Url(salt),
      },
      cipher: { name: "AES-GCM" as const, keyLength: 256 as const, iv: encodeBase64Url(iv) },
      ciphertext: encodeBase64Url(ciphertext),
    });
    return Object.freeze({ backup, recoverySigningKey, recoveryPublicKey });
  } catch (error) {
    throw new E2eeError("KEY_BACKUP_INVALID", "No se pudo cifrar la copia offline de recuperación.", { cause: error });
  }
}

export async function openEncryptedTenantKeyRecoveryBackup(
  value: unknown,
  passphrase: string,
): Promise<{
  readonly tenantId: string;
  readonly tenantKeyId: string;
  readonly generation: number;
  readonly tenantKey: Uint8Array<ArrayBuffer>;
  readonly recoverySigningKey: CustodianSigningPrivateKey;
}> {
  assertPassphrase(passphrase);
  const backup = parseRecoveryBackup(value);
  const metadata = recoveryBackupMetadata(backup);
  const key = await deriveRecoveryBackupKey(
    passphrase,
    decodeBase64Url(backup.kdf.salt, "salt", "KEY_BACKUP_INVALID", 16),
  );
  let decoded: unknown;
  try {
    const plaintext = await getSubtleCrypto().decrypt(
      {
        name: "AES-GCM",
        iv: decodeBase64Url(backup.cipher.iv, "iv", "KEY_BACKUP_INVALID", 12),
        additionalData: utf8(canonicalize(metadata)),
        tagLength: 128,
      },
      key,
      decodeBase64Url(backup.ciphertext, "ciphertext", "KEY_BACKUP_INVALID"),
    );
    const json = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    decoded = JSON.parse(json) as unknown;
    if (canonicalize(decoded) !== json) throw new Error("non-canonical recovery bundle");
  } catch (error) {
    throw new E2eeError("KEY_BACKUP_DECRYPTION_FAILED", "La contraseña es incorrecta o la copia offline fue alterada.", { cause: error });
  }
  const bundle = parseRecoveryBundle(decoded, backup);
  const [tenantKey, recoverySigningKey] = await Promise.all([
    Promise.resolve(decodeBase64Url(bundle.tenantKey, "tenantKey", "KEY_BACKUP_INVALID", TENANT_KEY_BYTES)),
    importCustodianSigningPrivateKey(bundle.recoverySigningKey),
  ]);
  if (recoverySigningKey.fingerprint !== backup.recoveryKeyFingerprint) {
    throw new E2eeError("KEY_FINGERPRINT_MISMATCH", "La clave de firma recuperada no coincide con la huella registrada.");
  }
  return Object.freeze({
    tenantId: backup.tenantId,
    tenantKeyId: backup.tenantKeyId,
    generation: backup.generation,
    tenantKey,
    recoverySigningKey,
  });
}

export function createTenantKeyRecoveryContext(input: Omit<TenantKeyRecoveryContext, "purpose" | "schemaVersion">): TenantKeyRecoveryContext {
  const context: TenantKeyRecoveryContext = {
    purpose: TENANT_KEY_RECOVERY_PURPOSE,
    schemaVersion: 1,
    tenantId: assertUuid(input.tenantId, "tenantId"),
    tenantKeyId: assertUuid(input.tenantKeyId, "tenantKeyId"),
    generation: assertGeneration(input.generation),
    recoveryNonce: assertUuid(input.recoveryNonce, "recoveryNonce"),
    targetIdentityId: assertUuid(input.targetIdentityId, "targetIdentityId"),
    targetDeviceId: assertUuid(input.targetDeviceId, "targetDeviceId"),
    targetDeviceFingerprint: assertDigest(input.targetDeviceFingerprint, "targetDeviceFingerprint"),
    envelopeHash: assertDigest(input.envelopeHash, "envelopeHash"),
  };
  return Object.freeze(context);
}

export function validateTenantKeyRecoveryContext(value: unknown): TenantKeyRecoveryContext {
  const input = asRecord(value, "contexto de recuperación", "SIGNATURE_INVALID");
  assertExactKeys(
    input,
    [
      "purpose", "schemaVersion", "tenantId", "tenantKeyId", "generation", "recoveryNonce",
      "targetIdentityId", "targetDeviceId", "targetDeviceFingerprint", "envelopeHash",
    ],
    "contexto de recuperación",
    "SIGNATURE_INVALID",
  );
  if (input["purpose"] !== TENANT_KEY_RECOVERY_PURPOSE || input["schemaVersion"] !== 1) {
    throw new E2eeError("SIGNATURE_INVALID", "Purpose o versión de recuperación no soportado.");
  }
  return createTenantKeyRecoveryContext({
    tenantId: input["tenantId"] as string,
    tenantKeyId: input["tenantKeyId"] as string,
    generation: input["generation"] as number,
    recoveryNonce: input["recoveryNonce"] as string,
    targetIdentityId: input["targetIdentityId"] as string,
    targetDeviceId: input["targetDeviceId"] as string,
    targetDeviceFingerprint: input["targetDeviceFingerprint"] as `sha256:${string}`,
    envelopeHash: input["envelopeHash"] as `sha256:${string}`,
  });
}

export async function signTenantKeyRecovery(
  recoverySigningKey: CustodianSigningPrivateKey,
  contextInput: unknown,
): Promise<TenantKeyRecoveryAuthorization> {
  const context = validateTenantKeyRecoveryContext(contextInput);
  const recoveryPublicKey = await exportCustodianSigningPublicKey(recoverySigningKey);
  try {
    const signature = await getSubtleCrypto().sign(
      SIGNING_ALGORITHM,
      recoverySigningKey.keyPair.privateKey,
      utf8(canonicalize(context)),
    );
    return Object.freeze({
      context,
      recoveryKeyFingerprint: recoveryPublicKey.fingerprint,
      signature: encodeBase64Url(signature),
    });
  } catch (error) {
    throw new E2eeError("SIGNATURE_INVALID", "No se pudo firmar la autorización de recuperación.", { cause: error });
  }
}

export async function verifyTenantKeyRecovery(
  recoveryPublicKeyInput: ExportedCustodianSigningPublicKey | CustodianSigningPublicKey,
  authorizationInput: unknown,
): Promise<boolean> {
  const authorization = parseRecoveryAuthorization(authorizationInput);
  const recoveryPublicKey = "publicKey" in recoveryPublicKeyInput
    ? recoveryPublicKeyInput
    : await importCustodianSigningPublicKey(recoveryPublicKeyInput);
  if (recoveryPublicKey.fingerprint !== authorization.recoveryKeyFingerprint) return false;
  try {
    return await getSubtleCrypto().verify(
      SIGNING_ALGORITHM,
      recoveryPublicKey.publicKey,
      decodeBase64Url(authorization.signature, "signature", "SIGNATURE_INVALID", 64),
      utf8(canonicalize(authorization.context)),
    );
  } catch (error) {
    throw new E2eeError("SIGNATURE_INVALID", "No se pudo verificar la autorización de recuperación.", { cause: error });
  }
}

function validateTenantKeyGrantAad(value: unknown): TenantKeyGrantAad {
  const input = asRecord(value, "AAD de concesión", "INVALID_AAD");
  assertExactKeys(
    input,
    ["purpose", "schemaVersion", "tenantId", "tenantKeyId", "generation", "identityId", "deviceId", "deviceFingerprint"],
    "AAD de concesión",
    "INVALID_AAD",
  );
  if (input["purpose"] !== "nombramientos.tenant-key-grant" || input["schemaVersion"] !== 1) {
    throw new E2eeError("INVALID_AAD", "Purpose o versión de concesión no soportado.");
  }
  return Object.freeze({
    purpose: "nombramientos.tenant-key-grant",
    schemaVersion: 1,
    tenantId: assertUuid(input["tenantId"], "tenantId"),
    tenantKeyId: assertUuid(input["tenantKeyId"], "tenantKeyId"),
    generation: assertGeneration(input["generation"]),
    identityId: assertUuid(input["identityId"], "identityId"),
    deviceId: assertUuid(input["deviceId"], "deviceId"),
    deviceFingerprint: assertDigest(input["deviceFingerprint"], "deviceFingerprint"),
  });
}

function assertHpkeSuite(value: unknown): asserts value is HpkeSuiteDescriptor {
  const suite = asRecord(value, "suite", "INVALID_ENVELOPE");
  assertExactKeys(suite, ["kem", "kemId", "kdf", "kdfId", "aead", "aeadId"], "suite", "INVALID_ENVELOPE");
  for (const key of Object.keys(HPKE_SUITE) as (keyof HpkeSuiteDescriptor)[]) {
    if (suite[key] !== HPKE_SUITE[key]) {
      throw new E2eeError("INVALID_ENVELOPE", "La concesión declara una suite HPKE no soportada.");
    }
  }
}

function parseRecoveryAuthorization(value: unknown): TenantKeyRecoveryAuthorization {
  const input = asRecord(value, "autorización de recuperación", "SIGNATURE_INVALID");
  assertExactKeys(input, ["context", "recoveryKeyFingerprint", "signature"], "autorización de recuperación", "SIGNATURE_INVALID");
  return Object.freeze({
    context: validateTenantKeyRecoveryContext(input["context"]),
    recoveryKeyFingerprint: assertDigest(input["recoveryKeyFingerprint"], "recoveryKeyFingerprint"),
    signature: assertString(input["signature"], "signature"),
  });
}

function recoveryBackupMetadata(backup: EncryptedTenantKeyRecoveryBackup) {
  return {
    format: backup.format,
    version: backup.version,
    tenantId: backup.tenantId,
    tenantKeyId: backup.tenantKeyId,
    generation: backup.generation,
    createdAt: backup.createdAt,
    recoveryKeyFingerprint: backup.recoveryKeyFingerprint,
  } as const;
}

function parseRecoveryBackup(value: unknown): EncryptedTenantKeyRecoveryBackup {
  const backup = asRecord(value, "copia de recuperación", "KEY_BACKUP_INVALID");
  assertExactKeys(
    backup,
    ["format", "version", "tenantId", "tenantKeyId", "generation", "createdAt", "recoveryKeyFingerprint", "kdf", "cipher", "ciphertext"],
    "copia de recuperación",
    "KEY_BACKUP_INVALID",
  );
  if (backup["format"] !== TENANT_KEY_RECOVERY_BACKUP_FORMAT || backup["version"] !== TENANT_KEY_RECOVERY_BACKUP_VERSION) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Formato o versión de copia de recuperación no soportado.");
  }
  const kdf = asRecord(backup["kdf"], "kdf", "KEY_BACKUP_INVALID");
  assertExactKeys(kdf, ["name", "hash", "iterations", "salt"], "kdf", "KEY_BACKUP_INVALID");
  if (kdf["name"] !== "PBKDF2" || kdf["hash"] !== "SHA-256" || kdf["iterations"] !== TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Parámetros KDF de recuperación no soportados.");
  }
  const cipher = asRecord(backup["cipher"], "cipher", "KEY_BACKUP_INVALID");
  assertExactKeys(cipher, ["name", "keyLength", "iv"], "cipher", "KEY_BACKUP_INVALID");
  if (cipher["name"] !== "AES-GCM" || cipher["keyLength"] !== 256) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Cifrado de recuperación no soportado.");
  }
  const createdAt = assertString(backup["createdAt"], "createdAt");
  if (!Number.isFinite(Date.parse(createdAt))) throw new E2eeError("KEY_BACKUP_INVALID", "createdAt no es válido.");
  const parsed: EncryptedTenantKeyRecoveryBackup = {
    format: TENANT_KEY_RECOVERY_BACKUP_FORMAT,
    version: TENANT_KEY_RECOVERY_BACKUP_VERSION,
    tenantId: assertUuid(backup["tenantId"], "tenantId"),
    tenantKeyId: assertUuid(backup["tenantKeyId"], "tenantKeyId"),
    generation: assertGeneration(backup["generation"]),
    createdAt,
    recoveryKeyFingerprint: assertDigest(backup["recoveryKeyFingerprint"], "recoveryKeyFingerprint"),
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS,
      salt: assertString(kdf["salt"], "salt"),
    },
    cipher: { name: "AES-GCM", keyLength: 256, iv: assertString(cipher["iv"], "iv") },
    ciphertext: assertString(backup["ciphertext"], "ciphertext"),
  };
  decodeBase64Url(parsed.kdf.salt, "salt", "KEY_BACKUP_INVALID", 16);
  decodeBase64Url(parsed.cipher.iv, "iv", "KEY_BACKUP_INVALID", 12);
  decodeBase64Url(parsed.ciphertext, "ciphertext", "KEY_BACKUP_INVALID");
  return Object.freeze(parsed);
}

function parseRecoveryBundle(value: unknown, backup: EncryptedTenantKeyRecoveryBackup): TenantKeyRecoveryBundle {
  const bundle = asRecord(value, "material de recuperación", "KEY_BACKUP_INVALID");
  assertExactKeys(
    bundle,
    ["format", "version", "tenantId", "tenantKeyId", "generation", "createdAt", "tenantKey", "recoverySigningKey"],
    "material de recuperación",
    "KEY_BACKUP_INVALID",
  );
  if (
    bundle["format"] !== "nombramientos.tenant-key-recovery-material"
    || bundle["version"] !== 1
    || bundle["tenantId"] !== backup.tenantId
    || bundle["tenantKeyId"] !== backup.tenantKeyId
    || bundle["generation"] !== backup.generation
    || bundle["createdAt"] !== backup.createdAt
  ) {
    throw new E2eeError("KEY_BACKUP_INVALID", "La identidad del material cifrado no coincide con la copia externa.");
  }
  return bundle as unknown as TenantKeyRecoveryBundle;
}

async function deriveRecoveryBackupKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await getSubtleCrypto().importKey("raw", utf8(passphrase), "PBKDF2", false, ["deriveKey"]);
  return getSubtleCrypto().deriveKey(
    { name: "PBKDF2", hash: "SHA-256", iterations: TENANT_KEY_RECOVERY_PBKDF2_ITERATIONS, salt },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function assertUuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new E2eeError("INVALID_KEY", `${label} debe ser un UUID canónico.`);
  }
  return value;
}

function assertGeneration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new E2eeError("INVALID_KEY", "generation debe ser un entero positivo.");
  }
  return value as number;
}

function assertDigest(value: unknown, label: string): `sha256:${string}` {
  if (!isSha256Digest(value)) throw new E2eeError("INVALID_KEY", `${label} debe ser un digest SHA-256 canónico.`);
  return value;
}

function assertString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new E2eeError("INVALID_KEY", `${label} debe ser string.`);
  return value;
}

function assertPassphrase(value: string): void {
  if (typeof value !== "string" || value.length < 16 || value.length > 1024) {
    throw new E2eeError("KEY_BACKUP_INVALID", "La contraseña de recuperación debe contener entre 16 y 1024 caracteres.");
  }
}
