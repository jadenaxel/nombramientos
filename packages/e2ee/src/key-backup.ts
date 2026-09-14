import { E2eeError } from "./errors.js";
import {
  exportCustodianPrivateKey,
  importCustodianPrivateKey,
  type CustodianPrivateKey,
  type ExportedCustodianPrivateKey,
} from "./keys.js";
import {
  asRecord,
  assertExactKeys,
  canonicalize,
  decodeBase64Url,
  decodeUtf8,
  encodeBase64Url,
  getSubtleCrypto,
  utf8,
} from "./internal.js";
import {
  exportCustodianSigningPrivateKey,
  importCustodianSigningPrivateKey,
  type CustodianSigningPrivateKey,
  type ExportedCustodianSigningPrivateKey,
} from "./signing.js";

export const KEY_BACKUP_FORMAT = "nombramientos.custodian-key-backup" as const;
export const KEY_BACKUP_VERSION = 1 as const;
export const KEY_BACKUP_PBKDF2_ITERATIONS = 600_000 as const;

export interface CustodianPrivateKeyBundle {
  readonly format: "nombramientos.custodian-private-keys";
  readonly version: 1;
  readonly tenantId: string;
  readonly deviceId: string;
  readonly recipientId: string;
  readonly createdAt: string;
  readonly hpke: ExportedCustodianPrivateKey;
  readonly signing: ExportedCustodianSigningPrivateKey;
}

export interface EncryptedCustodianKeyBackup {
  readonly format: typeof KEY_BACKUP_FORMAT;
  readonly version: typeof KEY_BACKUP_VERSION;
  readonly tenantId: string;
  readonly deviceId: string;
  readonly recipientId: string;
  readonly createdAt: string;
  readonly kdf: {
    readonly name: "PBKDF2";
    readonly hash: "SHA-256";
    readonly iterations: typeof KEY_BACKUP_PBKDF2_ITERATIONS;
    readonly salt: string;
  };
  readonly cipher: {
    readonly name: "AES-GCM";
    readonly keyLength: 256;
    readonly iv: string;
  };
  readonly ciphertext: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const RECIPIENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u;

function assertIdentity(value: unknown, label: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new E2eeError("KEY_BACKUP_INVALID", `${label} no es válido.`);
  }
  return value;
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== "string" || passphrase.length < 16 || passphrase.length > 1024) {
    throw new E2eeError(
      "KEY_BACKUP_INVALID",
      "La contraseña de la copia debe contener entre 16 y 1024 caracteres.",
    );
  }
}

function backupAad(value: {
  readonly tenantId: string;
  readonly deviceId: string;
  readonly recipientId: string;
  readonly createdAt: string;
}): string {
  return canonicalize({
    format: KEY_BACKUP_FORMAT,
    version: KEY_BACKUP_VERSION,
    purpose: "custodian-private-key-recovery",
    tenantId: value.tenantId,
    deviceId: value.deviceId,
    recipientId: value.recipientId,
    createdAt: value.createdAt,
  });
}

async function deriveBackupKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const material = await getSubtleCrypto().importKey("raw", utf8(passphrase), "PBKDF2", false, ["deriveKey"]);
  return getSubtleCrypto().deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: KEY_BACKUP_PBKDF2_ITERATIONS,
      salt,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function createEncryptedCustodianKeyBackup(input: {
  readonly tenantId: string;
  readonly deviceId: string;
  readonly recipientId: string;
  readonly createdAt?: string;
  readonly passphrase: string;
  readonly hpke: CustodianPrivateKey;
  readonly signing: CustodianSigningPrivateKey;
}): Promise<EncryptedCustodianKeyBackup> {
  assertPassphrase(input.passphrase);
  const tenantId = assertIdentity(input.tenantId, "tenantId", UUID_PATTERN);
  const deviceId = assertIdentity(input.deviceId, "deviceId", UUID_PATTERN);
  const recipientId = assertIdentity(input.recipientId, "recipientId", RECIPIENT_PATTERN);
  if (input.hpke.recipientId !== recipientId) {
    throw new E2eeError("KEY_BACKUP_INVALID", "recipientId no corresponde a la clave HPKE.");
  }
  const createdAt = input.createdAt ?? new Date().toISOString();
  if (!Number.isFinite(Date.parse(createdAt))) {
    throw new E2eeError("KEY_BACKUP_INVALID", "createdAt no es una fecha válida.");
  }
  const bundle: CustodianPrivateKeyBundle = {
    format: "nombramientos.custodian-private-keys",
    version: 1,
    tenantId,
    deviceId,
    recipientId,
    createdAt,
    hpke: await exportCustodianPrivateKey(input.hpke),
    signing: await exportCustodianSigningPrivateKey(input.signing),
  };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(input.passphrase, salt);
  const aad = backupAad({ tenantId, deviceId, recipientId, createdAt });
  try {
    const ciphertext = await getSubtleCrypto().encrypt(
      { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 },
      key,
      utf8(canonicalize(bundle)),
    );
    const backup: EncryptedCustodianKeyBackup = {
      format: KEY_BACKUP_FORMAT,
      version: KEY_BACKUP_VERSION,
      tenantId,
      deviceId,
      recipientId,
      createdAt,
      kdf: {
        name: "PBKDF2",
        hash: "SHA-256",
        iterations: KEY_BACKUP_PBKDF2_ITERATIONS,
        salt: encodeBase64Url(salt),
      },
      cipher: { name: "AES-GCM", keyLength: 256, iv: encodeBase64Url(iv) },
      ciphertext: encodeBase64Url(ciphertext),
    };
    return Object.freeze(backup);
  } catch (error) {
    throw new E2eeError("KEY_BACKUP_INVALID", "No se pudo cifrar la copia de claves.", { cause: error });
  }
}

function parseBackup(value: unknown): EncryptedCustodianKeyBackup {
  const backup = asRecord(value, "copia de claves", "KEY_BACKUP_INVALID");
  assertExactKeys(
    backup,
    ["format", "version", "tenantId", "deviceId", "recipientId", "createdAt", "kdf", "cipher", "ciphertext"],
    "copia de claves",
    "KEY_BACKUP_INVALID",
  );
  if (backup["format"] !== KEY_BACKUP_FORMAT || backup["version"] !== KEY_BACKUP_VERSION) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Formato o versión de copia no soportado.");
  }
  const tenantId = assertIdentity(backup["tenantId"], "tenantId", UUID_PATTERN);
  const deviceId = assertIdentity(backup["deviceId"], "deviceId", UUID_PATTERN);
  const recipientId = assertIdentity(backup["recipientId"], "recipientId", RECIPIENT_PATTERN);
  if (typeof backup["createdAt"] !== "string" || !Number.isFinite(Date.parse(backup["createdAt"]))) {
    throw new E2eeError("KEY_BACKUP_INVALID", "createdAt no es válido.");
  }
  const kdf = asRecord(backup["kdf"], "kdf", "KEY_BACKUP_INVALID");
  assertExactKeys(kdf, ["name", "hash", "iterations", "salt"], "kdf", "KEY_BACKUP_INVALID");
  if (
    kdf["name"] !== "PBKDF2"
    || kdf["hash"] !== "SHA-256"
    || kdf["iterations"] !== KEY_BACKUP_PBKDF2_ITERATIONS
  ) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Parámetros KDF no soportados.");
  }
  const cipher = asRecord(backup["cipher"], "cipher", "KEY_BACKUP_INVALID");
  assertExactKeys(cipher, ["name", "keyLength", "iv"], "cipher", "KEY_BACKUP_INVALID");
  if (cipher["name"] !== "AES-GCM" || cipher["keyLength"] !== 256) {
    throw new E2eeError("KEY_BACKUP_INVALID", "Cifrado de copia no soportado.");
  }
  decodeBase64Url(kdf["salt"], "salt", "KEY_BACKUP_INVALID", 16);
  decodeBase64Url(cipher["iv"], "iv", "KEY_BACKUP_INVALID", 12);
  decodeBase64Url(backup["ciphertext"], "ciphertext", "KEY_BACKUP_INVALID");
  return {
    format: KEY_BACKUP_FORMAT,
    version: KEY_BACKUP_VERSION,
    tenantId,
    deviceId,
    recipientId,
    createdAt: backup["createdAt"],
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: KEY_BACKUP_PBKDF2_ITERATIONS,
      salt: kdf["salt"] as string,
    },
    cipher: { name: "AES-GCM", keyLength: 256, iv: cipher["iv"] as string },
    ciphertext: backup["ciphertext"] as string,
  };
}

function parseBundle(value: unknown, expected: EncryptedCustodianKeyBackup): CustodianPrivateKeyBundle {
  const bundle = asRecord(value, "contenido de copia", "KEY_BACKUP_INVALID");
  assertExactKeys(
    bundle,
    ["format", "version", "tenantId", "deviceId", "recipientId", "createdAt", "hpke", "signing"],
    "contenido de copia",
    "KEY_BACKUP_INVALID",
  );
  if (
    bundle["format"] !== "nombramientos.custodian-private-keys"
    || bundle["version"] !== 1
    || bundle["tenantId"] !== expected.tenantId
    || bundle["deviceId"] !== expected.deviceId
    || bundle["recipientId"] !== expected.recipientId
    || bundle["createdAt"] !== expected.createdAt
  ) {
    throw new E2eeError("KEY_BACKUP_INVALID", "La identidad cifrada no coincide con la copia externa.");
  }
  return bundle as unknown as CustodianPrivateKeyBundle;
}

export async function openEncryptedCustodianKeyBackup(
  value: unknown,
  passphrase: string,
): Promise<{
  readonly metadata: Pick<CustodianPrivateKeyBundle, "tenantId" | "deviceId" | "recipientId" | "createdAt">;
  readonly hpke: CustodianPrivateKey;
  readonly signing: CustodianSigningPrivateKey;
}> {
  assertPassphrase(passphrase);
  const backup = parseBackup(value);
  const salt = decodeBase64Url(backup.kdf.salt, "salt", "KEY_BACKUP_INVALID", 16);
  const iv = decodeBase64Url(backup.cipher.iv, "iv", "KEY_BACKUP_INVALID", 12);
  const key = await deriveBackupKey(passphrase, salt);
  const aad = backupAad(backup);
  let decoded: unknown;
  try {
    const plaintext = await getSubtleCrypto().decrypt(
      { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 },
      key,
      decodeBase64Url(backup.ciphertext, "ciphertext", "KEY_BACKUP_INVALID"),
    );
    decoded = JSON.parse(decodeUtf8(plaintext)) as unknown;
    if (canonicalize(decoded) !== decodeUtf8(plaintext)) {
      throw new E2eeError("KEY_BACKUP_INVALID", "La copia descifrada no usa JSON canónico.");
    }
  } catch (error) {
    if (error instanceof E2eeError && error.code === "KEY_BACKUP_INVALID") throw error;
    throw new E2eeError(
      "KEY_BACKUP_DECRYPTION_FAILED",
      "La contraseña es incorrecta o la copia fue alterada.",
      { cause: error },
    );
  }
  const bundle = parseBundle(decoded, backup);
  const [hpke, signing] = await Promise.all([
    importCustodianPrivateKey(bundle.hpke),
    importCustodianSigningPrivateKey(bundle.signing),
  ]);
  if (hpke.recipientId !== bundle.recipientId) {
    throw new E2eeError("KEY_BACKUP_INVALID", "La clave HPKE no corresponde al custodio de la copia.");
  }
  return Object.freeze({
    metadata: Object.freeze({
      tenantId: bundle.tenantId,
      deviceId: bundle.deviceId,
      recipientId: bundle.recipientId,
      createdAt: bundle.createdAt,
    }),
    hpke,
    signing,
  });
}
