import { E2eeError } from "./errors.js";
import {
  asRecord,
  assertExactKeys,
  assertRecipientId,
  decodeBase64Url,
  encodeBase64Url,
  isSha256Digest,
  sha256,
  utf8,
} from "./internal.js";
import { HPKE_INFO, HPKE_SUITE, hpkeSuite, type HpkeSuiteDescriptor } from "./suite.js";

const PUBLIC_KEY_FORMAT = "nombramientos.hpke-public-key";
const PRIVATE_KEY_FORMAT = "nombramientos.hpke-private-key";
const KEY_FORMAT_VERSION = 1;

export interface CustodianPublicKey {
  readonly recipientId: string;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKey: CryptoKey;
}

export interface CustodianPrivateKey extends CustodianPublicKey {
  readonly keyPair: CryptoKeyPair;
}

export interface ExportedCustodianPublicKey {
  readonly format: typeof PUBLIC_KEY_FORMAT;
  readonly version: typeof KEY_FORMAT_VERSION;
  readonly suite: HpkeSuiteDescriptor;
  readonly recipientId: string;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKey: string;
}

export interface ExportedCustodianPrivateKey {
  readonly format: typeof PRIVATE_KEY_FORMAT;
  readonly version: typeof KEY_FORMAT_VERSION;
  readonly suite: HpkeSuiteDescriptor;
  readonly recipientId: string;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKey: string;
  readonly privateKey: string;
}

function assertSuite(value: unknown): asserts value is HpkeSuiteDescriptor {
  const suite = asRecord(value, "suite", "INVALID_KEY");
  assertExactKeys(
    suite,
    ["kem", "kemId", "kdf", "kdfId", "aead", "aeadId"],
    "suite",
    "INVALID_KEY",
  );
  for (const key of Object.keys(HPKE_SUITE) as (keyof HpkeSuiteDescriptor)[]) {
    if (suite[key] !== HPKE_SUITE[key]) {
      throw new E2eeError("INVALID_KEY", "La clave declara una suite HPKE no soportada.");
    }
  }
}

export async function fingerprintPublicKey(publicKey: CryptoKey): Promise<`sha256:${string}`> {
  try {
    const serialized = await hpkeSuite.kem.serializePublicKey(publicKey);
    return (await sha256(serialized)) as `sha256:${string}`;
  } catch (error) {
    throw new E2eeError("INVALID_KEY", "No se pudo serializar la clave pública P-256.", {
      cause: error,
    });
  }
}

async function assertPublicDescriptor(key: CustodianPublicKey): Promise<void> {
  assertRecipientId(key.recipientId);
  if (!isSha256Digest(key.fingerprint)) {
    throw new E2eeError("INVALID_KEY", "La huella de clave pública no es SHA-256 válida.");
  }
  const actualFingerprint = await fingerprintPublicKey(key.publicKey);
  if (actualFingerprint !== key.fingerprint) {
    throw new E2eeError(
      "KEY_FINGERPRINT_MISMATCH",
      "La huella declarada no corresponde a la clave pública.",
    );
  }
}

export async function generateCustodianKeyPair(recipientId: string): Promise<CustodianPrivateKey> {
  const normalizedRecipientId = assertRecipientId(recipientId);
  try {
    const keyPair = await hpkeSuite.kem.generateKeyPair();
    const fingerprint = await fingerprintPublicKey(keyPair.publicKey);
    return Object.freeze({
      recipientId: normalizedRecipientId,
      fingerprint,
      publicKey: keyPair.publicKey,
      keyPair,
    });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("INVALID_KEY", "No se pudo generar el par de claves del custodio.", {
      cause: error,
    });
  }
}

export function toCustodianPublicKey(key: CustodianPrivateKey): CustodianPublicKey {
  return Object.freeze({
    recipientId: key.recipientId,
    fingerprint: key.fingerprint,
    publicKey: key.publicKey,
  });
}

export async function exportCustodianPublicKey(
  key: CustodianPublicKey,
): Promise<ExportedCustodianPublicKey> {
  await assertPublicDescriptor(key);
  try {
    const serialized = await hpkeSuite.kem.serializePublicKey(key.publicKey);
    return Object.freeze({
      format: PUBLIC_KEY_FORMAT,
      version: KEY_FORMAT_VERSION,
      suite: HPKE_SUITE,
      recipientId: key.recipientId,
      fingerprint: key.fingerprint,
      publicKey: encodeBase64Url(serialized),
    });
  } catch (error) {
    throw new E2eeError("INVALID_KEY", "No se pudo exportar la clave pública del custodio.", {
      cause: error,
    });
  }
}

export async function exportCustodianPrivateKey(
  key: CustodianPrivateKey,
): Promise<ExportedCustodianPrivateKey> {
  await assertCustodianPrivateKey(key);
  try {
    const [publicKey, privateKey] = await Promise.all([
      hpkeSuite.kem.serializePublicKey(key.keyPair.publicKey),
      hpkeSuite.kem.serializePrivateKey(key.keyPair.privateKey),
    ]);
    return Object.freeze({
      format: PRIVATE_KEY_FORMAT,
      version: KEY_FORMAT_VERSION,
      suite: HPKE_SUITE,
      recipientId: key.recipientId,
      fingerprint: key.fingerprint,
      publicKey: encodeBase64Url(publicKey),
      privateKey: encodeBase64Url(privateKey),
    });
  } catch (error) {
    throw new E2eeError("INVALID_KEY", "No se pudo exportar la clave privada del custodio.", {
      cause: error,
    });
  }
}

function parsePublicExport(value: unknown): {
  recipientId: string;
  fingerprint: `sha256:${string}`;
  publicKey: Uint8Array;
} {
  const input = asRecord(value, "clave pública", "INVALID_KEY");
  assertExactKeys(
    input,
    ["format", "version", "suite", "recipientId", "fingerprint", "publicKey"],
    "clave pública",
    "INVALID_KEY",
  );
  if (input["format"] !== PUBLIC_KEY_FORMAT || input["version"] !== KEY_FORMAT_VERSION) {
    throw new E2eeError("INVALID_KEY", "Formato o versión de clave pública no soportado.");
  }
  assertSuite(input["suite"]);
  const recipientId = assertRecipientId(input["recipientId"], "INVALID_KEY");
  if (!isSha256Digest(input["fingerprint"])) {
    throw new E2eeError("INVALID_KEY", "Huella de clave pública inválida.");
  }
  return {
    recipientId,
    fingerprint: input["fingerprint"],
    publicKey: decodeBase64Url(
      input["publicKey"],
      "publicKey",
      "INVALID_KEY",
      hpkeSuite.kem.publicKeySize,
    ),
  };
}

export async function importCustodianPublicKey(value: unknown): Promise<CustodianPublicKey> {
  const parsed = parsePublicExport(value);
  try {
    const publicKey = await hpkeSuite.kem.deserializePublicKey(parsed.publicKey);
    const actualFingerprint = await fingerprintPublicKey(publicKey);
    if (actualFingerprint !== parsed.fingerprint) {
      throw new E2eeError(
        "KEY_FINGERPRINT_MISMATCH",
        "La huella no corresponde a la clave pública importada.",
      );
    }
    return Object.freeze({
      recipientId: parsed.recipientId,
      fingerprint: parsed.fingerprint,
      publicKey,
    });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("INVALID_KEY", "No se pudo importar la clave pública del custodio.", {
      cause: error,
    });
  }
}

export async function importCustodianPrivateKey(value: unknown): Promise<CustodianPrivateKey> {
  const input = asRecord(value, "clave privada", "INVALID_KEY");
  assertExactKeys(
    input,
    ["format", "version", "suite", "recipientId", "fingerprint", "publicKey", "privateKey"],
    "clave privada",
    "INVALID_KEY",
  );
  if (input["format"] !== PRIVATE_KEY_FORMAT || input["version"] !== KEY_FORMAT_VERSION) {
    throw new E2eeError("INVALID_KEY", "Formato o versión de clave privada no soportado.");
  }
  assertSuite(input["suite"]);
  const recipientId = assertRecipientId(input["recipientId"], "INVALID_KEY");
  if (!isSha256Digest(input["fingerprint"])) {
    throw new E2eeError("INVALID_KEY", "Huella de clave privada inválida.");
  }
  const publicBytes = decodeBase64Url(
    input["publicKey"],
    "publicKey",
    "INVALID_KEY",
    hpkeSuite.kem.publicKeySize,
  );
  const privateBytes = decodeBase64Url(
    input["privateKey"],
    "privateKey",
    "INVALID_KEY",
    hpkeSuite.kem.privateKeySize,
  );

  try {
    const [publicKey, privateKey] = await Promise.all([
      hpkeSuite.kem.deserializePublicKey(publicBytes),
      hpkeSuite.kem.deserializePrivateKey(privateBytes),
    ]);
    const actualFingerprint = await fingerprintPublicKey(publicKey);
    if (actualFingerprint !== input["fingerprint"]) {
      throw new E2eeError(
        "KEY_FINGERPRINT_MISMATCH",
        "La huella no corresponde a la clave pública importada.",
      );
    }

    const keyPair = { publicKey, privateKey };
    const probe = utf8("nombramientos-hpke-key-pair-check-v1");
    const aad = utf8(input["fingerprint"]);
    const sealed = await hpkeSuite.seal(
      { recipientPublicKey: publicKey, info: HPKE_INFO },
      probe,
      aad,
    );
    const opened = await hpkeSuite.open(
      { recipientKey: keyPair, enc: sealed.enc, info: HPKE_INFO },
      sealed.ct,
      aad,
    );
    if (encodeBase64Url(opened) !== encodeBase64Url(probe)) {
      throw new E2eeError("KEY_PAIR_MISMATCH", "La clave privada no corresponde a la pública.");
    }

    return Object.freeze({
      recipientId,
      fingerprint: input["fingerprint"],
      publicKey,
      keyPair,
    });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError(
      "KEY_PAIR_MISMATCH",
      "La clave privada no corresponde a la pública o no pudo importarse.",
      { cause: error },
    );
  }
}

export async function assertCustodianPublicKey(key: CustodianPublicKey): Promise<void> {
  await assertPublicDescriptor(key);
}

export async function assertCustodianPrivateKey(key: CustodianPrivateKey): Promise<void> {
  await assertPublicDescriptor(key);
  if (key.keyPair.publicKey !== key.publicKey) {
    const pairFingerprint = await fingerprintPublicKey(key.keyPair.publicKey);
    if (pairFingerprint !== key.fingerprint) {
      throw new E2eeError(
        "KEY_FINGERPRINT_MISMATCH",
        "El par privado no corresponde a la identidad pública del custodio.",
      );
    }
  }
}
