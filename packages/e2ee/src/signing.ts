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

export const SIGNING_ALGORITHM = "Ed25519" as const;
export const SIGNING_PUBLIC_KEY_FORMAT = "nombramientos.ed25519-public-key" as const;
export const SIGNING_PRIVATE_KEY_FORMAT = "nombramientos.ed25519-private-key" as const;
export const SIGNING_KEY_FORMAT_VERSION = 1 as const;
export const TALLY_ATTESTATION_PURPOSE = "nombramientos.tally.attestation" as const;

export interface CustodianSigningPublicKey {
  readonly fingerprint: `sha256:${string}`;
  readonly publicKey: CryptoKey;
}

export interface CustodianSigningPrivateKey extends CustodianSigningPublicKey {
  readonly keyPair: CryptoKeyPair;
}

export interface ExportedCustodianSigningPublicKey {
  readonly format: typeof SIGNING_PUBLIC_KEY_FORMAT;
  readonly version: typeof SIGNING_KEY_FORMAT_VERSION;
  readonly algorithm: typeof SIGNING_ALGORITHM;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKeySpki: string;
}

export interface ExportedCustodianSigningPrivateKey {
  readonly format: typeof SIGNING_PRIVATE_KEY_FORMAT;
  readonly version: typeof SIGNING_KEY_FORMAT_VERSION;
  readonly algorithm: typeof SIGNING_ALGORITHM;
  readonly fingerprint: `sha256:${string}`;
  readonly publicKeySpki: string;
  readonly privateKeyPkcs8: string;
}

export interface TallyAttestationContext {
  readonly tenantId: string;
  readonly roundId: string;
  readonly manifestId: string;
  readonly manifestHash: `sha256:${string}`;
  readonly aggregateHash: `sha256:${string}`;
  readonly purpose: typeof TALLY_ATTESTATION_PURPOSE;
  readonly schemaVersion: 1;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function assertUuid(value: unknown, name: string): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new E2eeError("SIGNATURE_INVALID", `${name} debe ser un UUID canónico en minúsculas.`);
  }
  return value;
}

function assertDigest(value: unknown, name: string): `sha256:${string}` {
  if (!isSha256Digest(value)) {
    throw new E2eeError("SIGNATURE_INVALID", `${name} debe ser un digest SHA-256 canónico.`);
  }
  return value;
}

export async function fingerprintSigningPublicKey(publicKey: CryptoKey): Promise<`sha256:${string}`> {
  try {
    const spki = await getSubtleCrypto().exportKey("spki", publicKey);
    return (await sha256(spki)) as `sha256:${string}`;
  } catch (error) {
    throw new E2eeError("INVALID_KEY", "No se pudo exportar la clave pública Ed25519.", { cause: error });
  }
}

async function assertSigningPublicKey(key: CustodianSigningPublicKey): Promise<void> {
  if (!isSha256Digest(key.fingerprint)) {
    throw new E2eeError("INVALID_KEY", "La huella Ed25519 no es válida.");
  }
  if (key.publicKey.type !== "public" || key.publicKey.algorithm.name !== SIGNING_ALGORITHM) {
    throw new E2eeError("INVALID_KEY", "La clave pública no es Ed25519.");
  }
  if (await fingerprintSigningPublicKey(key.publicKey) !== key.fingerprint) {
    throw new E2eeError("KEY_FINGERPRINT_MISMATCH", "La huella no corresponde a la clave Ed25519.");
  }
}

export async function generateCustodianSigningKeyPair(): Promise<CustodianSigningPrivateKey> {
  try {
    const generated = await getSubtleCrypto().generateKey(
      { name: SIGNING_ALGORITHM },
      true,
      ["sign", "verify"],
    );
    if (!("privateKey" in generated)) {
      throw new Error("WebCrypto did not return a key pair");
    }
    const fingerprint = await fingerprintSigningPublicKey(generated.publicKey);
    return Object.freeze({ fingerprint, publicKey: generated.publicKey, keyPair: generated });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("INVALID_KEY", "No se pudo generar el par Ed25519.", { cause: error });
  }
}

export function toCustodianSigningPublicKey(
  key: CustodianSigningPrivateKey,
): CustodianSigningPublicKey {
  return Object.freeze({ fingerprint: key.fingerprint, publicKey: key.publicKey });
}

export async function exportCustodianSigningPublicKey(
  key: CustodianSigningPublicKey,
): Promise<ExportedCustodianSigningPublicKey> {
  await assertSigningPublicKey(key);
  const publicKeySpki = encodeBase64Url(await getSubtleCrypto().exportKey("spki", key.publicKey));
  return Object.freeze({
    format: SIGNING_PUBLIC_KEY_FORMAT,
    version: SIGNING_KEY_FORMAT_VERSION,
    algorithm: SIGNING_ALGORITHM,
    fingerprint: key.fingerprint,
    publicKeySpki,
  });
}

export async function exportCustodianSigningPrivateKey(
  key: CustodianSigningPrivateKey,
): Promise<ExportedCustodianSigningPrivateKey> {
  await assertSigningPublicKey(key);
  try {
    const [spki, pkcs8] = await Promise.all([
      getSubtleCrypto().exportKey("spki", key.keyPair.publicKey),
      getSubtleCrypto().exportKey("pkcs8", key.keyPair.privateKey),
    ]);
    return Object.freeze({
      format: SIGNING_PRIVATE_KEY_FORMAT,
      version: SIGNING_KEY_FORMAT_VERSION,
      algorithm: SIGNING_ALGORITHM,
      fingerprint: key.fingerprint,
      publicKeySpki: encodeBase64Url(spki),
      privateKeyPkcs8: encodeBase64Url(pkcs8),
    });
  } catch (error) {
    throw new E2eeError("INVALID_KEY", "No se pudo exportar el par Ed25519.", { cause: error });
  }
}

function parseSigningExport(value: unknown, privateExport: boolean): {
  readonly fingerprint: `sha256:${string}`;
  readonly publicKeySpki: Uint8Array<ArrayBuffer>;
  readonly privateKeyPkcs8?: Uint8Array<ArrayBuffer>;
} {
  const input = asRecord(value, "clave Ed25519", "INVALID_KEY");
  assertExactKeys(
    input,
    privateExport
      ? ["format", "version", "algorithm", "fingerprint", "publicKeySpki", "privateKeyPkcs8"]
      : ["format", "version", "algorithm", "fingerprint", "publicKeySpki"],
    "clave Ed25519",
    "INVALID_KEY",
  );
  const expectedFormat = privateExport ? SIGNING_PRIVATE_KEY_FORMAT : SIGNING_PUBLIC_KEY_FORMAT;
  if (
    input["format"] !== expectedFormat
    || input["version"] !== SIGNING_KEY_FORMAT_VERSION
    || input["algorithm"] !== SIGNING_ALGORITHM
    || !isSha256Digest(input["fingerprint"])
  ) {
    throw new E2eeError("INVALID_KEY", "Formato, versión, algoritmo o huella Ed25519 inválidos.");
  }
  return {
    fingerprint: input["fingerprint"],
    publicKeySpki: decodeBase64Url(input["publicKeySpki"], "publicKeySpki", "INVALID_KEY"),
    ...(privateExport
      ? { privateKeyPkcs8: decodeBase64Url(input["privateKeyPkcs8"], "privateKeyPkcs8", "INVALID_KEY") }
      : {}),
  };
}

export async function importCustodianSigningPublicKey(
  value: unknown,
): Promise<CustodianSigningPublicKey> {
  const parsed = parseSigningExport(value, false);
  try {
    const publicKey = await getSubtleCrypto().importKey(
      "spki",
      parsed.publicKeySpki,
      { name: SIGNING_ALGORITHM },
      true,
      ["verify"],
    );
    const actual = await fingerprintSigningPublicKey(publicKey);
    if (actual !== parsed.fingerprint) {
      throw new E2eeError("KEY_FINGERPRINT_MISMATCH", "La huella no corresponde a la clave Ed25519.");
    }
    return Object.freeze({ fingerprint: parsed.fingerprint, publicKey });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("INVALID_KEY", "La clave pública Ed25519 no es válida.", { cause: error });
  }
}

export async function importCustodianSigningPrivateKey(
  value: unknown,
): Promise<CustodianSigningPrivateKey> {
  const parsed = parseSigningExport(value, true);
  if (parsed.privateKeyPkcs8 === undefined) {
    throw new E2eeError("INVALID_KEY", "Falta la clave privada Ed25519.");
  }
  try {
    const [publicKey, privateKey] = await Promise.all([
      getSubtleCrypto().importKey("spki", parsed.publicKeySpki, { name: SIGNING_ALGORITHM }, true, ["verify"]),
      getSubtleCrypto().importKey("pkcs8", parsed.privateKeyPkcs8, { name: SIGNING_ALGORITHM }, true, ["sign"]),
    ]);
    const actual = await fingerprintSigningPublicKey(publicKey);
    if (actual !== parsed.fingerprint) {
      throw new E2eeError("KEY_FINGERPRINT_MISMATCH", "La huella no corresponde a la clave Ed25519.");
    }
    const probe = utf8("nombramientos-ed25519-key-pair-check-v1");
    const signature = await getSubtleCrypto().sign(SIGNING_ALGORITHM, privateKey, probe);
    if (!await getSubtleCrypto().verify(SIGNING_ALGORITHM, publicKey, signature, probe)) {
      throw new E2eeError("KEY_PAIR_MISMATCH", "El par Ed25519 no corresponde.");
    }
    return Object.freeze({
      fingerprint: parsed.fingerprint,
      publicKey,
      keyPair: { publicKey, privateKey },
    });
  } catch (error) {
    if (error instanceof E2eeError) throw error;
    throw new E2eeError("KEY_PAIR_MISMATCH", "El par Ed25519 no corresponde o no pudo importarse.", { cause: error });
  }
}

export function createTallyAttestationContext(value: unknown): TallyAttestationContext {
  const input = asRecord(value, "contexto de atestación", "SIGNATURE_INVALID");
  assertExactKeys(
    input,
    ["tenantId", "roundId", "manifestId", "manifestHash", "aggregateHash"],
    "contexto de atestación",
    "SIGNATURE_INVALID",
  );
  return Object.freeze({
    tenantId: assertUuid(input["tenantId"], "tenantId"),
    roundId: assertUuid(input["roundId"], "roundId"),
    manifestId: assertUuid(input["manifestId"], "manifestId"),
    manifestHash: assertDigest(input["manifestHash"], "manifestHash"),
    aggregateHash: assertDigest(input["aggregateHash"], "aggregateHash"),
    purpose: TALLY_ATTESTATION_PURPOSE,
    schemaVersion: 1,
  });
}

export async function signTallyAttestation(
  key: CustodianSigningPrivateKey,
  context: TallyAttestationContext,
): Promise<{ readonly signature: string; readonly contextHash: `sha256:${string}` }> {
  await assertSigningPublicKey(key);
  const canonical = canonicalize(context);
  try {
    const signature = await getSubtleCrypto().sign(
      SIGNING_ALGORITHM,
      key.keyPair.privateKey,
      utf8(canonical),
    );
    return Object.freeze({
      signature: encodeBase64Url(signature),
      contextHash: (await sha256(canonical)) as `sha256:${string}`,
    });
  } catch (error) {
    throw new E2eeError("SIGNATURE_INVALID", "No se pudo firmar la atestación Ed25519.", { cause: error });
  }
}

export async function verifyTallyAttestationSignature(
  key: CustodianSigningPublicKey,
  context: TallyAttestationContext,
  signature: string,
): Promise<boolean> {
  await assertSigningPublicKey(key);
  const bytes = decodeBase64Url(signature, "signature", "SIGNATURE_INVALID", 64);
  try {
    return await getSubtleCrypto().verify(
      SIGNING_ALGORITHM,
      key.publicKey,
      bytes,
      utf8(canonicalize(context)),
    );
  } catch (error) {
    throw new E2eeError("SIGNATURE_INVALID", "No se pudo verificar la atestación Ed25519.", { cause: error });
  }
}
