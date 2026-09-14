import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";

export const CUSTODY_HPKE_SUITE = Object.freeze({
  kem: "DHKEM(P-256, HKDF-SHA256)",
  kemId: 0x0010,
  kdf: "HKDF-SHA256",
  kdfId: 0x0001,
  aead: "AES-256-GCM",
  aeadId: 0x0002,
} as const);

export const CUSTODY_SIGNING_ALGORITHM = "Ed25519" as const;
export const CUSTODY_ATTESTATION_PURPOSE = "nombramientos.tally.attestation" as const;

export class CustodyError extends Error {
  public constructor(
    public readonly statusCode: 400 | 403 | 404 | 409,
    public readonly code: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CustodyError";
  }
}

export interface CustodianKeyMaterial {
  readonly recipientId: string;
  readonly suite: typeof CUSTODY_HPKE_SUITE;
  readonly hpkePublicKey: string;
  readonly hpkeFingerprint: string;
  readonly signingAlgorithm: typeof CUSTODY_SIGNING_ALGORITHM;
  readonly signingPublicKeySpki: string;
  readonly signingFingerprint: string;
}

export interface FrozenRecipient {
  readonly recipientId: string;
  readonly hpkeFingerprint: string;
}

export interface EncryptedBallotContext {
  readonly tenantId: string;
  readonly cycleId: string;
  readonly roundId: string;
  readonly submissionRoundVersion: number;
  readonly candidateSetHash: string;
  readonly rulesHash: string;
  readonly recipients: readonly FrozenRecipient[];
}

export interface ValidatedEnvelopeHashes {
  readonly contentHash: string;
  readonly envelopeHash: string;
}

export interface TallyAttestationContext {
  readonly tenantId: string;
  readonly roundId: string;
  readonly manifestId: string;
  readonly manifestHash: string;
  readonly aggregateHash: string;
  readonly purpose: typeof CUSTODY_ATTESTATION_PURPOSE;
  readonly schemaVersion: 1;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const RECIPIENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u;

export function canonicalCustodyJson(value: unknown): string {
  return canonicalize(value, new Set<object>());
}

function canonicalize(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalid("Canonical JSON does not allow non-finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw invalid("Value is not canonical JSON");
  if (ancestors.has(value)) throw invalid("Canonical JSON does not allow cycles");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalize(entry, ancestors)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw invalid("Canonical JSON only accepts plain objects");
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => {
      const entry = record[key];
      if (entry === undefined) throw invalid("Canonical JSON does not allow undefined");
      return `${JSON.stringify(key)}:${canonicalize(entry, ancestors)}`;
    }).join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function custodySha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function hashCanonicalCustodyJson(value: unknown): string {
  return custodySha256(canonicalCustodyJson(value));
}

export function validateCustodianKeyMaterial(value: CustodianKeyMaterial): {
  readonly hpkeBytes: Buffer;
  readonly signingKey: KeyObject;
  readonly signingBytes: Buffer;
} {
  assertExactKeys(
    asRecord(value, "key material"),
    [
      "recipientId",
      "suite",
      "hpkePublicKey",
      "hpkeFingerprint",
      "signingAlgorithm",
      "signingPublicKeySpki",
      "signingFingerprint",
    ],
    "key material",
  );
  if (!RECIPIENT_PATTERN.test(value.recipientId)) throw invalid("recipientId is invalid");
  assertHpkeSuite(value.suite);
  if (value.signingAlgorithm !== CUSTODY_SIGNING_ALGORITHM) {
    throw invalid("Only Ed25519 signing keys are supported");
  }

  const hpkeBytes = decodeBase64Url(value.hpkePublicKey, "hpkePublicKey", 65);
  if (hpkeBytes[0] !== 0x04) throw invalid("HPKE public key must be an uncompressed P-256 point");
  try {
    const key = createPublicKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: hpkeBytes.subarray(1, 33).toString("base64url"),
        y: hpkeBytes.subarray(33, 65).toString("base64url"),
      },
      format: "jwk",
    });
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
      throw new Error("not P-256");
    }
  } catch (error) {
    throw invalid("HPKE public key is not a valid P-256 point", error);
  }
  assertFingerprint(value.hpkeFingerprint, hpkeBytes, "hpkeFingerprint");

  const signingBytes = decodeBase64Url(value.signingPublicKeySpki, "signingPublicKeySpki");
  if (signingBytes.byteLength > 256) throw invalid("Ed25519 SPKI is too large");
  let signingKey: KeyObject;
  try {
    signingKey = createPublicKey({ key: signingBytes, format: "der", type: "spki" });
    if (signingKey.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
    const canonicalSpki = signingKey.export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(canonicalSpki) || !sameBytes(canonicalSpki, signingBytes)) {
      throw new Error("non-canonical SPKI");
    }
  } catch (error) {
    throw invalid("Signing public key is not canonical Ed25519 SPKI", error);
  }
  assertFingerprint(value.signingFingerprint, signingBytes, "signingFingerprint");
  return { hpkeBytes, signingKey, signingBytes };
}

export function buildTallyAttestationContext(input: {
  readonly tenantId: string;
  readonly roundId: string;
  readonly manifestId: string;
  readonly manifestHash: string;
  readonly aggregateHash: string;
}): TallyAttestationContext {
  for (const [name, value] of [
    ["tenantId", input.tenantId],
    ["roundId", input.roundId],
    ["manifestId", input.manifestId],
  ] as const) {
    if (!UUID_PATTERN.test(value)) throw invalid(`${name} must be a canonical lowercase UUID`);
  }
  assertDigest(input.manifestHash, "manifestHash");
  assertDigest(input.aggregateHash, "aggregateHash");
  return Object.freeze({
    tenantId: input.tenantId,
    roundId: input.roundId,
    manifestId: input.manifestId,
    manifestHash: input.manifestHash,
    aggregateHash: input.aggregateHash,
    purpose: CUSTODY_ATTESTATION_PURPOSE,
    schemaVersion: 1,
  });
}

export function verifyTallyAttestation(input: {
  readonly context: TallyAttestationContext;
  readonly signingPublicKeySpki: string;
  readonly signingFingerprint: string;
  readonly signature: string;
}): string {
  const signingBytes = decodeBase64Url(input.signingPublicKeySpki, "signingPublicKeySpki");
  assertFingerprint(input.signingFingerprint, signingBytes, "signingFingerprint");
  let key: KeyObject;
  try {
    key = createPublicKey({ key: signingBytes, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") throw new Error("not Ed25519");
  } catch (error) {
    throw invalid("Frozen signing key is not Ed25519 SPKI", error);
  }
  const signature = decodeBase64Url(input.signature, "signature", 64);
  const canonical = canonicalCustodyJson(input.context);
  if (!verify(null, Buffer.from(canonical, "utf8"), key, signature)) {
    throw new CustodyError(409, "ATTESTATION_SIGNATURE_INVALID", "Ed25519 attestation is invalid");
  }
  return custodySha256(canonical);
}

export function validateEncryptedBallotEnvelope(
  value: unknown,
  storedContentHash: string,
  expected: EncryptedBallotContext,
): ValidatedEnvelopeHashes {
  assertDigest(storedContentHash, "contentHash");
  const envelope = asRecord(value, "envelope");
  assertExactKeys(
    envelope,
    ["format", "version", "suite", "aad", "recipients", "envelopeHash"],
    "envelope",
  );
  if (envelope["format"] !== "nombramientos.hpke-ballot-envelope" || envelope["version"] !== 1) {
    throw conflict("E2EE_ENVELOPE_REQUIRED", "Submission is not a supported E2EE envelope");
  }
  assertHpkeSuite(envelope["suite"]);
  if (typeof envelope["envelopeHash"] !== "string") throw invalid("envelopeHash is invalid");
  assertDigest(envelope["envelopeHash"], "envelopeHash");

  const aad = asRecord(envelope["aad"], "envelope.aad");
  assertExactKeys(
    aad,
    [
      "tenantId",
      "cycleId",
      "roundId",
      "purpose",
      "schemaVersion",
      "roundVersion",
      "candidateSetHash",
      "rulesHash",
    ],
    "envelope.aad",
  );
  const expectedAad: Readonly<Record<string, unknown>> = {
    tenantId: expected.tenantId,
    cycleId: expected.cycleId,
    roundId: expected.roundId,
    purpose: "nombramientos.ballot.selections",
    schemaVersion: 1,
    roundVersion: expected.submissionRoundVersion,
    candidateSetHash: expected.candidateSetHash,
    rulesHash: expected.rulesHash,
  };
  for (const [key, expectedValue] of Object.entries(expectedAad)) {
    if (aad[key] !== expectedValue) {
      throw conflict("ENVELOPE_CONTEXT_MISMATCH", `Encrypted ballot context mismatch: ${key}`);
    }
  }

  if (!Array.isArray(envelope["recipients"]) || envelope["recipients"].length < 2) {
    throw conflict("CUSTODY_RECIPIENTS_MISMATCH", "Encrypted ballot has fewer than two recipients");
  }
  const actualRecipients = envelope["recipients"].map((item, index) => {
    const recipient = asRecord(item, `recipients[${index}]`);
    assertExactKeys(recipient, ["recipientId", "fingerprint", "enc", "ciphertext"], `recipients[${index}]`);
    if (typeof recipient["recipientId"] !== "string" || !RECIPIENT_PATTERN.test(recipient["recipientId"])) {
      throw invalid(`recipients[${index}].recipientId is invalid`);
    }
    if (typeof recipient["fingerprint"] !== "string") throw invalid("Recipient fingerprint is invalid");
    assertDigest(recipient["fingerprint"], `recipients[${index}].fingerprint`);
    decodeBase64Url(recipient["enc"], `recipients[${index}].enc`, 65);
    const ciphertext = decodeBase64Url(recipient["ciphertext"], `recipients[${index}].ciphertext`);
    if (ciphertext.byteLength <= 16) throw invalid("Recipient ciphertext is too short");
    return {
      recipientId: recipient["recipientId"],
      hpkeFingerprint: recipient["fingerprint"],
    };
  }).sort(compareRecipients);
  const frozenRecipients = [...expected.recipients].sort(compareRecipients);
  if (canonicalCustodyJson(actualRecipients) !== canonicalCustodyJson(frozenRecipients)) {
    throw conflict("CUSTODY_RECIPIENTS_MISMATCH", "Encrypted ballot recipients differ from the frozen custody set");
  }

  const body = {
    format: envelope["format"],
    version: envelope["version"],
    suite: envelope["suite"],
    aad: envelope["aad"],
    recipients: envelope["recipients"],
  };
  if (hashCanonicalCustodyJson(body) !== envelope["envelopeHash"]) {
    throw conflict("ENVELOPE_HASH_MISMATCH", "Encrypted ballot envelope hash is invalid");
  }
  if (hashCanonicalCustodyJson(envelope) !== storedContentHash) {
    throw conflict("CONTENT_HASH_MISMATCH", "Stored encrypted ballot content hash is invalid");
  }
  return { contentHash: storedContentHash, envelopeHash: envelope["envelopeHash"] };
}

export function assertDigest(value: string, name: string): void {
  if (!DIGEST_PATTERN.test(value)) throw invalid(`${name} must be a canonical SHA-256 digest`);
}

function assertHpkeSuite(value: unknown): void {
  const suite = asRecord(value, "suite");
  assertExactKeys(suite, ["kem", "kemId", "kdf", "kdfId", "aead", "aeadId"], "suite");
  for (const [key, expected] of Object.entries(CUSTODY_HPKE_SUITE)) {
    if (suite[key] !== expected) throw conflict("HPKE_SUITE_MISMATCH", "Only the required RFC 9180 suite is allowed");
  }
}

function assertFingerprint(value: string, bytes: Buffer, name: string): void {
  assertDigest(value, name);
  const actual = custodySha256(bytes);
  if (!sameBytes(Buffer.from(value), Buffer.from(actual))) {
    throw conflict("KEY_FINGERPRINT_MISMATCH", `${name} does not match the supplied public key`);
  }
}

function decodeBase64Url(value: unknown, name: string, expectedLength?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
    throw invalid(`${name} must be canonical base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value || (expectedLength !== undefined && bytes.byteLength !== expectedLength)) {
    throw invalid(`${name} has invalid base64url encoding or length`);
  }
  return bytes;
}

function asRecord(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalid(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(value: Record<string, unknown>, expected: readonly string[], name: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw invalid(`${name} has missing or unsupported fields`);
  }
}

function compareRecipients(left: FrozenRecipient, right: FrozenRecipient): number {
  return left.recipientId < right.recipientId ? -1 : left.recipientId > right.recipientId ? 1 : 0;
}

function sameBytes(left: Buffer, right: Buffer): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function invalid(message: string, cause?: unknown): CustodyError {
  return new CustodyError(400, "CUSTODY_VALIDATION_ERROR", message, { cause });
}

function conflict(code: string, message: string): CustodyError {
  return new CustodyError(409, code, message);
}
