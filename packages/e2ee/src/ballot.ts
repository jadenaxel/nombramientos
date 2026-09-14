import { E2eeError } from "./errors.js";
import {
  asRecord,
  assertExactKeys,
  assertRecipientId,
  canonicalize,
  decodeBase64Url,
  decodeUtf8,
  encodeBase64Url,
  isSha256Digest,
  sha256,
  utf8,
} from "./internal.js";
import {
  assertCustodianPrivateKey,
  assertCustodianPublicKey,
  type CustodianPrivateKey,
  type CustodianPublicKey,
} from "./keys.js";
import { HPKE_INFO, HPKE_SUITE, hpkeSuite, type HpkeSuiteDescriptor } from "./suite.js";

export const BALLOT_PURPOSE = "nombramientos.ballot.selections" as const;
export const BALLOT_SCHEMA_VERSION = 1 as const;
export const ENVELOPE_FORMAT = "nombramientos.hpke-ballot-envelope" as const;
export const ENVELOPE_VERSION = 1 as const;

export type Sha256Digest = `sha256:${string}`;

export interface BallotRules {
  readonly candidateIds: readonly string[];
  readonly minSelections: number;
  readonly maxSelections: number;
  readonly allowAbstention: boolean;
}

export interface BallotPayload {
  readonly schemaVersion: typeof BALLOT_SCHEMA_VERSION;
  readonly selections: readonly string[];
  readonly abstain: boolean;
}

export interface BallotAad {
  readonly tenantId: string;
  readonly cycleId: string;
  readonly roundId: string;
  readonly purpose: typeof BALLOT_PURPOSE;
  readonly schemaVersion: typeof BALLOT_SCHEMA_VERSION;
  readonly roundVersion: number;
  readonly candidateSetHash: Sha256Digest;
  readonly rulesHash: Sha256Digest;
}

export interface BallotAadIdentity {
  readonly tenantId: string;
  readonly cycleId: string;
  readonly roundId: string;
  readonly purpose: typeof BALLOT_PURPOSE;
  readonly schemaVersion: typeof BALLOT_SCHEMA_VERSION;
  readonly roundVersion: number;
}

export interface EncryptedBallotRecipient {
  readonly recipientId: string;
  readonly fingerprint: Sha256Digest;
  readonly enc: string;
  readonly ciphertext: string;
}

export interface BallotEnvelopeBody {
  readonly format: typeof ENVELOPE_FORMAT;
  readonly version: typeof ENVELOPE_VERSION;
  readonly suite: HpkeSuiteDescriptor;
  readonly aad: BallotAad;
  readonly recipients: readonly EncryptedBallotRecipient[];
}

export interface BallotEnvelope extends BallotEnvelopeBody {
  readonly envelopeHash: Sha256Digest;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function assertUuid(value: unknown, label: string, code: "INVALID_AAD" | "BALLOT_INVALID"): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new E2eeError(code, `${label} debe ser un UUID canónico en minúsculas.`);
  }
  return value;
}

function assertSafeInteger(
  value: unknown,
  label: string,
  minimum: number,
  code: "INVALID_AAD" | "BALLOT_INVALID",
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new E2eeError(code, `${label} debe ser un entero seguro mayor o igual que ${minimum}.`);
  }
  return value as number;
}

export function validateBallotRules(value: unknown): BallotRules {
  const rules = asRecord(value, "rules", "BALLOT_INVALID");
  assertExactKeys(
    rules,
    ["candidateIds", "minSelections", "maxSelections", "allowAbstention"],
    "rules",
    "BALLOT_INVALID",
  );
  if (!Array.isArray(rules["candidateIds"]) || rules["candidateIds"].length === 0) {
    throw new E2eeError("BALLOT_INVALID", "candidateIds debe ser una lista no vacía.");
  }
  const candidateIds = rules["candidateIds"].map((candidateId, index) =>
    assertUuid(candidateId, `candidateIds[${index}]`, "BALLOT_INVALID"),
  );
  if (new Set(candidateIds).size !== candidateIds.length) {
    throw new E2eeError("BALLOT_INVALID", "candidateIds no admite candidatos duplicados.");
  }

  const minSelections = assertSafeInteger(
    rules["minSelections"],
    "minSelections",
    0,
    "BALLOT_INVALID",
  );
  const maxSelections = assertSafeInteger(
    rules["maxSelections"],
    "maxSelections",
    1,
    "BALLOT_INVALID",
  );
  if (maxSelections < minSelections || maxSelections > candidateIds.length) {
    throw new E2eeError(
      "BALLOT_INVALID",
      "La cardinalidad debe cumplir minSelections <= maxSelections <= candidateIds.length.",
    );
  }
  if (typeof rules["allowAbstention"] !== "boolean") {
    throw new E2eeError("BALLOT_INVALID", "allowAbstention debe ser booleano.");
  }

  return Object.freeze({
    candidateIds: Object.freeze(candidateIds),
    minSelections,
    maxSelections,
    allowAbstention: rules["allowAbstention"],
  });
}

export function validateBallotPayload(value: unknown, rulesInput: unknown): BallotPayload {
  const rules = validateBallotRules(rulesInput);
  const ballot = asRecord(value, "ballot", "BALLOT_INVALID");
  assertExactKeys(
    ballot,
    ["schemaVersion", "selections", "abstain"],
    "ballot",
    "BALLOT_INVALID",
  );
  if (ballot["schemaVersion"] !== BALLOT_SCHEMA_VERSION) {
    throw new E2eeError("BALLOT_INVALID", "schemaVersion de boleta no soportado.");
  }
  if (!Array.isArray(ballot["selections"])) {
    throw new E2eeError("BALLOT_INVALID", "selections debe ser una lista.");
  }
  const selections = ballot["selections"].map((candidateId, index) =>
    assertUuid(candidateId, `selections[${index}]`, "BALLOT_INVALID"),
  );
  if (new Set(selections).size !== selections.length) {
    throw new E2eeError("BALLOT_INVALID", "Una boleta no admite selecciones duplicadas.");
  }
  const allowed = new Set(rules.candidateIds);
  if (selections.some((candidateId) => !allowed.has(candidateId))) {
    throw new E2eeError("BALLOT_INVALID", "La boleta contiene un candidato fuera de la lista.");
  }
  if (typeof ballot["abstain"] !== "boolean") {
    throw new E2eeError("BALLOT_INVALID", "abstain debe ser booleano.");
  }
  if (ballot["abstain"]) {
    if (!rules.allowAbstention) {
      throw new E2eeError("BALLOT_INVALID", "Las reglas no permiten abstención.");
    }
    if (selections.length !== 0) {
      throw new E2eeError(
        "BALLOT_INVALID",
        "Una abstención no puede mezclarse con selecciones de candidatos.",
      );
    }
  } else if (
    selections.length < rules.minSelections ||
    selections.length > rules.maxSelections
  ) {
    throw new E2eeError(
      "BALLOT_INVALID",
      "La cantidad de selecciones queda fuera de la cardinalidad permitida.",
    );
  }

  return Object.freeze({
    schemaVersion: BALLOT_SCHEMA_VERSION,
    selections: Object.freeze(selections),
    abstain: ballot["abstain"],
  });
}

export async function hashCandidateSet(candidateIdsInput: unknown): Promise<Sha256Digest> {
  const rules = validateBallotRules({
    candidateIds: candidateIdsInput,
    minSelections: 0,
    maxSelections: Array.isArray(candidateIdsInput) ? candidateIdsInput.length : 1,
    allowAbstention: true,
  });
  const candidateIds = [...rules.candidateIds].sort();
  return (await sha256(canonicalize({ candidateIds }))) as Sha256Digest;
}

export async function hashBallotRules(rulesInput: unknown): Promise<Sha256Digest> {
  const rules = validateBallotRules(rulesInput);
  return (await sha256(
    canonicalize({
      allowAbstention: rules.allowAbstention,
      maxSelections: rules.maxSelections,
      minSelections: rules.minSelections,
    }),
  )) as Sha256Digest;
}

export function validateBallotAad(value: unknown): BallotAad {
  const aad = asRecord(value, "aad", "INVALID_AAD");
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
    "aad",
    "INVALID_AAD",
  );
  const tenantId = assertUuid(aad["tenantId"], "tenantId", "INVALID_AAD");
  const cycleId = assertUuid(aad["cycleId"], "cycleId", "INVALID_AAD");
  const roundId = assertUuid(aad["roundId"], "roundId", "INVALID_AAD");
  if (aad["purpose"] !== BALLOT_PURPOSE) {
    throw new E2eeError("INVALID_AAD", "purpose de AAD no soportado.");
  }
  if (aad["schemaVersion"] !== BALLOT_SCHEMA_VERSION) {
    throw new E2eeError("INVALID_AAD", "schemaVersion de AAD no soportado.");
  }
  const roundVersion = assertSafeInteger(aad["roundVersion"], "roundVersion", 1, "INVALID_AAD");
  if (!isSha256Digest(aad["candidateSetHash"]) || !isSha256Digest(aad["rulesHash"])) {
    throw new E2eeError("INVALID_AAD", "Los hashes de AAD deben ser SHA-256 canónicos.");
  }
  return Object.freeze({
    tenantId,
    cycleId,
    roundId,
    purpose: BALLOT_PURPOSE,
    schemaVersion: BALLOT_SCHEMA_VERSION,
    roundVersion,
    candidateSetHash: aad["candidateSetHash"],
    rulesHash: aad["rulesHash"],
  });
}

export async function createBallotAad(
  identityInput: unknown,
  rulesInput: unknown,
): Promise<BallotAad> {
  const identity = asRecord(identityInput, "aad identity", "INVALID_AAD");
  assertExactKeys(
    identity,
    ["tenantId", "cycleId", "roundId", "purpose", "schemaVersion", "roundVersion"],
    "aad identity",
    "INVALID_AAD",
  );
  const rules = validateBallotRules(rulesInput);
  return validateBallotAad({
    tenantId: identity["tenantId"],
    cycleId: identity["cycleId"],
    roundId: identity["roundId"],
    purpose: identity["purpose"],
    schemaVersion: identity["schemaVersion"],
    roundVersion: identity["roundVersion"],
    candidateSetHash: await hashCandidateSet(rules.candidateIds),
    rulesHash: await hashBallotRules(rules),
  });
}

async function assertContextHashes(aad: BallotAad, rules: BallotRules): Promise<void> {
  const [candidateSetHash, rulesHash] = await Promise.all([
    hashCandidateSet(rules.candidateIds),
    hashBallotRules(rules),
  ]);
  if (candidateSetHash !== aad.candidateSetHash || rulesHash !== aad.rulesHash) {
    throw new E2eeError(
      "CONTEXT_HASH_MISMATCH",
      "candidateSetHash o rulesHash no corresponde a las reglas locales.",
    );
  }
}

function parseSuite(value: unknown): HpkeSuiteDescriptor {
  const suite = asRecord(value, "suite", "INVALID_ENVELOPE");
  assertExactKeys(
    suite,
    ["kem", "kemId", "kdf", "kdfId", "aead", "aeadId"],
    "suite",
    "INVALID_ENVELOPE",
  );
  for (const key of Object.keys(HPKE_SUITE) as (keyof HpkeSuiteDescriptor)[]) {
    if (suite[key] !== HPKE_SUITE[key]) {
      throw new E2eeError("INVALID_ENVELOPE", "El sobre declara una suite HPKE no soportada.");
    }
  }
  return HPKE_SUITE;
}

function parseEnvelopeRecipient(value: unknown): EncryptedBallotRecipient {
  const recipient = asRecord(value, "recipient", "INVALID_ENVELOPE");
  assertExactKeys(
    recipient,
    ["recipientId", "fingerprint", "enc", "ciphertext"],
    "recipient",
    "INVALID_ENVELOPE",
  );
  const recipientId = assertRecipientId(recipient["recipientId"], "INVALID_ENVELOPE");
  if (!isSha256Digest(recipient["fingerprint"])) {
    throw new E2eeError("INVALID_ENVELOPE", "fingerprint del destinatario es inválido.");
  }
  if (typeof recipient["enc"] !== "string" || typeof recipient["ciphertext"] !== "string") {
    throw new E2eeError("INVALID_ENVELOPE", "enc y ciphertext deben ser strings base64url.");
  }
  decodeBase64Url(
    recipient["enc"],
    "enc",
    "INVALID_ENVELOPE",
    hpkeSuite.kem.encSize,
  );
  const ciphertext = decodeBase64Url(recipient["ciphertext"], "ciphertext", "INVALID_ENVELOPE");
  if (ciphertext.byteLength <= 16) {
    throw new E2eeError("INVALID_ENVELOPE", "ciphertext HPKE es demasiado corto.");
  }
  return Object.freeze({
    recipientId,
    fingerprint: recipient["fingerprint"],
    enc: recipient["enc"],
    ciphertext: recipient["ciphertext"],
  });
}

function parseEnvelopeBody(value: unknown): BallotEnvelopeBody {
  const body = asRecord(value, "envelope body", "INVALID_ENVELOPE");
  assertExactKeys(
    body,
    ["format", "version", "suite", "aad", "recipients"],
    "envelope body",
    "INVALID_ENVELOPE",
  );
  if (body["format"] !== ENVELOPE_FORMAT || body["version"] !== ENVELOPE_VERSION) {
    throw new E2eeError("INVALID_ENVELOPE", "Formato o versión de sobre no soportado.");
  }
  if (!Array.isArray(body["recipients"]) || body["recipients"].length < 2) {
    throw new E2eeError("INVALID_ENVELOPE", "El sobre requiere al menos dos destinatarios.");
  }
  const recipients = body["recipients"].map(parseEnvelopeRecipient);
  const ids = new Set<string>();
  const fingerprints = new Set<string>();
  for (const recipient of recipients) {
    if (ids.has(recipient.recipientId) || fingerprints.has(recipient.fingerprint)) {
      throw new E2eeError(
        "DUPLICATE_RECIPIENT",
        "El sobre no admite recipientId ni huellas de clave duplicadas.",
      );
    }
    ids.add(recipient.recipientId);
    fingerprints.add(recipient.fingerprint);
  }
  return Object.freeze({
    format: ENVELOPE_FORMAT,
    version: ENVELOPE_VERSION,
    suite: parseSuite(body["suite"]),
    aad: validateBallotAad(body["aad"]),
    recipients: Object.freeze(recipients),
  });
}

export async function computeBallotEnvelopeHash(value: unknown): Promise<Sha256Digest> {
  const body = parseEnvelopeBody(value);
  return (await sha256(canonicalize(body))) as Sha256Digest;
}

export async function verifyBallotEnvelope(value: unknown): Promise<BallotEnvelope> {
  const envelope = asRecord(value, "envelope", "INVALID_ENVELOPE");
  assertExactKeys(
    envelope,
    ["format", "version", "suite", "aad", "recipients", "envelopeHash"],
    "envelope",
    "INVALID_ENVELOPE",
  );
  if (!isSha256Digest(envelope["envelopeHash"])) {
    throw new E2eeError("INVALID_ENVELOPE", "envelopeHash no es SHA-256 canónico.");
  }
  const body = parseEnvelopeBody({
    format: envelope["format"],
    version: envelope["version"],
    suite: envelope["suite"],
    aad: envelope["aad"],
    recipients: envelope["recipients"],
  });
  const actualHash = (await sha256(canonicalize(body))) as Sha256Digest;
  if (actualHash !== envelope["envelopeHash"]) {
    throw new E2eeError(
      "ENVELOPE_HASH_MISMATCH",
      "El hash del sobre no corresponde a su contenido.",
    );
  }
  return Object.freeze({ ...body, envelopeHash: envelope["envelopeHash"] });
}

/** Digest of the complete persisted envelope, including its independently checked body hash. */
export async function computeBallotContentHash(value: unknown): Promise<Sha256Digest> {
  const envelope = await verifyBallotEnvelope(value);
  return (await sha256(canonicalize(envelope))) as Sha256Digest;
}

export async function sealBallotEnvelope(input: {
  readonly payload: unknown;
  readonly aad: unknown;
  readonly rules: unknown;
  readonly recipients: readonly CustodianPublicKey[];
}): Promise<BallotEnvelope> {
  const rules = validateBallotRules(input.rules);
  const payload = validateBallotPayload(input.payload, rules);
  const aad = validateBallotAad(input.aad);
  await assertContextHashes(aad, rules);

  if (!Array.isArray(input.recipients) || input.recipients.length < 2) {
    throw new E2eeError("INVALID_RECIPIENT", "Se requieren al menos dos custodios destinatarios.");
  }
  const recipients = [...input.recipients].sort((left, right) =>
    left.recipientId < right.recipientId ? -1 : left.recipientId > right.recipientId ? 1 : 0,
  );
  const ids = new Set<string>();
  const fingerprints = new Set<string>();
  for (const recipient of recipients) {
    await assertCustodianPublicKey(recipient);
    if (ids.has(recipient.recipientId) || fingerprints.has(recipient.fingerprint)) {
      throw new E2eeError(
        "DUPLICATE_RECIPIENT",
        "No se permiten recipientId ni claves públicas duplicadas.",
      );
    }
    ids.add(recipient.recipientId);
    fingerprints.add(recipient.fingerprint);
  }

  const plaintext = utf8(canonicalize(payload));
  const aadBytes = utf8(canonicalize(aad));
  let encryptedRecipients: EncryptedBallotRecipient[];
  try {
    encryptedRecipients = await Promise.all(
      recipients.map(async (recipient) => {
        const sealed = await hpkeSuite.seal(
          { recipientPublicKey: recipient.publicKey, info: HPKE_INFO },
          plaintext,
          aadBytes,
        );
        return Object.freeze({
          recipientId: recipient.recipientId,
          fingerprint: recipient.fingerprint,
          enc: encodeBase64Url(sealed.enc),
          ciphertext: encodeBase64Url(sealed.ct),
        });
      }),
    );
  } catch (error) {
    throw new E2eeError("ENCRYPTION_FAILED", "HPKE no pudo sellar la boleta.", { cause: error });
  }

  const body: BallotEnvelopeBody = Object.freeze({
    format: ENVELOPE_FORMAT,
    version: ENVELOPE_VERSION,
    suite: HPKE_SUITE,
    aad,
    recipients: Object.freeze(encryptedRecipients),
  });
  return Object.freeze({
    ...body,
    envelopeHash: await computeBallotEnvelopeHash(body),
  });
}

export async function openBallotEnvelope(input: {
  readonly envelope: unknown;
  readonly recipient: CustodianPrivateKey;
  readonly expectedAad: unknown;
  readonly rules: unknown;
}): Promise<BallotPayload> {
  const envelope = await verifyBallotEnvelope(input.envelope);
  const expectedAad = validateBallotAad(input.expectedAad);
  const rules = validateBallotRules(input.rules);
  await assertContextHashes(expectedAad, rules);
  if (canonicalize(envelope.aad) !== canonicalize(expectedAad)) {
    throw new E2eeError(
      "AAD_MISMATCH",
      "El AAD del sobre no coincide exactamente con el contexto esperado.",
    );
  }

  await assertCustodianPrivateKey(input.recipient);
  const recipient = envelope.recipients.find(
    (candidate) => candidate.recipientId === input.recipient.recipientId,
  );
  if (recipient === undefined) {
    throw new E2eeError("RECIPIENT_NOT_FOUND", "El custodio no es destinatario de este sobre.");
  }
  if (recipient.fingerprint !== input.recipient.fingerprint) {
    throw new E2eeError(
      "KEY_FINGERPRINT_MISMATCH",
      "La clave del custodio no coincide con la huella registrada en el sobre.",
    );
  }

  let plaintext: ArrayBuffer;
  try {
    plaintext = await hpkeSuite.open(
      {
        recipientKey: input.recipient.keyPair,
        enc: decodeBase64Url(
          recipient.enc,
          "enc",
          "INVALID_ENVELOPE",
          hpkeSuite.kem.encSize,
        ),
        info: HPKE_INFO,
      },
      decodeBase64Url(recipient.ciphertext, "ciphertext", "INVALID_ENVELOPE"),
      utf8(canonicalize(expectedAad)),
    );
  } catch (error) {
    throw new E2eeError(
      "DECRYPTION_FAILED",
      "HPKE rechazó la clave, el ciphertext, enc o el AAD.",
      { cause: error },
    );
  }

  const decoded = decodeUtf8(plaintext);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded) as unknown;
  } catch (error) {
    throw new E2eeError("BALLOT_INVALID", "El payload descifrado no es JSON válido.", {
      cause: error,
    });
  }
  if (canonicalize(parsed) !== decoded) {
    throw new E2eeError("BALLOT_INVALID", "El payload descifrado no usa JSON canónico.");
  }
  return validateBallotPayload(parsed, rules);
}
