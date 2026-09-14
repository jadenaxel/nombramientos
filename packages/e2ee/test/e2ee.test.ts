import { beforeAll, describe, expect, it } from "vitest";
import {
  BALLOT_PURPOSE,
  BALLOT_SCHEMA_VERSION,
  computeBallotEnvelopeHash,
  computeBallotContentHash,
  computeTallyAggregateHash,
  createBallotAad,
  createEncryptedCustodianKeyBackup,
  createTallyAggregate,
  createTallyAttestationContext,
  exportCustodianPrivateKey,
  exportCustodianPublicKey,
  exportCustodianSigningPrivateKey,
  exportCustodianSigningPublicKey,
  generateCustodianKeyPair,
  generateCustodianSigningKeyPair,
  importCustodianPrivateKey,
  importCustodianPublicKey,
  importCustodianSigningPrivateKey,
  importCustodianSigningPublicKey,
  openBallotEnvelope,
  openEncryptedCustodianKeyBackup,
  sealBallotEnvelope,
  signTallyAttestation,
  toCustodianPublicKey,
  toCustodianSigningPublicKey,
  verifyTallyAttestationSignature,
  type BallotAad,
  type BallotEnvelope,
  type BallotEnvelopeBody,
  type BallotRules,
  type CustodianPrivateKey,
  type CustodianPublicKey,
  type CustodianSigningPrivateKey,
  type CustodianSigningPublicKey,
  type E2eeErrorCode,
} from "../src/index.js";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT_ID = "11111111-1111-4111-8111-111111111112";
const CYCLE_ID = "22222222-2222-4222-8222-222222222222";
const ROUND_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_ROUND_ID = "33333333-3333-4333-8333-333333333334";
const CANDIDATE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CANDIDATE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CANDIDATE_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OUTSIDE_CANDIDATE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

const rules: BallotRules = {
  candidateIds: [CANDIDATE_A, CANDIDATE_B, CANDIDATE_C],
  minSelections: 1,
  maxSelections: 2,
  allowAbstention: true,
};

const aadIdentity = {
  tenantId: TENANT_ID,
  cycleId: CYCLE_ID,
  roundId: ROUND_ID,
  purpose: BALLOT_PURPOSE,
  schemaVersion: BALLOT_SCHEMA_VERSION,
  roundVersion: 7,
} as const;

const payload = {
  schemaVersion: BALLOT_SCHEMA_VERSION,
  selections: [CANDIDATE_A, CANDIDATE_B],
  abstain: false,
} as const;

let custodianA: CustodianPrivateKey;
let custodianB: CustodianPrivateKey;
let custodianC: CustodianPrivateKey;
let publicA: CustodianPublicKey;
let publicB: CustodianPublicKey;
let signingA: CustodianSigningPrivateKey;
let signingB: CustodianSigningPrivateKey;
let signingPublicA: CustodianSigningPublicKey;
let aad: BallotAad;
let envelope: BallotEnvelope;

function jsonRoundTrip<T>(value: T): unknown {
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function bodyOf(value: BallotEnvelope): BallotEnvelopeBody {
  return {
    format: value.format,
    version: value.version,
    suite: value.suite,
    aad: value.aad,
    recipients: value.recipients,
  };
}

async function rehash(value: BallotEnvelope): Promise<BallotEnvelope> {
  const mutable = value as BallotEnvelope & { envelopeHash: string };
  mutable.envelopeHash = await computeBallotEnvelopeHash(bodyOf(value));
  return value;
}

function flipBase64UrlCharacter(value: string, index = 0): string {
  const original = value[index];
  if (original === undefined) throw new Error("fixture base64url vacío");
  const replacement = original === "A" ? "B" : "A";
  return `${value.slice(0, index)}${replacement}${value.slice(index + 1)}`;
}

async function expectCode(operation: Promise<unknown>, code: E2eeErrorCode): Promise<void> {
  await expect(operation).rejects.toMatchObject({ name: "E2eeError", code });
}

async function openWith(
  recipient: CustodianPrivateKey,
  expectedAad: BallotAad = aad,
  expectedRules: BallotRules = rules,
  selectedEnvelope: unknown = envelope,
) {
  return openBallotEnvelope({
    envelope: selectedEnvelope,
    recipient,
    expectedAad,
    rules: expectedRules,
  });
}

beforeAll(async () => {
  const generatedA = await generateCustodianKeyPair("custodian-a");
  const generatedB = await generateCustodianKeyPair("custodian-b");
  custodianC = await generateCustodianKeyPair("custodian-c");

  const exportedPrivateA = await exportCustodianPrivateKey(generatedA);
  const exportedPublicA = await exportCustodianPublicKey(toCustodianPublicKey(generatedA));
  const exportedPrivateB = await exportCustodianPrivateKey(generatedB);
  const exportedPublicB = await exportCustodianPublicKey(toCustodianPublicKey(generatedB));

  custodianA = await importCustodianPrivateKey(jsonRoundTrip(exportedPrivateA));
  custodianB = await importCustodianPrivateKey(jsonRoundTrip(exportedPrivateB));
  publicA = await importCustodianPublicKey(jsonRoundTrip(exportedPublicA));
  publicB = await importCustodianPublicKey(jsonRoundTrip(exportedPublicB));
  const generatedSigningA = await generateCustodianSigningKeyPair();
  const generatedSigningB = await generateCustodianSigningKeyPair();
  signingA = await importCustodianSigningPrivateKey(
    jsonRoundTrip(await exportCustodianSigningPrivateKey(generatedSigningA)),
  );
  signingB = await importCustodianSigningPrivateKey(
    jsonRoundTrip(await exportCustodianSigningPrivateKey(generatedSigningB)),
  );
  signingPublicA = await importCustodianSigningPublicKey(
    jsonRoundTrip(await exportCustodianSigningPublicKey(toCustodianSigningPublicKey(signingA))),
  );
  aad = await createBallotAad(aadIdentity, rules);
  envelope = await sealBallotEnvelope({
    payload,
    aad,
    rules,
    recipients: [publicA, publicB],
  });
});

describe("firma independiente de escrutinio", () => {
  const contextInput = {
    tenantId: TENANT_ID,
    roundId: ROUND_ID,
    manifestId: "44444444-4444-4444-8444-444444444444",
    manifestHash: `sha256:${"a".repeat(64)}`,
    aggregateHash: `sha256:${"b".repeat(64)}`,
  } as const;

  it("firma y verifica el contexto Ed25519 exacto que consume el servidor", async () => {
    const context = createTallyAttestationContext(contextInput);
    const attestation = await signTallyAttestation(signingA, context);
    expect(attestation.signature).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(attestation.contextHash).toMatch(/^sha256:[0-9a-f]{64}$/u);
    await expect(
      verifyTallyAttestationSignature(signingPublicA, context, attestation.signature),
    ).resolves.toBe(true);
    await expect(
      verifyTallyAttestationSignature(
        signingPublicA,
        createTallyAttestationContext({
          ...contextInput,
          aggregateHash: `sha256:${"c".repeat(64)}`,
        }),
        attestation.signature,
      ),
    ).resolves.toBe(false);
  });

  it("rechaza mezclar una clave pública y otra privada Ed25519", async () => {
    const exportedA = await exportCustodianSigningPrivateKey(signingA);
    const exportedB = await exportCustodianSigningPrivateKey(signingB);
    await expectCode(
      importCustodianSigningPrivateKey({ ...exportedA, privateKeyPkcs8: exportedB.privateKeyPkcs8 }),
      "KEY_PAIR_MISMATCH",
    );
  });
});

describe("copia cifrada de claves privadas del custodio", () => {
  const passphrase = "correct horse battery staple / custodia 2026";
  const deviceId = "55555555-5555-4555-8555-555555555555";

  it("recupera ambos pares únicamente con contraseña y contexto correctos", async () => {
    const backup = await createEncryptedCustodianKeyBackup({
      tenantId: TENANT_ID,
      deviceId,
      recipientId: custodianA.recipientId,
      createdAt: "2026-09-11T12:00:00.000Z",
      passphrase,
      hpke: custodianA,
      signing: signingA,
    });
    const restored = await openEncryptedCustodianKeyBackup(jsonRoundTrip(backup), passphrase);
    expect(restored.metadata).toEqual({
      tenantId: TENANT_ID,
      deviceId,
      recipientId: custodianA.recipientId,
      createdAt: "2026-09-11T12:00:00.000Z",
    });
    expect(restored.hpke.fingerprint).toBe(custodianA.fingerprint);
    expect(restored.signing.fingerprint).toBe(signingA.fingerprint);
    await expect(openWith(restored.hpke)).resolves.toEqual(payload);
  });

  it("rechaza contraseña incorrecta, ciphertext alterado y AAD externo alterado", async () => {
    const backup = await createEncryptedCustodianKeyBackup({
      tenantId: TENANT_ID,
      deviceId,
      recipientId: custodianA.recipientId,
      passphrase,
      hpke: custodianA,
      signing: signingA,
    });
    await expectCode(
      openEncryptedCustodianKeyBackup(backup, "this passphrase is definitely incorrect"),
      "KEY_BACKUP_DECRYPTION_FAILED",
    );
    const corrupted = structuredClone(backup);
    (corrupted as { ciphertext: string }).ciphertext = flipBase64UrlCharacter(corrupted.ciphertext);
    await expectCode(
      openEncryptedCustodianKeyBackup(corrupted, passphrase),
      "KEY_BACKUP_DECRYPTION_FAILED",
    );
    const crossed = { ...backup, tenantId: OTHER_TENANT_ID };
    await expectCode(
      openEncryptedCustodianKeyBackup(crossed, passphrase),
      "KEY_BACKUP_DECRYPTION_FAILED",
    );
  });

  it("no admite una contraseña de copia débil", async () => {
    await expectCode(
      createEncryptedCustodianKeyBackup({
        tenantId: TENANT_ID,
        deviceId,
        recipientId: custodianA.recipientId,
        passphrase: "short",
        hpke: custodianA,
        signing: signingA,
      }),
      "KEY_BACKUP_INVALID",
    );
  });
});

describe("claves de custodios", () => {
  it("genera, exporta e importa claves pública/privada conservando id y huella", async () => {
    expect(custodianA.recipientId).toBe("custodian-a");
    expect(publicA.recipientId).toBe(custodianA.recipientId);
    expect(publicA.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(publicA.fingerprint).toBe(custodianA.fingerprint);
    expect(await openWith(custodianA)).toEqual(payload);
  });

  it("rechaza un export privado cuyo par público/privado no corresponde", async () => {
    const exportedA = await exportCustodianPrivateKey(custodianA);
    const exportedB = await exportCustodianPrivateKey(custodianB);
    await expectCode(
      importCustodianPrivateKey({ ...exportedA, privateKey: exportedB.privateKey }),
      "KEY_PAIR_MISMATCH",
    );
  });
});

describe("sobre HPKE multi-destinatario", () => {
  it("hace roundtrip real para dos custodios con sellos independientes", async () => {
    expect(envelope.recipients).toHaveLength(2);
    expect(envelope.recipients[0]?.enc).not.toBe(envelope.recipients[1]?.enc);
    expect(envelope.recipients[0]?.ciphertext).not.toBe(envelope.recipients[1]?.ciphertext);
    expect(await computeBallotContentHash(envelope)).toMatch(/^sha256:[0-9a-f]{64}$/u);
    await expect(openWith(custodianA)).resolves.toEqual(payload);
    await expect(openWith(custodianB)).resolves.toEqual(payload);
  });

  it("rechaza un custodio que no figura como destinatario", async () => {
    await expectCode(openWith(custodianC), "RECIPIENT_NOT_FOUND");
  });

  it("rechaza otra clave privada aun si se presenta con la identidad del destinatario", async () => {
    const wrongPrivateKey: CustodianPrivateKey = {
      recipientId: custodianA.recipientId,
      fingerprint: custodianA.fingerprint,
      publicKey: custodianA.publicKey,
      keyPair: {
        publicKey: custodianA.publicKey,
        privateKey: custodianB.keyPair.privateKey,
      },
    };
    await expectCode(openWith(wrongPrivateKey), "DECRYPTION_FAILED");
  });

  it("detecta alteración de ciphertext mediante envelopeHash", async () => {
    const altered = structuredClone(envelope);
    const first = altered.recipients[0];
    if (first === undefined) throw new Error("fixture sin destinatario");
    (first as { ciphertext: string }).ciphertext = flipBase64UrlCharacter(first.ciphertext);
    await expectCode(openWith(custodianA, aad, rules, altered), "ENVELOPE_HASH_MISMATCH");
  });

  it("rechaza ciphertext corrupto por AEAD incluso si se recalcula envelopeHash", async () => {
    const altered = structuredClone(envelope);
    const first = altered.recipients.find((entry) => entry.recipientId === custodianA.recipientId);
    if (first === undefined) throw new Error("fixture sin destinatario A");
    (first as { ciphertext: string }).ciphertext = flipBase64UrlCharacter(
      first.ciphertext,
      first.ciphertext.length - 1,
    );
    await rehash(altered);
    await expectCode(openWith(custodianA, aad, rules, altered), "DECRYPTION_FAILED");
  });

  it("rechaza enc corrupto por HPKE incluso si se recalcula envelopeHash", async () => {
    const altered = structuredClone(envelope);
    const first = altered.recipients.find((entry) => entry.recipientId === custodianA.recipientId);
    if (first === undefined) throw new Error("fixture sin destinatario A");
    (first as { enc: string }).enc = flipBase64UrlCharacter(first.enc);
    await rehash(altered);
    await expectCode(openWith(custodianA, aad, rules, altered), "DECRYPTION_FAILED");
  });

  it("exige como mínimo dos custodios distintos", async () => {
    await expectCode(
      sealBallotEnvelope({ payload, aad, rules, recipients: [publicA] }),
      "INVALID_RECIPIENT",
    );
    await expectCode(
      sealBallotEnvelope({ payload, aad, rules, recipients: [publicA, publicA] }),
      "DUPLICATE_RECIPIENT",
    );
  });
});

describe("protección contra replay por AAD", () => {
  it("rechaza replay en otro tenant", async () => {
    await expectCode(openWith(custodianA, { ...aad, tenantId: OTHER_TENANT_ID }), "AAD_MISMATCH");
  });

  it("rechaza replay en otra ronda", async () => {
    await expectCode(openWith(custodianA, { ...aad, roundId: OTHER_ROUND_ID }), "AAD_MISMATCH");
  });

  it("rechaza replay contra otra versión de ronda", async () => {
    await expectCode(openWith(custodianA, { ...aad, roundVersion: aad.roundVersion + 1 }), "AAD_MISMATCH");
  });

  it("rechaza replay contra otro conjunto de candidatos/hash", async () => {
    const alternateRules: BallotRules = {
      ...rules,
      candidateIds: [CANDIDATE_A, CANDIDATE_B],
    };
    const alternateAad = await createBallotAad(aadIdentity, alternateRules);
    await expectCode(openWith(custodianA, alternateAad, alternateRules), "AAD_MISMATCH");
  });

  it("rechaza replay contra otras reglas/hash", async () => {
    const alternateRules: BallotRules = { ...rules, maxSelections: 1 };
    const alternateAad = await createBallotAad(aadIdentity, alternateRules);
    await expectCode(openWith(custodianA, alternateAad, alternateRules), "AAD_MISMATCH");
  });

  it("rechaza AAD incompleto antes de cifrar", async () => {
    const { rulesHash: _omitted, ...incompleteAad } = aad;
    await expectCode(
      sealBallotEnvelope({ payload, aad: incompleteAad, rules, recipients: [publicA, publicB] }),
      "INVALID_AAD",
    );
  });
});

describe("validación local de boleta", () => {
  it("rechaza candidato fuera de la lista", async () => {
    await expectCode(
      sealBallotEnvelope({
        payload: { ...payload, selections: [OUTSIDE_CANDIDATE] },
        aad,
        rules,
        recipients: [publicA, publicB],
      }),
      "BALLOT_INVALID",
    );
  });

  it("rechaza exceso de selecciones", async () => {
    await expectCode(
      sealBallotEnvelope({
        payload: { ...payload, selections: [CANDIDATE_A, CANDIDATE_B, CANDIDATE_C] },
        aad,
        rules,
        recipients: [publicA, publicB],
      }),
      "BALLOT_INVALID",
    );
  });

  it("rechaza candidato duplicado", async () => {
    await expectCode(
      sealBallotEnvelope({
        payload: { ...payload, selections: [CANDIDATE_A, CANDIDATE_A] },
        aad,
        rules,
        recipients: [publicA, publicB],
      }),
      "BALLOT_INVALID",
    );
  });

  it("rechaza abstención mezclada con una selección", async () => {
    await expectCode(
      sealBallotEnvelope({
        payload: { ...payload, selections: [CANDIDATE_A], abstain: true },
        aad,
        rules,
        recipients: [publicA, publicB],
      }),
      "BALLOT_INVALID",
    );
  });

  it("rechaza una clave reemplazada después de perder la original", async () => {
    const replacement = await generateCustodianKeyPair(custodianA.recipientId);
    await expectCode(openWith(replacement), "KEY_FINGERPRINT_MISMATCH");
  });
});

describe("escrutinio canónico en el cliente custodio", () => {
  it("produce agregado y decisión deterministas sin identidad del elector", async () => {
    const aggregate = createTallyAggregate({
      ...rules,
      vacancies: 1,
      rule: { kind: "PLURALITY" },
      ballots: [
        { schemaVersion: 1, selections: [CANDIDATE_A], abstain: false },
        { schemaVersion: 1, selections: [CANDIDATE_A, CANDIDATE_B], abstain: false },
        { schemaVersion: 1, selections: [], abstain: true },
      ],
    });
    expect(aggregate).toEqual({
      schemaVersion: 1,
      receivedBallots: 3,
      nonAbstainingBallots: 2,
      abstentions: 1,
      maxSelections: 2,
      candidates: [
        { candidateId: CANDIDATE_A, votes: 2 },
        { candidateId: CANDIDATE_B, votes: 1 },
        { candidateId: CANDIDATE_C, votes: 0 },
      ],
      rule: { kind: "PLURALITY" },
      decision: {
        status: "SELECTED",
        reason: "TOP_K",
        selectedCandidateIds: [CANDIDATE_A],
        tiebreakCandidateIds: [],
        unfilledSeats: 0,
      },
    });
    expect(await computeTallyAggregateHash(aggregate)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(aggregate)).not.toContain("elector");
  });

  it("normaliza mayoría estricta y detecta empate en el último cupo", () => {
    const aggregate = createTallyAggregate({
      ...rules,
      vacancies: 1,
      rule: { kind: "STRICT_MAJORITY" },
      ballots: [
        { schemaVersion: 1, selections: [CANDIDATE_A], abstain: false },
        { schemaVersion: 1, selections: [CANDIDATE_B], abstain: false },
      ],
    });
    expect(aggregate.rule).toEqual({
      kind: "STRICT_MAJORITY",
      threshold: 0.5,
      denominator: "NON_ABSTAINING_BALLOTS",
    });
    expect(aggregate.decision).toMatchObject({ status: "NO_SELECTION", reason: "THRESHOLD_NOT_MET" });
  });

  it("rechaza una boleta semánticamente inválida antes de contar", () => {
    expect(() => createTallyAggregate({
      ...rules,
      vacancies: 1,
      rule: { kind: "PLURALITY" },
      ballots: [{ schemaVersion: 1, selections: [OUTSIDE_CANDIDATE], abstain: false }],
    })).toThrowError(expect.objectContaining({ code: "BALLOT_INVALID" }));
  });
});
