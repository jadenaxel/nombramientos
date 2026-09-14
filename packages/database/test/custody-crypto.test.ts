import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CUSTODY_HPKE_SUITE,
  CUSTODY_SIGNING_ALGORITHM,
  CustodyError,
  buildTallyAttestationContext,
  canonicalCustodyJson,
  custodySha256,
  hashCanonicalCustodyJson,
  validateCustodianKeyMaterial,
  validateEncryptedBallotEnvelope,
  verifyTallyAttestation,
  type CustodianKeyMaterial,
} from "../src/custody-crypto.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const cycleId = "22222222-2222-4222-8222-222222222222";
const roundId = "33333333-3333-4333-8333-333333333333";
const manifestId = "44444444-4444-4444-8444-444444444444";
const candidateSetHash = `sha256:${"a".repeat(64)}`;
const rulesHash = `sha256:${"b".repeat(64)}`;
const aggregateHash = `sha256:${"c".repeat(64)}`;
const manifestHash = `sha256:${"d".repeat(64)}`;

function keyFixture(recipientId: string) {
  const hpke = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = hpke.publicKey.export({ format: "jwk" });
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("P-256 JWK fixture is incomplete");
  const hpkeBytes = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  const signing = generateKeyPairSync("ed25519");
  const signingSpki = signing.publicKey.export({ format: "der", type: "spki" });
  const material: CustodianKeyMaterial = {
    recipientId,
    suite: CUSTODY_HPKE_SUITE,
    hpkePublicKey: hpkeBytes.toString("base64url"),
    hpkeFingerprint: custodySha256(hpkeBytes),
    signingAlgorithm: CUSTODY_SIGNING_ALGORITHM,
    signingPublicKeySpki: signingSpki.toString("base64url"),
    signingFingerprint: custodySha256(signingSpki),
  };
  return { material, signingPrivateKey: signing.privateKey };
}

function envelopeFixture(keys: readonly CustodianKeyMaterial[]) {
  const body = {
    format: "nombramientos.hpke-ballot-envelope",
    version: 1,
    suite: CUSTODY_HPKE_SUITE,
    aad: {
      tenantId,
      cycleId,
      roundId,
      purpose: "nombramientos.ballot.selections",
      schemaVersion: 1,
      roundVersion: 7,
      candidateSetHash,
      rulesHash,
    },
    recipients: keys.map((key) => ({
      recipientId: key.recipientId,
      fingerprint: key.hpkeFingerprint,
      enc: randomBytes(65).toString("base64url"),
      ciphertext: randomBytes(48).toString("base64url"),
    })),
  };
  const envelope = { ...body, envelopeHash: hashCanonicalCustodyJson(body) };
  return { envelope, contentHash: hashCanonicalCustodyJson(envelope) };
}

describe("custody cryptographic boundary", () => {
  it("accepts only valid P-256 HPKE and canonical Ed25519 SPKI fingerprints", () => {
    const key = keyFixture("custodian-a");
    expect(() => validateCustodianKeyMaterial(key.material)).not.toThrow();
    expect(() => validateCustodianKeyMaterial({
      ...key.material,
      hpkeFingerprint: `sha256:${"0".repeat(64)}`,
    })).toThrowError(CustodyError);
    expect(() => validateCustodianKeyMaterial({
      ...key.material,
      suite: { ...CUSTODY_HPKE_SUITE, aead: "AES-128-GCM" } as unknown as typeof CUSTODY_HPKE_SUITE,
    })).toThrowError(CustodyError);
  });

  it("validates the canonical E2EE format, frozen recipients, AAD and both hashes", () => {
    const first = keyFixture("custodian-a").material;
    const second = keyFixture("custodian-b").material;
    const fixture = envelopeFixture([first, second]);
    expect(validateEncryptedBallotEnvelope(fixture.envelope, fixture.contentHash, {
      tenantId,
      cycleId,
      roundId,
      submissionRoundVersion: 7,
      candidateSetHash,
      rulesHash,
      recipients: [
        { recipientId: first.recipientId, hpkeFingerprint: first.hpkeFingerprint },
        { recipientId: second.recipientId, hpkeFingerprint: second.hpkeFingerprint },
      ],
    })).toEqual({ contentHash: fixture.contentHash, envelopeHash: fixture.envelope.envelopeHash });
  });

  it("rejects tenant replay, wrong recipient sets and recomputed content around a bad envelope hash", () => {
    const first = keyFixture("custodian-a").material;
    const second = keyFixture("custodian-b").material;
    const fixture = envelopeFixture([first, second]);
    const expected = {
      tenantId,
      cycleId,
      roundId,
      submissionRoundVersion: 7,
      candidateSetHash,
      rulesHash,
      recipients: [
        { recipientId: first.recipientId, hpkeFingerprint: first.hpkeFingerprint },
        { recipientId: second.recipientId, hpkeFingerprint: second.hpkeFingerprint },
      ],
    } as const;
    expect(() => validateEncryptedBallotEnvelope(fixture.envelope, fixture.contentHash, {
      ...expected,
      tenantId: "11111111-1111-4111-8111-111111111112",
    })).toThrowError(/tenantId/u);
    expect(() => validateEncryptedBallotEnvelope(fixture.envelope, fixture.contentHash, {
      ...expected,
      recipients: expected.recipients.slice(0, 1),
    })).toThrowError(/recipients/u);
    const altered = { ...fixture.envelope, envelopeHash: `sha256:${"e".repeat(64)}` };
    expect(() => validateEncryptedBallotEnvelope(
      altered,
      hashCanonicalCustodyJson(altered),
      expected,
    )).toThrowError(/envelope hash/u);
  });

  it("verifies Ed25519 only over the exact canonical tenant/round/manifest/aggregate context", () => {
    const key = keyFixture("custodian-a");
    const context = buildTallyAttestationContext({
      tenantId,
      roundId,
      manifestId,
      manifestHash,
      aggregateHash,
    });
    const signature = sign(null, Buffer.from(canonicalCustodyJson(context)), key.signingPrivateKey).toString("base64url");
    expect(verifyTallyAttestation({
      context,
      signingPublicKeySpki: key.material.signingPublicKeySpki,
      signingFingerprint: key.material.signingFingerprint,
      signature,
    })).toBe(custodySha256(canonicalCustodyJson(context)));
    expect(() => verifyTallyAttestation({
      context: { ...context, roundId: "33333333-3333-4333-8333-333333333334" },
      signingPublicKeySpki: key.material.signingPublicKeySpki,
      signingFingerprint: key.material.signingFingerprint,
      signature,
    })).toThrowError(/attestation/u);
  });
});

