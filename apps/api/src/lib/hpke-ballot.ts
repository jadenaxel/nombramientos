import { z } from "zod";

const canonicalUuid = z.string().regex(
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  "Must be a canonical lowercase UUID",
);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const base64url = z.string().min(1).regex(/^[A-Za-z0-9_-]+$/);
const recipientId = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/);

export const custodyHpkeSuiteSchema = z.object({
  kem: z.literal("DHKEM(P-256, HKDF-SHA256)"),
  kemId: z.literal(0x0010),
  kdf: z.literal("HKDF-SHA256"),
  kdfId: z.literal(0x0001),
  aead: z.literal("AES-256-GCM"),
  aeadId: z.literal(0x0002),
}).strict();

export const hpkeBallotAadSchema = z.object({
  tenantId: canonicalUuid,
  cycleId: canonicalUuid,
  roundId: canonicalUuid,
  purpose: z.literal("nombramientos.ballot.selections"),
  schemaVersion: z.literal(1),
  roundVersion: z.number().int().positive(),
  candidateSetHash: digest,
  rulesHash: digest,
}).strict();

const encryptedRecipientSchema = z.object({
  recipientId,
  fingerprint: digest,
  enc: base64url,
  ciphertext: base64url,
}).strict().superRefine((value, context) => {
  if (Buffer.from(value.enc, "base64url").byteLength !== 65) {
    context.addIssue({ code: "custom", path: ["enc"], message: "P-256 HPKE enc must contain 65 bytes" });
  }
  if (Buffer.from(value.ciphertext, "base64url").byteLength <= 16) {
    context.addIssue({ code: "custom", path: ["ciphertext"], message: "HPKE ciphertext is too short" });
  }
});

export const hpkeBallotEnvelopeSchema = z.object({
  format: z.literal("nombramientos.hpke-ballot-envelope"),
  version: z.literal(1),
  suite: custodyHpkeSuiteSchema,
  aad: hpkeBallotAadSchema,
  recipients: z.array(encryptedRecipientSchema).min(2).max(16),
  envelopeHash: digest,
}).strict().superRefine((value, context) => {
  const ids = value.recipients.map((recipient) => recipient.recipientId);
  const fingerprints = value.recipients.map((recipient) => recipient.fingerprint);
  if (new Set(ids).size !== ids.length) {
    context.addIssue({ code: "custom", path: ["recipients"], message: "recipientId values must be unique" });
  }
  if (new Set(fingerprints).size !== fingerprints.length) {
    context.addIssue({ code: "custom", path: ["recipients"], message: "recipient fingerprints must be unique" });
  }
});

export type HpkeBallotEnvelopeInput = z.infer<typeof hpkeBallotEnvelopeSchema>;

