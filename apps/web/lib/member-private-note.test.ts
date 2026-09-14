import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import { encryptJson } from "./crypto-client.ts";
import { parseMemberEligibilityReview, revealMemberEligibilityReview } from "./member-private-note.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const tenantId = "10000000-0000-4000-8000-000000000001";
const memberId = "20000000-0000-4000-8000-000000000001";
const reviewerId = "30000000-0000-4000-8000-000000000001";
const keyId = "tenant-key-ac09";

test("AC-09 descifra la revisión únicamente con private-note.read", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const sealed = await encryptJson(key, keyId, {
    tenantId,
    memberId,
    purpose: "member-eligibility",
    schemaVersion: 1,
  }, {
    schema: "nombramientos-member-eligibility/v1",
    note: "Entrevista pastoral pendiente",
    departmentRestriction: "Tesorería",
    validUntil: "2027-03-31",
    reviewedByIdentityId: reviewerId,
    reviewedAt: "2026-09-11T12:00:00.000Z",
  });

  const hidden = await revealMemberEligibilityReview({
    permissions: ["member.read"],
    key,
    keyId,
    tenantId,
    memberId,
    eligibilityEnvelope: { ...sealed.envelope, ciphertext: `${sealed.envelope.ciphertext}A` },
  });
  assert.equal(hidden, undefined, "a principal without permission must not even attempt restricted decryption");

  const revealed = await revealMemberEligibilityReview({
    permissions: ["member.read", "private-note.read"],
    key,
    keyId,
    tenantId,
    memberId,
    eligibilityEnvelope: sealed.envelope,
  });
  assert.deepEqual(revealed, {
    schema: "nombramientos-member-eligibility/v1",
    note: "Entrevista pastoral pendiente",
    departmentRestriction: "Tesorería",
    validUntil: "2027-03-31",
    reviewedByIdentityId: reviewerId,
    reviewedAt: "2026-09-11T12:00:00.000Z",
  });
});

test("AC-09 falla cerrado ante sobre restringido alterado", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const sealed = await encryptJson(key, keyId, {
    tenantId,
    memberId,
    purpose: "member-eligibility",
    schemaVersion: 1,
  }, { schema: "nombramientos-member-eligibility/v1", note: "Contenido restringido" });

  await assert.rejects(revealMemberEligibilityReview({
    permissions: ["member.read", "private-note.read"],
    key,
    keyId,
    tenantId,
    memberId,
    eligibilityEnvelope: { ...sealed.envelope, ciphertext: `${sealed.envelope.ciphertext}A` },
  }));
});

test("la revisión cifrada admite campos opcionales ausentes y rechaza null o texto vacío", () => {
  assert.deepEqual(parseMemberEligibilityReview({ synthetic: true }), {});
  assert.throws(
    () => parseMemberEligibilityReview({ visibleReason: null, synthetic: true }),
    /invalid visibleReason field/,
  );
  assert.throws(
    () => parseMemberEligibilityReview({ visibleReason: "  ", synthetic: true }),
    /invalid visibleReason field/,
  );
});
