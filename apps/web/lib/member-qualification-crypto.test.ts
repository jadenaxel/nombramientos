import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import { encryptJson } from "./crypto-client.ts";
import {
  memberQualificationAad,
  openMemberQualificationDetails,
  parseQualificationDetails,
  type MemberQualificationCryptoContext,
} from "./member-qualification-crypto.ts";
import { TenantCryptoKeyring } from "./tenant-keyring.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const tenantId = "10000000-0000-4000-8000-000000000001";
const otherTenantId = "10000000-0000-4000-8000-000000000002";
const memberId = "20000000-0000-4000-8000-000000000001";
const qualificationId = "30000000-0000-4000-8000-000000000001";
const oldKeyId = "40000000-0000-4000-8000-000000000001";
const currentKeyId = "40000000-0000-4000-8000-000000000002";

test("a tenant keyring decrypts current and historical qualification revisions after rotation", async () => {
  const oldKey = await qualificationKey();
  const currentKey = await qualificationKey();
  const oldContext = context({ version: 1, status: "pending" });
  const currentContext = context({ version: 2, status: "verified" });
  const oldSealed = await encryptJson(oldKey, oldKeyId, memberQualificationAad(oldContext), {
    title: "Ordination review",
    issuer: "Historical issuer",
  });
  const currentSealed = await encryptJson(currentKey, currentKeyId, memberQualificationAad(currentContext), {
    title: "Ordination verified",
    issuer: "Current issuer",
  });

  const keyring = new TenantCryptoKeyring();
  keyring.rememberCurrent(tenantId, currentKeyId, currentKey);
  keyring.rememberHistorical(tenantId, oldKeyId, oldKey);

  assert.deepEqual(await openMemberQualificationDetails({
    key: keyring.keyFor(tenantId, oldSealed.envelope.keyId),
    envelope: oldSealed.envelope,
    context: oldContext,
  }), { title: "Ordination review", issuer: "Historical issuer" });
  assert.deepEqual(await openMemberQualificationDetails({
    key: keyring.keyFor(tenantId, currentSealed.envelope.keyId),
    envelope: currentSealed.envelope,
    context: currentContext,
  }), { title: "Ordination verified", issuer: "Current issuer" });
  assert.deepEqual(keyring.keyIds(tenantId), [currentKeyId, oldKeyId].sort());
});

test("the keyring never crosses tenant boundaries and clears history on tenant switch", async () => {
  const firstKey = await qualificationKey();
  const secondKey = await qualificationKey();
  const keyring = new TenantCryptoKeyring();
  keyring.rememberCurrent(tenantId, currentKeyId, firstKey);

  assert.equal(keyring.keyFor(otherTenantId, currentKeyId), undefined);
  assert.throws(
    () => keyring.rememberHistorical(otherTenantId, oldKeyId, secondKey),
    /TENANT_KEY_CONTEXT_MISMATCH/u,
  );

  keyring.rememberCurrent(otherTenantId, oldKeyId, secondKey);
  assert.equal(keyring.keyFor(tenantId, currentKeyId), undefined);
  assert.deepEqual(keyring.keyIds(otherTenantId), [oldKeyId]);
});

test("decrypted qualification details are validated at runtime and fail closed", async () => {
  const key = await qualificationKey();
  const revisionContext = context({ version: 1, status: "pending" });
  const malformed = await encryptJson(key, oldKeyId, memberQualificationAad(revisionContext), {
    title: { unexpected: "object" },
  });

  await assert.rejects(openMemberQualificationDetails({
    key,
    envelope: malformed.envelope,
    context: revisionContext,
  }), /QUALIFICATION_DETAILS_INVALID/u);
  await assert.rejects(openMemberQualificationDetails({
    key: undefined,
    envelope: malformed.envelope,
    context: revisionContext,
  }), /QUALIFICATION_KEY_UNAVAILABLE/u);
  assert.throws(
    () => parseQualificationDetails({ title: "Valid", privateMetadata: "leak" }),
    /QUALIFICATION_DETAILS_INVALID/u,
  );
});

async function qualificationKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function context(input: {
  readonly version: number;
  readonly status: "pending" | "verified";
}): MemberQualificationCryptoContext {
  return {
    tenantId,
    memberId,
    qualificationId,
    version: input.version,
    type: "ordination",
    status: input.status,
    effectiveOn: "2026-09-12",
    expiresOn: null,
  };
}
