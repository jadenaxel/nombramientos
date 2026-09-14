import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const component = readFileSync(
  new URL("../components/nombramientos/member-qualifications.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
const membersView = readFileSync(
  new URL("../components/nombramientos/members-view.tsx", import.meta.url),
  "utf8",
);
const crypto = readFileSync(new URL("./member-qualification-crypto.ts", import.meta.url), "utf8");
const keyring = readFileSync(new URL("./tenant-keyring.ts", import.meta.url), "utf8");
const providers = readFileSync(new URL("../app/providers.tsx", import.meta.url), "utf8");
const lifecycle = readFileSync(
  new URL("../components/nombramientos/key-lifecycle-view.tsx", import.meta.url),
  "utf8",
);

test("member qualifications use atomic read/manage permissions and append-only revision endpoints", () => {
  assert.match(component, /member\.qualification\.read/u);
  assert.match(component, /member\.qualification\.manage/u);
  assert.match(api, /\/qualifications\/\$\{encodeURIComponent\(qualificationId\)\}\/revisions/u);
  assert.match(api, /expectedVersion/u);
  assert.match(api, /idempotent: true/u);
  assert.match(membersView, /MemberQualifications/u);
  assert.match(membersView, /member\.qualification\.read/u);
  assert.match(membersView, /setQualificationMember\(member\)/u);
});

test("qualification detail encryption binds the full independent record context", () => {
  for (const field of [
    "tenantId", "memberId", "qualificationId", "purpose", "schemaVersion",
    "version", "type", "status", "effectiveOn", "expiresOn",
  ]) {
    assert.match(crypto, new RegExp(`${field}:`, "u"));
  }
  assert.match(crypto, /member-qualification-details/u);
  assert.match(crypto, /decryptJson<unknown>/u);
  assert.match(crypto, /parseQualificationDetails\(decrypted\)/u);
  assert.match(component, /encryptJson\(/u);
});

test("qualification history selects keys by keyId and degrades safely when a generation is unavailable", () => {
  assert.match(component, /openMemberQualificationDetails/u);
  assert.match(component, /qualificationKeyFor\(revision\.detailsEnvelope\.keyId/u);
  assert.match(component, /keyringRevision/u);
  assert.match(component, /failures\.add\(key\)/u);
  assert.match(keyring, /Map<string, CryptoKey>/u);
  assert.match(keyring, /TENANT_KEY_CONTEXT_MISMATCH/u);
  assert.match(providers, /rememberHistorical/u);
  assert.match(providers, /keyringRef\.current\.clear\(\)/u);
  assert.match(lifecycle, /historicalGrant\.status !== "retired"/u);
  assert.match(lifecycle, /vault\.rememberRaw/u);
});

test("the UI explicitly rejects automatic eligibility inference", () => {
  assert.match(component, /qualification\.independent\.body/u);
  assert.doesNotMatch(component, /eligibilityStatus\s*:/u);
  assert.doesNotMatch(component, /available\s*:/u);
  assert.doesNotMatch(component, /candidate|ballot|assignment/iu);
});
