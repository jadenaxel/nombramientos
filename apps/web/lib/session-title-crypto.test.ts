import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  agendaTitleAad,
  openAgendaTitle,
  openSessionTitle,
  sealAgendaTitle,
  sealSessionTitle,
  sessionTitleAad,
} from "./session-title-crypto.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

const tenantId = "10000000-0000-4000-8000-000000000001";
const cycleId = "20000000-0000-4000-8000-000000000001";
const sessionId = "30000000-0000-4000-8000-000000000001";
const agendaItemId = "40000000-0000-4000-8000-000000000001";
const keyId = "tenant-key-session-title-v1";
const base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function nonCanonicalTailAlias(value: string): string {
  assert.ok(value.length % 4 === 2 || value.length % 4 === 3);
  const lastIndex = base64UrlAlphabet.indexOf(value.at(-1) ?? "");
  assert.ok(lastIndex >= 0);
  const replacement = base64UrlAlphabet[lastIndex + 1];
  assert.ok(replacement);
  return `${value.slice(0, -1)}${replacement}`;
}

test("session titles use an exact, independently versioned E2EE context", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const context = { tenantId, cycleId, sessionId, titleVersion: 1 };
  const sealed = await sealSessionTitle(key, keyId, context, "Acta extraordinaria");

  assert.deepEqual(sessionTitleAad(context), {
    tenantId,
    cycleId,
    sessionId,
    purpose: "session-title",
    schemaVersion: 1,
    titleVersion: 1,
  });
  assert.equal(await openSessionTitle(key, keyId, context, sealed.envelope), "Acta extraordinaria");
  await assert.rejects(openSessionTitle(key, keyId, { ...context, titleVersion: 2 }, sealed.envelope));
  await assert.rejects(openSessionTitle(key, keyId, { ...context, sessionId: agendaItemId }, sealed.envelope));

  const equivalentNonCanonicalCiphertext = nonCanonicalTailAlias(sealed.envelope.ciphertext);
  assert.deepEqual(
    Buffer.from(equivalentNonCanonicalCiphertext, "base64url"),
    Buffer.from(sealed.envelope.ciphertext, "base64url"),
  );
  await assert.rejects(openSessionTitle(key, keyId, context, {
    ...sealed.envelope,
    ciphertext: equivalentNonCanonicalCiphertext,
  }));

  const tamperedCiphertext = Buffer.from(sealed.envelope.ciphertext, "base64url");
  tamperedCiphertext[0] ^= 1;
  await assert.rejects(openSessionTitle(key, keyId, context, {
    ...sealed.envelope,
    ciphertext: tamperedCiphertext.toString("base64url"),
  }));
});

test("agenda titles cannot be replayed into another item or session", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const context = { tenantId, sessionId, agendaItemId, titleVersion: 1 };
  const sealed = await sealAgendaTitle(key, keyId, context, "Nombramiento de tesorería");

  assert.deepEqual(agendaTitleAad(context), {
    tenantId,
    sessionId,
    agendaItemId,
    purpose: "session-agenda-title",
    schemaVersion: 1,
    titleVersion: 1,
  });
  assert.equal(await openAgendaTitle(key, keyId, context, sealed.envelope), "Nombramiento de tesorería");
  await assert.rejects(openAgendaTitle(key, keyId, { ...context, agendaItemId: cycleId }, sealed.envelope));
  await assert.rejects(openAgendaTitle(key, keyId, { ...context, sessionId: cycleId }, sealed.envelope));
});
