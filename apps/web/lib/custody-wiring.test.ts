import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const roundSource = readFileSync(path.join(webRoot, "components/nombramientos/round-view.tsx"), "utf8");
const custodySource = readFileSync(path.join(webRoot, "components/nombramientos/custody-view.tsx"), "utf8");
const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");

test("la votación cifra HPKE para el set congelado antes del submit real", () => {
  assert.match(roundSource, /api\.ballotRecipients\(round\.id\)/);
  assert.match(roundSource, /createBallotAad/);
  assert.match(roundSource, /sealBallotEnvelope/);
  assert.match(roundSource, /computeBallotContentHash/);
  assert.match(roundSource, /aad\.candidateSetHash !== round\.candidateSetHash/);
  assert.match(roundSource, /kind: "vote"/);
});

test("la ceremonia nunca persiste ni transmite claves privadas o contraseñas", () => {
  assert.doesNotMatch(custodySource, /localStorage|sessionStorage|indexedDB|console\./);
  assert.doesNotMatch(apiSource, /privateKeyPkcs8|nombramientos\.hpke-private-key|passphrase/);
  assert.match(custodySource, /createEncryptedCustodianKeyBackup/);
  assert.match(custodySource, /openEncryptedCustodianKeyBackup/);
  assert.match(custodySource, /document\.visibilityState === "hidden"/);
  assert.match(custodySource, /10 \* 60_000/);
});

test("el cliente conecta las once operaciones públicas de custodia", () => {
  for (const pathFragment of [
    "/v1/custody/keys",
    "/custody/recipients",
    "/custody/freeze",
    "/custody/manifest",
    "/custody/attestations",
    "/custody/publication",
    "/custody/aggregate",
  ]) assert.ok(apiSource.includes(pathFragment), `falta ${pathFragment}`);
  assert.match(custodySource, /computeTallyAggregateHash/);
  assert.match(custodySource, /signTallyAttestation/);
  assert.match(custodySource, /manifest\.manifest\.decisionRule/);
});

test("los 403 de dependencias no se convierten en estados vacíos", () => {
  assert.match(custodySource, /function optionalNotFound/);
  assert.match(custodySource, /error\.status === 404/);
  assert.doesNotMatch(custodySource, /\[403, 404\]\.includes/);
  assert.match(custodySource, /roundQuery\.isError \? <DataError/);
  assert.match(custodySource, /custodyQuery\.isError && <DataError/);
  assert.match(custodySource, /manifestQuery\.isError && <DataError/);
});
