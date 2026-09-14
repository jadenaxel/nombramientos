import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import type { Envelope } from "./api.ts";
import {
  bytesToCanonicalBase64,
  createReportArtifactAad,
  decryptReportArtifact,
  encryptReportArtifact,
  reportEnvelopeSha256,
  type ReportArtifactDescriptor,
} from "./report-artifact.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
Object.defineProperty(globalThis, "btoa", { value: (value: string) => Buffer.from(value, "binary").toString("base64"), configurable: true });
Object.defineProperty(globalThis, "atob", { value: (value: string) => Buffer.from(value, "base64").toString("binary"), configurable: true });

const descriptor: ReportArtifactDescriptor = {
  tenantId: "d0000000-0000-4000-8000-000000000001",
  reportId: "40000000-0000-4000-8000-000000000001",
  requestVersion: 1,
  reportType: "cycle_summary",
  audience: "committee",
  locale: "es",
  format: "pdf",
  filename: "cycle-summary.pdf",
  mediaType: "application/pdf",
  snapshotSha256: `sha256:${"a".repeat(64)}`,
};

test("el artefacto persiste sólo un sobre AES-GCM ligado al tenant, emisión y huella", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plaintext = new TextEncoder().encode("%PDF-1.7\nSENTINELA-NOMBRE-PRIVADO") as Uint8Array<ArrayBuffer>;
  const artifact = await encryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor, plaintext });

  assert.equal(artifact.envelope.algorithm, "AES-256-GCM");
  assert.equal(JSON.stringify(artifact.envelope).includes("SENTINELA-NOMBRE-PRIVADO"), false);
  assert.equal(await reportEnvelopeSha256(artifact.envelope), artifact.artifactSha256);
  assert.equal(artifact.ciphertextBytes, plaintext.byteLength + 16);
  assert.deepEqual(await decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor, artifact }), plaintext);
});

test("el descifrado rechaza replay de tenant/reporte, digest alterado y formato falso", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plaintext = new TextEncoder().encode("%PDF-1.7\nfixture") as Uint8Array<ArrayBuffer>;
  const artifact = await encryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor, plaintext });

  await assert.rejects(
    decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor: { ...descriptor, tenantId: "d0000000-0000-4000-8000-000000000002" }, artifact }),
    /CONTEXT_MISMATCH/,
  );
  await assert.rejects(
    decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor, artifact: { ...artifact, artifactSha256: `sha256:${"0".repeat(64)}` } }),
    /DIGEST_MISMATCH/,
  );
  await assert.rejects(
    decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor, artifact: { ...artifact, ciphertextSha256: `sha256:${"0".repeat(64)}` } }),
    /CIPHERTEXT_MISMATCH/,
  );

  const csvDescriptor = { ...descriptor, format: "csv" as const, filename: "cycle-summary.csv", mediaType: "text/csv; charset=utf-8" };
  const fakeCsv = await encryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor: csvDescriptor, plaintext });
  await assert.rejects(decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor: csvDescriptor, artifact: fakeCsv }), /FORMAT_MISMATCH/);
});

test("el AAD exacto y Base64 canónico soportan datos binarios por bloques", () => {
  const aad = createReportArtifactAad(descriptor, 128);
  assert.deepEqual(Object.keys(aad), [
    "tenantId", "reportId", "requestVersion", "reportType", "audience", "locale", "format", "filename", "mediaType", "snapshotSha256",
    "purpose", "schemaVersion", "plaintextBytes",
  ]);
  const bytes = Uint8Array.from({ length: 70_001 }, (_, index) => index % 251);
  const encoded = bytesToCanonicalBase64(bytes);
  assert.equal(Buffer.from(encoded, "base64").equals(Buffer.from(bytes)), true);
  assert.equal(Buffer.from(encoded, "base64").toString("base64"), encoded);

  const invalidEnvelope: Envelope = { algorithm: "AES-256-GCM", keyId: "key", nonce: "AA", ciphertext: "AA", aad: "AA" };
  assert.equal(JSON.stringify(invalidEnvelope).includes("plaintext"), false);
});

test("el AAD de una corrección autentica el vínculo y la revisión completa", async () => {
  const correctionDescriptor: ReportArtifactDescriptor = {
    ...descriptor,
    reportId: "40000000-0000-4000-8000-000000000002",
    supersedesReportId: descriptor.reportId,
    correctionReasonCode: "SOURCE_DATA_CORRECTED",
    lineageRootId: descriptor.reportId,
    lineageRevision: 2,
  };
  const aad = createReportArtifactAad(correctionDescriptor, 128);
  assert.deepEqual(Object.keys(aad).slice(10, 14), [
    "supersedesReportId", "correctionReasonCode", "lineageRootId", "lineageRevision",
  ]);
  assert.throws(() => createReportArtifactAad({ ...correctionDescriptor, lineageRevision: 1 }, 128), /LINEAGE_INVALID/);
  assert.throws(() => createReportArtifactAad({ ...correctionDescriptor, correctionReasonCode: undefined }, 128), /LINEAGE_INVALID/);

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const plaintext = new TextEncoder().encode("%PDF-1.7\ncorrected") as Uint8Array<ArrayBuffer>;
  const artifact = await encryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor: correctionDescriptor, plaintext });
  await assert.rejects(
    decryptReportArtifact({ key, keyId: "tenant-key-generation-1", descriptor: { ...correctionDescriptor, lineageRevision: 3 }, artifact }),
    /CONTEXT_MISMATCH/,
  );
});
