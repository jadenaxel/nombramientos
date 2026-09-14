import type { Envelope, Locale, ReportAudience, ReportCorrectionReasonCode, ReportFormat, ReportType } from "./api.ts";
import { base64UrlToBytes, bytesToBase64Url } from "./crypto-client.ts";

export const REPORT_ARTIFACT_MAX_PLAINTEXT_BYTES = 20 * 1024 * 1024;
export const REPORT_ARTIFACT_SCHEMA_VERSION = 1 as const;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type ReportArtifactDescriptor = {
  readonly tenantId: string;
  readonly reportId: string;
  readonly requestVersion: number;
  readonly reportType: ReportType;
  readonly audience: ReportAudience;
  readonly locale: Locale;
  readonly format: ReportFormat;
  readonly filename: string;
  readonly mediaType: string;
  readonly snapshotSha256: `sha256:${string}`;
  readonly supersedesReportId?: string;
  readonly correctionReasonCode?: ReportCorrectionReasonCode;
  readonly lineageRootId?: string;
  readonly lineageRevision?: number;
};

export type ReportArtifactAad = ReportArtifactDescriptor & {
  readonly purpose: "report-artifact";
  readonly schemaVersion: typeof REPORT_ARTIFACT_SCHEMA_VERSION;
  readonly plaintextBytes: number;
};

export type EncryptedReportArtifact = {
  readonly envelope: Envelope;
  readonly artifactSha256: `sha256:${string}`;
  readonly ciphertextSha256: `sha256:${string}`;
  readonly ciphertextBytes: number;
  readonly plaintextBytes: number;
};

export function createReportArtifactAad(
  descriptor: ReportArtifactDescriptor,
  plaintextBytes: number,
): ReportArtifactAad {
  if (!Number.isSafeInteger(descriptor.requestVersion) || descriptor.requestVersion < 1) {
    throw new Error("REPORT_VERSION_INVALID");
  }
  if (!Number.isSafeInteger(plaintextBytes) || plaintextBytes < 1 || plaintextBytes > REPORT_ARTIFACT_MAX_PLAINTEXT_BYTES) {
    throw new Error("REPORT_ARTIFACT_SIZE_INVALID");
  }
  if (!/^sha256:[0-9a-f]{64}$/u.test(descriptor.snapshotSha256)) {
    throw new Error("REPORT_SNAPSHOT_DIGEST_INVALID");
  }
  if (!descriptor.filename.toLocaleLowerCase().endsWith(`.${descriptor.format}`)) {
    throw new Error("REPORT_FILENAME_INVALID");
  }
  const correctionFields = [
    descriptor.supersedesReportId,
    descriptor.correctionReasonCode,
    descriptor.lineageRootId,
    descriptor.lineageRevision,
  ];
  if (correctionFields.some((value) => value !== undefined)) {
    if (
      !descriptor.supersedesReportId
      || !descriptor.correctionReasonCode
      || !descriptor.lineageRootId
      || !Number.isSafeInteger(descriptor.lineageRevision)
      || (descriptor.lineageRevision ?? 0) < 2
    ) throw new Error("REPORT_LINEAGE_INVALID");
  }
  return {
    tenantId: descriptor.tenantId,
    reportId: descriptor.reportId,
    requestVersion: descriptor.requestVersion,
    reportType: descriptor.reportType,
    audience: descriptor.audience,
    locale: descriptor.locale,
    format: descriptor.format,
    filename: descriptor.filename,
    mediaType: descriptor.mediaType,
    snapshotSha256: descriptor.snapshotSha256,
    ...(descriptor.supersedesReportId ? {
      supersedesReportId: descriptor.supersedesReportId,
      correctionReasonCode: descriptor.correctionReasonCode!,
      lineageRootId: descriptor.lineageRootId!,
      lineageRevision: descriptor.lineageRevision!,
    } : {}),
    purpose: "report-artifact",
    schemaVersion: REPORT_ARTIFACT_SCHEMA_VERSION,
    plaintextBytes,
  };
}

export async function encryptReportArtifact(input: {
  readonly key: CryptoKey;
  readonly keyId: string;
  readonly descriptor: ReportArtifactDescriptor;
  readonly plaintext: Uint8Array<ArrayBuffer>;
}): Promise<EncryptedReportArtifact> {
  const aad = createReportArtifactAad(input.descriptor, input.plaintext.byteLength);
  const aadBytes = encoder.encode(JSON.stringify(aad));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes },
    input.key,
    input.plaintext,
  ));
  const envelope: Envelope = {
    algorithm: "AES-256-GCM",
    keyId: input.keyId,
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(ciphertext),
    aad: bytesToBase64Url(aadBytes),
  };
  return {
    envelope,
    artifactSha256: await reportEnvelopeSha256(envelope),
    ciphertextSha256: await reportBytesSha256(ciphertext),
    ciphertextBytes: ciphertext.byteLength,
    plaintextBytes: input.plaintext.byteLength,
  };
}

export async function decryptReportArtifact(input: {
  readonly key: CryptoKey;
  readonly keyId: string;
  readonly descriptor: ReportArtifactDescriptor;
  readonly artifact: EncryptedReportArtifact;
}): Promise<Uint8Array<ArrayBuffer>> {
  const { artifact, descriptor } = input;
  if (artifact.envelope.algorithm !== "AES-256-GCM" || artifact.envelope.keyId !== input.keyId) {
    throw new Error("REPORT_ARTIFACT_KEY_MISMATCH");
  }
  if (await reportEnvelopeSha256(artifact.envelope) !== artifact.artifactSha256) {
    throw new Error("REPORT_ARTIFACT_DIGEST_MISMATCH");
  }
  const ciphertext = base64UrlToBytes(artifact.envelope.ciphertext);
  if (ciphertext.byteLength !== artifact.ciphertextBytes || await reportBytesSha256(ciphertext) !== artifact.ciphertextSha256) {
    throw new Error("REPORT_ARTIFACT_CIPHERTEXT_MISMATCH");
  }
  const expectedAad = createReportArtifactAad(descriptor, artifact.plaintextBytes);
  const actualAad = JSON.parse(decoder.decode(base64UrlToBytes(artifact.envelope.aad))) as unknown;
  assertExactObject(actualAad, expectedAad);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64UrlToBytes(artifact.envelope.nonce),
      additionalData: base64UrlToBytes(artifact.envelope.aad),
    },
    input.key,
    ciphertext,
  ));
  if (plaintext.byteLength !== artifact.plaintextBytes) throw new Error("REPORT_ARTIFACT_SIZE_MISMATCH");
  assertReportSignature(plaintext, descriptor.format);
  return plaintext;
}

export async function reportEnvelopeSha256(envelope: Envelope): Promise<`sha256:${string}`> {
  return reportBytesSha256(serializeReportEnvelope(envelope));
}

export async function reportBytesSha256(bytes: Uint8Array<ArrayBuffer>): Promise<`sha256:${string}`> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

export function serializeReportEnvelope(envelope: Envelope): Uint8Array<ArrayBuffer> {
  return encoder.encode(JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  }));
}

export function bytesToCanonicalBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 32 * 1024;
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.byteLength));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function assertExactObject(actual: unknown, expected: Readonly<Record<string, unknown>>): void {
  if (!actual || typeof actual !== "object" || Array.isArray(actual)) throw new Error("REPORT_ARTIFACT_CONTEXT_INVALID");
  const record = actual as Record<string, unknown>;
  const actualKeys = Object.keys(record).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (
    actualKeys.length !== expectedKeys.length
    || actualKeys.some((key, index) => key !== expectedKeys[index] || record[key] !== expected[key])
  ) throw new Error("REPORT_ARTIFACT_CONTEXT_MISMATCH");
}

function assertReportSignature(bytes: Uint8Array, format: ReportFormat): void {
  if (format === "pdf") {
    if (decoder.decode(bytes.subarray(0, 5)) !== "%PDF-") throw new Error("REPORT_ARTIFACT_FORMAT_MISMATCH");
    return;
  }
  if (format === "xlsx") {
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4b || ![0x03, 0x05, 0x07].includes(bytes[2] ?? -1)) {
      throw new Error("REPORT_ARTIFACT_FORMAT_MISMATCH");
    }
    return;
  }
  if (bytes.byteLength < 3 || bytes[0] !== 0xef || bytes[1] !== 0xbb || bytes[2] !== 0xbf) {
    throw new Error("REPORT_ARTIFACT_FORMAT_MISMATCH");
  }
}
