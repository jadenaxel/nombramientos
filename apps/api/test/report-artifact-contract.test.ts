import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { reportCompleteSchema, reportCorrectionSchema, reportFailSchema, reportGenerateSchema, reportPrintSchema } from "../src/modules/tenant-routes.js";

const digest = `sha256:${"a".repeat(64)}`;

describe("durable report artifact lifecycle contract", () => {
  it("accepts only a canonical bounded encrypted completion request", () => {
    const plaintextBytes = 17;
    const envelope = {
      algorithm: "AES-256-GCM" as const,
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12, 1).toString("base64url"),
      ciphertext: Buffer.alloc(plaintextBytes + 16, 2).toString("base64url"),
      aad: Buffer.from('{"purpose":"report-artifact"}').toString("base64url"),
    };
    expect(reportCompleteSchema.safeParse({
      expectedVersion: 1,
      envelope,
      artifactSha256: digest,
      ciphertextSha256: digest,
      plaintextBytes,
      rowCount: 3,
      generatedAt: "2026-09-11T12:00:00.000Z",
    }).success).toBe(true);
    expect(reportCompleteSchema.safeParse({
      expectedVersion: 1,
      envelope: { ...envelope, ciphertext: "not canonical base64!" },
      artifactSha256: digest,
      ciphertextSha256: digest,
      plaintextBytes,
      rowCount: 3,
      generatedAt: "2026-09-11T12:00:00.000Z",
    }).success).toBe(false);
    expect(reportCompleteSchema.safeParse({
      expectedVersion: 1,
      envelope,
      artifactSha256: digest,
      ciphertextSha256: digest,
      plaintextBytes: 20 * 1024 * 1024 + 1,
      rowCount: 3,
      generatedAt: "2026-09-11T12:00:00.000Z",
    }).success).toBe(false);
  });

  it("keeps failure and print payloads strict", () => {
    expect(reportFailSchema.safeParse({ expectedVersion: 1, errorCode: "CLIENT_GENERATION_FAILED" }).success).toBe(true);
    expect(reportFailSchema.safeParse({ expectedVersion: 1, errorCode: "free text" }).success).toBe(false);
    expect(reportPrintSchema.safeParse({ artifactSha256: digest }).success).toBe(true);
    expect(reportPrintSchema.safeParse({ artifactSha256: digest, reportId: "unexpected" }).success).toBe(false);
  });

  it("requires a selected session only when issuing session minutes", () => {
    const filters = { snapshotSha256: digest, snapshotAt: "2026-09-11T12:00:00.000Z" };
    expect(reportGenerateSchema.safeParse({ reportType: "session_minutes", audience: "committee", locale: "es", format: "pdf", filters }).success).toBe(false);
    expect(reportGenerateSchema.safeParse({
      reportType: "session_minutes",
      audience: "committee",
      locale: "es",
      format: "pdf",
      filters: { ...filters, sessionId: "11111111-1111-4111-8111-111111111111" },
    }).success).toBe(true);
  });

  it("accepts only normalized correction reasons and a strict snapshot scope", () => {
    const correction = {
      expectedPreviousVersion: 2,
      reasonCode: "SOURCE_DATA_CORRECTED",
      filters: {
        cycleId: "11111111-1111-4111-8111-111111111111",
        snapshotSha256: digest,
        snapshotAt: "2026-09-12T12:00:00.000Z",
      },
    };
    expect(reportCorrectionSchema.safeParse(correction).success).toBe(true);
    expect(reportCorrectionSchema.safeParse({ ...correction, reasonCode: "member name corrected" }).success).toBe(false);
    expect(reportCorrectionSchema.safeParse({ ...correction, explanation: "sensitive free text" }).success).toBe(false);
  });

  it("documents encrypted JSON retrieval and all state transitions", () => {
    const directory = path.dirname(fileURLToPath(import.meta.url));
    const document = JSON.parse(readFileSync(path.resolve(directory, "../../../docs/api/openapi.json"), "utf8")) as {
      paths: Record<string, Record<string, Record<string, unknown>>>;
    };
    expect(document.paths["/v1/reports/{reportId}/complete"]?.["post"]).toMatchObject({
      operationId: "completeReport",
      "x-required-permissions": ["report.export"],
    });
    expect(document.paths["/v1/reports/{reportId}/fail"]?.["post"]).toMatchObject({ operationId: "failReport" });
    expect(document.paths["/v1/reports/{reportId}/print"]?.["post"]).toMatchObject({ operationId: "recordReportPrint" });
    expect(document.paths["/v1/reports/{reportId}/artifact"]?.["get"]).toMatchObject({
      operationId: "downloadReportArtifact",
      "x-required-permissions": ["report.read", "report.export"],
      "x-mfa-max-age-seconds": 300,
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/ReportArtifactResponse" } } } },
      },
    });
    expect(document.paths["/v1/reports/generate"]?.["post"]).toMatchObject({ "x-mfa-max-age-seconds": 300 });
    expect(document.paths["/v1/reports/{reportId}/corrections"]?.["post"]).toMatchObject({
      operationId: "createReportCorrection",
      "x-required-permissions": ["report.export"],
      "x-mfa-required": true,
      "x-mfa-max-age-seconds": 300,
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/ReportCorrectionRequest" } } } },
    });
    expect(document.paths["/v1/reports/{reportId}/print"]?.["post"]).toMatchObject({ "x-mfa-max-age-seconds": 300 });
    expect(document.paths["/v1/members/export-authorizations"]?.["post"]).toMatchObject({
      operationId: "authorizeMemberExport",
      "x-required-permissions": ["report.export"],
      "x-mfa-max-age-seconds": 300,
    });
  });
});
