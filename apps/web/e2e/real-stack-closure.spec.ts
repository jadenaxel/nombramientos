import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import fontkit from "@pdf-lib/fontkit";
import { expect, test, type Page } from "@playwright/test";
import {
  decodePDFRawStream,
  PDFArray,
  PDFDict,
  PDFDocument,
  PDFName,
  PDFRawStream,
  PDFStream,
} from "pdf-lib";
import {
  BALLOT_PURPOSE,
  BALLOT_SCHEMA_VERSION,
  HPKE_SUITE,
  computeBallotContentHash,
  computeTallyAggregateHash,
  createBallotAad,
  createTallyAggregate,
  createTallyAttestationContext,
  exportCustodianPublicKey,
  exportCustodianSigningPublicKey,
  generateCustodianKeyPair,
  generateCustodianSigningKeyPair,
  importCustodianPublicKey,
  openBallotEnvelope,
  sealBallotEnvelope,
  signTallyAttestation,
  type CustodianPrivateKey,
  type CustodianSigningPrivateKey,
} from "@nombramientos/e2ee";
import type { PendingReport, ReportFormat, StoredReportArtifact } from "../lib/api.ts";
import { decryptReportArtifact, encryptReportArtifact, type ReportArtifactDescriptor } from "../lib/report-artifact.ts";
import { buildLocalArtifact } from "../lib/report-export.ts";

const fixture = readFixture();

type Session = { readonly sessionToken: string; readonly csrfToken: string };
type JsonRecord = Record<string, unknown>;

test.describe.serial("real isolated browser to Fastify to PostgreSQL closure", () => {
  test("real PDF, XLSX and CSV reports generate, persist, download and validate", async ({ page }) => {
    await openHarness(page);
    const snapshotResponse = await apiRequest(
      page,
      fixture.sessions.admin,
      "GET",
      `/v1/reports/workflow-snapshot?reportType=cycle_summary&audience=committee&cycleId=${encodeURIComponent(fixture.round.cycleId)}`,
    );
    expect(snapshotResponse.status).toBe(200);
    const snapshot = responseData(snapshotResponse);
    const cycle = recordValue(snapshot["cycle"]);
    expect(cycle).toMatchObject({ id: fixture.round.cycleId, timezone: fixture.tenant.timezone });
    const metrics = recordValue(snapshot["metrics"]);
    const metricValues = [
      numberField(metrics, "vacanciesTotal"),
      numberField(metrics, "recommended"),
      numberField(metrics, "accepted"),
      numberField(metrics, "congregationallyElected"),
    ] as const;
    const snapshotAt = stringField(snapshot, "generatedAt");
    expect(Number.isNaN(Date.parse(snapshotAt))).toBe(false);
    const fontBytes = {
      regular: await readFile(new URL("../public/fonts/report-sans-regular.ttf", import.meta.url)),
      bold: await readFile(new URL("../public/fonts/report-sans-bold.ttf", import.meta.url)),
    };
    const rawTenantKey = Uint8Array.from(Buffer.from(fixture.tenantKey, "base64url"));
    let tenantKey: CryptoKey;
    try {
      tenantKey = await crypto.subtle.importKey("raw", rawTenantKey, "AES-GCM", false, ["encrypt", "decrypt"]);
    } finally {
      rawTenantKey.fill(0);
    }
    const reportIds: string[] = [];
    const cases = [
      {
        format: "pdf",
        locale: "es",
        title: "Resumen verificable del ciclo",
        audience: "Comité",
        sheet: "Reporte",
        labels: ["Vacantes aplicables", "Recomendaciones", "Aceptaciones", "Elecciones por la iglesia"],
      },
      {
        format: "xlsx",
        locale: "en",
        title: "Verifiable cycle summary",
        audience: "Committee",
        sheet: "Report",
        labels: ["Applicable vacancies", "Recommendations", "Acceptances", "Church elections"],
      },
      {
        format: "csv",
        locale: "fr",
        title: "Résumé vérifiable du cycle",
        audience: "Comité",
        sheet: "Rapport",
        labels: ["Postes applicables", "Recommandations", "Acceptations", "Élections par l’Église"],
      },
    ] as const;

    try {
      for (const reportCase of cases) {
        const rows = reportCase.labels.map((label, index) => [label, metricValues[index]!] as const);
        const snapshotSha256 = digest(JSON.stringify({ reportType: "cycle_summary", audience: "committee", rows }));
        const generated = await apiRequest(page, fixture.sessions.admin, "POST", "/v1/reports/generate", {
          reportType: "cycle_summary",
          audience: "committee",
          locale: reportCase.locale,
          format: reportCase.format,
          filters: { cycleId: fixture.round.cycleId, snapshotSha256, snapshotAt },
        }, randomUUID());
        expect(generated.status).toBe(201);
        const pendingData = responseData(generated);
        expect(pendingData).toMatchObject({
          reportType: "cycle_summary",
          audience: "committee",
          locale: reportCase.locale,
          format: reportCase.format,
          state: "pending",
          version: 1,
          filters: { cycleId: fixture.round.cycleId, snapshotSha256, snapshotAt },
          supersedesReportId: null,
          correctedByReportId: null,
          correctionReasonCode: null,
          lineageRevision: 1,
        });
        const reportId = uuidField(pendingData, "id");
        expect(stringField(pendingData, "lineageRootId")).toBe(reportId);
        expect(stringField(pendingData, "filename")).toMatch(new RegExp(`^[^/\\\\]+\\.${reportCase.format}$`, "u"));
        expect(stringField(pendingData, "mediaType")).toBe(reportMediaType(reportCase.format));
        const pending = pendingData as unknown as PendingReport;
        let plaintext: Uint8Array<ArrayBuffer> | undefined;
        let downloaded: Buffer | undefined;
        try {
          plaintext = await buildLocalArtifact(
            pending,
            rows,
            fixture.tenant.name,
            reportCase.title,
            reportCase.audience,
            fixture.tenant.timezone,
            fontBytes,
          );
          const descriptor: ReportArtifactDescriptor = {
            tenantId: fixture.tenantId,
            reportId,
            requestVersion: pending.version,
            reportType: pending.reportType,
            audience: pending.audience,
            locale: pending.locale,
            format: pending.format,
            filename: pending.filename,
            mediaType: pending.mediaType,
            snapshotSha256,
          };
          const encrypted = await encryptReportArtifact({
            key: tenantKey,
            keyId: fixture.tenantKeyId,
            descriptor,
            plaintext,
          });
          const completion = await apiRequest(page, fixture.sessions.admin, "POST", `/v1/reports/${reportId}/complete`, {
            expectedVersion: pending.version,
            envelope: encrypted.envelope,
            artifactSha256: encrypted.artifactSha256,
            ciphertextSha256: encrypted.ciphertextSha256,
            plaintextBytes: encrypted.plaintextBytes,
            rowCount: rows.length,
            generatedAt: new Date().toISOString(),
          }, randomUUID());
          expect(completion.status).toBe(200);
          const completed = responseData(completion);
          expect(completed).toMatchObject({
            id: reportId,
            state: "ready",
            version: 2,
            artifactSha256: encrypted.artifactSha256,
            ciphertextSha256: encrypted.ciphertextSha256,
            ciphertextBytes: encrypted.ciphertextBytes,
            plaintextBytes: plaintext.byteLength,
            lineageRootId: reportId,
            lineageRevision: 1,
            manifest: {
              schemaVersion: 1,
              reportId,
              reportType: "cycle_summary",
              audience: "committee",
              locale: reportCase.locale,
              format: reportCase.format,
              requestVersion: 1,
              snapshotSha256,
              rowCount: rows.length,
            },
          });

          const artifactResponse = await apiRequest(page, fixture.sessions.admin, "GET", `/v1/reports/${reportId}/artifact`);
          expect(artifactResponse.status).toBe(200);
          const artifactData = responseData(artifactResponse);
          expect(artifactData).toMatchObject({
            filename: pending.filename,
            mediaType: pending.mediaType,
            artifactSha256: encrypted.artifactSha256,
            ciphertextSha256: encrypted.ciphertextSha256,
            ciphertextBytes: encrypted.ciphertextBytes,
            plaintextBytes: plaintext.byteLength,
            requestVersion: 1,
            reportType: "cycle_summary",
            audience: "committee",
            locale: reportCase.locale,
            format: reportCase.format,
            version: 2,
            lineageRootId: reportId,
            lineageRevision: 1,
          });
          const artifact = artifactData as unknown as StoredReportArtifact;
          const decrypted = await decryptReportArtifact({
            key: tenantKey,
            keyId: fixture.tenantKeyId,
            descriptor,
            artifact: {
              envelope: artifact.envelope,
              artifactSha256: artifact.artifactSha256,
              ciphertextSha256: artifact.ciphertextSha256,
              ciphertextBytes: artifact.ciphertextBytes,
              plaintextBytes: artifact.plaintextBytes,
            },
          });
          try {
            expect(equalBytes(decrypted, plaintext)).toBe(true);
            downloaded = await downloadBytesThroughBrowser(page, decrypted, artifact.filename, artifact.mediaType);
            expect(equalBytes(downloaded, plaintext)).toBe(true);
            await validateDownloadedReport(downloaded, reportCase, metricValues);
          } finally {
            decrypted.fill(0);
          }
        } finally {
          plaintext?.fill(0);
          downloaded?.fill(0);
        }
        reportIds.push(reportId);
      }
    } finally {
      fontBytes.regular.fill(0);
      fontBytes.bold.fill(0);
    }

    const historyResponse = await apiRequest(page, fixture.sessions.admin, "GET", "/v1/reports?limit=30");
    expect(historyResponse.status).toBe(200);
    const history = arrayField(responseData(historyResponse), "items").map(recordValue);
    for (const reportId of reportIds) expect(requireItem(history, reportId)).toMatchObject({ state: "ready", version: 2 });

    const auditResponse = await apiRequest(page, fixture.sessions.admin, "GET", "/v1/audit");
    expect(auditResponse.status).toBe(200);
    const audit = responseData(auditResponse);
    expect(audit["verified"]).toBe(true);
    const actions = arrayField(audit, "items").map(recordValue).map((item) => item["action"]);
    for (const action of ["report.requested", "report.ready", "report.downloaded"]) {
      expect(actions.filter((candidate) => candidate === action)).toHaveLength(3);
    }
  });

  test("import preview, commit and idempotent retries preserve a separate accent-insensitive homonym", async ({ page }) => {
    await openHarness(page);
    const updateEnvelope = sealMemberDisplay(fixture.members.updateTargetId, "Persona actualizada");
    const homonymEnvelope = sealMemberDisplay(fixture.members.createdHomonymId, "Angela Nunez");
    const previewIdempotencyKey = randomUUID();
    const previewPayload = {
      sourceFingerprint: digest("real-browser-stack-roster-v1"),
      sourceFileName: "roster.csv",
      sourceSheetName: `sheet-${digest("real-browser-stack-sheet-v1")}`,
      columnMapping: { sourceId: 0, displayName: 1, eligible: 2 },
      rows: [{
        sourceRow: 2,
        id: fixture.members.updateTargetId,
        shortId: "RB-UPD-001",
        eligible: true,
        decision: { action: "update", matchBasis: "stable_id" },
        expectedVersion: 1,
        displayEnvelope: updateEnvelope,
        displayContentHash: envelopeContentHash(updateEnvelope),
      }, {
        sourceRow: 3,
        id: fixture.members.createdHomonymId,
        shortId: "RB-HOM-002",
        eligible: true,
        decision: { action: "create", matchBasis: "normalized_name" },
        displayEnvelope: homonymEnvelope,
        displayContentHash: envelopeContentHash(homonymEnvelope),
      }, {
        sourceRow: 4,
        id: fixture.members.skippedMemberId,
        shortId: "RB-SKIP-001",
        eligible: false,
        decision: { action: "skip", matchBasis: "none" },
      }],
    };

    const preview = await apiRequest(page, fixture.sessions.admin, "POST", "/v1/members/import/preview", previewPayload, previewIdempotencyKey);
    expect(preview.status).toBe(201);
    const previewData = responseData(preview);
    expect(previewData).toMatchObject({
      rowCount: 3,
      state: "previewed",
      revision: 1,
      counts: { create: 1, update: 1, skip: 1, errors: 0 },
    });
    expect(previewData["rows"]).toEqual([
      { sourceRow: 2, action: "update", status: "ready", codes: [] },
      { sourceRow: 3, action: "create", status: "ready", codes: [] },
      { sourceRow: 4, action: "skip", status: "ready", codes: [] },
    ]);
    const importId = uuidField(previewData, "importId");

    const previewRetry = await apiRequest(page, fixture.sessions.admin, "POST", "/v1/members/import/preview", previewPayload, previewIdempotencyKey);
    expect(previewRetry.status).toBe(201);
    expect(responseData(previewRetry)).toEqual(previewData);

    const commitIdempotencyKey = randomUUID();
    const commitPayload = { importId, expectedRevision: 1 };
    const commit = await apiRequest(page, fixture.sessions.admin, "POST", "/v1/members/import/commit", commitPayload, commitIdempotencyKey);
    expect(commit.status).toBe(200);
    const commitData = responseData(commit);
    expect(commitData).toEqual({
      importId,
      state: "completed",
      created: 1,
      updated: 1,
      skipped: 1,
      rejected: 0,
      total: 3,
      pausedProcessIds: [],
    });
    const commitRetry = await apiRequest(page, fixture.sessions.admin, "POST", "/v1/members/import/commit", commitPayload, commitIdempotencyKey);
    expect(commitRetry.status).toBe(200);
    expect(responseData(commitRetry)).toEqual(commitData);

    const members = await apiRequest(page, fixture.sessions.admin, "GET", "/v1/members?limit=100");
    expect(members.status).toBe(200);
    const items = arrayField(responseData(members), "items").map(recordValue);
    const existing = requireItem(items, fixture.members.existingHomonymId);
    const created = requireItem(items, fixture.members.createdHomonymId);
    const updated = requireItem(items, fixture.members.updateTargetId);
    expect(items.some((item) => item["id"] === fixture.members.skippedMemberId)).toBe(false);
    expect(existing["id"]).not.toBe(created["id"]);
    expect(existing["shortId"]).toBe("RB-HOM-001");
    expect(created["shortId"]).toBe("RB-HOM-002");
    expect(normalizeName(displayName(existing))).toBe(normalizeName(displayName(created)));
    expect(displayName(updated)).toBe("Persona actualizada");
    expect(updated["version"]).toBe(2);
  });

  test("real ballot and abstention return receipts and reach a two-custodian published tally", async ({ page }) => {
    await openHarness(page);
    const first = await custodianMaterial("one");
    const second = await custodianMaterial("two");
    const firstKeyId = await registerCustodian(page, fixture.sessions.custodianOne, first);
    const secondKeyId = await registerCustodian(page, fixture.sessions.custodianTwo, second);

    const frozen = await apiRequest(page, fixture.sessions.custodianOne, "POST", `/v1/rounds/${fixture.round.id}/custody/freeze`, {
      expectedRoundVersion: 1,
      keyIds: [firstKeyId, secondKeyId],
    }, randomUUID());
    expect(frozen.status).toBe(201);
    expect(responseData(frozen)).toMatchObject({
      roundId: fixture.round.id,
      roundVersion: 1,
      version: 1,
      state: "frozen",
    });

    const recipientsResponse = await apiRequest(
      page,
      fixture.sessions.selectionVoter,
      "GET",
      `/v1/rounds/${fixture.round.id}/custody/recipients`,
    );
    expect(recipientsResponse.status).toBe(200);
    const recipientsData = responseData(recipientsResponse);
    expect(recipientsData).toMatchObject({ roundId: fixture.round.id, roundVersion: 1, custodyVersion: 1, suite: HPKE_SUITE });
    const recipients = await Promise.all(arrayField(recipientsData, "recipients").map(async (value) => {
      const recipient = recordValue(value);
      return importCustodianPublicKey({
        format: "nombramientos.hpke-public-key",
        version: 1,
        suite: HPKE_SUITE,
        recipientId: stringField(recipient, "recipientId"),
        fingerprint: stringField(recipient, "fingerprint"),
        publicKey: stringField(recipient, "hpkePublicKey"),
      });
    }));
    const rules = {
      candidateIds: [...fixture.round.candidateIds],
      minSelections: 0,
      maxSelections: 1,
      allowAbstention: true,
    } as const;
    const aad = await createBallotAad({
      tenantId: fixture.tenantId,
      cycleId: fixture.round.cycleId,
      roundId: fixture.round.id,
      purpose: BALLOT_PURPOSE,
      schemaVersion: BALLOT_SCHEMA_VERSION,
      roundVersion: 1,
    }, rules);
    expect(aad.candidateSetHash).toBe(fixture.round.candidateSetHash);
    expect(aad.rulesHash).toBe(fixture.round.rulesHash);

    const selectedEnvelope = await sealBallotEnvelope({
      payload: { schemaVersion: 1, selections: [fixture.round.candidateIds[0]], abstain: false },
      aad,
      rules,
      recipients,
    });
    const abstentionEnvelope = await sealBallotEnvelope({
      payload: { schemaVersion: 1, selections: [], abstain: true },
      aad,
      rules,
      recipients,
    });
    const selectedHash = await computeBallotContentHash(selectedEnvelope);
    const abstentionHash = await computeBallotContentHash(abstentionEnvelope);
    const voteIdempotencyKey = randomUUID();
    const selectedPayload = { kind: "vote", expectedVersion: 1, envelope: selectedEnvelope, contentHash: selectedHash };

    const selected = await apiRequest(
      page,
      fixture.sessions.selectionVoter,
      "POST",
      `/v1/rounds/${fixture.round.id}/submissions`,
      selectedPayload,
      voteIdempotencyKey,
    );
    expect(selected.status).toBe(201);
    const selectedReceipt = responseData(selected);
    expect(selectedReceipt).toMatchObject({ roundId: fixture.round.id, roundVersion: 1, contentHash: selectedHash, status: "received" });
    const selectedRetry = await apiRequest(
      page,
      fixture.sessions.selectionVoter,
      "POST",
      `/v1/rounds/${fixture.round.id}/submissions`,
      selectedPayload,
      voteIdempotencyKey,
    );
    expect(selectedRetry.status).toBe(201);
    expect(responseData(selectedRetry)).toEqual(selectedReceipt);

    const abstention = await apiRequest(
      page,
      fixture.sessions.abstentionVoter,
      "POST",
      `/v1/rounds/${fixture.round.id}/submissions`,
      { kind: "vote", expectedVersion: 1, envelope: abstentionEnvelope, contentHash: abstentionHash },
      randomUUID(),
    );
    expect(abstention.status).toBe(201);
    const abstentionReceipt = responseData(abstention);
    expect(abstentionReceipt).toMatchObject({ roundId: fixture.round.id, roundVersion: 1, contentHash: abstentionHash, status: "received" });
    expect(uuidField(abstentionReceipt, "receiptId")).not.toBe(uuidField(selectedReceipt, "receiptId"));

    for (const [session, expected] of [
      [fixture.sessions.selectionVoter, selectedReceipt],
      [fixture.sessions.abstentionVoter, abstentionReceipt],
    ] as const) {
      const acknowledgement = await apiRequest(page, session, "GET", `/v1/rounds/${fixture.round.id}/submissions/me`);
      expect(acknowledgement.status).toBe(200);
      expect(responseData(acknowledgement)).toEqual(expected);
    }

    const closed = await apiRequest(page, fixture.sessions.admin, "POST", `/v1/rounds/${fixture.round.id}/close`, {
      expectedVersion: 1,
      reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED",
    }, randomUUID());
    expect(closed.status).toBe(200);
    expect(responseData(closed)).toMatchObject({ roundId: fixture.round.id, newPhase: "VOTACION_CERRADA", version: 2 });

    const manifestResponse = await apiRequest(page, fixture.sessions.custodianOne, "POST", `/v1/rounds/${fixture.round.id}/custody/manifest`, {
      expectedRoundVersion: 2,
      expectedCustodyVersion: 1,
    }, randomUUID());
    expect(manifestResponse.status).toBe(201);
    const manifest = responseData(manifestResponse);
    expect(manifest).toMatchObject({ roundId: fixture.round.id, roundVersion: 3, custodyVersion: 1, entryCount: 2, version: 1, state: "awaiting_attestations" });

    const downloaded = await apiRequest(page, fixture.sessions.custodianOne, "GET", `/v1/rounds/${fixture.round.id}/custody/manifest`);
    expect(downloaded.status).toBe(200);
    const downloadedData = responseData(downloaded);
    const decryptedBallots = await Promise.all(arrayField(downloadedData, "entries").map(async (entry) => {
      const envelope = recordValue(entry)["envelope"];
      return openBallotEnvelope({ envelope, recipient: first.hpke, expectedAad: aad, rules });
    }));
    const aggregate = createTallyAggregate({
      candidateIds: fixture.round.candidateIds,
      minSelections: 0,
      maxSelections: 1,
      allowAbstention: true,
      vacancies: 1,
      rule: { kind: "PLURALITY" },
      ballots: decryptedBallots,
    });
    expect(aggregate).toMatchObject({
      receivedBallots: 2,
      nonAbstainingBallots: 1,
      abstentions: 1,
      decision: { status: "SELECTED", reason: "TOP_K", selectedCandidateIds: [fixture.round.candidateIds[0]] },
    });
    const aggregateHash = await computeTallyAggregateHash(aggregate);
    const context = createTallyAttestationContext({
      tenantId: fixture.tenantId,
      roundId: fixture.round.id,
      manifestId: uuidField(manifest, "manifestId"),
      manifestHash: digestField(manifest, "manifestHash"),
      aggregateHash,
    });
    const firstSignature = await signTallyAttestation(first.signing, context);
    const firstAttestation = await apiRequest(page, fixture.sessions.custodianOne, "POST", `/v1/rounds/${fixture.round.id}/custody/attestations`, {
      expectedManifestVersion: 1,
      aggregate,
      signature: firstSignature.signature,
    }, randomUUID());
    expect(firstAttestation.status).toBe(201);
    expect(responseData(firstAttestation)).toMatchObject({ state: "awaiting_attestations", version: 2, aggregateHash });

    const secondSignature = await signTallyAttestation(second.signing, context);
    const secondAttestation = await apiRequest(page, fixture.sessions.custodianTwo, "POST", `/v1/rounds/${fixture.round.id}/custody/attestations`, {
      expectedManifestVersion: 2,
      aggregate,
      signature: secondSignature.signature,
    }, randomUUID());
    expect(secondAttestation.status).toBe(201);
    expect(responseData(secondAttestation)).toMatchObject({ state: "publishable", version: 3, aggregateHash });

    const publication = await apiRequest(page, fixture.sessions.custodianOne, "POST", `/v1/rounds/${fixture.round.id}/custody/publication`, {
      expectedRoundVersion: 3,
      expectedManifestVersion: 3,
    }, randomUUID());
    expect(publication.status).toBe(200);
    expect(responseData(publication)).toMatchObject({ state: "published", version: 4, roundVersion: 4, aggregateHash, aggregate });

    const published = await apiRequest(page, fixture.sessions.selectionVoter, "GET", `/v1/rounds/${fixture.round.id}/custody/aggregate`);
    expect(published.status).toBe(200);
    expect(responseData(published)).toMatchObject({ roundId: fixture.round.id, state: "published", version: 4, aggregateHash, aggregate });
  });
});

async function openHarness(page: Page): Promise<void> {
  await page.goto(fixture.harnessBaseUrl);
  await expect(page.locator("body")).toHaveAttribute("data-marker", fixture.marker);
}

async function apiRequest(
  page: Page,
  session: Session,
  method: "GET" | "POST",
  pathname: string,
  body?: unknown,
  idempotencyKey?: string,
): Promise<{ readonly status: number; readonly body: unknown; readonly requestId: string | null }> {
  if (!pathname.startsWith("/v1/") || pathname.includes("//")) throw new Error("Invalid real-stack API path");
  await page.context().clearCookies();
  await page.context().addCookies([{
    name: "nom_session",
    value: session.sessionToken,
    url: fixture.apiBaseUrl,
    httpOnly: true,
    secure: false,
    sameSite: "Strict",
  }, {
    name: "nom_csrf",
    value: session.csrfToken,
    url: fixture.apiBaseUrl,
    httpOnly: false,
    secure: false,
    sameSite: "Strict",
  }]);
  return page.evaluate(async ({ apiBaseUrl, csrfToken, method: requestMethod, pathname: requestPath, body: requestBody, idempotencyKey: key }) => {
    const headers: Record<string, string> = {};
    if (requestBody !== undefined) headers["content-type"] = "application/json";
    if (requestMethod !== "GET") headers["x-csrf-token"] = csrfToken;
    if (key !== undefined) headers["idempotency-key"] = key;
    const response = await fetch(`${apiBaseUrl}${requestPath}`, {
      method: requestMethod,
      credentials: "include",
      cache: "no-store",
      headers,
      ...(requestBody === undefined ? {} : { body: JSON.stringify(requestBody) }),
    });
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      responseBody = null;
    }
    return { status: response.status, body: responseBody, requestId: response.headers.get("x-request-id") };
  }, {
    apiBaseUrl: fixture.apiBaseUrl,
    csrfToken: session.csrfToken,
    method,
    pathname,
    body,
    idempotencyKey,
  });
}

function reportMediaType(format: ReportFormat): string {
  return {
    pdf: "application/pdf",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    csv: "text/csv; charset=utf-8",
  }[format];
}

async function downloadBytesThroughBrowser(
  page: Page,
  bytes: Uint8Array,
  filename: string,
  mediaType: string,
): Promise<Buffer> {
  const downloadPromise = page.waitForEvent("download");
  await page.evaluate(({ encoded, downloadFilename, downloadMediaType }) => {
    const binary = atob(encoded);
    const content = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) content[index] = binary.charCodeAt(index);
    const artifact = new Blob([content], { type: downloadMediaType });
    content.fill(0);
    const url = URL.createObjectURL(artifact);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = downloadFilename;
    anchor.rel = "noopener";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }, {
    encoded: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64"),
    downloadFilename: filename,
    downloadMediaType: mediaType,
  });
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(filename);
  const stream = await download.createReadStream();
  const chunks: Buffer[] = [];
  try {
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    expect(await download.failure()).toBeNull();
    return Buffer.concat(chunks);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function validateDownloadedReport(
  bytes: Buffer,
  reportCase: {
    readonly format: ReportFormat;
    readonly locale: "es" | "en" | "fr";
    readonly title: string;
    readonly audience: string;
    readonly sheet: string;
    readonly labels: readonly [string, string, string, string];
  },
  metricValues: readonly [number, number, number, number],
): Promise<void> {
  expect(bytes.byteLength).toBeGreaterThan(reportCase.format === "pdf" ? 8_000 : 100);
  if (reportCase.format === "pdf") {
    const document = await PDFDocument.load(bytes);
    expect(document.getPageCount()).toBeGreaterThanOrEqual(1);
    expect(document.getTitle()).toBe(reportCase.title);
    expect(document.getAuthor()).toBe("Nombramientos");
    const inspection = inspectPortablePdf(document);
    expect(inspection.embeddedFonts).toBeGreaterThanOrEqual(2);
    expect(inspection.textOperators).toBeGreaterThanOrEqual(8);
    const visibleText = inspection.visibleText.normalize("NFC").replace(/\s+/gu, " ");
    expect(visibleText).toContain(reportCase.title.normalize("NFC"));
    reportCase.labels.forEach((label) => expect(visibleText).toContain(label.normalize("NFC")));
    metricValues.forEach((value) => expect(visibleText).toContain(String(value)));
    return;
  }
  if (reportCase.format === "xlsx") {
    const ExcelJS = (await import("exceljs")).default;
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(bytes as unknown as Parameters<typeof workbook.xlsx.load>[0]);
    const sheet = workbook.getWorksheet(reportCase.sheet);
    expect(sheet).toBeDefined();
    expect(sheet!.getCell("A1").value).toBe(reportCase.title);
    expect(sheet!.views[0]).toMatchObject({ state: "frozen" });
    expect(sheet!.autoFilter).toBeDefined();
    const valuesByLabel = new Map<string, unknown>();
    let formulas = 0;
    sheet!.eachRow((row) => row.eachCell((cell) => {
      if (typeof cell.value === "string") valuesByLabel.set(cell.value, row.getCell(2).value);
      if (typeof cell.value === "object" && cell.value !== null && "formula" in cell.value) formulas += 1;
    }));
    expect(formulas).toBe(0);
    reportCase.labels.forEach((label, index) => expect(valuesByLabel.get(label)).toBe(metricValues[index]));
    return;
  }
  const csv = bytes.toString("utf8");
  expect(csv.startsWith("\uFEFF")).toBe(true);
  expect(csv).toContain(`"${reportCase.title}"`);
  reportCase.labels.forEach((label, index) => expect(csv).toContain(`"${label}","${metricValues[index]}"`));
}

function inspectPortablePdf(document: PDFDocument): {
  readonly embeddedFonts: number;
  readonly textOperators: number;
  readonly visibleText: string;
} {
  const inspectedFonts = new Map<PDFDict, Map<number, string>>();
  const visibleText: string[] = [];
  let textOperators = 0;

  for (const page of document.getPages()) {
    const resources = page.node.Resources();
    if (!resources) throw new Error("PDF page has no resources");
    const fonts = resources.lookup(PDFName.of("Font"), PDFDict);
    const unicodeByResource = new Map<string, Map<number, string>>();
    for (const [resourceName, fontValue] of fonts.entries()) {
      const font = document.context.lookup(fontValue, PDFDict);
      if (!font) throw new Error(`PDF font ${resourceName.decodeText()} is unresolved`);
      let unicodeMap = inspectedFonts.get(font);
      if (!unicodeMap) {
        unicodeMap = inspectPortablePdfFont(font);
        inspectedFonts.set(font, unicodeMap);
      }
      unicodeByResource.set(resourceName.decodeText(), unicodeMap);
    }

    const contents = page.node.Contents();
    if (!contents) throw new Error("PDF page has no content stream");
    const contentStreams = contents instanceof PDFArray
      ? contents.asArray().map((value) => document.context.lookup(value, PDFStream))
      : [contents];
    let pageText = "";
    for (const stream of contentStreams) {
      if (!stream) throw new Error("PDF page content stream is unresolved");
      const content = decodedPdfStreamText(stream);
      let activeFont: Map<number, string> | undefined;
      const operators = /\/([^\s/<>{}\[\]()]+)\s+[-+]?(?:\d+(?:\.\d+)?|\.\d+)\s+Tf|<([0-9A-Fa-f]+)>\s*Tj/gu;
      for (const match of content.matchAll(operators)) {
        const resourceName = match[1];
        if (resourceName) {
          activeFont = unicodeByResource.get(resourceName);
          if (!activeFont) throw new Error(`PDF content references unknown font ${resourceName}`);
          continue;
        }
        const encodedText = match[2];
        if (!encodedText || encodedText.length % 4 !== 0 || !activeFont) {
          throw new Error("PDF text operator is not a two-byte mapped glyph sequence");
        }
        let decodedText = "";
        for (let offset = 0; offset < encodedText.length; offset += 4) {
          const cid = Number.parseInt(encodedText.slice(offset, offset + 4), 16);
          const unicode = activeFont.get(cid);
          if (unicode === undefined) throw new Error(`PDF glyph ${cid} has no ToUnicode mapping`);
          decodedText += unicode;
        }
        textOperators += 1;
        pageText += `${decodedText}\n`;
      }
    }
    if (pageText.replace(/\s/gu, "").length < 20) throw new Error("PDF page has no meaningful extractable text");
    visibleText.push(pageText);
  }

  return { embeddedFonts: inspectedFonts.size, textOperators, visibleText: visibleText.join("\n") };
}

function inspectPortablePdfFont(font: PDFDict): Map<number, string> {
  expect(font.lookup(PDFName.of("Subtype"), PDFName).decodeText()).toBe("Type0");
  expect(font.lookup(PDFName.of("Encoding"), PDFName).decodeText()).toBe("Identity-H");
  const descendants = font.lookup(PDFName.of("DescendantFonts"), PDFArray);
  expect(descendants.size()).toBe(1);
  const descendant = descendants.lookup(0, PDFDict);
  expect(descendant.lookup(PDFName.of("Subtype"), PDFName).decodeText()).toBe("CIDFontType2");
  expect(descendant.lookup(PDFName.of("CIDToGIDMap"), PDFName).decodeText()).toBe("Identity");
  const descriptor = descendant.lookup(PDFName.of("FontDescriptor"), PDFDict);
  expect(descriptor.has(PDFName.of("FontFile"))).toBe(false);
  expect(descriptor.has(PDFName.of("FontFile3"))).toBe(false);
  const unicodeStream = font.lookup(PDFName.of("ToUnicode"), PDFStream);
  if (!(unicodeStream instanceof PDFRawStream)) throw new Error("PDF ToUnicode map is not a decodable raw stream");
  const unicodeMap = parseToUnicodeMap(decodedPdfStreamText(unicodeStream));
  expect(unicodeMap.size).toBeGreaterThan(0);
  const fontProgram = descriptor.lookup(PDFName.of("FontFile2"), PDFStream);
  if (!(fontProgram instanceof PDFRawStream)) throw new Error("PDF FontFile2 is not a decodable raw stream");
  const decodedFont = decodePDFRawStream(fontProgram).decode();
  try {
    const glyphCount = validateTrueTypeSubset(decodedFont);
    const parsedFont = fontkit.create(decodedFont);
    expect(parsedFont.numGlyphs).toBe(glyphCount);
    for (let glyphId = 0; glyphId < glyphCount; glyphId += 1) {
      const glyph = parsedFont.getGlyph(glyphId);
      expect(Number.isFinite(glyph.advanceWidth)).toBe(true);
      void glyph.path.toSVG();
    }
    for (const [glyphId, unicode] of unicodeMap) {
      expect(glyphId).toBeGreaterThan(0);
      expect(glyphId).toBeLessThan(glyphCount);
      if (/\S/u.test(unicode)) expect(parsedFont.getGlyph(glyphId).path.toSVG().length).toBeGreaterThan(0);
    }
  } finally {
    decodedFont.fill(0);
  }
  return unicodeMap;
}

function validateTrueTypeSubset(bytes: Uint8Array): number {
  if (bytes.byteLength < 12) throw new Error("Embedded TrueType program is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const signature = view.getUint32(0);
  if (signature !== 0x0001_0000 && signature !== 0x7472_7565) {
    throw new Error("Embedded report font is not a raw TrueType sfnt");
  }
  const tableCount = view.getUint16(4);
  const directoryEnd = 12 + tableCount * 16;
  if (tableCount < 6 || tableCount > 64 || directoryEnd > bytes.byteLength) {
    throw new Error("Embedded TrueType table directory is invalid");
  }
  const tables = new Map<string, { readonly offset: number; readonly length: number }>();
  for (let index = 0; index < tableCount; index += 1) {
    const entry = 12 + index * 16;
    const tag = String.fromCharCode(...bytes.subarray(entry, entry + 4));
    const offset = view.getUint32(entry + 8);
    const length = view.getUint32(entry + 12);
    if (!/^[\x20-\x7E]{4}$/u.test(tag) || tables.has(tag) || offset < directoryEnd || length === 0
      || offset > bytes.byteLength || length > bytes.byteLength - offset) {
      throw new Error("Embedded TrueType table bounds are invalid");
    }
    tables.set(tag, { offset, length });
  }
  const required = ["head", "hhea", "maxp", "hmtx", "loca", "glyf"] as const;
  for (const tag of required) if (!tables.has(tag)) throw new Error(`Embedded TrueType table ${tag} is missing`);
  const head = tables.get("head")!;
  const hhea = tables.get("hhea")!;
  const maxp = tables.get("maxp")!;
  const hmtx = tables.get("hmtx")!;
  const loca = tables.get("loca")!;
  const glyf = tables.get("glyf")!;
  if (head.length < 54 || view.getUint32(head.offset + 12) !== 0x5F0F_3CF5) {
    throw new Error("Embedded TrueType head table is invalid");
  }
  const unitsPerEm = view.getUint16(head.offset + 18);
  const locaFormat = view.getInt16(head.offset + 50);
  if (unitsPerEm < 16 || unitsPerEm > 16_384 || (locaFormat !== 0 && locaFormat !== 1) || hhea.length < 36 || maxp.length < 6) {
    throw new Error("Embedded TrueType metrics are invalid");
  }
  const glyphCount = view.getUint16(maxp.offset + 4);
  const horizontalMetrics = view.getUint16(hhea.offset + 34);
  const locaEntryBytes = locaFormat === 0 ? 2 : 4;
  if (glyphCount < 2 || horizontalMetrics < 1 || horizontalMetrics > glyphCount
    || loca.length < (glyphCount + 1) * locaEntryBytes
    || hmtx.length < horizontalMetrics * 4 + (glyphCount - horizontalMetrics) * 2) {
    throw new Error("Embedded TrueType glyph metrics are inconsistent");
  }
  let previousGlyphOffset = 0;
  for (let glyphId = 0; glyphId <= glyphCount; glyphId += 1) {
    const locaOffset = loca.offset + glyphId * locaEntryBytes;
    const glyphOffset = locaFormat === 0 ? view.getUint16(locaOffset) * 2 : view.getUint32(locaOffset);
    if (glyphOffset < previousGlyphOffset || glyphOffset > glyf.length) {
      throw new Error("Embedded TrueType glyph locations are inconsistent");
    }
    previousGlyphOffset = glyphOffset;
  }
  return glyphCount;
}

function parseToUnicodeMap(value: string): Map<number, string> {
  if (/\bbeginbfrange\b/u.test(value)) throw new Error("Unexpected ranged ToUnicode map");
  const mapping = new Map<number, string>();
  const blocks = [...value.matchAll(/(\d+)\s+beginbfchar([\s\S]*?)endbfchar/gu)];
  if (!blocks.length) throw new Error("PDF ToUnicode map has no bfchar block");
  for (const block of blocks) {
    const expectedEntries = Number(block[1]);
    const entries = [...(block[2] ?? "").matchAll(/<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]+)>/gu)];
    if (entries.length !== expectedEntries) throw new Error("PDF ToUnicode entry count is inconsistent");
    for (const entry of entries) {
      const glyphId = Number.parseInt(entry[1]!, 16);
      if (mapping.has(glyphId)) throw new Error("PDF ToUnicode map contains a duplicate glyph");
      mapping.set(glyphId, decodeUtf16Be(entry[2]!));
    }
  }
  return mapping;
}

function decodeUtf16Be(value: string): string {
  if (value.length === 0 || value.length % 4 !== 0) throw new Error("PDF ToUnicode value is not UTF-16BE");
  let decoded = "";
  for (let offset = 0; offset < value.length; offset += 4) {
    decoded += String.fromCharCode(Number.parseInt(value.slice(offset, offset + 4), 16));
  }
  return decoded;
}

function decodedPdfStreamText(stream: PDFStream): string {
  if (!(stream instanceof PDFRawStream)) throw new Error("PDF stream is not a decodable raw stream");
  const decoded = decodePDFRawStream(stream).decode();
  try {
    return new TextDecoder("latin1").decode(decoded);
  } finally {
    decoded.fill(0);
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

async function custodianMaterial(label: "one" | "two"): Promise<{
  readonly hpke: CustodianPrivateKey;
  readonly signing: CustodianSigningPrivateKey;
  readonly registration: JsonRecord;
}> {
  const hpke = await generateCustodianKeyPair(`real-browser:${fixture.runId}:${label}`);
  const signing = await generateCustodianSigningKeyPair();
  const [hpkePublic, signingPublic] = await Promise.all([
    exportCustodianPublicKey(hpke),
    exportCustodianSigningPublicKey(signing),
  ]);
  return {
    hpke,
    signing,
    registration: {
      deviceId: randomUUID(),
      recipientId: hpkePublic.recipientId,
      expectedVersion: 0,
      suite: HPKE_SUITE,
      hpkePublicKey: hpkePublic.publicKey,
      hpkeFingerprint: hpkePublic.fingerprint,
      signingAlgorithm: "Ed25519",
      signingPublicKeySpki: signingPublic.publicKeySpki,
      signingFingerprint: signingPublic.fingerprint,
    },
  };
}

async function registerCustodian(
  page: Page,
  session: Session,
  material: Awaited<ReturnType<typeof custodianMaterial>>,
): Promise<string> {
  const response = await apiRequest(page, session, "POST", "/v1/custody/keys", material.registration, randomUUID());
  expect(response.status).toBe(201);
  return uuidField(responseData(response), "keyId");
}

function sealMemberDisplay(memberId: string, displayName: string): JsonRecord {
  const key = Buffer.from(fixture.tenantKey, "base64url");
  const nonce = randomBytes(12);
  const aad = Buffer.from(canonicalJson({
    tenantId: fixture.tenantId,
    memberId,
    purpose: "member-display",
    schemaVersion: 1,
  }), "utf8");
  const plaintext = Buffer.from(JSON.stringify({ displayName }), "utf8");
  const encryptedChunks: Buffer[] = [];
  let ciphertext: Buffer | undefined;
  try {
    if (key.byteLength !== 32) throw new Error("Real-stack tenant key has invalid length");
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    encryptedChunks.push(cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
    ciphertext = Buffer.concat(encryptedChunks);
    return {
      algorithm: "AES-256-GCM",
      keyId: fixture.tenantKeyId,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      aad: aad.toString("base64url"),
    };
  } finally {
    key.fill(0);
    plaintext.fill(0);
    for (const chunk of encryptedChunks) chunk.fill(0);
    ciphertext?.fill(0);
    nonce.fill(0);
    aad.fill(0);
  }
}

function openMemberDisplay(value: unknown): JsonRecord {
  const envelope = recordValue(value);
  const key = Buffer.from(fixture.tenantKey, "base64url");
  const encrypted = Buffer.from(stringField(envelope, "ciphertext"), "base64url");
  const nonce = Buffer.from(stringField(envelope, "nonce"), "base64url");
  const aad = Buffer.from(stringField(envelope, "aad"), "base64url");
  const plaintextChunks: Buffer[] = [];
  let plaintext: Buffer | undefined;
  try {
    if (key.byteLength !== 32 || encrypted.byteLength <= 16) throw new Error("Real-stack member envelope is invalid");
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(encrypted.subarray(-16));
    plaintextChunks.push(decipher.update(encrypted.subarray(0, -16)), decipher.final());
    plaintext = Buffer.concat(plaintextChunks);
    return recordValue(JSON.parse(plaintext.toString("utf8")) as unknown);
  } finally {
    key.fill(0);
    encrypted.fill(0);
    nonce.fill(0);
    aad.fill(0);
    for (const chunk of plaintextChunks) chunk.fill(0);
    plaintext?.fill(0);
  }
}

function displayName(member: JsonRecord): string {
  return stringField(openMemberDisplay(member["displayEnvelope"]), "displayName");
}

function envelopeContentHash(envelope: JsonRecord): `sha256:${string}` {
  return digest(JSON.stringify({
    algorithm: envelope["algorithm"],
    keyId: envelope["keyId"],
    nonce: envelope["nonce"],
    ciphertext: envelope["ciphertext"],
    aad: envelope["aad"],
  }));
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as JsonRecord;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function digest(value: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function normalizeName(value: string): string {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/gu, "").toLocaleLowerCase("es").replace(/\s+/gu, " ").trim();
}

function responseData(response: { readonly body: unknown }): JsonRecord {
  const envelope = recordValue(response.body);
  return recordValue(envelope["data"]);
}

function recordValue(value: unknown): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object response");
  return value as JsonRecord;
}

function arrayField(value: JsonRecord, key: string): unknown[] {
  const field = value[key];
  if (!Array.isArray(field)) throw new Error(`Expected array field ${key}`);
  return field;
}

function stringField(value: JsonRecord, key: string): string {
  const field = value[key];
  if (typeof field !== "string") throw new Error(`Expected string field ${key}`);
  return field;
}

function numberField(value: JsonRecord, key: string): number {
  const field = value[key];
  if (typeof field !== "number" || !Number.isFinite(field)) throw new Error(`Expected numeric field ${key}`);
  return field;
}

function uuidField(value: JsonRecord, key: string): string {
  const field = stringField(value, key);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(field)) {
    throw new Error(`Expected UUID field ${key}`);
  }
  return field;
}

function digestField(value: JsonRecord, key: string): `sha256:${string}` {
  const field = stringField(value, key);
  if (!/^sha256:[0-9a-f]{64}$/u.test(field)) throw new Error(`Expected SHA-256 field ${key}`);
  return field as `sha256:${string}`;
}

function requireItem(items: readonly JsonRecord[], id: string): JsonRecord {
  const item = items.find((candidate) => candidate["id"] === id);
  if (!item) throw new Error("Expected member item is absent");
  return item;
}

function readFixture(): {
  readonly marker: "nombramientos-real-browser-stack-v1";
  readonly runId: string;
  readonly apiBaseUrl: string;
  readonly harnessBaseUrl: string;
  readonly tenantId: string;
  readonly tenant: {
    readonly name: string;
    readonly timezone: string;
  };
  readonly tenantKey: string;
  readonly tenantKeyId: string;
  readonly members: {
    readonly existingHomonymId: string;
    readonly updateTargetId: string;
    readonly createdHomonymId: string;
    readonly skippedMemberId: string;
  };
  readonly round: {
    readonly id: string;
    readonly cycleId: string;
    readonly candidateIds: readonly [string, string];
    readonly candidateSetHash: `sha256:${string}`;
    readonly rulesHash: `sha256:${string}`;
  };
  readonly sessions: {
    readonly admin: Session;
    readonly selectionVoter: Session;
    readonly abstentionVoter: Session;
    readonly custodianOne: Session;
    readonly custodianTwo: Session;
  };
} {
  const encoded = process.env["NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64"];
  if (process.env["TEST_WORKER_INDEX"] !== undefined) {
    delete process.env["NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64"];
  }
  if (!encoded || !/^[A-Za-z0-9_-]+$/u.test(encoded)) throw new Error("Real-stack fixture is unavailable");
  const fixtureBytes = Buffer.from(encoded, "base64url");
  let value: JsonRecord;
  try {
    value = recordValue(JSON.parse(fixtureBytes.toString("utf8")) as unknown);
  } finally {
    fixtureBytes.fill(0);
  }
  if (value["schemaVersion"] !== 1
    || value["marker"] !== "nombramientos-real-browser-stack-v1"
    || value["userAgent"] !== "nombramientos-real-browser-stack-e2e/1") {
    throw new Error("Real-stack fixture marker is invalid");
  }
  const apiBaseUrl = loopbackOrigin(value["apiBaseUrl"], "API");
  const harnessBaseUrl = loopbackOrigin(value["harnessBaseUrl"], "harness");
  if (apiBaseUrl === harnessBaseUrl) throw new Error("Real-stack API and browser harness origins must differ");
  const members = recordValue(value["members"]);
  const round = recordValue(value["round"]);
  const tenant = recordValue(value["tenant"]);
  const candidateIds = round["candidateIds"];
  if (!Array.isArray(candidateIds) || candidateIds.length !== 2) throw new Error("Real-stack candidate pair is invalid");
  const sessions = recordValue(value["sessions"]);
  const parseSession = (key: string): Session => {
    const session = recordValue(sessions[key]);
    const sessionToken = stringField(session, "sessionToken");
    const csrfToken = stringField(session, "csrfToken");
    if (!/^[A-Za-z0-9_-]{40,}$/u.test(sessionToken) || !/^[A-Za-z0-9_-]{40,}$/u.test(csrfToken)) {
      throw new Error(`Real-stack session ${key} is invalid`);
    }
    return { sessionToken, csrfToken };
  };
  const tenantKey = stringField(value, "tenantKey");
  const tenantKeyBytes = Buffer.from(tenantKey, "base64url");
  try {
    if (tenantKeyBytes.byteLength !== 32) throw new Error("Real-stack tenant key is invalid");
  } finally {
    tenantKeyBytes.fill(0);
  }
  const parsed = {
    marker: "nombramientos-real-browser-stack-v1",
    runId: requiredUuid(value, "runId"),
    apiBaseUrl,
    harnessBaseUrl,
    tenantId: requiredUuid(value, "tenantId"),
    tenant: {
      name: stringField(tenant, "name"),
      timezone: stringField(tenant, "timezone"),
    },
    tenantKey,
    tenantKeyId: requiredUuid(value, "tenantKeyId"),
    members: {
      existingHomonymId: requiredUuid(members, "existingHomonymId"),
      updateTargetId: requiredUuid(members, "updateTargetId"),
      createdHomonymId: requiredUuid(members, "createdHomonymId"),
      skippedMemberId: requiredUuid(members, "skippedMemberId"),
    },
    round: {
      id: requiredUuid(round, "id"),
      cycleId: requiredUuid(round, "cycleId"),
      candidateIds: [requiredUuid({ value: candidateIds[0] }, "value"), requiredUuid({ value: candidateIds[1] }, "value")],
      candidateSetHash: requiredDigest(round, "candidateSetHash"),
      rulesHash: requiredDigest(round, "rulesHash"),
    },
    sessions: {
      admin: parseSession("admin"),
      selectionVoter: parseSession("selectionVoter"),
      abstentionVoter: parseSession("abstentionVoter"),
      custodianOne: parseSession("custodianOne"),
      custodianTwo: parseSession("custodianTwo"),
    },
  } as const;
  if (parsed.tenant.name !== "Real browser-stack synthetic tenant" || parsed.tenant.timezone !== "America/La_Paz") {
    throw new Error("Real-stack synthetic tenant metadata is invalid");
  }
  const identifiers = [
    parsed.runId,
    parsed.tenantId,
    parsed.tenantKeyId,
    ...Object.values(parsed.members),
    parsed.round.id,
    parsed.round.cycleId,
    ...parsed.round.candidateIds,
  ];
  const sessionValues = Object.values(parsed.sessions);
  if (new Set(identifiers).size !== identifiers.length
    || new Set(sessionValues.map(({ sessionToken }) => sessionToken)).size !== sessionValues.length
    || new Set(sessionValues.map(({ csrfToken }) => csrfToken)).size !== sessionValues.length) {
    throw new Error("Real-stack fixture identifiers and sessions must be unique");
  }
  return parsed;
}

function loopbackOrigin(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`Real-stack ${label} origin is missing`);
  const parsed = new URL(value);
  const port = Number(parsed.port);
  if (parsed.protocol !== "http:" || parsed.hostname !== "localhost" || parsed.host !== `localhost:${parsed.port}`
    || !Number.isInteger(port) || port < 1 || port > 65_535
    || [3_000, 4_000, 55_432].includes(port) || parsed.origin !== value) {
    throw new Error(`Real-stack ${label} origin is not an isolated random loopback port`);
  }
  return parsed.origin;
}

function requiredUuid(record: JsonRecord, key: string): string {
  const value = stringField(record, key);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)) {
    throw new Error(`Real-stack ${key} is not a UUIDv4`);
  }
  return value;
}

function requiredDigest(record: JsonRecord, key: string): `sha256:${string}` {
  const value = stringField(record, key);
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) throw new Error(`Real-stack ${key} is not a digest`);
  return value as `sha256:${string}`;
}
