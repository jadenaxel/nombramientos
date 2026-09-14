import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

import {
  buildProposalAggregate,
  canonicalWorkflowJson,
  proposalEnvelopeContentHash,
  verifyProposalManifest,
  workflowHash,
  type ProposalSubmissionPlaintext,
} from "./workflow-aggregate.ts";
import { isoToLocalDateTimeInZone, localDateTimeInZoneToIso } from "./workflow-time.ts";

const MEMBER_A = "11111111-1111-4111-8111-111111111111";
const MEMBER_B = "22222222-2222-4222-8222-222222222222";
const MEMBER_C = "33333333-3333-4333-8333-333333333333";
const envelope = {
  algorithm: "AES-256-GCM" as const,
  keyId: "tenant-key-v1",
  nonce: "AAAAAAAAAAAAAAAA",
  ciphertext: "BBBBBBBBBBBBBBBBBBBBBBBB",
  aad: "e30",
};
const webRoot = path.resolve(import.meta.dirname, "..");
const workflowClientSource = readFileSync(path.join(webRoot, "lib/workflow-api.ts"), "utf8");
const workflowConsoleSource = readFileSync(path.join(webRoot, "components/nombramientos/workflow-console.tsx"), "utf8");
const sessionConsoleSource = readFileSync(path.join(webRoot, "components/nombramientos/workflow-session-console.tsx"), "utf8");
async function verifiedManifest() {
  const contentHash = await proposalEnvelopeContentHash(envelope);
  const entries = Array.from({ length: 7 }, (_, index) => ({
    position: index + 1,
    receiptId: `66666666-6666-4666-8666-${String(index + 1).padStart(12, "0")}`,
    contentHash,
    submissionRoundVersion: 2,
    envelope,
  }));
  const body = {
    schemaVersion: 1 as const,
    tenantId: "44444444-4444-4444-8444-444444444444",
    roundId: "55555555-5555-4555-8555-555555555555",
    roundVersion: 3,
    candidateSetHash: `sha256:${"b".repeat(64)}` as const,
    rulesHash: `sha256:${"c".repeat(64)}` as const,
    configurationHash: `sha256:${"d".repeat(64)}` as const,
    electorateHash: `sha256:${"e".repeat(64)}` as const,
    candidateIds: [MEMBER_A, MEMBER_B, MEMBER_C],
    entries: entries.map((entry) => ({
      position: entry.position,
      receiptId: entry.receiptId,
      contentHash: entry.contentHash,
      submissionRoundVersion: entry.submissionRoundVersion,
    })),
  };
  return {
    manifestId: "77777777-7777-4777-8777-777777777777",
    manifestHash: await workflowHash(body),
    ...body,
    entryCount: entries.length,
    createdAt: "2026-09-11T12:00:00.000Z",
    entries,
  };
}

test("buildProposalAggregate separates 7/7 participation from 4/6, 3/6 and 2/6 support", async () => {
  const manifest = await verifiedManifest();
  const submissions: ProposalSubmissionPlaintext[] = [
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_A, MEMBER_B] },
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_A, MEMBER_B] },
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_A, MEMBER_C] },
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_A] },
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_B] },
    { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_C] },
    { schema: "nombramientos-submission/v1", abstain: true, selections: [] },
  ];
  const result = await buildProposalAggregate({ manifest, submissions, maxProposalSelections: 2 });
  assert.deepEqual(result.aggregate.candidates, [
    { memberId: MEMBER_A, distinctProponentCount: 4 },
    { memberId: MEMBER_B, distinctProponentCount: 3 },
    { memberId: MEMBER_C, distinctProponentCount: 2 },
  ]);
  assert.equal(result.aggregate.completedResponses, 7);
  assert.equal(result.aggregate.electorateDenominator, 7);
  assert.equal(result.aggregate.effectiveResponseDenominator, 6);
  assert.equal(result.aggregate.sourceManifestHash, manifest.manifestHash);
  const expected = `sha256:${createHash("sha256").update(canonicalWorkflowJson(result.aggregate), "utf8").digest("hex")}`;
  assert.equal(result.aggregateHash, expected);
  assert.doesNotMatch(JSON.stringify(result.aggregate), /identityId|receiptId/);
});

test("buildProposalAggregate validates every opaque response before counting", async () => {
  const base = await verifiedManifest();
  const manifest = { ...base, entryCount: 2, entries: base.entries.slice(0, 2) };
  await assert.rejects(
    buildProposalAggregate({
      manifest,
      maxProposalSelections: 2,
      submissions: [
        { schema: "nombramientos-submission/v1", abstain: false, selections: [MEMBER_A, MEMBER_A] },
        { schema: "nombramientos-submission/v1", abstain: true, selections: [] },
      ],
    }),
    /repite/,
  );
  await assert.rejects(
    buildProposalAggregate({
      manifest,
      maxProposalSelections: 2,
      submissions: [
        { schema: "nombramientos-submission/v1", abstain: false, selections: ["77777777-7777-4777-8777-777777777777"] },
        { schema: "nombramientos-submission/v1", abstain: true, selections: [] },
      ],
    }),
    /fuera del padrón/,
  );
});

test("verifyProposalManifest rejects reordered entries and tampered ciphertext before decrypting", async () => {
  const manifest = await verifiedManifest();
  await verifyProposalManifest(manifest);
  await assert.rejects(
    verifyProposalManifest({ ...manifest, entries: [manifest.entries[1]!, manifest.entries[0]!, ...manifest.entries.slice(2)] }),
    /posiciones|recibos/,
  );
  await assert.rejects(
    verifyProposalManifest({
      ...manifest,
      entries: manifest.entries.map((entry, index) => index === 0
        ? { ...entry, envelope: { ...entry.envelope, ciphertext: `${entry.envelope.ciphertext}A` } }
        : entry),
    }),
    /huella cifrada/,
  );
  await assert.rejects(
    verifyProposalManifest({ ...manifest, manifestHash: `sha256:${"f".repeat(64)}` }),
    /huella del manifiesto/,
  );
});

test("the session console wires persisted attendance, agenda ordering, decisions, and lifecycle", () => {
  for (const endpoint of [
    "/v1/cycles/${resource(cycleId)}/sessions",
    "/v1/sessions/${resource(sessionId)}",
    "/attendance/${resource(identityId)}",
    "/agenda/order",
    "/decisions",
    "/start",
    "/close",
  ]) assert.ok(workflowClientSource.includes(endpoint), `missing ${endpoint}`);
  assert.match(workflowClientSource, /updateSession:[\s\S]*"PATCH"/u);
  assert.match(sessionConsoleSource, /expectedVersion: existing\?\.version \?\? 0/u);
  assert.match(sessionConsoleSource, /expectedSessionVersion: session\.version/u);
  assert.match(sessionConsoleSource, /itemIds,/u);
  assert.match(sessionConsoleSource, /substituteForIdentityId/u);
});

test("session notes and decision evidence use exact tenant-scoped encrypted contexts", () => {
  assert.match(sessionConsoleSource, /purpose: "session-agenda-notes", schemaVersion: 1/u);
  assert.match(sessionConsoleSource, /agendaItemId: decisionForm\.agendaItemId,[\s\S]*purpose: "session-decision-evidence", schemaVersion: 1/u);
  assert.match(sessionConsoleSource, /exactAad: true/u);
  assert.doesNotMatch(sessionConsoleSource, /localStorage|sessionStorage|console\.|error\.message/u);
});

test("workflow consoles enforce the permission required by every privileged query and action", () => {
  assert.match(workflowConsoleSource, /enabled: canManageCycle/u);
  assert.match(workflowConsoleSource, /queryFn: \(\) => api\.members\(\), enabled: canManageCycle && canReadMembers/u);
  assert.match(workflowConsoleSource, /enabled: canManageCommittee && canReadMembers && Boolean\(resolvedCycleId\)/u);
  assert.match(workflowConsoleSource, /enabled: isOrdinaryWorkflow && canReviewCandidates && Boolean/u);
  assert.match(workflowConsoleSource, /enabled: canReadAssignmentHistory && Boolean\(assignment\)/u);
  assert.match(workflowConsoleSource, /canOpenProposals && proposalRound\?\.phase === "CONFIGURADO"/u);
  assert.match(workflowConsoleSource, /canCloseProposals && proposalRound\?\.phase === "PROPUESTAS_ABIERTAS"/u);
  assert.match(workflowConsoleSource, /canCloseProposals && canReviewCandidates && proposalRound\?\.phase === "PROPUESTAS_CERRADAS"/u);
  assert.match(workflowConsoleSource, /canOpenBallots && ballotRound\?\.phase === "LISTA_CONFIRMADA"/u);
  assert.match(workflowConsoleSource, /canCloseBallots && ballotRound\?\.phase === "VOTACION_ABIERTA"/u);
  assert.match(workflowConsoleSource, /canReviewCandidates && canReadAggregates && ballotRound/u);
  assert.match(workflowConsoleSource, /canOpenBallots && canReadAggregates && process\.phase === "DESEMPATE_PENDIENTE"/u);
  assert.match(workflowConsoleSource, /canRecordConsent && assignment\.state === "PROPUESTA_INTERNA"/u);
  assert.match(workflowConsoleSource, /canRecordConsent && assignment\.state === "ACEPTACION_PENDIENTE"/u);
  assert.match(workflowConsoleSource, /canRecordConsent && assignment\.state === "ACEPTADA"/u);
  assert.match(workflowConsoleSource, /canRecordCongregationalDecision && !assignmentProcessPaused && assignment\.state === "ACEPTADA"/u);
  assert.match(workflowConsoleSource, /canReadAssignmentHistory && <section/u);
  assert.match(sessionConsoleSource, /enabled: canManageSessions && Boolean\(cycleId\)/u);
  assert.match(sessionConsoleSource, /enabled: canManageSessions && Boolean\(resolvedSessionId\)/u);
  assert.match(sessionConsoleSource, /canManageAttendanceDirectory \? <>/u);
});

test("eligibility pauses and linked designations are encrypted, permission-gated, and wired to distinct endpoints", () => {
  assert.ok(workflowClientSource.includes("/eligibility-pause/resolve"));
  assert.ok(workflowClientSource.includes("/linked-designations"));
  assert.match(workflowConsoleSource, /hasPermissions\(session, "workflow\.eligibility\.resolve"\)/u);
  assert.match(workflowConsoleSource, /hasPermissions\(session, "linked-designation\.record"\)/u);
  assert.match(workflowConsoleSource, /pauseIds,[\s\S]*resolutionCode: effectiveResolutionCode,[\s\S]*purpose: "eligibility-pause-resolution"/u);
  assert.match(workflowConsoleSource, /baseAssignmentId: selectedLinkedBaseAssignmentId,[\s\S]*purpose: "linked-designation"/u);
  assert.match(workflowConsoleSource, /processLane === "linked_designation"/u);
  assert.match(workflowConsoleSource, /assignment\.office_snapshot\?\.canonicalCode === linkedBaseOfficeCode/u);
  assert.match(workflowConsoleSource, /message\(locale, "screen\.workflowConsole\.e2a2a7070886"\)/u);
  assert.match(getMessage("es", "screen.workflowConsole.e2a2a7070886"), /Esta función no abre una ronda/u);
  assert.match(workflowConsoleSource, /CLOSE_AFTER_REPLACEMENT/u);
  assert.match(workflowConsoleSource, /assignmentProcessPaused/u);
  assert.match(workflowConsoleSource, /withdraw-after-presentation/u);
  assert.match(workflowConsoleSource, /\["ELEGIDA_POR_IGLESIA", "VIGENTE"\]\.includes\(assignment\.state\)/u);
});

test("appointment mechanisms expose only supported vacancy paths and never mimic a ballot for separate procedures", () => {
  assert.match(workflowConsoleSource, /isConfigurableVacancyProcessMechanism/u);
  assert.match(workflowConsoleSource, /configurableOffices\.map/u);
  assert.match(workflowConsoleSource, /message\(locale, "screen\.workflowConsole\.26cea43b62e6"\)/u);
  assert.equal(getMessage("es", "screen.workflowConsole.26cea43b62e6"), "Cargos con procedimiento separado");
  assert.match(workflowConsoleSource, /const isOrdinaryWorkflow = processEnabled && processLane === "ordinary_proposal_ballot"/u);
  assert.match(workflowConsoleSource, /isOrdinaryWorkflow && <section className="grid gap-4 lg:grid-cols-3">/u);
  assert.match(workflowConsoleSource, /message\(locale, "screen\.workflowConsole\.d75a06b8956f"\)/u);
  assert.equal(getMessage("es", "screen.workflowConsole.d75a06b8956f"), "Sin flujo electoral");
  assert.match(getMessage("es", "screen.workflowConsole.3fdd9f346bd7"), /no se habilitan propuestas, candidaturas, papeletas ni escrutinio/u);
});

test("cycle applicability is reversible, versioned, confirmed, and historical instead of destructive", () => {
  assert.ok(workflowClientSource.includes("/applicability"));
  assert.match(workflowClientSource, /expectedCycleVersion: number; expectedProcessVersion: number; enabled: boolean/u);
  assert.match(workflowClientSource, /processVersions: Array<\{ processId: string; version: number \}>/u);
  assert.match(workflowClientSource, /reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE" \| "CYCLE_STRUCTURE_APPLICABILITY_RESTORED"/u);
  assert.match(workflowConsoleSource, /CYCLE_STRUCTURE_NOT_APPLICABLE/u);
  assert.match(workflowConsoleSource, /CYCLE_STRUCTURE_APPLICABILITY_RESTORED/u);
  assert.match(workflowConsoleSource, /<AlertDialog>/u);
  assert.match(workflowConsoleSource, /message\(locale, "screen\.workflowConsole\.09aaca31e1be"\)/u);
  assert.match(getMessage("es", "screen.workflowConsole.09aaca31e1be"), /no se borrarán su proceso, rondas, decisiones ni evidencia histórica/u);
  assert.match(workflowConsoleSource, /processes\.filter\(\(\{ enabled \}\) => enabled\)/u);
  assert.match(workflowConsoleSource, /process\.enabled && process\.procedure_sequence === 1/u);
  assert.equal(getMessage("es", "screen.workflowConsole.ca99f977e164"), "Expediente conservado en solo lectura");
  assert.match(workflowConsoleSource, /invalidateQueries\(\{ queryKey: \["organization", session\.tenant\.id\] \}\)/u);
  assert.match(workflowConsoleSource, /invalidateQueries\(\{ queryKey: \["workflow-report-snapshot", session\.tenant\.id\] \}\)/u);
  assert.match(workflowConsoleSource, /label\.startsWith\("applicability:"\) \? applicabilityError/u);
  assert.match(workflowConsoleSource, /OFFICE_PROCESS_HAS_ACTIVE_ROUNDS/u);
  assert.match(workflowConsoleSource, /OFFICE_PROCESS_REQUIRED_BY_ENABLED_STRUCTURE/u);
});

test("session datetime-local values round-trip in the cycle IANA timezone", () => {
  assert.equal(localDateTimeInZoneToIso("2030-10-01T18:00", "America/La_Paz"), "2030-10-01T22:00:00.000Z");
  assert.equal(isoToLocalDateTimeInZone("2030-10-01T22:00:00.000Z", "America/La_Paz"), "2030-10-01T18:00");
  assert.equal(localDateTimeInZoneToIso("2030-07-01T18:00", "Europe/Paris"), "2030-07-01T16:00:00.000Z");
  assert.throws(() => localDateTimeInZoneToIso("2030-03-31T02:30", "Europe/Paris"), /DATE_TIME_NOT_VALID_IN_TIME_ZONE/u);
  assert.match(workflowConsoleSource, /tenantTimeZone=\{session\.tenant\.timezone\}/u);
  assert.match(workflowConsoleSource, /currentYearInTimeZone\(tenantTimeZone\)/u);
  assert.match(workflowConsoleSource, /timezone: tenantTimeZone/u);
  assert.match(workflowConsoleSource, /formatCalendarDate\(workflow\.cycle\.termStart, locale\)/u);
  assert.doesNotMatch(workflowConsoleSource, /timezone: "America\/La_Paz"|new Date\(\)\.getFullYear\(\)/u);
});
