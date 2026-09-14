import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";
import { neutralizeSpreadsheetCell } from "./spreadsheet-cell.ts";

import {
  classifyEligiblePeople,
  compareCycleSnapshots,
  countRatio,
  filterOrganizationByStableIds,
  groupIndependentResponsibilities,
  organizationForReportAudience,
  projectOrganizationStage,
  summarizeCommitteeParticipation,
} from "./report-semantics.ts";

const webRoot = path.resolve(import.meta.dirname, "..");
const source = readFileSync(path.join(webRoot, "components/nombramientos/reports-view.tsx"), "utf8");
const artifactSource = readFileSync(path.join(webRoot, "lib/report-export.ts"), "utf8");
const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");
const workflowApiSource = readFileSync(path.join(webRoot, "lib/workflow-api.ts"), "utf8");
const shellSource = readFileSync(path.join(webRoot, "components/nombramientos/app-shell.tsx"), "utf8");
const navigationSource = readFileSync(path.join(webRoot, "lib/app-navigation.ts"), "utf8");

test("CSV y XLSX neutralizan todos los prefijos de fórmula, tabulación y retorno", () => {
  for (const value of [
    "=SUM(A1:A2)",
    "+cmd|' /C calc'!A0",
    "-1+2",
    "@SUM(A1:A2)",
    "\ttexto",
    "\rtexto",
    "\ntexto",
    "   =SUM(A1:A2)",
    "  \ttexto",
  ]) {
    assert.equal(neutralizeSpreadsheetCell(value), `'${value}`);
  }
  for (const value of ["Texto", " texto", "123", ""]) {
    assert.equal(neutralizeSpreadsheetCell(value), value);
  }
  assert.match(artifactSource, /neutralizeSpreadsheetCell\(String\(value\)\)/u);
  assert.match(artifactSource, /neutralizeSpreadsheetCell\(label\)/u);
});

test("la emisión registra sólo el sobre E2EE antes de descargar el texto claro local", () => {
  const lifecycle = source.slice(source.indexOf("const issueReport = async"), source.indexOf("const historyMutation = useMutation"));
  const steps = [
    "api.generateReport(",
    "buildLocalArtifact(",
    "encryptReportArtifact(",
    "api.completeReport(",
    "validateStoredArtifact(",
    "downloadBytes(",
  ].map((needle) => lifecycle.indexOf(needle));
  assert.ok(steps.every((index) => index >= 0), "falta un paso del ciclo de emisión");
  assert.deepEqual(steps, [...steps].sort((left, right) => left - right));
  assert.match(lifecycle, /plaintext\?\.fill\(0\)/);
  assert.match(lifecycle, /api\.failReport\(pending\.id, pending\.version, reportFailureCode\(error\)/);
  assert.doesNotMatch(lifecycle, /artifactBytes|plaintext:\s*plaintext/);
});

test("la corrección crea una emisión enlazada, conserva el alcance y expone navegación lineal", () => {
  const lifecycle = source.slice(source.indexOf("const issueReport = async"), source.indexOf("const historyMutation = useMutation"));
  assert.match(apiSource, /correctReport:[\s\S]*\/corrections/u);
  assert.match(lifecycle, /api\.correctReport\(correction\.previous\.id, correction\.previous\.version, filters, correction\.reasonCode/u);
  assert.match(lifecycle, /validatePendingLineage\(pending, correction\?\.previous, correction\?\.reasonCode\)/u);
  for (const field of ["supersedesReportId", "correctionReasonCode", "lineageRootId", "lineageRevision"]) {
    assert.match(lifecycle, new RegExp(`\\b${field}\\b`, "u"));
  }
  assert.match(source, /report\.correctedByReportId === null/u);
  assert.match(source, /href=\{`#report-\$\{previous\.id\}`\}/u);
  assert.match(source, /href=\{`#report-\$\{next\.id\}`\}/u);
  assert.match(source, /message\(locale, "screen\.reportsView\.d3a3400055e0"\)/u);
  assert.deepEqual(["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.reportsView.d3a3400055e0")), ["CORRECCIÓN INMUTABLE", "IMMUTABLE CORRECTION", "CORRECTION IMMUABLE"]);
  for (const reason of ["SOURCE_DATA_CORRECTED", "TRANSLATION_CORRECTED", "STRUCTURE_CORRECTED", "LAYOUT_CORRECTED", "AUTHORIZED_CORRECTION"]) {
    assert.match(source, new RegExp(reason, "u"));
  }
});

test("descarga e impresión histórica verifican manifiesto, AAD, huellas y clave antes de usar el archivo", () => {
  const lifecycle = source.slice(source.indexOf("const historyMutation = useMutation"), source.indexOf("const loading ="));
  const steps = [
    "api.reportArtifact(",
    "validateStoredArtifact(",
    "decryptReportArtifact(",
  ].map((needle) => lifecycle.indexOf(needle));
  assert.ok(steps.every((index) => index >= 0));
  assert.deepEqual(steps, [...steps].sort((left, right) => left - right));
  assert.match(lifecycle, /api\.recordReportPrint\(report\.id, artifact\.artifactSha256/);
  assert.match(lifecycle, /plaintext\.fill\(0\)/);
  assert.match(source, /message\(locale, "screen\.reportsView\.7c6b3fefbae3"\)/u);
  assert.match(getMessage("es", "screen.reportsView.7c6b3fefbae3"), /otra generación de la clave/u);
  assert.doesNotMatch(source, /onClick=\{\(\) => window\.print\(\)\}/);
});

test("el contrato web representa el artefacto cifrado y nunca un cuerpo binario claro", () => {
  for (const field of ["envelope", "artifactSha256", "ciphertextSha256", "ciphertextBytes", "plaintextBytes", "manifest", "requestVersion"]) {
    assert.match(apiSource, new RegExp(`\\b${field}\\b`));
  }
  assert.doesNotMatch(apiSource, /artifactBytes|plaintextArtifact|cleartext/);
  assert.match(shellSource, /canAccessAppSection/u);
  assert.match(navigationSource, /reports: \{ all: \["report\.read"\] \}/u);
});

test("el acta emitida exige una sesión y usa asistencia, agenda y decisiones sanitizadas", () => {
  const branch = source.slice(source.indexOf('if (reportType === "session_minutes")'), source.indexOf('if (reportType === "cycle_history")'));
  for (const field of ["workflow.sessionMinutes", "minutes.attendance", "minutes.agendaItems", "item.decision"]) {
    assert.ok(branch.includes(field), `falta ${field}`);
  }
  assert.match(source, /selected\.id === "session_minutes" && sessionId !== "all" \? sessionId : undefined/u);
  assert.match(source, /reportSelectionComplete/u);
  assert.match(workflowApiSource, /if \(sessionId\) query\.set\("sessionId", sessionId\)/u);
  assert.match(workflowApiSource, /displayEnvelope: Envelope \| null; photoSnapshot: StoredPhotoRecord \| null/u);
  assert.match(source, /attendanceNames\.get\(entry\.identityId\)/u);
  assert.match(source, /purpose: "member-display", schemaVersion: 1/u);
  assert.match(source, /purpose: "committee-display", schemaVersion: 1/u);
  assert.match(source, /message\(locale, "screen\.reportsView\.c5f9db0a521f"\)/u);
  assert.equal(getMessage("en", "screen.reportsView.c5f9db0a521f"), "Historical minutes names could not be authenticated.");
  assert.doesNotMatch(branch, /notesEnvelope|evidenceEnvelope|actorIdentityId/u);
});

test("todos los reportes de ciclo usan el snapshot histórico y sólo persisten filtros que aplican", () => {
  assert.doesNotMatch(source, /api\.dashboard|api\.organization|api\.committee/u);
  assert.match(source, /workflow\.metrics \? summaryRows\(workflow\.metrics/u);
  assert.match(source, /workflowQuery\.data\?\.organization/u);
  assert.match(source, /item\.memberSnapshot\.displayEnvelope/u);
  assert.match(source, /cycleId: cycle\.id, identityId: item\.identityId, purpose: "committee-display", schemaVersion: 1/u);
  assert.match(source, /audit_integrity: \[\]/u);
  assert.match(source, /roster_import_incidents: \[\]/u);
  for (const filter of ["cycle", "term", "session", "department", "office", "person", "phase", "state"]) {
    assert.match(source, new RegExp(`hasFilter\\(\\"${filter}\\"\\)`));
  }
  assert.match(source, /selected\.id === "cycle_history" && cycleId === "all" \? null/u);
  assert.match(source, /snapshotAt: workflowQuery\.data\.generatedAt/u);
});

test("la emisión y el historial formatean fechas en la zona autoritativa del tenant", () => {
  assert.match(source, /function formatTenantDate/u);
  assert.match(source, /workflowQuery\.data\?\.cycle\?\.timezone \?\? session\.tenant\.timezone/u);
  assert.match(source, /buildLocalArtifact\([^\n]+reportTimeZone\)/u);
  assert.match(source, /formatCalendarDate\((?:comparison\.)?cycle\.termStart, locale\)/u);
  assert.doesNotMatch(source, /new Intl\.DateTimeFormat\(report\.locale, \{ dateStyle: "long", timeStyle: "short" \}\)/u);
});

test("PDF y XLSX declaran idioma y localizan su paginación", () => {
  assert.match(artifactSource, /document\.setLanguage\(report\.locale === "es" \? "es-DO"/u);
  assert.match(artifactSource, /document\.setKeywords\(\["nombramientos", "reporte", report\.reportType, report\.locale, report\.audience\]\)/u);
  assert.match(artifactSource, /message\(report\.locale, "screen\.reportsView\.be29af45774e"\).*&P \/ &N/u);
  assert.deepEqual(["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.reportsView.be29af45774e")), ["Página", "Page", "Page"]);
  assert.doesNotMatch(artifactSource, /&RPage &P \/ &N/u);
  const xlsx = artifactSource.slice(artifactSource.indexOf('const sheet = workbook.addWorksheet'), artifactSource.indexOf('const buffer = await workbook.xlsx.writeBuffer'));
  assert.match(xlsx, /\[sheet\.getCell\("A1"\), sheet\.getCell\("B1"\)\]/u);
  assert.match(xlsx, /\[tableHeader\.getCell\(1\), tableHeader\.getCell\(2\)\]/u);
  assert.doesNotMatch(xlsx, /sheet\.getRow\(1\)\.(?:font|fill)/u);
  assert.doesNotMatch(xlsx, /tableHeader\.(?:font|fill)/u);
});

test("los filtros de organigrama son invariantes al idioma y a nombres duplicados", () => {
  const records = [
    { id: "row-1", vacancyId: "vacancy-1", departmentId: "department-a", officeId: "office-a", memberId: "member-a", status: "accepted", departmentName: "Ministerio", officeName: "Dirección" },
    { id: "row-2", vacancyId: "vacancy-2", departmentId: "department-b", officeId: "office-b", memberId: "member-b", status: "accepted", departmentName: "Ministerio", officeName: "Dirección" },
  ];
  assert.deepEqual(filterOrganizationByStableIds(records, {
    departmentId: "department-b",
    officeId: "office-b",
    memberId: "member-b",
    state: "accepted",
  }).map(({ id }) => id), ["row-2"]);
  assert.match(source, /departmentId: input\.department/u);
  assert.match(source, /officeId: input\.officeId/u);
  assert.doesNotMatch(source.slice(source.indexOf("const organization = projectOrganizationStage"), source.indexOf('if (reportType === "cycle_summary")')), /localizedName/u);
  assert.deepEqual(projectOrganizationStage([
    ...records,
    { ...records[0]!, id: "row-elected", status: "elected" },
    { ...records[0]!, id: "row-vacant", status: "vacant" },
  ], "proposal").map(({ id, status }) => ({ id, status })), [
    { id: "row-1", status: "accepted" },
    { id: "row-2", status: "accepted" },
    { id: "row-elected", status: "accepted" },
  ]);
  assert.match(source, /requestedOrganizationStage === "proposal" \|\| requestedOrganizationStage === "elected"/u);
});

test("el informe general conserva recomendaciones, aceptaciones, elecciones y pendientes según audiencia", () => {
  const records = [
    { id: "vacant", vacancyId: "v1", departmentId: "d", officeId: "o1", status: "vacant" },
    { id: "recommended", vacancyId: "v2", departmentId: "d", officeId: "o2", status: "recommended", memberId: "m1", displayName: "Nombre interno", memberSnapshot: { encrypted: true } },
    { id: "accepted", vacancyId: "v3", departmentId: "d", officeId: "o3", status: "accepted", memberId: "m2", displayName: "Otro nombre", memberSnapshot: { encrypted: true } },
    { id: "elected", vacancyId: "v4", departmentId: "d", officeId: "o4", status: "elected", memberId: "m3", displayName: "Nombre público" },
  ];
  assert.deepEqual(organizationForReportAudience(records, "committee").map(({ status }) => status), ["vacant", "recommended", "accepted", "elected"]);
  const church = organizationForReportAudience(records, "church");
  assert.deepEqual(church.map(({ status }) => status), ["vacant", "vacant", "vacant", "elected"]);
  assert.equal(church[1]?.memberId, undefined);
  assert.equal(church[1]?.displayName, undefined);
  assert.equal(church[1]?.memberSnapshot, undefined);
  const branch = source.slice(source.indexOf('if (reportType === "general_recommendations")'), source.indexOf('if (reportType === "elected_board")'));
  assert.match(branch, /return organizationRows\(organization, locale\)/u);
  assert.doesNotMatch(branch, /new Set|status === "elected"/u);
});

test("cargo y ronda calcula porcentajes con denominadores explícitos y maneja cero", () => {
  assert.deepEqual(countRatio(4, 6), { count: 4, denominator: 6, percent: 66.67 });
  assert.deepEqual(countRatio(0, 0), { count: 0, denominator: 0, percent: null });
  const branch = source.slice(source.indexOf('if (reportType === "office_round")'), source.indexOf('if (reportType === "committee_participation")'));
  for (const semantic of ["distinctProponentCount", "supportDenominator", "nonAbstainingBallots", "abstentions", "receivedBallots", 'rule["kind"]', 'decision["status"]', 'decision["unfilledSeats"]']) {
    assert.ok(branch.includes(semantic), `falta ${semantic}`);
  }
  assert.match(branch, /countRatio\(candidate\.votes, published\.aggregate\.nonAbstainingBallots\)/u);
});

test("participación nominal separa cumplimiento y asistencia sin preferencias", () => {
  const summary = summarizeCommitteeParticipation("identity-a", [
    { roundId: "r1", identityId: "identity-a", canSubmit: true, recused: false, status: "received" },
    { roundId: "r2", identityId: "identity-a", canSubmit: true, recused: false, status: "pending" },
    { roundId: "r3", identityId: "identity-a", canSubmit: true, recused: true, status: "recused" },
    { roundId: "r4", identityId: "identity-a", canSubmit: false, recused: false, status: "not_required" },
  ], [
    { sessionId: "s1", attendance: [{ identityId: "identity-a", presenceStatus: "PRESENT" }] },
    { sessionId: "s2", attendance: [{ identityId: "identity-a", presenceStatus: "EXCUSED" }] },
    { sessionId: "s3", attendance: [] },
  ]);
  assert.deepEqual(summary, {
    steps: { count: 1, denominator: 2, percent: 50 },
    pendingSteps: 1,
    recusedSteps: 1,
    notRequiredSteps: 1,
    attendance: { count: 1, denominator: 3, percent: 33.33 },
    absentSessions: 0,
    excusedSessions: 1,
    unrecordedSessions: 1,
  });
  const branch = source.slice(source.indexOf('if (reportType === "committee_participation")'), source.indexOf('if (reportType === "responsibility_distribution")'));
  assert.match(branch, /summarizeCommitteeParticipation/u);
  assert.doesNotMatch(branch, /candidateId|votes|preference|selection/u);
});

test("la carga agrupa exclusivamente por memberId y excluye funciones vinculadas", () => {
  const base = { vacancyId: "vacancy", departmentId: "department", officeId: "office", status: "elected" };
  const groups = [...groupIndependentResponsibilities([
    { ...base, id: "a1", memberId: "member-a", displayName: "Nombre igual" },
    { ...base, id: "a2", memberId: "member-a", displayName: "Nombre renombrado" },
    { ...base, id: "b1", memberId: "member-b", displayName: "Nombre igual" },
    { ...base, id: "linked", memberId: "member-a", displayName: "Nombre igual", linkedToId: "a1" },
  ])].sort((left, right) => left.memberId.localeCompare(right.memberId));
  assert.deepEqual(groups.map(({ memberId, count }) => ({ memberId, count })), [
    { memberId: "member-a", count: 2 },
    { memberId: "member-b", count: 1 },
  ]);
  const branch = source.slice(source.indexOf('if (reportType === "responsibility_distribution")'), source.indexOf('if (reportType === "unconsidered_unassigned")'));
  assert.doesNotMatch(branch, /shortId\s*\?\?|new Map<string, number>/u);
});

test("no considerados, sin recomendación y sin cargo elegido son conjuntos independientes", () => {
  const classified = classifyEligiblePeople([
    { memberId: "never-considered", eligibilityStatus: "eligible", consideredCount: 0, assignedCount: 0 },
    { memberId: "considered-only", eligibilityStatus: "eligible", consideredCount: 1, assignedCount: 0 },
    { memberId: "recommended", eligibilityStatus: "eligible", consideredCount: 1, assignedCount: 1 },
    { memberId: "elected", eligibilityStatus: "eligible", consideredCount: 1, assignedCount: 1 },
    { memberId: "ineligible", eligibilityStatus: "ineligible", consideredCount: 0, assignedCount: 0 },
  ], [
    { memberId: "recommended", state: "ACEPTADA" },
    { memberId: "elected", state: "VIGENTE" },
  ], "all");
  assert.deepEqual(classified.unconsidered.map(({ memberId }) => memberId), ["never-considered"]);
  assert.deepEqual(classified.withoutRecommendation.map(({ memberId }) => memberId), ["never-considered", "considered-only"]);
  assert.deepEqual(classified.withoutElectedOffice.map(({ memberId }) => memberId), ["never-considered", "considered-only", "recommended"]);
});

test("historial compara métricas homogéneas entre ciclos y no inventa métricas internas públicas", () => {
  const snapshots = [
    { cycle: { id: "new", name: "2026", termStart: "2026-01-01", termEnd: "2027-12-31", status: "active", version: 2 }, metrics: { vacanciesTotal: 40, recommended: 20, accepted: 15, congregationallyElected: 10 } },
    { cycle: { id: "old", name: "2024", termStart: "2024-01-01", termEnd: "2025-12-31", status: "archived", version: 4 }, metrics: { vacanciesTotal: 38, recommended: 18, accepted: 12, congregationallyElected: 9 } },
  ];
  const comparisons = compareCycleSnapshots(snapshots, "all", "all");
  assert.equal(comparisons.length, 2);
  assert.deepEqual(comparisons[0]?.deltas, { vacanciesTotal: 2, recommended: 2, accepted: 3, congregationallyElected: 1, coveragePercent: 2.63 });
  const publicComparison = compareCycleSnapshots([
    { cycle: snapshots[0]!.cycle, metrics: { vacanciesTotal: 40, congregationallyElected: 10 } },
    { cycle: snapshots[1]!.cycle, metrics: { vacanciesTotal: 40, congregationallyElected: 8 } },
  ], "all", "all")[0];
  assert.equal(publicComparison?.metrics.recommended, undefined);
  assert.equal(publicComparison?.metrics.coveragePercent, 25);
  assert.match(source, /workflow-report-cycle-comparison/u);
});

test("errores de descifrado son scoped y el deep-link de organigrama usa IDs validados", () => {
  assert.match(source, /Partial<Record<DecryptScope, string>>/u);
  for (const scope of ["organization", "committee", "members", "workflow", "attendance"]) {
    assert.match(source, new RegExp(`scopedDecryptErrors\\(current, \\"${scope}\\"`));
  }
  assert.doesNotMatch(source, /setDecryptError\(/u);
  assert.match(source, /requestedType === "department_organization" \? "department"/u);
  assert.match(source, /params\.get\("cycleId"\)/u);
  assert.match(source, /params\.get\("departmentId"\) \?\? params\.get\("department"\)/u);
  assert.match(source, /\^\[0-9a-f\]\{8\}/u);
});
