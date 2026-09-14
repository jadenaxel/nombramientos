import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

const webRoot = path.resolve(import.meta.dirname, "..");
const source = readFileSync(path.join(webRoot, "components/nombramientos/members-view.tsx"), "utf8");
const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");
const reportsSource = readFileSync(path.join(webRoot, "components/nombramientos/reports-view.tsx"), "utf8");
const importWorkerClientSource = readFileSync(path.join(webRoot, "lib/member-import-worker-client.ts"), "utf8");
const importWorkerSource = readFileSync(path.join(webRoot, "workers/member-import.worker.ts"), "utf8");
const importWorkerE2eSource = readFileSync(path.join(webRoot, "e2e/import-worker.spec.ts"), "utf8");

test("la administración lista activos y archivados sin cambiar la lectura ordinaria", () => {
  assert.match(source, /mayManage \? "\/v1\/members\/manage" : "\/v1\/members"/);
  assert.match(source, /type MemberStatusFilter = "all" \| "active" \| "archived"/);
  assert.match(source, /member\.archived \? "reactivate" : "archive"/);
});

test("crear una persona exige administración y elegibilidad", () => {
  assert.match(source, /const mayCreate = mayManage && mayManageEligibility/);
  assert.match(source, /action=\{mayCreate \?/);
});

test("editar, archivar y reactivar usan OCC e idempotencia estable", () => {
  assert.match(source, /expectedVersion: editingMember\.version/);
  assert.match(source, /method: "PATCH"/);
  assert.match(source, /expectedVersion: lifecycle\.member\.version/);
  assert.match(source, /`\/v1\/members\/\$\{encodeURIComponent\(lifecycle\.member\.id\)\}\/\$\{lifecycle\.action\}`/);
  assert.match(source, /idempotencyKey: editIdempotency\.current/);
  assert.match(source, /idempotencyKey: lifecycleIdempotency\.current/);
});

test("la nota privada queda cifrada y el ámbito operativo se envía estructurado", () => {
  const eligibilityStart = source.indexOf("const eligibility = await encryptJson(");
  const envelopeAssignment = source.indexOf("body.eligibilityEnvelope = eligibility.envelope", eligibilityStart);
  assert.ok(eligibilityStart >= 0 && envelopeAssignment > eligibilityStart);
  const encryptedSection = source.slice(eligibilityStart, envelopeAssignment);
  assert.match(encryptedSection, /privateNote\.trim\(\)/);
  assert.match(encryptedSection, /purpose: "member-eligibility"/);
  assert.doesNotMatch(encryptedSection, /departmentRestriction|validUntil/);
  assert.doesNotMatch(source, /body\.privateNote/);
  assert.match(source, /body\.departmentRestriction = normalizedDepartment/);
  assert.match(source, /body\.validUntil = normalizedValidUntil/);
  assert.match(source, /member\.departmentRestriction \?\? ""/);
  assert.match(source, /members\.scopeAllDepartments/);
  assert.match(source, /mayManageEligibility && <div className="field-stack"><Label htmlFor="member-edit-eligibility"/);
});

test("AC-09 revela la revisión privada sólo con permiso y falla cerrado", () => {
  assert.match(apiSource, /eligibilityEnvelope\?: Envelope/);
  assert.match(source, /const mayReadPrivateNote = session\.permissions\.includes\("private-note\.read"\)/);
  assert.match(source, /mayReadPrivateNote \? "private" : "standard"/);
  assert.match(source, /revealMemberEligibilityReview\(\{[\s\S]*?permissions: session\.permissions,[\s\S]*?key: keyForEnvelope\(vault, session\.tenant\.id, eligibilityEnvelope\)/u);
  assert.match(source, /mayReadPrivateNote && member\.eligibilityReview/);
  assert.match(source, /setMembers\(\[\]\);\s*setDecryptError/u);
  assert.match(source, /privateReviewChanged && privateNote\.trim\(\)/);
});

test("la revisión privada no entra en exportaciones ni reportes", () => {
  const exportStart = source.indexOf("async function exportMembers");
  const exportEnd = source.indexOf("async function downloadXlsxTemplate", exportStart);
  assert.ok(exportStart >= 0 && exportEnd > exportStart);
  assert.doesNotMatch(source.slice(exportStart, exportEnd), /eligibilityReview|eligibilityEnvelope|privateNote/);
  assert.doesNotMatch(reportsSource, /eligibilityReview|eligibilityEnvelope|privateNote/);
});

test("una opción no elegible exige razón visible autorizada", () => {
  assert.match(source, /editNeedsVisibleReason/);
  assert.match(source, /required=\{editNeedsVisibleReason\}/);
  assert.match(source, /editVisibleReason\.trim\(\)\.length < 4/);
  assert.match(source, /member\.visibleReason && !member\.eligible/);
});

test("la plantilla XLSX incluye ejemplo sintético y validaciones simples", () => {
  assert.match(source, /async function downloadXlsxTemplate\(\)/);
  assert.match(source, /demo\.person@example\.invalid/);
  assert.match(source, /\.dataValidation = \{ type: "list"/);
  assert.match(source, /\.xlsx`\)/);
});

test("la inspección y previsualización grande se ejecutan en un Web Worker medido", () => {
  assert.match(source, /createMemberImportWorkerClient\(\)/);
  assert.doesNotMatch(source, /parseUtf8Csv\(fileBytes/);
  assert.doesNotMatch(source, /workbook\.xlsx\.load\(fileBytes\)/);
  assert.match(importWorkerClientSource, /new Worker\(new URL\("\.\.\/workers\/member-import\.worker\.ts", import\.meta\.url\)/);
  assert.match(importWorkerClientSource, /worker\.postMessage\([^;]+, transfer\)/s);
  assert.match(importWorkerSource, /await buildImportPreview\(/);
  assert.match(importWorkerSource, /500_000/);
  assert.match(importWorkerE2eSource, /length: 10_000/);
  assert.match(importWorkerE2eSource, /maxGapMs/);
});

test("la exportación del padrón obtiene autorización MFA auditada antes de construir el archivo", () => {
  const exportStart = source.indexOf("async function exportMembers");
  const authorize = source.indexOf("await api.authorizeMemberExport", exportStart);
  const rows = source.indexOf("const values = exportSelection.map", exportStart);
  const workbook = source.indexOf("await loadExcelJsBrowser()", exportStart);
  assert.ok(exportStart >= 0 && authorize > exportStart && rows > authorize && workbook > authorize);
  assert.match(source.slice(exportStart, authorize), /map\(\(member\) => \(\{ id: member\.id, version: member\.version \}\)\)/);
  assert.doesNotMatch(source.slice(exportStart, authorize), /member\.(displayName|email)/);
  assert.match(source, /filters: \{ status: statusFilter, queryApplied: Boolean\(normalizeSearchText\(search\)\) \}/);
  assert.match(apiSource, /"\/v1\/members\/export-authorizations"/);
});

test("la UI separa identidad y contacto con AAD exacto y no descifra el sobre heredado", () => {
  assert.match(source, /purpose: "member-display", schemaVersion: 1/);
  assert.match(source, /purpose: "member-contact", schemaVersion: 1/);
  assert.doesNotMatch(source, /purpose: "member-profile"/);
  assert.match(source, /if \(!member\.displayEnvelope\)/);
  assert.match(source, /profileMigrationRequired \? "" : member\.displayName/);
  assert.match(source, /body\.resolveLegacyProfile = true/);
  assert.match(source, /body\.contactEnvelope = null/);
});

test("correo, búsqueda y exportación de contacto no se materializan sin permiso", () => {
  assert.match(source, /const mayReadContact = session\.permissions\.includes\("member\.contact\.read"\)/);
  assert.match(source, /const mayManageContact = session\.permissions\.includes\("member\.contact\.manage"\)/);
  assert.match(source, /mayReadContact && contactEnvelope/);
  assert.match(source, /mayReadContact \? ` \$\{member\.email \?\? ""\}` : ""/);
  assert.match(source, /mayReadContact && member\.email \?/);
  assert.match(source, /mayManageContact && <div className="field-stack"><Label htmlFor="member-email"/);
  assert.match(source, /mayManageContact && <div className="field-stack"><Label htmlFor="member-edit-email"/);
  assert.match(source, /includeContact: mayReadContact/);
  assert.match(source, /\.\.\.\(mayReadContact \? \[message\(locale, "screen\.membersView\.2684d6bc9e11"\)\] : \[\]\)/);
  assert.deepEqual(
    ["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.membersView.2684d6bc9e11")),
    ["Correo", "Email", "Courriel"],
  );
  assert.match(source, /\.\.\.\(mayReadContact \? \[neutralizeSpreadsheetCell\(member\.email \?\? ""\)\] : \[\]\)/);
  assert.doesNotMatch(source, /trimStart\(\).*dangerousSpreadsheetPrefix|dangerousSpreadsheetPrefix.*trimStart\(\)/s);
  assert.match(source, /delete displayOnly\.email/);
});
