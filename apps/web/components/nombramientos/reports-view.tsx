"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Download, FileBarChart, FilePenLine, FileSpreadsheet, FileText, Languages, LoaderCircle, Printer, ShieldCheck, X } from "lucide-react";
import { localeMetadata, supportedLocales } from "@nombramientos/i18n";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  api,
  idempotencyKey,
  REPORT_CORRECTION_REASON_CODES,
  type AuditRecord,
  type AuthenticatedSession,
  type GeneratedReport,
  type Locale,
  type MemberImportHistory,
  type MemberRecord,
  type PendingReport,
  type ReportAudience,
  type ReportCorrectionReasonCode,
  type StoredReportArtifact,
  type ReportFilters,
  type ReportFormat,
  type ReportType,
  type StoredReport,
} from "@/lib/api";
import { keyForEnvelope, openJsonEnvelope } from "@/lib/historical-envelope";
import { message, assignmentLabel, localizedApiError, localizedName, phaseLabel } from "@/lib/product-i18n";
import { decryptReportArtifact, encryptReportArtifact, type EncryptedReportArtifact, type ReportArtifactDescriptor } from "@/lib/report-artifact";
import { buildLocalArtifact } from "@/lib/report-export";
import { isLegacyTitleUnavailable, openAgendaTitle, openSessionTitle } from "@/lib/session-title-crypto";
import {
  classifyEligiblePeople,
  compareCycleSnapshots,
  countRatio,
  filterOrganizationByStableIds,
  groupIndependentResponsibilities,
  organizationForReportAudience,
  projectOrganizationStage,
  summarizeCommitteeParticipation,
  type CommitteeAttendanceSession,
} from "@/lib/report-semantics";
import { formatCalendarDate } from "@/lib/tenant-time";
import { workflowApi, type WorkflowReportSnapshot } from "@/lib/workflow-api";
import { DataError, EmptyState, LoadingBlock, PageTitle } from "./workspace-view";

type Audience = ReportAudience;
type ReportRow = readonly [string, string | number];
type VisibleOrganization = WorkflowReportSnapshot["organization"][number] & { displayName?: string; shortId?: string };
type VisibleCommittee = WorkflowReportSnapshot["committee"][number] & { displayName?: string };
type VisibleMember = MemberRecord & { displayName?: string };
type DecryptScope = "organization" | "committee" | "members" | "workflow" | "attendance" | "minutesTitles";
type ReportDefinition = {
  id: ReportType;
  titles: Record<Locale, string>;
  audiences: readonly Audience[];
  permissions?: readonly string[];
};
type ReportFilterKey = "cycle" | "term" | "session" | "department" | "office" | "person" | "phase" | "state";

const ORGANIZATION_PERMISSIONS = ["aggregate.read", "organigram.read"] as const;

const reports: readonly ReportDefinition[] = [
  { id: "cycle_summary", titles: { es: message("es", "screen.reportsView.0866d7335167"), en: message("en", "screen.reportsView.0866d7335167"), fr: message("fr", "screen.reportsView.0866d7335167") }, audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  { id: "general_recommendations", titles: { es: message("es", "screen.reportsView.91555107aef6"), en: message("en", "screen.reportsView.91555107aef6"), fr: message("fr", "screen.reportsView.91555107aef6") }, audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  { id: "elected_board", titles: { es: message("es", "screen.reportsView.028ff1d351e5"), en: message("en", "screen.reportsView.028ff1d351e5"), fr: message("fr", "screen.reportsView.028ff1d351e5") }, audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  { id: "department", titles: { es: message("es", "screen.reportsView.85c1f7890495"), en: message("en", "screen.reportsView.85c1f7890495"), fr: message("fr", "screen.reportsView.85c1f7890495") }, audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  { id: "office_round", titles: { es: message("es", "screen.reportsView.04b82e6e4542"), en: message("en", "screen.reportsView.04b82e6e4542"), fr: message("fr", "screen.reportsView.04b82e6e4542") }, audiences: ["committee", "auditor"], permissions: ["aggregate.read"] },
  { id: "committee_participation", titles: { es: message("es", "screen.reportsView.a95b20284e58"), en: message("en", "screen.reportsView.a95b20284e58"), fr: message("fr", "screen.reportsView.a95b20284e58") }, audiences: ["committee", "auditor"], permissions: ["member.read", "participation.nominal.read"] },
  { id: "responsibility_distribution", titles: { es: message("es", "screen.reportsView.43c2aace70d4"), en: message("en", "screen.reportsView.43c2aace70d4"), fr: message("fr", "screen.reportsView.43c2aace70d4") }, audiences: ["committee", "auditor"], permissions: ORGANIZATION_PERMISSIONS },
  { id: "unconsidered_unassigned", titles: { es: message("es", "screen.reportsView.e6315640a1e1"), en: message("en", "screen.reportsView.e6315640a1e1"), fr: message("fr", "screen.reportsView.e6315640a1e1") }, audiences: ["committee", "auditor"], permissions: ["member.read", ...ORGANIZATION_PERMISSIONS] },
  { id: "progress", titles: { es: message("es", "screen.reportsView.64a35d803217"), en: message("en", "screen.reportsView.64a35d803217"), fr: message("fr", "screen.reportsView.64a35d803217") }, audiences: ["committee", "auditor", "church"], permissions: ORGANIZATION_PERMISSIONS },
  { id: "session_minutes", titles: { es: message("es", "screen.reportsView.9a54ec78360e"), en: message("en", "screen.reportsView.9a54ec78360e"), fr: message("fr", "screen.reportsView.9a54ec78360e") }, audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  { id: "cycle_history", titles: { es: message("es", "screen.reportsView.ae88a5039326"), en: message("en", "screen.reportsView.ae88a5039326"), fr: message("fr", "screen.reportsView.ae88a5039326") }, audiences: ["committee", "auditor", "church"], permissions: ["aggregate.read"] },
  { id: "audit_integrity", titles: { es: message("es", "screen.reportsView.12af05cec626"), en: message("en", "screen.reportsView.12af05cec626"), fr: message("fr", "screen.reportsView.12af05cec626") }, audiences: ["committee", "auditor"], permissions: ["audit.read"] },
  { id: "roster_import_incidents", titles: { es: message("es", "screen.reportsView.df78b3d408a7"), en: message("en", "screen.reportsView.df78b3d408a7"), fr: message("fr", "screen.reportsView.df78b3d408a7") }, audiences: ["committee"], permissions: ["member.read", "member.import"] },
] as const;

const reportFilters: Readonly<Record<ReportType, readonly ReportFilterKey[]>> = {
  cycle_summary: ["cycle"],
  general_recommendations: ["cycle", "department", "office", "person", "state"],
  elected_board: ["cycle", "department", "office", "person"],
  department: ["cycle", "department", "office", "person", "state"],
  office_round: ["cycle", "office", "person", "phase"],
  committee_participation: ["cycle", "person"],
  responsibility_distribution: ["cycle", "department", "office", "person"],
  unconsidered_unassigned: ["cycle", "person"],
  progress: ["cycle", "department"],
  session_minutes: ["cycle", "session"],
  cycle_history: ["cycle", "term"],
  audit_integrity: [],
  roster_import_incidents: [],
};

const copy: Record<Locale, {
  title: string; description: string; generate: string; reportType: string; language: string;
  audience: string; cycle: string; term: string; session: string; department: string; office: string; person: string; phase: string; state: string; formats: string; history: string;
  noReports: string; generated: string; download: string; print: string; all: string; currentCycle: string; selectSession: string; preview: string;
}> = {
  es: { title: message("es", "screen.reportsView.ac093224fa25"), description: message("es", "screen.reportsView.692737901163"), generate: message("es", "screen.reportsView.9168eecff541"), reportType: message("es", "screen.reportsView.3a01db3d76c8"), language: message("es", "screen.reportsView.cd98527c436d"), audience: message("es", "screen.reportsView.32ecf25bb4e9"), cycle: message("es", "screen.reportsView.e5992ae2b006"), term: message("es", "screen.reportsView.b9863bfbe89a"), session: message("es", "screen.reportsView.bba4234f0ca5"), department: message("es", "screen.reportsView.a9c1f5f4089f"), office: message("es", "screen.reportsView.94977dfd3c65"), person: message("es", "screen.reportsView.b792923baa6a"), phase: message("es", "screen.reportsView.21c749ea4cb9"), state: message("es", "screen.reportsView.ad26aee88899"), formats: message("es", "screen.reportsView.b690b9f39f1d"), history: message("es", "screen.reportsView.1a83710a3371"), noReports: message("es", "screen.reportsView.0f5a3443037a"), generated: message("es", "screen.reportsView.65559c3f0eef"), download: message("es", "screen.reportsView.6651cc158a86"), print: message("es", "screen.reportsView.715b65dcd729"), all: message("es", "screen.reportsView.e49424718bbf"), currentCycle: message("es", "screen.reportsView.96aab5497534"), selectSession: message("es", "screen.reportsView.33588ffa6e11"), preview: message("es", "screen.reportsView.bebc0718ba77") },
  en: { title: message("en", "screen.reportsView.ac093224fa25"), description: message("en", "screen.reportsView.692737901163"), generate: message("en", "screen.reportsView.9168eecff541"), reportType: message("en", "screen.reportsView.3a01db3d76c8"), language: message("en", "screen.reportsView.cd98527c436d"), audience: message("en", "screen.reportsView.32ecf25bb4e9"), cycle: message("en", "screen.reportsView.e5992ae2b006"), term: message("en", "screen.reportsView.b9863bfbe89a"), session: message("en", "screen.reportsView.bba4234f0ca5"), department: message("en", "screen.reportsView.a9c1f5f4089f"), office: message("en", "screen.reportsView.94977dfd3c65"), person: message("en", "screen.reportsView.b792923baa6a"), phase: message("en", "screen.reportsView.21c749ea4cb9"), state: message("en", "screen.reportsView.ad26aee88899"), formats: message("en", "screen.reportsView.b690b9f39f1d"), history: message("en", "screen.reportsView.1a83710a3371"), noReports: message("en", "screen.reportsView.0f5a3443037a"), generated: message("en", "screen.reportsView.65559c3f0eef"), download: message("en", "screen.reportsView.6651cc158a86"), print: message("en", "screen.reportsView.715b65dcd729"), all: message("en", "screen.reportsView.e49424718bbf"), currentCycle: message("en", "screen.reportsView.96aab5497534"), selectSession: message("en", "screen.reportsView.33588ffa6e11"), preview: message("en", "screen.reportsView.bebc0718ba77") },
  fr: { title: message("fr", "screen.reportsView.ac093224fa25"), description: message("fr", "screen.reportsView.692737901163"), generate: message("fr", "screen.reportsView.9168eecff541"), reportType: message("fr", "screen.reportsView.3a01db3d76c8"), language: message("fr", "screen.reportsView.cd98527c436d"), audience: message("fr", "screen.reportsView.32ecf25bb4e9"), cycle: message("fr", "screen.reportsView.e5992ae2b006"), term: message("fr", "screen.reportsView.b9863bfbe89a"), session: message("fr", "screen.reportsView.bba4234f0ca5"), department: message("fr", "screen.reportsView.a9c1f5f4089f"), office: message("fr", "screen.reportsView.94977dfd3c65"), person: message("fr", "screen.reportsView.b792923baa6a"), phase: message("fr", "screen.reportsView.21c749ea4cb9"), state: message("fr", "screen.reportsView.ad26aee88899"), formats: message("fr", "screen.reportsView.b690b9f39f1d"), history: message("fr", "screen.reportsView.1a83710a3371"), noReports: message("fr", "screen.reportsView.0f5a3443037a"), generated: message("fr", "screen.reportsView.65559c3f0eef"), download: message("fr", "screen.reportsView.6651cc158a86"), print: message("fr", "screen.reportsView.715b65dcd729"), all: message("fr", "screen.reportsView.e49424718bbf"), currentCycle: message("fr", "screen.reportsView.96aab5497534"), selectSession: message("fr", "screen.reportsView.33588ffa6e11"), preview: message("fr", "screen.reportsView.bebc0718ba77") },
};

const correctionReasonLabels: Readonly<Record<ReportCorrectionReasonCode, Readonly<Record<Locale, string>>>> = {
  SOURCE_DATA_CORRECTED: { es: message("es", "screen.reportsView.28ae0de24889"), en: message("en", "screen.reportsView.28ae0de24889"), fr: message("fr", "screen.reportsView.28ae0de24889") },
  TRANSLATION_CORRECTED: { es: message("es", "screen.reportsView.d1e4579e92de"), en: message("en", "screen.reportsView.d1e4579e92de"), fr: message("fr", "screen.reportsView.d1e4579e92de") },
  STRUCTURE_CORRECTED: { es: message("es", "screen.reportsView.248a68e9b5e1"), en: message("en", "screen.reportsView.248a68e9b5e1"), fr: message("fr", "screen.reportsView.248a68e9b5e1") },
  LAYOUT_CORRECTED: { es: message("es", "screen.reportsView.1ef30f6f6e3b"), en: message("en", "screen.reportsView.1ef30f6f6e3b"), fr: message("fr", "screen.reportsView.1ef30f6f6e3b") },
  AUTHORIZED_CORRECTION: { es: message("es", "screen.reportsView.3399b3607c8b"), en: message("en", "screen.reportsView.3399b3607c8b"), fr: message("fr", "screen.reportsView.3399b3607c8b") },
};

const audienceLabels: Record<Locale, Record<Audience, string>> = {
  es: { committee: message("es", "screen.reportsView.8f711c9795ec"), auditor: message("es", "screen.reportsView.df15dc554d54"), church: message("es", "screen.reportsView.dd287562c7af") },
  en: { committee: message("en", "screen.reportsView.8f711c9795ec"), auditor: message("en", "screen.reportsView.df15dc554d54"), church: message("en", "screen.reportsView.dd287562c7af") },
  fr: { committee: message("fr", "screen.reportsView.8f711c9795ec"), auditor: message("fr", "screen.reportsView.df15dc554d54"), church: message("fr", "screen.reportsView.dd287562c7af") },
};

const metricLabels: Record<Locale, readonly [string, string, string, string]> = {
  es: [message("es", "screen.reportsView.91eea5daa3f0"), message("es", "screen.reportsView.1958a24985cd"), message("es", "screen.reportsView.32ae54b4e050"), message("es", "screen.reportsView.6eb74c1b9b68")],
  en: [message("en", "screen.reportsView.91eea5daa3f0"), message("en", "screen.reportsView.1958a24985cd"), message("en", "screen.reportsView.32ae54b4e050"), message("en", "screen.reportsView.6eb74c1b9b68")],
  fr: [message("fr", "screen.reportsView.91eea5daa3f0"), message("fr", "screen.reportsView.1958a24985cd"), message("fr", "screen.reportsView.32ae54b4e050"), message("fr", "screen.reportsView.6eb74c1b9b68")],
};

const statusLabels: Record<Locale, Record<string, string>> = {
  es: { vacant: message("es", "screen.reportsView.3bc0d5dea231"), recommended: message("es", "screen.reportsView.3ecc6dc36e4e"), accepted: message("es", "screen.reportsView.1c3143b1de1b"), elected: message("es", "screen.reportsView.cb8860f8a573") },
  en: { vacant: message("en", "screen.reportsView.3bc0d5dea231"), recommended: message("en", "screen.reportsView.3ecc6dc36e4e"), accepted: message("en", "screen.reportsView.1c3143b1de1b"), elected: message("en", "screen.reportsView.cb8860f8a573") },
  fr: { vacant: message("fr", "screen.reportsView.3bc0d5dea231"), recommended: message("fr", "screen.reportsView.3ecc6dc36e4e"), accepted: message("fr", "screen.reportsView.1c3143b1de1b"), elected: message("fr", "screen.reportsView.cb8860f8a573") },
};

function formatTenantDate(
  value: string | Date,
  locale: Locale,
  timeZone: string,
  options: Intl.DateTimeFormatOptions,
): string {
  return new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(new Date(value));
}

function reportCodeLabel(locale: Locale, value: string): string {
  const normalized = value.trim().toUpperCase().replaceAll("-", "_").replaceAll(".", "_").replaceAll(" ", "_");
  const labels: Record<string, Parameters<typeof message>[1]> = {
    PROPOSAL: "screen.reportsView.e3cd6351cf2b", BALLOT: "screen.reportsView.f2a768496384", TIEBREAK: "screen.reportsView.02d20d61e7f4",
    CHAIR: "screen.reportsView.89d5e0367cc6", PASTOR: "screen.reportsView.f0380a1573f1", SECRETARY: "screen.reportsView.a8e5562c03b7", MEMBER: "screen.reportsView.61854ff3e331", CUSTODIAN: "screen.reportsView.cba24f9a6545", ADVISOR: "screen.reportsView.8b645bb6cb60",
    DRAFT: "screen.reportsView.ce0c560e78ec", SCHEDULED: "screen.reportsView.39fdf5253e51", ACTIVE: "screen.reportsView.901bb448bee7", OPEN: "screen.reportsView.65f4105072e6", CLOSED: "screen.reportsView.745e95cb6d55", COMPLETED: "screen.reportsView.dbdbe509ac14", CANCELLED: "screen.reportsView.bcbdd0614e06", ARCHIVED: "screen.reportsView.9cf8b062b4b5",
    PROPOSED: "screen.reportsView.b058355cc920", UNDER_REVIEW: "screen.reportsView.0938ed37d662", PRELIMINARY_ACCEPTED: "screen.reportsView.2e1704ce7202", CONFIRMED_FOR_BALLOT: "screen.reportsView.eb7f9e4e99bd", WITHDRAWN: "screen.reportsView.6be4cbedb6da", EXCLUDED: "screen.reportsView.3ace37de165b", INELIGIBLE: "screen.reportsView.2f62bbcd1a22",
    PLURALITY: "screen.reportsView.d576567e1e43", STRICT_MAJORITY: "screen.reportsView.c1d352c86cf3", SELECTED: "screen.reportsView.2601940352b5", PARTIAL_SELECTION: "screen.reportsView.f608e2e04f38", TIEBREAK_REQUIRED: "screen.reportsView.5e261568d787", NO_SELECTION: "screen.reportsView.1539434f3232",
    NON_ABSTAINING_BALLOTS: "screen.reportsView.05f934f8f743", ALL_RECEIVED_BALLOTS: "screen.reportsView.544106c4cc21",
    TOP_K: "screen.reportsView.df0897897d27", CUTOFF_TIE: "screen.reportsView.d9e63eed397c", NO_VALID_CANDIDATE_VOTES: "screen.reportsView.41d47c6789d4", THRESHOLD_NOT_MET: "screen.reportsView.5066802dac6d", INSUFFICIENT_QUALIFIED_CANDIDATES: "screen.reportsView.d65fbb5dfea0",
    CREATE: "screen.reportsView.99fe9024025b", UPDATE: "screen.reportsView.c85458aeb753", SKIP: "screen.reportsView.4bf53261cc26", PREVIEWED: "screen.reportsView.4883e36cec7d", FAILED: "screen.reportsView.03e735025a7e",
    INICIO: "screen.reportsView.c91ca116b24c", START: "screen.reportsView.c91ca116b24c", RECEIVED: "screen.reportsView.67294ca64c17", PENDING: "screen.reportsView.1e4142a7f2f5", IN_PROGRESS: "screen.reportsView.4fa7e5d0a2fc",
    PRESENT: "screen.reportsView.5bf711c932ce", REMOTE: "screen.reportsView.38ce7f0786b9", ABSENT: "screen.reportsView.ae36561bf709", EXCUSED: "screen.reportsView.23c08636e7dd",
    APPROVED: "screen.reportsView.b7418b55d2ca", REJECTED: "screen.reportsView.1879102901e0", DEFERRED: "screen.reportsView.476a17d3240a", RECORDED: "screen.reportsView.6e54e6846eae", DECIDED: "screen.reportsView.605ffe517224",
    CONSENT_RECORDED: "screen.reportsView.9828adfa0868", CONGREGATIONAL_DECISION_RECORDED: "screen.reportsView.2089d0cc003a", PRESENTED_TO_CHURCH: "screen.reportsView.96db5f6d350d", PROVISIONAL_CREATED: "screen.reportsView.2f35818fffe5", TERM_ACTIVATED: "screen.reportsView.a197b3f07432", VACANCY_OPENED: "screen.reportsView.b1b6a69e9cd4",
    DUPLICATE_SOURCE_ROW: "screen.reportsView.24ebd3d199e1", DUPLICATE_TARGET: "screen.reportsView.29de2427462e", DUPLICATE_STABLE_ID: "screen.reportsView.81ab5c74170d", TARGET_EXISTS: "screen.reportsView.2b5ca9e13a04", TARGET_NOT_FOUND: "screen.reportsView.654ebf7e44e0", STABLE_ID_EXISTS: "screen.reportsView.dfa54a185634", STABLE_ID_MISMATCH: "screen.reportsView.8ad0c52776f8", VERSION_CONFLICT: "screen.reportsView.e830bd3f0085",
  };
  const label=labels[normalized];
  return label?message(locale, label):value.replaceAll("_"," ").replaceAll("."," · ");
}

function reportTitle(reportType: ReportType, locale: Locale): string {
  return reports.find(({ id }) => id === reportType)?.titles[locale] ?? reportType;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

function downloadBytes(bytes: Uint8Array<ArrayBuffer>, mediaType: string, filename: string): void {
  downloadBlob(new Blob([bytes], { type: mediaType }), filename);
}

function printPdfBytes(bytes: Uint8Array<ArrayBuffer>): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  const frame = document.createElement("iframe");
  frame.title = "report-print-frame";
  frame.setAttribute("aria-hidden", "true");
  frame.style.position = "fixed";
  frame.style.width = "1px";
  frame.style.height = "1px";
  frame.style.opacity = "0";
  frame.style.pointerEvents = "none";
  frame.onload = () => {
    frame.contentWindow?.focus();
    frame.contentWindow?.print();
  };
  frame.src = url;
  document.body.appendChild(frame);
  window.setTimeout(() => {
    frame.remove();
    URL.revokeObjectURL(url);
  }, 60_000);
}

function expectedReportMediaType(format: ReportFormat): string {
  const mediaTypes: Record<ReportFormat, string> = {
    pdf: "application/pdf",
    xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    csv: "text/csv; charset=utf-8",
  };
  return mediaTypes[format];
}

function formatIcon(format: ReportFormat | "html") {
  if (format === "pdf") return FileText;
  if (format === "xlsx") return FileSpreadsheet;
  return FileBarChart;
}

function reportStateLabel(locale: Locale, state: StoredReport["state"]): string {
  const labels: Record<StoredReport["state"], Parameters<typeof message>[1]> = {
    queued: "screen.reportsView.4539e6c50522",
    pending: "screen.reportsView.990da15134c2",
    ready: "screen.reportsView.4a409d6457dd",
    failed: "screen.reportsView.d0a6fbabc0c0",
    expired: "screen.reportsView.8d68001dbc20",
  };
  const label = labels[state];
  return message(locale, label);
}

function emptyRows(locale: Locale): readonly ReportRow[] {
  return [[message(locale, "screen.reportsView.cfd770dbff0e"), message(locale, "screen.reportsView.14a82ef6df2a")]];
}

function scopedDecryptErrors(
  current: Partial<Record<DecryptScope, string>>,
  scope: DecryptScope,
  error?: string,
): Partial<Record<DecryptScope, string>> {
  if (error === undefined && current[scope] === undefined) return current;
  if (error === current[scope]) return current;
  const next = { ...current };
  if (error === undefined) delete next[scope];
  else next[scope] = error;
  return next;
}

function summaryRows(metrics: NonNullable<WorkflowReportSnapshot["metrics"]>, locale: Locale, audience: Audience): readonly ReportRow[] {
  const labels = metricLabels[locale];
  if (audience === "church") return [[labels[0], metrics.vacanciesTotal], [labels[3], metrics.congregationallyElected]];
  return [[labels[0], metrics.vacanciesTotal], [labels[1], metrics.recommended ?? 0], [labels[2], metrics.accepted ?? 0], [labels[3], metrics.congregationallyElected]];
}

function organizationRows(items: readonly VisibleOrganization[], locale: Locale): readonly ReportRow[] {
  const rows = items.map((item) => {
    const lifecycle = item.processState ? ` · ${assignmentLabel(locale, item.processState)}` : "";
    return [`${localizedName(item.departmentNames, locale, item.departmentName)} · ${localizedName(item.officeNames, locale, item.officeName)}`, `${item.displayName ?? message(locale, "screen.reportsView.31c490317dc7")} · ${statusLabels[locale][item.status] ?? assignmentLabel(locale, item.status)}${lifecycle}`] as const;
  });
  return rows.length ? rows : emptyRows(locale);
}

function buildRows(input: {
  reportType: ReportType; locale: Locale; audience: Audience; timeZone: string;
  workflow: WorkflowReportSnapshot; workflowNames: ReadonlyMap<string, string>;
  attendanceNames: ReadonlyMap<string, string>;
  sessionTitles: ReadonlyMap<string, string>; agendaTitles: ReadonlyMap<string, string>;
  organization: readonly VisibleOrganization[]; committee: readonly VisibleCommittee[];
  attendanceSessions: readonly CommitteeAttendanceSession[];
  attendanceAvailable: boolean;
  historySnapshots: readonly WorkflowReportSnapshot[];
  members: readonly VisibleMember[]; audit?: { items: AuditRecord[]; verified: boolean };
  imports: readonly MemberImportHistory[]; storedReports: readonly StoredReport[];
  cycleId: string; term: string; sessionId: string; department: string; officeId: string; personId: string; phase: string; state: string;
}): readonly ReportRow[] {
  const { reportType, locale, audience, timeZone, workflow, workflowNames, attendanceNames, sessionTitles, agendaTitles, committee, members, audit, imports } = input;
  const organization = input.state === "proposal" && audience === "church" ? [] : projectOrganizationStage(filterOrganizationByStableIds(organizationForReportAudience(input.organization, audience), {
    departmentId: input.department,
    officeId: input.officeId,
    memberId: input.personId,
    state: input.state,
  }), input.state);
  if (reportType === "cycle_summary") return workflow.metrics ? summaryRows(workflow.metrics, locale, audience) : emptyRows(locale);
  if (reportType === "general_recommendations") {
    return organizationRows(organization, locale);
  }
  if (reportType === "elected_board") return organizationRows(organization.filter((item) => item.status === "elected"), locale);
  if (reportType === "department") return organizationRows(organization, locale);
  if (reportType === "office_round") {
    const rows: ReportRow[] = [];
    for (const process of workflow.processes.filter((item) => (input.officeId === "all" || item.officeId === input.officeId) && (input.phase === "all" || item.phase === input.phase))) {
      const office = workflow.offices.find((item) => item.id === process.officeId);
      const officeName = office?.names[locale] ?? office?.canonicalCode ?? process.officeId;
      rows.push(
        [message(locale, "screen.reportsView.94977dfd3c65"), officeName],
        [message(locale, "screen.reportsView.6d9fe872c971"), phaseLabel(locale, process.phase)],
        [message(locale, "screen.reportsView.01c1bd2abc45"), process.vacancyCount],
      );
      if (process.proposalAggregate) rows.push(
        [message(locale, "screen.reportsView.1ad78b746402"), `${process.proposalAggregate.completedResponses} / ${process.proposalAggregate.electorateDenominator}`],
        [message(locale, "screen.reportsView.b9ec1b72c01c"), process.proposalAggregate.effectiveResponseDenominator || message(locale, "screen.reportsView.14a82ef6df2a")],
      );
      const processCandidacies = workflow.candidacies.filter((item) => item.processId === process.id && (input.personId === "all" || item.memberId === input.personId));
      if (!processCandidacies.length && workflow.redactions.includes("candidate_dossiers")) rows.push([
        message(locale, "screen.reportsView.c131db4f9829"),
        message(locale, "screen.reportsView.4ed6b392dfce"),
      ]);
      for (const candidate of processCandidacies) {
        const support = countRatio(candidate.distinctProponentCount, candidate.supportDenominator);
        rows.push([
          `${message(locale, "screen.reportsView.f538cb19ab12")} · ${workflowNames.get(candidate.memberId) ?? candidate.memberId}`,
          `${support.count} / ${support.denominator} ${message(locale, "screen.reportsView.10f1ab4b4167")} · ${support.percent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${support.percent} %`} · ${reportCodeLabel(locale, candidate.state)}`,
        ]);
      }
      for (const round of workflow.rounds.filter((item) => item.processId === process.id && (input.phase === "all" || item.phase === input.phase))) {
        rows.push([`${message(locale, "screen.reportsView.6dbb1275b1bc")} · ${reportCodeLabel(locale, round.workflowStage)}`, `${phaseLabel(locale, round.phase)} · v${round.version}`]);
        const published = workflow.publishedAggregates.find((item) => item.roundId === round.id);
        if (published) {
          const abstentionRatio = countRatio(published.aggregate.abstentions, published.aggregate.receivedBallots);
          const rule = published.aggregate.rule;
          const ruleDenominator = rule["denominator"] ? ` · ${reportCodeLabel(locale, String(rule["denominator"]))}` : "";
          const ruleThreshold = typeof rule["threshold"] === "number" ? ` · ${Number(rule["threshold"]) * 100} %` : "";
          const decision = published.aggregate.decision;
          const decisionDetails = [
            reportCodeLabel(locale, String(decision["status"] ?? "")),
            decision["reason"] ? reportCodeLabel(locale, String(decision["reason"])) : undefined,
            typeof decision["unfilledSeats"] === "number"
              ? `${decision["unfilledSeats"]} ${message(locale, "screen.reportsView.d960c7e5fa84")}`
              : undefined,
          ].filter(Boolean).join(" · ");
          rows.push(
            [message(locale, "screen.reportsView.b872f2607904"), published.aggregate.receivedBallots],
            [message(locale, "screen.reportsView.0f3909f76eee"), published.aggregate.nonAbstainingBallots],
            [message(locale, "screen.reportsView.995af184934e"), `${abstentionRatio.count} / ${abstentionRatio.denominator} ${message(locale, "screen.reportsView.fa88a4bc2f94")} · ${abstentionRatio.percent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${abstentionRatio.percent} %`}`],
            [message(locale, "screen.reportsView.8fd4b0306ad2"), `${reportCodeLabel(locale, String(rule["kind"] ?? ""))}${ruleThreshold}${ruleDenominator}`],
            [message(locale, "screen.reportsView.b85f7ddfa303"), decisionDetails || message(locale, "screen.reportsView.4d6140b354ec")],
          );
          for (const candidate of published.aggregate.candidates) {
            const candidacy = workflow.candidacies.find((item) => item.id === candidate.candidateId);
            if (input.personId !== "all" && candidacy?.memberId !== input.personId) continue;
            const voteRatio = countRatio(candidate.votes, published.aggregate.nonAbstainingBallots);
            rows.push([
              `${message(locale, "screen.reportsView.40685eda0d70")} · ${workflowNames.get(candidacy?.memberId ?? "") ?? candidate.candidateId}`,
              `${voteRatio.count} / ${voteRatio.denominator} ${message(locale, "screen.reportsView.9f2c7f5c78ac")} · ${voteRatio.percent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${voteRatio.percent} %`}`,
            ]);
          }
        }
      }
    }
    return rows.length ? rows : emptyRows(locale);
  }
  if (reportType === "committee_participation") {
    const accountableRoundIds = new Set(workflow.rounds.filter((round) => !["ANNULLED", "ANULADO"].includes(round.phase)).map((round) => round.id));
    const accountableParticipation = workflow.participation.filter((entry) => accountableRoundIds.has(entry.roundId));
    const rows = workflow.committee.flatMap<ReportRow>((member) => {
      if (input.personId !== "all" && (member.memberId ?? member.identityId) !== input.personId) return [];
      const legacy = committee.find((item) => item.identityId === member.identityId);
      const summary = summarizeCommitteeParticipation(member.identityId, accountableParticipation, input.attendanceSessions);
      const stepPercent = summary.steps.percent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${summary.steps.percent} %`;
      const attendancePercent = summary.attendance.percent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${summary.attendance.percent} %`;
      return [[legacy?.displayName ?? (member.memberId ? workflowNames.get(member.memberId) ?? member.memberId : member.identityId), [
        reportCodeLabel(locale, member.roleCode),
        member.votingRight ? message(locale, "screen.reportsView.04b0ca0d4213") : message(locale, "screen.reportsView.3d9a41b6ff1a"),
        `${message(locale, "screen.reportsView.cbfdcc3f5b96")} ${summary.steps.count} / ${summary.steps.denominator} · ${stepPercent}`,
        `${summary.pendingSteps} ${message(locale, "screen.reportsView.5fbdecdf6cc9")}`,
        input.attendanceAvailable
          ? `${message(locale, "screen.reportsView.6c51de69d2ba")} ${summary.attendance.count} / ${summary.attendance.denominator} · ${attendancePercent}`
          : message(locale, "screen.reportsView.43dea7fc2039"),
        input.attendanceAvailable ? `${summary.absentSessions} ${message(locale, "screen.reportsView.b84e971cf4eb")}` : undefined,
        input.attendanceAvailable ? `${summary.excusedSessions} ${message(locale, "screen.reportsView.18415e0be247")}` : undefined,
        input.attendanceAvailable ? `${summary.unrecordedSessions} ${message(locale, "screen.reportsView.ffc4040cbacc")}` : undefined,
        summary.recusedSteps ? `${summary.recusedSteps} ${message(locale, "screen.reportsView.24d863034e63")}` : undefined,
        summary.notRequiredSteps ? `${summary.notRequiredSteps} ${message(locale, "screen.reportsView.487738354a43")}` : undefined,
      ].filter(Boolean).join(" · ")]];
    });
    return rows.length ? rows : emptyRows(locale);
  }
  if (reportType === "responsibility_distribution") {
    if (!workflow.metrics) return emptyRows(locale);
    const eligibleReference = workflow.metrics.eligibleReference ?? 0;
    const people = [...groupIndependentResponsibilities(organization)].sort((left, right) => right.count - left.count || left.memberId.localeCompare(right.memberId));
    const population = input.personId === "all" ? eligibleReference : 1;
    const distributionRows: ReportRow[] = [0, 1, 2, 3].map((count) => [count === 3 ? message(locale, "screen.reportsView.84ec1a2cddb1") : `${count} ${message(locale, "screen.reportsView.8b2ebcb65ae8")}`, count === 0 ? Math.max(0, population - people.length) : people.filter((person) => count === 3 ? person.count >= 3 : person.count === count).length] as const);
    const alertRows: ReportRow[] = people.filter(({ count }) => count >= 2).map((person) => {
      const responsibilities = person.responsibilities.map((item) => `${localizedName(item.departmentNames, locale, item.departmentName)} · ${localizedName(item.officeNames, locale, item.officeName)}`).join("; ");
      return [`${message(locale, "screen.reportsView.4317d31cfa88")} · ${person.displayName ?? workflowNames.get(person.memberId) ?? person.memberId}`, `${person.count} · ${responsibilities}`] as const;
    });
    return [...distributionRows, ...alertRows];
  }
  if (reportType === "unconsidered_unassigned") {
    const categories = classifyEligiblePeople(workflow.eligibleMembers, workflow.assignments, input.personId);
    const rows: ReportRow[] = [
      [message(locale, "screen.reportsView.538bc56a8f2e"), message(locale, "screen.reportsView.4b62a2caae39")],
      [message(locale, "screen.reportsView.b84d0d52b5a4"), categories.unconsidered.length],
      ...categories.unconsidered.map((member) => [`${message(locale, "screen.reportsView.fa767325f888")} · ${workflowNames.get(member.memberId) ?? member.memberId}`, message(locale, "screen.reportsView.2d011b3b3ba8")] as const),
      [message(locale, "screen.reportsView.1a621125554b"), message(locale, "screen.reportsView.e09915bb9676")],
      [message(locale, "screen.reportsView.fa1d5e411e95"), categories.withoutRecommendation.length],
      ...categories.withoutRecommendation.map((member) => [`${message(locale, "screen.reportsView.ee9e23b7e4ea")} · ${workflowNames.get(member.memberId) ?? member.memberId}`, message(locale, "screen.reportsView.ce1bb81a4aaa")] as const),
      [message(locale, "screen.reportsView.f9bc7c60cac0"), categories.withoutElectedOffice.length],
      ...categories.withoutElectedOffice.map((member) => [`${message(locale, "screen.reportsView.320073b3451e")} · ${workflowNames.get(member.memberId) ?? member.memberId}`, message(locale, "screen.reportsView.6175c0b0c1c6")] as const),
    ];
    return rows.length ? rows : emptyRows(locale);
  }
  if (reportType === "progress") {
    if (!workflow.metrics) return emptyRows(locale);
    const departments = new Map<string, { name: string; total: number; covered: number }>();
    for (const item of organization) {
      const value = departments.get(item.departmentId) ?? { name: localizedName(item.departmentNames, locale, item.departmentName), total: 0, covered: 0 };
      value.total += 1;
      if (["recommended", "accepted", "elected"].includes(item.status)) value.covered += 1;
      departments.set(item.departmentId, value);
    }
    return [...summaryRows(workflow.metrics, locale, audience), ...[...departments.values()].map((value) => [value.name, value.total === 0 ? message(locale, "screen.reportsView.14a82ef6df2a") : `${value.covered} / ${value.total} · ${Math.round(value.covered / value.total * 100)} %`] as const)];
  }
  if (reportType === "session_minutes") {
    const rows: ReportRow[] = workflow.cycle ? [
      [message(locale, "screen.reportsView.e5992ae2b006"), workflow.cycle.name],
      [message(locale, "screen.reportsView.b9863bfbe89a"), `${workflow.cycle.termStart} — ${workflow.cycle.termEnd}`],
    ] : [];
    const minutes = workflow.sessionMinutes;
    if (!minutes) {
      rows.push([message(locale, "screen.reportsView.bba4234f0ca5"), message(locale, "screen.reportsView.fe6a4b43eb3c")]);
      return rows;
    }
    const dateTime = (value: string) => formatTenantDate(value, locale, timeZone, { dateStyle: "short", timeStyle: "short" });
    const sessionTitle = audience === "church"
      ? message(locale, "screen.reportsView.614128b94d67", { value0: minutes.sequence })
      : sessionTitles.get(minutes.id) ?? message(locale, "screen.reportsView.30394ed2ba2b");
    rows.push([
      `${minutes.sequence}. ${sessionTitle}`,
      `${dateTime(minutes.startsAt)} — ${dateTime(minutes.endsAt)} · ${reportCodeLabel(locale, minutes.status)}`,
    ]);
    if (minutes.actualStartedAt) rows.push([message(locale, "screen.reportsView.27ace6412ff6"), dateTime(minutes.actualStartedAt)]);
    if (minutes.actualClosedAt) rows.push([message(locale, "screen.reportsView.877dafe90fcc"), dateTime(minutes.actualClosedAt)]);
    rows.push(...minutes.attendance.map((entry, index) => {
      const visibleName = attendanceNames.get(entry.identityId)
        ?? committee.find((person) => person.identityId === entry.identityId)?.displayName
        ?? members.find((person) => person.id === entry.memberId)?.displayName
        ?? `${message(locale, "screen.reportsView.5311a2153592")} ${index + 1}`;
      const substitute = entry.substituteForIdentityId
        ? committee.find((person) => person.identityId === entry.substituteForIdentityId)?.displayName
        : undefined;
      const details = [
        reportCodeLabel(locale, entry.presenceStatus),
        entry.advisory ? message(locale, "screen.reportsView.243814bfc9c8") : undefined,
        entry.votingRight ? message(locale, "screen.reportsView.cf560f635b66") : message(locale, "screen.reportsView.e83ca71633d9"),
        substitute ? `${message(locale, "screen.reportsView.b7c5e4ae5d4f")} ${substitute}` : undefined,
      ].filter(Boolean).join(" · ");
      return [`${message(locale, "screen.reportsView.ab0075f92cbf")} · ${visibleName}`, details] as const;
    }));
    for (const item of minutes.agendaItems) {
      const agendaTitle = audience === "church"
        ? message(locale, "screen.reportsView.fc4c3b95ceaf", { value0: item.position })
        : agendaTitles.get(item.id) ?? message(locale, "screen.reportsView.30394ed2ba2b");
      rows.push([`${message(locale, "screen.reportsView.e45ceb63ef15")} ${item.position} · ${agendaTitle}`, reportCodeLabel(locale, item.status)]);
      if (item.decision) rows.push([
        `${message(locale, "screen.reportsView.57c457729918")} · ${item.decision.decisionCode}`,
        `${reportCodeLabel(locale, item.decision.outcome)} · ${dateTime(item.decision.createdAt)}`,
      ]);
    }
    rows.push(...workflow.transitions.map((transition) => [`${message(locale, "screen.reportsView.57c457729918")} · ${reportCodeLabel(locale,transition.action)}`, `${transition.fromState ? assignmentLabel(locale,transition.fromState) : reportCodeLabel(locale,"INICIO")} → ${assignmentLabel(locale,transition.toState)} · ${formatTenantDate(transition.occurredAt, locale, timeZone, { dateStyle: "short", timeStyle: "short" })}`] as const));
    return rows.length ? rows : emptyRows(locale);
  }
  if (reportType === "cycle_history") {
    const comparisons = compareCycleSnapshots(input.historySnapshots.length ? input.historySnapshots : [workflow], input.cycleId, input.term);
    const delta = (value: number | null | undefined) => value === null || value === undefined
      ? message(locale, "screen.reportsView.191b297d63e4")
      : `${value > 0 ? "+" : ""}${value}`;
    const rows = comparisons.flatMap<ReportRow>((comparison) => {
      const prefix = comparison.cycle.name;
      const baseline = comparison.previousCycleName
        ? `${message(locale, "screen.reportsView.4735e155d3de")} ${comparison.previousCycleName}`
        : message(locale, "screen.reportsView.34d1c280034e");
      return [
        [prefix, `${formatCalendarDate(comparison.cycle.termStart, locale)} — ${formatCalendarDate(comparison.cycle.termEnd, locale)} · ${reportCodeLabel(locale, comparison.cycle.status)} · v${comparison.cycle.version}`],
        [`${prefix} · ${metricLabels[locale][0]}`, `${comparison.metrics.vacanciesTotal} · ${baseline}: ${delta(comparison.deltas?.vacanciesTotal)}`],
        ...(comparison.metrics.recommended === undefined ? [] : [[`${prefix} · ${metricLabels[locale][1]}`, `${comparison.metrics.recommended} · ${baseline}: ${delta(comparison.deltas?.recommended)}`] as const]),
        ...(comparison.metrics.accepted === undefined ? [] : [[`${prefix} · ${metricLabels[locale][2]}`, `${comparison.metrics.accepted} · ${baseline}: ${delta(comparison.deltas?.accepted)}`] as const]),
        [`${prefix} · ${metricLabels[locale][3]}`, `${comparison.metrics.congregationallyElected} · ${baseline}: ${delta(comparison.deltas?.congregationallyElected)}`],
        [`${prefix} · ${comparison.metrics.recommended === undefined ? message(locale, "screen.reportsView.01a8f13d70c3") : message(locale, "screen.reportsView.57b9c5796a07")}`, `${comparison.metrics.coveragePercent === null ? message(locale, "screen.reportsView.14a82ef6df2a") : `${comparison.metrics.coveragePercent} %`} · ${baseline}: ${delta(comparison.deltas?.coveragePercent)} ${comparison.deltas?.coveragePercent === null || comparison.deltas?.coveragePercent === undefined ? "" : message(locale, "screen.reportsView.26f3528eb392")}`],
      ];
    });
    return rows.length ? rows : emptyRows(locale);
  }
  if (reportType === "audit_integrity") return [
    [message(locale, "screen.reportsView.82093c072bd4"), audit?.verified ? message(locale, "screen.reportsView.e788d558d520") : message(locale, "screen.reportsView.5a9a74d68eb8")],
    [message(locale, "screen.reportsView.cf17a622fcbb"), audit?.items.length ?? 0],
    [message(locale, "screen.reportsView.719a462cff3b"), audit?.items[0]?.action ? reportCodeLabel(locale,audit.items[0].action) : message(locale, "screen.reportsView.4d6140b354ec")],
    [message(locale, "screen.reportsView.f478aacea01f"), message(locale, "screen.reportsView.5467a3d3e9ee")],
  ];
  if (reportType === "roster_import_incidents") {
    const importRows = imports.flatMap((item): ReportRow[] => {
      const summary = item.summary;
      const heading = item.sourceFileName ?? message(locale, "screen.reportsView.5897484a622d");
      const rows: ReportRow[] = [
        [`${message(locale, "screen.reportsView.c05b6832522d")} · ${heading}`, `${reportCodeLabel(locale,item.state)} · ${item.rowCount} ${message(locale, "screen.reportsView.7a4c2c0357fd")} · v${item.revision}`],
        [message(locale, "screen.reportsView.146f817cac9c"), item.sourceSheetName],
        [message(locale, "screen.reportsView.e1f14511e470"), item.errorCount],
      ];
      if (summary) rows.push([
        message(locale, "screen.reportsView.bab9a36cd747"),
        `${summary.created} ${message(locale, "screen.reportsView.1311b1b3ba58")} · ${summary.updated} ${message(locale, "screen.reportsView.35a5ee8d64f1")} · ${summary.skipped} ${message(locale, "screen.reportsView.8fcde0cf9232")} · ${summary.rejected} ${message(locale, "screen.reportsView.2b0b1e599a98")}`,
      ]);
      rows.push(...item.errors.map((error) => [
        `${message(locale, "screen.reportsView.62cc5db7178e")} ${error.sourceRow} · ${reportCodeLabel(locale,error.action)}`,
        error.codes.map((code)=>reportCodeLabel(locale,code)).join(", "),
      ] as const));
      if (item.errorsTruncated) rows.push([
        message(locale, "screen.reportsView.fd9aefa0e67f"),
        message(locale, "screen.reportsView.170fc8075239"),
      ]);
      return rows;
    });
    return [
      [message(locale, "screen.reportsView.9476303fbaa0"), members.length],
      [message(locale, "screen.reportsView.65f9c9be667f"), members.filter((member) => member.eligible && !member.archived).length],
      [message(locale, "screen.reportsView.c107d41c9bd9"), members.filter((member) => member.archived).length],
      [message(locale, "screen.reportsView.b2dc694dff49"), imports.length],
      ...importRows,
      ...members.map((member) => [member.displayName ?? member.shortId, member.eligible ? message(locale, "screen.reportsView.92bae68302f7") : message(locale, "screen.reportsView.2f62bbcd1a22")] as const),
    ];
  }
  return emptyRows(locale);
}

async function digestSnapshot(value: unknown): Promise<`sha256:${string}`> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(value)));
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function reportFailureCode(error: unknown): string {
  const code = error instanceof Error ? error.message : "";
  return /^[A-Z][A-Z0-9_]{2,63}$/u.test(code) ? code : "REPORT_CLIENT_GENERATION_FAILED";
}

function reportArtifactError(error: unknown, locale: Locale): string {
  const code = error instanceof Error ? error.message : "";
  if (code === "TENANT_KEY_LOCKED") return message(locale, "screen.reportsView.f697275e23ac");
  if (code === "REPORT_ARTIFACT_KEY_MISMATCH") return message(locale, "screen.reportsView.7c6b3fefbae3");
  if (code.startsWith("REPORT_ARTIFACT_") || code.startsWith("REPORT_SNAPSHOT_") || code === "REPORT_VERSION_INVALID" || code === "REPORT_FILENAME_INVALID") return message(locale, "screen.reportsView.c4fbdf5384d2");
  return localizedApiError(error, locale);
}

function validatePendingReport(report: PendingReport, expected: {
  reportType: ReportType;
  format: ReportFormat;
  locale: Locale;
  audience: ReportAudience;
  snapshotSha256: `sha256:${string}`;
}): void {
  if (
    report.state !== "pending"
    || report.reportType !== expected.reportType
    || report.format !== expected.format
    || report.locale !== expected.locale
    || report.audience !== expected.audience
    || report.filters.snapshotSha256 !== expected.snapshotSha256
    || report.version < 1
    || report.mediaType !== expectedReportMediaType(expected.format)
    || !/^[^/\\\u0000-\u001f]{1,180}\.(?:pdf|xlsx|csv)$/iu.test(report.filename)
  ) throw new Error("REPORT_ARTIFACT_CONTEXT_MISMATCH");
}

function validatePendingLineage(
  report: PendingReport,
  previous: StoredReport | undefined,
  reasonCode: ReportCorrectionReasonCode | undefined,
): void {
  if (!previous) {
    if (
      report.supersedesReportId !== null
      || report.correctedByReportId !== null
      || report.correctionReasonCode !== null
      || report.lineageRootId !== report.id
      || report.lineageRevision !== 1
    ) throw new Error("REPORT_LINEAGE_INVALID");
    return;
  }
  if (
    !reasonCode
    || report.supersedesReportId !== previous.id
    || report.correctedByReportId !== null
    || report.correctionReasonCode !== reasonCode
    || report.lineageRootId !== previous.lineageRootId
    || report.lineageRevision !== previous.lineageRevision + 1
  ) throw new Error("REPORT_LINEAGE_INVALID");
}

function validateStoredArtifact(
  tenantId: string,
  report: StoredReport,
  artifact: StoredReportArtifact,
): { descriptor: ReportArtifactDescriptor; encrypted: EncryptedReportArtifact } {
  const snapshotSha256 = report.filters["snapshotSha256"];
  const manifest = artifact.manifest;
  const correction = report.supersedesReportId !== null;
  if (
    report.state !== "ready"
    || report.format === "html"
    || typeof snapshotSha256 !== "string"
    || !/^sha256:[0-9a-f]{64}$/u.test(snapshotSha256)
    || report.artifactSha256 === null
    || report.ciphertextSha256 === null
    || report.ciphertextBytes === null
    || report.plaintextBytes === null
    || artifact.reportType !== report.reportType
    || artifact.audience !== report.audience
    || artifact.locale !== report.locale
    || artifact.format !== report.format
    || artifact.filename !== report.filename
    || artifact.mediaType !== expectedReportMediaType(report.format)
    || artifact.version !== report.version
    || artifact.artifactSha256 !== report.artifactSha256
    || artifact.ciphertextSha256 !== report.ciphertextSha256
    || artifact.ciphertextBytes !== report.ciphertextBytes
    || artifact.plaintextBytes !== report.plaintextBytes
    || artifact.supersedesReportId !== report.supersedesReportId
    || artifact.correctionReasonCode !== report.correctionReasonCode
    || artifact.lineageRootId !== report.lineageRootId
    || artifact.lineageRevision !== report.lineageRevision
    || manifest.schemaVersion !== 1
    || manifest.reportId !== report.id
    || manifest.reportType !== report.reportType
    || manifest.audience !== report.audience
    || manifest.locale !== report.locale
    || manifest.format !== report.format
    || manifest.requestVersion !== artifact.requestVersion
    || manifest.snapshotSha256 !== snapshotSha256
    || manifest.artifactSha256 !== artifact.artifactSha256
    || manifest.ciphertextSha256 !== artifact.ciphertextSha256
    || manifest.ciphertextBytes !== artifact.ciphertextBytes
    || manifest.plaintextBytes !== artifact.plaintextBytes
    || artifact.ciphertextBytes !== artifact.plaintextBytes + 16
    || !Number.isSafeInteger(manifest.rowCount)
    || manifest.rowCount < 0
    || Number.isNaN(Date.parse(manifest.generatedAt))
    || (manifest.lineageRootId !== undefined && manifest.lineageRootId !== report.lineageRootId)
    || (manifest.lineageRevision !== undefined && manifest.lineageRevision !== report.lineageRevision)
    || (manifest.supersedesReportId !== undefined && manifest.supersedesReportId !== report.supersedesReportId)
    || (manifest.correctionReasonCode !== undefined && manifest.correctionReasonCode !== report.correctionReasonCode)
    || (correction && (
      !report.correctionReasonCode
      || manifest.lineageRootId !== report.lineageRootId
      || manifest.lineageRevision !== report.lineageRevision
      || manifest.supersedesReportId !== report.supersedesReportId
      || manifest.correctionReasonCode !== report.correctionReasonCode
    ))
  ) throw new Error("REPORT_ARTIFACT_CONTEXT_MISMATCH");

  return {
    descriptor: {
      tenantId,
      reportId: report.id,
      requestVersion: artifact.requestVersion,
      reportType: artifact.reportType,
      audience: artifact.audience,
      locale: artifact.locale,
      format: artifact.format,
      filename: artifact.filename,
      mediaType: artifact.mediaType,
      snapshotSha256: manifest.snapshotSha256,
      ...(correction ? {
        supersedesReportId: report.supersedesReportId!,
        correctionReasonCode: report.correctionReasonCode!,
        lineageRootId: report.lineageRootId,
        lineageRevision: report.lineageRevision,
      } : {}),
    },
    encrypted: {
      envelope: artifact.envelope,
      artifactSha256: artifact.artifactSha256,
      ciphertextSha256: artifact.ciphertextSha256,
      ciphertextBytes: artifact.ciphertextBytes,
      plaintextBytes: artifact.plaintextBytes,
    },
  };
}

async function loadAllMembers(locale: Locale): Promise<{ items: MemberRecord[]; total: number }> {
  const items: MemberRecord[] = [];
  const seenCursors = new Set<string>();
  let total: number | undefined;
  let cursor: string | undefined;
  for (let pageIndex = 0; pageIndex < 100; pageIndex += 1) {
    const page = await api.members(cursor);
    total ??= page.total;
    items.push(...page.items);
    const nextCursor = page.nextCursor;
    if (!nextCursor) return { items, total: total ?? items.length };
    if (seenCursors.has(nextCursor)) throw new Error(message(locale, "screen.reportsView.32c15f6edc9a"));
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }
  throw new Error(message(locale, "screen.reportsView.adac634edc84"));
}

export function ReportsView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const queryClient = useQueryClient();
  const vault = useVault();
  const preselectionRef = useRef<string | undefined>(undefined);
  const text = copy[locale];
  const [reportType, setReportType] = useState<ReportType>("cycle_summary");
  const [documentLocale, setDocumentLocale] = useState<Locale>(locale);
  const [audience, setAudience] = useState<Audience>("committee");
  const [cycleId, setCycleId] = useState("all");
  const [term, setTerm] = useState("all");
  const [sessionId, setSessionId] = useState("all");
  const [department, setDepartment] = useState("all");
  const [officeId, setOfficeId] = useState("all");
  const [personId, setPersonId] = useState("all");
  const [phase, setPhase] = useState("all");
  const [state, setState] = useState("all");
  const [lastGenerated, setLastGenerated] = useState<GeneratedReport>();
  const [organization, setOrganization] = useState<VisibleOrganization[]>([]);
  const [committee, setCommittee] = useState<VisibleCommittee[]>([]);
  const [members, setMembers] = useState<VisibleMember[]>([]);
  const [workflowNames, setWorkflowNames] = useState<Map<string, string>>(new Map());
  const [attendanceNames, setAttendanceNames] = useState<Map<string, string>>(new Map());
  const [sessionTitles, setSessionTitles] = useState<Map<string, string>>(new Map());
  const [agendaTitles, setAgendaTitles] = useState<Map<string, string>>(new Map());
  const [decryptErrors, setDecryptErrors] = useState<Partial<Record<DecryptScope, string>>>({});
  const [historyNotice, setHistoryNotice] = useState<string>();
  const [correctionTarget, setCorrectionTarget] = useState<StoredReport>();
  const [correctionReason, setCorrectionReason] = useState<ReportCorrectionReasonCode>("SOURCE_DATA_CORRECTED");
  const mayExport = session.permissions.includes("report.export");
  const canReadMembers = session.permissions.includes("member.read");
  const canReadAudit = session.permissions.includes("audit.read");
  const canReadImports = session.permissions.includes("member.import");
  const canReadAggregates = session.permissions.includes("aggregate.read");
  const availableReports = useMemo(() => reports.filter((report) => !report.permissions || report.permissions.every((permission) => session.permissions.includes(permission))), [session.permissions]);
  const selected = availableReports.find(({ id }) => id === reportType) ?? availableReports[0];
  const selectedAudience = selected?.audiences.includes(audience) ? audience : selected?.audiences[0] ?? audience;
  const activeFilters = selected ? reportFilters[selected.id] : [];
  const hasFilter = (filter: ReportFilterKey) => activeFilters.includes(filter);
  const needsCurrentMembers = selected?.id === "roster_import_incidents" && canReadMembers;
  const needsAudit = selected?.id === "audit_integrity" && canReadAudit;
  const needsImports = selected?.id === "roster_import_incidents" && canReadImports;
  const selectReport = (next: ReportDefinition) => {
    setCorrectionTarget(undefined);
    setReportType(next.id);
    if (!next.audiences.includes(audience)) setAudience(next.audiences[0]!);
    setCycleId("all"); setTerm("all"); setSessionId("all"); setDepartment("all");
    setOfficeId("all"); setPersonId("all"); setPhase("all"); setState("all");
  };
  const prepareCorrection = (report: StoredReport) => {
    const definition = availableReports.find((item) => item.id === report.reportType);
    if (!definition || report.format === "html") return;
    const filterValue = (key: string) => typeof report.filters[key] === "string" ? report.filters[key] as string : "all";
    setReportType(definition.id);
    setDocumentLocale(report.locale);
    setAudience(report.audience);
    setCycleId(filterValue("cycleId"));
    setTerm(filterValue("term"));
    setSessionId(filterValue("sessionId"));
    setDepartment(filterValue("department"));
    setOfficeId(filterValue("office"));
    setPersonId(filterValue("personId"));
    setPhase(filterValue("phase"));
    setState(filterValue("assignmentState"));
    setCorrectionReason("SOURCE_DATA_CORRECTED");
    setHistoryNotice(undefined);
    setCorrectionTarget(report);
  };
  useEffect(() => {
    if (typeof window === "undefined") return;
    const search = window.location.search;
    const key = `${session.tenant.id}:${search}`;
    if (preselectionRef.current === key) return;
    const timeout = window.setTimeout(() => {
      if (preselectionRef.current === key) return;
      preselectionRef.current = key;
      const params = new URLSearchParams(search);
      const requestedType = params.get("reportType");
      const normalizedType = requestedType === "department_organization" ? "department" : requestedType;
      const requestedReport = availableReports.find((report) => report.id === normalizedType);
      if (requestedReport) {
        setReportType(requestedReport.id);
        if (!requestedReport.audiences.includes(audience)) setAudience(requestedReport.audiences[0]!);
      }
      const stableId = (value: string | null) => value && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value) ? value : undefined;
      const requestedCycle = stableId(params.get("cycleId"));
      const requestedDepartment = stableId(params.get("departmentId") ?? params.get("department"));
      const requestedOrganizationStage = params.get("organizationStage");
      if (requestedCycle) setCycleId(requestedCycle);
      if (requestedDepartment) setDepartment(requestedDepartment);
      if (requestedOrganizationStage === "proposal" || requestedOrganizationStage === "elected") setState(requestedOrganizationStage);
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [audience, availableReports, session.tenant.id]);
  const reportsQuery = useQuery({ queryKey: ["reports", session.tenant.id], queryFn: api.reports });
  const membersQuery = useQuery({ queryKey: ["members", "reports", session.tenant.id], queryFn: () => loadAllMembers(locale), enabled: needsCurrentMembers });
  const auditQuery = useQuery({ queryKey: ["audit", "reports", session.tenant.id], queryFn: api.audit, enabled: needsAudit });
  const importsQuery = useQuery({ queryKey: ["member-imports", "reports", session.tenant.id], queryFn: () => api.memberImportHistory(100), enabled: needsImports });
  const workflowQuery = useQuery({
    queryKey: ["workflow-report-snapshot", session.tenant.id, selected?.id, selectedAudience, cycleId, sessionId],
    queryFn: () => {
      if (!selected) throw new Error("REPORT_TYPE_NOT_AUTHORIZED");
      return workflowApi.reportSnapshot(
        selected.id,
        selectedAudience,
        cycleId === "all" ? undefined : cycleId,
        selected.id === "session_minutes" && sessionId !== "all" ? sessionId : undefined,
      );
    },
    enabled: Boolean(selected),
  });
  const comparisonCycleIds = useMemo(() => selected?.id === "cycle_history" && cycleId === "all"
    ? (workflowQuery.data?.cycleOptions ?? []).map((cycle) => cycle.id)
    : [], [cycleId, selected?.id, workflowQuery.data?.cycleOptions]);
  const historyComparisonQueries = useQueries({
    queries: comparisonCycleIds.map((comparisonCycleId) => ({
      queryKey: ["workflow-report-cycle-comparison", session.tenant.id, selectedAudience, comparisonCycleId],
      queryFn: () => workflowApi.reportSnapshot("cycle_history", selectedAudience, comparisonCycleId),
    })),
  });
  const committeeSessionIndexQuery = useQuery({
    queryKey: ["workflow-report-committee-session-index", session.tenant.id, selectedAudience, workflowQuery.data?.cycle?.id],
    queryFn: () => workflowApi.reportSnapshot("cycle_history", selectedAudience, workflowQuery.data!.cycle!.id),
    enabled: selected?.id === "committee_participation" && canReadAggregates && Boolean(workflowQuery.data?.cycle),
  });
  const committeeSessionIds = useMemo(() => committeeSessionIndexQuery.data?.sessions.filter((item) => item.status !== "cancelled").map((item) => item.id) ?? [], [committeeSessionIndexQuery.data?.sessions]);
  const committeeMinutesQueries = useQueries({
    queries: committeeSessionIds.map((committeeSessionId) => ({
      queryKey: ["workflow-report-committee-attendance", session.tenant.id, selectedAudience, workflowQuery.data?.cycle?.id, committeeSessionId],
      queryFn: () => workflowApi.reportSnapshot("session_minutes", selectedAudience, workflowQuery.data!.cycle!.id, committeeSessionId),
    })),
  });
  const historySnapshots = useMemo(() => selected?.id !== "cycle_history"
    ? []
    : cycleId === "all"
      ? historyComparisonQueries.flatMap((query) => query.data ? [query.data] : [])
      : workflowQuery.data ? [workflowQuery.data] : [], [cycleId, historyComparisonQueries, selected?.id, workflowQuery.data]);
  const attendanceSessions = useMemo<CommitteeAttendanceSession[]>(() => committeeMinutesQueries.flatMap((query) => {
    const minutes = query.data?.sessionMinutes;
    const index = minutes ? committeeSessionIndexQuery.data?.sessions.find((sessionItem) => sessionItem.id === minutes.id) : undefined;
    const accountable = index?.status !== "cancelled"
      && (index?.status === "in_progress" || index?.status === "closed" || Boolean(minutes?.attendance.length));
    return minutes && accountable ? [{ sessionId: minutes.id, attendance: minutes.attendance }] : [];
  }), [committeeMinutesQueries, committeeSessionIndexQuery.data?.sessions]);
  const historyComparisonsLoading = selected?.id === "cycle_history" && comparisonCycleIds.length > 0 && historyComparisonQueries.some((query) => query.isLoading);
  const committeeAttendanceLoading = selected?.id === "committee_participation" && canReadAggregates
    && (committeeSessionIndexQuery.isLoading || committeeMinutesQueries.some((query) => query.isLoading));
  const companionQueryError = historyComparisonQueries.some((query) => query.isError)
    || committeeSessionIndexQuery.isError
    || committeeMinutesQueries.some((query) => query.isError);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      const items = workflowQuery.data?.organization;
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "organization"));
      if (!items) { if (!cancelled) setOrganization([]); return; }
      if (!vault.key) { if (!cancelled) setOrganization(items.map((item) => ({ ...item, memberId: undefined, memberSnapshot: null }))); return; }
      try {
        let hadFailures = false;
        const value = await Promise.all(items.map(async (item) => {
          if (!item.memberSnapshot) return item;
          const memberId = item.memberId ?? item.memberSnapshot.memberId;
          try {
            if (!memberId) throw new Error("Encrypted historical organization record has no member binding");
            if (!item.memberSnapshot.displayEnvelope) throw new Error("Encrypted historical organization member display is unavailable");
            return {
              ...item,
              memberId,
              ...await openJsonEnvelope<{ displayName: string; shortId?: string }>({
                resolver: vault,
                tenantId: session.tenant.id,
                envelope: item.memberSnapshot.displayEnvelope,
                aad: { tenantId: session.tenant.id, memberId, purpose: "member-display", schemaVersion: 1 },
              }),
            };
          } catch {
            hadFailures = true;
            return { ...item, memberId: undefined, memberSnapshot: null };
          }
        }));
        if (!cancelled) {
          setOrganization(value);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "organization", message(locale, "screen.reportsView.0918ad7f6889")));
        }
      } catch { if (!cancelled) { setOrganization([]); setDecryptErrors((current) => scopedDecryptErrors(current, "organization", message(locale, "screen.reportsView.0918ad7f6889"))); } }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, workflowQuery.data?.organization]);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      const cycle = workflowQuery.data?.cycle;
      const items = workflowQuery.data?.committee;
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "committee"));
      if (!vault.key || !cycle || !items) { if (!cancelled) setCommittee([]); return; }
      try {
        let hadFailures = false;
        const value = await Promise.all(items.map(async (item) => {
          try {
            return { ...item, ...await openJsonEnvelope<{ displayName: string }>({ resolver: vault, tenantId: session.tenant.id, envelope: item.displayEnvelope, aad: { tenantId: session.tenant.id, cycleId: cycle.id, identityId: item.identityId, purpose: "committee-display", schemaVersion: 1 } }) };
          } catch {
            hadFailures = true;
            return item;
          }
        }));
        if (!cancelled) {
          setCommittee(value);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "committee", message(locale, "screen.reportsView.2c8e331ff4e0")));
        }
      } catch { if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "committee", message(locale, "screen.reportsView.2c8e331ff4e0"))); }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, workflowQuery.data?.committee, workflowQuery.data?.cycle]);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "members"));
      if (!vault.key || !membersQuery.data || !needsCurrentMembers) { if (!cancelled) setMembers([]); return; }
      try {
        let hadFailures = false;
        const value = await Promise.all(membersQuery.data.items.map(async (item) => {
          try {
            if (!item.displayEnvelope) throw new Error("Encrypted member display is unavailable");
            return { ...item, ...await openJsonEnvelope<{ displayName: string }>({ resolver: vault, tenantId: session.tenant.id, envelope: item.displayEnvelope, aad: { tenantId: session.tenant.id, memberId: item.id, purpose: "member-display", schemaVersion: 1 } }) };
          } catch {
            hadFailures = true;
            return item;
          }
        }));
        if (!cancelled) {
          setMembers(value);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "members", message(locale, "screen.reportsView.9346a5f9a42a")));
        }
      } catch { if (!cancelled) { setMembers([]); setDecryptErrors((current) => scopedDecryptErrors(current, "members", message(locale, "screen.reportsView.9346a5f9a42a"))); } }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, membersQuery.data, needsCurrentMembers, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "workflow"));
      if (!vault.key || !workflowQuery.data) { if (!cancelled) setWorkflowNames(new Map()); return; }
      const sources = [
        ...workflowQuery.data.candidacies.map((item) => ({ memberId: item.memberId, displayEnvelope: item.displayEnvelope })),
        ...workflowQuery.data.assignments.flatMap((item) => item.memberSnapshot ? [{ memberId: item.memberId, displayEnvelope: item.memberSnapshot.displayEnvelope }] : []),
        ...workflowQuery.data.eligibleMembers.map((item) => ({ memberId: item.memberId, displayEnvelope: item.displayEnvelope })),
        ...workflowQuery.data.organization.flatMap((item) => item.memberSnapshot && (item.memberId ?? item.memberSnapshot.memberId) ? [{ memberId: (item.memberId ?? item.memberSnapshot.memberId)!, displayEnvelope: item.memberSnapshot.displayEnvelope }] : []),
      ];
      try {
        const names = new Map<string, string>();
        let hadFailures = false;
        for (const source of sources) {
          if (names.has(source.memberId)) continue;
          try {
            if (!source.displayEnvelope) throw new Error("Encrypted workflow member display is unavailable");
            const profile = await openJsonEnvelope<{ displayName?: string; firstName?: string; lastName?: string }>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: source.displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: source.memberId, purpose: "member-display", schemaVersion: 1 },
            });
            const name = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!name) throw new Error("Encrypted workflow snapshot has no visible name");
            names.set(source.memberId, name);
          } catch {
            hadFailures = true;
          }
        }
        if (!cancelled) {
          setWorkflowNames(names);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "workflow", message(locale, "screen.reportsView.6869d5da7547")));
        }
      } catch {
        if (!cancelled) { setWorkflowNames(new Map()); setDecryptErrors((current) => scopedDecryptErrors(current, "workflow", message(locale, "screen.reportsView.6869d5da7547"))); }
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, workflowQuery.data]);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      const minutes = workflowQuery.data?.sessionMinutes;
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "attendance"));
      if (!vault.key || !minutes) {
        if (!cancelled) setAttendanceNames(new Map());
        return;
      }
      try {
        const names = new Map<string, string>();
        let hadFailures = false;
        for (const attendee of minutes.attendance) {
          try {
            if (!attendee.displayEnvelope) throw new Error("Encrypted attendance display is unavailable");
            const aad = attendee.memberId
              ? { tenantId: session.tenant.id, memberId: attendee.memberId, purpose: "member-display", schemaVersion: 1 }
              : { tenantId: session.tenant.id, cycleId: minutes.cycleId, identityId: attendee.identityId, purpose: "committee-display", schemaVersion: 1 };
            const profile = await openJsonEnvelope<{ displayName?: string; firstName?: string; lastName?: string }>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: attendee.displayEnvelope,
              aad,
            });
            const name = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!name) throw new Error("Encrypted attendance snapshot has no visible name");
            names.set(attendee.identityId, name);
          } catch {
            hadFailures = true;
          }
        }
        if (!cancelled) {
          setAttendanceNames(names);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "attendance", message(locale, "screen.reportsView.c5f9db0a521f")));
        }
      } catch {
        if (!cancelled) { setAttendanceNames(new Map()); setDecryptErrors((current) => scopedDecryptErrors(current, "attendance", message(locale, "screen.reportsView.c5f9db0a521f"))); }
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, workflowQuery.data?.sessionMinutes]);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      const snapshot = workflowQuery.data;
      if (!cancelled) setDecryptErrors((current) => scopedDecryptErrors(current, "minutesTitles"));
      if (!snapshot || selectedAudience === "church") {
        if (!cancelled) {
          setSessionTitles(new Map());
          setAgendaTitles(new Map());
        }
        return;
      }
      const cycle = snapshot.cycle;
      const minutes = snapshot.sessionMinutes;
      const sessionReferences = [
        ...snapshot.sessions,
        ...(minutes && !snapshot.sessions.some(({ id }) => id === minutes.id) ? [minutes] : []),
      ];
      const requiresKey = sessionReferences.some(({ titleEnvelope }) => Boolean(titleEnvelope))
        || Boolean(minutes?.agendaItems.some(({ titleEnvelope }) => Boolean(titleEnvelope)));
      if (requiresKey && (!vault.key || !vault.keyId || vault.tenantId !== session.tenant.id)) {
        if (!cancelled) {
          setSessionTitles(new Map());
          setAgendaTitles(new Map());
          setDecryptErrors((current) => scopedDecryptErrors(current, "minutesTitles", message(locale, "screen.reportsView.97583501000e")));
        }
        return;
      }
      try {
        const visibleSessions = new Map<string, string>();
        const visibleAgenda = new Map<string, string>();
        let hadFailures = false;
        for (const item of sessionReferences) {
          const reference = {
            titleEnvelope: item.titleEnvelope ?? null,
            titleVersion: item.titleVersion ?? -1,
            legacyTitleUnavailable: item.legacyTitleUnavailable === true,
          };
          if (isLegacyTitleUnavailable(reference)) continue;
          try {
            if (!cycle || !reference.titleEnvelope) {
              throw new Error("Encrypted session title reference is incomplete");
            }
            visibleSessions.set(item.id, await openSessionTitle(
              keyForEnvelope(vault, session.tenant.id, reference.titleEnvelope),
              reference.titleEnvelope.keyId,
              {
                tenantId: session.tenant.id,
                cycleId: cycle.id,
                sessionId: item.id,
                titleVersion: reference.titleVersion,
              },
              reference.titleEnvelope,
            ));
          } catch {
            hadFailures = true;
          }
        }
        if (minutes) {
          for (const item of minutes.agendaItems) {
            const reference = {
              titleEnvelope: item.titleEnvelope ?? null,
              titleVersion: item.titleVersion ?? -1,
              legacyTitleUnavailable: item.legacyTitleUnavailable === true,
            };
            if (isLegacyTitleUnavailable(reference)) continue;
            try {
              if (!reference.titleEnvelope) {
                throw new Error("Encrypted agenda title reference is incomplete");
              }
              visibleAgenda.set(item.id, await openAgendaTitle(
                keyForEnvelope(vault, session.tenant.id, reference.titleEnvelope),
                reference.titleEnvelope.keyId,
                {
                  tenantId: session.tenant.id,
                  sessionId: minutes.id,
                  agendaItemId: item.id,
                  titleVersion: reference.titleVersion,
                },
                reference.titleEnvelope,
              ));
            } catch {
              hadFailures = true;
            }
          }
        }
        if (!cancelled) {
          setSessionTitles(visibleSessions);
          setAgendaTitles(visibleAgenda);
          if (hadFailures) setDecryptErrors((current) => scopedDecryptErrors(current, "minutesTitles", message(locale, "screen.reportsView.5bf6a142746b")));
        }
      } catch {
        if (!cancelled) {
          setSessionTitles(new Map());
          setAgendaTitles(new Map());
          setDecryptErrors((current) => scopedDecryptErrors(current, "minutesTitles", message(locale, "screen.reportsView.5bf6a142746b")));
        }
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, selectedAudience, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyId, vault.keyringRevision, vault.tenantId, workflowQuery.data]);

  const cycleOptions = useMemo(() => workflowQuery.data?.cycleOptions ?? [], [workflowQuery.data?.cycleOptions]);
  const terms = useMemo(() => [...new Set(cycleOptions.map((item) => `${item.termStart}—${item.termEnd}`))].sort(), [cycleOptions]);
  const sessions = workflowQuery.data?.sessions ?? [];
  const departments = useMemo(() => [...(workflowQuery.data?.departments ?? [])].sort((left, right) => localizedName(left.names, locale, left.canonicalCode).localeCompare(localizedName(right.names, locale, right.canonicalCode), locale)), [locale, workflowQuery.data?.departments]);
  const offices = useMemo(() => [...(workflowQuery.data?.offices ?? [])].filter((office) => department === "all" || office.departmentId === department).sort((left, right) => localizedName(left.names, locale, left.canonicalCode).localeCompare(localizedName(right.names, locale, right.canonicalCode), locale)), [department, locale, workflowQuery.data?.offices]);
  const people = useMemo(() => {
    const names = new Map(workflowNames);
    for (const item of organization) if (item.memberId && item.displayName) names.set(item.memberId, item.displayName);
    for (const item of committee) if (item.displayName) names.set(item.memberId ?? item.identityId, item.displayName);
    return [...names.entries()].sort((left, right) => left[1].localeCompare(right[1], locale));
  }, [committee, locale, organization, workflowNames]);
  const phases = useMemo(() => [...new Set([...(workflowQuery.data?.processes ?? []).map((item) => item.phase), ...(workflowQuery.data?.rounds ?? []).map((item) => item.phase)])].sort(), [workflowQuery.data?.processes, workflowQuery.data?.rounds]);
  const states = useMemo(() => [...new Set([...(state === "proposal" ? ["proposal"] : []), ...organization.map((item) => item.status)])].sort(), [organization, state]);
  const reportTimeZone = workflowQuery.data?.cycle?.timezone ?? session.tenant.timezone;
  const decryptError = useMemo(() => {
    const errors = [...new Set(Object.values(decryptErrors).filter((value): value is string => Boolean(value)))];
    return errors.length ? errors.join(" ") : undefined;
  }, [decryptErrors]);
  const rows = useMemo(() => reportsQuery.data && workflowQuery.data && selected ? buildRows({ reportType: selected.id, locale: documentLocale, audience: selectedAudience, timeZone: reportTimeZone, workflow: workflowQuery.data, workflowNames, attendanceNames, sessionTitles, agendaTitles, organization, committee, attendanceSessions, attendanceAvailable: canReadAggregates, historySnapshots, members, audit: auditQuery.data, imports: importsQuery.data?.items ?? [], storedReports: reportsQuery.data.items, cycleId, term, sessionId, department, officeId, personId, phase, state }) : [], [agendaTitles, attendanceNames, attendanceSessions, auditQuery.data, canReadAggregates, committee, cycleId, department, documentLocale, historySnapshots, importsQuery.data?.items, members, officeId, organization, personId, phase, reportTimeZone, reportsQuery.data, selected, selectedAudience, sessionId, sessionTitles, state, term, workflowNames, workflowQuery.data]);
  const reportsById = useMemo(() => new Map((reportsQuery.data?.items ?? []).map((report) => [report.id, report])), [reportsQuery.data?.items]);
  const reportSelectionComplete = selected?.id !== "session_minutes"
    || (sessionId !== "all" && workflowQuery.data?.sessionMinutes?.id === sessionId);
  const issueReport = async (
    format: "pdf" | "xlsx" | "csv",
    correction?: { previous: StoredReport; reasonCode: ReportCorrectionReasonCode },
  ): Promise<GeneratedReport> => {
      if (!selected || !workflowQuery.data) throw new Error("REPORT_TYPE_NOT_AUTHORIZED");
      if (!reportSelectionComplete) throw new Error("REPORT_SESSION_REQUIRED");
      if (!vault.key || !vault.keyId || vault.tenantId !== session.tenant.id) throw new Error("TENANT_KEY_LOCKED");
      if (correction && (
        correction.previous.reportType !== selected.id
        || correction.previous.format !== format
        || correction.previous.locale !== documentLocale
        || correction.previous.audience !== selectedAudience
      )) throw new Error("REPORT_LINEAGE_INVALID");
      const snapshotSha256 = await digestSnapshot({ reportType: selected.id, audience: selectedAudience, rows });
      const filters: ReportFilters = {
        ...(hasFilter("cycle") ? { cycleId: selected.id === "cycle_history" && cycleId === "all" ? null : cycleId === "all" ? workflowQuery.data.cycle?.id ?? null : cycleId } : {}),
        ...(hasFilter("term") ? { term: term === "all" ? null : term } : {}),
        ...(hasFilter("session") ? { sessionId: sessionId === "all" ? null : sessionId } : {}),
        ...(hasFilter("department") ? { department: department === "all" ? null : department } : {}),
        ...(hasFilter("office") ? { office: officeId === "all" ? null : officeId } : {}),
        ...(hasFilter("person") ? { personId: personId === "all" ? null : personId } : {}),
        ...(hasFilter("phase") ? { phase: phase === "all" ? null : phase } : {}),
        ...(hasFilter("state") ? { assignmentState: state === "all" ? null : state } : {}),
        snapshotSha256,
        snapshotAt: workflowQuery.data.generatedAt,
      };
      let pending: PendingReport | undefined;
      let registered = false;
      let plaintext: Uint8Array<ArrayBuffer> | undefined;
      try {
        pending = correction
          ? await api.correctReport(correction.previous.id, correction.previous.version, filters, correction.reasonCode, idempotencyKey())
          : await api.generateReport(selected.id, format, documentLocale, selectedAudience, filters, idempotencyKey());
        validatePendingReport(pending, { reportType: selected.id, format, locale: documentLocale, audience: selectedAudience, snapshotSha256 });
        validatePendingLineage(pending, correction?.previous, correction?.reasonCode);
        plaintext = await buildLocalArtifact(pending, rows, session.tenant.name, reportTitle(selected.id, documentLocale), audienceLabels[documentLocale][selectedAudience], reportTimeZone);
        const encrypted = await encryptReportArtifact({
          key: vault.key,
          keyId: vault.keyId,
          descriptor: {
            tenantId: session.tenant.id,
            reportId: pending.id,
            requestVersion: pending.version,
            reportType: pending.reportType,
            audience: pending.audience,
            locale: pending.locale,
            format: pending.format,
            filename: pending.filename,
            mediaType: pending.mediaType,
            snapshotSha256,
            ...(pending.supersedesReportId ? {
              supersedesReportId: pending.supersedesReportId,
              correctionReasonCode: pending.correctionReasonCode!,
              lineageRootId: pending.lineageRootId,
              lineageRevision: pending.lineageRevision,
            } : {}),
          },
          plaintext,
        });
        const completed = await api.completeReport(pending.id, {
          expectedVersion: pending.version,
          envelope: encrypted.envelope,
          artifactSha256: encrypted.artifactSha256,
          ciphertextSha256: encrypted.ciphertextSha256,
          plaintextBytes: encrypted.plaintextBytes,
          rowCount: rows.length,
          generatedAt: new Date().toISOString(),
        }, idempotencyKey());
        registered = true;
        if (
          completed.id !== pending.id
          || completed.reportType !== pending.reportType
          || completed.audience !== pending.audience
          || completed.locale !== pending.locale
          || completed.format !== pending.format
          || completed.filename !== pending.filename
          || completed.mediaType !== pending.mediaType
          || completed.version !== pending.version + 1
          || completed.filters.snapshotSha256 !== snapshotSha256
          || completed.supersedesReportId !== pending.supersedesReportId
          || completed.correctionReasonCode !== pending.correctionReasonCode
          || completed.lineageRootId !== pending.lineageRootId
          || completed.lineageRevision !== pending.lineageRevision
        ) throw new Error("REPORT_ARTIFACT_CONTEXT_MISMATCH");
        validateStoredArtifact(session.tenant.id, completed, {
          envelope: encrypted.envelope,
          filename: completed.filename,
          mediaType: completed.mediaType,
          artifactSha256: encrypted.artifactSha256,
          ciphertextSha256: encrypted.ciphertextSha256,
          ciphertextBytes: encrypted.ciphertextBytes,
          plaintextBytes: encrypted.plaintextBytes,
          requestVersion: pending.version,
          manifest: completed.manifest,
          reportType: completed.reportType,
          audience: completed.audience,
          locale: completed.locale,
          format: completed.format,
          version: completed.version,
          supersedesReportId: completed.supersedesReportId,
          correctionReasonCode: completed.correctionReasonCode,
          lineageRootId: completed.lineageRootId,
          lineageRevision: completed.lineageRevision,
        });
        downloadBytes(plaintext, completed.mediaType, completed.filename);
        return completed;
      } catch (error) {
        if (pending && !registered) {
          await api.failReport(pending.id, pending.version, reportFailureCode(error), idempotencyKey()).catch(() => undefined);
        }
        throw error;
      } finally {
        plaintext?.fill(0);
      }
  };
  const mutation = useMutation({
    mutationFn: (format: "pdf" | "xlsx" | "csv") => issueReport(format),
    onSuccess: (report) => { setLastGenerated(report); void queryClient.invalidateQueries({ queryKey: ["reports", session.tenant.id] }); },
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ["reports", session.tenant.id] }); },
  });
  const correctionMutation = useMutation({
    mutationFn: (reasonCode: ReportCorrectionReasonCode) => {
      if (!correctionTarget || correctionTarget.format === "html") throw new Error("REPORT_CORRECTION_NOT_ELIGIBLE");
      return issueReport(correctionTarget.format, { previous: correctionTarget, reasonCode });
    },
    onSuccess: (report) => {
      setLastGenerated(report);
      setCorrectionTarget(undefined);
      setHistoryNotice(message(locale, "screen.reportsView.ac7469f614e8", { value0: report.lineageRevision }));
    },
    onError: () => setCorrectionTarget(undefined),
    onSettled: () => { void queryClient.invalidateQueries({ queryKey: ["reports", session.tenant.id] }); },
  });
  const historyMutation = useMutation({
    mutationFn: async ({ report, action }: { report: StoredReport; action: "download" | "print" }) => {
      if (!vault.key || !vault.keyId || vault.tenantId !== session.tenant.id) throw new Error("TENANT_KEY_LOCKED");
      if (report.state !== "ready" || report.format === "html" || (action === "print" && report.format !== "pdf")) throw new Error("REPORT_ARTIFACT_CONTEXT_MISMATCH");
      const artifact = await api.reportArtifact(report.id);
      const verified = validateStoredArtifact(session.tenant.id, report, artifact);
      const plaintext = await decryptReportArtifact({
        key: keyForEnvelope(vault, session.tenant.id, verified.encrypted.envelope),
        keyId: verified.encrypted.envelope.keyId,
        descriptor: verified.descriptor,
        artifact: verified.encrypted,
      });
      try {
        if (action === "print") {
          await api.recordReportPrint(report.id, artifact.artifactSha256, idempotencyKey());
          printPdfBytes(plaintext);
        } else {
          downloadBytes(plaintext, artifact.mediaType, artifact.filename);
        }
      } finally {
        plaintext.fill(0);
      }
      return { report, action };
    },
    onMutate: () => setHistoryNotice(undefined),
    onSuccess: ({ report, action }) => setHistoryNotice(action === "print"
      ? message(locale, "screen.reportsView.b5fe7c0d39b3", { value0: report.filename })
      : message(locale, "screen.reportsView.fdcfeb1a586f", { value0: report.filename })),
  });
  const loading = reportsQuery.isLoading || workflowQuery.isLoading || historyComparisonsLoading || committeeAttendanceLoading || (needsCurrentMembers && membersQuery.isLoading) || (needsAudit && auditQuery.isLoading) || (needsImports && importsQuery.isLoading);
  if (loading) return <LoadingBlock locale={locale} label={message(locale, "screen.reportsView.10f5366b11d7")} />;
  if (!selected) return <>
    <PageTitle eyebrow={message(locale, "screen.reportsView.a6cae6405a7b")} title={text.title} description={text.description} />
    <Alert variant="destructive"><ShieldCheck /><AlertTitle>{message(locale, "screen.reportsView.244d06bae81b")}</AlertTitle><AlertDescription>{message(locale, "screen.reportsView.15278a506da8")}</AlertDescription></Alert>
  </>;
  if (
    companionQueryError
    || !reportsQuery.data
    || !workflowQuery.data
    || (needsCurrentMembers && !membersQuery.data)
    || (needsAudit && !auditQuery.data)
    || (needsImports && !importsQuery.data)
  ) return <DataError locale={locale} title={message(locale, "screen.reportsView.4eba7afa6430")} />;

  return <>
    <PageTitle eyebrow={message(locale, "screen.reportsView.a6cae6405a7b")} title={text.title} description={text.description} />
    <Alert><ShieldCheck /><AlertTitle>{message(locale, "screen.reportsView.8186f8500300")}</AlertTitle><AlertDescription>{message(locale, "screen.reportsView.7093bcba08a3")}</AlertDescription></Alert>
    {decryptError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{message(locale, "screen.reportsView.6544fdadbe29")}</AlertTitle><AlertDescription>{decryptError}</AlertDescription></Alert>}
    <div className="reports-layout">
      <section className="report-builder surface-card">
        <div className="card-heading"><div><p className="eyebrow">{correctionTarget ? message(locale, "screen.reportsView.d3a3400055e0") : message(locale, "screen.reportsView.05fc12af92d3")}</p><h2>{correctionTarget ? message(locale, "screen.reportsView.dc9fc56993e1", { value0: correctionTarget.lineageRevision }) : text.generate}</h2></div><span className="report-seal">{correctionTarget ? <FilePenLine /> : <FileBarChart />}</span></div>
        {correctionTarget && <Alert className="report-correction-alert"><FilePenLine /><AlertTitle>{message(locale, "screen.reportsView.3cbd01129183")}</AlertTitle><AlertDescription><p>{correctionTarget.filename} · v{correctionTarget.lineageRevision}</p><div className="field-stack"><Label htmlFor="report-correction-reason">{message(locale, "screen.reportsView.6f7001c6967c")}</Label><select id="report-correction-reason" value={correctionReason} onChange={(event) => setCorrectionReason(event.target.value as ReportCorrectionReasonCode)} disabled={correctionMutation.isPending}>{REPORT_CORRECTION_REASON_CODES.map((reason) => <option key={reason} value={reason}>{correctionReasonLabels[reason][locale]}</option>)}</select></div><Button type="button" variant="outline" onClick={() => setCorrectionTarget(undefined)} disabled={correctionMutation.isPending}><X />{message(locale, "screen.reportsView.a3e57bf05fe9")}</Button></AlertDescription></Alert>}
        <div className="report-form-grid">
          <div className="field-stack"><Label htmlFor="report-type">{text.reportType}</Label><select id="report-type" value={selected.id} onChange={(event) => selectReport(availableReports.find(({ id }) => id === event.target.value) ?? selected)} disabled={Boolean(correctionTarget)}>{availableReports.map((report) => <option value={report.id} key={report.id}>{report.titles[locale]}</option>)}</select></div>
          <div className="field-stack"><Label htmlFor="report-locale">{text.language}</Label><select id="report-locale" value={documentLocale} onChange={(event) => setDocumentLocale(event.target.value as Locale)} disabled={Boolean(correctionTarget)}>{supportedLocales.map((item) => <option key={item} value={item}>{localeMetadata[item].label}</option>)}</select></div>
          <div className="field-stack"><Label htmlFor="report-audience">{text.audience}</Label><select id="report-audience" value={selectedAudience} onChange={(event) => setAudience(event.target.value as Audience)} disabled={Boolean(correctionTarget)}>{selected.audiences.map((value) => <option value={value} key={value}>{audienceLabels[locale][value]}</option>)}</select></div>
          {hasFilter("cycle") && <div className="field-stack"><Label htmlFor="report-cycle">{text.cycle}</Label><select id="report-cycle" value={cycleId} onChange={(event) => { setCycleId(event.target.value); setSessionId("all"); setDepartment("all"); setOfficeId("all"); setPersonId("all"); setPhase("all"); setState("all"); }} disabled={Boolean(correctionTarget)}><option value="all">{selected.id === "cycle_history" ? text.all : text.currentCycle}</option>{cycleOptions.map((value) => <option value={value.id} key={value.id}>{value.name}</option>)}</select></div>}
          {hasFilter("term") && <div className="field-stack"><Label htmlFor="report-term">{text.term}</Label><select id="report-term" value={term} onChange={(event) => setTerm(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{terms.map((value) => <option value={value} key={value}>{value.replace("—", " — ")}</option>)}</select></div>}
          {hasFilter("session") && <div className="field-stack"><Label htmlFor="report-session">{text.session}</Label><select id="report-session" value={sessionId} onChange={(event) => setSessionId(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.selectSession}</option>{sessions.map((value) => <option value={value.id} key={value.id}>{value.sequence}. {selectedAudience === "church" ? message(locale, "screen.reportsView.bba4234f0ca5") : sessionTitles.get(value.id) ?? message(locale, "screen.reportsView.30394ed2ba2b")}</option>)}</select></div>}
          {hasFilter("department") && <div className="field-stack"><Label htmlFor="report-department">{text.department}</Label><select id="report-department" value={department} onChange={(event) => { setDepartment(event.target.value); setOfficeId("all"); }} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{departments.map((value) => <option value={value.id} key={value.id}>{localizedName(value.names, locale, value.canonicalCode)}</option>)}</select></div>}
          {hasFilter("office") && <div className="field-stack"><Label htmlFor="report-office">{text.office}</Label><select id="report-office" value={officeId} onChange={(event) => setOfficeId(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{offices.map((value) => <option value={value.id} key={value.id}>{localizedName(value.names, locale, value.canonicalCode)}</option>)}</select></div>}
          {hasFilter("person") && <div className="field-stack"><Label htmlFor="report-person">{text.person}</Label><select id="report-person" value={personId} onChange={(event) => setPersonId(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{people.map(([id, name]) => <option value={id} key={id}>{name}</option>)}</select></div>}
          {hasFilter("phase") && <div className="field-stack"><Label htmlFor="report-phase">{text.phase}</Label><select id="report-phase" value={phase} onChange={(event) => setPhase(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{phases.map((value) => <option value={value} key={value}>{phaseLabel(locale, value)}</option>)}</select></div>}
          {hasFilter("state") && <div className="field-stack"><Label htmlFor="report-state">{text.state}</Label><select id="report-state" value={state} onChange={(event) => setState(event.target.value)} disabled={Boolean(correctionTarget)}><option value="all">{text.all}</option>{states.map((value) => <option value={value} key={value}>{value === "proposal" ? message(locale, "screen.reportsView.07a0dacbeb7f") : statusLabels[locale][value] ?? assignmentLabel(locale,value)}</option>)}</select></div>}
        </div>
        <div className="report-preview"><div className="report-paper"><header><span className="brand-mark">N</span><div><small>{session.tenant.name}</small><strong>{reportTitle(selected.id, documentLocale)}</strong></div></header><p className="watermark">{copy[documentLocale].preview}</p><dl>{rows.slice(0, 7).map(([label, value], index) => <div key={`${label}-${index}`}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><footer>{audienceLabels[documentLocale][selectedAudience]} · {rows.length} {message(documentLocale, "screen.reportsView.7a4c2c0357fd")}</footer></div></div>
        <p className="eyebrow">{text.formats}</p>
        {mayExport ? correctionTarget && correctionTarget.format !== "html"
          ? <div className="format-actions"><Button onClick={() => correctionMutation.mutate(correctionReason)} disabled={correctionMutation.isPending || Boolean(decryptError) || !reportSelectionComplete}>{correctionMutation.isPending ? <LoaderCircle className="animate-spin" /> : <FilePenLine />}{message(locale, "screen.reportsView.812c2007ad0a", { value0: correctionTarget.format.toUpperCase() })}</Button></div>
          : <div className="format-actions">{(["pdf", "xlsx", "csv"] as const).map((format) => { const Icon = formatIcon(format); return <Button key={format} variant={format === "pdf" ? "default" : "outline"} onClick={() => mutation.mutate(format)} disabled={mutation.isPending || Boolean(decryptError) || !reportSelectionComplete}>{mutation.isPending && mutation.variables === format ? <LoaderCircle className="animate-spin" /> : <Icon />} {format.toLocaleUpperCase()}</Button>; })}</div>
          : <Alert><ShieldCheck /><AlertTitle>{message(locale, "screen.reportsView.4cdf62d99a57")}</AlertTitle><AlertDescription>{message(locale, "screen.reportsView.c0ce9cacd38e")}</AlertDescription></Alert>}
        {(mutation.error || correctionMutation.error) && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{correctionMutation.error ? message(locale, "screen.reportsView.67b872731ab6") : message(locale, "screen.reportsView.996c4b45775e")}</AlertTitle><AlertDescription>{reportArtifactError(correctionMutation.error ?? mutation.error, locale)}</AlertDescription></Alert>}
        {lastGenerated && <Alert className="success-alert"><CheckCircle2 /><AlertTitle>{text.generated}</AlertTitle><AlertDescription>{lastGenerated.filename} · {formatTenantDate(lastGenerated.createdAt, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" })}</AlertDescription></Alert>}
      </section>
      <aside className="surface-card report-history">
        <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.reportsView.7d83811a08e8")}</p><h2>{text.history}</h2></div><Badge variant="outline">{reportsQuery.data.items.length}</Badge></div>
        {reportsQuery.data.items.length ? <div className="report-list">{reportsQuery.data.items.map((report) => {
          const Icon = formatIcon(report.format);
          const actionable = mayExport && report.state === "ready" && report.format !== "html";
          const correctionEligible = mayExport
            && report.correctedByReportId === null
            && report.format !== "html"
            && (report.state === "ready" || (report.state === "failed" && report.supersedesReportId !== null))
            && availableReports.some((definition) => definition.id === report.reportType);
          const previous = report.supersedesReportId ? reportsById.get(report.supersedesReportId) : undefined;
          const next = report.correctedByReportId ? reportsById.get(report.correctedByReportId) : undefined;
          const busy = historyMutation.isPending && historyMutation.variables.report.id === report.id;
          return <article key={report.id} id={`report-${report.id}`}>
            <span><Icon /></span>
            <div>
              <strong>{reportTitle(report.reportType, locale)}</strong>
              <small>{report.filename}</small>
              <small>{formatTenantDate(report.createdAt, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" })}{report.createdBy ? ` · ${report.createdBy}` : ""}</small>
              {report.correctionReasonCode && <small>{correctionReasonLabels[report.correctionReasonCode][locale]}</small>}
              {report.supersedesReportId && <small>{previous
                ? <a href={`#report-${previous.id}`}>{message(locale, "screen.reportsView.68e53c53c95f", { value0: previous.lineageRevision })}</a>
                : message(locale, "screen.reportsView.68e53c53c95f", { value0: report.lineageRevision - 1 })}</small>}
              {report.correctedByReportId && <small>{next
                ? <a href={`#report-${next.id}`}>{message(locale, "screen.reportsView.6d028dce47c8", { value0: next.lineageRevision })}</a>
                : message(locale, "screen.reportsView.6d028dce47c8", { value0: report.lineageRevision + 1 })}</small>}
              {report.errorCode && <small>{reportCodeLabel(locale, report.errorCode)}</small>}
            </div>
            <div className="report-history-actions">
              <div><Badge variant="outline">v{report.lineageRevision}</Badge><Badge variant="outline">{reportStateLabel(locale, report.state)}</Badge><Badge variant="outline">{report.format.toUpperCase()}</Badge></div>
              {actionable && <div>
                <Button variant="outline" onClick={() => historyMutation.mutate({ report, action: "download" })} disabled={historyMutation.isPending} aria-label={`${text.download}: ${report.filename}`}>{busy && historyMutation.variables.action === "download" ? <LoaderCircle className="animate-spin" /> : <Download />}<span>{text.download}</span></Button>
                {report.format === "pdf" && <Button variant="outline" onClick={() => historyMutation.mutate({ report, action: "print" })} disabled={historyMutation.isPending} aria-label={`${text.print}: ${report.filename}`}>{busy && historyMutation.variables.action === "print" ? <LoaderCircle className="animate-spin" /> : <Printer />}<span>{text.print}</span></Button>}
              </div>}
              {correctionEligible && <Button variant="outline" onClick={() => prepareCorrection(report)} disabled={correctionMutation.isPending || mutation.isPending} aria-label={`${message(locale, "screen.reportsView.0247e59b7a87")}: ${report.filename}`}><FilePenLine /><span>{message(locale, "screen.reportsView.0247e59b7a87")}</span></Button>}
            </div>
          </article>;
        })}</div> : <EmptyState locale={locale} icon={FileBarChart} title={text.noReports} />}
        {historyMutation.error && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{message(locale, "screen.reportsView.d2a6e3adc100")}</AlertTitle><AlertDescription>{reportArtifactError(historyMutation.error, locale)}</AlertDescription></Alert>}
        {historyNotice && <Alert className="success-alert"><CheckCircle2 /><AlertTitle>{message(locale, "screen.reportsView.5c0673bf966c")}</AlertTitle><AlertDescription>{historyNotice}</AlertDescription></Alert>}
      </aside>
    </div>
    <section className="language-assurance surface-card"><Languages /><div><strong>ES · EN · FR</strong><p>{message(locale, "screen.reportsView.166ad49283df")}</p></div><Badge variant="outline">{documentLocale.toUpperCase()}</Badge></section>
  </>;
}
