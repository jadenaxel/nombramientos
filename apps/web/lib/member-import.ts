import { getMessage } from "@nombramientos/i18n";
import { hasDangerousSpreadsheetPrefix, neutralizeSpreadsheetCell } from "./spreadsheet-cell.ts";

export const IMPORT_FIELDS = [
  "sourceId",
  "displayName",
  "firstName",
  "lastName",
  "email",
  "membershipStatus",
  "eligible",
  "visibleReason",
  "photoReference",
] as const;

export type ImportField = (typeof IMPORT_FIELDS)[number];
export type ImportLocale = "es" | "en" | "fr";
export type ImportColumnMapping = Partial<Record<ImportField, number>>;
export type ImportAction = "undecided" | "create" | "update" | "skip";
export type ImportMatchBasis = "none" | "stable_id" | "email" | "normalized_name" | "user_selected";

export type ImportIssueCode =
  | "MISSING_NAME"
  | "INVALID_EMAIL"
  | "INVALID_ELIGIBILITY"
  | "INVALID_MEMBERSHIP_STATUS"
  | "UNSAFE_FORMULA_PREFIX"
  | "UNSAFE_PHOTO_REFERENCE"
  | "DUPLICATE_SOURCE_ID"
  | "POSSIBLE_EMAIL_DUPLICATE"
  | "POSSIBLE_NAME_DUPLICATE"
  | "STABLE_ID_MATCH"
  | "HOMONYM_RETAINED";

export interface ImportIssue {
  readonly code: ImportIssueCode;
  readonly severity: "error" | "warning";
}

export interface ImportExistingMember {
  readonly id: string;
  readonly shortId: string;
  readonly version: number;
  readonly displayName: string;
  readonly email?: string;
}

export interface ImportCandidate {
  readonly id: string;
  readonly shortId: string;
  readonly version: number;
  readonly displayName: string;
  readonly basis: Exclude<ImportMatchBasis, "none" | "user_selected">;
}

export interface ImportPreviewRow {
  readonly sourceRow: number;
  readonly generatedId: string;
  readonly sourceId?: string;
  readonly displayName: string;
  readonly firstName?: string;
  readonly lastName?: string;
  readonly email?: string;
  readonly membershipStatus: "active" | "inactive";
  readonly eligible: boolean;
  readonly visibleReason?: string;
  readonly photoReference?: string;
  readonly issues: readonly ImportIssue[];
  readonly candidates: readonly ImportCandidate[];
  readonly suggestedAction: Exclude<ImportAction, "undecided">;
  readonly suggestedMatchBasis: ImportMatchBasis;
  readonly action: ImportAction;
  readonly targetId?: string;
}

export interface BuildImportPreviewInput {
  readonly rows: readonly (readonly string[])[];
  readonly mapping: ImportColumnMapping;
  readonly existingMembers: readonly ImportExistingMember[];
  readonly tenantId: string;
  readonly sourceFingerprint: string;
  readonly sheetName: string;
  readonly locale?: ImportLocale;
}

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const remoteReferencePattern = /^(?:[a-z][a-z0-9+.-]*:|\/\/|www\.)/i;

const headerAliases: Readonly<Record<ImportField, readonly string[]>> = {
  sourceId: ["id", "codigo", "identificador", "source id", "member id", "identifiant"],
  displayName: ["nombre", "nombre completo", "name", "full name", "nom", "nom complet"],
  firstName: ["nombres", "primer nombre", "first name", "given name", "prenom"],
  lastName: ["apellidos", "apellido", "last name", "surname", "nom de famille"],
  email: ["correo", "correo electronico", "email", "e-mail", "courriel"],
  membershipStatus: ["estado de membresia", "membresia", "membership status", "membership", "statut de membre"],
  eligible: ["elegible", "eligible", "eligibility"],
  visibleReason: ["motivo visible", "motivo", "visible reason", "reason", "motif"],
  photoReference: ["referencia de foto", "foto", "photo reference", "photo", "reference photo"],
};

export function normalizeSearchText(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .replace(/\s+/g, " ")
    .trim()
    .toLocaleLowerCase("es");
}

export function normalizeEmail(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}

export function parseUtf8Csv(bytes: ArrayBuffer, locale: ImportLocale = "es"): string[][] {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replace(/^\uFEFF/, "");
  if (text.includes("\u0000")) throw new Error(getMessage(locale, "screen.memberImport.3adfae5bb578"));
  const delimiter = detectDelimiter(text);
  return parseDelimited(text, delimiter, locale);
}

export function suggestColumnMapping(headers: readonly string[]): ImportColumnMapping {
  const normalized = headers.map(normalizeSearchText);
  const mapping: ImportColumnMapping = {};
  for (const field of IMPORT_FIELDS) {
    const index = normalized.findIndex((header) => headerAliases[field]?.includes(header));
    if (index >= 0 && !Object.values(mapping).includes(index)) mapping[field] = index;
  }
  return mapping;
}

export function mappingHasName(mapping: ImportColumnMapping): boolean {
  return mapping.displayName !== undefined
    || (mapping.firstName !== undefined && mapping.lastName !== undefined);
}

export async function buildImportPreview(input: BuildImportPreviewInput): Promise<readonly ImportPreviewRow[]> {
  const locale = input.locale ?? "es";
  if (!mappingHasName(input.mapping)) throw new Error(getMessage(locale, "screen.memberImport.4b50d6185d96"));
  const sourceRows = input.rows.slice(1)
    .map((values, index) => ({ sourceRow: index + 2, values }))
    .filter(({ values }) => values.some((value) => cleanDisplayValue(value).length > 0));
  if (sourceRows.length > 10_000) throw new Error(getMessage(locale, "screen.memberImport.0b78396dcaf3"));

  const sourceIdCounts = countNormalized(sourceRows.map(({ values }) => field(values, input.mapping.sourceId)).filter(Boolean));
  const importedEmailCounts = countNormalized(sourceRows.map(({ values }) => normalizeEmail(field(values, input.mapping.email))).filter(Boolean));
  const importedNameCounts = countNormalized(sourceRows.map(({ values }) => mappedName(values, input.mapping)).filter(Boolean));
  const existingByStableId = groupMembers(input.existingMembers, (member) => normalizeSearchText(member.shortId));
  const existingByEmail = groupMembers(input.existingMembers.filter(({ email }) => Boolean(email)), (member) => normalizeEmail(member.email ?? ""));
  const existingByName = groupMembers(input.existingMembers, (member) => normalizeSearchText(member.displayName));

  return Promise.all(sourceRows.map(async ({ sourceRow, values }) => {
    const sourceId = cleanDisplayValue(field(values, input.mapping.sourceId)) || undefined;
    const firstName = cleanDisplayValue(field(values, input.mapping.firstName)) || undefined;
    const lastName = cleanDisplayValue(field(values, input.mapping.lastName)) || undefined;
    const displayName = mappedName(values, input.mapping);
    const email = cleanDisplayValue(field(values, input.mapping.email)) || undefined;
    const membershipRaw = cleanDisplayValue(field(values, input.mapping.membershipStatus));
    const eligibleRaw = cleanDisplayValue(field(values, input.mapping.eligible));
    const visibleReason = cleanDisplayValue(field(values, input.mapping.visibleReason)) || undefined;
    const photoReference = cleanDisplayValue(field(values, input.mapping.photoReference)) || undefined;
    const issues: ImportIssue[] = [];

    if (!displayName) issues.push(error("MISSING_NAME"));
    if (email && !emailPattern.test(email)) issues.push(error("INVALID_EMAIL"));
    const membershipStatus = parseMembershipStatus(membershipRaw, issues);
    const eligible = parseEligibility(eligibleRaw, issues);
    const mappedText = [sourceId, displayName, firstName, lastName, email, membershipRaw, eligibleRaw, visibleReason, photoReference]
      .filter((value): value is string => Boolean(value));
    if (mappedText.some(hasDangerousSpreadsheetPrefix)) {
      issues.push(error("UNSAFE_FORMULA_PREFIX"));
    }
    if (photoReference && remoteReferencePattern.test(photoReference)) issues.push(error("UNSAFE_PHOTO_REFERENCE"));
    if (sourceId && (sourceIdCounts.get(normalizeSearchText(sourceId)) ?? 0) > 1) issues.push(error("DUPLICATE_SOURCE_ID"));

    const matches = new Map<string, ImportCandidate>();
    const addMatches = (members: readonly ImportExistingMember[], basis: ImportCandidate["basis"]) => {
      for (const member of members) {
        if (!matches.has(member.id)) matches.set(member.id, { ...member, basis });
      }
    };
    const stableMatches = sourceId ? existingByStableId.get(normalizeSearchText(sourceId)) ?? [] : [];
    const emailMatches = email ? existingByEmail.get(normalizeEmail(email)) ?? [] : [];
    const nameMatches = displayName ? existingByName.get(normalizeSearchText(displayName)) ?? [] : [];
    addMatches(stableMatches, "stable_id");
    addMatches(emailMatches, "email");
    addMatches(nameMatches, "normalized_name");
    if (stableMatches.length > 0) issues.push(warning("STABLE_ID_MATCH"));
    if (emailMatches.length > 0 || (email && (importedEmailCounts.get(normalizeEmail(email)) ?? 0) > 1)) {
      issues.push(warning("POSSIBLE_EMAIL_DUPLICATE"));
    }
    if (nameMatches.length > 0 || (displayName && (importedNameCounts.get(normalizeSearchText(displayName)) ?? 0) > 1)) {
      issues.push(warning("POSSIBLE_NAME_DUPLICATE"));
      issues.push(warning("HOMONYM_RETAINED"));
    }

    const candidates = [...matches.values()];
    const uniqueStable = stableMatches.length === 1 ? stableMatches[0] : undefined;
    const uniqueEmail = !uniqueStable && emailMatches.length === 1 ? emailMatches[0] : undefined;
    const suggestedTarget = uniqueStable ?? uniqueEmail;
    const suggestedMatchBasis: ImportMatchBasis = uniqueStable
      ? "stable_id"
      : uniqueEmail
        ? "email"
        : nameMatches.length > 0
          ? "normalized_name"
          : "none";
    const generatedId = await deterministicMemberId(
      input.tenantId,
      input.sourceFingerprint,
      input.sheetName,
      sourceRow,
      sourceId,
    );
    return {
      sourceRow,
      generatedId,
      ...(sourceId ? { sourceId } : {}),
      displayName,
      ...(firstName ? { firstName } : {}),
      ...(lastName ? { lastName } : {}),
      ...(email ? { email } : {}),
      membershipStatus,
      eligible,
      ...(visibleReason ? { visibleReason } : {}),
      ...(photoReference ? { photoReference } : {}),
      issues,
      candidates,
      suggestedAction: issues.some(({ severity }) => severity === "error") ? "skip" : suggestedTarget ? "update" : "create",
      suggestedMatchBasis,
      action: "undecided",
      ...(suggestedTarget ? { targetId: suggestedTarget.id } : {}),
    };
  }));
}

export function createImportErrorCsv(
  rows: readonly ImportPreviewRow[],
  serverCodes: ReadonlyMap<number, readonly string[]> = new Map(),
  locale: ImportLocale = "es",
): string {
  const header = [
    getMessage(locale, "import.errorCsv.row"),
    getMessage(locale, "import.errorCsv.name"),
    getMessage(locale, "import.errorCsv.email"),
    getMessage(locale, "import.errorCsv.decision"),
    getMessage(locale, "import.errorCsv.issues"),
  ];
  const values = rows
    .filter((row) => row.issues.length > 0 || row.action === "skip" || (serverCodes.get(row.sourceRow)?.length ?? 0) > 0)
    .map((row) => [
      String(row.sourceRow),
      row.displayName,
      row.email ?? "",
      row.action,
      [...row.issues.map(({ code }) => code), ...(serverCodes.get(row.sourceRow) ?? [])].join("|"),
    ]);
  return `\uFEFF${[header, ...values].map((row) => row.map(csvCell).join(",")).join("\r\n")}`;
}

function field(row: readonly string[], index: number | undefined): string {
  return index === undefined ? "" : row[index] ?? "";
}

function mappedName(row: readonly string[], mapping: ImportColumnMapping): string {
  if (mapping.displayName !== undefined) return cleanDisplayValue(field(row, mapping.displayName));
  return cleanDisplayValue([field(row, mapping.firstName), field(row, mapping.lastName)].filter(Boolean).join(" "));
}

function cleanDisplayValue(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function parseMembershipStatus(value: string, issues: ImportIssue[]): "active" | "inactive" {
  if (!value) return "active";
  const normalized = normalizeSearchText(value);
  if (["activo", "active", "actif", "miembro"].includes(normalized)) return "active";
  if (["inactivo", "inactive", "inactif", "no miembro"].includes(normalized)) return "inactive";
  issues.push(error("INVALID_MEMBERSHIP_STATUS"));
  return "inactive";
}

function parseEligibility(value: string, issues: ImportIssue[]): boolean {
  if (!value) return true;
  const normalized = normalizeSearchText(value);
  if (["si", "yes", "true", "1", "oui", "eligible", "elegible"].includes(normalized)) return true;
  if (["no", "false", "0", "non", "ineligible", "no elegible"].includes(normalized)) return false;
  issues.push(error("INVALID_ELIGIBILITY"));
  return false;
}

function error(code: ImportIssueCode): ImportIssue {
  return { code, severity: "error" };
}

function warning(code: ImportIssueCode): ImportIssue {
  return { code, severity: "warning" };
}

function groupMembers(
  members: readonly ImportExistingMember[],
  key: (member: ImportExistingMember) => string,
): ReadonlyMap<string, readonly ImportExistingMember[]> {
  const grouped = new Map<string, ImportExistingMember[]>();
  for (const member of members) {
    const value = key(member);
    if (!value) continue;
    const group = grouped.get(value) ?? [];
    group.push(member);
    grouped.set(value, group);
  }
  return grouped;
}

function countNormalized(values: readonly string[]): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const normalized = normalizeSearchText(value);
    if (normalized) counts.set(normalized, (counts.get(normalized) ?? 0) + 1);
  }
  return counts;
}

function detectDelimiter(text: string): string {
  const header = firstLogicalLine(text);
  const candidates = [",", ";", "\t"];
  const scored = candidates.map((delimiter) => ({ delimiter, count: countUnquoted(header, delimiter) }));
  scored.sort((left, right) => right.count - left.count);
  return scored[0]?.count ? scored[0].delimiter : ",";
}

function firstLogicalLine(text: string): string {
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '"') {
      if (quoted && text[index + 1] === '"') index += 1;
      else quoted = !quoted;
    } else if (!quoted && (text[index] === "\r" || text[index] === "\n")) {
      return text.slice(0, index);
    }
  }
  return text;
}

function countUnquoted(value: string, delimiter: string): number {
  let quoted = false;
  let count = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === '"') {
      if (quoted && value[index + 1] === '"') index += 1;
      else quoted = !quoted;
    } else if (!quoted && value[index] === delimiter) count += 1;
  }
  return count;
}

function parseDelimited(text: string, delimiter: string, locale: ImportLocale): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"') {
      if (quoted && text[index + 1] === '"') { value += '"'; index += 1; }
      else quoted = !quoted;
    } else if (character === delimiter && !quoted) {
      row.push(value); value = "";
    } else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(value); value = "";
      if (row.some((cell) => cell.length > 0)) rows.push(row);
      row = [];
    } else {
      value += character;
    }
  }
  if (quoted) throw new Error(getMessage(locale, "screen.memberImport.66828227533d"));
  row.push(value);
  if (row.some((cell) => cell.length > 0)) rows.push(row);
  return rows;
}

async function deterministicMemberId(
  tenantId: string,
  fingerprint: string,
  sheetName: string,
  sourceRow: number,
  sourceId?: string,
): Promise<string> {
  const material = [tenantId, fingerprint, sheetName, sourceId ? normalizeSearchText(sourceId) : `row:${sourceRow}`].join("\u001f");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
  digest[6] = ((digest[6] ?? 0) & 0x0f) | 0x50;
  digest[8] = ((digest[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(digest.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function csvCell(value: string): string {
  const safe = neutralizeSpreadsheetCell(value);
  return `"${safe.replaceAll('"', '""')}"`;
}
