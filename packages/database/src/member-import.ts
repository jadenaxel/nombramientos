import type { EncryptedEnvelope } from "./types.js";

export const MEMBER_IMPORT_ACTIONS = ["create", "update", "skip"] as const;
export const MEMBER_IMPORT_MATCH_BASES = ["none", "stable_id", "email", "normalized_name", "user_selected"] as const;

export type MemberImportAction = (typeof MEMBER_IMPORT_ACTIONS)[number];
export type MemberImportMatchBasis = (typeof MEMBER_IMPORT_MATCH_BASES)[number];

export interface MemberImportDecision {
  readonly action: MemberImportAction;
  readonly matchBasis: MemberImportMatchBasis;
}

export interface MemberImportRow {
  readonly sourceRow: number;
  readonly id: string;
  readonly shortId?: string | undefined;
  readonly eligible: boolean;
  readonly decision: MemberImportDecision;
  readonly expectedVersion?: number | undefined;
  readonly displayEnvelope?: EncryptedEnvelope | undefined;
  readonly displayContentHash?: string | undefined;
  readonly contactEnvelope?: EncryptedEnvelope | undefined;
  readonly contactContentHash?: string | undefined;
}

export interface ExistingImportMember {
  readonly id: string;
  readonly stableCode: string;
  readonly version: number;
  readonly profileMigrationRequired?: boolean;
}

export const MEMBER_IMPORT_RESULT_CODES = [
  "DUPLICATE_SOURCE_ROW",
  "DUPLICATE_TARGET",
  "DUPLICATE_STABLE_ID",
  "TARGET_EXISTS",
  "TARGET_NOT_FOUND",
  "STABLE_ID_EXISTS",
  "STABLE_ID_MISMATCH",
  "VERSION_CONFLICT",
  "LEGACY_PROFILE_MIGRATION_REQUIRED",
] as const;

export type MemberImportResultCode = (typeof MEMBER_IMPORT_RESULT_CODES)[number];

export interface MemberImportRowResult {
  readonly sourceRow: number;
  readonly action: MemberImportAction;
  readonly status: "ready" | "error";
  readonly codes: readonly MemberImportResultCode[];
}

export interface MemberImportPlanResult {
  readonly rows: readonly MemberImportRowResult[];
  readonly counts: {
    readonly create: number;
    readonly update: number;
    readonly skip: number;
    readonly errors: number;
  };
}

/**
 * Evaluates only opaque identifiers and concurrency metadata. Names and email
 * addresses remain encrypted and duplicate suggestions based on them are made
 * by the authorized browser before this plan reaches the server.
 */
export function evaluateMemberImportPlan(
  rows: readonly MemberImportRow[],
  existingMembers: readonly ExistingImportMember[],
): MemberImportPlanResult {
  const existingById = new Map(existingMembers.map((member) => [member.id, member]));
  const existingByStableCode = new Map(existingMembers.map((member) => [normalizeStableCode(member.stableCode), member]));
  const sourceRowCounts = countValues(rows.map((row) => String(row.sourceRow)));
  const targetCounts = countValues(rows.filter(({ decision }) => decision.action !== "skip").map((row) => row.id));
  const newStableCodeCounts = countValues(rows
    .filter(({ decision, shortId }) => decision.action === "create" && shortId !== undefined)
    .map((row) => normalizeStableCode(row.shortId!)));

  const evaluated = rows.map((row): MemberImportRowResult => {
    const codes = new Set<MemberImportResultCode>();
    if ((sourceRowCounts.get(String(row.sourceRow)) ?? 0) > 1) codes.add("DUPLICATE_SOURCE_ROW");
    if (row.decision.action !== "skip" && (targetCounts.get(row.id) ?? 0) > 1) codes.add("DUPLICATE_TARGET");

    if (row.decision.action === "create") {
      if (existingById.has(row.id)) codes.add("TARGET_EXISTS");
      if (row.shortId) {
        const stableCode = normalizeStableCode(row.shortId);
        if ((newStableCodeCounts.get(stableCode) ?? 0) > 1) codes.add("DUPLICATE_STABLE_ID");
        if (existingByStableCode.has(stableCode)) codes.add("STABLE_ID_EXISTS");
      }
    }

    if (row.decision.action === "update") {
      const existing = existingById.get(row.id);
      if (!existing) {
        codes.add("TARGET_NOT_FOUND");
      } else {
        if (row.expectedVersion !== existing.version) codes.add("VERSION_CONFLICT");
        // A bulk import cannot safely infer whether the contact portion of the
        // quarantined combined envelope should be replaced or discarded.
        // Resolve it explicitly through the authorized split-profile flow.
        if (existing.profileMigrationRequired) codes.add("LEGACY_PROFILE_MIGRATION_REQUIRED");
        if (row.shortId && normalizeStableCode(row.shortId) !== normalizeStableCode(existing.stableCode)) {
          codes.add("STABLE_ID_MISMATCH");
        }
      }
    }

    return {
      sourceRow: row.sourceRow,
      action: row.decision.action,
      status: codes.size === 0 ? "ready" : "error",
      codes: [...codes],
    };
  });

  return {
    rows: evaluated,
    counts: {
      create: rows.filter(({ decision }) => decision.action === "create").length,
      update: rows.filter(({ decision }) => decision.action === "update").length,
      skip: rows.filter(({ decision }) => decision.action === "skip").length,
      errors: evaluated.filter(({ status }) => status === "error").length,
    },
  };
}

export function normalizeStableCode(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}

function countValues(values: readonly string[]): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return counts;
}
