export type CatalogLocale = "es" | "en" | "fr";

export type CatalogReviewStatus =
  | "verified_primary_source"
  | "verified_official_supporting_source"
  | "pending_primary_source_validation"
  | "pending_regional_validation"
  | "pending_local_approval";

export interface CatalogSourceReference {
  readonly sourceId: string;
  readonly chapter: string | null;
  readonly section: string | null;
  readonly printedPages: readonly number[];
  readonly sourceLanguage: string | null;
  readonly url: string | null;
}

export interface CatalogRichMetadata {
  readonly purpose: string | null;
  readonly responsibilities: readonly string[];
  readonly conditions: readonly string[];
  readonly notes: string | null;
  readonly aliases: readonly string[];
  readonly sourceRuleIds: readonly string[];
  readonly sourceLocators: readonly CatalogSourceReference[];
  readonly reviewStatus: CatalogReviewStatus | null;
  readonly catalogVersion: string;
  readonly territory: string | null;
  readonly reportsToOfficeCode: string | null;
  readonly linkedBaseOfficeCode: string | null;
  readonly applicableByDefault: boolean | null;
}

const reviewStatuses = new Set<CatalogReviewStatus>([
  "verified_primary_source",
  "verified_official_supporting_source",
  "pending_primary_source_validation",
  "pending_regional_validation",
  "pending_local_approval",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cleanString(value: unknown, maximum = 2_000): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.trim();
  return cleaned.length > 0 && cleaned.length <= maximum ? cleaned : null;
}

export function localizedCatalogText(value: unknown, locale: CatalogLocale): string | null {
  const direct = cleanString(value);
  if (direct) return direct;
  if (!isRecord(value)) return null;
  for (const language of [locale, "es", "en", "fr"] as const) {
    const localized = cleanString(value[language]);
    if (localized) return localized;
  }
  return null;
}

function localizedList(value: unknown, locale: CatalogLocale): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => localizedCatalogText(entry, locale))
    .filter((entry): entry is string => entry !== null)
    .slice(0, 100);
}

function stringList(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => cleanString(entry, 160))
    .filter((entry): entry is string => entry !== null)
    .slice(0, 100);
}

function optionalCode(value: unknown): string | null {
  const code = cleanString(value, 160);
  return code && /^[a-z0-9][a-z0-9._-]*$/iu.test(code) ? code : null;
}

function safeSourceUrl(value: unknown): string | null {
  const raw = cleanString(value, 2_048);
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "https:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}

function pageList(value: unknown): readonly number[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is number => Number.isInteger(entry) && Number(entry) > 0).slice(0, 100);
}

function sourceReferences(value: unknown): readonly CatalogSourceReference[] {
  if (!Array.isArray(value)) return [];
  const references: CatalogSourceReference[] = [];
  for (const entry of value.slice(0, 100)) {
    if (!isRecord(entry)) continue;
    const sourceId = optionalCode(entry["sourceId"]);
    if (!sourceId) continue;
    references.push({
      sourceId,
      chapter: cleanString(entry["chapter"], 320),
      section: cleanString(entry["section"], 320),
      printedPages: pageList(entry["printedPages"]),
      sourceLanguage: cleanString(entry["sourceLanguage"], 40),
      url: safeSourceUrl(entry["url"]),
    });
  }
  return references;
}

export function readCatalogRichMetadata(
  record: Readonly<Record<string, unknown>>,
  locale: CatalogLocale,
  normativeVersion: string,
): CatalogRichMetadata {
  const reviewStatus = cleanString(record["reviewStatus"], 80);
  const catalogVersion = cleanString(record["catalogVersion"], 160);
  return {
    purpose: localizedCatalogText(record["purpose"], locale),
    responsibilities: localizedList(record["responsibilities"], locale),
    conditions: localizedList(record["conditions"], locale),
    notes: localizedCatalogText(record["notes"], locale),
    aliases: localizedList(record["aliases"], locale),
    sourceRuleIds: stringList(record["sourceRuleIds"]),
    sourceLocators: sourceReferences(record["sourceLocators"]),
    reviewStatus: reviewStatus && reviewStatuses.has(reviewStatus as CatalogReviewStatus)
      ? reviewStatus as CatalogReviewStatus
      : null,
    catalogVersion: catalogVersion ?? normativeVersion,
    territory: cleanString(record["territory"], 320),
    reportsToOfficeCode: optionalCode(record["reportsToOfficeCode"]),
    linkedBaseOfficeCode: optionalCode(record["linkedBaseOfficeCode"]),
    applicableByDefault: typeof record["applicableByDefault"] === "boolean"
      ? record["applicableByDefault"]
      : null,
  };
}
