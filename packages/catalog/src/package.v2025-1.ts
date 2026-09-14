import { departments } from "./departments.v2025-1.js";
import { normativeMatrix, CATALOG_PACKAGE_VERSION } from "./normative-matrix.v2025-1.js";
import { offices } from "./offices.v2025-1.js";
import type { CatalogPackage } from "./types.js";

export const catalogPackage2025 = {
  version: CATALOG_PACKAGE_VERSION,
  // Content is versioned and regression-checked; this status remains draft until
  // the tenant and competent territorial authority complete external validation.
  status: "draft",
  effectiveFrom: "2026-09-13",
  sourceIds: ["SDA_CM_2025_EN", "SDA_CHURCH_MANUAL_PORTAL", "SDA_ELDERS_HANDBOOK_2016_EN"],
  departments,
  offices,
  normativeRules: normativeMatrix,
  externalValidationRequired: [
    "Confirmar asociación/misión, unión y división de Iglesia Adventista Ozama.",
    "Validar suplementos regionales vigentes con la autoridad territorial competente.",
    "Confirmar cuáles cargos opcionales de la lista de muestra de las páginas impresas 191–192 aplican a Ozama.",
    "Revisar las traducciones ES/FR con personal eclesiástico competente; son traducciones de trabajo.",
    "Confirmar autorización de uso y redistribución de recursos protegidos; por defecto solo se enlazan fuentes oficiales.",
    "Aprobar las prácticas locales de Ozama antes de convertir cualquier entrada pending_local_approval en vacante.",
  ],
} as const satisfies CatalogPackage;

/** @deprecated Use catalogPackage2025. Retained only for source compatibility. */
export const catalogPackage2025Draft = catalogPackage2025;

/**
 * Human-auditable coverage guard for the 2025 Manual's sample list of local
 * church leaders (printed pages 191–192). Collegial bodies such as the church
 * board remain organization structures rather than synthetic person offices.
 */
export const churchManualSampleOfficeCodes2025 = [
  "elder",
  "deacon",
  "deaconess",
  "church_clerk",
  "church_treasurer",
  "assistant_church_treasurer",
  "interest_coordinator",
  "community_services_leader",
  "community_services_secretary_treasurer",
  "possibility_ministries_leader",
  "adventist_youth_leader",
  "aym_music_leader",
  "aym_pianist_organist",
  "aym_secretary_treasurer",
  "aym_assistant_secretary_treasurer",
  "adventurer_club_director",
  "ambassador_ministry_leader",
  "pathfinder_club_director",
  "pathfinder_deputy_director",
  "public_campus_ministry_coordinator",
  "young_adults_leader",
  "bible_school_coordinator",
  "childrens_ministries_coordinator",
  "music_coordinator",
  "church_pianist_organist",
  "communication_secretary",
  "education_secretary",
  "school_principal_head_teacher",
  "family_ministries_leader",
  "health_ministries_leader",
  "personal_ministries_leader",
  "personal_ministries_secretary",
  "prayer_ministries_coordinator",
  "publishing_ministries_coordinator",
  "religious_liberty_leader",
  "sabbath_school_superintendent",
  "assistant_sabbath_school_superintendent",
  "sabbath_school_secretary",
  "assistant_sabbath_school_secretary",
  "sabbath_school_division_leader",
  "sabbath_school_investment_secretary",
  "spirit_of_prophecy_coordinator",
  "stewardship_ministries_leader",
  "vacation_bible_school_coordinator",
  "womens_ministries_leader",
  "home_school_leader",
  "home_school_secretary_treasurer",
] as const;

const unique = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;
const normalizeSentence = (value: string): string => value.trim().replace(/[.!?…]+$/u, "").toLocaleLowerCase("en");
const sameLocalizedText = (first: Readonly<Record<"es" | "en" | "fr", string>>, second: Readonly<Record<"es" | "en" | "fr", string>>) =>
  (["es", "en", "fr"] as const).every((locale) => normalizeSentence(first[locale]) === normalizeSentence(second[locale]));
const repeatsPurposeAsLead = (responsibility: Readonly<Record<"es" | "en" | "fr", string>>, purpose: Readonly<Record<"es" | "en" | "fr", string>>) =>
  (["es", "en", "fr"] as const).every((locale) => {
    const normalizedPurpose = normalizeSentence(purpose[locale]);
    const normalizedResponsibility = normalizeSentence(responsibility[locale]);
    return normalizedResponsibility === normalizedPurpose
      || normalizedResponsibility.startsWith(`${normalizedPurpose}.`)
      || normalizedResponsibility.startsWith(`${normalizedPurpose} `);
  });

const expectedChurchManualChapter = (printedPage: number): string | null => {
  if (printedPage >= 80 && printedPage <= 119) return "Chapter 9 — Local Church Officers and Organizations";
  if (printedPage >= 120 && printedPage < 190) return "Chapter 10 — Elections";
  if (printedPage === 190) return "Chapter 9 Notes";
  if (printedPage === 191 || printedPage === 192) return "Chapter 10 Notes";
  return null;
};

export const validateCatalogPackage = (catalog: CatalogPackage): readonly string[] => {
  const errors: string[] = [];
  const departmentCodes = catalog.departments.map((department) => department.canonicalCode);
  const officeCodes = catalog.offices.map((officeDefinition) => officeDefinition.canonicalCode);
  const ruleIds = catalog.normativeRules.map((rule) => rule.id);

  if (!unique(departmentCodes)) errors.push("Duplicate department canonicalCode");
  if (!unique(officeCodes)) errors.push("Duplicate office canonicalCode");
  if (!unique(ruleIds)) errors.push("Duplicate normative rule id");

  const departmentsSet = new Set(departmentCodes);
  const officesSet = new Set(officeCodes);
  const rulesSet = new Set(ruleIds);
  const sourcesSet = new Set(catalog.sourceIds);

  if (catalog.version === CATALOG_PACKAGE_VERSION) {
    if (!/^\d{4}\.\d+\.\d+$/u.test(catalog.version)) errors.push("Current catalog package version must be a stable numeric revision");
    for (const requiredCode of churchManualSampleOfficeCodes2025) {
      if (!officesSet.has(requiredCode)) errors.push(`Missing 2025 Church Manual sample office ${requiredCode}`);
    }
    for (const rule of catalog.normativeRules) {
      if (rule.implementationStatus === "implemented_unverified" || rule.implementationStatus === "documented_only") {
        errors.push(`Stale implementation status for current rule ${rule.id}`);
      }
      if (rule.implementationStatus === "verified_with_evidence") {
        if (rule.implementationRefs.length === 0) errors.push(`Verified rule ${rule.id} requires an implementation reference`);
        if (!rule.testRefs.some((reference) => /(?:^|\/)[^/]+\.(?:test|spec)\.[cm]?[jt]sx?$/u.test(reference))) {
          errors.push(`Verified rule ${rule.id} requires a concrete automated test reference`);
        }
      }
    }
  }

  for (const department of catalog.departments) {
    if (department.parentDepartmentCode !== null && !departmentsSet.has(department.parentDepartmentCode)) {
      errors.push(`Unknown parent department ${department.parentDepartmentCode} for ${department.canonicalCode}`);
    }
    for (const ruleId of department.sourceRuleIds) {
      if (!rulesSet.has(ruleId)) errors.push(`Unknown rule ${ruleId} for department ${department.canonicalCode}`);
    }
  }

  for (const officeDefinition of catalog.offices) {
    if (!departmentsSet.has(officeDefinition.departmentCode)) {
      errors.push(`Unknown department ${officeDefinition.departmentCode} for ${officeDefinition.canonicalCode}`);
    }
    if (officeDefinition.linkedBaseOfficeCode !== null && !officesSet.has(officeDefinition.linkedBaseOfficeCode)) {
      errors.push(`Unknown linked office ${officeDefinition.linkedBaseOfficeCode} for ${officeDefinition.canonicalCode}`);
    }
    if (officeDefinition.reportsToOfficeCode === officeDefinition.canonicalCode) {
      errors.push(`Office ${officeDefinition.canonicalCode} cannot report to itself`);
    } else if (officeDefinition.reportsToOfficeCode !== null && !officesSet.has(officeDefinition.reportsToOfficeCode)) {
      errors.push(`Unknown reporting office ${officeDefinition.reportsToOfficeCode} for ${officeDefinition.canonicalCode}`);
    }
    if (!officeDefinition.names.es.trim() || !officeDefinition.names.en.trim() || !officeDefinition.names.fr.trim()) {
      errors.push(`Incomplete localized name for office ${officeDefinition.canonicalCode}`);
    }
    if (officeDefinition.responsibilities.length === 0 || officeDefinition.responsibilities.some((responsibility) =>
      !responsibility.es.trim() || !responsibility.en.trim() || !responsibility.fr.trim()
    )) {
      errors.push(`Incomplete localized responsibilities for office ${officeDefinition.canonicalCode}`);
    }
    if (officeDefinition.responsibilities.some((responsibility) => sameLocalizedText(responsibility, officeDefinition.purpose))) {
      errors.push(`Office ${officeDefinition.canonicalCode} repeats its purpose as a responsibility`);
    }
    if (officeDefinition.responsibilities.some((responsibility) => repeatsPurposeAsLead(responsibility, officeDefinition.purpose))) {
      errors.push(`Office ${officeDefinition.canonicalCode} prefixes a responsibility with its purpose`);
    }
    if (!officeDefinition.applicableByDefault && officeDefinition.conditions.length === 0) {
      errors.push(`Optional office ${officeDefinition.canonicalCode} requires an applicability condition`);
    }
    if (officeDefinition.reviewStatus === "verified_primary_source" && officeDefinition.sourceLocators.length === 0) {
      errors.push(`Verified office ${officeDefinition.canonicalCode} requires a primary-source locator`);
    }
    for (const locator of officeDefinition.sourceLocators) {
      if (!sourcesSet.has(locator.sourceId)) errors.push(`Unknown source ${locator.sourceId} for office ${officeDefinition.canonicalCode}`);
      if (locator.printedPages.length === 0 || locator.pdfPages.length === 0) {
        errors.push(`Empty source pages for office ${officeDefinition.canonicalCode}`);
      }
      if (locator.printedPages.length !== locator.pdfPages.length
          || locator.printedPages.some((page, index) => page !== locator.pdfPages[index])) {
        errors.push(`Printed/PDF page mismatch for office ${officeDefinition.canonicalCode}`);
      }
      if (locator.sourceId === "SDA_CM_2025_EN") {
        for (const printedPage of locator.printedPages) {
          const expectedChapter = expectedChurchManualChapter(printedPage);
          if (expectedChapter !== null && locator.chapter !== expectedChapter) {
            errors.push(`False chapter locator for office ${officeDefinition.canonicalCode} page ${printedPage}`);
          }
          if ((printedPage === 191 || printedPage === 192)
              && locator.section !== "1. Sample List of Church Leaders (see p. 122).") {
            errors.push(`False Chapter 10 Notes topic for office ${officeDefinition.canonicalCode} page ${printedPage}`);
          }
        }
      }
    }
    for (const ruleId of officeDefinition.sourceRuleIds) {
      if (!rulesSet.has(ruleId)) errors.push(`Unknown rule ${ruleId} for office ${officeDefinition.canonicalCode}`);
    }
  }

  return errors;
};
