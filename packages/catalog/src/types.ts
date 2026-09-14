export type CatalogLocale = "es" | "en" | "fr";

export interface LocalizedText {
  readonly es: string;
  readonly en: string;
  readonly fr: string;
}

export type SourceKind =
  | "primary_manual"
  | "official_supporting_manual"
  | "regional_supplement"
  | "local_approved_policy"
  | "product_decision";

export type SourceReviewStatus =
  | "verified_primary_source"
  | "verified_official_supporting_source"
  | "pending_primary_source_validation"
  | "pending_regional_validation"
  | "pending_local_approval";

export interface CatalogSource {
  readonly id: string;
  readonly title: string;
  readonly authority: string;
  readonly kind: SourceKind;
  readonly edition: string | null;
  readonly sourceLanguage: string;
  readonly url: string | null;
  readonly consultedOn: string | null;
  readonly reviewStatus: SourceReviewStatus;
  readonly redistribution: "link_only" | "permission_required" | "not_applicable";
  readonly notes: string;
}

export type NormativeClassification =
  | "norma_manual"
  | "disposicion_regional_validada"
  | "practica_local_aprobada"
  | "configuracion_producto"
  | "pendiente_validacion";

export type ImplementationStatus =
  | "documented_only"
  | "catalogued_not_enforced"
  | "implemented_unverified"
  | "verified_with_evidence"
  | "blocked_pending_validation";

export interface SourceLocator {
  readonly sourceId: string;
  readonly chapter: string;
  readonly section: string;
  readonly printedPages: readonly number[];
  readonly pdfPages: readonly number[];
  readonly sourceLanguage: string;
  readonly url: string;
  readonly locatorNotes?: string;
}

export interface NormativeRule {
  readonly id: string;
  readonly packageVersion: string;
  readonly title: LocalizedText;
  readonly summary: LocalizedText;
  readonly classification: NormativeClassification;
  readonly territory: string;
  readonly authority: string;
  readonly source: SourceLocator | null;
  readonly interpretation: LocalizedText;
  readonly productRequirement: LocalizedText;
  readonly implementationStatus: ImplementationStatus;
  readonly implementationRefs: readonly string[];
  readonly testRefs: readonly string[];
  readonly validationNotes: readonly string[];
  readonly mandatoryWhenApplicable: boolean;
}

export type AppointmentMechanism =
  | "church_election_after_nominating_report"
  | "church_election"
  | "board_appointment"
  | "council_recommendation_board_approval"
  | "conference_appointment"
  | "ex_officio"
  | "linked_designation"
  | "local_configuration_pending";

export interface Cardinality {
  readonly minimum: number;
  readonly maximum: number | null;
  readonly homogeneousVacancies: boolean;
}

export interface DepartmentDefinition {
  readonly canonicalCode: string;
  readonly names: LocalizedText;
  readonly aliases: readonly LocalizedText[];
  readonly purpose: LocalizedText;
  readonly parentDepartmentCode: string | null;
  readonly sourceRuleIds: readonly string[];
  readonly reviewStatus: SourceReviewStatus;
  readonly applicableByDefault: boolean;
  readonly notes: LocalizedText;
}

export interface OfficeDefinition {
  readonly canonicalCode: string;
  readonly departmentCode: string;
  readonly names: LocalizedText;
  readonly aliases: readonly LocalizedText[];
  readonly purpose: LocalizedText;
  readonly responsibilities: readonly LocalizedText[];
  readonly reportsToOfficeCode: string | null;
  readonly mechanism: AppointmentMechanism;
  readonly cardinality: Cardinality;
  readonly conditions: readonly LocalizedText[];
  readonly sourceRuleIds: readonly string[];
  readonly sourceLocators: readonly SourceLocator[];
  readonly territory: string;
  readonly catalogVersion: string;
  readonly reviewStatus: SourceReviewStatus;
  readonly linkedBaseOfficeCode: string | null;
  readonly applicableByDefault: boolean;
  readonly notes: LocalizedText;
}

export interface CatalogPackage {
  readonly version: string;
  readonly status: "draft" | "tenant_validated" | "superseded";
  readonly effectiveFrom: string;
  readonly sourceIds: readonly string[];
  readonly departments: readonly DepartmentDefinition[];
  readonly offices: readonly OfficeDefinition[];
  readonly normativeRules: readonly NormativeRule[];
  readonly externalValidationRequired: readonly string[];
}
