import type { Locale } from "./types.js";

export type GlossaryReviewStatus =
  | "working_translation_pending_ecclesiastical_review"
  | "tenant_approved";

export interface GlossaryEntry {
  readonly id: string;
  readonly terms: Readonly<Record<Locale, string>>;
  readonly context: Readonly<Record<Locale, string>>;
  readonly avoid: Partial<Readonly<Record<Locale, readonly string[]>>>;
  readonly reviewStatus: GlossaryReviewStatus;
}

export const glossary = [
  {
    id: "nominating_committee",
    terms: {
      es: "Junta de nombramientos / Comisión de nombramientos",
      en: "Nominating Committee",
      fr: "Commission des nominations",
    },
    context: {
      es: "Órgano autorizado que prepara recomendaciones; el tenant debe elegir una forma principal.",
      en: "Authorized body that prepares recommendations.",
      fr: "Organe autorisé qui prépare des recommandations.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "nomination",
    terms: { es: "Nombramiento", en: "Nomination / appointment", fr: "Nomination / désignation" },
    context: {
      es: "Término general; usar una etiqueta más precisa cuando se conozca la fase.",
      en: "General term; use a more precise label when the phase is known.",
      fr: "Terme général; utiliser une étiquette plus précise lorsque la phase est connue.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "candidate_proposal",
    terms: { es: "Propuesta de candidato", en: "Candidate proposal", fr: "Proposition de candidature" },
    context: {
      es: "Nombre presentado durante la fase de propuestas; no equivale a voto ni elección.",
      en: "A name submitted during the proposal phase; not a vote or election.",
      fr: "Nom présenté pendant la phase de propositions; ce n’est ni un vote ni une élection.",
    },
    avoid: { es: ["ganador"], en: ["winner"], fr: ["gagnant"] },
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "recommendation",
    terms: { es: "Recomendación de la junta", en: "Committee recommendation", fr: "Recommandation de la commission" },
    context: {
      es: "Resultado formal de la comisión que todavía requiere el proceso de la iglesia.",
      en: "Formal committee outcome that still requires the church process.",
      fr: "Résultat officiel de la commission qui doit encore suivre la procédure de l’Église.",
    },
    avoid: { es: ["elegido"], en: ["elected"], fr: ["élu"] },
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "church_election",
    terms: { es: "Elección por la iglesia", en: "Election by the church", fr: "Élection par l’Église" },
    context: {
      es: "Acción congregacional distinta de la decisión interna de la comisión.",
      en: "Congregational action distinct from the committee's internal decision.",
      fr: "Action de l’Église distincte de la décision interne de la commission.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "elder",
    terms: { es: "Anciano/a", en: "Elder", fr: "Ancien/Ancienne" },
    context: {
      es: "Cargo eclesiástico; no es un rol de acceso informático.",
      en: "Church office; not an application access role.",
      fr: "Fonction ecclésiastique; ne correspond pas à un rôle d’accès informatique.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "deaconess",
    terms: { es: "Diaconisa", en: "Deaconess", fr: "Diaconesse" },
    context: {
      es: "Cargo eclesiástico modelado separadamente de la cuenta de usuario.",
      en: "Church office modeled separately from the user account.",
      fr: "Fonction ecclésiastique modélisée séparément du compte utilisateur.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "abstention",
    terms: { es: "Abstención", en: "Abstention", fr: "Abstention" },
    context: {
      es: "Respuesta explícita que completa el paso sin apoyar a un candidato; no es ausencia.",
      en: "Explicit response completing the step without supporting a candidate; not absence.",
      fr: "Réponse explicite qui termine l’étape sans soutenir une candidature; ce n’est pas une absence.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
  {
    id: "vacancy",
    terms: { es: "Vacante", en: "Vacancy", fr: "Poste vacant" },
    context: {
      es: "Plaza concreta de un cargo y mandato.",
      en: "A specific seat for an office and term.",
      fr: "Place précise correspondant à une fonction et à un mandat.",
    },
    avoid: {},
    reviewStatus: "working_translation_pending_ecclesiastical_review",
  },
] as const satisfies readonly GlossaryEntry[];
