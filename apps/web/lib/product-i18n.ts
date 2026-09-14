import { getMessage, type MessageKey } from "@nombramientos/i18n";
import type { Permission } from "@nombramientos/domain";

import { ApiError, type Locale } from "./api";
import { formatIcuMessage } from "./icu-message";

export type LocalizedNames = Partial<Record<Locale, string>> | null | undefined;

export function localizedName(names: LocalizedNames, locale: Locale, fallback: string): string {
  return names?.[locale]?.trim() || names?.es?.trim() || names?.en?.trim() || names?.fr?.trim() || fallback;
}

export function message(locale: Locale, key: MessageKey, values?: Readonly<Record<string, string | number>>): string {
  const source = getMessage(locale, key);
  if (!values) return source;
  return formatIcuMessage(locale, source, values);
}

const phaseKeys: Readonly<Record<string, MessageKey>> = {
  PENDIENTE: "phase.pending",
  CONFIGURADO: "phase.configured",
  PROPUESTAS_ABIERTAS: "phase.proposalsOpen",
  PROPUESTAS_CERRADAS: "phase.proposalsClosed",
  DEPURACION: "phase.review",
  LISTA_CONFIRMADA: "phase.listConfirmed",
  VOTACION_ABIERTA: "phase.votingOpen",
  VOTACION_CERRADA: "phase.votingClosed",
  ESCRUTINIO: "phase.tally",
  RESULTADO_INTERNO: "phase.internalResult",
  RECOMENDACION_CONFIRMADA: "phase.recommendationConfirmed",
  CERRADO: "phase.closed",
  PAUSADO: "phase.paused",
  SIN_CANDIDATOS: "phase.noCandidates",
  DESEMPATE_PENDIENTE: "phase.tiePending",
  ANULADO: "phase.annulled",
  VACANTE_PENDIENTE: "phase.vacancyPending",
};

const assignmentKeys: Readonly<Record<string, MessageKey>> = {
  PROPUESTA_INTERNA: "assignment.internalProposal",
  ACEPTACION_PENDIENTE: "assignment.acceptancePending",
  ACEPTADA: "assignment.accepted",
  PRESENTADA_A_IGLESIA: "assignment.presentedToChurch",
  ELEGIDA_POR_IGLESIA: "assignment.electedByChurch",
  VIGENTE: "assignment.active",
  FINALIZADA: "assignment.finished",
  DECLINADA: "assignment.declined",
  DEVUELTA_A_COMISION: "assignment.returned",
  RETIRADA: "assignment.withdrawn",
  SUSTITUIDA: "assignment.replaced",
};

export function phaseLabel(locale: Locale, phase: string): string {
  const key = phaseKeys[phase];
  return key ? message(locale, key) : phase.replaceAll("_", " ");
}

export function assignmentLabel(locale: Locale, state: string): string {
  const key = assignmentKeys[state];
  return key ? message(locale, key) : state.replaceAll("_", " ");
}

type TenantPermission = Exclude<Permission, `platform.${string}`>;

export const permissionDescriptionKeys: Readonly<Record<TenantPermission, MessageKey>> = {
  "tenant.settings.manage": "permission.tenantSettingsManage",
  "member.read": "permission.memberRead",
  "member.manage": "permission.memberManage",
  "member.contact.read": "permission.memberContactRead",
  "member.contact.manage": "permission.memberContactManage",
  "member.eligibility.manage": "permission.memberEligibilityManage",
  "member.qualification.read": "permission.memberQualificationRead",
  "member.qualification.manage": "permission.memberQualificationManage",
  "workflow.eligibility.resolve": "permission.workflowEligibilityResolve",
  "member.photo.manage": "permission.memberPhotoManage",
  "member.import": "permission.memberImport",
  "committee.manage": "permission.committeeManage",
  "catalog.manage": "permission.catalogManage",
  "cycle.manage": "permission.cycleManage",
  "proposal.open": "permission.proposalOpen",
  "proposal.close": "permission.proposalClose",
  "proposal.submit": "permission.proposalSubmit",
  "participation.nominal.read": "permission.participationNominalRead",
  "candidate.review": "permission.candidateReview",
  "ballot.open": "permission.ballotOpen",
  "ballot.close": "permission.ballotClose",
  "ballot.submit": "permission.ballotSubmit",
  "tally.custody": "permission.tallyCustody",
  "tally.recount": "permission.tallyRecount",
  "aggregate.publish": "permission.aggregatePublish",
  "aggregate.read": "permission.aggregateRead",
  "linked-designation.record": "permission.linkedDesignationRecord",
  "consent.record": "permission.consentRecord",
  "congregational-decision.record": "permission.congregationalDecisionRecord",
  "organigram.read": "permission.organigramRead",
  "report.read": "permission.reportRead",
  "report.export": "permission.reportExport",
  "private-note.read": "permission.privateNoteRead",
  "audit.read": "permission.auditRead",
  "role.manage": "permission.roleManage",
  "recovery.activate": "permission.recoveryActivate",
};

export function permissionDescription(
  locale: Locale,
  permission: Readonly<{ code: string; description: string }>,
): string {
  const key = permissionDescriptionKeys[permission.code as TenantPermission];
  return key ? message(locale, key) : permission.description;
}

const apiCodeKeys: Readonly<Record<string, MessageKey>> = {
  UNAUTHENTICATED: "error.unauthenticated",
  AUTHENTICATION_REQUIRED: "error.unauthenticated",
  MFA_ASSURANCE_REQUIRED: "error.mfaStepUp",
  MFA_STEP_UP_REQUIRED: "error.mfaStepUp",
  KEY_LIFECYCLE_STEP_UP_REQUIRED: "error.mfaStepUp",
  FORBIDDEN: "error.forbidden",
  PERMISSION_DENIED: "error.forbidden",
  PERMISSION_ESCALATION: "error.forbidden",
  NOT_FOUND: "error.notFound",
  VALIDATION_ERROR: "error.validation",
  PHASE_CONFLICT: "error.phaseConflict",
  VERSION_CONFLICT: "error.versionConflict",
  PHOTO_VERSION_CONFLICT: "error.versionConflict",
  ROUND_CLOSED: "error.roundClosed",
  LIMIT_EXCEEDED: "error.limitExceeded",
  CRYPTO_ERROR: "error.crypto",
  BALLOT_INVALID: "vote.invalidBallot",
  KEYS_UNAVAILABLE: "error.keysUnavailable",
  CUSTODY_KEY_UNAVAILABLE: "error.keysUnavailable",
  KEY_GRANT_REQUIRED: "error.keysUnavailable",
  EXPORT_DENIED: "error.exportDenied",
  FILE_REJECTED: "error.fileRejected",
};

const identitySecurityErrors: Readonly<Record<string, Readonly<Record<Locale, string>>>> = {
  WEBAUTHN_ORIGIN_DENIED: {
    es: "Abre la aplicación desde su dominio autorizado para usar una llave de acceso.",
    en: "Open the application from its authorized domain to use a passkey.",
    fr: "Ouvrez l’application depuis son domaine autorisé pour utiliser une clé d’accès.",
  },
  WEBAUTHN_CEREMONY_INVALID: {
    es: "La verificación expiró o ya fue utilizada. Inicia una nueva confirmación.",
    en: "The verification expired or was already used. Start a new confirmation.",
    fr: "La vérification a expiré ou a déjà été utilisée. Lancez une nouvelle confirmation.",
  },
  WEBAUTHN_VERIFICATION_FAILED: {
    es: "No pudimos validar esta llave de acceso. Inténtalo de nuevo o usa otro método.",
    en: "We could not validate this passkey. Try again or use another method.",
    fr: "Impossible de valider cette clé d’accès. Réessayez ou utilisez une autre méthode.",
  },
  PASSKEY_REQUIRED: {
    es: "Registra una llave de acceso antes de autorizar esta operación protegida.",
    en: "Register a passkey before authorizing this protected operation.",
    fr: "Enregistrez une clé d’accès avant d’autoriser cette opération protégée.",
  },
  PASSKEY_LIMIT_REACHED: {
    es: "Alcanzaste el límite de llaves de acceso de tu organización.",
    en: "You reached your organization’s passkey limit.",
    fr: "Vous avez atteint la limite de clés d’accès de votre organisation.",
  },
  PASSKEY_POLICY_DENIED: {
    es: "Esta llave no cumple la política de seguridad de tu organización.",
    en: "This passkey does not meet your organization’s security policy.",
    fr: "Cette clé d’accès ne respecte pas la politique de sécurité de votre organisation.",
  },
  PASSKEY_VERSION_CONFLICT: {
    es: "Esta llave cambió en otro dispositivo. Actualiza la lista e inténtalo de nuevo.",
    en: "This passkey changed on another device. Refresh the list and try again.",
    fr: "Cette clé d’accès a été modifiée sur un autre appareil. Actualisez la liste et réessayez.",
  },
  PASSKEY_NOT_FOUND: {
    es: "La llave de acceso ya no está disponible.",
    en: "The passkey is no longer available.",
    fr: "La clé d’accès n’est plus disponible.",
  },
  PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED: {
    es: "Por seguridad, tu verificación reciente venció. Vuelve a iniciar sesión con MFA y luego crea tu primera llave de acceso.",
    en: "For your security, your recent verification expired. Sign in again with MFA, then create your first passkey.",
    fr: "Pour votre sécurité, votre vérification récente a expiré. Reconnectez-vous avec l’AMF, puis créez votre première clé d’accès.",
  },
  SESSION_NOT_FOUND: {
    es: "La sesión ya estaba cerrada o dejó de estar disponible.",
    en: "The session was already closed or is no longer available.",
    fr: "La session était déjà fermée ou n’est plus disponible.",
  },
  RECOVERY_RESTRICTED: {
    es: "Esta sesión de recuperación solo puede reparar tus métodos de acceso.",
    en: "This recovery session can only repair your sign-in methods.",
    fr: "Cette session de récupération peut uniquement réparer vos méthodes d’accès.",
  },
  TOTP_POLICY_DENIED: {
    es: "La política de tu organización exige llaves de acceso y no permite TOTP.",
    en: "Your organization’s policy requires passkeys and does not allow TOTP.",
    fr: "La politique de votre organisation exige des clés d’accès et n’autorise pas TOTP.",
  },
  AAL3_REQUIRED: {
    es: "Esta operación exige una llave física o administrada con mayor nivel de garantía.",
    en: "This operation requires a hardware or managed passkey with a higher assurance level.",
    fr: "Cette opération exige une clé matérielle ou gérée avec un niveau d’assurance supérieur.",
  },
  ATTESTED_PASSKEY_REQUIRED: {
    es: "La política exige una llave de acceso verificada por la organización.",
    en: "Policy requires an organization-verified passkey.",
    fr: "La politique exige une clé d’accès vérifiée par l’organisation.",
  },
  DEVICE_BOUND_PASSKEY_REQUIRED: {
    es: "La política exige una llave vinculada a este dispositivo.",
    en: "Policy requires a passkey bound to this device.",
    fr: "La politique exige une clé d’accès liée à cet appareil.",
  },
};

export function localizedApiError(error: unknown, locale: Locale, fallbackKey: MessageKey = "error.generic"): string {
  if (!(error instanceof ApiError)) return message(locale, fallbackKey);
  if (error.code === "PASSKEY_CEREMONY_CANCELLED") {
    return {
      es: "La confirmación con llave de acceso fue cancelada. No se realizó ningún cambio.",
      en: "Passkey confirmation was cancelled. No changes were made.",
      fr: "La confirmation par clé d’accès a été annulée. Aucun changement n’a été effectué.",
    }[locale];
  }
  const identitySecurityMessage = identitySecurityErrors[error.code]?.[locale];
  if (identitySecurityMessage) {
    return error.requestId
      ? `${identitySecurityMessage} (${message(locale, "audit.correlationId", { id: error.requestId })})`
      : identitySecurityMessage;
  }
  const key = apiCodeKeys[error.code]
    ?? (error.status === 401 ? "error.unauthenticated"
      : error.status === 429 ? "auth.tooManyAttempts"
      : error.status === 403 ? "error.forbidden"
        : error.status === 404 ? "error.notFound"
          : error.status === 409 ? "error.versionConflict"
            : error.status === 422 || error.status === 400 ? "error.validation"
              : error.status >= 500 ? "error.transient"
                : fallbackKey);
  const base = message(locale, key);
  return error.requestId ? `${base} (${message(locale, "audit.correlationId", { id: error.requestId })})` : base;
}

export function localizedSignInError(error: ApiError, locale: Locale): string {
  const key = error.status === 429
    ? "auth.tooManyAttempts"
    : error.status === 408 || error.status >= 500
      ? "error.transient"
      : error.status === 401
        ? "auth.invalidCredentials"
        : undefined;

  if (!key) return localizedApiError(error, locale, "auth.invalidCredentials");
  const base = message(locale, key);
  return error.requestId ? `${base} (${message(locale, "audit.correlationId", { id: error.requestId })})` : base;
}
