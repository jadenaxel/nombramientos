"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  Fingerprint,
  KeyRound,
  Laptop,
  LoaderCircle,
  MonitorSmartphone,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Trash2,
} from "lucide-react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  ApiError,
  setCsrfToken,
  type AuthenticatedSession,
  type AuthSessionSummary,
  type EnterpriseIdentityPolicy,
  type IdentityPolicyState,
  type IdentityPolicyValues,
  type Locale,
  type PasskeyCredentialSummary,
} from "@/lib/api";
import { appLandingPath } from "@/lib/app-navigation";
import { localizedApiError } from "@/lib/product-i18n";
import {
  cancelPasskeyCeremony,
  detectPasskeyCapability,
  isPasskeyCancellation,
  isPasskeyUnsupported,
  registerPasskey,
  type PasskeyCapability,
} from "@/lib/webauthn";
import { useVault } from "@/app/providers";
import { MfaEnrollmentPanel } from "./mfa-enrollment";

const copy = {
  es: {
    eyebrow: "Identidad y acceso", title: "Centro de seguridad", description: "Administra métodos de acceso resistentes al phishing y controla dónde permanece abierta tu cuenta.",
    requiredTitle: "Protege tu cuenta antes de continuar", requiredBody: "Crea una llave de acceso en este dispositivo. Tu huella, rostro o PIN nunca salen del equipo.",
    protected: "Protección avanzada", needsPasskey: "Mejora recomendada", recovery: "Recuperación restringida", recoveryBody: "Esta sesión solo puede reparar tus métodos de acceso. El contenido y las operaciones permanecen bloqueados.",
    create: "Crear llave de acceso", createHere: "Crear en este dispositivo", creating: "Esperando confirmación del dispositivo…", cancelled: "No se creó ninguna llave. Puedes intentarlo de nuevo cuando estés listo.",
    unsupported: "Este navegador no admite llaves de acceso. Usa un navegador actualizado o configura el autenticador como alternativa.", invalidOrigin: "Las llaves de acceso locales requieren localhost como dominio confiable.", openCanonical: "Abrir esta página en localhost",
    passkeyHelp: "En celular usa Face ID, huella o PIN sin escanear un QR. En PC usa Windows Hello, Touch ID o tu administrador de llaves.",
    crossDevice: "¿Tu llave está en otro dispositivo? El navegador puede ofrecer un QR temporal y proximidad Bluetooth; ese QR nunca contiene tu secreto TOTP.",
    name: "Nombre reconocible", defaultName: "Este dispositivo", nameHelp: "Ejemplo: iPhone personal o Portátil de oficina", added: "Llave de acceso creada correctamente.", replacement: "Reemplazar una llave existente", replacementNone: "Agregar sin reemplazar", replacementHelp: "La llave anterior seguirá activa y sus sesiones no cambiarán hasta que la nueva quede verificada. Si el registro falla o se cancela, no se revocará nada.", replacementRequired: "Alcanzaste el máximo de llaves. Selecciona cuál reemplazar para continuar.", replaceHere: "Registrar reemplazo seguro",
    passkeys: "Tus llaves de acceso", passkeysBody: "Registra al menos dos métodos en dispositivos distintos para evitar bloqueos.", none: "Aún no hay llaves registradas.",
    lastUsed: "Último uso", created: "Creada", synced: "Sincronizada", deviceBound: "Vinculada al dispositivo", never: "Nunca", rename: "Renombrar", save: "Guardar", revoke: "Revocar",
    revokeKeyTitle: "¿Revocar esta llave de acceso?", revokeKeyBody: "Dejará de funcionar de inmediato. Para protegerte, confirmarás la acción con otra llave.",
    sessions: "Sesiones activas", sessionsBody: "Revisa dispositivos y cierra cualquier acceso que no reconozcas.", current: "Esta sesión", other: "Otra sesión", unknownDevice: "Dispositivo no identificado", lastSeen: "Actividad", expires: "Expira", signOut: "Cerrar sesión", revokeOthers: "Cerrar las demás sesiones",
    riskTitle: "Verificación adicional de sesión", riskBody: "Cambió el navegador o la red de esta sesión. Las operaciones sensibles pedirán una confirmación con tu llave de acceso y, al validarla, reconocerán el contexto actual.", riskBadge: "Contexto cambiado", riskEvidence: "Cambio detectado", riskBrowser: "Navegador o dispositivo", riskNetwork: "Red de conexión", riskBoth: "Navegador/dispositivo y red",
    revokeSessionTitle: "¿Cerrar esta sesión?", revokeSessionBody: "La cuenta se cerrará en ese dispositivo. Esta acción requiere confirmación resistente al phishing.",
    revokeOthersTitle: "¿Cerrar todas las demás sesiones?", revokeOthersBody: "Conservarás únicamente esta sesión. Confirma con tu llave de acceso.",
    cancel: "Cancelar", confirm: "Confirmar de forma segura", working: "Confirmando identidad…", updated: "Configuración de seguridad actualizada.", reauthenticate: "Volver a iniciar sesión con MFA",
    fallback: "Método alternativo", fallbackTitle: "Aplicación autenticadora (TOTP)", fallbackBody: "Consérvala como respaldo. Las llaves de acceso son el método principal y resistente al phishing.",
    loadError: "No fue posible cargar el estado de seguridad.", retry: "Reintentar", platform: "Autenticador del dispositivo disponible", roaming: "También puedes usar una llave física o un teléfono cercano.",
    policyEyebrow: "Despliegue de garantía", policyTitle: "Política de identidad", policyMonitor: "Monitoreo", policyEnforce: "Aplicación activa", policyMonitorBody: "Evalúa las metas de AAL, cantidad de llaves y autenticadores privilegiados antes de activarlas. La disponibilidad de métodos, los límites de sesión y la verificación criptográfica permanecen activos.", policyEnforceBody: "Aplica las metas de garantía y los requisitos privilegiados. La disponibilidad de métodos, los límites de sesión y la verificación criptográfica siempre permanecen activos.", policyCompliant: "Esta sesión cumple la meta general", policyNotCompliant: "Esta sesión aún no cumple la meta general", privilegedReady: "Lista para operaciones privilegiadas", privilegedNotReady: "Requiere refuerzo para operaciones privilegiadas", editPolicy: "Editar política de la organización", savePolicy: "Guardar política", policySaved: "Política actualizada y verificada", policyInvalid: "Revisa los límites: AAL privilegiado no puede ser menor, las cantidades mínimas no pueden superar el máximo y el tiempo inactivo no puede superar la duración absoluta.", policyUnsupportedEnforcement: "AAL3 y la atestación administrada permanecen disponibles como metas de monitoreo, pero requieren un servicio externo de confianza FIDO antes de activar su aplicación.", generalAal: "AAL mínimo general", privilegedAal: "AAL mínimo privilegiado", minimumPasskeys: "Llaves mínimas", privilegedPasskeys: "Llaves mínimas privilegiadas", maximumPasskeys: "Máximo de llaves", activePasskeys: "Llaves activas", methodControls: "Métodos permitidos", passwordAllowed: "Contraseña", totpAllowed: "TOTP de respaldo", recoveryAllowed: "Códigos de recuperación", syncedAllowed: "Llaves sincronizadas", privilegedControls: "Controles privilegiados", phishingRequired: "Resistencia al phishing", deviceBoundRequired: "Llave vinculada al dispositivo", attestationRequired: "Atestación administrada", userVerificationRequired: "Verificación local del usuario (PIN, rostro o huella)", sessionControls: "Límites de sesión", maximumSessions: "Sesiones activas máximas", idleMinutes: "Inactividad (minutos)", absoluteMinutes: "Duración absoluta (minutos)", stepUpSeconds: "Vigencia de confirmación (segundos)", actionControls: "Matriz de operaciones protegidas", actionMinAal: "AAL mínimo", actionPhishing: "Antiphishing", actionStepUp: "Confirmación por operación", policySafetyNotice: "Los cambios se validan contra todos los usuarios activos y se rechazan de forma atómica si pueden provocar un bloqueo. Las sesiones existentes se ajustan inmediatamente.", noFindings: "Sin brechas de garantía para esta sesión.", findings: "Brechas detectadas", policyReadOnly: "Solo quienes administran la configuración de la organización pueden modificar esta política.",
  },
  en: {
    eyebrow: "Identity and access", title: "Security center", description: "Manage phishing-resistant sign-in methods and control where your account remains signed in.",
    requiredTitle: "Protect your account before continuing", requiredBody: "Create a passkey on this device. Your fingerprint, face, or PIN never leaves it.",
    protected: "Advanced protection", needsPasskey: "Upgrade recommended", recovery: "Restricted recovery", recoveryBody: "This session can only repair your sign-in methods. Content and operations remain blocked.",
    create: "Create a passkey", createHere: "Create on this device", creating: "Waiting for device confirmation…", cancelled: "No passkey was created. You can try again whenever you are ready.",
    unsupported: "This browser does not support passkeys. Use an up-to-date browser or configure the authenticator fallback.", invalidOrigin: "Local passkeys require localhost as the trusted domain.", openCanonical: "Open this page on localhost",
    passkeyHelp: "On a phone, use Face ID, fingerprint, or PIN without scanning a QR. On a computer, use Windows Hello, Touch ID, or your passkey manager.",
    crossDevice: "Is your passkey on another device? The browser may offer a temporary QR and Bluetooth proximity; that QR never contains your TOTP secret.",
    name: "Recognizable name", defaultName: "This device", nameHelp: "Example: Personal iPhone or Office laptop", added: "Passkey created successfully.", replacement: "Replace an existing passkey", replacementNone: "Add without replacing", replacementHelp: "The previous passkey stays active and its sessions remain unchanged until the new one is verified. If registration fails or is cancelled, nothing is revoked.", replacementRequired: "You have reached the passkey limit. Select the passkey to replace before continuing.", replaceHere: "Register secure replacement",
    passkeys: "Your passkeys", passkeysBody: "Register at least two methods on separate devices to prevent lockout.", none: "No passkeys are registered yet.",
    lastUsed: "Last used", created: "Created", synced: "Synced", deviceBound: "Device-bound", never: "Never", rename: "Rename", save: "Save", revoke: "Revoke",
    revokeKeyTitle: "Revoke this passkey?", revokeKeyBody: "It will stop working immediately. To protect you, the action is confirmed with another passkey.",
    sessions: "Active sessions", sessionsBody: "Review devices and close any access you do not recognize.", current: "This session", other: "Other session", unknownDevice: "Unidentified device", lastSeen: "Activity", expires: "Expires", signOut: "Sign out", revokeOthers: "Close other sessions",
    riskTitle: "Additional session verification", riskBody: "This session's browser or network changed. Sensitive operations will request passkey confirmation and recognize the current context after it is verified.", riskBadge: "Context changed", riskEvidence: "Detected change", riskBrowser: "Browser or device", riskNetwork: "Connection network", riskBoth: "Browser/device and network",
    revokeSessionTitle: "Close this session?", revokeSessionBody: "The account will be signed out on that device. This action requires phishing-resistant confirmation.",
    revokeOthersTitle: "Close all other sessions?", revokeOthersBody: "Only this session will remain. Confirm with your passkey.",
    cancel: "Cancel", confirm: "Confirm securely", working: "Confirming identity…", updated: "Security settings updated.", reauthenticate: "Sign in again with MFA",
    fallback: "Fallback method", fallbackTitle: "Authenticator app (TOTP)", fallbackBody: "Keep it as a backup. Passkeys are the primary phishing-resistant method.",
    loadError: "Security status could not be loaded.", retry: "Try again", platform: "Device authenticator available", roaming: "You can also use a physical key or a nearby phone.",
    policyEyebrow: "Assurance rollout", policyTitle: "Identity policy", policyMonitor: "Monitor", policyEnforce: "Enforced", policyMonitorBody: "Evaluates AAL, passkey-count, and privileged-authenticator targets before activating them. Method availability, session limits, and cryptographic verification remain active.", policyEnforceBody: "Applies assurance targets and privileged requirements. Method availability, session limits, and cryptographic verification always remain active.", policyCompliant: "This session meets the general target", policyNotCompliant: "This session does not yet meet the general target", privilegedReady: "Ready for privileged operations", privilegedNotReady: "Hardening required for privileged operations", editPolicy: "Edit organization policy", savePolicy: "Save policy", policySaved: "Policy updated and verified", policyInvalid: "Review the limits: privileged AAL cannot be lower, minimum counts cannot exceed the maximum, and idle time cannot exceed absolute lifetime.", policyUnsupportedEnforcement: "AAL3 and managed attestation remain available as monitor targets, but require an external FIDO trust service before enforcement can be activated.", generalAal: "General minimum AAL", privilegedAal: "Privileged minimum AAL", minimumPasskeys: "Minimum passkeys", privilegedPasskeys: "Privileged minimum passkeys", maximumPasskeys: "Maximum passkeys", activePasskeys: "Active passkeys", methodControls: "Allowed methods", passwordAllowed: "Password", totpAllowed: "Fallback TOTP", recoveryAllowed: "Recovery codes", syncedAllowed: "Synced passkeys", privilegedControls: "Privileged controls", phishingRequired: "Phishing resistance", deviceBoundRequired: "Device-bound passkey", attestationRequired: "Managed attestation", userVerificationRequired: "Local user verification (PIN, face, or fingerprint)", sessionControls: "Session limits", maximumSessions: "Maximum active sessions", idleMinutes: "Idle time (minutes)", absoluteMinutes: "Absolute lifetime (minutes)", stepUpSeconds: "Confirmation lifetime (seconds)", actionControls: "Protected-operation matrix", actionMinAal: "Minimum AAL", actionPhishing: "Phishing-resistant", actionStepUp: "Per-operation confirmation", policySafetyNotice: "Changes are validated against every active user and rejected atomically if they could cause lockout. Existing sessions are reconciled immediately.", noFindings: "No assurance gaps for this session.", findings: "Detected gaps", policyReadOnly: "Only organization settings administrators can change this policy.",
  },
  fr: {
    eyebrow: "Identité et accès", title: "Centre de sécurité", description: "Gérez les méthodes résistantes à l’hameçonnage et contrôlez les appareils connectés.",
    requiredTitle: "Protégez votre compte avant de continuer", requiredBody: "Créez une clé d’accès sur cet appareil. Votre empreinte, visage ou NIP ne le quitte jamais.",
    protected: "Protection avancée", needsPasskey: "Amélioration recommandée", recovery: "Récupération restreinte", recoveryBody: "Cette session peut uniquement réparer vos méthodes d’accès. Le contenu et les opérations restent bloqués.",
    create: "Créer une clé d’accès", createHere: "Créer sur cet appareil", creating: "En attente de la confirmation de l’appareil…", cancelled: "Aucune clé n’a été créée. Vous pouvez réessayer quand vous le souhaitez.",
    unsupported: "Ce navigateur ne prend pas en charge les clés d’accès. Utilisez un navigateur récent ou configurez l’authentificateur de secours.", invalidOrigin: "Les clés d’accès locales exigent localhost comme domaine de confiance.", openCanonical: "Ouvrir cette page sur localhost",
    passkeyHelp: "Sur mobile, utilisez Face ID, l’empreinte ou le NIP sans scanner de QR. Sur ordinateur, utilisez Windows Hello, Touch ID ou votre gestionnaire de clés.",
    crossDevice: "Votre clé se trouve sur un autre appareil ? Le navigateur peut proposer un QR temporaire et la proximité Bluetooth ; ce QR ne contient jamais votre secret TOTP.",
    name: "Nom reconnaissable", defaultName: "Cet appareil", nameHelp: "Exemple : iPhone personnel ou Portable du bureau", added: "Clé d’accès créée avec succès.", replacement: "Remplacer une clé existante", replacementNone: "Ajouter sans remplacer", replacementHelp: "L’ancienne clé et ses sessions restent actives jusqu’à la vérification de la nouvelle. Si l’inscription échoue ou est annulée, rien n’est révoqué.", replacementRequired: "Vous avez atteint la limite de clés. Sélectionnez la clé à remplacer pour continuer.", replaceHere: "Enregistrer le remplacement sécurisé",
    passkeys: "Vos clés d’accès", passkeysBody: "Enregistrez au moins deux méthodes sur des appareils distincts pour éviter le blocage.", none: "Aucune clé d’accès n’est encore enregistrée.",
    lastUsed: "Dernière utilisation", created: "Créée", synced: "Synchronisée", deviceBound: "Liée à l’appareil", never: "Jamais", rename: "Renommer", save: "Enregistrer", revoke: "Révoquer",
    revokeKeyTitle: "Révoquer cette clé d’accès ?", revokeKeyBody: "Elle cessera de fonctionner immédiatement. Pour votre protection, confirmez avec une autre clé.",
    sessions: "Sessions actives", sessionsBody: "Vérifiez les appareils et fermez tout accès inconnu.", current: "Cette session", other: "Autre session", unknownDevice: "Appareil non identifié", lastSeen: "Activité", expires: "Expire", signOut: "Fermer la session", revokeOthers: "Fermer les autres sessions",
    riskTitle: "Vérification supplémentaire de la session", riskBody: "Le navigateur ou le réseau de cette session a changé. Les opérations sensibles demanderont une confirmation avec votre clé d’accès, puis reconnaîtront le contexte validé.", riskBadge: "Contexte modifié", riskEvidence: "Changement détecté", riskBrowser: "Navigateur ou appareil", riskNetwork: "Réseau de connexion", riskBoth: "Navigateur/appareil et réseau",
    revokeSessionTitle: "Fermer cette session ?", revokeSessionBody: "Le compte sera déconnecté sur cet appareil. Cette action exige une confirmation résistante à l’hameçonnage.",
    revokeOthersTitle: "Fermer toutes les autres sessions ?", revokeOthersBody: "Seule cette session restera ouverte. Confirmez avec votre clé d’accès.",
    cancel: "Annuler", confirm: "Confirmer en sécurité", working: "Confirmation de l’identité…", updated: "Configuration de sécurité mise à jour.", reauthenticate: "Se reconnecter avec l’AMF",
    fallback: "Méthode de secours", fallbackTitle: "Application d’authentification (TOTP)", fallbackBody: "Conservez-la en secours. Les clés d’accès sont la méthode principale résistante à l’hameçonnage.",
    loadError: "Impossible de charger l’état de sécurité.", retry: "Réessayer", platform: "Authentificateur de l’appareil disponible", roaming: "Vous pouvez aussi utiliser une clé physique ou un téléphone à proximité.",
    policyEyebrow: "Déploiement de l’assurance", policyTitle: "Politique d’identité", policyMonitor: "Surveillance", policyEnforce: "Application active", policyMonitorBody: "Évalue les objectifs AAL, le nombre de clés et les authentificateurs privilégiés avant leur activation. La disponibilité des méthodes, les limites de session et la vérification cryptographique restent actives.", policyEnforceBody: "Applique les objectifs d’assurance et les exigences privilégiées. La disponibilité des méthodes, les limites de session et la vérification cryptographique restent toujours actives.", policyCompliant: "Cette session atteint l’objectif général", policyNotCompliant: "Cette session n’atteint pas encore l’objectif général", privilegedReady: "Prête pour les opérations privilégiées", privilegedNotReady: "Renforcement requis pour les opérations privilégiées", editPolicy: "Modifier la politique de l’organisation", savePolicy: "Enregistrer la politique", policySaved: "Politique mise à jour et vérifiée", policyInvalid: "Vérifiez les limites : l’AAL privilégié ne peut pas être inférieur, les minimums ne peuvent pas dépasser le maximum et l’inactivité ne peut pas dépasser la durée absolue.", policyUnsupportedEnforcement: "L’AAL3 et l’attestation administrée restent disponibles comme objectifs de surveillance, mais exigent un service de confiance FIDO externe avant l’activation de leur application.", generalAal: "AAL général minimum", privilegedAal: "AAL privilégié minimum", minimumPasskeys: "Clés minimales", privilegedPasskeys: "Clés privilégiées minimales", maximumPasskeys: "Maximum de clés", activePasskeys: "Clés actives", methodControls: "Méthodes autorisées", passwordAllowed: "Mot de passe", totpAllowed: "TOTP de secours", recoveryAllowed: "Codes de récupération", syncedAllowed: "Clés synchronisées", privilegedControls: "Contrôles privilégiés", phishingRequired: "Résistance à l’hameçonnage", deviceBoundRequired: "Clé liée à l’appareil", attestationRequired: "Attestation administrée", userVerificationRequired: "Vérification locale (NIP, visage ou empreinte)", sessionControls: "Limites de session", maximumSessions: "Sessions actives maximales", idleMinutes: "Inactivité (minutes)", absoluteMinutes: "Durée absolue (minutes)", stepUpSeconds: "Durée de confirmation (secondes)", actionControls: "Matrice des opérations protégées", actionMinAal: "AAL minimum", actionPhishing: "Résistant à l’hameçonnage", actionStepUp: "Confirmation par opération", policySafetyNotice: "Les changements sont validés pour chaque utilisateur actif et rejetés atomiquement s’ils risquent de bloquer l’accès. Les sessions existantes sont ajustées immédiatement.", noFindings: "Aucun écart d’assurance pour cette session.", findings: "Écarts détectés", policyReadOnly: "Seuls les administrateurs des paramètres de l’organisation peuvent modifier cette politique.",
  },
} as const;

function formatDate(value: string | null | undefined, locale: Locale, fallback: string): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return fallback;
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function isRecoveryRestricted(session: AuthenticatedSession): boolean {
  return session.security.recoveryRestricted === true || session.security.assurance === "recovery_limited";
}

function credentialIcon(credential: PasskeyCredentialSummary) {
  return credential.attachment === "platform" ? Smartphone : KeyRound;
}

function riskContextLabel(
  risk: Readonly<{ userAgentContextChanged: boolean | null; ipContextChanged: boolean }>,
  labels: Readonly<{ riskBrowser: string; riskNetwork: string; riskBoth: string }>,
): string {
  if (risk.userAgentContextChanged && risk.ipContextChanged) return labels.riskBoth;
  if (risk.userAgentContextChanged) return labels.riskBrowser;
  return labels.riskNetwork;
}

const policyFindingCopy: Readonly<Record<string, Readonly<Record<Locale, string>>>> = {
  session_aal_below_minimum: {
    es: "La sesión actual está por debajo del AAL general.",
    en: "The current session is below the general AAL target.",
    fr: "La session actuelle est sous l’objectif AAL général.",
  },
  passkey_count_below_minimum: {
    es: "Faltan llaves de acceso para la meta general.",
    en: "More passkeys are needed for the general target.",
    fr: "D’autres clés d’accès sont nécessaires pour l’objectif général.",
  },
  session_aal_below_privileged_minimum: {
    es: "La sesión actual está por debajo del AAL privilegiado.",
    en: "The current session is below the privileged AAL target.",
    fr: "La session actuelle est sous l’objectif AAL privilégié.",
  },
  passkey_count_below_privileged_minimum: {
    es: "Faltan llaves de acceso para operaciones privilegiadas.",
    en: "More passkeys are needed for privileged operations.",
    fr: "D’autres clés d’accès sont nécessaires pour les opérations privilégiées.",
  },
  phishing_resistant_step_up_required: {
    es: "Las operaciones privilegiadas requieren confirmar con una llave de acceso.",
    en: "Privileged operations require passkey confirmation.",
    fr: "Les opérations privilégiées exigent une confirmation par clé d’accès.",
  },
};

function policyValues(policy: EnterpriseIdentityPolicy): IdentityPolicyValues {
  return {
    enforcementMode: policy.enforcementMode,
    minimumAal: policy.minimumAal,
    privilegedMinimumAal: policy.privilegedMinimumAal,
    requireUserVerification: policy.requireUserVerification,
    requirePhishingResistantForPrivileged: policy.requirePhishingResistantForPrivileged,
    requireDeviceBoundForPrivileged: policy.requireDeviceBoundForPrivileged,
    requireAttestationForPrivileged: policy.requireAttestationForPrivileged,
    allowPassword: policy.allowPassword,
    allowTotpFallback: policy.allowTotpFallback,
    allowRecoveryCodes: policy.allowRecoveryCodes,
    allowSyncedPasskeys: policy.allowSyncedPasskeys,
    minimumPasskeyCount: policy.minimumPasskeyCount,
    privilegedMinimumPasskeyCount: policy.privilegedMinimumPasskeyCount,
    maximumPasskeys: policy.maximumPasskeys,
    maximumActiveSessions: policy.maximumActiveSessions,
    idleTimeoutMinutes: policy.idleTimeoutMinutes,
    absoluteSessionMinutes: policy.absoluteSessionMinutes,
    stepUpTtlSeconds: policy.stepUpTtlSeconds,
    actionRequirements: policy.actionRequirements,
  };
}

function validPolicy(policy: EnterpriseIdentityPolicy): boolean {
  return policy.privilegedMinimumAal >= policy.minimumAal
    && Number.isInteger(policy.minimumPasskeyCount)
    && policy.minimumPasskeyCount >= 0
    && policy.minimumPasskeyCount <= policy.maximumPasskeys
    && Number.isInteger(policy.privilegedMinimumPasskeyCount)
    && policy.privilegedMinimumPasskeyCount >= 1
    && policy.privilegedMinimumPasskeyCount >= policy.minimumPasskeyCount
    && policy.privilegedMinimumPasskeyCount <= policy.maximumPasskeys
    && Number.isInteger(policy.maximumPasskeys)
    && policy.maximumPasskeys >= 1
    && policy.maximumPasskeys <= 20
    && Number.isInteger(policy.maximumActiveSessions)
    && policy.maximumActiveSessions >= 1
    && policy.maximumActiveSessions <= 100
    && Number.isInteger(policy.idleTimeoutMinutes)
    && policy.idleTimeoutMinutes >= 5
    && policy.idleTimeoutMinutes <= 1_440
    && Number.isInteger(policy.absoluteSessionMinutes)
    && policy.absoluteSessionMinutes >= 5
    && policy.absoluteSessionMinutes <= 10_080
    && policy.idleTimeoutMinutes <= policy.absoluteSessionMinutes
    && Number.isInteger(policy.stepUpTtlSeconds)
    && policy.stepUpTtlSeconds >= 60
    && policy.stepUpTtlSeconds <= 900;
}

function IdentityPolicyCard({
  locale,
  state,
  canManage,
  refresh,
}: {
  locale: Locale;
  state: IdentityPolicyState;
  canManage: boolean;
  refresh: () => Promise<void>;
}) {
  const text = copy[locale];
  const [draft, setDraft] = useState<EnterpriseIdentityPolicy>(state.policy);
  const [saved, setSaved] = useState(false);
  const [policyError, setPolicyError] = useState<string>();
  const update = useMutation({
    mutationFn: () => api.updateIdentityPolicy(draft.tenantVersion ?? 0, policyValues(draft)),
    onSuccess: async (updated) => {
      setDraft(updated);
      setPolicyError(undefined);
      setSaved(true);
      await refresh();
    },
    onError: (caught) => {
      setSaved(false);
      setPolicyError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError);
    },
  });
  const structurallyValid = validPolicy(draft);
  const unsupportedEnforcement = draft.enforcementMode === "enforce" && (
    draft.minimumAal > 2
    || draft.privilegedMinimumAal > 2
    || draft.requireAttestationForPrivileged
    || Object.values(draft.actionRequirements).some((requirement) => requirement.minAal > 2)
  );
  const isValid = structurallyValid && !unsupportedEnforcement;
  const unchanged = JSON.stringify(policyValues(draft)) === JSON.stringify(policyValues(state.policy));

  const setNumber = <K extends "minimumAal" | "privilegedMinimumAal" | "minimumPasskeyCount" | "privilegedMinimumPasskeyCount" | "maximumPasskeys" | "maximumActiveSessions" | "idleTimeoutMinutes" | "absoluteSessionMinutes" | "stepUpTtlSeconds",>(
    key: K,
    value: number,
  ) => setDraft((current) => ({ ...current, [key]: value }));
  const setFlag = <K extends "requireDeviceBoundForPrivileged" | "requireAttestationForPrivileged" | "allowPassword" | "allowTotpFallback" | "allowRecoveryCodes" | "allowSyncedPasskeys",>(
    key: K,
    value: boolean,
  ) => setDraft((current) => ({ ...current, [key]: value }));

  return <section className="surface-card identity-policy-card" aria-labelledby="identity-policy-title">
    <div className="card-heading">
      <div><p className="eyebrow">{text.policyEyebrow}</p><h2 id="identity-policy-title">{text.policyTitle}</h2></div>
      <Badge className={state.policy.enforcementMode === "enforce" ? "security-badge-strong" : ""} variant="outline">{state.policy.enforcementMode === "enforce" ? text.policyEnforce : text.policyMonitor}</Badge>
    </div>
    <p className="identity-policy-explainer">{state.policy.enforcementMode === "enforce" ? text.policyEnforceBody : text.policyMonitorBody}</p>
    <div className="identity-policy-posture">
      <span className={state.compliance.sessionMeetsMinimum ? "is-ready" : ""}>{state.compliance.sessionMeetsMinimum ? <CheckCircle2 /> : <ShieldAlert />}<strong>{state.compliance.sessionMeetsMinimum ? text.policyCompliant : text.policyNotCompliant}</strong></span>
      <span className={state.compliance.privilegedSessionReady ? "is-ready" : ""}>{state.compliance.privilegedSessionReady ? <CheckCircle2 /> : <ShieldAlert />}<strong>{state.compliance.privilegedSessionReady ? text.privilegedReady : text.privilegedNotReady}</strong></span>
      <span><KeyRound /><strong>{text.activePasskeys}: {state.compliance.activePasskeys} / {state.compliance.minimumPasskeys}</strong></span>
    </div>
    <div className="identity-policy-summary" aria-label={text.sessionControls}>
      <span><small>{text.methodControls}</small><strong>{[state.policy.allowPassword && text.passwordAllowed, state.policy.allowTotpFallback && text.totpAllowed, state.policy.allowRecoveryCodes && text.recoveryAllowed, state.policy.allowSyncedPasskeys && text.syncedAllowed].filter(Boolean).join(" · ")}</strong></span>
      <span><small>{text.sessionControls}</small><strong>{text.maximumSessions}: {state.policy.maximumActiveSessions} · {text.idleMinutes}: {state.policy.idleTimeoutMinutes} · {text.absoluteMinutes}: {state.policy.absoluteSessionMinutes}</strong></span>
    </div>
    <div className="identity-policy-findings">
      <strong>{state.compliance.findings.length ? text.findings : text.noFindings}</strong>
      {state.compliance.findings.length > 0 && <ul>{state.compliance.findings.map((finding) => <li key={finding}>{policyFindingCopy[finding]?.[locale] ?? text.policyNotCompliant}</li>)}</ul>}
    </div>
    {canManage ? <details className="identity-policy-editor">
      <summary><Pencil />{text.editPolicy}</summary>
      <div className="identity-policy-form">
        <label><span>{text.policyEyebrow}</span><select value={draft.enforcementMode} onChange={(event) => { setSaved(false); setDraft((current) => ({ ...current, enforcementMode: event.target.value as "monitor" | "enforce" })); }}><option value="monitor">{text.policyMonitor}</option><option value="enforce">{text.policyEnforce}</option></select></label>
        <label><span>{text.generalAal}</span><select value={draft.minimumAal} onChange={(event) => { setSaved(false); setNumber("minimumAal", Number(event.target.value) as 1 | 2 | 3); }}><option value={1}>AAL1</option><option value={2}>AAL2</option><option value={3}>AAL3</option></select></label>
        <label><span>{text.privilegedAal}</span><select value={draft.privilegedMinimumAal} onChange={(event) => { setSaved(false); setNumber("privilegedMinimumAal", Number(event.target.value) as 2 | 3); }}><option value={2}>AAL2</option><option value={3}>AAL3</option></select></label>
        <label><span>{text.minimumPasskeys}</span><Input type="number" min={0} max={10} value={draft.minimumPasskeyCount} onChange={(event) => { setSaved(false); setNumber("minimumPasskeyCount", Number(event.target.value)); }} /></label>
        <label><span>{text.privilegedPasskeys}</span><Input type="number" min={1} max={10} value={draft.privilegedMinimumPasskeyCount} onChange={(event) => { setSaved(false); setNumber("privilegedMinimumPasskeyCount", Number(event.target.value)); }} /></label>
        <label><span>{text.maximumPasskeys}</span><Input type="number" min={1} max={20} value={draft.maximumPasskeys} onChange={(event) => { setSaved(false); setNumber("maximumPasskeys", Number(event.target.value)); }} /></label>
        <fieldset className="identity-policy-toggles"><legend>{text.methodControls}</legend>
          {([
            ["allowPassword", text.passwordAllowed],
            ["allowTotpFallback", text.totpAllowed],
            ["allowRecoveryCodes", text.recoveryAllowed],
            ["allowSyncedPasskeys", text.syncedAllowed],
          ] as const).map(([key, label]) => <label key={key}><input type="checkbox" checked={draft[key]} onChange={(event) => { setSaved(false); setFlag(key, event.target.checked); }} /><span>{label}</span></label>)}
        </fieldset>
        <fieldset className="identity-policy-toggles"><legend>{text.privilegedControls}</legend>
          <label aria-disabled="true"><input type="checkbox" checked={draft.requireUserVerification} disabled /><span>{text.userVerificationRequired}</span></label>
          <label aria-disabled="true"><input type="checkbox" checked={draft.requirePhishingResistantForPrivileged} disabled /><span>{text.phishingRequired}</span></label>
          {([
            ["requireDeviceBoundForPrivileged", text.deviceBoundRequired],
            ["requireAttestationForPrivileged", text.attestationRequired],
          ] as const).map(([key, label]) => <label key={key}><input type="checkbox" checked={draft[key]} onChange={(event) => { setSaved(false); setFlag(key, event.target.checked); }} /><span>{label}</span></label>)}
        </fieldset>
        <fieldset className="identity-policy-session-grid"><legend>{text.sessionControls}</legend>
          <label><span>{text.maximumSessions}</span><Input type="number" min={1} max={100} value={draft.maximumActiveSessions} onChange={(event) => { setSaved(false); setNumber("maximumActiveSessions", Number(event.target.value)); }} /></label>
          <label><span>{text.idleMinutes}</span><Input type="number" min={5} max={1440} value={draft.idleTimeoutMinutes} onChange={(event) => { setSaved(false); setNumber("idleTimeoutMinutes", Number(event.target.value)); }} /></label>
          <label><span>{text.absoluteMinutes}</span><Input type="number" min={5} max={10080} value={draft.absoluteSessionMinutes} onChange={(event) => { setSaved(false); setNumber("absoluteSessionMinutes", Number(event.target.value)); }} /></label>
          <label><span>{text.stepUpSeconds}</span><Input type="number" min={60} max={900} value={draft.stepUpTtlSeconds} onChange={(event) => { setSaved(false); setNumber("stepUpTtlSeconds", Number(event.target.value)); }} /></label>
        </fieldset>
        <div className="identity-policy-actions" aria-label={text.actionControls}>
          <strong>{text.actionControls}</strong>
          {Object.entries(draft.actionRequirements).sort(([left], [right]) => left.localeCompare(right)).map(([action, requirement]) => <div key={action}>
            <code>{action}</code>
            <span>{text.actionMinAal}: AAL{requirement.minAal}</span>
            <span>{text.actionPhishing}: {requirement.phishingResistant ? "✓" : "—"}</span>
            <span>{text.actionStepUp}: {requirement.stepUpRequired ? "✓" : "—"}</span>
          </div>)}
        </div>
        <p className="identity-policy-safety"><ShieldCheck />{text.policySafetyNotice}</p>
      </div>
      {!structurallyValid && <p className="form-error" role="alert">{text.policyInvalid}</p>}
      {unsupportedEnforcement && <p className="form-error" role="alert">{text.policyUnsupportedEnforcement}</p>}
      {policyError && <p className="form-error" role="alert">{policyError}</p>}
      {saved && <p className="security-inline-status success" role="status"><CheckCircle2 />{text.policySaved}</p>}
      <Button type="button" disabled={!isValid || unchanged || update.isPending} onClick={() => update.mutate()}>{update.isPending ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{text.savePolicy}</Button>
    </details> : <p className="identity-policy-readonly"><ShieldCheck />{text.policyReadOnly}</p>}
  </section>;
}

export function SecurityCenter({
  locale,
  session,
  requiredGate = false,
}: {
  locale: Locale;
  session: AuthenticatedSession;
  requiredGate?: boolean;
}) {
  const text = copy[locale];
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const [capability, setCapability] = useState<PasskeyCapability>();
  const [passkeyName, setPasskeyName] = useState<string>(text.defaultName);
  const [replacementCredentialId, setReplacementCredentialId] = useState("");
  const [renames, setRenames] = useState<Record<string, string>>({});
  const [ceremonyState, setCeremonyState] = useState<"idle" | "working" | "cancelled" | "success">("idle");
  const [actionId, setActionId] = useState<string>();
  const [error, setError] = useState<string>();
  const [reauthenticationRequired, setReauthenticationRequired] = useState(false);
  const [totpRecoveryRequested, setTotpRecoveryRequested] = useState(false);

  useEffect(() => {
    let active = true;
    void detectPasskeyCapability().then((value) => { if (active) setCapability(value); });
    return () => {
      active = false;
      cancelPasskeyCeremony();
    };
  }, []);

  useEffect(() => {
    const syncRecoveryDestination = () => setTotpRecoveryRequested(window.location.hash === "#totp-fallback");
    syncRecoveryDestination();
    window.addEventListener("hashchange", syncRecoveryDestination);
    return () => window.removeEventListener("hashchange", syncRecoveryDestination);
  }, []);

  const passkeysQuery = useQuery({
    queryKey: ["security", "passkeys", session.user.id],
    queryFn: api.passkeys,
    retry: false,
    enabled: !requiredGate || isRecoveryRestricted(session),
  });
  const sessionsQuery = useQuery({
    queryKey: ["security", "sessions", session.user.id],
    queryFn: api.authSessions,
    retry: false,
    enabled: !requiredGate,
  });
  const policyQuery = useQuery({
    queryKey: ["security", "identity-policy", session.tenant.id],
    queryFn: api.identityPolicy,
    retry: false,
    enabled: !requiredGate || isRecoveryRestricted(session),
  });
  const passkeys = passkeysQuery.data ?? [];
  const activePasskeys = passkeys.filter((item) => !item.revokedAt);
  const sessions = sessionsQuery.data ?? [];
  const otherSessions = sessions.filter((item) => !item.current && !item.revokedAt);
  const effectivePasskeyCount = Math.max(session.security.passkeyCount ?? 0, activePasskeys.length);
  const passkeyLimitReached = Boolean(policyQuery.data && effectivePasskeyCount >= policyQuery.data.policy.maximumPasskeys);
  const protectedSession = session.security.phishingResistant === true || session.security.authMethod === "passkey";

  async function refreshSecurityState() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["security", "passkeys", session.user.id] }),
      queryClient.invalidateQueries({ queryKey: ["security", "sessions", session.user.id] }),
      queryClient.invalidateQueries({ queryKey: ["security", "identity-policy", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["session"] }),
    ]);
  }

  async function createPasskey() {
    if (!capability?.supported || !passkeyName.trim() || (passkeyLimitReached && !replacementCredentialId)) return;
    setCeremonyState("working");
    setError(undefined);
    setReauthenticationRequired(false);
    try {
      cancelPasskeyCeremony();
      const ceremony = await api.passkeyRegistrationOptions(replacementCredentialId || undefined);
      const response = await registerPasskey(ceremony.options);
      const verified = await api.verifyPasskeyRegistration(ceremony.ceremonyId, response, passkeyName.trim());
      let nextSession = verified.session;
      if (!nextSession || requiredGate || isRecoveryRestricted(session)) {
        nextSession = await api.session();
      }
      if (nextSession) {
        setCsrfToken(nextSession.csrfToken);
        queryClient.setQueryData(["session"], nextSession);
      }
      setCeremonyState("success");
      setPasskeyName(text.defaultName);
      setReplacementCredentialId("");
      await refreshSecurityState();
      if (requiredGate || isRecoveryRestricted(session)) {
        const destinationSession = nextSession ?? session;
        router.replace(appLandingPath(locale, destinationSession.permissions));
        router.refresh();
      }
    } catch (caught) {
      if (isPasskeyCancellation(caught)) {
        setCeremonyState("cancelled");
        return;
      }
      setCeremonyState("idle");
      setReauthenticationRequired(caught instanceof ApiError && caught.code === "PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED");
      setError(isPasskeyUnsupported(caught)
        ? text.unsupported
        : caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError);
    }
  }

  function clearLocalAuthentication() {
    cancelPasskeyCeremony();
    vault.lock();
    setCsrfToken(undefined);
    queryClient.clear();
    router.replace(`/${locale}/auth/sign-in`);
    router.refresh();
  }

  async function reauthenticate() {
    setActionId("reauthenticate");
    try {
      await api.logout();
    } catch {
      // A stale or concurrently revoked server session must never prevent
      // deterministic local credential/cache teardown.
    } finally {
      clearLocalAuthentication();
    }
  }

  const renameMutation = useMutation({
    mutationFn: ({ id, name, expectedVersion }: { id: string; name: string; expectedVersion: number }) => api.renamePasskey(id, name, expectedVersion),
    onSuccess: async (_, variables) => {
      setRenames((current) => { const next = { ...current }; delete next[variables.id]; return next; });
      await refreshSecurityState();
      setCeremonyState("success");
    },
    onError: (caught) => setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError),
  });

  async function revokePasskey(credentialId: string) {
    setActionId(`passkey:${credentialId}`); setError(undefined); setCeremonyState("working");
    try {
      const result = await api.revokePasskey(credentialId, "user_revoked");
      if (result.signedOut) {
        clearLocalAuthentication();
        return;
      }
      await refreshSecurityState();
      setCeremonyState("success");
    } catch (caught) {
      if (isPasskeyCancellation(caught)) setCeremonyState("cancelled");
      else { setCeremonyState("idle"); setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError); }
    } finally { setActionId(undefined); }
  }

  async function revokeSession(target: AuthSessionSummary) {
    setActionId(`session:${target.id}`); setError(undefined); setCeremonyState("working");
    try {
      await api.revokeAuthSession(target.id);
      await refreshSecurityState();
      setCeremonyState("success");
    } catch (caught) {
      if (isPasskeyCancellation(caught)) setCeremonyState("cancelled");
      else { setCeremonyState("idle"); setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError); }
    } finally { setActionId(undefined); }
  }

  async function revokeOtherSessions() {
    setActionId("sessions:others"); setError(undefined); setCeremonyState("working");
    try {
      await api.revokeOtherAuthSessions();
      await refreshSecurityState();
      setCeremonyState("success");
    } catch (caught) {
      if (isPasskeyCancellation(caught)) setCeremonyState("cancelled");
      else { setCeremonyState("idle"); setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.loadError); }
    } finally { setActionId(undefined); }
  }

  const securityLabel = protectedSession || effectivePasskeyCount > 0 ? text.protected : text.needsPasskey;
  const capabilityDescription = useMemo(() => capability?.platform ? text.platform : text.roaming, [capability?.platform, text.platform, text.roaming]);
  const loadingLists = passkeysQuery.isLoading || sessionsQuery.isLoading || policyQuery.isLoading;
  const listError = passkeysQuery.error ?? sessionsQuery.error ?? policyQuery.error;

  return <div className="security-center-stack">
    <section className="security-hero" aria-labelledby="security-center-title">
      <div className="security-hero-copy">
        <p className="eyebrow">{text.eyebrow}</p>
        <h1 id="security-center-title">{requiredGate ? text.requiredTitle : text.title}</h1>
        <p>{requiredGate ? text.requiredBody : text.description}</p>
        <div className="security-assurance-row">
          <Badge className={protectedSession ? "security-badge-strong" : ""} variant="outline"><ShieldCheck />{securityLabel}</Badge>
          {isRecoveryRestricted(session) && <Badge variant="destructive"><ShieldAlert />{text.recovery}</Badge>}
          {capability?.supported && <span><CheckCircle2 />{capabilityDescription}</span>}
        </div>
      </div>
      <span className="security-hero-icon" aria-hidden="true"><Fingerprint /></span>
    </section>

    {isRecoveryRestricted(session) && <Alert className="security-recovery-alert"><ShieldAlert /><AlertTitle>{text.recovery}</AlertTitle><AlertDescription>{text.recoveryBody}</AlertDescription></Alert>}
    {session.security.risk?.elevated && <Alert className="security-risk-alert" role="status"><ShieldAlert /><AlertTitle>{text.riskTitle}</AlertTitle><AlertDescription><p>{text.riskBody}</p><strong>{text.riskEvidence}{locale === "fr" ? " :" : ":"} {riskContextLabel(session.security.risk, text)}</strong></AlertDescription></Alert>}
    {error && <Alert variant="destructive" role="alert"><ShieldAlert /><AlertTitle>{text.loadError}</AlertTitle><AlertDescription><p>{error}</p>{reauthenticationRequired && <Button className="mt-3" type="button" size="sm" variant="outline" disabled={actionId === "reauthenticate"} onClick={() => void reauthenticate()}>{actionId === "reauthenticate" ? <LoaderCircle className="animate-spin" /> : <KeyRound />}{text.reauthenticate}</Button>}</AlertDescription></Alert>}
    <div aria-live="polite" className="sr-only">{ceremonyState === "working" ? text.working : ceremonyState === "cancelled" ? text.cancelled : ceremonyState === "success" ? text.updated : ""}</div>

    <section className="surface-card passkey-onboarding" aria-labelledby="passkey-onboarding-title">
      <div className="card-heading"><div><p className="eyebrow">Passkeys · WebAuthn</p><h2 id="passkey-onboarding-title">{text.create}</h2></div><Badge>{text.createHere}</Badge></div>
      <div className="passkey-onboarding-grid">
        <div className="passkey-primary-flow">
          <span className="passkey-device-orb"><MonitorSmartphone /></span>
          <p>{text.passkeyHelp}</p>
          <div className="field-stack">
            <Label htmlFor="passkey-name">{text.name}</Label>
            <Input id="passkey-name" value={passkeyName} onChange={(event) => setPasskeyName(event.target.value)} maxLength={80} autoComplete="off" disabled={ceremonyState === "working"} aria-describedby="passkey-name-help" />
            <small id="passkey-name-help">{text.nameHelp}</small>
          </div>
          {activePasskeys.length > 0 && <div className="field-stack passkey-replacement-control">
            <Label htmlFor="passkey-replacement">{text.replacement}</Label>
            <select id="passkey-replacement" value={replacementCredentialId} onChange={(event) => setReplacementCredentialId(event.target.value)} disabled={ceremonyState === "working"} aria-describedby="passkey-replacement-help" required={passkeyLimitReached}>
              <option value="" disabled={passkeyLimitReached}>{passkeyLimitReached ? text.replacementRequired : text.replacementNone}</option>
              {activePasskeys.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} · {credential.deviceType === "multiDevice" || credential.backedUp ? text.synced : text.deviceBound}</option>)}
            </select>
            <small id="passkey-replacement-help">{passkeyLimitReached ? `${text.replacementRequired} ${text.replacementHelp}` : text.replacementHelp}</small>
          </div>}
          {!capability?.supported && capability && <Alert><ShieldAlert /><AlertTitle>{text.needsPasskey}</AlertTitle><AlertDescription>{capability.reason === "invalid_origin" ? text.invalidOrigin : text.unsupported}{capability.canonicalUrl && <div className="mt-3"><Button asChild size="sm" variant="outline"><a href={capability.canonicalUrl}>{text.openCanonical}</a></Button></div>}</AlertDescription></Alert>}
          {ceremonyState === "cancelled" && <p className="security-inline-status"><ShieldAlert />{text.cancelled}</p>}
          {ceremonyState === "success" && <p className="security-inline-status success"><CheckCircle2 />{text.added}</p>}
          <Button className="passkey-create-button" type="button" onClick={() => void createPasskey()} disabled={!capability?.supported || !passkeyName.trim() || ceremonyState === "working" || (passkeyLimitReached && !replacementCredentialId)}>
            {ceremonyState === "working" ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{ceremonyState === "working" ? text.creating : replacementCredentialId ? text.replaceHere : text.createHere}
          </Button>
        </div>
        <div className="passkey-device-guidance">
          <article><Smartphone /><div><strong>iOS · Android</strong><p>{text.passkeyHelp}</p></div></article>
          <article><Laptop /><div><strong>Windows · macOS</strong><p>{text.crossDevice}</p></div></article>
        </div>
      </div>
    </section>

    {!requiredGate && policyQuery.data && <IdentityPolicyCard
      key={`${policyQuery.data.policy.baselineVersion}:${policyQuery.data.policy.tenantVersion ?? 0}`}
      locale={locale}
      state={policyQuery.data}
      canManage={session.permissions.includes("tenant.settings.manage")}
      refresh={async () => { await queryClient.invalidateQueries({ queryKey: ["security", "identity-policy", session.tenant.id] }); }}
    />}

    {!requiredGate && <>
      <div className="security-management-grid">
        <section className="surface-card" aria-labelledby="passkey-list-title">
          <div className="card-heading"><div><p className="eyebrow">WebAuthn</p><h2 id="passkey-list-title">{text.passkeys}</h2><p>{text.passkeysBody}</p></div><Badge variant="outline">{effectivePasskeyCount}</Badge></div>
          {passkeysQuery.isLoading ? <p role="status" className="security-loading"><LoaderCircle className="animate-spin" />{text.working}</p> : passkeys.length === 0 ? <p className="security-empty"><KeyRound />{text.none}</p> : <div className="credential-list">
            {passkeys.filter((item) => !item.revokedAt).map((credential) => {
              const Icon = credentialIcon(credential);
              const nextName = renames[credential.id] ?? credential.name;
              const saving = renameMutation.isPending && renameMutation.variables?.id === credential.id;
              return <article key={credential.id}>
                <span className="credential-icon"><Icon /></span>
                <div className="credential-copy"><strong>{credential.name}</strong><span><Badge variant="outline">{credential.deviceType === "multiDevice" || credential.backedUp ? text.synced : text.deviceBound}</Badge></span><small>{text.lastUsed}: {formatDate(credential.lastUsedAt, locale, text.never)}</small><small>{text.created}: {formatDate(credential.createdAt, locale, text.never)}</small></div>
                <form className="credential-actions" onSubmit={(event) => { event.preventDefault(); if (nextName.trim() && nextName.trim() !== credential.name) renameMutation.mutate({ id: credential.id, name: nextName.trim(), expectedVersion: credential.version }); }}>
                  <Label className="sr-only" htmlFor={`passkey-rename-${credential.id}`}>{text.rename}: {credential.name}</Label>
                  <Input id={`passkey-rename-${credential.id}`} value={nextName} onChange={(event) => setRenames((current) => ({ ...current, [credential.id]: event.target.value }))} maxLength={80} />
                  <Button type="submit" size="sm" variant="outline" disabled={saving || !nextName.trim() || nextName.trim() === credential.name}>{saving ? <LoaderCircle className="animate-spin" /> : <Pencil />}{text.save}</Button>
                  <AlertDialog>
                    <AlertDialogTrigger asChild><Button type="button" size="sm" variant="ghost" disabled={actionId === `passkey:${credential.id}`}><Trash2 />{text.revoke}</Button></AlertDialogTrigger>
                    <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{text.revokeKeyTitle}</AlertDialogTitle><AlertDialogDescription>{text.revokeKeyBody}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{text.cancel}</AlertDialogCancel><AlertDialogAction variant="destructive" onClick={() => void revokePasskey(credential.id)}>{text.confirm}</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
                  </AlertDialog>
                </form>
              </article>;
            })}
          </div>}
        </section>

        <section className="surface-card" aria-labelledby="session-list-title">
          <div className="card-heading"><div><p className="eyebrow">Zero trust</p><h2 id="session-list-title">{text.sessions}</h2><p>{text.sessionsBody}</p></div><Button variant="outline" size="sm" type="button" onClick={() => void refreshSecurityState()} aria-label={text.retry}><RefreshCw /></Button></div>
          {sessionsQuery.isLoading ? <p role="status" className="security-loading"><LoaderCircle className="animate-spin" />{text.working}</p> : <div className="auth-session-list">
            {sessions.filter((item) => !item.revokedAt).map((item) => <article key={item.id}>
              <span className="credential-icon"><MonitorSmartphone /></span>
              <div><strong>{item.deviceLabel || text.unknownDevice}</strong><span><Badge className={item.current ? "security-badge-strong" : ""} variant="outline">{item.current ? text.current : text.other}</Badge>{item.phishingResistant && <Badge variant="outline"><ShieldCheck />Passkey</Badge>}{item.risk?.elevated && <Badge variant="destructive"><ShieldAlert />{text.riskBadge}</Badge>}</span>{item.risk?.elevated && <small className="security-risk-detail">{text.riskEvidence}{locale === "fr" ? " :" : ":"} {riskContextLabel(item.risk, text)}</small>}<small>{text.lastSeen}: {formatDate(item.lastSeenAt, locale, text.never)}</small><small>{text.expires}: {formatDate(item.expiresAt, locale, text.never)}</small></div>
              {!item.current && <AlertDialog><AlertDialogTrigger asChild><Button size="sm" type="button" variant="ghost" disabled={actionId === `session:${item.id}`}><Trash2 />{text.signOut}</Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{text.revokeSessionTitle}</AlertDialogTitle><AlertDialogDescription>{text.revokeSessionBody}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{text.cancel}</AlertDialogCancel><AlertDialogAction variant="destructive" onClick={() => void revokeSession(item)}>{text.confirm}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>}
            </article>)}
            {otherSessions.length > 0 && <AlertDialog><AlertDialogTrigger asChild><Button className="mt-4 w-full" type="button" variant="outline" disabled={actionId === "sessions:others"}><ShieldCheck />{text.revokeOthers}</Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{text.revokeOthersTitle}</AlertDialogTitle><AlertDialogDescription>{text.revokeOthersBody}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{text.cancel}</AlertDialogCancel><AlertDialogAction variant="destructive" onClick={() => void revokeOtherSessions()}>{text.confirm}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>}
          </div>}
        </section>
      </div>
      {listError && <Alert><ShieldAlert /><AlertTitle>{text.loadError}</AlertTitle><AlertDescription><Button type="button" variant="outline" size="sm" onClick={() => void refreshSecurityState()}><RefreshCw />{text.retry}</Button></AlertDescription></Alert>}
    </>}

    <details id="totp-fallback" className="surface-card security-fallback" open={requiredGate && (capability?.supported === false || totpRecoveryRequested)}>
      <summary><span><span className="credential-icon"><KeyRound /></span><span><small>{text.fallback}</small><strong>{text.fallbackTitle}</strong></span></span><Plus aria-hidden="true" /></summary>
      <p>{text.fallbackBody}</p>
      <MfaEnrollmentPanel locale={locale} session={session} requiredGate={requiredGate} />
    </details>

    {loadingLists && <span className="sr-only" role="status">{text.working}</span>}
  </div>;
}
