"use client";

import { message } from "@/lib/product-i18n";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, KeyRound, LoaderCircle, ShieldCheck } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, apiRequest, setCsrfToken, type AuthenticatedSession, type Locale } from "@/lib/api";
import { currentPreAuthOriginGateUrl } from "@/lib/auth-origin";

const copy = {
  es: { title: message("es", "screen.invitationAcceptForm.aab402b39bde"), description: message("es", "screen.invitationAcceptForm.bab90ce086f6"), token: message("es", "screen.invitationAcceptForm.41f6229127ef"), email: message("es", "screen.invitationAcceptForm.a87309e18887"), name: message("es", "screen.invitationAcceptForm.62f1331ac0fd"), password: message("es", "screen.invitationAcceptForm.1218c673b613"), help: message("es", "screen.invitationAcceptForm.6434aa25a8c9"), submit: message("es", "screen.invitationAcceptForm.c64370865f5b"), success: message("es", "screen.invitationAcceptForm.928b2561b55c"), successBody: message("es", "screen.invitationAcceptForm.9e71dc152234"), signIn: message("es", "screen.invitationAcceptForm.e27ca5098ee9"), error: message("es", "screen.invitationAcceptForm.b1902525fc41") },
  en: { title: message("en", "screen.invitationAcceptForm.aab402b39bde"), description: message("en", "screen.invitationAcceptForm.bab90ce086f6"), token: message("en", "screen.invitationAcceptForm.41f6229127ef"), email: message("en", "screen.invitationAcceptForm.a87309e18887"), name: message("en", "screen.invitationAcceptForm.62f1331ac0fd"), password: message("en", "screen.invitationAcceptForm.1218c673b613"), help: message("en", "screen.invitationAcceptForm.6434aa25a8c9"), submit: message("en", "screen.invitationAcceptForm.c64370865f5b"), success: message("en", "screen.invitationAcceptForm.928b2561b55c"), successBody: message("en", "screen.invitationAcceptForm.9e71dc152234"), signIn: message("en", "screen.invitationAcceptForm.e27ca5098ee9"), error: message("en", "screen.invitationAcceptForm.b1902525fc41") },
  fr: { title: message("fr", "screen.invitationAcceptForm.aab402b39bde"), description: message("fr", "screen.invitationAcceptForm.bab90ce086f6"), token: message("fr", "screen.invitationAcceptForm.41f6229127ef"), email: message("fr", "screen.invitationAcceptForm.a87309e18887"), name: message("fr", "screen.invitationAcceptForm.62f1331ac0fd"), password: message("fr", "screen.invitationAcceptForm.1218c673b613"), help: message("fr", "screen.invitationAcceptForm.6434aa25a8c9"), submit: message("fr", "screen.invitationAcceptForm.c64370865f5b"), success: message("fr", "screen.invitationAcceptForm.928b2561b55c"), successBody: message("fr", "screen.invitationAcceptForm.9e71dc152234"), signIn: message("fr", "screen.invitationAcceptForm.e27ca5098ee9"), error: message("fr", "screen.invitationAcceptForm.b1902525fc41") },
} as const;

const enterpriseCopy = {
  es: {
    passkeyFirstTitle: "Activación sin contraseña, cuando la política lo permite",
    passkeyFirstBody: "Primero activaremos una sesión limitada y luego crearás una llave de acceso con la huella, el rostro o el PIN de este dispositivo. En celular o PC no necesitas escanear un QR.",
    passwordRequiredTitle: "Esta organización conserva una contraseña de respaldo",
    passwordRequiredBody: "La invitación sigue pendiente. Crea ahora la contraseña exigida por su política; después continuarás directamente con la llave de acceso.",
    originTitle: "Abre la activación local segura",
    originBody: "Antes de introducir el token o datos personales, cambia a localhost. Así la sesión de activación y tu futura llave permanecerán en el mismo origen protegido.",
    openCanonical: "Continuar de forma segura en localhost",
  },
  en: {
    passkeyFirstTitle: "Passwordless activation when policy allows",
    passkeyFirstBody: "We first activate a restricted session, then you create a passkey with this device’s fingerprint, face, or PIN. No QR scan is required on a phone or computer.",
    passwordRequiredTitle: "This organization keeps a backup password",
    passwordRequiredBody: "Your invitation is still pending. Create the password required by its policy; you will then continue directly to passkey setup.",
    originTitle: "Open the secure local activation",
    originBody: "Before entering the token or personal data, switch to localhost. This keeps the activation session and your future passkey on the same protected origin.",
    openCanonical: "Continue securely on localhost",
  },
  fr: {
    passkeyFirstTitle: "Activation sans mot de passe lorsque la politique l’autorise",
    passkeyFirstBody: "Nous activons d’abord une session limitée, puis vous créez une clé d’accès avec l’empreinte, le visage ou le NIP de cet appareil. Aucun QR n’est requis sur mobile ou ordinateur.",
    passwordRequiredTitle: "Cette organisation conserve un mot de passe de secours",
    passwordRequiredBody: "Votre invitation reste en attente. Créez le mot de passe exigé par sa politique ; vous passerez ensuite directement à la clé d’accès.",
    originTitle: "Ouvrez l’activation locale sécurisée",
    originBody: "Avant de saisir le jeton ou des données personnelles, passez à localhost. La session d’activation et votre future clé resteront ainsi sur la même origine protégée.",
    openCanonical: "Continuer en sécurité sur localhost",
  },
} as const;

type InvitationField = "token" | "email" | "displayName" | "password";
type InvitationErrors = Partial<Record<InvitationField, string>>;
type InvitationAcceptance = AuthenticatedSession & {
  accepted: true;
  signInRequired: false;
  enrollmentRequired: true;
  tenantId: string;
  roles: string[];
};

const emailPattern = /^[^\s@]+@[^\s@]+$/u;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/u;
const subscribeToHydration = () => () => undefined;
const hydratedClientSnapshot = () => true;
const hydratedServerSnapshot = () => false;
const preAuthOriginServerSnapshot = () => "pending";
const commonPasswords = new Set([
  "password123!", "contraseña123!", "administrador123!", "nombramientos123!",
]);

function passwordMatchesPolicy(password: string, email: string, displayName: string) {
  if (password.length < 14 || password.length > 256
      || !/[a-z]/u.test(password) || !/[A-Z]/u.test(password)
      || !/\d/u.test(password) || !/[^A-Za-z0-9]/u.test(password)) return false;
  const normalizedPassword = password.normalize("NFKC").toLocaleLowerCase("en-US");
  if (commonPasswords.has(normalizedPassword)) return false;
  const emailLocalPart = email.split("@")[0]?.normalize("NFKC").toLocaleLowerCase("en-US") ?? "";
  const nameTokens = displayName.normalize("NFKC").toLocaleLowerCase("en-US").split(/[^\p{L}\p{N}]+/u)
    .filter((item) => item.length >= 4);
  return !(emailLocalPart.length >= 3 && normalizedPassword.includes(emailLocalPart))
    && !nameTokens.some((item) => normalizedPassword.includes(item));
}

function localizedInvitationFailure(caught: unknown, locale: Locale, fallback: string) {
  if (!(caught instanceof ApiError)) return fallback;
  const base = caught.status === 429
    ? message(locale, "auth.tooManyAttempts")
    : caught.status === 408 || caught.status >= 500
      ? message(locale, "error.transient")
      : fallback;
  return caught.requestId
    ? `${base} (${message(locale, "audit.correlationId", { id: caught.requestId })})`
    : base;
}

export function InvitationAcceptForm({ locale }: { locale: Locale }) {
  const text = copy[locale];
  const guidance = enterpriseCopy[locale];
  const router = useRouter();
  const queryClient = useQueryClient();
  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [busy, setBusy] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState<string>();
  const [fieldErrors, setFieldErrors] = useState<InvitationErrors>({});
  const hydrated = useSyncExternalStore(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot);
  const originGateUrl = useSyncExternalStore(subscribeToHydration, currentPreAuthOriginGateUrl, preAuthOriginServerSnapshot);
  const validationSummaryRef = useRef<HTMLDivElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const fieldErrorCount = Object.values(fieldErrors).filter(Boolean).length;
  const preAuthReady = hydrated && originGateUrl === "";

  useEffect(() => {
    const purge = () => {
      setToken("");
      setEmail("");
      setDisplayName("");
      setPassword("");
      setPasswordRequired(false);
      setError(undefined);
      setFieldErrors({});
    };
    window.addEventListener("pagehide", purge);
    return () => window.removeEventListener("pagehide", purge);
  }, []);

  useEffect(() => {
    if (!passwordRequired || busy || !preAuthReady) return;
    // The password input is conditionally mounted after the server's 428
    // response. Focusing from the catch block races React's commit (notably in
    // WebKit); wait until the field is both mounted and enabled.
    const focusFrame = window.requestAnimationFrame(() => passwordRef.current?.focus());
    return () => window.cancelAnimationFrame(focusFrame);
  }, [busy, passwordRequired, preAuthReady]);

  function clearFieldError(field: InvitationField) {
    setFieldErrors((current) => ({ ...current, [field]: undefined }));
    setError(undefined);
  }

  function installInvitationSession(session: AuthenticatedSession) {
    if (!isRestrictedEnrollmentSession(session)) {
      throw new ApiError(502, "INVALID_INVITATION_SESSION", "Invitation did not return a restricted enrollment session");
    }
    setToken("");
    setEmail("");
    setDisplayName("");
    setAccepted(true);
    queryClient.clear();
    setCsrfToken(session.csrfToken);
    queryClient.setQueryData(["session"], session);
    router.replace(`/${locale}/app/settings`);
    router.refresh();
  }

  async function submitInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!preAuthReady) return;
    const submitted = {
      token: token.trim(),
      email: email.trim(),
      displayName: displayName.trim(),
    };
    const nextErrors: InvitationErrors = {};
    if (!submitted.token) nextErrors.token = `${text.token}: ${message(locale, "a11y.requiredField")}`;
    else if (!tokenPattern.test(submitted.token)) nextErrors.token = `${text.token}: ${message(locale, "error.validation")}`;
    if (!submitted.email) nextErrors.email = `${text.email}: ${message(locale, "a11y.requiredField")}`;
    else if (!emailPattern.test(submitted.email) || submitted.email.length > 320) nextErrors.email = `${text.email}: ${message(locale, "error.validation")}`;
    if (!submitted.displayName) nextErrors.displayName = `${text.name}: ${message(locale, "a11y.requiredField")}`;
    else if (submitted.displayName.length < 2 || submitted.displayName.length > 120 || /[\p{Cc}\p{Cf}]/u.test(submitted.displayName)) nextErrors.displayName = `${text.name}: ${message(locale, "error.validation")}`;
    if (passwordRequired && !password) nextErrors.password = `${text.password}: ${message(locale, "a11y.requiredField")}`;
    else if (passwordRequired && !passwordMatchesPolicy(password, submitted.email, submitted.displayName)) nextErrors.password = `${text.password}: ${text.help}`;

    if (Object.keys(nextErrors).length > 0) {
      setPassword("");
      setFieldErrors(nextErrors);
      setError(undefined);
      requestAnimationFrame(() => validationSummaryRef.current?.focus());
      return;
    }

    setPassword("");
    setFieldErrors({});
    setBusy(true);
    setError(undefined);
    try {
      await withInvitationBrowserLock(async () => {
        // Establish a host-only, HttpOnly possession context before any
        // database mutation. A fixed Web Lock serializes normal first-use
        // preflights across tabs without putting the invitation token, email,
        // or recovery material in the lock name or persistent web storage.
        await apiRequest<{ prepared: true }>("/v1/invitations/recovery-context", {
          method: "POST",
          body: JSON.stringify({}),
        });
        const acceptancePayload = JSON.stringify(passwordRequired
          ? { ...submitted, password }
          : submitted);
        const acceptOnce = () => apiRequest<InvitationAcceptance>("/v1/invitations/accept", {
          method: "POST",
          body: acceptancePayload,
        });

        // A lost/5xx acceptance response is never resolved by blindly trusting
        // whichever session another tab left in the shared cookie jar. Repeat
        // the exact idempotent acceptance once to obtain its canonical identity
        // and tenant correlation, then validate the installed bearer below.
        let acceptedResponse: InvitationAcceptance;
        try {
          acceptedResponse = await acceptOnce();
        } catch (acceptanceError) {
          if (!isRetryableAcceptanceFailure(acceptanceError)) throw acceptanceError;
          acceptedResponse = await acceptOnce();
        }
        assertRestrictedInvitationSession(acceptedResponse);

        // The cookie jar, not response arrival order, is authoritative. Validate
        // the installed bearer; if a stale Set-Cookie loser produced 401/network,
        // one final exact retry rotates it. A valid session for another account
        // is an explicit browser-session conflict and is never overwritten.
        let canonicalResponse = acceptedResponse;
        let installedSession: AuthenticatedSession;
        try {
          installedSession = await apiRequest<AuthenticatedSession>("/v1/session");
        } catch (probeError) {
          if (!isRepairableSessionProbeFailure(probeError)) throw probeError;
          const repairedResponse = await acceptOnce();
          assertRestrictedInvitationSession(repairedResponse);
          if (
            repairedResponse.user.id !== acceptedResponse.user.id
            || repairedResponse.tenantId !== acceptedResponse.tenantId
          ) {
            throw browserSessionConflict();
          }
          canonicalResponse = repairedResponse;
          installedSession = await apiRequest<AuthenticatedSession>("/v1/session");
        }
        assertInstalledInvitationSession(installedSession, canonicalResponse);
        installInvitationSession(installedSession);
      });
    } catch (caught) {
      setPassword("");
      if (caught instanceof ApiError && caught.status === 428 && caught.code === "INVITATION_PASSWORD_REQUIRED") {
        setPasswordRequired(true);
        setError(undefined);
        return;
      }
      setError(localizedInvitationFailure(caught, locale, text.error));
    } finally {
      setBusy(false);
    }
  }

  return <main className="activation-shell" id="main-content" tabIndex={-1}><section className="activation-card">
    <div className="activation-mark"><span className="brand-mark">N</span><BadgeLine locale={locale} /></div>
    {accepted ? <div className="activation-success"><span><CheckCircle2 /></span><h1>{text.success}</h1><p>{text.successBody}</p><Button asChild><Link href={`/${locale}/app/settings`}>{text.signIn}</Link></Button></div> : <>
      <div className="form-heading"><span className="form-icon"><KeyRound /></span><h1>{text.title}</h1><p>{text.description}</p></div>
      {originGateUrl !== "" && originGateUrl !== "pending"
        ? <Alert role="status" className="mb-5"><ShieldCheck /><AlertTitle>{guidance.originTitle}</AlertTitle><AlertDescription><p>{guidance.originBody}</p><Button asChild className="mt-3" size="sm"><a href={originGateUrl}>{guidance.openCanonical}</a></Button></AlertDescription></Alert>
        : <Alert className="mb-5"><ShieldCheck /><AlertTitle>{guidance.passkeyFirstTitle}</AlertTitle><AlertDescription>{guidance.passkeyFirstBody}</AlertDescription></Alert>}
      {passwordRequired && <Alert className="mb-5" role="status"><ShieldCheck /><AlertTitle>{guidance.passwordRequiredTitle}</AlertTitle><AlertDescription>{guidance.passwordRequiredBody}</AlertDescription></Alert>}
      <form className="auth-form" onSubmit={submitInvitation} noValidate aria-busy={busy}>
        <div className="field-stack"><Label htmlFor="accept-token">{text.token}</Label><Input id="accept-token" value={token} onChange={(event) => { setToken(event.target.value); clearFieldError("token"); }} disabled={!preAuthReady || busy} minLength={43} maxLength={43} autoComplete="one-time-code" required aria-invalid={fieldErrors.token ? true : undefined} aria-describedby={fieldErrors.token ? "accept-token-error" : undefined} />{fieldErrors.token && <p id="accept-token-error" className="form-error">{fieldErrors.token}</p>}</div>
        <div className="field-stack"><Label htmlFor="accept-email">{text.email}</Label><Input id="accept-email" type="email" value={email} onChange={(event) => { setEmail(event.target.value); clearFieldError("email"); }} disabled={!preAuthReady || busy} autoComplete="email" maxLength={320} required aria-invalid={fieldErrors.email ? true : undefined} aria-describedby={fieldErrors.email ? "accept-email-error" : undefined} />{fieldErrors.email && <p id="accept-email-error" className="form-error">{fieldErrors.email}</p>}</div>
        <div className="field-stack"><Label htmlFor="accept-name">{text.name}</Label><Input id="accept-name" value={displayName} onChange={(event) => { setDisplayName(event.target.value); clearFieldError("displayName"); }} disabled={!preAuthReady || busy} autoComplete="name" minLength={2} maxLength={120} required aria-invalid={fieldErrors.displayName ? true : undefined} aria-describedby={fieldErrors.displayName ? "accept-name-error" : undefined} />{fieldErrors.displayName && <p id="accept-name-error" className="form-error">{fieldErrors.displayName}</p>}</div>
        {passwordRequired && <div className="field-stack"><Label htmlFor="accept-password">{text.password}</Label><Input ref={passwordRef} id="accept-password" type="password" value={password} onChange={(event) => { setPassword(event.target.value); clearFieldError("password"); }} disabled={!preAuthReady || busy} autoComplete="new-password" minLength={14} maxLength={256} required aria-invalid={fieldErrors.password ? true : undefined} aria-describedby={fieldErrors.password ? "accept-password-help accept-password-error" : "accept-password-help"} /><small id="accept-password-help">{text.help}</small>{fieldErrors.password && <p id="accept-password-error" className="form-error">{fieldErrors.password}</p>}</div>}
        {fieldErrorCount > 0 && <Alert id="accept-validation-summary" ref={validationSummaryRef} variant="destructive" tabIndex={-1} aria-labelledby="accept-validation-summary-title"><ShieldCheck /><AlertTitle id="accept-validation-summary-title">{message(locale, "a11y.errorSummary", { count: fieldErrorCount })}</AlertTitle><AlertDescription><ul className="list-disc pl-4">{fieldErrors.token && <li><a href="#accept-token">{fieldErrors.token}</a></li>}{fieldErrors.email && <li><a href="#accept-email">{fieldErrors.email}</a></li>}{fieldErrors.displayName && <li><a href="#accept-name">{fieldErrors.displayName}</a></li>}{fieldErrors.password && <li><a href="#accept-password">{fieldErrors.password}</a></li>}</ul></AlertDescription></Alert>}
        {error && <Alert variant="destructive"><ShieldCheck /><AlertTitle>{text.error}</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
        <Button className="h-12" type="submit" disabled={!preAuthReady || busy}>{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{text.submit}</Button>
      </form>
    </>}
  </section></main>;
}

function isRestrictedInvitationSession(session: InvitationAcceptance): boolean {
  return session.accepted === true
    && session.signInRequired === false
    && session.enrollmentRequired === true
    && isRestrictedEnrollmentSession(session)
    && session.tenant.id === session.tenantId;
}

function assertRestrictedInvitationSession(session: InvitationAcceptance): void {
  if (!isRestrictedInvitationSession(session)) {
    throw new ApiError(502, "INVALID_INVITATION_SESSION", "Invitation did not return a restricted enrollment session");
  }
}

function assertInstalledInvitationSession(
  session: AuthenticatedSession,
  acceptedResponse: InvitationAcceptance,
): void {
  if (!isRestrictedEnrollmentSession(session)) {
    throw new ApiError(502, "INVALID_INVITATION_SESSION", "The installed invitation session is not restricted");
  }
  if (
    session.user.id !== acceptedResponse.user.id
    || session.tenant.id !== acceptedResponse.tenantId
  ) {
    throw browserSessionConflict();
  }
}

function browserSessionConflict(): ApiError {
  return new ApiError(
    409,
    "INVITATION_BROWSER_SESSION_CONFLICT",
    "A different invitation session is already active in this browser",
  );
}

function isRetryableAcceptanceFailure(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 408 || error.status >= 500;
}

function isRepairableSessionProbeFailure(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 401;
}

async function withInvitationBrowserLock<T>(work: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && navigator.locks) {
    return navigator.locks.request("nombramientos.invitation-recovery-context.v1", work);
  }
  return work();
}

function isRestrictedEnrollmentSession(session: AuthenticatedSession): boolean {
  return session.authenticated === true
    && session.status === "mfa_enrollment_required"
    && session.security.enrollmentOnly === true
    && session.security.assurance === "enrollment_only"
    && session.permissions.length === 0
    && !session.keyGrant
    && typeof session.csrfToken === "string"
    && session.csrfToken.length > 0
    && Number.isFinite(Date.parse(session.expiresAt))
    && Date.parse(session.expiresAt) > Date.now();
}

function BadgeLine({ locale }: { locale: Locale }) {
  const labels = { es: message("es", "screen.invitationAcceptForm.1f3b1b2a4ece"), en: message("en", "screen.invitationAcceptForm.1f3b1b2a4ece"), fr: message("fr", "screen.invitationAcceptForm.1f3b1b2a4ece") } as const;
  return <span>{labels[locale]}</span>;
}
