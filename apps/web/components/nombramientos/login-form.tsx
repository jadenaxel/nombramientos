"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { DatabaseZap, Fingerprint, Languages, LoaderCircle, LockKeyhole, ShieldCheck } from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import { api, ApiError, type Locale, type LoginResult, setCsrfToken } from "@/lib/api";
import { appLandingPath } from "@/lib/app-navigation";
import { currentPreAuthOriginGateUrl } from "@/lib/auth-origin";
import { messages } from "@/lib/messages";
import { localizedApiError, localizedSignInError, message } from "@/lib/product-i18n";
import {
  authenticateWithPasskey,
  cancelPasskeyCeremony,
  detectPasskeyCapability,
  isPasskeyCancellation,
  isPasskeyUnsupported,
  type PasskeyCapability,
} from "@/lib/webauthn";

const subscribeToHydration = () => () => undefined;
const hydratedClientSnapshot = () => true;
const hydratedServerSnapshot = () => false;
const preAuthOriginServerSnapshot = () => "pending";
const emailPattern = /^[^\s@]+@[^\s@]+$/u;

type CredentialErrors = Partial<Record<"email" | "password", string>>;

const passkeyCopy = {
  es: { button: "Entrar con llave de acceso", help: "Usa tu huella, rostro o PIN. En este teléfono no necesitas escanear un QR.", divider: "o continúa con contraseña", cancelled: "La verificación fue cancelada. No se realizó ningún cambio.", unsupported: "Este navegador no admite llaves de acceso. Puedes continuar con contraseña y autenticador.", invalidOrigin: "Las llaves de acceso locales requieren localhost. Abre la dirección segura para continuar.", originTitle: "Abre el acceso local seguro", originBody: "Antes de introducir datos, cambia a localhost. Así la sesión y la llave de acceso permanecerán en el mismo origen protegido.", openCanonical: "Continuar de forma segura en localhost", checking: "Buscando llaves de acceso…" },
  en: { button: "Sign in with a passkey", help: "Use your fingerprint, face, or PIN. On this phone, no QR scan is needed.", divider: "or continue with password", cancelled: "Verification was cancelled. No changes were made.", unsupported: "This browser does not support passkeys. You can continue with password and authenticator.", invalidOrigin: "Local passkeys require localhost. Open the secure address to continue.", originTitle: "Open the secure local sign-in", originBody: "Before entering any data, switch to localhost. This keeps the session and passkey on the same protected origin.", openCanonical: "Continue securely on localhost", checking: "Looking for passkeys…" },
  fr: { button: "Se connecter avec une clé d’accès", help: "Utilisez votre empreinte, visage ou NIP. Sur ce téléphone, aucun QR n’est nécessaire.", divider: "ou continuer avec le mot de passe", cancelled: "La vérification a été annulée. Aucun changement n’a été effectué.", unsupported: "Ce navigateur ne prend pas en charge les clés d’accès. Vous pouvez continuer avec le mot de passe et l’authentificateur.", invalidOrigin: "Les clés d’accès locales exigent localhost. Ouvrez l’adresse sécurisée pour continuer.", originTitle: "Ouvrez l’accès local sécurisé", originBody: "Avant de saisir des données, passez à localhost. La session et la clé d’accès resteront ainsi sur la même origine protégée.", openCanonical: "Continuer en sécurité sur localhost", checking: "Recherche de clés d’accès…" },
} as const;

export function LoginForm({ locale }: { locale: Locale }) {
  const copy = messages[locale];
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [verificationMethod, setVerificationMethod] = useState<"totp" | "recovery">("totp");
  const [challengeId, setChallengeId] = useState("");
  const [stage, setStage] = useState<"credentials" | "mfa">("credentials");
  const [busy, setBusy] = useState(false);
  const [passkeyBusy, setPasskeyBusy] = useState(false);
  const [passkeyCapability, setPasskeyCapability] = useState<PasskeyCapability>();
  const [passkeyNotice, setPasskeyNotice] = useState<string>();
  const [error, setError] = useState<string>();
  const [credentialErrors, setCredentialErrors] = useState<CredentialErrors>({});
  const hydrated = useSyncExternalStore(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot);
  const originGateUrl = useSyncExternalStore(subscribeToHydration, currentPreAuthOriginGateUrl, preAuthOriginServerSnapshot);
  const pendingPassword = useRef("");
  const conditionalRun = useRef<symbol | undefined>(undefined);
  const validationSummaryRef = useRef<HTMLDivElement>(null);
  const credentialErrorCount = Number(Boolean(credentialErrors.email)) + Number(Boolean(credentialErrors.password));
  const preAuthReady = hydrated && originGateUrl === "";

  const finish = useCallback(async (result: LoginResult) => {
    if (result.status === "mfa_required") {
      setChallengeId(result.challengeId);
      setStage("mfa");
      return;
    }
    vault.lock();
    queryClient.clear();
    setCsrfToken(result.csrfToken);
    if (result.status === "authenticated" && result.keyGrant && pendingPassword.current) {
      await vault.unlock(pendingPassword.current, result.keyGrant, result.tenant.id);
    }
    pendingPassword.current = "";
    setPassword("");
    const recoveryRestricted = result.security.recoveryRestricted === true || result.security.assurance === "recovery_limited";
    router.replace(result.status === "mfa_enrollment_required" || recoveryRestricted
      ? `/${locale}/app/settings`
      : appLandingPath(locale, result.permissions));
    router.refresh();
  }, [locale, queryClient, router, vault]);

  useEffect(() => {
    if (!preAuthReady || stage !== "credentials" || busy || passkeyBusy) return;
    const run = Symbol("conditional-passkey");
    conditionalRun.current = run;
    let ceremonyStarted = false;
    void (async () => {
      const capability = await detectPasskeyCapability();
      if (conditionalRun.current !== run) return;
      setPasskeyCapability(capability);
      if (!capability.conditional) return;
      const ceremony = await api.passkeyAuthenticationOptions(undefined, "conditional");
      if (conditionalRun.current !== run) return;
      ceremonyStarted = true;
      const response = await authenticateWithPasskey(ceremony.options, true);
      if (conditionalRun.current !== run) return;
      const result = await api.verifyPasskeyAuthentication(ceremony.ceremonyId, response);
      if (conditionalRun.current !== run) return;
      await finish(result);
    })().catch((caught) => {
      // Conditional UI is progressive enhancement. User cancellation and an
      // unavailable passkey endpoint must never block password fallback.
      if (conditionalRun.current === run && !isPasskeyCancellation(caught) && isPasskeyUnsupported(caught)) {
        setPasskeyCapability({ supported: false, conditional: false, platform: false });
      }
    });
    return () => {
      if (conditionalRun.current === run) {
        conditionalRun.current = undefined;
        if (ceremonyStarted) cancelPasskeyCeremony();
      }
    };
  }, [busy, finish, passkeyBusy, preAuthReady, stage]);

  async function signInWithPasskey() {
    if (!preAuthReady) return;
    conditionalRun.current = undefined;
    cancelPasskeyCeremony();
    setPasskeyBusy(true); setPasskeyNotice(undefined); setError(undefined);
    try {
      // Keep the primary passkey ceremony discoverable/usernameless even when
      // the email field contains text. The authenticator selects the identity,
      // so this path cannot become an account-enumeration oracle.
      const ceremony = await api.passkeyAuthenticationOptions(undefined, "optional");
      const response = await authenticateWithPasskey(ceremony.options);
      await finish(await api.verifyPasskeyAuthentication(ceremony.ceremonyId, response));
    } catch (caught) {
      if (isPasskeyCancellation(caught)) setPasskeyNotice(passkeyCopy[locale].cancelled);
      else if (isPasskeyUnsupported(caught)) {
        setPasskeyCapability({ supported: false, conditional: false, platform: false });
        setPasskeyNotice(passkeyCopy[locale].unsupported);
      } else setError(caught instanceof ApiError ? localizedApiError(caught, locale) : copy.unavailable);
    } finally { setPasskeyBusy(false); }
  }

  async function submitCredentials(event: React.FormEvent) {
    event.preventDefault();
    if (!preAuthReady) return;
    conditionalRun.current = undefined;
    cancelPasskeyCeremony();
    const normalizedEmail = email.trim();
    const nextErrors: CredentialErrors = {};
    if (!normalizedEmail) nextErrors.email = `${copy.email}: ${message(locale, "a11y.requiredField")}`;
    else if (!emailPattern.test(normalizedEmail)) nextErrors.email = `${copy.email}: ${message(locale, "error.validation")}`;
    if (!password) nextErrors.password = `${copy.password}: ${message(locale, "a11y.requiredField")}`;
    else if (password.length < 12) nextErrors.password = `${copy.password}: ${copy.minPassword}`;

    if (Object.keys(nextErrors).length > 0) {
      pendingPassword.current = "";
      setPassword("");
      setCredentialErrors(nextErrors);
      setError(undefined);
      requestAnimationFrame(() => validationSummaryRef.current?.focus());
      return;
    }

    vault.lock(); queryClient.clear(); setCsrfToken(undefined);
    pendingPassword.current = password;
    const submittedPassword = password;
    setPassword("");
    setCredentialErrors({});
    setBusy(true); setError(undefined);
    try { await finish(await api.login(normalizedEmail, submittedPassword)); }
    catch (caught) {
      pendingPassword.current = "";
      setPassword("");
      setError(caught instanceof ApiError ? localizedSignInError(caught, locale) : copy.unavailable);
    } finally { setBusy(false); }
  }

  async function submitMfa(event: React.FormEvent) {
    event.preventDefault();
    if (verificationMethod === "totp" && code.length !== 6) return;
    if (verificationMethod === "recovery" && recoveryCode.trim().length < 16) return;
    setBusy(true); setError(undefined);
    try {
      await finish(await api.verifyMfa(
        challengeId,
        verificationMethod === "totp" ? code : recoveryCode.trim(),
        verificationMethod,
      ));
      setCode(""); setRecoveryCode("");
    }
    catch (caught) { setError(caught instanceof ApiError ? localizedSignInError(caught, locale) : copy.unavailable); }
    finally { setBusy(false); }
  }

  return (
    <main className="login-shell" id="main-content" tabIndex={-1}>
      <section className="login-story" aria-label={copy.privateSpace}>
        <div className="creation-grid" aria-hidden="true">{Array.from({ length: 7 }, (_, index) => <span key={index} />)}</div>
        <div className="login-brand"><span className="brand-mark">N</span><strong>Nombramientos</strong></div>
        <div className="login-story-copy">
          <p className="eyebrow text-cyan-200">{copy.storyEyebrow}</p>
          <p className="login-story-title">{copy.privateSpace}</p>
          <p>{copy.storyBody}</p>
        </div>
        <div className="login-assurances">
          <div><ShieldCheck /><span><strong>{copy.isolationTitle}</strong><small>{copy.isolationBody}</small></span></div>
          <div><LockKeyhole /><span><strong>{copy.encryptedTitle}</strong><small>{copy.encryptedBody}</small></span></div>
          <div><DatabaseZap /><span><strong>{copy.postgresTitle}</strong><small>{copy.postgresBody}</small></span></div>
        </div>
      </section>

      <section className="login-panel">
        <div className="login-card">
          <div className="language-links" aria-label={copy.language}>
            <Languages size={16} />
            {(["es", "en", "fr"] as Locale[]).map((item) => <Link key={item} aria-current={locale === item ? "page" : undefined} href={`/${item}/auth/sign-in`}>{item.toUpperCase()}</Link>)}
          </div>

          {stage === "credentials" ? (
            <>
              <div className="form-heading"><span className="form-icon"><LockKeyhole /></span><h1>{copy.signIn}</h1><p>{copy.security}</p></div>
              {originGateUrl !== "" && originGateUrl !== "pending" && <Alert role="status" className="mb-5"><ShieldCheck /><AlertTitle>{passkeyCopy[locale].originTitle}</AlertTitle><AlertDescription><p>{passkeyCopy[locale].originBody}</p><Button asChild className="mt-3" size="sm"><a href={originGateUrl}>{passkeyCopy[locale].openCanonical}</a></Button></AlertDescription></Alert>}
              <form onSubmit={submitCredentials} className="auth-form" noValidate>
                <div className="field-stack">
                  <Label htmlFor="email">{copy.email}</Label>
                  <Input id="email" type="email" autoComplete="username webauthn" value={email} onChange={(event) => { setEmail(event.target.value); setCredentialErrors((current) => ({ ...current, email: undefined })); setError(undefined); setPasskeyNotice(undefined); }} disabled={!preAuthReady || busy || passkeyBusy} required aria-invalid={credentialErrors.email ? true : undefined} aria-describedby={credentialErrors.email ? "email-error" : undefined} />
                  {credentialErrors.email && <p id="email-error" className="form-error">{credentialErrors.email}</p>}
                </div>
                <div className="passkey-login-option">
                  <Button className="passkey-login-button" type="button" variant="outline" onClick={() => void signInWithPasskey()} disabled={!preAuthReady || busy || passkeyBusy || passkeyCapability?.supported === false} aria-describedby="passkey-login-help">
                    {passkeyBusy || !passkeyCapability ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}
                    {passkeyBusy || !passkeyCapability ? passkeyCopy[locale].checking : passkeyCopy[locale].button}
                  </Button>
                  <p id="passkey-login-help">{passkeyCopy[locale].help}</p>
                  {passkeyCapability?.reason === "invalid_origin" && <p className="passkey-login-notice" role="status">{passkeyCopy[locale].invalidOrigin}{passkeyCapability.canonicalUrl && <> <a href={passkeyCapability.canonicalUrl}>{passkeyCopy[locale].openCanonical}</a></>}</p>}
                  {passkeyNotice && <p className="passkey-login-notice" role="status">{passkeyNotice}</p>}
                </div>
                <div className="auth-divider"><span>{passkeyCopy[locale].divider}</span></div>
                <div className="field-stack">
                  <div className="flex items-center justify-between"><Label htmlFor="password">{copy.password}</Label><span id="password-requirements" className="text-xs text-muted-foreground">{copy.minPassword}</span></div>
                  <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(event) => { setPassword(event.target.value); setCredentialErrors((current) => ({ ...current, password: undefined })); setError(undefined); }} disabled={!preAuthReady || busy || passkeyBusy} minLength={12} required aria-invalid={credentialErrors.password ? true : undefined} aria-describedby={credentialErrors.password ? "password-requirements password-error" : "password-requirements"} />
                  {credentialErrors.password && <p id="password-error" className="form-error">{credentialErrors.password}</p>}
                </div>
                {credentialErrorCount > 0 && <Alert ref={validationSummaryRef} variant="destructive" tabIndex={-1} aria-labelledby="credential-error-summary-title"><ShieldCheck /><AlertTitle id="credential-error-summary-title">{message(locale, "a11y.errorSummary", { count: credentialErrorCount })}</AlertTitle><AlertDescription><ul className="list-disc pl-4">{credentialErrors.email && <li><a href="#email">{credentialErrors.email}</a></li>}{credentialErrors.password && <li><a href="#password">{credentialErrors.password}</a></li>}</ul></AlertDescription></Alert>}
                {error && <Alert variant="destructive"><ShieldCheck /><AlertTitle>{copy.signInError}</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
                <Button className="h-12 w-full" disabled={!preAuthReady || busy || passkeyBusy} type="submit">{busy && <LoaderCircle className="animate-spin" />} {copy.continue}</Button>
              </form>
            </>
          ) : (
            <>
              <div className="form-heading"><span className="form-icon"><ShieldCheck /></span><h1>{copy.mfa}</h1><p>{copy.mfaHelp}</p></div>
              <form onSubmit={submitMfa} className="auth-form" noValidate>
                {verificationMethod === "totp" ? <>
                  <Label htmlFor="mfa-code">{copy.code}</Label>
                  <InputOTP id="mfa-code" maxLength={6} inputMode="numeric" value={code} onChange={setCode} containerClassName="justify-center">
                    <InputOTPGroup>{Array.from({ length: 6 }, (_, index) => <InputOTPSlot key={index} index={index} className="h-12 w-12 text-lg" />)}</InputOTPGroup>
                  </InputOTP>
                </> : <div className="field-stack">
                  <Label htmlFor="mfa-recovery-code">{copy.recoveryCode}</Label>
                  <Input id="mfa-recovery-code" value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value.toUpperCase())} autoComplete="one-time-code" placeholder="XXXX-XXXX-XXXX-XXXX" maxLength={19} required />
                  <small>{copy.recoveryHelp}</small>
                </div>}
                {error && <Alert variant="destructive"><ShieldCheck /><AlertTitle>{copy.verificationRejected}</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
                <Button className="h-12 w-full" disabled={busy || (verificationMethod === "totp" ? code.length !== 6 : recoveryCode.trim().length < 16)} type="submit">{busy && <LoaderCircle className="animate-spin" />} {copy.verify}</Button>
                <Button type="button" variant="outline" onClick={() => { setVerificationMethod(verificationMethod === "totp" ? "recovery" : "totp"); setCode(""); setRecoveryCode(""); setError(undefined); }}>{verificationMethod === "totp" ? copy.useRecovery : copy.useAuthenticator}</Button>
                <Button type="button" variant="ghost" onClick={() => { pendingPassword.current = ""; setStage("credentials"); setChallengeId(""); setCode(""); setRecoveryCode(""); setVerificationMethod("totp"); setError(undefined); }}>{copy.back}</Button>
              </form>
            </>
          )}
          <Button asChild variant="ghost" className="mt-3 w-full"><Link href={`/${locale}/auth/invitation`}>{copy.invitation}</Link></Button>
          <p className="demo-caption"><span /> {copy.demo}</p>
        </div>
        <p className="legal-caption">{copy.legal}</p>
      </section>
    </main>
  );
}
