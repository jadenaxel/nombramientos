"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Eye, EyeOff, Fingerprint, KeyRound, LoaderCircle, MonitorSmartphone, ShieldCheck } from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  apiRequest,
  ApiError,
  setCsrfToken,
  type AuthenticatedSession,
  type Locale,
} from "@/lib/api";
import { currentPreAuthOriginGateUrl } from "@/lib/auth-origin";
import { redeemInitialAdminRecoverySafely } from "@/lib/initial-admin-recovery-browser";
import { message } from "@/lib/product-i18n";

type RecoveryField = "recoveryId" | "token";
type RecoveryFieldErrors = Partial<Record<RecoveryField, string>>;

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/u;
const subscribeToHydration = () => () => undefined;
const hydratedClientSnapshot = () => true;
const hydratedServerSnapshot = () => false;
const preAuthOriginServerSnapshot = () => "pending";

export function InitialAdminOnboardingRecoveryForm({ locale }: { locale: Locale }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const [recoveryId, setRecoveryId] = useState("");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [busy, setBusy] = useState(false);
  const [recovered, setRecovered] = useState(false);
  const [error, setError] = useState<string>();
  const [fieldErrors, setFieldErrors] = useState<RecoveryFieldErrors>({});
  const summaryRef = useRef<HTMLDivElement>(null);
  const hydrated = useSyncExternalStore(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot);
  const originGateUrl = useSyncExternalStore(subscribeToHydration, currentPreAuthOriginGateUrl, preAuthOriginServerSnapshot);
  const originReady = hydrated && originGateUrl === "";

  useEffect(() => {
    const conceal = () => { if (document.visibilityState === "hidden") setShowToken(false); };
    const purge = () => {
      setRecoveryId("");
      setToken("");
      setShowToken(false);
      setError(undefined);
      setFieldErrors({});
    };
    document.addEventListener("visibilitychange", conceal);
    window.addEventListener("pagehide", purge);
    return () => {
      document.removeEventListener("visibilitychange", conceal);
      window.removeEventListener("pagehide", purge);
    };
  }, []);

  function clearFieldError(field: RecoveryField) {
    setFieldErrors((current) => ({ ...current, [field]: undefined }));
    setError(undefined);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!originReady || busy) return;
    const submittedRecoveryId = recoveryId.trim().toLowerCase();
    const submittedToken = token.trim();
    const nextErrors: RecoveryFieldErrors = {};
    if (!submittedRecoveryId) {
      nextErrors.recoveryId = `${message(locale, "recovery.public.recoveryId")}: ${message(locale, "a11y.requiredField")}`;
    } else if (!uuidPattern.test(submittedRecoveryId)) {
      nextErrors.recoveryId = `${message(locale, "recovery.public.recoveryId")}: ${message(locale, "error.validation")}`;
    }
    if (!submittedToken) {
      nextErrors.token = `${message(locale, "recovery.public.token")}: ${message(locale, "a11y.requiredField")}`;
    } else if (!tokenPattern.test(submittedToken)) {
      nextErrors.token = `${message(locale, "recovery.public.token")}: ${message(locale, "error.validation")}`;
    }
    if (Object.keys(nextErrors).length > 0) {
      setFieldErrors(nextErrors);
      setError(undefined);
      requestAnimationFrame(() => summaryRef.current?.focus());
      return;
    }

    setBusy(true);
    setShowToken(false);
    setFieldErrors({});
    setError(undefined);
    try {
      const session = await redeemInitialAdminRecoverySafely(submittedRecoveryId, submittedToken, {
        readSession: () => apiRequest<AuthenticatedSession>("/v1/session", { csrf: false }),
        prepareContext: api.prepareInitialAdminRecoveryContext,
        redeem: api.redeemInitialAdminRecovery,
        beforeMutation: () => {
          vault.lock();
          queryClient.clear();
          setCsrfToken(undefined);
        },
      });
      setCsrfToken(session.csrfToken);
      queryClient.setQueryData(["session"], session);
      setRecoveryId("");
      setToken("");
      setRecovered(true);
    } catch (caught) {
      // Keep the bearer only in this component's volatile memory so a person
      // can safely retry an ambiguous transfer without requesting reissuance.
      setError(localizedRecoveryFailure(caught, locale));
    } finally {
      setBusy(false);
    }
  }

  function continueEnrollment(anchor: "passkey-onboarding-title" | "totp-fallback") {
    router.replace(`/${locale}/app/settings#${anchor}`);
    router.refresh();
  }

  return <main className="activation-shell recovery-activation-shell" id="main-content" tabIndex={-1}>
    <section className="activation-card recovery-activation-card" aria-labelledby="recovery-page-title">
      <div className="activation-mark"><span className="brand-mark" aria-hidden="true">N</span><span>{message(locale, "recovery.public.eyebrow")}</span></div>
      {recovered ? <div className="activation-success recovery-success" role="status" aria-live="polite">
        <span><CheckCircle2 /></span>
        <p className="eyebrow">{message(locale, "recovery.public.restrictedSession")}</p>
        <h1 id="recovery-page-title">{message(locale, "recovery.public.successTitle")}</h1>
        <p>{message(locale, "recovery.public.successBody")}</p>
        <div className="recovery-enrollment-actions">
          <Button type="button" onClick={() => continueEnrollment("passkey-onboarding-title")}><Fingerprint />{message(locale, "recovery.public.continuePasskey")}</Button>
          <Button type="button" variant="outline" onClick={() => continueEnrollment("totp-fallback")}><KeyRound />{message(locale, "recovery.public.continueTotp")}</Button>
        </div>
        <small>{message(locale, "recovery.public.sessionBoundary")}</small>
      </div> : <>
        <div className="form-heading recovery-form-heading"><span className="form-icon"><MonitorSmartphone /></span><h1 id="recovery-page-title">{message(locale, "recovery.public.title")}</h1><p>{message(locale, "recovery.public.description")}</p></div>
        <ol className="recovery-assurance-steps" aria-label={message(locale, "recovery.public.stepsLabel")}>
          <li className="active"><span>1</span><small>{message(locale, "recovery.public.stepProof")}</small></li>
          <li><span>2</span><small>{message(locale, "recovery.public.stepRestricted")}</small></li>
          <li><span>3</span><small>{message(locale, "recovery.public.stepFactor")}</small></li>
        </ol>
        {originGateUrl !== "" && originGateUrl !== "pending"
          ? <Alert role="status" className="mb-5"><ShieldCheck /><AlertTitle>{message(locale, "recovery.public.originTitle")}</AlertTitle><AlertDescription><p>{message(locale, "recovery.public.originBody")}</p><Button asChild className="mt-3" size="sm"><a href={originGateUrl}>{message(locale, "recovery.public.openCanonical")}</a></Button></AlertDescription></Alert>
          : <Alert className="recovery-security-note"><ShieldCheck /><AlertTitle>{message(locale, "recovery.public.securityTitle")}</AlertTitle><AlertDescription>{message(locale, "recovery.public.securityBody")}</AlertDescription></Alert>}
        <form className="auth-form recovery-public-form" onSubmit={submit} noValidate aria-busy={busy}>
          <div className="field-stack">
            <Label htmlFor="initial-admin-recovery-id">{message(locale, "recovery.public.recoveryId")}</Label>
            <Input id="initial-admin-recovery-id" value={recoveryId} onChange={(event) => { setRecoveryId(event.target.value); clearFieldError("recoveryId"); }} disabled={!originReady || busy} autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false} maxLength={36} required aria-invalid={fieldErrors.recoveryId ? true : undefined} aria-describedby={fieldErrors.recoveryId ? "initial-admin-recovery-id-help initial-admin-recovery-id-error" : "initial-admin-recovery-id-help"} />
            <small id="initial-admin-recovery-id-help">{message(locale, "recovery.public.recoveryIdHelp")}</small>
            {fieldErrors.recoveryId && <p id="initial-admin-recovery-id-error" className="form-error">{fieldErrors.recoveryId}</p>}
          </div>
          <div className="field-stack">
            <Label htmlFor="initial-admin-recovery-token">{message(locale, "recovery.public.token")}</Label>
            <div className="recovery-secret-input">
              <Input id="initial-admin-recovery-token" type={showToken ? "text" : "password"} value={token} onChange={(event) => { setToken(event.target.value); clearFieldError("token"); }} disabled={!originReady || busy} autoCapitalize="none" autoCorrect="off" autoComplete="one-time-code" spellCheck={false} minLength={43} maxLength={43} required aria-invalid={fieldErrors.token ? true : undefined} aria-describedby={fieldErrors.token ? "initial-admin-recovery-token-help initial-admin-recovery-token-error" : "initial-admin-recovery-token-help"} />
              <Button type="button" size="icon" variant="ghost" disabled={!token || busy} onClick={() => setShowToken((current) => !current)} aria-label={message(locale, showToken ? "recovery.public.hideToken" : "recovery.public.showToken")} aria-pressed={showToken}>{showToken ? <EyeOff /> : <Eye />}</Button>
            </div>
            <small id="initial-admin-recovery-token-help">{message(locale, "recovery.public.tokenHelp")}</small>
            {fieldErrors.token && <p id="initial-admin-recovery-token-error" className="form-error">{fieldErrors.token}</p>}
          </div>
          {Object.values(fieldErrors).some(Boolean) && <Alert ref={summaryRef} variant="destructive" tabIndex={-1} aria-labelledby="initial-admin-recovery-error-summary-title"><ShieldCheck /><AlertTitle id="initial-admin-recovery-error-summary-title">{message(locale, "a11y.errorSummary", { count: Object.values(fieldErrors).filter(Boolean).length })}</AlertTitle><AlertDescription><ul className="list-disc pl-4">{fieldErrors.recoveryId && <li><a href="#initial-admin-recovery-id">{fieldErrors.recoveryId}</a></li>}{fieldErrors.token && <li><a href="#initial-admin-recovery-token">{fieldErrors.token}</a></li>}</ul></AlertDescription></Alert>}
          {error && <Alert variant="destructive" role="alert"><ShieldCheck /><AlertTitle>{message(locale, "recovery.public.errorTitle")}</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
          <Button className="h-12" type="submit" disabled={!originReady || busy}>{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{busy ? message(locale, "recovery.public.verifying") : message(locale, "recovery.public.submit")}</Button>
          <p className="recovery-privacy-caption">{message(locale, "recovery.public.volatileSecret")}</p>
          <Button asChild type="button" variant="ghost"><Link href={`/${locale}/auth/sign-in`}>{message(locale, "recovery.public.backToSignIn")}</Link></Button>
        </form>
      </>}
    </section>
  </main>;
}

function localizedRecoveryFailure(caught: unknown, locale: Locale): string {
  const generic = message(locale, "recovery.public.errorBody");
  if (!(caught instanceof ApiError)) return generic;
  const base = caught.status === 429
    ? message(locale, "auth.tooManyAttempts")
    : caught.status === 408 || caught.status >= 500
      ? message(locale, "error.transient")
      : generic;
  return caught.requestId ? `${base} (${message(locale, "audit.correlationId", { id: caught.requestId })})` : base;
}
