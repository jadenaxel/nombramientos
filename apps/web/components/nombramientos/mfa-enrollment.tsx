"use client";

import Image from "next/image";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { Check, Clipboard, ExternalLink, KeyRound, LoaderCircle, QrCode, RotateCcw, ShieldCheck, Smartphone } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import {
  api,
  ApiError,
  setCsrfToken,
  type AuthenticatedSession,
  type Locale,
  type MfaEnrollmentStarted,
} from "@/lib/api";
import { message, localizedApiError } from "@/lib/product-i18n";
import { appLandingPath } from "@/lib/app-navigation";
import { scheduleMfaEnrollmentExpiry } from "@/lib/mfa-enrollment-lifetime";
import { isTotpEnrollmentRequired } from "@/lib/mfa-enrollment-requirement";
import { validatedTotpEnrollmentUri } from "@/lib/totp-enrollment";

const copy = {
  es: {
    eyebrow: message("es", "screen.mfaEnrollment.b8ff62e3c47b"), title: message("es", "screen.mfaEnrollment.79121ac8e67b"), required: message("es", "screen.mfaEnrollment.9717d831f28e"), optional: message("es", "screen.mfaEnrollment.a14b54afe510"), start: message("es", "screen.mfaEnrollment.871a15da1131"), rotate: message("es", "screen.mfaEnrollment.8ce529c68ced"), once: message("es", "screen.mfaEnrollment.14c10268c403"), onceBody: message("es", "screen.mfaEnrollment.7d676afcb377"), manual: message("es", "screen.mfaEnrollment.f3932e4c0f05"), uri: message("es", "screen.mfaEnrollment.ca3d99fe9878"), copied: message("es", "screen.mfaEnrollment.2b46f63d1ecb"), copyFailed: message("es", "screen.mfaEnrollment.bdad151cc636"), code: message("es", "screen.mfaEnrollment.2eb572ed4d27"), confirm: message("es", "screen.mfaEnrollment.8719d13c14be"), cancel: message("es", "screen.mfaEnrollment.19862510d1f9"), recoveryTitle: message("es", "screen.mfaEnrollment.3c0450a79a92"), recoveryBody: message("es", "screen.mfaEnrollment.4f7225e10e85"), copyCodes: message("es", "screen.mfaEnrollment.bc94f7eb6f45"), saved: message("es", "screen.mfaEnrollment.93c2b6aef7b4"), active: message("es", "screen.mfaEnrollment.f2241b23513f"), activeBody: message("es", "screen.mfaEnrollment.f04ebbac542c"), error: message("es", "screen.mfaEnrollment.429b18f92d5d"), retry: message("es", "screen.mfaEnrollment.edc22f0e3ecb"), expires: message("es", "screen.mfaEnrollment.c2aa58fce2d8"), noPrivileges: message("es", "screen.mfaEnrollment.bda0aa6ca170"),
  },
  en: {
    eyebrow: message("en", "screen.mfaEnrollment.b8ff62e3c47b"), title: message("en", "screen.mfaEnrollment.79121ac8e67b"), required: message("en", "screen.mfaEnrollment.9717d831f28e"), optional: message("en", "screen.mfaEnrollment.a14b54afe510"), start: message("en", "screen.mfaEnrollment.871a15da1131"), rotate: message("en", "screen.mfaEnrollment.8ce529c68ced"), once: message("en", "screen.mfaEnrollment.14c10268c403"), onceBody: message("en", "screen.mfaEnrollment.7d676afcb377"), manual: message("en", "screen.mfaEnrollment.f3932e4c0f05"), uri: message("en", "screen.mfaEnrollment.ca3d99fe9878"), copied: message("en", "screen.mfaEnrollment.2b46f63d1ecb"), copyFailed: message("en", "screen.mfaEnrollment.bdad151cc636"), code: message("en", "screen.mfaEnrollment.2eb572ed4d27"), confirm: message("en", "screen.mfaEnrollment.8719d13c14be"), cancel: message("en", "screen.mfaEnrollment.19862510d1f9"), recoveryTitle: message("en", "screen.mfaEnrollment.3c0450a79a92"), recoveryBody: message("en", "screen.mfaEnrollment.4f7225e10e85"), copyCodes: message("en", "screen.mfaEnrollment.bc94f7eb6f45"), saved: message("en", "screen.mfaEnrollment.93c2b6aef7b4"), active: message("en", "screen.mfaEnrollment.f2241b23513f"), activeBody: message("en", "screen.mfaEnrollment.f04ebbac542c"), error: message("en", "screen.mfaEnrollment.429b18f92d5d"), retry: message("en", "screen.mfaEnrollment.edc22f0e3ecb"), expires: message("en", "screen.mfaEnrollment.c2aa58fce2d8"), noPrivileges: message("en", "screen.mfaEnrollment.bda0aa6ca170"),
  },
  fr: {
    eyebrow: message("fr", "screen.mfaEnrollment.b8ff62e3c47b"), title: message("fr", "screen.mfaEnrollment.79121ac8e67b"), required: message("fr", "screen.mfaEnrollment.9717d831f28e"), optional: message("fr", "screen.mfaEnrollment.a14b54afe510"), start: message("fr", "screen.mfaEnrollment.871a15da1131"), rotate: message("fr", "screen.mfaEnrollment.8ce529c68ced"), once: message("fr", "screen.mfaEnrollment.14c10268c403"), onceBody: message("fr", "screen.mfaEnrollment.7d676afcb377"), manual: message("fr", "screen.mfaEnrollment.f3932e4c0f05"), uri: message("fr", "screen.mfaEnrollment.ca3d99fe9878"), copied: message("fr", "screen.mfaEnrollment.2b46f63d1ecb"), copyFailed: message("fr", "screen.mfaEnrollment.bdad151cc636"), code: message("fr", "screen.mfaEnrollment.2eb572ed4d27"), confirm: message("fr", "screen.mfaEnrollment.8719d13c14be"), cancel: message("fr", "screen.mfaEnrollment.19862510d1f9"), recoveryTitle: message("fr", "screen.mfaEnrollment.3c0450a79a92"), recoveryBody: message("fr", "screen.mfaEnrollment.4f7225e10e85"), copyCodes: message("fr", "screen.mfaEnrollment.bc94f7eb6f45"), saved: message("fr", "screen.mfaEnrollment.93c2b6aef7b4"), active: message("fr", "screen.mfaEnrollment.f2241b23513f"), activeBody: message("fr", "screen.mfaEnrollment.f04ebbac542c"), error: message("fr", "screen.mfaEnrollment.429b18f92d5d"), retry: message("fr", "screen.mfaEnrollment.edc22f0e3ecb"), expires: message("fr", "screen.mfaEnrollment.c2aa58fce2d8"), noPrivileges: message("fr", "screen.mfaEnrollment.bda0aa6ca170"),
  },
} as const;

const continuityCopy = {
  es: { open: "Abrir mi aplicación autenticadora", qr: "Código QR local para configurar el autenticador", resume: "Continuar verificación", resumeBody: "La semilla no se guardó en este navegador. Introduce el código de la aplicación que configuraste; si no terminaste, cancela y comienza de nuevo.", qrHelp: "Escanéalo únicamente desde otro dispositivo. Si estás en este teléfono, usa el botón para abrir el autenticador.", generateQrError: "No fue posible generar el QR local. Usa la clave manual.", setup: "Configurar en este dispositivo" },
  en: { open: "Open my authenticator app", qr: "Locally generated QR code for authenticator setup", resume: "Continue verification", resumeBody: "The seed was not stored in this browser. Enter the code from the app you configured; if setup was not completed, cancel and start again.", qrHelp: "Scan it only from another device. If you are on this phone, use the button to open the authenticator.", generateQrError: "The local QR could not be generated. Use the manual key.", setup: "Set up on this device" },
  fr: { open: "Ouvrir mon application d’authentification", qr: "Code QR généré localement pour configurer l’authentificateur", resume: "Continuer la vérification", resumeBody: "La graine n’a pas été stockée dans ce navigateur. Saisissez le code de l’application configurée ; si la configuration est incomplète, annulez et recommencez.", qrHelp: "Scannez-le uniquement depuis un autre appareil. Si vous êtes sur ce téléphone, utilisez le bouton pour ouvrir l’authentificateur.", generateQrError: "Impossible de générer le QR local. Utilisez la clé manuelle.", setup: "Configurer sur cet appareil" },
} as const;

const pendingEnrollmentStorageKey = "nombramientos.mfa-enrollment.v1";
const pendingEnrollmentEvent = "nombramientos:mfa-enrollment";
type PendingEnrollmentReference = Pick<MfaEnrollmentStarted, "enrollmentId" | "expiresAt">;

function savePendingEnrollment(reference: PendingEnrollmentReference | undefined) {
  if (typeof window === "undefined") return;
  if (!reference) sessionStorage.removeItem(pendingEnrollmentStorageKey);
  else sessionStorage.setItem(pendingEnrollmentStorageKey, JSON.stringify(reference));
  window.dispatchEvent(new Event(pendingEnrollmentEvent));
}

function subscribePendingEnrollment(callback: () => void) {
  window.addEventListener("storage", callback);
  window.addEventListener(pendingEnrollmentEvent, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(pendingEnrollmentEvent, callback);
  };
}

function pendingEnrollmentSnapshot() {
  return sessionStorage.getItem(pendingEnrollmentStorageKey);
}

export function MfaEnrollmentPanel({
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
  const [started, setStarted] = useState<MfaEnrollmentStarted>();
  const pendingValue = useSyncExternalStore(subscribePendingEnrollment, pendingEnrollmentSnapshot, () => null);
  const pendingReference = useMemo<PendingEnrollmentReference | undefined>(() => {
    if (!pendingValue) return undefined;
    try {
      const parsed = JSON.parse(pendingValue) as Partial<PendingEnrollmentReference>;
      if (typeof parsed.enrollmentId !== "string" || typeof parsed.expiresAt !== "string" || !Number.isFinite(Date.parse(parsed.expiresAt))) return undefined;
      return { enrollmentId: parsed.enrollmentId, expiresAt: parsed.expiresAt };
    } catch { return undefined; }
  }, [pendingValue]);
  const [qr, setQr] = useState<{ uri: string; dataUrl: string }>();
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>();
  const [completedSession, setCompletedSession] = useState<AuthenticatedSession>();
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<"secret" | "uri" | "codes">();
  const [error, setError] = useState<string>();
  const continuity = continuityCopy[locale];
  const activeEnrollment = started ?? pendingReference;
  const activeEnrollmentId = activeEnrollment?.enrollmentId;
  const activeEnrollmentExpiresAt = activeEnrollment?.expiresAt;
  const safeOtpAuthUri = useMemo(() => started ? validatedTotpEnrollmentUri(started) : undefined, [started]);
  const setupIntegrityError = started && !safeOtpAuthUri ? continuity.generateQrError : undefined;
  const totpEnrollmentRequired = isTotpEnrollmentRequired(requiredGate, session.security);

  useEffect(() => {
    if (pendingValue && !pendingReference) savePendingEnrollment(undefined);
  }, [pendingReference, pendingValue]);

  useEffect(() => {
    if (!activeEnrollmentId || !activeEnrollmentExpiresAt) return;
    return scheduleMfaEnrollmentExpiry(activeEnrollmentExpiresAt, () => {
      setStarted(undefined);
      setQr(undefined);
      setCode("");
      setCopied(undefined);
      savePendingEnrollment(undefined);
      // Expiry is locally authoritative for secret removal. Cancellation is
      // best-effort because the server also rejects the expired enrollment.
      void api.cancelMfaEnrollment(activeEnrollmentId).catch(() => undefined);
    });
  }, [activeEnrollmentExpiresAt, activeEnrollmentId]);

  useEffect(() => {
    const concealSecrets = () => {
      if (document.visibilityState !== "hidden") return;
      // Moving from a phone browser to an authenticator app must not leave the
      // TOTP seed, URI-derived QR, or partially entered code in the page tree.
      setStarted(undefined);
      setQr(undefined);
      setCode("");
      setCopied(undefined);
    };
    document.addEventListener("visibilitychange", concealSecrets);
    return () => document.removeEventListener("visibilitychange", concealSecrets);
  }, []);

  useEffect(() => {
    const purgeOnPageExit = () => {
      // `pagehide` also covers bfcache: a back navigation must never restore a
      // rendered TOTP seed, QR payload, partial OTP, or recovery-code sheet.
      setStarted(undefined);
      setQr(undefined);
      setCode("");
      setCopied(undefined);
      setRecoveryCodes(undefined);
      setCompletedSession(undefined);
    };
    window.addEventListener("pagehide", purgeOnPageExit);
    return () => window.removeEventListener("pagehide", purgeOnPageExit);
  }, []);

  useEffect(() => {
    if (!started || !safeOtpAuthUri) return;
    let active = true;
    void import("qrcode").then(({ toDataURL }) => toDataURL(safeOtpAuthUri, {
      errorCorrectionLevel: "M",
      margin: 2,
      width: 240,
      color: { dark: "#082b3d", light: "#ffffff" },
    })).then((dataUrl) => { if (active) setQr({ uri: safeOtpAuthUri, dataUrl }); }).catch(() => {
      if (active) setError(continuity.generateQrError);
    });
    return () => { active = false; };
  }, [continuity.generateQrError, safeOtpAuthUri, started]);

  async function copyValue(value: string, kind: "secret" | "uri" | "codes") {
    setError(undefined);
    try {
      await navigator.clipboard.writeText(value);
      setCopied(kind);
      window.setTimeout(() => setCopied(undefined), 1_500);
    } catch {
      setCopied(undefined);
      setError(text.copyFailed);
    }
  }

  async function begin() {
    setBusy(true); setError(undefined); setRecoveryCodes(undefined); setQr(undefined);
    try {
      const enrollment = await api.startMfaEnrollment();
      if (!validatedTotpEnrollmentUri(enrollment)) {
        // Reject malformed server material before it can enter resumable state,
        // the QR encoder, the DOM, or the clipboard surface.
        setStarted(undefined); setQr(undefined); setCode(""); setCopied(undefined);
        savePendingEnrollment(undefined);
        setError(continuity.generateQrError);
        void api.cancelMfaEnrollment(enrollment.enrollmentId).catch(() => undefined);
        return;
      }
      setStarted(enrollment);
      savePendingEnrollment({ enrollmentId: enrollment.enrollmentId, expiresAt: enrollment.expiresAt });
    }
    catch (caught) { setError(caught instanceof ApiError ? `${localizedApiError(caught, locale)} ${text.retry}` : text.error); }
    finally { setBusy(false); }
  }

  async function cancel() {
    if (!activeEnrollment) return;
    const enrollmentId = activeEnrollment.enrollmentId;
    setBusy(true); setError(undefined);
    try {
      await api.cancelMfaEnrollment(enrollmentId);
    } catch (caught) { setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.error); }
    finally {
      setStarted(undefined); setQr(undefined); setCode(""); setCopied(undefined);
      savePendingEnrollment(undefined);
      setBusy(false);
    }
  }

  async function confirm(event: React.FormEvent) {
    event.preventDefault();
    if (!activeEnrollment || code.length !== 6 || (started && !safeOtpAuthUri)) return;
    setBusy(true); setError(undefined);
    try {
      const result = await api.confirmMfaEnrollment(activeEnrollment.enrollmentId, code);
      const { recoveryCodes: issuedCodes, ...safeSession } = result;
      setCsrfToken(result.csrfToken);
      // Keep the enrollment-only shell mounted until the user has had a chance
      // to save the one-time recovery codes. Only the secret-free session is
      // retained, and it is promoted into the shared cache on acknowledgement.
      setCompletedSession(safeSession);
      setRecoveryCodes([...issuedCodes]);
      setStarted(undefined); setQr(undefined); setCode(""); setCopied(undefined);
      savePendingEnrollment(undefined);
    } catch (caught) {
      if (caught instanceof ApiError && [400, 404, 409, 410].includes(caught.status)) {
        setStarted(undefined); setQr(undefined); setCode(""); setCopied(undefined);
        savePendingEnrollment(undefined);
      }
      setError(caught instanceof ApiError ? localizedApiError(caught, locale) : text.error);
    }
    finally { setBusy(false); }
  }

  if (recoveryCodes) {
    return <section className="surface-card mx-auto max-w-3xl" aria-live="polite">
      <div className="form-heading"><span className="form-icon"><KeyRound /></span><p className="eyebrow">{text.eyebrow}</p><h2>{text.recoveryTitle}</h2><p>{text.recoveryBody}</p></div>
      <ol className="my-6 grid gap-2 rounded-2xl border bg-slate-950 p-5 font-mono text-sm text-cyan-50 sm:grid-cols-2" aria-label={text.recoveryTitle}>
        {recoveryCodes.map((item, index) => <li key={item} className="flex gap-3"><span className="text-slate-300">{String(index + 1).padStart(2, "0")}</span><code>{item}</code></li>)}
      </ol>
      {error && <Alert variant="destructive" className="mb-4" role="alert"><ShieldCheck /><AlertTitle>{text.error}</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
      <div className="button-row">
        <Button type="button" variant="outline" onClick={() => void copyValue(recoveryCodes.join("\n"), "codes")}><Clipboard />{copied === "codes" ? text.copied : text.copyCodes}</Button>
        <Button type="button" onClick={() => {
          if (completedSession) queryClient.setQueryData(["session"], completedSession);
          setCompletedSession(undefined); setRecoveryCodes(undefined);
          void queryClient.invalidateQueries({ queryKey: ["session"] });
          router.replace(appLandingPath(locale, completedSession?.permissions ?? session.permissions));
          router.refresh();
        }}><Check />{text.saved}</Button>
      </div>
    </section>;
  }

  return <section className="surface-card mx-auto max-w-3xl">
    <div className="card-heading"><div><p className="eyebrow">{text.eyebrow}</p><h2 className="text-2xl font-bold">{text.title}</h2></div><Badge variant={session.security.mfaEnabled ? "default" : "outline"}>{session.security.mfaEnabled ? text.active : "TOTP"}</Badge></div>
    <p className="mt-3 text-sm text-slate-600">{totpEnrollmentRequired ? text.required : text.optional}</p>
    {totpEnrollmentRequired && <Alert className="mt-5"><ShieldCheck /><AlertTitle>{text.required}</AlertTitle><AlertDescription>{text.noPrivileges}</AlertDescription></Alert>}
    {session.security.mfaEnabled && !activeEnrollment && <Alert className="mt-5"><ShieldCheck /><AlertTitle>{text.active}</AlertTitle><AlertDescription>{text.activeBody}</AlertDescription></Alert>}
    {(error ?? setupIntegrityError) && <Alert variant="destructive" className="mt-5" role="alert"><ShieldCheck /><AlertTitle>{text.error}</AlertTitle><AlertDescription>{error ?? setupIntegrityError}</AlertDescription></Alert>}

    {!activeEnrollment ? <Button className="mt-6" type="button" disabled={busy} onClick={() => void begin()}>{busy ? <LoaderCircle className="animate-spin" /> : session.security.mfaEnabled ? <RotateCcw /> : <Smartphone />}{session.security.mfaEnabled ? text.rotate : text.start}</Button> : <div className="mt-6 space-y-5">
      <Alert><KeyRound /><AlertTitle>{text.once}</AlertTitle><AlertDescription>{text.onceBody} {text.expires}</AlertDescription></Alert>
      {pendingReference && !started && <Alert><RotateCcw /><AlertTitle>{continuity.resume}</AlertTitle><AlertDescription>{continuity.resumeBody}</AlertDescription></Alert>}
      {started && safeOtpAuthUri && <div className="totp-setup-grid rounded-2xl border bg-slate-50 p-5">
        <div>
        <Label>{text.manual}</Label>
        <div className="mt-2 flex flex-wrap items-center gap-3"><code className="break-all rounded-lg bg-white px-3 py-2 font-mono text-sm font-bold tracking-widest">{started.secret.match(/.{1,4}/g)?.join(" ")}</code><Button size="sm" type="button" variant="outline" onClick={() => void copyValue(started.secret, "secret")}><Clipboard />{copied === "secret" ? text.copied : text.manual}</Button></div>
        <div className="button-row mt-3"><Button asChild size="sm"><a href={safeOtpAuthUri}><ExternalLink />{continuity.open}</a></Button><Button size="sm" type="button" variant="outline" onClick={() => void copyValue(safeOtpAuthUri, "uri")}><Clipboard />{copied === "uri" ? text.copied : text.uri}</Button></div>
        </div>
        <div className="totp-qr-panel"><span><QrCode />{continuity.setup}</span>{qr?.uri === safeOtpAuthUri ? <Image unoptimized src={qr.dataUrl} width={240} height={240} alt={continuity.qr} /> : <span className="totp-qr-loading" role="status"><LoaderCircle className="animate-spin" /></span>}<small>{continuity.qrHelp}</small></div>
      </div>}
      <form className="space-y-4" onSubmit={confirm}>
        <Label htmlFor="mfa-enrollment-code">{text.code}</Label>
        <InputOTP id="mfa-enrollment-code" maxLength={6} inputMode="numeric" value={code} onChange={setCode} containerClassName="justify-start">
          <InputOTPGroup>{Array.from({ length: 6 }, (_, index) => <InputOTPSlot key={index} index={index} className="h-12 w-12 text-lg" />)}</InputOTPGroup>
        </InputOTP>
        <div className="button-row"><Button disabled={busy || code.length !== 6 || Boolean(started && !safeOtpAuthUri)} type="submit">{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{text.confirm}</Button><Button disabled={busy} type="button" variant="ghost" onClick={() => void cancel()}>{text.cancel}</Button></div>
      </form>
    </div>}
  </section>;
}
