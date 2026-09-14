"use client";

import { message } from "@/lib/product-i18n";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState, useSyncExternalStore } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, ServerCog, ShieldCheck } from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, apiRequest, setCsrfToken, type AuthenticatedSession, type Locale } from "@/lib/api";

const copy = {
  es: { eyebrow: message("es", "screen.platformBootstrapForm.f0c747f52277"), title: message("es", "screen.platformBootstrapForm.5cc1eeead70a"), description: message("es", "screen.platformBootstrapForm.ee8880391aea"), token: message("es", "screen.platformBootstrapForm.0f0e18d1ce9f"), email: message("es", "screen.platformBootstrapForm.842a9a1a4778"), name: message("es", "screen.platformBootstrapForm.19c1f3652481"), password: message("es", "screen.platformBootstrapForm.1218c673b613"), passwordHelp: message("es", "screen.platformBootstrapForm.6f5ba4c4fefa"), submit: message("es", "screen.platformBootstrapForm.54e032bbf9f4"), gate: message("es", "screen.platformBootstrapForm.94739167bee1"), gateBody: message("es", "screen.platformBootstrapForm.168d5e6d2028"), error: message("es", "screen.platformBootstrapForm.9209fca70865"), signIn: message("es", "screen.platformBootstrapForm.4b0ee4b2a4ce") },
  en: { eyebrow: message("en", "screen.platformBootstrapForm.f0c747f52277"), title: message("en", "screen.platformBootstrapForm.5cc1eeead70a"), description: message("en", "screen.platformBootstrapForm.ee8880391aea"), token: message("en", "screen.platformBootstrapForm.0f0e18d1ce9f"), email: message("en", "screen.platformBootstrapForm.842a9a1a4778"), name: message("en", "screen.platformBootstrapForm.19c1f3652481"), password: message("en", "screen.platformBootstrapForm.1218c673b613"), passwordHelp: message("en", "screen.platformBootstrapForm.6f5ba4c4fefa"), submit: message("en", "screen.platformBootstrapForm.54e032bbf9f4"), gate: message("en", "screen.platformBootstrapForm.94739167bee1"), gateBody: message("en", "screen.platformBootstrapForm.168d5e6d2028"), error: message("en", "screen.platformBootstrapForm.9209fca70865"), signIn: message("en", "screen.platformBootstrapForm.4b0ee4b2a4ce") },
  fr: { eyebrow: message("fr", "screen.platformBootstrapForm.f0c747f52277"), title: message("fr", "screen.platformBootstrapForm.5cc1eeead70a"), description: message("fr", "screen.platformBootstrapForm.ee8880391aea"), token: message("fr", "screen.platformBootstrapForm.0f0e18d1ce9f"), email: message("fr", "screen.platformBootstrapForm.842a9a1a4778"), name: message("fr", "screen.platformBootstrapForm.19c1f3652481"), password: message("fr", "screen.platformBootstrapForm.1218c673b613"), passwordHelp: message("fr", "screen.platformBootstrapForm.6f5ba4c4fefa"), submit: message("fr", "screen.platformBootstrapForm.54e032bbf9f4"), gate: message("fr", "screen.platformBootstrapForm.94739167bee1"), gateBody: message("fr", "screen.platformBootstrapForm.168d5e6d2028"), error: message("fr", "screen.platformBootstrapForm.9209fca70865"), signIn: message("fr", "screen.platformBootstrapForm.4b0ee4b2a4ce") },
} as const;

type BootstrapSession = AuthenticatedSession & { contentAccess: false; keyAccess: false };
type BootstrapField = "token" | "email" | "displayName" | "password";
type BootstrapErrors = Partial<Record<BootstrapField, string>>;

const emailPattern = /^[^\s@]+@[^\s@]+$/u;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/u;
const subscribeToHydration = () => () => undefined;
const hydratedClientSnapshot = () => true;
const hydratedServerSnapshot = () => false;
const commonPasswords = new Set([
  "password123!", "contraseña123!", "administrador123!", "nombramientos123!",
]);

function passwordMatchesPolicy(password: string, email: string, displayName: string): boolean {
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

function localizedBootstrapError(error: unknown, locale: Locale, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback;
  const base = error.status === 429
    ? message(locale, "auth.tooManyAttempts")
    : error.status === 408 || error.status >= 500
      ? message(locale, "error.transient")
      : fallback;
  return error.requestId ? `${base} (${message(locale, "audit.correlationId", { id: error.requestId })})` : base;
}

export function PlatformBootstrapForm({ locale }: { locale: Locale }) {
  const text = copy[locale];
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [fieldErrors, setFieldErrors] = useState<BootstrapErrors>({});
  const hydrated = useSyncExternalStore(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot);
  const validationSummaryRef = useRef<HTMLDivElement>(null);
  const fieldErrorCount = Object.values(fieldErrors).filter(Boolean).length;

  function clearFieldError(field: BootstrapField) {
    setFieldErrors((current) => ({ ...current, [field]: undefined }));
    setError(undefined);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const normalizedToken = token.trim();
    const normalizedEmail = email.trim();
    const normalizedDisplayName = displayName.trim();
    const nextErrors: BootstrapErrors = {};
    const required = message(locale, "a11y.requiredField");
    const invalid = message(locale, "error.validation");
    if (!normalizedToken) nextErrors.token = `${text.token}: ${required}`;
    else if (!tokenPattern.test(normalizedToken)) nextErrors.token = `${text.token}: ${invalid}`;
    if (!normalizedEmail) nextErrors.email = `${text.email}: ${required}`;
    else if (!emailPattern.test(normalizedEmail) || normalizedEmail.length > 320) nextErrors.email = `${text.email}: ${invalid}`;
    if (!normalizedDisplayName) nextErrors.displayName = `${text.name}: ${required}`;
    else if (normalizedDisplayName.length < 2 || normalizedDisplayName.length > 120 || /[\p{Cc}\p{Cf}]/u.test(normalizedDisplayName)) nextErrors.displayName = `${text.name}: ${invalid}`;
    if (!password) nextErrors.password = `${text.password}: ${required}`;
    else if (!passwordMatchesPolicy(password, normalizedEmail, normalizedDisplayName)) nextErrors.password = `${text.password}: ${text.passwordHelp}`;

    if (Object.keys(nextErrors).length > 0) {
      setPassword("");
      setFieldErrors(nextErrors);
      setError(undefined);
      requestAnimationFrame(() => validationSummaryRef.current?.focus());
      return;
    }

    const submitted = { token: normalizedToken, email: normalizedEmail, displayName: normalizedDisplayName, password };
    setPassword("");
    setFieldErrors({});
    setBusy(true);
    setError(undefined);
    vault.lock();
    queryClient.clear();
    setCsrfToken(undefined);
    try {
      const session = await apiRequest<BootstrapSession>("/v1/auth/platform-bootstrap/accept", {
        method: "POST",
        body: JSON.stringify(submitted),
      });
      setToken("");
      setEmail("");
      setDisplayName("");
      setCsrfToken(session.csrfToken);
      queryClient.setQueryData(["session"], session);
      router.replace(`/${locale}/app/settings`);
      router.refresh();
    } catch (caught) {
      setToken("");
      setError(localizedBootstrapError(caught, locale, text.error));
    } finally {
      setBusy(false);
    }
  }

  return <main className="activation-shell" id="main-content" tabIndex={-1}><section className="activation-card">
    <div className="activation-mark"><span className="brand-mark">N</span><span>{text.eyebrow}</span></div>
    <div className="form-heading"><span className="form-icon"><ServerCog /></span><h1>{text.title}</h1><p>{text.description}</p></div>
    <Alert className="my-5"><ShieldCheck /><AlertTitle>{text.gate}</AlertTitle><AlertDescription>{text.gateBody}</AlertDescription></Alert>
    <form className="auth-form" onSubmit={submit} noValidate>
      <div className="field-stack"><Label htmlFor="platform-bootstrap-token">{text.token}</Label><Input id="platform-bootstrap-token" value={token} onChange={(event) => { setToken(event.target.value); clearFieldError("token"); }} disabled={!hydrated || busy} minLength={43} maxLength={43} autoComplete="one-time-code" required aria-invalid={fieldErrors.token ? true : undefined} aria-describedby={fieldErrors.token ? "platform-bootstrap-token-error" : undefined} />{fieldErrors.token && <p id="platform-bootstrap-token-error" className="form-error">{fieldErrors.token}</p>}</div>
      <div className="field-stack"><Label htmlFor="platform-bootstrap-email">{text.email}</Label><Input id="platform-bootstrap-email" type="email" value={email} onChange={(event) => { setEmail(event.target.value); clearFieldError("email"); }} disabled={!hydrated || busy} autoComplete="email" maxLength={320} required aria-invalid={fieldErrors.email ? true : undefined} aria-describedby={fieldErrors.email ? "platform-bootstrap-email-error" : undefined} />{fieldErrors.email && <p id="platform-bootstrap-email-error" className="form-error">{fieldErrors.email}</p>}</div>
      <div className="field-stack"><Label htmlFor="platform-bootstrap-name">{text.name}</Label><Input id="platform-bootstrap-name" value={displayName} onChange={(event) => { setDisplayName(event.target.value); clearFieldError("displayName"); }} disabled={!hydrated || busy} autoComplete="name" minLength={2} maxLength={120} required aria-invalid={fieldErrors.displayName ? true : undefined} aria-describedby={fieldErrors.displayName ? "platform-bootstrap-name-error" : undefined} />{fieldErrors.displayName && <p id="platform-bootstrap-name-error" className="form-error">{fieldErrors.displayName}</p>}</div>
      <div className="field-stack"><Label htmlFor="platform-bootstrap-password">{text.password}</Label><Input id="platform-bootstrap-password" type="password" value={password} onChange={(event) => { setPassword(event.target.value); clearFieldError("password"); }} disabled={!hydrated || busy} autoComplete="new-password" minLength={14} maxLength={256} required aria-invalid={fieldErrors.password ? true : undefined} aria-describedby={fieldErrors.password ? "platform-bootstrap-password-help platform-bootstrap-password-error" : "platform-bootstrap-password-help"} /><small id="platform-bootstrap-password-help">{text.passwordHelp}</small>{fieldErrors.password && <p id="platform-bootstrap-password-error" className="form-error">{fieldErrors.password}</p>}</div>
      {fieldErrorCount > 0 && <Alert ref={validationSummaryRef} variant="destructive" tabIndex={-1} aria-labelledby="platform-bootstrap-error-summary-title"><ShieldCheck /><AlertTitle id="platform-bootstrap-error-summary-title">{message(locale, "a11y.errorSummary", { count: fieldErrorCount })}</AlertTitle><AlertDescription><ul className="list-disc pl-4">{fieldErrors.token && <li><a href="#platform-bootstrap-token">{fieldErrors.token}</a></li>}{fieldErrors.email && <li><a href="#platform-bootstrap-email">{fieldErrors.email}</a></li>}{fieldErrors.displayName && <li><a href="#platform-bootstrap-name">{fieldErrors.displayName}</a></li>}{fieldErrors.password && <li><a href="#platform-bootstrap-password">{fieldErrors.password}</a></li>}</ul></AlertDescription></Alert>}
      {error && <Alert variant="destructive"><KeyRound /><AlertTitle>{text.error}</AlertTitle><AlertDescription>{text.description}</AlertDescription></Alert>}
      <Button className="h-12" type="submit" disabled={!hydrated || busy}>{busy ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{text.submit}</Button>
      <Button asChild type="button" variant="ghost"><Link href={`/${locale}/auth/sign-in`}>{text.signIn}</Link></Button>
    </form>
  </section></main>;
}
