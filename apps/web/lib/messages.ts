import { getMessage, getMessages, supportedLocales } from "@nombramientos/i18n";
import type { Locale } from "./api";

export const locales: readonly Locale[] = supportedLocales;

function createLoginMessages(locale: Locale) {
  return {
    signIn: getMessage(locale, "auth.signIn"),
    email: getMessage(locale, "auth.email"),
    password: getMessage(locale, "auth.password"),
    continue: getMessage(locale, "common.continue"),
    mfa: getMessage(locale, "auth.mfaTitle"),
    mfaHelp: getMessage(locale, "auth.mfaHelp"),
    code: getMessage(locale, "auth.mfaCode"),
    verify: getMessage(locale, "auth.verifyAndSignIn"),
    back: getMessage(locale, "common.back"),
    useRecovery: getMessage(locale, "auth.useRecovery"),
    useAuthenticator: getMessage(locale, "auth.useAuthenticator"),
    recoveryCode: getMessage(locale, "auth.recoveryCode"),
    recoveryHelp: getMessage(locale, "auth.recoveryHelp"),
    privateSpace: getMessage(locale, "auth.privateSpace"),
    demo: getMessage(locale, "app.demoBadge"),
    security: getMessage(locale, "auth.security"),
    unavailable: getMessage(locale, "error.transient"),
    storyEyebrow: getMessage(locale, "auth.storyEyebrow"),
    storyBody: getMessage(locale, "auth.storyBody"),
    isolationTitle: getMessage(locale, "auth.isolationTitle"),
    isolationBody: getMessage(locale, "auth.isolationBody"),
    encryptedTitle: getMessage(locale, "auth.encryptedTitle"),
    encryptedBody: getMessage(locale, "auth.encryptedBody"),
    postgresTitle: getMessage(locale, "auth.postgresTitle"),
    postgresBody: getMessage(locale, "auth.postgresBody"),
    language: getMessage(locale, "auth.language"),
    minPassword: getMessage(locale, "auth.minimumPasswordLength"),
    signInError: getMessage(locale, "auth.signInError"),
    verificationRejected: getMessage(locale, "auth.verificationRejected"),
    invitation: getMessage(locale, "auth.acceptInvitation"),
    legal: getMessage(locale, "auth.legalNotice"),
  };
}

export const messages: Readonly<Record<Locale, ReturnType<typeof createLoginMessages>>> = {
  es: createLoginMessages("es"),
  en: createLoginMessages("en"),
  fr: createLoginMessages("fr"),
};

function nestMessages(flat: Readonly<Record<string, string>>) {
  const nested: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(flat)) {
    const parts = key.split(".");
    let cursor = nested;
    for (let index = 0; index < parts.length - 1; index += 1) {
      const part = parts[index];
      if (!cursor[part] || typeof cursor[part] !== "object") cursor[part] = {};
      cursor = cursor[part] as Record<string, unknown>;
    }
    cursor[parts.at(-1)!] = value;
  }
  return nested;
}

export const intlMessages = {
  es: nestMessages(getMessages("es")),
  en: nestMessages(getMessages("en")),
  fr: nestMessages(getMessages("fr")),
};

export function isLocale(value: string): value is Locale { return locales.includes(value as Locale); }
