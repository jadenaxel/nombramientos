export type Locale = "es" | "en" | "fr";

export interface LocaleMetadata {
  readonly locale: Locale;
  readonly label: string;
  readonly htmlLang: string;
  readonly defaultDateLocale: string;
  readonly textDirection: "ltr" | "rtl";
}

export const supportedLocales: readonly Locale[] = ["es", "en", "fr"];

export const localeMetadata: Readonly<Record<Locale, LocaleMetadata>> = {
  es: { locale: "es", label: "Español", htmlLang: "es", defaultDateLocale: "es-DO", textDirection: "ltr" },
  en: { locale: "en", label: "English", htmlLang: "en", defaultDateLocale: "en", textDirection: "ltr" },
  fr: { locale: "fr", label: "Français", htmlLang: "fr", defaultDateLocale: "fr", textDirection: "ltr" },
};

export const defaultTenantTimeZone = "America/Santo_Domingo";
