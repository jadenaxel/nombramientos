import type { MetadataRoute } from "next";
import { getMessage, supportedLocales } from "@nombramientos/i18n";

import type { Locale } from "./api";

export const PWA_MANIFEST_CONTENT_TYPE = "application/manifest+json; charset=utf-8";

export function isPwaManifestLocale(value: string): value is Locale {
  return supportedLocales.some((locale) => locale === value);
}

export function buildPwaManifest(locale: Locale): MetadataRoute.Manifest {
  const appName = getMessage(locale, "app.name");

  return {
    name: appName,
    short_name: appName,
    description: getMessage(locale, "app.tagline"),
    lang: locale,
    id: "/",
    start_url: `/${locale}/auth/sign-in`,
    scope: "/",
    display: "standalone",
    background_color: "#f3f6f9",
    theme_color: "#081b2c",
    orientation: "any",
    categories: ["productivity", "utilities"],
    icons: [
      {
        src: "/favicon.svg",
        sizes: "any",
        type: "image/svg+xml",
        purpose: "any",
      },
    ],
  };
}
