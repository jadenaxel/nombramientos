import assert from "node:assert/strict";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

import fallbackManifest from "../app/manifest.ts";
import { GET } from "../app/[locale]/manifest.webmanifest/route.ts";
import {
  buildPwaManifest,
  isPwaManifestLocale,
  PWA_MANIFEST_CONTENT_TYPE,
} from "./pwa-manifest.ts";

for (const locale of ["es", "en", "fr"] as const) {
  test(`builds and serves the ${locale} PWA manifest from the localized catalogs`, async () => {
    const expected = buildPwaManifest(locale);

    assert.equal(expected.name, getMessage(locale, "app.name"));
    assert.equal(expected.short_name, getMessage(locale, "app.name"));
    assert.equal(expected.description, getMessage(locale, "app.tagline"));
    assert.equal(expected.lang, locale);
    assert.equal(expected.start_url, `/${locale}/auth/sign-in`);
    assert.equal(expected.id, "/");
    assert.equal(expected.scope, "/");
    assert.deepEqual(expected.icons, [{
      src: "/favicon.svg",
      sizes: "any",
      type: "image/svg+xml",
      purpose: "any",
    }]);

    const response = await GET(
      new Request(`http://localhost/${locale}/manifest.webmanifest`),
      { params: Promise.resolve({ locale }) },
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), PWA_MANIFEST_CONTENT_TYPE);
    assert.deepEqual(await response.json(), expected);
  });
}

test("keeps the root special manifest as the Spanish fallback", () => {
  assert.deepEqual(fallbackManifest(), buildPwaManifest("es"));
});

test("rejects unsupported localized manifest routes", async () => {
  assert.equal(isPwaManifestLocale("pt"), false);
  const response = await GET(
    new Request("http://localhost/pt/manifest.webmanifest"),
    { params: Promise.resolve({ locale: "pt" }) },
  );
  assert.equal(response.status, 404);
  assert.equal(await response.text(), "");
});
