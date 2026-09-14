import { expect, test } from "@playwright/test";
import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const { webOrigin } = resolveLocalQaOrigins();
const sourceOrigin = webOrigin.replace("//localhost:", "//127.0.0.1:");

test("the production runtime moves IPv4 loopback users to the canonical WebAuthn origin", async ({ page }) => {
  const sourceUrl = `${sourceOrigin}/es/auth/sign-in?source=canonical-live`;
  const canonicalUrl = `${webOrigin}/es/auth/sign-in?source=canonical-live`;

  const redirect = await page.request.get(sourceUrl, {
    maxRedirects: 0,
    headers: {
      "x-forwarded-host": "redirect.attacker.invalid:8443",
      "x-forwarded-proto": "https",
    },
  });
  expect(redirect.status()).toBe(307);
  expect(redirect.headers()["location"]).toBe(canonicalUrl);
  expect(redirect.headers()["cache-control"]).toBe("no-store");
  expect(redirect.headers()["set-cookie"]).toBeUndefined();

  const health = await page.request.get(`${sourceOrigin}/healthz`, { maxRedirects: 0 });
  expect(health.status()).toBe(200);
  expect(health.headers()["location"]).toBeUndefined();

  await page.goto(`${sourceUrl}#same-device`);
  await expect(page).toHaveURL(`${canonicalUrl}#same-device`);
  await expect(page.getByRole("heading", { level: 1, name: "Iniciar sesión" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Entrar con llave de acceso" })).toBeVisible();
});
