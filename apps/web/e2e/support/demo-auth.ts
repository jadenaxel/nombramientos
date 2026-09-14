import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { expect, type Cookie, type Page } from "@playwright/test";
import { getMessage } from "@nombramientos/i18n";

import { resolveLocalQaOrigins } from "../../scripts/local-qa-boundary.ts";

export type DemoProfile = "administrator" | "secretary" | "committee" | "custodian" | "auditor";

type DemoCredential = {
  readonly email: string;
  readonly password: string;
  readonly totpEnrollmentUri: string;
};

type DemoAccessFile = DemoCredential & {
  readonly version?: number;
  readonly defaultProfile?: DemoProfile;
  readonly profiles?: Partial<Record<DemoProfile, DemoCredential>>;
};

// Session material is reused only in this Playwright worker's memory. Nothing
// is serialized to reports or disk, and each origin + browser user agent gets
// its own server-bound session containing only the two required cookies.
const sessionsByBinding = new Map<string, readonly Cookie[]>();
let inheritedSessionsLoaded = false;
const lastAcceptedTotpCounterByIdentity = new Map<string, number>();

export async function signInDemo(
  page: Page,
  profile: DemoProfile = "administrator",
  options: { readonly forceFresh?: boolean } = {},
): Promise<void> {
  loadInheritedSessions();
  const access = demoAccess(profile);
  const userAgent = await page.evaluate(() => navigator.userAgent);
  const binding = sessionBindingKey(userAgent, undefined, profile);
  if (options.forceFresh) {
    sessionsByBinding.delete(binding);
    await page.context().clearCookies();
  }
  const cached = sessionsByBinding.get(binding);

  if (cached) {
    await page.context().addCookies([...cached]);
    await page.goto("/es/app/overview");
    if (!page.url().includes("/auth/sign-in")) {
      await prepareDemoProfile(page, profile);
      return;
    }
    sessionsByBinding.delete(binding);
  }

  await loginThroughUi(page, access);
  sessionsByBinding.set(binding, filterSessionCookies(await page.context().cookies()));
  await prepareDemoProfile(page, profile);
}

export async function loginThroughUi(page: Page, access: DemoCredential = demoAccess()): Promise<void> {
  // The product intentionally rejects reuse of a TOTP time step across login
  // challenges. A previous browser worker may have consumed the current step,
  // so every retry deliberately creates a fresh password challenge after
  // crossing the boundary instead of reusing a rejected challenge.
  let mfaAttempt = 0;
  let rateLimitWaits = 0;
  while (mfaAttempt < 3) {
    await waitForUnusedTotpStep(page, access.email);
    await page.goto("/es/auth/sign-in");
    const emailInput = page.getByLabel("Correo electrónico");
    const passwordInput = page.getByLabel("Contraseña");
    await expect(emailInput).toBeEnabled();
    await emailInput.fill(access.email);
    await passwordInput.fill(access.password);
    let loginResponse: Awaited<ReturnType<Page["waitForResponse"]>>;
    try {
      [loginResponse] = await Promise.all([
        page.waitForResponse((response) => response.request().method() === "POST" && /\/v1\/auth\/login$/u.test(new URL(response.url()).pathname), { timeout: 15_000 }),
        page.getByRole("button", { name: "Continuar" }).click(),
      ]);
    } catch {
      await passwordInput.fill("").catch(() => undefined);
      await emailInput.fill("").catch(() => undefined);
      throw new Error("The hydrated local login form did not produce a bounded API response");
    }
    if (loginResponse.status() === 429) {
      rateLimitWaits += 1;
      if (rateLimitWaits > 2) throw new Error("The local login rate limit remained active after two bounded waits");
      await waitForRetryAfter(page, loginResponse.headers()["retry-after"]);
      continue;
    }
    await expect(page.getByRole("heading", { name: "Verificación en dos pasos" })).toBeVisible();
    await avoidExpiringTotpStep(page);
    const totp = currentTotp(access.totpEnrollmentUri);
    await page.getByLabel("Código de verificación").fill(totp.code);
    let mfaResponse: Awaited<ReturnType<Page["waitForResponse"]>>;
    try {
      [mfaResponse] = await Promise.all([
        page.waitForResponse((response) => response.request().method() === "POST" && /\/v1\/auth\/mfa\/verify$/u.test(new URL(response.url()).pathname), { timeout: 15_000 }),
        page.getByRole("button", { name: "Verificar y entrar" }).click(),
      ]);
    } catch {
      await page.getByLabel("Código de verificación").fill("").catch(() => undefined);
      throw new Error("The hydrated local MFA form did not produce a bounded API response");
    }
    if (mfaResponse.ok()) {
      await page.waitForURL(/\/es\/app\/overview$/, { timeout: 15_000 }).catch(() => {
        throw new Error("The local MFA API accepted the code but the authenticated route did not settle");
      });
      lastAcceptedTotpCounterByIdentity.set(access.email, totp.counter);
      return;
    }
    if (mfaResponse.status() === 429) {
      throw new Error("The local MFA rate limit is active; refusing to consume additional login challenges");
    }
    if (mfaResponse.status() !== 401) {
      throw new Error(`The local MFA API rejected verification with unexpected status ${mfaResponse.status()}`);
    }
    await page.getByLabel("Código de verificación").fill("").catch(() => undefined);
    mfaAttempt += 1;
    if (mfaAttempt < 3) await waitForNextTotpStep(page);
  }
  throw new Error("The demo MFA ceremony was rejected after three fresh challenges in distinct TOTP time steps");
}

export async function unlockDemoVault(page: Page, locale: "es" | "en" | "fr", profile: DemoProfile): Promise<void> {
  await submitDemoVaultUnlock(page, locale, profile);
  await expect(page.getByRole("heading", { name: getMessage(locale, "screen.membersView.500cd8288ddc"), level: 1 })).toBeVisible({ timeout: 30_000 });
}

export async function submitDemoVaultUnlock(page: Page, locale: "es" | "en" | "fr", profile: DemoProfile): Promise<void> {
  const unlockPassword = page.locator("#unlock-password");
  const needsUnlock = await unlockPassword.waitFor({ state: "visible", timeout: 3_000 })
    .then(() => true)
    .catch(() => false);
  if (needsUnlock) {
    await unlockPassword.fill(demoAccess(profile).password);
    const unlockButton = page.getByRole("button", { name: getMessage(locale, "shell.unlock") });
    await unlockButton.click();
    const unlockError = page.getByText(getMessage(locale, "shell.unlockError"), { exact: true });
    await expect(unlockPassword).toBeHidden({ timeout: 30_000 }).catch(async (cause: unknown) => {
      if (await unlockError.isVisible().catch(() => false)) {
        throw new Error(`The ${profile} Demo content-key grant could not be opened with its protected profile password`, { cause });
      }
      if (await unlockButton.isDisabled().catch(() => false)) {
        throw new Error(`The ${profile} Demo browser content-key unlock remained pending for 30 seconds`, { cause });
      }
      throw cause;
    });
  }
}

export async function navigateToAppSection(page: Page, label: string): Promise<void> {
  const links = page.getByRole("link", { name: label, exact: true });
  if ((page.viewportSize()?.width ?? 1_024) < 1_024) {
    await page.getByRole("button", { name: /^(?:Abrir menú|Open menu|Ouvrir le menu)$/u }).first().click();
    await expect(links.last()).toBeVisible();
    await links.last().click();
    return;
  }
  await expect(links.first()).toBeVisible();
  await links.first().click();
}

export function sessionBindingKey(userAgent: string, origin = demoOrigin(), profile: DemoProfile = "administrator"): string {
  return `${new URL(origin).origin}\n${userAgent}\n${profile}`;
}

export function filterSessionCookies(cookies: readonly Cookie[]): readonly Cookie[] {
  return cookies.filter((cookie) => cookie.name === "nom_session" || cookie.name === "nom_csrf");
}

async function avoidExpiringTotpStep(page: Page): Promise<void> {
  const remaining = 30_000 - (Date.now() % 30_000);
  if (remaining < 5_000) await page.waitForTimeout(remaining + 350);
}

async function waitForNextTotpStep(page: Page): Promise<void> {
  const remaining = 30_000 - (Date.now() % 30_000);
  await page.waitForTimeout(remaining + 350);
}

async function waitForUnusedTotpStep(page: Page, identity: string): Promise<void> {
  if (lastAcceptedTotpCounterByIdentity.get(identity) === Math.floor(Date.now() / 30_000)) {
    await waitForNextTotpStep(page);
  }
}

async function waitForRetryAfter(page: Page, header: string | undefined): Promise<void> {
  const parsed = header === undefined ? Number.NaN : Number(header);
  const seconds = Number.isFinite(parsed) && parsed > 0 ? Math.ceil(parsed) : 30;
  const deadline = Date.now() + Math.min(seconds, 900) * 1_000 + 350;
  while (Date.now() < deadline) {
    await page.waitForTimeout(Math.min(30_000, deadline - Date.now()));
  }
}

function currentTotp(enrollmentUri: string): { readonly code: string; readonly counter: number } {
  const secret = new URL(enrollmentUri).searchParams.get("secret");
  if (!secret) throw new Error("The local TOTP enrollment URI has no secret");
  const counter = Math.floor(Date.now() / 30_000);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest.at(-1)! & 0x0f;
  return {
    code: String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0"),
    counter,
  };
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of value.replaceAll("=", "").toUpperCase()) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("The local TOTP enrollment secret is malformed");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function demoAccess(profile: DemoProfile = "administrator"): DemoCredential {
  const configured = process.env.DEMO_ACCESS_FILE;
  const filename = configured ?? path.resolve(import.meta.dirname, "../../../../packages/database/.local/demo-access.json");
  const parsed = JSON.parse(readFileSync(filename, "utf8")) as DemoAccessFile;
  const credential = parsed.profiles?.[profile] ?? (profile === "administrator" ? parsed : undefined);
  if (
    !credential ||
    typeof credential.email !== "string" ||
    typeof credential.password !== "string" ||
    typeof credential.totpEnrollmentUri !== "string"
  ) {
    throw new Error(`The protected local Demo access file has no valid ${profile} profile`);
  }
  return credential;
}

async function prepareDemoProfile(page: Page, profile: DemoProfile): Promise<void> {
  await page.goto("/es/app/overview");
  if (profile === "administrator") {
    await page.goto("/es/app/members");
    await unlockDemoVault(page, "es", profile);
    await page.getByRole("link", { name: "Resumen" }).click();
  }
  await expect(page).toHaveURL(/\/es\/app\/overview$/);
  // Restricted roles can authenticate and use their permitted shell routes even
  // when this device has no tenant-content grant yet. Prove the active tenant in
  // the shared shell instead of requiring the encrypted overview heading.
  await expect(page.getByText("Iglesia Demostración", { exact: true }).filter({ visible: true }).first()).toBeVisible();
}

function loadInheritedSessions(): void {
  if (inheritedSessionsLoaded) return;
  inheritedSessionsLoaded = true;
  const encoded = process.env["NOMBRAMIENTOS_E2E_SESSION_COOKIES_B64"];
  if (!encoded) return;
  delete process.env["NOMBRAMIENTOS_E2E_SESSION_COOKIES_B64"];
  const decoded: unknown = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  if (!Array.isArray(decoded)) throw new Error("Inherited E2E session map is malformed");
  for (const entry of decoded) {
    if (!Array.isArray(entry) || typeof entry[0] !== "string" || !Array.isArray(entry[1])) {
      throw new Error("Inherited E2E session entry is malformed");
    }
    sessionsByBinding.set(entry[0], filterSessionCookies(entry[1] as readonly Cookie[]));
  }
}

function demoOrigin(): string {
  return resolveLocalQaOrigins().webOrigin;
}
