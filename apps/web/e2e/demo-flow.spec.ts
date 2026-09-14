import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Download, type Page, type Route } from "@playwright/test";
import type {
  Envelope,
  GeneratedReport,
  Locale,
  PendingReport,
  ReportAudience,
  ReportFilters,
  ReportFormat,
  ReportType,
  StoredReport,
  StoredReportArtifact,
} from "../lib/api.ts";
import { navigateToAppSection, signInDemo, submitDemoVaultUnlock, unlockDemoVault } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";
import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const evidenceDirectory = path.resolve(import.meta.dirname, "../../../docs/evidence");
const apiOrigin = resolveLocalQaOrigins().apiOrigin;
const demoTenantId = "d0000000-0000-4000-8000-000000000001";

async function expectAccessibleCredentialTabOrder(
  page: Page,
  labels: { readonly email: string; readonly passkey: string; readonly password: string },
): Promise<void> {
  const emailInput = page.getByLabel(labels.email);
  const passkeyButton = page.getByRole("button", { name: labels.passkey });
  const passwordInput = page.getByLabel(labels.password);
  await expect(passkeyButton).toBeVisible();
  await emailInput.focus();
  await page.keyboard.press("Tab");
  if (await passkeyButton.isEnabled()) {
    await expect(passkeyButton).toBeFocused();
    await page.keyboard.press("Tab");
  } else {
    await expect(passkeyButton).toBeDisabled();
  }
  await expect(passwordInput).toBeFocused();
}

test("login is localized, responsive and has no axe findings", async ({ page }, testInfo) => {
  const localizedLogin = [
    { locale: "es", heading: "Iniciar sesión", email: "Correo electrónico", passkey: "Entrar con llave de acceso", password: "Contraseña", submit: "Continuar", summary: "Hay 2 errores en el formulario", required: "Campo obligatorio", invalid: "Revisa los campos indicados.", minimum: "Mín. 12 caracteres" },
    { locale: "en", heading: "Sign in", email: "Email address", passkey: "Sign in with a passkey", password: "Password", submit: "Continue", summary: "2 form errors", required: "Required field", invalid: "Review the indicated fields.", minimum: "12 characters minimum" },
    { locale: "fr", heading: "Se connecter", email: "Adresse électronique", passkey: "Se connecter avec une clé d’accès", password: "Mot de passe", submit: "Continuer", summary: "2 erreurs dans le formulaire", required: "Champ obligatoire", invalid: "Vérifiez les champs indiqués.", minimum: "12 caractères minimum" },
  ] as const;
  for (const { locale, heading, email, passkey, password, submit, summary, required, invalid, minimum } of localizedLogin) {
    await page.goto(`/${locale}/auth/sign-in`);
    await expect(page.locator("html")).toHaveAttribute("lang", locale);
    await expect(page.locator("h1")).toHaveCount(1);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();

    await expectAccessibleCredentialTabOrder(page, { email, passkey, password });

    await page.getByRole("button", { name: submit }).click();
    const validationAlert = page.getByRole("alert").filter({ hasText: summary });
    await expect(validationAlert).toBeFocused();
    await expect(validationAlert).toContainText(summary);
    await expect(validationAlert).toContainText(`${email}: ${required}`);
    await expect(validationAlert).toContainText(`${password}: ${required}`);
    await expect(page.getByLabel(email)).toHaveAttribute("aria-invalid", "true");
    await expect(page.getByLabel(email)).toHaveAttribute("aria-describedby", "email-error");
    await expect(page.getByLabel(password)).toHaveAttribute("aria-invalid", "true");
    await expect(page.getByLabel(password)).toHaveAttribute("aria-describedby", "password-requirements password-error");

    await page.getByLabel(email).fill("not-an-email");
    await page.getByLabel(password).fill("short");
    await page.getByRole("button", { name: submit }).click();
    await expect(page.getByRole("alert").filter({ hasText: `${email}: ${invalid}` })).toContainText(`${password}: ${minimum}`);
    await expect(page.getByLabel(password)).toHaveValue("");
  }
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/es/auth/sign-in");
  await expect(page.locator("h1")).toHaveCount(1);
  await expect(page.getByRole("heading", { level: 1, name: "Iniciar sesión" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Continuar" })).toBeInViewport();
  await expect(page.getByLabel("Correo electrónico")).toBeEnabled();
  await expectAccessibleCredentialTabOrder(page, {
    email: "Correo electrónico",
    passkey: "Entrar con llave de acceso",
    password: "Contraseña",
  });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const continueBox = await page.getByRole("button", { name: "Continuar" }).boundingBox();
  expect(continueBox?.height ?? 0).toBeGreaterThanOrEqual(44);
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations).toEqual([]);
  if (testInfo.project.name === "mobile-small") {
    mkdirSync(evidenceDirectory, { recursive: true });
    await page.screenshot({ path: path.join(evidenceDirectory, "login-mobile.png"), fullPage: true });
  }

  const failures = [
    { status: 401, expected: "No pudimos verificar esas credenciales.", requestId: "login-invalid" },
    { status: 429, expected: "Demasiados intentos. Espera antes de volver a intentar.", requestId: "login-limited" },
    { status: 503, expected: "El servicio no respondió a tiempo. No se confirmó la operación.", requestId: "login-transient" },
  ] as const;
  let failureIndex = 0;
  await page.route(localQaApiRoute("/v1/auth/login"), async (route) => {
    const failure = failures[failureIndex++];
    if (!failure) throw new Error("Unexpected extra mocked login request");
    await route.fulfill({
      status: failure.status,
      contentType: "application/json",
      headers: {
        "access-control-expose-headers": "x-request-id",
        "x-request-id": failure.requestId,
      },
      body: JSON.stringify({ error: { code: "UNAUTHENTICATED", message: "SERVER_AUTH_SENTINEL" } }),
    });
  });
  await page.getByLabel("Correo electrónico").fill("synthetic-user@example.invalid");
  for (const failure of failures) {
    await page.getByLabel("Contraseña").fill("synthetic-password-123");
    await page.getByRole("button", { name: "Continuar" }).click();
    const signInAlert = page.getByRole("alert").filter({ hasText: failure.expected });
    await expect(signInAlert).toContainText(failure.expected);
    await expect(signInAlert).toContainText(`ID de correlación: ${failure.requestId}`);
    await expect(signInAlert).not.toContainText("SERVER_AUTH_SENTINEL");
    await expect(page.getByLabel("Contraseña")).toHaveValue("");
  }
  expect(failureIndex).toBe(failures.length);
});

test("authenticated surfaces follow the URL locale and never expose a server error message", async ({ page }) => {
  await signInDemo(page);

  await page.goto("/en/app/overview");
  await submitDemoVaultUnlock(page, "en", "administrator");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.getByText("Verifiable status of the nomination cycle.")).toBeVisible();
  if ((page.viewportSize()?.width ?? 1_024) < 1_024) {
    await expect(page.getByRole("button", { name: "More" })).toBeVisible();
  } else {
    await expect(page.getByRole("link", { name: "Members", exact: true })).toBeVisible();
  }

  await page.goto("/fr/app/library");
  await expect(page.locator("html")).toHaveAttribute("lang", "fr");
  await expect(page.getByRole("heading", { name: "Sources, index et glossaire" })).toBeVisible();
  const sourceSearch = page.getByPlaceholder("Rechercher une édition, un thème ou un manuel…");
  await sourceSearch.fill("ancien");
  await expect(page.getByRole("heading", { name: "Manuel de l’ancien" })).toBeVisible();
  await sourceSearch.fill("source qui n’existe pas");
  await expect(page.getByText("Aucune source ne correspond à la recherche")).toBeVisible();

  await page.goto("/en/app/members");
  await unlockDemoVault(page, "en", "administrator");
  await expect(page.getByRole("heading", { name: "Members" })).toBeVisible({ timeout: 30_000 });
  let interceptedMemberCreates = 0;
  await page.route(localQaApiRoute("/v1/members"), async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    interceptedMemberCreates += 1;
    return route.fulfill({
      status: 500,
      contentType: "application/json",
      headers: { "x-request-id": "localized-sentinel-id" },
      body: JSON.stringify({ error: { code: "INTERNAL_FAILURE", message: "SERVER_SECRET_SENTINEL" } }),
    });
  });
  await page.getByRole("button", { name: "New person" }).click();
  await page.getByLabel("Full name").fill("Localized Test Person");
  await page.getByRole("button", { name: "Encrypt and save" }).click();
  await expect(page.locator(".form-error")).toContainText("The operation was not confirmed");
  await expect(page.getByText("SERVER_SECRET_SENTINEL")).toHaveCount(0);
  expect(interceptedMemberCreates).toBe(1);
  const persistedMemberTotal = await page.evaluate(async (origin) => {
    const response = await fetch(`${origin}/v1/members`, { credentials: "include", cache: "no-store" });
    if (!response.ok) throw new Error(`Member count guard failed with ${response.status}`);
    const envelope = await response.json() as { data: { total: number } };
    return envelope.data.total;
  }, apiOrigin);
  expect(persistedMemberTotal).toBe(180);
});

test("a reload preserves the session but gates encrypted overview and results until vault unlock", async ({ page }) => {
  await signInDemo(page);

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/es\/app\/overview$/u);
  await expect(page.locator("#unlock-password")).toBeVisible();
  await expect(page.locator(".metrics-grid")).toHaveCount(0);
  await submitDemoVaultUnlock(page, "es", "administrator");
  await expect(page.locator(".metrics-grid")).toBeVisible({ timeout: 30_000 });

  await page.goto("/es/app/results");
  await submitDemoVaultUnlock(page, "es", "administrator");
  await expect(page.locator(".results-grid")).toBeVisible({ timeout: 30_000 });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/es\/app\/results$/u);
  await expect(page.locator("#unlock-password")).toBeVisible();
  await expect(page.locator(".results-grid")).toHaveCount(0);
  await submitDemoVaultUnlock(page, "es", "administrator");
  await expect(page.locator(".results-grid")).toBeVisible({ timeout: 30_000 });
});

test("real demo login loads persisted members and submits or recovers one opaque proposal", async ({ page, context }, testInfo) => {
  // The frozen active-round electorate intentionally contains the Demo
  // administrator identity. Its explicit COMMITTEE_MEMBER binding grants the
  // proposal capability without broadening CHURCH_ADMIN itself.
  await signInDemo(page, "administrator");
  if (testInfo.project.name === "desktop-chromium-es") {
    mkdirSync(evidenceDirectory, { recursive: true });
    await page.screenshot({ path: path.join(evidenceDirectory, "overview-desktop.png"), fullPage: true });
    await page.bringToFront();
    await expect.poll(() => page.evaluate(() => document.visibilityState)).toBe("visible");
  }

  await navigateToAppSection(page, "Miembros");
  await unlockDemoVault(page, "es", "administrator");
  await expect(page.getByRole("heading", { name: /180 de 180 personas/ })).toBeVisible({ timeout: 30_000 });
  const firstMember = page.locator("article").filter({ hasText: "M001" });
  await expect(firstMember.getByText("Miembro Demo 001", { exact: true })).toBeVisible();

  // Exercise the complete browser ceremony without adding an irreversible
  // receipt to the shared Demo tenant. The active-round projection, receipt
  // read and final write are isolated below because the shared fixture may
  // legitimately retain an earlier receipt. The dedicated real-stack runner
  // separately proves authorization and persistence against ephemeral DBs.
  let interceptedSubmissions = 0;
  await page.route(localQaApiRoute("/v1/rounds/active"), async (route) => {
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    const envelope = structuredClone(await response.json() as {
      data: { viewerCanSubmit: boolean };
      meta?: unknown;
    });
    envelope.data.viewerCanSubmit = true;
    await route.fulfill({ response, json: envelope });
  });
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions\/me$/u), async (route) => {
    await route.fulfill({
      status: 404,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "isolated-no-prior-receipt" },
      body: JSON.stringify({ error: { code: "NOT_FOUND", message: "No isolated receipt" } }),
    });
  });
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions$/u), async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    interceptedSubmissions += 1;
    const request = route.request().postDataJSON() as { expectedVersion: number; contentHash: string };
    const roundId = new URL(route.request().url()).pathname.split("/").at(-2);
    if (!roundId) throw new Error("The isolated E2E submission has no round identifier");
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "isolated-demo-submission" },
      body: JSON.stringify({
        data: {
          receiptId: "e2000000-0000-4000-8000-000000000001",
          receivedAt: "2026-09-11T12:00:00.000Z",
          roundId,
          roundVersion: request.expectedVersion,
          contentHash: request.contentHash,
          status: "received",
        },
        meta: { requestId: "isolated-demo-submission" },
      }),
    });
  });
  await navigateToAppSection(page, "Sesión en curso");
  await expect(page.getByText("BOLETA CONGELADA")).toBeVisible({ timeout: 30_000 });
  const connectionStatus = page.locator(".connection-banner");
  await expect(connectionStatus).toContainText("En línea", { timeout: 15_000 });
  const receiptHeading = page.getByRole("heading", { name: /Tu (?:propuesta|respuesta) fue recibida/u });
  const reviewButton = page.getByRole("button", { name: "Revisar y enviar" });
  const enabledReviewButton = reviewButton.and(page.locator("button:enabled"));
  await expect(reviewButton).toBeVisible();

  const firstCandidate = page.locator(".candidate-list").locator("[role='checkbox']:not([disabled]), [role='radio']:not([disabled])").first();
  await expect(firstCandidate).toBeEnabled();
  await firstCandidate.focus();
  await page.keyboard.press("Space");
  await expect(firstCandidate).toBeChecked();

  const abstention = page.getByRole("checkbox", { name: /^Abstenerme en este paso/ });
  await abstention.focus();
  await page.keyboard.press("Space");
  await expect(abstention).toBeChecked();
  await expect(firstCandidate).not.toBeChecked();
  await expect(enabledReviewButton).toBeVisible();

  await enabledReviewButton.focus();
  await page.keyboard.press("Enter");
  const confirmationDialog = page.getByRole("dialog");
  await expect(confirmationDialog).toBeVisible();
  expect(await confirmationDialog.evaluate((dialog) => dialog.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(confirmationDialog).toBeHidden();
  await expect(enabledReviewButton).toBeFocused();

  await page.keyboard.press("Enter");
  await expect(confirmationDialog).toBeVisible();
  const encryptAndSend = confirmationDialog.getByRole("button", { name: /Cifrar y enviar/ });
  await encryptAndSend.focus();
  await page.keyboard.press("Enter");
  await expect(receiptHeading).toBeVisible();
  await expect(receiptHeading).toBeFocused();
  expect(interceptedSubmissions).toBe(1);
  await expect(page.getByText("RECIBIDO POR EL SERVIDOR")).toBeVisible();
  await page.setViewportSize({ width: 320, height: 720 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const mobileNavigation = page.getByRole("navigation", { name: "Navegación móvil" });
  await expect(mobileNavigation).toBeVisible();
  const mobileTargets = await mobileNavigation.locator("a,button").evaluateAll((elements) =>
    elements.map((element) => element.getBoundingClientRect().height));
  expect(mobileTargets.every((height) => height >= 44)).toBe(true);

  const mobileMenuTrigger = page.getByRole("button", { name: "Abrir menú" });
  await mobileMenuTrigger.focus();
  await page.keyboard.press("Enter");
  const mobileMenu = page.getByRole("dialog", { name: "Navegación principal" });
  await expect(mobileMenu).toBeVisible();
  expect(await mobileMenu.evaluate((dialog) => dialog.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(mobileMenu).toBeHidden();
  await expect(mobileMenuTrigger).toBeFocused();

  await context.setOffline(true);
  await expect(connectionStatus).toContainText("Sin conexión", { timeout: 15_000 });
  await expect(page.getByText("RECIBIDO POR EL SERVIDOR")).toBeVisible();
  await expect(mobileMenuTrigger).toBeFocused();
  await context.setOffline(false);
  await expect(connectionStatus).toContainText("En línea", { timeout: 15_000 });
  if (testInfo.project.name === "mobile-small") {
    await page.screenshot({ path: path.join(evidenceDirectory, "round-receipt-mobile.png"), fullPage: true });
  }

  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(axe.violations).toEqual([]);
});

test("authorized browser generates valid PDF, XLSX and CSV artifacts locally", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One isolated client ceremony validates every downloadable report format");
  for (const vector of ["=SUM(A1:A2)", "+cmd", "-1+2", "@SUM(A1:A2)", "\ttext", "\rtext", "  \ttext"]) {
    expect(isUnsafeSpreadsheetCell(vector)).toBe(true);
    expect(isUnsafeSpreadsheetCell(`'${vector}`)).toBe(false);
  }
  await signInDemo(page);
  const isolatedReports = await installIsolatedReportRoutes(page);
  await navigateToAppSection(page, "Reportes");
  await expect(page.getByRole("heading", { name: "Reportes" })).toBeVisible({ timeout: 30_000 });
  const reportType = page.getByLabel("Contenido");
  const audience = page.getByLabel("Audiencia");
  await expect(reportType.locator("option")).toHaveCount(13);
  await reportType.selectOption("office_round");
  await expect(audience.locator('option[value="church"]')).toHaveCount(0);
  await reportType.selectOption("roster_import_incidents");
  await expect(audience.locator("option")).toHaveCount(1);
  await expect(audience).toHaveValue("committee");
  await reportType.selectOption("department");
  await audience.selectOption("church");
  const assignmentState = page.getByLabel("Estado de asignación");
  await expect(assignmentState.locator('option[value="elected"]')).toHaveCount(1);
  await assignmentState.selectOption("elected");
  await expect(page.locator(".report-paper")).toContainText("Elegida por la iglesia");
  await assignmentState.selectOption("all");
  await reportType.selectOption("cycle_summary");
  await audience.selectOption("committee");
  mkdirSync(evidenceDirectory, { recursive: true });
  const generatedReports: Array<{ format: "PDF" | "XLSX" | "CSV"; locale: "es" | "en" | "fr"; filename: string }> = [];
  for (const [format, locale] of [["PDF", "es"], ["XLSX", "en"], ["CSV", "fr"]] as const) {
    await page.getByLabel("Idioma del documento").selectOption(locale);
    let download = await requestReportDownload(page, format);
    if (!download) {
      await expect(page.getByText("No se descargó el reporte", { exact: true })).toBeVisible();
      await signInDemo(page, "administrator", { forceFresh: true });
      await navigateToAppSection(page, "Reportes");
      await expect(page.getByRole("heading", { name: "Reportes" })).toBeVisible({ timeout: 30_000 });
      await page.getByLabel("Contenido").selectOption("cycle_summary");
      await page.getByLabel("Audiencia").selectOption("committee");
      await page.getByLabel("Idioma del documento").selectOption(locale);
      download = await requestReportDownload(page, format);
    }
    expect(download, `${format} download must succeed after recent-MFA recovery`).toBeDefined();
    if (!download) throw new Error(`${format} download remained unavailable after recent-MFA recovery`);
    generatedReports.push({ format, locale, filename: download.suggestedFilename() });
    const extension = format.toLocaleLowerCase();
    const destination = path.join(evidenceDirectory, `demo-cycle-summary.${extension}`);
    await download.saveAs(destination);
    expect(statSync(destination).size).toBeGreaterThan(format === "PDF" ? 500 : 100);
    await validateReportArtifact(destination, format, locale);
  }
  for (const { format, locale, filename } of generatedReports) {
    const historicalIssue = page.locator(".report-list article").filter({ hasText: filename }).first();
    await expect(historicalIssue.getByText("Lista", { exact: true })).toBeVisible();
    const [historicalDownload] = await Promise.all([
      page.waitForEvent("download"),
      historicalIssue.getByRole("button", { name: `Descargar: ${filename}` }).click(),
    ]);
    const historicalDestination = path.join(evidenceDirectory, `demo-cycle-summary-history.${format.toLocaleLowerCase()}`);
    await historicalDownload.saveAs(historicalDestination);
    await validateReportArtifact(historicalDestination, format, locale);
  }
  expect(isolatedReports.operations).toEqual({ generate: 3, complete: 3, fail: 0, print: 0, download: 3 });
  expect(isolatedReports.reportListReads()).toBeGreaterThanOrEqual(1);
  expect([...isolatedReports.reports.values()].filter(({ state }) => state === "ready")).toHaveLength(3);
  expect(isolatedReports.artifacts.size).toBe(3);
});

async function requestReportDownload(page: Page, format: "PDF" | "XLSX" | "CSV"): Promise<Download | undefined> {
  let settled = false;
  let resolveDownload!: (download: Download | undefined) => void;
  const downloadPromise = new Promise<Download | undefined>((resolve) => {
    resolveDownload = resolve;
  });
  function onDownload(download: Download): void {
    settleDownload(download);
  }
  function settleDownload(download?: Download): void {
    if (settled) return;
    settled = true;
    page.off("download", onDownload);
    clearTimeout(timeout);
    resolveDownload(download);
  }
  page.on("download", onDownload);
  const timeout = setTimeout(() => settleDownload(), 30_000);

  try {
    const responsePromise = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return response.request().method() === "POST" && url.pathname === "/v1/reports/generate";
    }, { timeout: 30_000 });
    await page.getByRole("button", { name: format, exact: true }).click();
    const response = await responsePromise;
    if (!response.ok()) {
      settleDownload();
      const payload: unknown = await response.json().catch(() => undefined);
      const error = typeof payload === "object" && payload !== null
        ? (payload as { readonly error?: unknown }).error
        : undefined;
      const code = typeof error === "object" && error !== null
        ? (error as { readonly code?: unknown }).code
        : undefined;
      if (response.status() === 428 && code === "MFA_STEP_UP_REQUIRED") return undefined;
      throw new Error(`Report generation failed with status ${response.status()}${typeof code === "string" ? ` (${code})` : ""}`);
    }
    const download = await downloadPromise;
    if (!download) throw new Error(`Report generation for ${format} succeeded without emitting a download`);
    return download;
  } finally {
    settleDownload();
  }
}

async function validateReportArtifact(filename: string, format: "PDF" | "XLSX" | "CSV", locale: "es" | "en" | "fr") {
  const expectedTitles = {
    es: "Resumen verificable del ciclo",
    en: "Verifiable cycle summary",
    fr: "Résumé vérifiable du cycle",
  } as const;
  const expectedLabels = {
    es: "Vacantes aplicables",
    en: "Applicable vacancies",
    fr: "Postes applicables",
  } as const;
  const bytes = readFileSync(filename);
  if (format === "PDF") {
    const { PDFDocument } = await import("pdf-lib");
    const document = await PDFDocument.load(bytes);
    expect(document.getPageCount()).toBe(1);
    expect(document.getTitle()).toBe(expectedTitles[locale]);
    expect(document.getAuthor()).toBe("Nombramientos");
    return;
  }
  if (format === "XLSX") {
    const ExcelJS = (await import("exceljs")).default;
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(bytes as unknown as Parameters<typeof workbook.xlsx.load>[0]);
    const sheet = workbook.getWorksheet({ es: "Reporte", en: "Report", fr: "Rapport" }[locale]);
    expect(sheet).toBeDefined();
    expect(sheet!.getCell("A1").value).toBe(expectedTitles[locale]);
    const valuesByLabel = new Map<string, unknown>();
    sheet!.eachRow((row) => {
      const label = row.getCell(1).value;
      if (typeof label === "string") valuesByLabel.set(label, row.getCell(2).value);
    });
    expect(valuesByLabel.get(expectedLabels[locale])).toBe(40);
    expect([...valuesByLabel.values()]).toEqual(expect.arrayContaining([20, 15, 10]));
    expect(valuesByLabel.get({ es: "Clasificación de audiencia", en: "Audience classification", fr: "Classification du public" }[locale])).toBeTruthy();
    expect(String(valuesByLabel.get({ es: "Huella de instantánea", en: "Snapshot digest", fr: "Empreinte de l’instantané" }[locale]))).toMatch(/^sha256:[0-9a-f]{64}$/);
    let formulas = 0;
    let unsafeTextCells = 0;
    sheet!.eachRow((row) => row.eachCell((cell) => {
      if (typeof cell.value === "object" && cell.value !== null && "formula" in cell.value) formulas += 1;
      if (typeof cell.value === "string" && isUnsafeSpreadsheetCell(cell.value)) unsafeTextCells += 1;
    }));
    expect(formulas).toBe(0);
    expect(unsafeTextCells).toBe(0);
    return;
  }
  const csv = bytes.toString("utf8");
  expect(csv.startsWith("\uFEFF")).toBe(true);
  expect(csv).toContain(`"${expectedTitles[locale]}"`);
  expect(csv).toContain(`"${expectedLabels[locale]}","40"`);
  expect(csv).toContain('"Recommandations","20"');
  expect(csv).toContain('"Acceptations","15"');
  expect(csv).toContain('"Élections par l’Église","10"');
  const cells = [...csv.matchAll(/(?:^|,)"((?:[^"]|"")*)"/gmu)]
    .map((match) => (match[1] ?? "").replaceAll('""', '"'));
  expect(cells.length).toBeGreaterThan(0);
  expect(cells.every((cell) => !isUnsafeSpreadsheetCell(cell))).toBe(true);
}

type IsolatedReportGenerationRequest = {
  readonly reportType: ReportType;
  readonly format: ReportFormat;
  readonly locale: Locale;
  readonly audience: ReportAudience;
  readonly filters: ReportFilters;
};

type IsolatedReportCompletionRequest = {
  readonly expectedVersion: number;
  readonly envelope: Envelope;
  readonly artifactSha256: `sha256:${string}`;
  readonly ciphertextSha256: `sha256:${string}`;
  readonly plaintextBytes: number;
  readonly rowCount: number;
  readonly generatedAt: string;
};

type IsolatedFailedReport = Omit<PendingReport, "state" | "version" | "errorCode" | "failedAt"> & {
  readonly state: "failed";
  readonly version: number;
  readonly errorCode: string;
  readonly failedAt: string;
};

type IsolatedReport = PendingReport | GeneratedReport | IsolatedFailedReport;

async function installIsolatedReportRoutes(page: Page) {
  const reports = new Map<string, IsolatedReport>();
  const artifacts = new Map<string, StoredReportArtifact>();
  const operations = { generate: 0, complete: 0, fail: 0, print: 0, download: 0 };
  let reportListReads = 0;

  await page.route(localQaApiRoute("/v1/reports"), async (route) => {
    if (route.request().method() !== "GET") {
      await fulfillReportError(route, 405, "METHOD_NOT_ALLOWED", "Synthetic report list is read-only");
      return;
    }
    reportListReads += 1;
    const response = await route.fetch();
    if (!response.ok()) {
      await route.fulfill({ response });
      return;
    }
    const envelope = structuredClone(await response.json() as {
      data: { items: StoredReport[] };
      meta?: { requestId?: string };
    });
    const projected = [...reports.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    const projectedIds = new Set(projected.map(({ id }) => id));
    envelope.data.items = [...projected, ...envelope.data.items.filter(({ id }) => !projectedIds.has(id))];
    await route.fulfill({ response, json: envelope });
  });

  await page.route(localQaApiRoute("/v1/reports/generate"), async (route) => {
    if (route.request().method() !== "POST") {
      await fulfillReportError(route, 405, "METHOD_NOT_ALLOWED", "Synthetic report generation requires POST");
      return;
    }
    await assertReportMutationHeaders(route);
    operations.generate += 1;
    const request = route.request().postDataJSON() as IsolatedReportGenerationRequest;
    expect(request.reportType).toBe("cycle_summary");
    expect(request.audience).toBe("committee");
    expect(["pdf", "xlsx", "csv"]).toContain(request.format);
    expect(["es", "en", "fr"]).toContain(request.locale);
    expect(request.filters.snapshotSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(Number.isNaN(Date.parse(request.filters.snapshotAt))).toBe(false);

    const ordinal = operations.generate;
    const id = `e3${String(ordinal).padStart(6, "0")}-0000-4000-8000-${String(ordinal).padStart(12, "0")}`;
    const pending: PendingReport = {
      id,
      reportType: request.reportType,
      format: request.format,
      locale: request.locale,
      filename: `${request.reportType}-${id.slice(0, 8)}.${request.format}`,
      mediaType: isolatedReportMediaType(request.format),
      createdAt: new Date(Date.UTC(2026, 8, 11, 12, ordinal, 0)).toISOString(),
      audience: request.audience,
      filters: request.filters,
      state: "pending",
      version: 1,
      artifactSha256: null,
      ciphertextSha256: null,
      ciphertextBytes: null,
      plaintextBytes: null,
      manifest: null,
      errorCode: null,
      supersedesReportId: null,
      correctedByReportId: null,
      correctionReasonCode: null,
      lineageRootId: id,
      lineageRevision: 1,
      readyAt: null,
      failedAt: null,
    };
    reports.set(id, pending);
    await fulfillReportData(route, 201, pending, `isolated-report-generate-${ordinal}`);
  });

  await page.route(localQaApiRoute(/^\/v1\/reports\/[^/]+\/(?:complete|fail|print)$/u), async (route) => {
    if (route.request().method() !== "POST") {
      await fulfillReportError(route, 405, "METHOD_NOT_ALLOWED", "Synthetic report transition requires POST");
      return;
    }
    await assertReportMutationHeaders(route);
    const segments = new URL(route.request().url()).pathname.split("/");
    const reportId = decodeURIComponent(segments[3] ?? "");
    const action = segments[4];
    const report = reports.get(reportId);
    if (!report) {
      await fulfillReportError(route, 404, "REPORT_UNAVAILABLE", "Synthetic report is unavailable");
      return;
    }

    if (action === "complete") {
      operations.complete += 1;
      if (report.state !== "pending") {
        await fulfillReportError(route, 409, "REPORT_STATE_CONFLICT", "Synthetic report is not pending");
        return;
      }
      const request = route.request().postDataJSON() as IsolatedReportCompletionRequest;
      expect(request.expectedVersion).toBe(report.version);
      expect(Number.isSafeInteger(request.expectedVersion) && request.expectedVersion > 0).toBe(true);
      expect(Object.keys(request.envelope).sort()).toEqual(["aad", "algorithm", "ciphertext", "keyId", "nonce"]);
      expect(request.envelope.algorithm).toBe("AES-256-GCM");
      expect(request.envelope.keyId.length >= 8 && request.envelope.keyId.length <= 160).toBe(true);
      expect(request.artifactSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(request.ciphertextSha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(Number.isSafeInteger(request.plaintextBytes)
        && request.plaintextBytes >= 1
        && request.plaintextBytes <= 20 * 1024 * 1024).toBe(true);
      expect(Number.isSafeInteger(request.rowCount) && request.rowCount >= 0 && request.rowCount <= 1_000_000).toBe(true);
      expect(request.generatedAt).toMatch(/(?:Z|[+-]\d{2}:\d{2})$/u);
      expect(Number.isNaN(Date.parse(request.generatedAt))).toBe(false);

      const nonce = canonicalBase64UrlBytes(request.envelope.nonce, "nonce");
      const ciphertext = canonicalBase64UrlBytes(request.envelope.ciphertext, "ciphertext");
      const aadBytes = canonicalBase64UrlBytes(request.envelope.aad, "aad");
      expect(nonce.byteLength).toBe(12);
      expect(ciphertext.byteLength).toBe(request.plaintextBytes + 16);
      const expectedAad = {
        tenantId: demoTenantId,
        reportId,
        requestVersion: report.version,
        reportType: report.reportType,
        audience: report.audience,
        locale: report.locale,
        format: report.format,
        filename: report.filename,
        mediaType: report.mediaType,
        snapshotSha256: report.filters.snapshotSha256,
        purpose: "report-artifact",
        schemaVersion: 1,
        plaintextBytes: request.plaintextBytes,
      };
      let actualAad: unknown;
      try {
        actualAad = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(aadBytes)) as unknown;
      } catch {
        throw new Error("Synthetic report completion received invalid AAD JSON");
      }
      expect(actualAad).toEqual(expectedAad);
      const canonicalEnvelope = JSON.stringify({
        algorithm: request.envelope.algorithm,
        keyId: request.envelope.keyId,
        nonce: request.envelope.nonce,
        ciphertext: request.envelope.ciphertext,
        aad: request.envelope.aad,
      });
      expect(request.artifactSha256).toBe(`sha256:${createHash("sha256").update(canonicalEnvelope, "utf8").digest("hex")}`);
      expect(request.ciphertextSha256).toBe(`sha256:${createHash("sha256").update(ciphertext).digest("hex")}`);

      const manifest: GeneratedReport["manifest"] = {
        schemaVersion: 1,
        reportId,
        reportType: report.reportType,
        audience: report.audience,
        locale: report.locale,
        format: report.format,
        requestVersion: report.version,
        snapshotSha256: report.filters.snapshotSha256,
        artifactSha256: request.artifactSha256,
        ciphertextSha256: request.ciphertextSha256,
        ciphertextBytes: ciphertext.byteLength,
        plaintextBytes: request.plaintextBytes,
        rowCount: request.rowCount,
        generatedAt: request.generatedAt,
        lineageRootId: report.lineageRootId,
        lineageRevision: report.lineageRevision,
        supersedesReportId: null,
        correctionReasonCode: null,
      };
      const completed: GeneratedReport = {
        ...report,
        state: "ready",
        version: report.version + 1,
        artifactSha256: request.artifactSha256,
        ciphertextSha256: request.ciphertextSha256,
        ciphertextBytes: ciphertext.byteLength,
        plaintextBytes: request.plaintextBytes,
        manifest,
        readyAt: request.generatedAt,
      };
      reports.set(reportId, completed);
      artifacts.set(reportId, {
        envelope: request.envelope,
        filename: completed.filename,
        mediaType: completed.mediaType,
        artifactSha256: completed.artifactSha256,
        ciphertextSha256: completed.ciphertextSha256,
        ciphertextBytes: completed.ciphertextBytes,
        plaintextBytes: completed.plaintextBytes,
        requestVersion: report.version,
        manifest,
        reportType: completed.reportType,
        audience: completed.audience,
        locale: completed.locale,
        format: completed.format,
        version: completed.version,
        supersedesReportId: null,
        correctionReasonCode: null,
        lineageRootId: completed.lineageRootId,
        lineageRevision: completed.lineageRevision,
      });
      await fulfillReportData(route, 200, completed, `isolated-report-complete-${operations.complete}`);
      return;
    }

    if (action === "fail") {
      operations.fail += 1;
      if (report.state !== "pending") {
        await fulfillReportError(route, 409, "REPORT_STATE_CONFLICT", "Synthetic report is not pending");
        return;
      }
      const request = route.request().postDataJSON() as { expectedVersion: number; errorCode: string };
      expect(request.expectedVersion).toBe(report.version);
      expect(request.errorCode).toMatch(/^[A-Z][A-Z0-9_]{2,63}$/u);
      const failedAt = new Date(Date.UTC(2026, 8, 11, 13, operations.fail, 0)).toISOString();
      const failed: IsolatedFailedReport = {
        ...report,
        state: "failed",
        version: report.version + 1,
        errorCode: request.errorCode,
        failedAt,
      };
      reports.set(reportId, failed);
      await fulfillReportData(route, 200, {
        id: reportId,
        state: "failed",
        version: failed.version,
        errorCode: failed.errorCode,
        failedAt,
      }, `isolated-report-fail-${operations.fail}`);
      return;
    }

    if (action === "print") {
      operations.print += 1;
      const artifact = artifacts.get(reportId);
      if (report.state !== "ready" || !artifact) {
        await fulfillReportError(route, 409, "REPORT_ARTIFACT_UNAVAILABLE", "Synthetic artifact is unavailable");
        return;
      }
      const request = route.request().postDataJSON() as { artifactSha256: `sha256:${string}` };
      expect(request.artifactSha256).toBe(artifact.artifactSha256);
      await fulfillReportData(route, 201, {
        id: reportId,
        artifactSha256: artifact.artifactSha256,
        printedAt: new Date(Date.UTC(2026, 8, 11, 14, operations.print, 0)).toISOString(),
      }, `isolated-report-print-${operations.print}`);
      return;
    }

    await fulfillReportError(route, 404, "REPORT_OPERATION_UNAVAILABLE", "Synthetic report operation is unavailable");
  });

  await page.route(localQaApiRoute(/^\/v1\/reports\/[^/]+\/artifact$/u), async (route) => {
    if (route.request().method() !== "GET") {
      await fulfillReportError(route, 405, "METHOD_NOT_ALLOWED", "Synthetic artifact download requires GET");
      return;
    }
    operations.download += 1;
    const reportId = decodeURIComponent(new URL(route.request().url()).pathname.split("/")[3] ?? "");
    const artifact = artifacts.get(reportId);
    if (!artifact) {
      await fulfillReportError(route, 404, "REPORT_ARTIFACT_UNAVAILABLE", "Synthetic artifact is unavailable");
      return;
    }
    await fulfillReportData(route, 200, artifact, `isolated-report-download-${operations.download}`);
  });

  return { operations, reports, artifacts, reportListReads: () => reportListReads };
}

async function fulfillReportData(route: Route, status: number, data: unknown, requestId: string): Promise<void> {
  await route.fulfill({
    status,
    contentType: "application/json",
    headers: { "cache-control": "private, no-store", "x-request-id": requestId },
    body: JSON.stringify({ data, meta: { requestId } }),
  });
}

async function fulfillReportError(route: Route, status: number, code: string, message: string): Promise<void> {
  const requestId = `isolated-report-error-${status}`;
  await route.fulfill({
    status,
    contentType: "application/json",
    headers: { "cache-control": "private, no-store", "x-request-id": requestId },
    body: JSON.stringify({ error: { code, message }, meta: { requestId } }),
  });
}

function isolatedReportMediaType(format: ReportFormat): string {
  if (format === "pdf") return "application/pdf";
  if (format === "xlsx") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  return "text/csv; charset=utf-8";
}

async function assertReportMutationHeaders(route: Route): Promise<void> {
  const headers = await route.request().allHeaders();
  const idempotencyKey = headers["idempotency-key"] ?? "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(idempotencyKey)) {
    throw new Error("Synthetic report mutation requires a UUID Idempotency-Key header");
  }
  const contentType = (headers["content-type"] ?? "").split(";", 1)[0]?.trim().toLocaleLowerCase();
  if (contentType !== "application/json") {
    throw new Error("Synthetic report mutation requires an application/json Content-Type header");
  }
  const csrfHeader = headers["x-csrf-token"];
  const csrfCookie = cookieValue(headers["cookie"], "nom_csrf");
  if (!csrfHeader || !csrfCookie || csrfHeader !== csrfCookie) {
    throw new Error("Synthetic report mutation failed CSRF header/cookie coherence");
  }
}

function cookieValue(cookieHeader: string | undefined, name: string): string | undefined {
  for (const segment of cookieHeader?.split(";") ?? []) {
    const separator = segment.indexOf("=");
    if (separator < 1 || segment.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(segment.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function canonicalBase64UrlBytes(value: string, field: "nonce" | "ciphertext" | "aad"): Buffer {
  if (!value || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error(`Synthetic report ${field} must be base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw new Error(`Synthetic report ${field} must use canonical base64url`);
  }
  return bytes;
}

function isUnsafeSpreadsheetCell(value: string): boolean {
  return /^[\p{White_Space}]*[=+\-@\t\r\n]/u.test(value);
}
