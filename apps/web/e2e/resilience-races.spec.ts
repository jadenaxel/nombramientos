import { expect, test, type APIResponse, type Page, type Route } from "@playwright/test";
import { signInDemo } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";

type ActiveRoundEnvelope = {
  data: {
    viewerCanSubmit?: boolean;
    round: {
      phase: string;
      version: number;
      submissionKind: "proposal" | "vote";
    };
    candidates: Array<{
      displayEnvelope: {
        ciphertext: string;
      };
    }>;
  };
  meta?: unknown;
};

test("offline draft is revalidated against a closed round before submission", async ({ page, context }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "Exercises the local demo race once without mutating tenant data");
  await signInDemo(page);

  let simulateClosedRound = false;
  let activeRoundReads = 0;
  let submissionPosts = 0;
  let releaseClosedRound!: () => void;
  const closedRoundGate = new Promise<void>((resolve) => { releaseClosedRound = resolve; });
  await page.route(localQaApiRoute("/v1/rounds/active"), async (route) => {
    activeRoundReads += 1;
    const { response, envelope } = await fetchActiveRoundEnvelope(route);
    envelope.data.viewerCanSubmit = true;
    if (simulateClosedRound) {
      await closedRoundGate;
      envelope.data.round.phase = envelope.data.round.submissionKind === "proposal"
        ? "PROPUESTAS_CERRADAS"
        : "VOTACION_CERRADA";
      envelope.data.round.version += 1;
    }
    await route.fulfill({ response, json: envelope });
  });
  await denyPriorReceipt(page);
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions$/u), async (route) => {
    if (route.request().method() === "POST") {
      submissionPosts += 1;
      return route.fulfill({
        status: 409,
        contentType: "application/json",
        headers: { "x-request-id": "synthetic-closed-round-race" },
        body: JSON.stringify({ error: { code: "ROUND_CLOSED", message: "Synthetic closed-round race" } }),
      });
    }
    return route.continue();
  });

  await page.getByRole("link", { name: "Sesión en curso" }).click();
  await expect(page.locator(".phase-badge")).toContainText(/Propuestas abiertas|Votación abierta/);
  await expect(page.locator(".connection-banner.live")).toBeVisible({ timeout: 15_000 });
  const candidateChoice = page.locator(".candidate-list").locator('[role="radio"]:not([disabled]), [role="checkbox"]:not([disabled])').first();
  await expect(candidateChoice).toBeVisible();
  await candidateChoice.click();
  const reviewButton = page.getByRole("button", { name: "Revisar y enviar" });
  await expect(reviewButton).toBeEnabled();
  const readsBeforeOffline = activeRoundReads;

  await context.setOffline(true);
  await expect(page.locator(".connection-banner.offline")).toBeVisible({ timeout: 15_000 });
  await expect(reviewButton).toBeDisabled();
  await expect(page.locator(".receipt-card")).toHaveCount(0);

  simulateClosedRound = true;
  await context.setOffline(false);
  await expect.poll(() => activeRoundReads, { timeout: 20_000 }).toBeGreaterThan(readsBeforeOffline);
  await expect(page.locator(".connection-banner.connecting")).toBeVisible();
  await expect(reviewButton).toBeDisabled();
  expect(submissionPosts).toBe(0);
  releaseClosedRound();
  await expect(page.locator(".phase-badge")).toContainText(/Propuestas cerradas|Votación cerrada/);
  const closedCandidateControls = page.locator(".candidate-list").locator('[role="radio"], [role="checkbox"]');
  await expect(closedCandidateControls.first()).toBeVisible({ timeout: 30_000 });
  expect(await closedCandidateControls.evaluateAll((controls: HTMLButtonElement[]) =>
    controls.length > 0 && controls.every((control) => control.disabled))).toBe(true);
  await expect(reviewButton).toBeDisabled();

  // Even a programmatic click on the disabled control cannot open confirmation
  // or create a request after the server phase has been revalidated.
  await reviewButton.evaluate((button: HTMLButtonElement) => button.click());
  await expect(page.getByRole("heading", { name: "Confirmar respuesta" })).toHaveCount(0);
  await expect(page.locator(".receipt-card")).toHaveCount(0);
  expect(submissionPosts).toBe(0);
});

test("tampered candidate ciphertext fails closed in the browser", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "Exercises one authenticated browser and never persists plaintext or secrets");
  await signInDemo(page);

  let submissionPosts = 0;
  await page.route(localQaApiRoute("/v1/rounds/active"), async (route) => {
    const { response, envelope } = await fetchActiveRoundEnvelope(route);
    envelope.data.viewerCanSubmit = true;
    const first = envelope.data.candidates[0];
    if (!first) throw new Error("The deterministic demo round has no candidate ciphertext to tamper");
    first.displayEnvelope.ciphertext = corruptCiphertext(first.displayEnvelope.ciphertext);
    await route.fulfill({ response, json: envelope });
  });
  await denyPriorReceipt(page);
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions$/u), async (route) => {
    if (route.request().method() === "POST") submissionPosts += 1;
    await route.abort("blockedbyclient");
  });

  await page.getByRole("link", { name: "Sesión en curso" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Lista cifrada no disponible" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("No fue posible autenticar y descifrar la lista congelada de candidatos.")).toBeVisible();
  const failedCandidateList = page.locator(".candidate-list");
  await expect(failedCandidateList).toBeVisible();
  const failedCandidateControls = failedCandidateList.locator('[role="radio"], [role="checkbox"]');
  await expect(failedCandidateControls.first()).toBeVisible();
  expect(await failedCandidateControls.evaluateAll((controls: HTMLButtonElement[]) =>
    controls.length > 0 && controls.every((control) => control.disabled))).toBe(true);
  await expect(page.locator(".receipt-card")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Revisar y enviar" })).toBeDisabled();
  expect(submissionPosts).toBe(0);
});

async function denyPriorReceipt(page: Page): Promise<void> {
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions\/me$/u), (route) => route.fulfill({
    status: 404,
    contentType: "application/json",
    headers: { "x-request-id": "synthetic-no-prior-receipt" },
    body: JSON.stringify({ error: { code: "SUBMISSION_NOT_FOUND", message: "Synthetic empty receipt" } }),
  }));
}

function corruptCiphertext(ciphertext: string): string {
  if (!ciphertext) throw new Error("The deterministic demo candidate ciphertext is empty");
  return `${ciphertext[0] === "A" ? "B" : "A"}${ciphertext.slice(1)}`;
}

const ACTIVE_ROUND_RATE_LIMIT_RETRIES = 3;
const ACTIVE_ROUND_MAX_RETRY_DELAY_MS = 5_000;

async function fetchActiveRoundEnvelope(route: Route): Promise<{
  readonly response: APIResponse;
  readonly envelope: ActiveRoundEnvelope;
}> {
  for (let attempt = 0; attempt <= ACTIVE_ROUND_RATE_LIMIT_RETRIES; attempt += 1) {
    const response = await route.fetch();
    if (response.status() === 429 && attempt < ACTIVE_ROUND_RATE_LIMIT_RETRIES) {
      const retryDelayMs = boundedRetryAfterMs(response.headers()["retry-after"]);
      await response.dispose();
      await new Promise<void>((resolve) => setTimeout(resolve, retryDelayMs));
      continue;
    }
    if (response.status() !== 200) {
      throw new Error(
        `The deterministic Demo active-round read returned HTTP ${response.status()}${safeRequestId(response)}`,
      );
    }

    const payload = await response.json().catch(() => undefined) as unknown;
    if (!isActiveRoundEnvelope(payload)) {
      throw new Error(`The deterministic Demo active-round read returned an invalid success envelope${safeRequestId(response)}`);
    }
    return { response, envelope: structuredClone(payload) };
  }
  throw new Error("The deterministic Demo active-round read exhausted its bounded retry loop");
}

function boundedRetryAfterMs(value: string | undefined): number {
  const seconds = value === undefined ? Number.NaN : Number(value);
  const requestedDelayMs = Number.isFinite(seconds) && seconds >= 0
    ? Math.ceil(seconds * 1_000)
    : 1_000;
  return Math.min(Math.max(requestedDelayMs, 250), ACTIVE_ROUND_MAX_RETRY_DELAY_MS);
}

function safeRequestId(response: APIResponse): string {
  const requestId = response.headers()["x-request-id"];
  return requestId && /^[0-9a-f-]{16,64}$/iu.test(requestId) ? ` (request ${requestId})` : "";
}

function isActiveRoundEnvelope(value: unknown): value is ActiveRoundEnvelope {
  if (!value || typeof value !== "object" || !("data" in value)) return false;
  const data = value.data;
  if (!data || typeof data !== "object" || !("round" in data) || !("candidates" in data)) return false;
  const round = data.round;
  return Boolean(
    round &&
    typeof round === "object" &&
    "phase" in round &&
    typeof round.phase === "string" &&
    "version" in round &&
    typeof round.version === "number" &&
    "submissionKind" in round &&
    (round.submissionKind === "proposal" || round.submissionKind === "vote") &&
    Array.isArray(data.candidates),
  );
}
