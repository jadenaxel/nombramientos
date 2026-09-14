import { expect, test } from "@playwright/test";

import { navigateToAppSection, signInDemo, submitDemoVaultUnlock, unlockDemoVault } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";
import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const apiOrigin = resolveLocalQaOrigins().apiOrigin;

type ImportRowPayload = {
  sourceRow: number;
  decision: { action: "create" | "update" | "skip"; matchBasis: string };
  displayEnvelope?: unknown;
  contactEnvelope?: unknown;
};

type ActiveRoundEnvelope = {
  data: {
    round: { id: string; phase: string; version: number };
    candidates: Array<{ id: string }>;
  };
  meta?: unknown;
};

test("AC-08 browser previews create, update and skip while retaining an accent-insensitive homonym", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One deterministic mocked commit avoids persistent roster growth");
  await signInDemo(page);

  let previewPayload: { rows: ImportRowPayload[] } | undefined;
  let commitPayload: { importId: string; expectedRevision: number } | undefined;
  await page.route(localQaApiRoute("/v1/members/import/preview"), async (route) => {
    previewPayload = route.request().postDataJSON() as { rows: ImportRowPayload[] };
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "ac08-preview-browser" },
      body: JSON.stringify({
        data: {
          importId: "a8000000-0000-4000-8000-000000000001",
          rowCount: 3,
          state: "previewed",
          createdAt: "2026-09-11T12:00:00.000Z",
          revision: 1,
          counts: { create: 1, update: 1, skip: 1, errors: 0 },
          rows: previewPayload.rows.map((row) => ({ sourceRow: row.sourceRow, action: row.decision.action, status: "ready", codes: [] })),
        },
        meta: { requestId: "ac08-preview-browser" },
      }),
    });
  });
  await page.route(localQaApiRoute("/v1/members/import/commit"), async (route) => {
    commitPayload = route.request().postDataJSON() as { importId: string; expectedRevision: number };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": "ac08-commit-browser" },
      body: JSON.stringify({
        data: { importId: commitPayload.importId, state: "completed", created: 1, updated: 1, skipped: 1, rejected: 0, total: 3 },
        meta: { requestId: "ac08-commit-browser" },
      }),
    });
  });

  await page.goto("/es/app/members");
  await unlockDemoVault(page, "es", "administrator");
  await expect(page.getByRole("heading", { name: /180 de 180 personas/ })).toBeVisible({ timeout: 30_000 });

  await page.getByLabel("Buscar en el padrón").fill("miembro demo 001");
  await expect(page.getByText("Miembro Demo 001", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: /1 de 180 personas/ })).toBeVisible();
  await page.getByLabel("Buscar en el padrón").fill("");

  await page.getByRole("button", { name: "Preparar importación" }).click();
  await page.locator("#member-import").setInputFiles({
    name: "ac08-browser.csv",
    mimeType: "text/csv",
    buffer: Buffer.from([
      "ID,Nombre completo,Correo",
      "M001,Miembro Demo 001,actualizar@example.test",
      ",Miémbró Démó 002,homonimo@example.test",
      "AC08-SKIP,Persona omitida,omitir@example.test",
    ].join("\r\n"), "utf8"),
  });
  await expect(page.getByLabel("Hoja")).toBeVisible();
  await page.getByRole("button", { name: "Validar y previsualizar" }).click();
  const preview = page.getByLabel("Previsualización de filas importadas");
  await expect(preview).toBeVisible();
  const homonymWarnings = preview.getByText("Posible homónimo por nombre");
  const retainedHomonymNotices = preview.getByText("El homónimo se conserva separado salvo decisión explícita");
  await expect(homonymWarnings).toHaveCount(2);
  await expect(retainedHomonymNotices).toHaveCount(2);
  await expect(homonymWarnings.first()).toBeVisible();
  await expect(homonymWarnings.nth(1)).toBeVisible();
  await expect(retainedHomonymNotices.first()).toBeVisible();
  await expect(retainedHomonymNotices.nth(1)).toBeVisible();

  await page.getByRole("button", { name: "Aplicar sugerencias a todas" }).click();
  await expect(page.getByLabel("Decisión fila 2")).toHaveValue("update");
  await expect(page.getByLabel("Decisión fila 3")).toHaveValue("create");
  await page.getByLabel("Decisión fila 4").selectOption("skip");
  await page.getByRole("button", { name: "Cifrar y validar en servidor" }).click();
  await expect(page.getByText("Previsualización persistida")).toBeVisible();

  expect(previewPayload?.rows.map((row) => row.decision.action)).toEqual(["update", "create", "skip"]);
  expect(previewPayload?.rows[0]?.displayEnvelope).toBeDefined();
  expect(previewPayload?.rows[1]?.displayEnvelope).toBeDefined();
  expect(previewPayload?.rows[2]?.displayEnvelope).toBeUndefined();
  await page.getByRole("button", { name: "Confirmar importación" }).click();
  await expect(page.getByText("Importación confirmada")).toBeVisible();
  await expect(page.getByText(/1 creados, 1 actualizados y 1 omitidos/)).toBeVisible();
  expect(commitPayload).toEqual({ importId: "a8000000-0000-4000-8000-000000000001", expectedRevision: 1 });
});

test("AC-09 restricted committee browser receives redacted members and cannot export", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "The real restricted Demo identity is exercised once");
  await signInDemo(page, "committee");

  const memberResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === "/v1/members" && response.status() === 200;
  });
  await page.goto("/es/app/members");
  await unlockDemoVault(page, "es", "committee");
  const memberResponse = await memberResponsePromise;
  const memberEnvelope = await memberResponse.json() as { data: { items: Array<Record<string, unknown>> } };
  expect(memberResponse.headers()["cache-control"]).toContain("no-store");
  expect(memberEnvelope.data.items.length).toBeGreaterThan(0);
  for (const member of memberEnvelope.data.items) {
    expect(member).not.toHaveProperty("contactEnvelope");
    expect(member).not.toHaveProperty("eligibilityEnvelope");
  }
  await expect(page.getByText("Nota privada · acceso restringido")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "CSV", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Excel", exact: true })).toHaveCount(0);

  await navigateToAppSection(page, "Reportes");
  await expect(page.getByRole("heading", { name: "Reportes" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Vista sin exportación")).toBeVisible();
  await expect(page.getByRole("button", { name: "PDF", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "XLSX", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "CSV", exact: true })).toHaveCount(0);

  const denied = await page.evaluate(async (origin) => {
    const sessionResponse = await fetch(`${origin}/v1/session`, { credentials: "include", cache: "no-store" });
    const session = await sessionResponse.json() as { data: { csrfToken: string } };
    const headers = {
      "content-type": "application/json",
      "x-csrf-token": session.data.csrfToken,
      "idempotency-key": crypto.randomUUID(),
    };
    const [memberExport, reportExport] = await Promise.all([
      fetch(`${origin}/v1/members/export-authorizations`, {
        method: "POST", credentials: "include", cache: "no-store", headers,
        body: JSON.stringify({ format: "csv", rowCount: 1, includeContact: false, filters: { status: "all", queryApplied: false }, selectionSha256: `sha256:${"a".repeat(64)}` }),
      }),
      fetch(`${origin}/v1/reports/generate`, {
        method: "POST", credentials: "include", cache: "no-store", headers: { ...headers, "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({ reportType: "cycle_summary", format: "csv", locale: "es", audience: "committee", filters: {} }),
      }),
    ]);
    return { memberExport: memberExport.status, reportExport: reportExport.status };
  }, apiOrigin);
  expect(denied).toEqual({ memberExport: 403, reportExport: 403 });
});

test("AC-18 browser presents zero-vote, single-candidate, tie, top-K and cutoff-tie outcomes without writes", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "Deterministic read-only aggregate projections run once");
  await signInDemo(page);

  let scenario = 0;
  let candidateIds: string[] = [];
  await page.route(localQaApiRoute("/v1/rounds/active"), async (route) => {
    const response = await route.fetch();
    const envelope = structuredClone(await response.json() as ActiveRoundEnvelope);
    envelope.data.round.phase = "RESULTADO_INTERNO";
    candidateIds = envelope.data.candidates.map(({ id }) => id);
    if (candidateIds.length < 3) throw new Error("AC-18 requires at least three deterministic Demo candidates");
    if (scenario === 1) envelope.data.candidates = envelope.data.candidates.slice(0, 1);
    await route.fulfill({ response, json: envelope });
  });
  await page.route(localQaApiRoute(/^\/v1\/rounds\/[^/]+\/custody\/aggregate$/u), async (route) => {
    const [first, second, third] = candidateIds;
    if (!first || !second || !third) throw new Error("AC-18 candidate projection was not loaded before its aggregate");
    const cases = [
      { votes: [0, 0, 0], maxSelections: 1, status: "NO_SELECTION", reason: "NO_VALID_CANDIDATE_VOTES", selected: [], tiebreak: [], unfilled: 1 },
      { votes: [1], maxSelections: 1, status: "SELECTED", reason: "TOP_K", selected: [first], tiebreak: [], unfilled: 0 },
      { votes: [3, 3, 1], maxSelections: 1, status: "TIEBREAK_REQUIRED", reason: "CUTOFF_TIE", selected: [], tiebreak: [first, second], unfilled: 1 },
      { votes: [5, 4, 1], maxSelections: 2, status: "SELECTED", reason: "TOP_K", selected: [first, second], tiebreak: [], unfilled: 0 },
      { votes: [5, 3, 3], maxSelections: 2, status: "PARTIAL_SELECTION", reason: "CUTOFF_TIE", selected: [first], tiebreak: [second, third], unfilled: 1 },
    ] as const;
    const current = cases[scenario]!;
    const aggregateCandidateIds = scenario === 1 ? [first] : [first, second, third];
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "cache-control": "no-store", "x-request-id": `ac18-${scenario}` },
      body: JSON.stringify({
        data: {
          roundId: "ac18-round", manifestId: "ac18-manifest", manifestHash: `sha256:${"a".repeat(64)}`,
          aggregateHash: `sha256:${"b".repeat(64)}`, state: "published", version: 1, publishedAt: "2026-09-11T12:00:00.000Z",
          aggregate: {
            schemaVersion: 1, receivedBallots: 5, nonAbstainingBallots: current.votes.some(Boolean) ? 5 : 0,
            abstentions: current.votes.some(Boolean) ? 0 : 5, maxSelections: current.maxSelections,
            candidates: aggregateCandidateIds.map((candidateId, index) => ({ candidateId, votes: current.votes[index] })),
            rule: { kind: "PLURALITY" },
            decision: { status: current.status, reason: current.reason, selectedCandidateIds: current.selected, tiebreakCandidateIds: current.tiebreak, unfilledSeats: current.unfilled },
          },
        },
        meta: { requestId: `ac18-${scenario}` },
      }),
    });
  });

  const expected = [
    ["Sin selección", "Ninguna candidatura recibió votos válidos", "Plazas sin cubrir", "1"],
    ["Selección completa", "Mayor cantidad de votos válidos dentro de las plazas disponibles", "Plazas sin cubrir", "0"],
    ["Desempate requerido", "Empate que afecta el último cupo; se requiere una ronda nueva", "Candidaturas para desempate", "Plazas sin cubrir", "1"],
    ["Selección completa", "Mayor cantidad de votos válidos dentro de las plazas disponibles", "Plazas sin cubrir", "0"],
    ["Selección parcial", "Empate que afecta el último cupo; se requiere una ronda nueva", "Candidaturas para desempate", "Plazas sin cubrir", "1"],
  ] as const;
  for (scenario = 0; scenario < expected.length; scenario += 1) {
    await page.goto(`/es/app/results?ac18=${scenario}`);
    await submitDemoVaultUnlock(page, "es", "administrator");
    const tally = page.locator(".published-tally");
    await expect(tally).toBeVisible({ timeout: 30_000 });
    for (const text of expected[scenario]!) await expect(tally).toContainText(text);
    await expect(tally).toContainText("No contiene vínculos entre elector y preferencia");
  }
});

test("AC-20 live browser responses are no-store and the SSE ready frame is metadata-only", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One live network inspection is sufficient");
  await signInDemo(page, "committee");
  const session = await page.evaluate(async (origin) => {
    const response = await fetch(`${origin}/v1/session`, { credentials: "include", cache: "no-store" });
    return response.json() as Promise<{ data: { tenant: { id: string } } }>;
  }, apiOrigin);

  const projections = await page.evaluate(async (origin) => {
    const paths = ["/v1/dashboard", "/v1/rounds/active", "/v1/reports"];
    return Promise.all(paths.map(async (path) => {
      const response = await fetch(`${origin}${path}`, { credentials: "include", cache: "no-store" });
      return { path, status: response.status, cacheControl: response.headers.get("cache-control"), body: await response.text() };
    }));
  }, apiOrigin);
  for (const projection of projections) {
    expect(projection.status).toBe(200);
    expect(projection.cacheControl).toContain("no-store");
    expect(projection.body).not.toMatch(/"(?:electorIdentityId|identityId|preference|selectedCandidateIds|privateNote|contactEnvelope|eligibilityEnvelope)"/u);
  }

  const streamResponsePromise = page.waitForResponse((response) => new URL(response.url()).pathname === "/v1/events" && response.status() === 200);
  const readyPromise = page.evaluate(({ origin, tenantId }) => new Promise<{ type: string; data: Record<string, unknown> }>((resolve, reject) => {
    const source = new EventSource(`${origin}/v1/events?tenantId=${encodeURIComponent(tenantId)}`, { withCredentials: true });
    const timeout = window.setTimeout(() => { source.close(); reject(new Error("SSE ready frame timeout")); }, 10_000);
    source.addEventListener("ready", (event) => {
      window.clearTimeout(timeout);
      source.close();
      resolve({ type: event.type, data: JSON.parse((event as MessageEvent<string>).data) as Record<string, unknown> });
    });
    source.onerror = () => { window.clearTimeout(timeout); source.close(); reject(new Error("SSE connection failed")); };
  }), { origin: apiOrigin, tenantId: session.data.tenant.id });
  const [streamResponse, ready] = await Promise.all([streamResponsePromise, readyPromise]);
  expect(streamResponse.headers()["content-type"]).toContain("text/event-stream");
  expect(streamResponse.headers()["cache-control"]).toContain("no-store");
  expect(streamResponse.headers()["cache-control"]).toContain("no-transform");
  expect(streamResponse.headers()["x-accel-buffering"]).toBe("no");
  expect(ready.type).toBe("ready");
  expect(Object.keys(ready.data).sort()).toEqual(["cursor", "requestId", "tenantId"]);
  expect(ready.data.tenantId).toBe(session.data.tenant.id);
  expect(JSON.stringify(ready.data)).not.toMatch(/preference|vote|candidate|member|private|email/iu);
  const cachedApiRequests = await page.evaluate(async () => {
    const requests: string[] = [];
    for (const cacheName of await caches.keys()) {
      const cache = await caches.open(cacheName);
      requests.push(...(await cache.keys()).map(({ url }) => url));
    }
    return requests.filter((url) => new URL(url).pathname.startsWith("/v1/"));
  });
  expect(cachedApiRequests).toEqual([]);
});

test("AC-30 every locale keeps localized failures bounded in each configured browser viewport", async ({ page }, testInfo) => {
  const expected = {
    es: ["No se pudo abrir el resumen", "La información no se reemplazó con datos ficticios"],
    en: ["The overview could not be opened", "The information was not replaced with fictional data"],
    fr: ["Le résumé n’a pas pu être ouvert", "Les informations n’ont pas été remplacées par des données fictives"],
  } as const;
  await signInDemo(page);
  await page.route(localQaApiRoute("/v1/dashboard"), (route) => route.fulfill({
    status: 500,
    contentType: "application/json",
    headers: { "cache-control": "no-store", "x-request-id": "ac30-localized-browser" },
    body: JSON.stringify({ error: { code: "INTERNAL_FAILURE", message: "AC30_SERVER_SENTINEL" } }),
  }));
  for (const locale of ["es", "en", "fr"] as const) {
    await page.goto(`/${locale}/app/overview?ac30=${encodeURIComponent(testInfo.project.name)}`);
    await submitDemoVaultUnlock(page, locale, "administrator");
    await expect(page.locator("html")).toHaveAttribute("lang", locale);
    await expect(page.getByText(expected[locale][0], { exact: true })).toBeVisible();
    await expect(page.getByText(expected[locale][1], { exact: false })).toBeVisible();
    await expect(page.getByText("AC30_SERVER_SENTINEL")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
    const viewport = page.viewportSize();
    expect(viewport?.width ?? 0).toBeGreaterThanOrEqual(320);
    if ((viewport?.width ?? 1_024) < 1_024) {
      await expect(page.getByRole("button", { name: /^(?:Abrir menú|Open menu|Ouvrir le menu)$/u }).first()).toBeVisible();
    } else {
      await expect(page.getByRole("link", { name: locale === "es" ? "Resumen" : locale === "en" ? "Overview" : "Vue d’ensemble", exact: true }).first()).toBeVisible();
    }
  }
});
