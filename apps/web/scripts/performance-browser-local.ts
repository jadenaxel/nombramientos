import { randomBytes, webcrypto } from "node:crypto";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";

import { chromium } from "@playwright/test";

import { writeBrowserJsonEvidenceAtomic } from "./performance-browser-evidence.ts";
import {
  EXACT_PUBLIC_SIGN_IN_PATH,
  assertExactLocalWebBaseUrl,
  isExactPublicSignInUrl,
} from "./performance-browser-guards.ts";

const MEMBER_COUNT = 10_000;
const SEARCH_QUERY_COUNT = 40;
const SEARCH_SAMPLE_COUNT = SEARCH_QUERY_COUNT + 1;
const SEARCH_BUDGET_MS = 300;
const LCP_BUDGET_MS = 2_500;
const INP_BUDGET_MS = 200;
const CLS_BUDGET = 0.1;
const UI_GAP_BUDGET_MS = 250;
const workspaceRoot = path.resolve(import.meta.dirname, "../../..");
const artifactPath = path.join(workspaceRoot, "artifacts", "performance-browser-local.json");

type BrowserPipelineMeasurement = {
  readonly memberCount: number;
  readonly payloadBytes: number;
  readonly downloadMs: number;
  readonly parseMs: number;
  readonly decryptMs: number;
  readonly indexBuildMs: number;
  readonly downloadDecryptIndexMs: number;
  readonly searchSamples: number;
  readonly searchP95Ms: number;
  readonly searchMaxMs: number;
  readonly knownMatchCount: number;
  readonly absentMatchCount: number;
};

type BrowserEvidenceReport = Readonly<Record<string, unknown>> & {
  readonly schemaVersion: 2;
  readonly status: "in-progress" | "passed" | "failed";
  readonly inProgress: boolean;
  readonly closureEligible: boolean;
  readonly cleanup: Readonly<Record<string, unknown>> & { readonly pass: boolean };
  readonly overallPass: boolean;
};

const startedAtUtc = new Date().toISOString();
const startedAt = performance.now();
writeArtifact({
  schemaVersion: 2,
  acceptanceCriterion: "AC-37-browser",
  startedAtUtc,
  completedAtUtc: startedAtUtc,
  status: "in-progress",
  inProgress: true,
  closureEligible: false,
  environment: { state: "pending" },
  dataset: browserDataset(),
  thresholds: browserThresholds(),
  measurements: {},
  cleanup: {
    browserClosed: false,
    syntheticServerClosed: false,
    ephemeralBuffersZeroedAndReferencesReleased: false,
    protectedOperationalDataAccess: "not-measured",
    pass: false,
  },
  checks: {},
  overallPass: false,
  deviations: ["run-in-progress"],
});
const webBaseUrl = assertExactLocalWebBaseUrl(process.env.WEB_BASE_URL ?? "http://localhost:3000");
const rawKey = randomBytes(32);
const datasetStartedAt = performance.now();
const dataset = await buildEncryptedDataset(rawKey);
const datasetJson = Buffer.from(JSON.stringify(dataset));
const payloadBytes = datasetJson.byteLength;
const datasetGenerationMs = round(performance.now() - datasetStartedAt);
const server = createServer((request, response) => {
  if (request.url === "/dataset.json") {
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-length": String(datasetJson.byteLength),
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    });
    response.end(datasetJson);
    return;
  }
  response.writeHead(200, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8",
    "x-content-type-options": "nosniff",
  });
  response.end("<!doctype html><html lang=es><meta charset=utf-8><title>Banco E2EE efímero</title><body><main><h1>Banco E2EE efímero</h1></main></body></html>");
});

let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
try {
  const origin = await listen(server);
  browser = await chromium.launch({ headless: true });
  const cryptoContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const cryptoPage = await cryptoContext.newPage();
  await cryptoPage.goto(origin, { waitUntil: "domcontentloaded" });
  await cryptoPage.addScriptTag({ content: "globalThis.__name = (target) => target;" });
  const browserPipeline = await cryptoPage.evaluate(async ({
    count,
    datasetUrl,
    key,
    searchBudgetMs,
    searchQueryCount,
    uiGapBudgetMs,
  }) => {
    const workerSource = `
      const decoder = new TextDecoder();
      function decode(value) {
        const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
        const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
        return bytes;
      }
      function normalize(value) {
        return value.normalize("NFD").replace(/\\p{Diacritic}/gu, "").toLocaleLowerCase("es").trim();
      }
      self.onmessage = async ({ data }) => {
        try {
          const totalStartedAt = performance.now();
          const downloadStartedAt = performance.now();
          const response = await fetch(data.url, { cache: "no-store", credentials: "omit" });
          if (!response.ok) throw new Error("dataset download failed");
          const bytes = await response.arrayBuffer();
          const downloadMs = performance.now() - downloadStartedAt;
          const parseStartedAt = performance.now();
          const rows = JSON.parse(decoder.decode(bytes));
          const parseMs = performance.now() - parseStartedAt;
          if (!Array.isArray(rows) || rows.length !== data.count) throw new Error("dataset cardinality mismatch");
          const cryptoKey = await crypto.subtle.importKey("raw", decode(data.key), "AES-GCM", false, ["decrypt"]);
          const decryptStartedAt = performance.now();
          const decrypted = [];
          for (let offset = 0; offset < rows.length; offset += 200) {
            const batch = rows.slice(offset, offset + 200);
            const values = await Promise.all(batch.map(async (row) => {
              if (row.envelope.algorithm !== "AES-256-GCM" || row.envelope.keyId !== "perf-tenant-key-v1") {
                throw new Error("envelope contract mismatch");
              }
              const aadBytes = decode(row.envelope.aad);
              const aad = JSON.parse(decoder.decode(aadBytes));
              if (aad.tenantId !== "performance-browser-ephemeral" || aad.memberId !== row.id || aad.purpose !== "member-display" || aad.schemaVersion !== 1) {
                throw new Error("AAD context mismatch");
              }
              const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: decode(row.envelope.nonce), additionalData: aadBytes },
                cryptoKey,
                decode(row.envelope.ciphertext),
              );
              return { id: row.id, stableCode: row.stableCode, ...JSON.parse(decoder.decode(plain)) };
            }));
            decrypted.push(...values);
          }
          const decryptMs = performance.now() - decryptStartedAt;
          const indexStartedAt = performance.now();
          const index = decrypted.map((row) => ({
            id: row.id,
            haystack: normalize(row.fullName + " " + row.givenNames + " " + row.familyNames + " " + row.stableCode),
          }));
          const indexBuildMs = performance.now() - indexStartedAt;
          const queries = Array.from({ length: data.searchQueryCount }, (_, index) => index % 5 === 0 ? "persona alvarez 9999" : "persona alvarez " + (index * 233 % data.count));
          queries.push("persona inexistente 000000");
          const searchDurations = [];
          let knownMatchCount = 0;
          let absentMatchCount = -1;
          for (const query of queries) {
            const searchStartedAt = performance.now();
            const matches = index.filter((entry) => entry.haystack.includes(normalize(query)));
            searchDurations.push(performance.now() - searchStartedAt);
            if (query === "persona alvarez 9999") knownMatchCount = matches.length;
            if (query === "persona inexistente 000000") absentMatchCount = matches.length;
          }
          searchDurations.sort((left, right) => left - right);
          self.postMessage({
            memberCount: rows.length,
            payloadBytes: bytes.byteLength,
            downloadMs,
            parseMs,
            decryptMs,
            indexBuildMs,
            downloadDecryptIndexMs: performance.now() - totalStartedAt,
            searchSamples: searchDurations.length,
            searchP95Ms: searchDurations[Math.ceil(searchDurations.length * 0.95) - 1],
            searchMaxMs: searchDurations.at(-1),
            knownMatchCount,
            absentMatchCount,
          });
        } catch (error) {
          self.postMessage({ error: error instanceof Error ? error.message : String(error) });
        }
      };
    `;
    const worker = new Worker(URL.createObjectURL(new Blob([workerSource], { type: "text/javascript" })));
    const nextAnimationFrame = () => new Promise<number>((resolve) => requestAnimationFrame(resolve));
    // Chromium's first compositor frame can include a one-time headless startup
    // delay. Establish a steady 60 Hz baseline before attributing frame gaps to
    // the worker workload itself.
    await nextAnimationFrame();
    await nextAnimationFrame();
    let animationFrameCount = 0;
    let maxAnimationFrameGapMs = 0;
    let lastFrame = performance.now();
    let active = true;
    const frame = (now: number) => {
      maxAnimationFrameGapMs = Math.max(maxAnimationFrameGapMs, now - lastFrame);
      lastFrame = now;
      animationFrameCount += 1;
      if (active) requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
    const result = await Promise.race([
      new Promise<BrowserPipelineMeasurement>((resolve, reject) => {
        worker.onmessage = ({ data }) => data.error ? reject(new Error(data.error)) : resolve(data as BrowserPipelineMeasurement);
        worker.onerror = (event) => reject(new Error(event.message));
        worker.postMessage({ url: datasetUrl, count, key, searchQueryCount });
      }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("browser pipeline timed out")), 120_000)),
    ]);
    // Observe the final main-thread interval before stopping the frame loop so a
    // long delivery/GC gap cannot disappear between the worker result and the
    // next scheduled animation frame.
    await nextAnimationFrame();
    active = false;
    worker.terminate();
    return {
      ...result,
      animationFrameApiSupported: typeof requestAnimationFrame === "function",
      animationFrameCount,
      maxAnimationFrameGapMs,
      thresholds: { searchBudgetMs, uiGapBudgetMs },
    };
  }, {
    count: MEMBER_COUNT,
    datasetUrl: `${origin}/dataset.json`,
    key: rawKey.toString("base64url"),
    searchBudgetMs: SEARCH_BUDGET_MS,
    searchQueryCount: SEARCH_QUERY_COUNT,
    uiGapBudgetMs: UI_GAP_BUDGET_MS,
  });
  await cryptoContext.close();

  const observedHttpOrigins = new Set<string>();
  let blockedNonWebHttpRequests = 0;
  let blockedUnsafeHttpRequests = 0;
  let blockedWebSocketRequests = 0;
  const appContext = await browser.newContext({
    baseURL: webBaseUrl,
    viewport: { width: 390, height: 844 },
    locale: "es-DO",
    isMobile: true,
    hasTouch: true,
    serviceWorkers: "block",
  });
  await appContext.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.protocol === "http:" || url.protocol === "https:") {
      observedHttpOrigins.add(url.origin);
      if (url.origin !== webBaseUrl) {
        blockedNonWebHttpRequests += 1;
        await route.abort("blockedbyclient");
        return;
      }
      if (!new Set(["GET", "HEAD", "OPTIONS"]).has(request.method())) {
        blockedUnsafeHttpRequests += 1;
        await route.abort("blockedbyclient");
        return;
      }
    }
    await route.continue();
  });
  await appContext.routeWebSocket(/.*/u, async (webSocket) => {
    blockedWebSocketRequests += 1;
    await webSocket.close({ code: 1008, reason: "Browser performance probe forbids WebSocket traffic" });
  });
  await appContext.addInitScript({ content: "globalThis.__name = (target) => target;" });
  await appContext.addInitScript(() => {
    const state = { cls: 0, lcp: 0, eventDurations: [] as Array<{ duration: number; interactionId: number }> };
    Object.defineProperty(window, "__nombramientosPerformance", { value: state, configurable: false });
    if (PerformanceObserver.supportedEntryTypes.includes("layout-shift")) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries() as Array<PerformanceEntry & { value: number; hadRecentInput: boolean }>) {
          if (!entry.hadRecentInput) state.cls += entry.value;
        }
      }).observe({ type: "layout-shift", buffered: true });
    }
    if (PerformanceObserver.supportedEntryTypes.includes("largest-contentful-paint")) {
      new PerformanceObserver((list) => {
        const latest = list.getEntries().at(-1);
        if (latest) state.lcp = latest.startTime;
      }).observe({ type: "largest-contentful-paint", buffered: true });
    }
    if (PerformanceObserver.supportedEntryTypes.includes("event")) {
      new PerformanceObserver((list) => {
        for (const entry of list.getEntries() as Array<PerformanceEntry & { duration: number; interactionId: number }>) {
          if (entry.interactionId) state.eventDurations.push({ duration: entry.duration, interactionId: entry.interactionId });
        }
      }).observe({ type: "event", buffered: true, durationThreshold: 16 } as PerformanceObserverInit);
    }
  });
  const appPage = await appContext.newPage();
  await appPage.goto(`${webBaseUrl}/es/auth/sign-in`, { waitUntil: "domcontentloaded" });
  const emailInput = appPage.getByLabel("Correo electrónico");
  const passwordInput = appPage.getByLabel("Contraseña");
  await emailInput.waitFor({ state: "visible", timeout: 30_000 });
  await passwordInput.waitFor({ state: "visible", timeout: 30_000 });
  await appPage.evaluate(() => document.fonts.ready);
  await appPage.waitForTimeout(2_000);
  await emailInput.click();
  await emailInput.pressSequentially("performance.probe@example.invalid", { delay: 1 });
  await emailInput.press("Control+A");
  await emailInput.press("Backspace");
  await passwordInput.click();
  await passwordInput.pressSequentially("local-noncredential-probe", { delay: 1 });
  await passwordInput.press("Control+A");
  await passwordInput.press("Backspace");
  await emailInput.click();
  await appPage.waitForTimeout(1_000);
  const webVitals = await appPage.evaluate(() => {
    const state = (window as unknown as Window & { __nombramientosPerformance: { cls: number; lcp: number; eventDurations: Array<{ duration: number; interactionId: number }> } }).__nombramientosPerformance;
    const supportedEntryTypes = PerformanceObserver.supportedEntryTypes;
    const byInteraction = new Map<number, number>();
    for (const event of state.eventDurations) {
      byInteraction.set(event.interactionId, Math.max(byInteraction.get(event.interactionId) ?? 0, event.duration));
    }
    const interactions = [...byInteraction.values()].sort((left, right) => right - left);
    const navigation = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
    const firstContentfulPaint = performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? 0;
    return {
      lcpMs: state.lcp,
      cls: state.cls,
      inpMs: interactions[0] ?? null,
      interactionCount: interactions.length,
      firstContentfulPaintMs: firstContentfulPaint,
      domContentLoadedMs: navigation?.domContentLoadedEventEnd ?? 0,
      loadEventMs: navigation?.loadEventEnd ?? 0,
      layoutShiftSupported: supportedEntryTypes.includes("layout-shift"),
      largestContentfulPaintSupported: supportedEntryTypes.includes("largest-contentful-paint"),
      eventTimingSupported: supportedEntryTypes.includes("event"),
      supportedEntryTypes,
    };
  });
  const finalAppUrl = appPage.url();
  const exactFinalAppUrl = isExactPublicSignInUrl(finalAppUrl, webBaseUrl);
  const protectedCookieCount = (await appContext.cookies())
    .filter((cookie) => ["nom_session", "nom_csrf", "nom_mfa"].includes(cookie.name)).length;
  await appContext.close();

  const pipeline = roundNumbers(browserPipeline);
  const vitals = roundNumbers(webVitals);
  const exactPipelineKeys = [
    "absentMatchCount",
    "animationFrameApiSupported",
    "animationFrameCount",
    "decryptMs",
    "downloadDecryptIndexMs",
    "downloadMs",
    "indexBuildMs",
    "knownMatchCount",
    "maxAnimationFrameGapMs",
    "memberCount",
    "parseMs",
    "payloadBytes",
    "searchMaxMs",
    "searchP95Ms",
    "searchSamples",
    "thresholds",
  ];
  const pipelineFiniteMetrics = [
    pipeline.downloadMs,
    pipeline.parseMs,
    pipeline.decryptMs,
    pipeline.indexBuildMs,
    pipeline.downloadDecryptIndexMs,
    pipeline.searchP95Ms,
    pipeline.searchMaxMs,
    pipeline.maxAnimationFrameGapMs,
  ];
  const vitalsFiniteMetrics = [
    vitals.lcpMs,
    vitals.cls,
    vitals.firstContentfulPaintMs,
    vitals.domContentLoadedMs,
    vitals.loadEventMs,
    vitals.inpMs,
  ];
  const reportedObserverTypes = vitals.supportedEntryTypes;
  const checks = {
    exactPipelineMetricCardinality: JSON.stringify(Object.keys(pipeline).sort()) === JSON.stringify(exactPipelineKeys),
    pipelineMetricsFinite: pipelineFiniteMetrics.length === 8
      && pipelineFiniteMetrics.every((metric) => Number.isFinite(metric) && metric >= 0),
    vitalsMetricsFinite: vitalsFiniteMetrics.length === 6
      && vitalsFiniteMetrics.every((metric) => typeof metric === "number" && Number.isFinite(metric) && metric >= 0),
    exactMemberCount: pipeline.memberCount === MEMBER_COUNT,
    exactPayloadCardinality: Number.isSafeInteger(pipeline.payloadBytes)
      && pipeline.payloadBytes === payloadBytes
      && pipeline.payloadBytes > 0,
    exactSearchSampleCount: Number.isSafeInteger(pipeline.searchSamples)
      && pipeline.searchSamples === SEARCH_SAMPLE_COUNT,
    exactMatchMetricCardinality: Number.isSafeInteger(pipeline.knownMatchCount)
      && Number.isSafeInteger(pipeline.absentMatchCount),
    knownMemberFoundExactlyOnce: pipeline.knownMatchCount === 1,
    absenceReportedOnlyAfterCompleteIndex: pipeline.absentMatchCount === 0,
    searchMetricsOrdered: pipeline.searchP95Ms <= pipeline.searchMaxMs,
    localSearchP95WithinBudget: pipeline.searchP95Ms <= SEARCH_BUDGET_MS,
    localSearchMaxWithinBudget: pipeline.searchMaxMs <= SEARCH_BUDGET_MS,
    animationFrameMeasurementSupported: pipeline.animationFrameApiSupported === true,
    animationFrameMeasurementHasSamples: Number.isSafeInteger(pipeline.animationFrameCount)
      && pipeline.animationFrameCount >= 2,
    mainThreadResponsiveDuringWorkerPipeline: pipeline.animationFrameApiSupported === true
      && pipeline.animationFrameCount >= 2
      && pipeline.maxAnimationFrameGapMs <= UI_GAP_BUDGET_MS,
    lcpSupported: vitals.largestContentfulPaintSupported === true,
    observerEntryTypesUniqueAndConsistent: Array.isArray(reportedObserverTypes)
      && reportedObserverTypes.every((entryType) => typeof entryType === "string")
      && new Set(reportedObserverTypes).size === reportedObserverTypes.length
      && vitals.layoutShiftSupported === reportedObserverTypes.includes("layout-shift")
      && vitals.largestContentfulPaintSupported === reportedObserverTypes.includes("largest-contentful-paint")
      && vitals.eventTimingSupported === reportedObserverTypes.includes("event"),
    exactInteractionMetricCardinality: Number.isSafeInteger(vitals.interactionCount)
      && vitals.interactionCount >= 1,
    lcpWithinBudget: vitals.largestContentfulPaintSupported === true
      && vitals.lcpMs > 0
      && vitals.lcpMs <= LCP_BUDGET_MS,
    inpMeasured: vitals.eventTimingSupported === true
      && vitals.interactionCount >= 1
      && vitals.inpMs !== null,
    inpWithinBudget: vitals.eventTimingSupported === true
      && vitals.interactionCount >= 1
      && vitals.inpMs !== null
      && vitals.inpMs <= INP_BUDGET_MS,
    clsSupported: vitals.layoutShiftSupported === true,
    clsWithinBudget: vitals.layoutShiftSupported === true && vitals.cls <= CLS_BUDGET,
    exactPublicSignInFinalUrl: exactFinalAppUrl,
    publicRouteOnly: observedHttpOrigins.size === 1 && observedHttpOrigins.has(webBaseUrl),
    noNonWebHttpRequestsAttempted: blockedNonWebHttpRequests === 0,
    noUnsafeHttpRequestsAttempted: blockedUnsafeHttpRequests === 0,
    noWebSocketRequestsAttempted: blockedWebSocketRequests === 0,
    noProtectedAuthCookiesAtClose: protectedCookieCount === 0,
  };
  const launchedBrowser = browser;
  const chromiumVersion = launchedBrowser.version();
  await launchedBrowser.close();
  const browserClosed = !launchedBrowser.isConnected();
  browser = undefined;
  await close(server);
  const syntheticServerClosed = !server.listening;
  rawKey.fill(0);
  datasetJson.fill(0);
  dataset.length = 0;
  const ephemeralBuffersZeroedAndReferencesReleased = rawKey.every((value) => value === 0)
    && datasetJson.every((value) => value === 0)
    && dataset.length === 0;
  const cleanup = {
    browserClosed,
    syntheticServerClosed,
    ephemeralBuffersZeroedAndReferencesReleased,
    blockedNonWebHttpRequests,
    blockedUnsafeHttpRequests,
    blockedWebSocketRequests,
    protectedAuthCookies: protectedCookieCount,
    protectedOperationalDataAccess: "not-measured",
    protectedDatabaseFingerprint: {
      status: "not-measured",
      reason: "This complementary browser probe has no protected credentials and does not claim visibility into server-side database access",
    },
    pass: browserClosed
      && syntheticServerClosed
      && ephemeralBuffersZeroedAndReferencesReleased
      && blockedNonWebHttpRequests === 0
      && blockedUnsafeHttpRequests === 0
      && blockedWebSocketRequests === 0
      && protectedCookieCount === 0,
  };
  const overallPass = Object.values(checks).every(Boolean) && cleanup.pass;
  const artifact: BrowserEvidenceReport = {
    schemaVersion: 2,
    acceptanceCriterion: "AC-37-browser",
    startedAtUtc,
    completedAtUtc: new Date().toISOString(),
    status: overallPass ? "passed" : "failed",
    inProgress: false,
    closureEligible: overallPass,
    closureScope: "complementary browser evidence only; not standalone proof of production Members-route performance",
    totalWallMs: round(performance.now() - startedAt),
    environment: {
      hardware: { cpuModel: os.cpus()[0]?.model ?? "unknown", logicalCpuCount: os.cpus().length, totalMemoryGiB: round(os.totalmem() / 1024 ** 3, 3) },
      operatingSystem: { platform: os.platform(), release: os.release(), arch: os.arch() },
      runtime: { node: process.version, chromium: chromiumVersion },
      network: {
        transport: "HTTP over loopback TCP",
        tls: false,
        proxy: false,
        allowedAppOrigin: webBaseUrl,
        observedHttpOrigins: [...observedHttpOrigins].sort(),
      },
      viewport: { width: 390, height: 844, mobileEmulation: true },
    },
    dataset: browserDataset({ payloadBytes, datasetGenerationMs }),
    thresholds: browserThresholds(),
    measurementBoundary: {
      syntheticPipeline: "standalone Web Worker download/decrypt/index/search pipeline over an in-memory generated dataset",
      exercisesProductionMembersRoute: false,
      exercisesProductionMembersComponents: false,
      appVitalsRoute: EXACT_PUBLIC_SIGN_IN_PATH,
      appVitalsFinalUrl: finalAppUrl,
      appVitalsFinalUrlExact: exactFinalAppUrl,
      appVitalsAuthenticated: false,
      protectedCredentialsLoaded: false,
      protectedOperationalApiRequestsAllowedFromBrowser: false,
      serverSideDatabaseAccessMeasured: false,
    },
    measurements: {
      syntheticStandaloneCryptoPipeline: pipeline,
      publicSignInMobileVitals: vitals,
    },
    cleanup,
    checks,
    overallPass,
    deviations: [
      "synthetic-crypto-pipeline-does-not-measure-production-members-route-components-rendering-or-api",
      "loopback-download-does-not-model-wan-jitter-loss-or-tls",
      "chromium-mobile-emulation-is-not-physical-mobile-hardware-or-field-core-web-vitals",
      "single-run-lab-inp-is-an-event-timing-observation-not-a-real-user-monitoring-percentile",
    ],
  };
  writeArtifact(artifact);
  process.stdout.write(`${JSON.stringify({ artifact: path.relative(workspaceRoot, artifactPath), overallPass: artifact.overallPass, checks }, null, 2)}\n`);
  if (!artifact.overallPass) process.exitCode = 1;
} finally {
  rawKey.fill(0);
  datasetJson.fill(0);
  dataset.length = 0;
  await browser?.close().catch(() => undefined);
  await close(server).catch(() => undefined);
}

async function buildEncryptedDataset(rawKey: Buffer) {
  const key = await webcrypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const encoder = new TextEncoder();
  const rows: Array<Record<string, unknown>> = [];
  for (let offset = 0; offset < MEMBER_COUNT; offset += 250) {
    const batch = await Promise.all(Array.from({ length: Math.min(250, MEMBER_COUNT - offset) }, async (_, batchIndex) => {
      const index = offset + batchIndex;
      const suffix = String(index).padStart(5, "0");
      const id = `PERF-${suffix}`;
      const stableCode = `PX-${suffix}`;
      const nonce = randomBytes(12);
      const aad = encoder.encode(JSON.stringify({ tenantId: "performance-browser-ephemeral", memberId: id, purpose: "member-display", schemaVersion: 1 }));
      const plain = encoder.encode(JSON.stringify({ fullName: `Persona Álvarez ${index}`, givenNames: `Persona ${index}`, familyNames: "Álvarez" }));
      const ciphertext = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plain);
      return {
        id,
        stableCode,
        envelope: {
          algorithm: "AES-256-GCM",
          keyId: "perf-tenant-key-v1",
          nonce: Buffer.from(nonce).toString("base64url"),
          ciphertext: Buffer.from(ciphertext).toString("base64url"),
          aad: Buffer.from(aad).toString("base64url"),
        },
      };
    }));
    rows.push(...batch);
  }
  return rows;
}

function browserDataset(
  measured: { readonly payloadBytes?: number; readonly datasetGenerationMs?: number } = {},
): Readonly<Record<string, unknown>> {
  return {
    classification: "standalone synthetic dataset generated only in process memory for this run",
    members: MEMBER_COUNT,
    encryptedEnvelopeAlgorithm: "AES-256-GCM",
    aadBoundFields: ["tenantId", "memberId", "purpose", "schemaVersion"],
    payloadBytes: measured.payloadBytes ?? null,
    datasetGenerationMs: measured.datasetGenerationMs ?? null,
    productionMembersRouteMeasured: false,
    protectedTenantDataUsed: false,
    persistedAfterRun: false,
  };
}

function browserThresholds(): Readonly<Record<string, number>> {
  return {
    localSearchP95MsInclusive: SEARCH_BUDGET_MS,
    localSearchMaxMsInclusive: SEARCH_BUDGET_MS,
    mainThreadAnimationFrameGapMsInclusive: UI_GAP_BUDGET_MS,
    lcpMsInclusive: LCP_BUDGET_MS,
    inpMsInclusive: INP_BUDGET_MS,
    clsInclusive: CLS_BUDGET,
  };
}

function writeArtifact(report: BrowserEvidenceReport): void {
  if (report.inProgress !== (report.status === "in-progress") || report.overallPass !== (report.status === "passed")) {
    throw new Error("Refusing to publish an internally inconsistent AC-37 browser report state");
  }
  if (
    report.status === "passed"
    && (
      !report.overallPass
      || report.inProgress
      || !report.closureEligible
      || report.cleanup.pass !== true
    )
  ) {
    throw new Error("Refusing to publish an inconsistent green AC-37 browser report");
  }
  writeBrowserJsonEvidenceAtomic(artifactPath, report);
}

function listen(server: ReturnType<typeof createServer>): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("ephemeral browser benchmark port was unavailable"));
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!server.listening) return resolve();
    server.close((error) => error ? reject(error) : resolve());
  });
}

function round(value: number, digits = 3): number {
  return Number(value.toFixed(digits));
}

function roundNumbers<T>(value: T): T {
  if (typeof value === "number") return round(value) as T;
  if (Array.isArray(value)) return value.map(roundNumbers) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, roundNumbers(item)])) as T;
  }
  return value;
}
