import path from "node:path";
import { defineConfig } from "@playwright/test";

import { resolveLocalQaOrigins } from "./scripts/local-qa-boundary.ts";

const chromiumBrowser = { browserName: "chromium" as const };
const includeFirefox = process.env["NOMBRAMIENTOS_E2E_FIREFOX"] !== "false";
const verificationEvidenceFile = process.env["NOMBRAMIENTOS_E2E_EVIDENCE_FILE"];
const localQaOrigins = resolveLocalQaOrigins();
const verificationReporter = verificationEvidenceFile
  ? [[
      "./scripts/verify-evidence-reporter.mjs",
      {
        outputFile: verificationEvidenceFile,
        repositoryRoot: path.resolve(import.meta.dirname, "../.."),
      },
    ] as const]
  : [];

export default defineConfig({
  testDir: "./e2e",
  testIgnore: ["real-stack-closure.spec.ts", "real-stack-passkey.spec.ts"],
  globalSetup: "./e2e/global-setup.ts",
  outputDir: "../../test-results/playwright",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: "../../playwright-report", open: "never" }],
    ...verificationReporter,
  ],
  projects: [
    { name: "desktop-chromium-es", use: { ...chromiumBrowser, viewport: { width: 1440, height: 900 }, locale: "es-DO" } },
    ...(includeFirefox
      ? [{ name: "desktop-firefox-en", use: { browserName: "firefox" as const, viewport: { width: 1280, height: 800 }, locale: "en-US" } }]
      : []),
    { name: "mobile-chromium-es", use: { ...chromiumBrowser, viewport: { width: 412, height: 915 }, locale: "es-DO", isMobile: true, hasTouch: true } },
    { name: "mobile-webkit-fr", use: { browserName: "webkit", viewport: { width: 390, height: 844 }, locale: "fr-FR", isMobile: true, hasTouch: true } },
    { name: "mobile-small", use: { ...chromiumBrowser, viewport: { width: 320, height: 568 }, locale: "es-DO", isMobile: true, hasTouch: true } },
  ],
  use: {
    baseURL: localQaOrigins.webOrigin,
    headless: true,
    // Page-level network mocks must never be bypassed by an already-active PWA
    // worker. The dedicated PWA ceremony opts back in with its own context.
    serviceWorkers: "block",
    // Authentication tests handle generated local credentials. Automatic traces and
    // failure screenshots are disabled so a failed form can never preserve them.
    screenshot: "off",
    trace: "off",
    video: "off",
  },
});
