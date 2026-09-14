import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["enterprise-auth-ui.spec.ts", "invitation-access.spec.ts", "mfa-enrollment-ui.spec.ts", "initial-admin-recovery-ui.spec.ts"],
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  projects: [
    { name: "desktop-es", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, locale: "es-DO" } },
    { name: "desktop-en", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 }, locale: "en-US" } },
    { name: "mobile-320-fr", use: { ...devices["Desktop Chrome"], viewport: { width: 320, height: 568 }, locale: "fr-FR", isMobile: true, hasTouch: true } },
  ],
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    serviceWorkers: "block",
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  webServer: {
    command: "pnpm dev",
    url: "http://127.0.0.1:3000/healthz",
    timeout: 120_000,
    reuseExistingServer: false,
    env: { NEXT_PUBLIC_API_URL: "http://localhost:4000" },
  },
});
