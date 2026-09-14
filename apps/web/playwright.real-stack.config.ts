import { defineConfig } from "@playwright/test";

import { assertExactRealStackOrigin } from "./scripts/local-qa-boundary.ts";

const baseURL = requiredLoopbackUrl("NOMBRAMIENTOS_REAL_STACK_HARNESS_URL");
const userAgent = process.env["NOMBRAMIENTOS_REAL_STACK_USER_AGENT"];
if (userAgent !== "nombramientos-real-browser-stack-e2e/1") {
  throw new Error("Real browser-stack Playwright user agent marker is invalid");
}

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["real-stack-closure.spec.ts", "real-stack-passkey.spec.ts"],
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  projects: [{
    name: "real-stack-chromium",
    use: {
      browserName: "chromium",
      viewport: { width: 1_280, height: 800 },
      locale: "es-DO",
      userAgent,
    },
  }],
  use: {
    baseURL,
    headless: true,
    serviceWorkers: "block",
    screenshot: "off",
    trace: "off",
    video: "off",
  },
});

function requiredLoopbackUrl(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return assertExactRealStackOrigin(value, name);
}
