import {
  chromium,
  firefox,
  webkit,
  type FullConfig,
} from "@playwright/test";
import { filterSessionCookies, loginThroughUi, sessionBindingKey } from "./support/demo-auth.ts";
import { assertConfiguredLocalQaWebOrigin } from "../scripts/local-qa-boundary.ts";

const SESSION_ENVIRONMENT = "NOMBRAMIENTOS_E2E_SESSION_COOKIES_B64";

/**
 * Authenticates once per distinct origin + browser user agent and passes the opaque
 * session cookies to workers through inherited process memory. No credential,
 * TOTP secret, cookie or storage-state file is written to reports or disk.
 */
export default async function globalSetup(config: FullConfig): Promise<void> {
  const sessions = new Map<string, Awaited<ReturnType<import("@playwright/test").BrowserContext["cookies"]>>>();
  const browserTypes = { chromium, firefox, webkit } as const;
  for (const browserName of ["chromium", "firefox", "webkit"] as const) {
    const projects = config.projects.filter((project) => String(project.use.browserName ?? "chromium") === browserName);
    if (projects.length === 0) continue;
    const browser = await browserTypes[browserName].launch({ headless: true });
    try {
      for (const project of projects) {
        const baseURL = assertConfiguredLocalQaWebOrigin(
          String(project.use.baseURL ?? config.projects[0]?.use.baseURL ?? ""),
        );
        const context = await browser.newContext({
          baseURL,
          viewport: project.use.viewport === null ? null : project.use.viewport,
          locale: project.use.locale,
          userAgent: project.use.userAgent,
          isMobile: project.use.isMobile,
          hasTouch: project.use.hasTouch,
          serviceWorkers: "block",
        });
        try {
          const page = await context.newPage();
          const userAgent = await page.evaluate(() => navigator.userAgent);
          const binding = sessionBindingKey(userAgent, baseURL);
          if (!sessions.has(binding)) {
            await loginThroughUi(page);
            sessions.set(binding, [...filterSessionCookies(await context.cookies())]);
          }
        } finally {
          await context.close();
        }
      }
    } finally {
      await browser.close();
    }
  }

  process.env[SESSION_ENVIRONMENT] = Buffer.from(JSON.stringify([...sessions]), "utf8").toString("base64url");
  process.stdout.write(`Prepared ${sessions.size} in-memory browser session(s) for E2E.\n`);
}
