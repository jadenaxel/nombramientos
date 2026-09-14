import { mkdirSync } from "node:fs";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const localQaOrigins = resolveLocalQaOrigins();
import { signInDemo } from "./support/demo-auth.ts";

const evidenceDirectory = path.resolve(import.meta.dirname, "../../../docs/evidence");

type HorizontalOverflowOffender = Readonly<{
  selector: string;
  parent: string;
  left: number;
  right: number;
  width: number;
  clientWidth: number;
  scrollWidth: number;
  minWidth: string;
  gridTemplateColumns: string;
  position: string;
}>;

async function horizontalOverflowOffenders(page: import("@playwright/test").Page): Promise<HorizontalOverflowOffender[]> {
  return page.locator("body *").evaluateAll((elements) => {
    const viewportWidth = document.documentElement.clientWidth;
    const selector = (element: Element | null): string => {
      if (!(element instanceof HTMLElement)) return "none";
      const classes = [...element.classList].slice(0, 4);
      return `${element.tagName.toLowerCase()}${classes.length > 0 ? `.${classes.join(".")}` : ""}`;
    };
    return elements.flatMap((element) => {
      if (!(element instanceof HTMLElement)) return [];
      const rect = element.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0 || rect.right <= viewportWidth + 1) return [];
      const style = getComputedStyle(element);
      return [{
        selector: selector(element),
        parent: selector(element.parentElement),
        left: Number(rect.left.toFixed(2)),
        right: Number(rect.right.toFixed(2)),
        width: Number(rect.width.toFixed(2)),
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
        minWidth: style.minWidth,
        gridTemplateColumns: style.gridTemplateColumns,
        position: style.position,
      }];
    });
  });
}

test("persistent accessibility controls reflow at 320px and the PWA caches public assets only", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One real Chromium ceremony avoids concurrent preference writes");
  const context = await browser.newContext({
    baseURL: localQaOrigins.webOrigin,
    locale: "es-DO",
    serviceWorkers: "allow",
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();
  try {
    await signInDemo(page);
    await page.goto("/es/app/settings");
    await expect(page.getByRole("heading", { name: "Preferencias de lectura" })).toBeVisible();

    await page.getByRole("radio", { name: "Muy grande" }).check();
    await page.getByRole("radio", { name: "Reforzado" }).check();
    await page.getByRole("radio", { name: "Reducido" }).check();
    await page.getByRole("radio", { name: "Compacta" }).check();
    await expect(page.locator("html")).toHaveAttribute("data-text-size", "extra-large");
    await expect(page.locator("html")).toHaveAttribute("data-contrast", "high");
    await expect(page.locator("html")).toHaveAttribute("data-motion", "reduced");
    await expect(page.locator("html")).toHaveAttribute("data-density", "compact");

    await page.reload();
    await expect(page.getByRole("radio", { name: "Muy grande" })).toBeChecked();
    await page.setViewportSize({ width: 320, height: 720 });
    expect(await horizontalOverflowOffenders(page)).toEqual([]);
    const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(axe.violations).toEqual([]);
    mkdirSync(evidenceDirectory, { recursive: true });
    await page.screenshot({ path: path.join(evidenceDirectory, "settings-accessibility-320.png"), fullPage: true });

    const cacheUrls = await page.evaluate(async () => {
      if (!("serviceWorker" in navigator)) return [];
      await navigator.serviceWorker.ready;
      const urls: string[] = [];
      for (const cacheName of await caches.keys()) {
        const cache = await caches.open(cacheName);
        urls.push(...(await cache.keys()).map((request) => new URL(request.url).pathname));
      }
      return urls;
    });
    expect(cacheUrls.every((url) => url === "/favicon.svg" || url.startsWith("/fonts/") || url.startsWith("/_next/static/"))).toBe(true);
    expect(cacheUrls.some((url) => url.startsWith("/v1/") || url.includes("/app/"))).toBe(false);

    await page.getByRole("button", { name: "Restablecer" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-text-size", "standard");
  } finally {
    await context.close();
  }
});
