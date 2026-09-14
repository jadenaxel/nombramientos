import { expect, test, type Page } from "@playwright/test";

import { signInDemo, unlockDemoVault } from "./support/demo-auth.ts";

test("large roster inspection and preview stay off the browser main thread", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One mandatory browser proves the dedicated-worker boundary");
  test.setTimeout(120_000);

  await signInDemo(page);
  await page.goto("/es/app/members");
  await unlockDemoVault(page, "es", "administrator");
  await expect(page.getByRole("heading", { name: /\d+ de \d+ personas/ })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Preparar importación" }).click();

  const headers = ["Nombre completo", ...Array.from({ length: 39 }, (_, index) => `Campo ${index + 1}`)];
  const rows = Array.from({ length: 10_000 }, (_, index) => [
    `Persona sintética ${String(index + 1).padStart(5, "0")}`,
    ...Array.from({ length: 39 }, () => "x"),
  ]);
  const csv = [headers, ...rows].map((row) => row.join(",")).join("\r\n");
  expect(Buffer.byteLength(csv, "utf8")).toBeLessThan(5 * 1024 * 1024);

  await startFrameProbe(page);
  await page.locator("#member-import").setInputFiles({
    name: "large-responsive-import.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(csv, "utf8"),
  });
  await expect(page.getByLabel("Hoja")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByLabel("Hoja").locator("option")).toContainText("10.000 filas");
  const inspection = await stopFrameProbe(page);
  expect(inspection.frames).toBeGreaterThan(1);
  expect(inspection.maxGapMs).toBeLessThan(500);

  await startFrameProbe(page);
  await page.getByRole("button", { name: "Validar y previsualizar" }).click();
  await expect(page.getByLabel("Previsualización de filas importadas")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("Persona sintética 00001", { exact: true })).toBeVisible();
  const preview = await stopFrameProbe(page);
  expect(preview.frames).toBeGreaterThan(1);
  expect(preview.maxGapMs).toBeLessThan(750);
});

async function startFrameProbe(page: Page): Promise<void> {
  await page.evaluate(() => {
    const target = globalThis as typeof globalThis & {
      __nomImportProbe?: { frames: number; last: number; maxGapMs: number; animationFrame: number };
    };
    const probe = { frames: 0, last: performance.now(), maxGapMs: 0, animationFrame: 0 };
    const tick = (now: number) => {
      probe.frames += 1;
      probe.maxGapMs = Math.max(probe.maxGapMs, now - probe.last);
      probe.last = now;
      probe.animationFrame = requestAnimationFrame(tick);
    };
    probe.animationFrame = requestAnimationFrame(tick);
    target.__nomImportProbe = probe;
  });
}

async function stopFrameProbe(page: Page): Promise<{ frames: number; maxGapMs: number }> {
  await page.waitForTimeout(50);
  return page.evaluate(() => {
    const target = globalThis as typeof globalThis & {
      __nomImportProbe?: { frames: number; last: number; maxGapMs: number; animationFrame: number };
    };
    const probe = target.__nomImportProbe;
    if (!probe) throw new Error("The import responsiveness probe was not started");
    cancelAnimationFrame(probe.animationFrame);
    delete target.__nomImportProbe;
    return { frames: probe.frames, maxGapMs: probe.maxGapMs };
  });
}
