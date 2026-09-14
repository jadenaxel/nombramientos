import { expect, test } from "@playwright/test";

import { signInDemo, submitDemoVaultUnlock } from "./support/demo-auth.ts";

test.describe("read-only analytics", () => {
  test("renders charts and their table alternatives without mutation requests", async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== "desktop-chromium-es", "One read-only browser is sufficient for the persisted aggregate contract");
    await signInDemo(page);
    const unexpectedMutations: string[] = [];
    page.on("request", (request) => {
      if (!["GET", "HEAD", "OPTIONS"].includes(request.method())) unexpectedMutations.push(`${request.method()} ${request.url()}`);
    });

    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto("/es/app/overview");
    await submitDemoVaultUnlock(page, "es", "administrator");
    await expect(page.getByRole("heading", { name: "Progreso por departamento" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Distribución de responsabilidades" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Evolución por sesiones" })).toBeVisible();
    await expect(page.getByText("Alternativa tabular del progreso por departamento", { exact: true })).toBeAttached();

    await page.goto("/es/app/results");
    await submitDemoVaultUnlock(page, "es", "administrator");
    await expect(page.getByRole("heading", { name: "Propuestas y votos" })).toBeVisible();
    await expect(page.getByText("Alternativa tabular de participación en propuestas y votos", { exact: true })).toBeAttached();
    expect(unexpectedMutations).toEqual([]);
  });
});
