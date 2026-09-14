import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { navigateToAppSection, signInDemo } from "./support/demo-auth";

test("authorized organigram separates stages, supports stable filters, zoom, and report deep-link", async ({ page }) => {
  await signInDemo(page);
  await navigateToAppSection(page, "Organigrama");
  await expect(page.getByRole("heading", { name: "Organigrama" })).toBeVisible({ timeout: 30_000 });

  const cycle = page.getByLabel("Mandato / ciclo");
  await expect(cycle.locator("option")).not.toHaveCount(0);
  await expect(page.getByRole("button", { name: "Directiva elegida" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".org-role .linked-marker").or(page.locator(".org-role")).first()).toBeVisible();
  await expect(page.locator(".org-role [data-slot=badge]").filter({ hasText: "Propuesta de la junta" })).toHaveCount(0);

  const graph = page.locator(".org-tree");
  await expect(graph).toBeVisible();
  await page.getByRole("button", { name: "Acercar" }).click();
  await expect(page.getByRole("group", { name: "Zoom del organigrama" }).locator("output")).toHaveText("125%");

  await page.getByRole("button", { name: "Propuesta de la junta" }).click();
  await expect(page.getByRole("button", { name: "Propuesta de la junta" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText("Esta vista preliminar no afirma una elección congregacional.")).toBeVisible();
  await expect(page.locator(".org-role [data-slot=badge]").filter({ hasText: "Elegida por la iglesia" })).toHaveCount(0);

  const department = page.getByLabel("Departamento", { exact: true });
  const departmentValues = await department.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value));
  expect(departmentValues[0]).toBe("all");
  if (departmentValues[1]) {
    await department.selectOption(departmentValues[1]);
    const exportLink = page.getByRole("link", { name: "Preparar exportación autorizada" });
    await expect(exportLink).toHaveAttribute("href", new RegExp(`reportType=department_organization.*cycleId=.*department=${encodeURIComponent(departmentValues[1])}`));
  }

  const search = page.getByLabel("Buscar persona, cargo o área");
  await search.fill("persona que no existe 000000");
  await expect(page.getByText("Ninguna responsabilidad coincide con los filtros")).toBeVisible();
  await search.clear();
  await department.selectOption("all");

  await page.getByRole("button", { name: "Lista accesible" }).click();
  const hierarchy = page.getByRole("region", { name: "Lista jerárquica equivalente" });
  await expect(hierarchy).toBeVisible();
  await expect(hierarchy.locator("details").first()).toHaveAttribute("open", "");

  const axe = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(axe.violations).toEqual([]);
});

test("organigram mobile path prioritizes the collapsible hierarchy without horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await signInDemo(page);
  await navigateToAppSection(page, "Organigrama");
  await expect(page.getByRole("heading", { name: "Organigrama" })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Lista accesible" }).click();
  await expect(page.getByRole("region", { name: "Lista jerárquica equivalente" }).locator("details").first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  const targets = await page.locator(".org-command button, .org-command select, .org-command input").evaluateAll((elements) => elements.map((element) => element.getBoundingClientRect().height));
  expect(targets.every((height) => height >= 40)).toBe(true);
});
