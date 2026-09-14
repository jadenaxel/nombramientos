import { expect, test, type Route } from "@playwright/test";
import type { Envelope, MemberRecord } from "../lib/api.ts";
import { signInDemo, unlockDemoVault } from "./support/demo-auth.ts";
import { localQaApiRoute } from "./support/local-api-route.ts";

type MemberListEnvelope = {
  data: { items: MemberRecord[]; total: number; nextCursor?: string | null };
  meta?: { requestId?: string };
};

type MemberUpdatePayload = {
  expectedVersion: number;
  displayEnvelope: Envelope;
  displayContentHash: string;
  eligibilityStatus: "eligible" | "ineligible" | "review";
  available: boolean;
};

type Names = { es: string; en: string; fr: string };
type CatalogDepartment = {
  id: string;
  canonicalCode: string;
  names: Names;
  parentId: string | null;
  localExtension: boolean;
  active: boolean;
  sortOrder: number;
  metadata: Record<string, unknown>;
  version: number;
  updatedAt?: string;
};
type CatalogEnvelope = {
  data: { departments: CatalogDepartment[]; offices: unknown[]; normativeVersion: string };
  meta?: { requestId?: string };
};

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const memberMutationPathPattern = /^\/v1\/members\/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:\/(archive|reactivate))?$/u;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const base64UrlPattern = /^[A-Za-z0-9_-]+$/u;

function expectMutationHeaders(route: Route): void {
  const headers = route.request().headers();
  expect(headers["idempotency-key"]).toMatch(uuidPattern);
  expect(headers["x-csrf-token"]).toBeTruthy();
}

function fulfillJson(route: Route, data: unknown, requestId: string, status = 200): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    headers: { "cache-control": "no-store", "x-request-id": requestId },
    body: JSON.stringify({ data, meta: { requestId } }),
  });
}

async function validateMemberUpdate(payload: MemberUpdatePayload, memberId: string, expectedVersion: number): Promise<void> {
  expect(Object.keys(payload).sort()).toEqual([
    "available",
    "displayContentHash",
    "displayEnvelope",
    "eligibilityStatus",
    "expectedVersion",
  ]);
  expect(payload.expectedVersion).toBe(expectedVersion);
  expect(["eligible", "ineligible", "review"]).toContain(payload.eligibilityStatus);
  expect(typeof payload.available).toBe("boolean");
  expect(payload.displayEnvelope.algorithm).toBe("AES-256-GCM");
  expect(Object.keys(payload.displayEnvelope).sort()).toEqual(["aad", "algorithm", "ciphertext", "keyId", "nonce"]);
  expect(payload.displayEnvelope.nonce).toMatch(base64UrlPattern);
  expect(Buffer.from(payload.displayEnvelope.nonce, "base64url")).toHaveLength(12);
  expect(payload.displayEnvelope.ciphertext).toMatch(base64UrlPattern);
  expect(Buffer.from(payload.displayEnvelope.ciphertext, "base64url").byteLength).toBeGreaterThan(16);
  expect(payload.displayEnvelope.aad).toMatch(base64UrlPattern);
  expect(JSON.parse(Buffer.from(payload.displayEnvelope.aad, "base64url").toString("utf8"))).toEqual({
    tenantId: "d0000000-0000-4000-8000-000000000001",
    memberId,
    purpose: "member-display",
    schemaVersion: 1,
  });
  expect(payload.displayContentHash).toMatch(digestPattern);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(payload.displayEnvelope)));
  expect(payload.displayContentHash).toBe(`sha256:${Buffer.from(digest).toString("hex")}`);
  expect(JSON.stringify(payload)).not.toMatch(/Miembro E2E sintético|passphrase|privateKey/iu);
}

test("member administration edits encrypted data and projects archive/reactivation without Demo writes", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One synthetic browser management scenario covers the member lifecycle without changing Demo");

  const realMembers = new Map<string, MemberRecord>();
  let projectedMember: MemberRecord | undefined;
  let memberEdits = 0;
  let memberArchives = 0;
  let memberReactivations = 0;

  await page.route(localQaApiRoute("/v1/members/manage"), async (route) => {
    expect(route.request().method()).toBe("GET");
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    const envelope = structuredClone(await response.json() as MemberListEnvelope);
    expect(Array.isArray(envelope.data.items)).toBe(true);
    envelope.data.items.forEach((member) => realMembers.set(member.id, member));
    if (projectedMember) {
      const projected = projectedMember;
      envelope.data.items = envelope.data.items.map((member) => member.id === projected.id ? projected : member);
    }
    return route.fulfill({ response, json: envelope });
  });

  await page.route(localQaApiRoute(memberMutationPathPattern), async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const match = memberMutationPathPattern.exec(pathname);
    const memberId = match?.[1];
    const action = match?.[2] as "archive" | "reactivate" | undefined;
    if (!match || !memberId) throw new Error(`Unexpected member mutation path: ${pathname}`);
    expect(pathname).toBe(`/v1/members/${memberId}${action ? `/${action}` : ""}`);
    expect(memberId).toMatch(uuidPattern);
    expectMutationHeaders(route);
    const current = projectedMember?.id === memberId ? projectedMember : realMembers.get(memberId);
    if (!current) throw new Error("The intercepted member mutation must target a member returned by the real Demo read");
    const updatedAt = new Date().toISOString();

    if (request.method() === "PATCH" && action === undefined) {
      memberEdits += 1;
      expect(memberEdits).toBe(1);
      const payload = request.postDataJSON() as MemberUpdatePayload;
      await validateMemberUpdate(payload, memberId, current.version);
      const eligible = payload.eligibilityStatus === "eligible" && payload.available;
      projectedMember = {
        ...current,
        displayEnvelope: payload.displayEnvelope,
        eligibilityStatus: payload.eligibilityStatus,
        available: payload.available,
        eligible,
        version: current.version + 1,
      };
      return fulfillJson(route, {
        id: memberId,
        version: projectedMember.version,
        updatedAt,
        departmentRestriction: projectedMember.departmentRestriction,
        validUntil: projectedMember.validUntil,
        eligibilityEvaluatedOn: projectedMember.eligibilityEvaluatedOn,
        eligible,
        pausedWorkflows: [],
      }, "synthetic-member-edit");
    }

    expect(request.method()).toBe("POST");
    expect(action === "archive" || action === "reactivate").toBe(true);
    const payload = request.postDataJSON() as { expectedVersion: number; reasonCode: string };
    expect(Object.keys(payload).sort()).toEqual(["expectedVersion", "reasonCode"]);
    expect(payload.expectedVersion).toBe(current.version);
    const nextVersion = current.version + 1;
    if (action === "archive") {
      memberArchives += 1;
      expect(memberArchives).toBe(1);
      expect(payload.reasonCode).toBe("RECORD_LIFECYCLE_CHANGE");
      const archivedAt = updatedAt;
      projectedMember = { ...current, archived: true, archivedAt, available: false, eligible: false, version: nextVersion };
      return fulfillJson(route, { id: memberId, version: nextVersion, archived: true, archivedAt, available: false, updatedAt, pausedWorkflows: [] }, "synthetic-member-archive");
    }

    memberReactivations += 1;
    expect(memberReactivations).toBe(1);
    expect(payload.reasonCode).toBe("ARCHIVE_REVERSED");
    projectedMember = { ...current, archived: false, archivedAt: null, available: false, eligible: false, version: nextVersion };
    return fulfillJson(route, { id: memberId, version: nextVersion, archived: false, archivedAt: null, available: false, updatedAt }, "synthetic-member-reactivate");
  });

  await signInDemo(page);
  await page.goto("/es/app/members");
  await unlockDemoVault(page, "es", "administrator");
  await expect(page.getByRole("heading", { name: "Miembros" })).toBeVisible({ timeout: 30_000 });

  const updatedName = "Miembro E2E sintético · validación local";
  const memberRow = page.locator("article").filter({ hasText: "M179" });
  await expect(memberRow).toBeVisible();
  await memberRow.getByRole("button", { name: /^Editar persona:/ }).click();
  await page.getByLabel("Nombre completo").fill(updatedName);
  await page.getByRole("button", { name: "Cifrar y guardar cambios" }).click();
  await expect(memberRow.getByText(updatedName, { exact: true })).toBeVisible();

  await memberRow.getByRole("button", { name: `Archivar persona: ${updatedName}` }).click();
  await page.getByLabel("Código de motivo no sensible").selectOption("RECORD_LIFECYCLE_CHANGE");
  await page.getByRole("button", { name: "Confirmar archivo" }).click();
  await page.getByLabel("Filtrar padrón").selectOption("archived");
  await expect(memberRow.getByText(updatedName, { exact: true })).toBeVisible();

  await memberRow.getByRole("button", { name: `Reactivar persona: ${updatedName}` }).click();
  await page.getByLabel("Código de motivo no sensible").selectOption("ARCHIVE_REVERSED");
  await page.getByRole("button", { name: "Confirmar reactivación" }).click();
  await page.getByLabel("Filtrar padrón").selectOption("active");
  await expect(memberRow.getByText(updatedName, { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: /180 de 180 personas/ })).toBeVisible();
  expect(memberEdits).toBe(1);
  expect(memberArchives).toBe(1);
  expect(memberReactivations).toBe(1);
});

test("local catalog extension create, edit, disable and reactivate are projected without Demo writes", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium-es", "One synthetic browser management scenario covers catalog lifecycle without changing Demo");

  const code = "local.e2e_validation";
  const name = "Departamento E2E estable";
  const edited = "Departamento E2E estable · actualizado";
  const syntheticDepartmentId = "c8000000-0000-4000-8000-000000000001";
  const names = { es: name, en: "Stable E2E Department", fr: "Département E2E stable" };
  let projectedDepartment: CatalogDepartment | undefined;
  let catalogCreates = 0;
  let catalogEdits = 0;
  let catalogDeactivations = 0;
  let catalogReactivations = 0;

  await page.route(localQaApiRoute("/v1/catalog/manage"), async (route) => {
    expect(route.request().method()).toBe("GET");
    const response = await route.fetch();
    expect(response.ok()).toBe(true);
    const envelope = structuredClone(await response.json() as CatalogEnvelope);
    expect(Array.isArray(envelope.data.departments)).toBe(true);
    envelope.data.departments = envelope.data.departments.filter((department) => department.canonicalCode !== code);
    if (projectedDepartment) envelope.data.departments.push(projectedDepartment);
    return route.fulfill({ response, json: envelope });
  });

  await page.route(localQaApiRoute("/v1/catalog/departments"), async (route) => {
    expect(route.request().method()).toBe("POST");
    expectMutationHeaders(route);
    catalogCreates += 1;
    expect(catalogCreates).toBe(1);
    const payload = route.request().postDataJSON() as { canonicalCode: string; names: Names; sortOrder: number; metadata: Record<string, unknown> };
    expect(payload).toEqual({ canonicalCode: code, names, sortOrder: 0, metadata: {} });
    projectedDepartment = {
      id: syntheticDepartmentId,
      canonicalCode: code,
      names: payload.names,
      parentId: null,
      localExtension: true,
      active: true,
      sortOrder: payload.sortOrder,
      metadata: payload.metadata,
      version: 1,
      updatedAt: new Date().toISOString(),
    };
    return fulfillJson(route, projectedDepartment, "synthetic-catalog-create", 201);
  });

  await page.route(localQaApiRoute(/^\/v1\/catalog\/departments\/[^/]+$/u), async (route) => {
    expect(route.request().method()).toBe("PATCH");
    expectMutationHeaders(route);
    if (!projectedDepartment) throw new Error("The synthetic catalog department must be created before it can be updated");
    expect(new URL(route.request().url()).pathname).toBe(`/v1/catalog/departments/${projectedDepartment.id}`);
    const payload = route.request().postDataJSON() as Record<string, unknown>;
    expect(payload.expectedVersion).toBe(projectedDepartment.version);

    if (Object.prototype.hasOwnProperty.call(payload, "active")) {
      expect(Object.keys(payload).sort()).toEqual(["active", "expectedVersion"]);
      expect(typeof payload.active).toBe("boolean");
      if (payload.active === false) {
        catalogDeactivations += 1;
        expect(catalogDeactivations).toBe(1);
      } else {
        catalogReactivations += 1;
        expect(catalogReactivations).toBe(1);
      }
      projectedDepartment = { ...projectedDepartment, active: payload.active as boolean, version: projectedDepartment.version + 1, updatedAt: new Date().toISOString() };
    } else {
      catalogEdits += 1;
      expect(catalogEdits).toBe(1);
      expect(payload).toEqual({ expectedVersion: projectedDepartment.version, names: { ...names, es: edited }, parentId: null, sortOrder: 0 });
      projectedDepartment = { ...projectedDepartment, names: payload.names as Names, parentId: payload.parentId as null, sortOrder: payload.sortOrder as number, version: projectedDepartment.version + 1, updatedAt: new Date().toISOString() };
    }
    return fulfillJson(route, projectedDepartment, `synthetic-catalog-update-${projectedDepartment.version}`);
  });

  await signInDemo(page);
  await page.goto("/es/app/catalog");
  await expect(page.getByRole("heading", { name: "Departamentos, cargos y configuración" })).toBeVisible();

  await page.getByRole("button", { name: "Nueva extensión" }).click();
  await page.getByLabel("Código local").fill(code);
  await page.getByLabel("Nombre en español").fill(name);
  await page.getByLabel("Nombre en inglés").fill(names.en);
  await page.getByLabel("Nombre en francés").fill(names.fr);
  await page.getByRole("button", { name: "Crear extensión local" }).click();
  const row = page.locator("article").filter({ hasText: code });
  await expect(row.getByText(name, { exact: true })).toBeVisible();

  await row.getByRole("button", { name: /^Editar:/ }).click();
  await page.getByLabel("Nombre en español").fill(edited);
  await page.getByRole("button", { name: "Guardar cambios" }).click();
  await expect(row.getByText(edited, { exact: true })).toBeVisible();
  await row.getByRole("button", { name: /^Desactivar:/ }).click();
  await expect(row.getByRole("button", { name: /^Reactivar:/ })).toBeVisible();
  await row.getByRole("button", { name: /^Reactivar:/ }).click();
  await expect(row.getByRole("button", { name: /^Desactivar:/ })).toBeVisible();

  expect(catalogCreates).toBe(1);
  expect(catalogEdits).toBe(1);
  expect(catalogDeactivations).toBe(1);
  expect(catalogReactivations).toBe(1);
  expect(projectedDepartment?.active).toBe(true);
});
