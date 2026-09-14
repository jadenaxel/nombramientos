import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  localDepartmentCreateSchema,
  localDepartmentUpdateSchema,
  localOfficeCreateSchema,
  memberArchiveSchema,
  tenantSettingsUpdateSchema,
} from "../src/modules/tenant-routes.js";
import { platformTenantProvisionSchema } from "../src/modules/platform-routes.js";

describe("tenant settings and local catalog contracts", () => {
  it("keeps normative/system settings outside tenant-admin mutation", () => {
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, locale: "fr" }).success).toBe(true);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1 }).success).toBe(false);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, catalogVersion: "forged" }).success).toBe(false);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, setupState: "ready" }).success).toBe(false);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, timezone: "America/La_Paz" }).success).toBe(true);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, timezone: "America/Invented_City" }).success).toBe(false);
    expect(tenantSettingsUpdateSchema.safeParse({ expectedVersion: 1, timezone: "not-a-timezone" }).success).toBe(false);
  });

  it("rejects unknown timezones before a tenant can be queued for provisioning", () => {
    const request = {
      tenantId: "10000000-0000-4000-8000-000000000001",
      slug: "tenant-timezone-test",
      displayName: "Timezone test tenant",
      kind: "real",
      timezone: "America/Santo_Domingo",
      locale: "es",
      initialAdmin: { mode: "pending" },
    } as const;
    expect(platformTenantProvisionSchema.safeParse(request).success).toBe(true);
    expect(platformTenantProvisionSchema.safeParse({ ...request, timezone: "America/Not_Real" }).success).toBe(false);
  });

  it("requires an explicit local namespace and complete trilingual names", () => {
    const valid = {
      canonicalCode: "local.community-care",
      names: { es: "Atención comunitaria", en: "Community care", fr: "Service communautaire" },
    };
    expect(localDepartmentCreateSchema.safeParse(valid).success).toBe(true);
    expect(localDepartmentCreateSchema.safeParse({ ...valid, canonicalCode: "church_leadership" }).success).toBe(false);
    expect(localDepartmentCreateSchema.safeParse({ ...valid, names: { es: "Solo español" } }).success).toBe(false);
    expect(localDepartmentUpdateSchema.safeParse({ expectedVersion: 1 }).success).toBe(false);
  });

  it("accepts only known appointment mechanisms and a positive cardinality", () => {
    const valid = {
      departmentId: "10000000-0000-4000-8000-000000000001",
      canonicalCode: "local.community-lead",
      names: { es: "Coordinación", en: "Coordinator", fr: "Coordination" },
      appointmentMechanism: "church_election_after_nominating_report",
      cardinality: 1,
    };
    expect(localOfficeCreateSchema.safeParse(valid).success).toBe(true);
    expect(localOfficeCreateSchema.safeParse({
      ...valid,
      appointmentMechanism: "council_recommendation_board_approval",
    }).success).toBe(true);
    expect(localOfficeCreateSchema.safeParse({ ...valid, appointmentMechanism: "invented" }).success).toBe(false);
    expect(localOfficeCreateSchema.safeParse({ ...valid, cardinality: 0 }).success).toBe(false);
  });

  it("documents every route with the matching permission and request schema", () => {
    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const document = JSON.parse(readFileSync(path.resolve(testDirectory, "../../../docs/api/openapi.json"), "utf8")) as {
      paths: Record<string, Record<string, Record<string, unknown>>>;
    };
    expect(document.paths["/v1/tenant/settings"]?.["patch"]).toMatchObject({
      "x-required-permissions": ["tenant.settings.manage"],
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/TenantSettingsUpdateRequest" } } } },
    });
    expect(document.paths["/v1/catalog/manage"]?.["get"]).toMatchObject({
      "x-required-permissions": ["catalog.manage"],
    });
    for (const [route, method] of [
      ["/v1/catalog/departments", "post"],
      ["/v1/catalog/departments/{departmentId}", "patch"],
      ["/v1/catalog/offices", "post"],
      ["/v1/catalog/offices/{officeId}", "patch"],
    ] as const) {
      expect(document.paths[route]?.[method]).toMatchObject({ "x-required-permissions": ["catalog.manage"] });
    }
  });

  it("keeps member archival recoverable, versioned, and separate from eligibility authority", () => {
    expect(memberArchiveSchema.safeParse({ expectedVersion: 3, reasonCode: "RECORD_LIFECYCLE_CHANGE" }).success).toBe(true);
    expect(memberArchiveSchema.safeParse({ expectedVersion: 3, reasonCode: "free text is forbidden" }).success).toBe(false);
    expect(memberArchiveSchema.safeParse({ expectedVersion: 3, reasonCode: "ADMINISTRATIVE_CORRECTION", available: true }).success).toBe(false);

    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const document = JSON.parse(readFileSync(path.resolve(testDirectory, "../../../docs/api/openapi.json"), "utf8")) as {
      paths: Record<string, Record<string, Record<string, unknown>>>;
    };
    expect(document.paths["/v1/members/manage"]?.["get"]).toMatchObject({
      operationId: "listManagedMembers",
      "x-required-permissions": ["member.read", "member.manage"],
    });
    for (const [route, requestSchema] of [
      ["/v1/members/{memberId}/archive", "MemberArchiveRequest"],
      ["/v1/members/{memberId}/reactivate", "MemberReactivateRequest"],
    ] as const) {
      expect(document.paths[route]?.["post"]).toMatchObject({
        "x-required-permissions": ["member.manage"],
        requestBody: { content: { "application/json": { schema: { $ref: `#/components/schemas/${requestSchema}` } } } },
      });
    }
  });
});
