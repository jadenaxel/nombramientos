import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
  new URL("../migrations/tenant/035_system_role_assignment_matrix.sql", import.meta.url),
  "utf8",
);
const activationMigration = readFileSync(
  new URL("../migrations/tenant/034_invitation_role_delegation.sql", import.meta.url),
  "utf8",
);
const tenantStore = readFileSync(new URL("../src/tenant-store.ts", import.meta.url), "utf8");
const runtime = readFileSync(new URL("../src/runtime.ts", import.meta.url), "utf8");

describe("invitation role delegation boundary", () => {
  it("uses an explicit system-role assignment matrix instead of operational permissions", () => {
    const assignmentRows = [...migration.matchAll(/\('([A-Z_]+)', '([A-Z_]+)'\)/gu)]
      .map((match) => [match[1], match[2]]);

    expect(migration).toContain("CREATE TABLE system_role_assignment_matrix");
    expect(migration).toContain("PRIMARY KEY (grantor_role_code, assignable_role_code)");
    expect(assignmentRows).toEqual([
      ["CHURCH_ADMIN", "AUDITOR"],
      ["CHURCH_ADMIN", "CHURCH_ADMIN"],
      ["CHURCH_ADMIN", "COMMITTEE_CHAIR"],
      ["CHURCH_ADMIN", "COMMITTEE_MEMBER"],
      ["CHURCH_ADMIN", "COMMITTEE_SECRETARY"],
      ["CHURCH_ADMIN", "TALLY_CUSTODIAN"],
    ]);
    expect(migration).toContain("JOIN public.system_role_assignment_matrix assignment");
    expect(migration).toContain("assignment.grantor_role_code = grantor_role.code");
    expect(migration).not.toContain("role_permission.delegable");
    expect(migration).not.toMatch(/(?:INSERT|UPDATE|DELETE)\s+(?:INTO\s+|FROM\s+)?public\.role_permissions/iu);
  });

  it("preserves tenant, actor, role-management, exact-set, and fail-closed checks", () => {
    expect(migration).toContain("assert_tenant_invitation_role_delegation_allowed");
    expect(migration).toContain("current_setting('app.tenant_id', true)::uuid");
    expect(migration).toContain("current_setting('app.identity_id', true)::uuid");
    expect(migration).toContain("Invitation grantor does not match the bound session");
    expect(migration).toContain("role_permission.permission_code = 'role.manage'");
    expect(migration).toContain("Invitation roles are not an exact supported set");
    expect(migration).toContain("Invitation references an unavailable tenant role");
    expect(migration).toContain("Actor cannot assign one or more invitation roles");
    expect(migration).toContain("EXCEPT");
    expect(migration).toContain("REVOKE ALL ON TABLE public.system_role_assignment_matrix FROM PUBLIC");
    expect(migration).toContain("REVOKE ALL ON FUNCTION public.assert_tenant_invitation_role_delegation_allowed(uuid,text[]) FROM PUBLIC");
  });

  it("exposes a creation-time check and preserves acceptance-time revalidation", () => {
    expect(tenantStore).toContain("assertInvitationRoleDelegation");
    expect(tenantStore).toContain("assert_tenant_invitation_role_delegation_allowed($1,$2::text[])");
    expect(activationMigration).toContain("PERFORM public.assert_tenant_invitation_role_delegation_allowed(");
    expect(runtime).toContain("withInvitationGrantorTenant");
    expect(runtime).toContain("identityId: input.grantorIdentityId");
  });
});
