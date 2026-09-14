import { DEFAULT_ROLE_PERMISSIONS, type DefaultRole } from "@nombramientos/domain";
import { expect, test } from "@playwright/test";

import { signInDemo, type DemoProfile } from "./support/demo-auth.ts";
import { resolveLocalQaOrigins } from "../scripts/local-qa-boundary.ts";

const localQaOrigins = resolveLocalQaOrigins();
const apiOrigin = localQaOrigins.apiOrigin;

const profiles = [
  {
    profile: "secretary",
    role: "COMMITTEE_SECRETARY",
    email: "secretaria.demo@nombramientos.local",
    visible: ["Conducción del ciclo", "Miembros", "Reportes"],
    hidden: ["Invitaciones y acceso", "Custodia E2EE", "Operación global"],
    membersStatus: 200,
    auditStatus: 403,
  },
  {
    profile: "committee",
    role: "COMMITTEE_MEMBER",
    email: "comision.demo@nombramientos.local",
    visible: ["Sesión en curso", "Miembros", "Organigrama"],
    hidden: ["Conducción del ciclo", "Invitaciones y acceso", "Custodia E2EE"],
    membersStatus: 200,
    auditStatus: 403,
  },
  {
    profile: "custodian",
    role: "TALLY_CUSTODIAN",
    email: "custodio.demo@nombramientos.local",
    visible: ["Custodia E2EE", "Historial"],
    hidden: ["Conducción del ciclo", "Miembros", "Invitaciones y acceso"],
    membersStatus: 403,
    auditStatus: 200,
  },
  {
    profile: "auditor",
    role: "AUDITOR",
    email: "auditor.demo@nombramientos.local",
    visible: ["Organigrama", "Reportes", "Historial"],
    hidden: ["Conducción del ciclo", "Miembros", "Custodia E2EE"],
    membersStatus: 403,
    auditStatus: 200,
  },
] as const satisfies ReadonlyArray<{
  profile: Exclude<DemoProfile, "administrator">;
  role: DefaultRole;
  email: string;
  visible: readonly string[];
  hidden: readonly string[];
  membersStatus: number;
  auditStatus: number;
}>;

for (const expected of profiles) {
  test(`${expected.profile} Demo identity enforces role-specific UI and API boundaries`, async ({ browser }, testInfo) => {
    test.skip(testInfo.project.name !== "desktop-chromium-es", "One real Chromium role matrix avoids redundant MFA traffic");
    const context = await browser.newContext({
      baseURL: localQaOrigins.webOrigin,
      locale: "es-DO",
      serviceWorkers: "block",
      viewport: { width: 1440, height: 900 },
    });
    try {
      const page = await context.newPage();
      await signInDemo(page, expected.profile);

      const session = await page.evaluate(async (origin) => {
        const response = await fetch(`${origin}/v1/session`, { credentials: "include", cache: "no-store" });
        if (!response.ok) throw new Error(`Session request failed with ${response.status}`);
        return response.json() as Promise<{ data: { user: { email: string }; permissions: string[] } }>;
      }, apiOrigin);
      expect(session.data.user.email).toBe(expected.email);
      expect([...session.data.permissions].sort()).toEqual([...DEFAULT_ROLE_PERMISSIONS[expected.role]].sort());

      for (const label of expected.visible) {
        await expect(page.getByRole("link", { name: label, exact: true }).first()).toBeVisible();
      }
      for (const label of expected.hidden) {
        await expect(page.getByRole("link", { name: label, exact: true })).toHaveCount(0);
      }

      const statuses = await page.evaluate(async (origin) => {
        const [members, audit, roles] = await Promise.all([
          fetch(`${origin}/v1/members`, { credentials: "include", cache: "no-store" }),
          fetch(`${origin}/v1/audit`, { credentials: "include", cache: "no-store" }),
          fetch(`${origin}/v1/access/roles`, { credentials: "include", cache: "no-store" }),
        ]);
        return { members: members.status, audit: audit.status, roles: roles.status };
      }, apiOrigin);
      expect(statuses).toEqual({
        members: expected.membersStatus,
        audit: expected.auditStatus,
        roles: 403,
      });
    } finally {
      await context.close();
    }
  });
}
