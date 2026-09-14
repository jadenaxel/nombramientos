import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";
import { registerAccessRoutes } from "../src/modules/access-routes.js";
import { registerCustodyRoutes } from "../src/modules/custody-routes.js";
import { registerEnterpriseAuthRoutes } from "../src/modules/enterprise-auth-routes.js";
import { registerKeyLifecycleRoutes } from "../src/modules/key-lifecycle-routes.js";
import { registerPlatformRoutes } from "../src/modules/platform-routes.js";
import { registerTenantRoutes } from "../src/modules/tenant-routes.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("sensitive administration MFA boundary", () => {
  it.each([
    ["access-role change", registerAccessRoutes, "POST", "/v1/access/roles", "MFA_STEP_UP_REQUIRED"],
    ["platform provisioning", registerPlatformRoutes, "POST", "/v1/platform/tenants/provisioning", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant export request", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/exports", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant export download authorization", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/exports/40000000-0000-4000-8000-000000000001/download-authorizations", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant export download", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/exports/40000000-0000-4000-8000-000000000001/download", "MFA_STEP_UP_REQUIRED"],
    ["tenant export download authorization revocation", registerPlatformRoutes, "POST", "/v1/platform/export-download-authorizations/40000000-0000-4000-8000-000000000001/revoke", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant reactivation", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/reactivate", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant decommission schedule", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/decommission", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["tenant decommission cancellation", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/decommission/40000000-0000-4000-8000-000000000001/cancel", "WEBAUTHN_STEP_UP_REQUIRED"],
    ["custody-key registration", registerCustodyRoutes, "POST", "/v1/custody/keys", "MFA_STEP_UP_REQUIRED"],
    ["custody-manifest download", registerCustodyRoutes, "GET", "/v1/rounds/40000000-0000-4000-8000-000000000001/custody/manifest", "MFA_STEP_UP_REQUIRED"],
  ] as const)("rejects insufficient assurance before parsing or storage for %s", async (_label, register, method, url, expectedCode) => {
    const app = await fixtureApp(register);
    const response = await app.inject({
      method,
      url,
      headers: { "idempotency-key": randomUUID() },
      payload: {},
    });

    expect(response.statusCode).toBe(428);
    expect(response.json<{ error: { code: string } }>().error.code).toBe(expectedCode);
  });

  it.each([
    ["role administration", registerAccessRoutes, "POST", "/v1/access/roles", "role_administration"],
    ["roster export", registerTenantRoutes, "POST", "/v1/members/export-authorizations", "data_export"],
    ["tenant configuration", registerTenantRoutes, "PATCH", "/v1/tenant/settings", "tenant_administration"],
    ["report generation", registerTenantRoutes, "POST", "/v1/reports/generate", "data_export"],
    ["custody key registration", registerCustodyRoutes, "POST", "/v1/custody/keys", "custody_operation"],
    ["key lifecycle challenge", registerKeyLifecycleRoutes, "POST", "/v1/key-lifecycle/challenges", "key_lifecycle"],
  ] as const)("requires operation-bound WebAuthn under enforce for %s", async (_label, register, method, url, purpose) => {
    const app = await fixtureApp(register, "enforce");
    const response = await app.inject({ method, url, payload: {} });
    expect(response.statusCode).toBe(428);
    expect(response.json<{ error: { code: string; details: unknown } }>().error).toMatchObject({
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: {
        purpose,
        operationHash: hashStepUpOperation(purpose, method, url, {}),
      },
    });
  });

  it.each([
    ["platform provision", registerPlatformRoutes, "POST", "/v1/platform/tenants/provisioning", "platform.tenant.provision"],
    ["platform suspend", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/suspend", "platform.tenant.suspend"],
    ["export download authorization", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/exports/40000000-0000-4000-8000-000000000001/download-authorizations", "platform.tenant.export.download"],
    ["decommission schedule", registerPlatformRoutes, "POST", "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/decommission", "platform.tenant.decommission.schedule"],
    ["passkey revoke", registerEnterpriseAuthRoutes, "DELETE", "/v1/auth/passkeys/40000000-0000-4000-8000-000000000001", "auth.passkey.revoke"],
    ["other-session revoke", registerEnterpriseAuthRoutes, "POST", "/v1/auth/sessions/revoke-others", "auth.session.revoke_others"],
  ] as const)("consults the named action policy for %s without weakening the WebAuthn floor", async (
    _label,
    register,
    method,
    url,
    action,
  ) => {
    const app = await fixtureApp(register, "enforce", {
      [action]: { minAal: 3, phishingResistant: true, stepUpRequired: true },
    });
    const response = await app.inject({
      method,
      url,
      headers: { "x-step-up-grant": "g".repeat(43) },
      payload: {},
    });
    expect(response.statusCode).toBe(403);
    expect(response.json<{ error: { code: string } }>().error.code).toBe("ACTION_ASSURANCE_REQUIRED");
  });
});

async function fixtureApp(
  register: (app: FastifyInstance) => Promise<void>,
  enforcementMode: "monitor" | "enforce" = "monitor",
  actionRequirements: Readonly<Record<string, {
    readonly minAal: 1 | 2 | 3;
    readonly phishingResistant?: boolean;
    readonly stepUpRequired?: boolean;
  }>> = {},
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const currentPrincipal = principal();
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = currentPrincipal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) throw new ApiError(403, "PERMISSION_DENIED", "Denied");
  });
  app.decorate("database", {
    enterpriseAuth: {
      getEffectiveIdentityPolicy: async () => ({
        enforcementMode,
        privilegedMinimumAal: 2,
        requirePhishingResistantForPrivileged: true,
        actionRequirements,
      }),
    },
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: {
          code: error.code,
          message: error.message,
          ...(error.details === undefined ? {} : { details: error.details }),
        },
        meta: { requestId: request.id },
      });
    }
    return reply.status(500).send({ error: { code: "INTERNAL_ERROR", message: "Unexpected" }, meta: { requestId: request.id } });
  });
  await register(app);
  return app;
}

function principal(): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "admin@example.invalid",
    displayName: "Admin",
    tenantSlug: "fixture",
    tenantName: "Fixture",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(Date.now() - 5 * 60_000),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set([
      "role.manage",
      "tally.custody",
      "tally.recount",
      "report.export",
      "tenant.settings.manage",
      "recovery.activate",
    ]),
  };
}
