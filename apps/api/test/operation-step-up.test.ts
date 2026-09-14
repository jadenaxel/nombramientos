import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import Fastify, { type FastifyRequest } from "fastify";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import {
  assertGovernedOperationStepUp,
  assertOperationStepUp,
  assertPolicyAwareOperationStepUp,
  requireFactorChangeStepUp,
  requireOperationStepUp,
} from "../src/lib/operation-step-up.js";
import { hashStepUpOperation } from "../src/modules/enterprise-auth-contract.js";

const path = "/v1/auth/sessions/20000000-0000-4000-8000-000000000002";
const body = { reason: "user_revoked" };

describe("operation-bound WebAuthn step-up", () => {
  it("atomically consumes a grant using the exact operation digest", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    await expect(assertOperationStepUp({
      database: database(consumeStepUpGrant),
      principal: principal(),
      grantToken: "g".repeat(43),
      purpose: "session_revocation",
      method: "DELETE",
      path,
      body,
    })).resolves.toBeUndefined();
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
      identityId: principal().identityId,
      sessionId: principal().sessionId,
      purpose: "session_revocation",
      operationHash: hashStepUpOperation("session_revocation", "DELETE", path, body),
    }));
  });

  it("rejects replayed, expired, wrong-purpose, or wrong-operation grants", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(false);
    const rejection = assertOperationStepUp({
      database: database(consumeStepUpGrant),
      principal: principal(),
      grantToken: "g".repeat(43),
      purpose: "identity_security_change",
      method: "PATCH",
      path: "/v1/auth/passkeys/20000000-0000-4000-8000-000000000002",
      body: { name: "Work laptop" },
    });
    await expect(rejection).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: {
        purpose: "identity_security_change",
        operationHash: hashStepUpOperation(
          "identity_security_change",
          "PATCH",
          "/v1/auth/passkeys/20000000-0000-4000-8000-000000000002",
          { name: "Work laptop" },
        ),
      },
    });
  });

  it("never elevates recovery-limited sessions", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    await expect(assertOperationStepUp({
      database: database(consumeStepUpGrant),
      principal: principal({ assuranceLevel: "recovery_limited", enrollmentOnly: true }),
      grantToken: "g".repeat(43),
      purpose: "session_revocation",
      method: "DELETE",
      path,
      body,
    })).rejects.toBeInstanceOf(ApiError);
    expect(consumeStepUpGrant).not.toHaveBeenCalled();
  });

  it("fails closed when a protected mutation contains any query string", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const app = Fastify({ logger: false });
    app.decorateRequest("principal", null);
    app.decorate("database", database(consumeStepUpGrant));
    app.addHook("preHandler", async (request: FastifyRequest) => { request.principal = principal(); });
    app.setErrorHandler((error, _request, reply) => reply.status((error as ApiError).statusCode ?? 500).send({
      code: (error as ApiError).code ?? "INTERNAL_ERROR",
    }));
    app.delete("/protected", { preHandler: requireOperationStepUp("session_revocation") }, async () => ({ ok: true }));

    const response = await app.inject({
      method: "DELETE",
      url: "/protected?scope=all",
      headers: { "x-step-up-grant": "g".repeat(43) },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json<{ code: string }>().code).toBe("STEP_UP_OPERATION_INVALID");
    expect(consumeStepUpGrant).not.toHaveBeenCalled();
    await app.close();
  });

  it("retains recent-MFA rollout in monitor and requires a bound passkey grant in enforce", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const input = {
      principal: principal(),
      grantToken: undefined,
      action: "platform.tenant.suspend",
      purpose: "platform_administration" as const,
      recentMfaPurpose: "suspending a tenant",
      method: "POST",
      path: "/v1/platform/tenants/30000000-0000-4000-8000-000000000001/suspend",
      body: { expectedVersion: 3, reasonCode: "security_review" },
    };
    const monitorDatabase = policyDatabase("monitor", consumeStepUpGrant);
    await expect(assertPolicyAwareOperationStepUp({ ...input, database: monitorDatabase })).resolves.toBeUndefined();
    expect(consumeStepUpGrant).not.toHaveBeenCalled();

    const enforceDatabase = policyDatabase("enforce", consumeStepUpGrant);
    const expectedHash = hashStepUpOperation(input.purpose, input.method, input.path, input.body);
    await expect(assertPolicyAwareOperationStepUp({ ...input, database: enforceDatabase })).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: { purpose: input.purpose, operationHash: expectedHash },
    });
    await expect(assertPolicyAwareOperationStepUp({
      ...input,
      database: enforceDatabase,
      grantToken: "g".repeat(43),
    })).resolves.toBeUndefined();
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
      purpose: input.purpose,
      operationHash: expectedHash,
    }));
  });

  it("requires a bound passkey grant for a risky session even during monitor rollout", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const monitoredDatabase = {
      ...policyDatabase("monitor", consumeStepUpGrant),
      control: { appendAudit },
    } as unknown as DatabaseRuntime;
    const operation = {
      database: monitoredDatabase,
      principal: principal({ ipContextChanged: true }),
      action: "tenant.custom.high_risk_action",
      purpose: "tenant_administration" as const,
      recentMfaPurpose: "changing tenant security",
      method: "PATCH",
      path: "/v1/tenant/settings",
      body: { locale: "es" },
      requestId: "risky-operation",
    };

    await expect(assertPolicyAwareOperationStepUp({
      ...operation,
      grantToken: undefined,
    })).rejects.toMatchObject({ statusCode: 428, code: "WEBAUTHN_STEP_UP_REQUIRED" });
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "auth.session_risk_sensitive_operation_denied",
      entityId: operation.principal.sessionId,
      result: "denied",
    }));

    await expect(assertPolicyAwareOperationStepUp({
      ...operation,
      grantToken: "g".repeat(43),
    })).resolves.toBeUndefined();
    expect(consumeStepUpGrant).toHaveBeenCalledWith(expect.objectContaining({
      operationHash: hashStepUpOperation(operation.purpose, operation.method, operation.path, operation.body),
    }));
  });

  it("protects fallback-factor replacement with an exact passkey grant and preserves recovery bootstrap", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const getEffectiveIdentityPolicy = vi.fn().mockResolvedValue({
      enforcementMode: "monitor",
      minimumPasskeyCount: 0,
      requirePhishingResistantForPrivileged: false,
      actionRequirements: {},
    });
    const listCredentials = vi.fn().mockResolvedValue([{ revokedAt: null }]);
    const authDatabase = {
      enterpriseAuth: { consumeStepUpGrant, getEffectiveIdentityPolicy, listCredentials },
    } as unknown as DatabaseRuntime;
    const handler = requireFactorChangeStepUp();
    const request = {
      principal: principal(),
      server: { database: authDatabase },
      headers: {},
      method: "POST",
      url: "/v1/auth/mfa/enrollment/confirm",
      body: { enrollmentId: "70000000-0000-4000-8000-000000000001", code: "123456" },
      id: "factor-change",
    } as unknown as FastifyRequest;

    await expect(handler(request)).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: {
        purpose: "identity_security_change",
        operationHash: hashStepUpOperation(
          "identity_security_change",
          request.method,
          request.url,
          request.body,
        ),
      },
    });
    expect(consumeStepUpGrant).not.toHaveBeenCalled();

    await expect(handler({
      ...request,
      headers: { "x-step-up-grant": "g".repeat(43) },
    } as unknown as FastifyRequest)).resolves.toBeUndefined();

    await expect(handler({
      ...request,
      principal: principal({ assuranceLevel: "recovery_limited", enrollmentOnly: true }),
      headers: {},
    } as unknown as FastifyRequest)).resolves.toBeUndefined();
    expect(getEffectiveIdentityPolicy).toHaveBeenCalledTimes(2);
  });

  it("does not let session risk bypass factor-change step-up when no passkey is registered", async () => {
    const handler = requireFactorChangeStepUp();
    const request = {
      principal: principal({ userAgentContextChanged: true }),
      server: {
        database: {
          enterpriseAuth: {
            getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
              enforcementMode: "monitor",
              minimumPasskeyCount: 0,
              requirePhishingResistantForPrivileged: false,
              actionRequirements: {},
            }),
            listCredentials: vi.fn().mockResolvedValue([]),
          },
        },
      },
      headers: {},
      method: "POST",
      url: "/v1/auth/mfa/enrollment/confirm",
      body: { enrollmentId: "70000000-0000-4000-8000-000000000001", code: "123456" },
      id: "factor-change-risk",
    } as unknown as FastifyRequest;
    await expect(handler(request)).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
    });
  });

  it("uses privileged policy as an enforce-mode floor when an action has no explicit override", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(false);
    const input = {
      database: {
        enterpriseAuth: {
          consumeStepUpGrant,
          getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
            enforcementMode: "enforce",
            privilegedMinimumAal: 2,
            requirePhishingResistantForPrivileged: true,
            actionRequirements: {},
          }),
        },
      } as unknown as DatabaseRuntime,
      principal: principal(),
      grantToken: undefined,
      action: "tenant.custom.high_risk_action",
      purpose: "tenant_administration" as const,
      recentMfaPurpose: "changing tenant security",
      method: "PATCH",
      path: "/v1/tenant/settings",
      body: { locale: "es" },
    };
    await expect(assertPolicyAwareOperationStepUp(input)).rejects.toMatchObject({
      statusCode: 428,
      code: "WEBAUTHN_STEP_UP_REQUIRED",
      details: {
        purpose: "tenant_administration",
        operationHash: hashStepUpOperation("tenant_administration", "PATCH", "/v1/tenant/settings", { locale: "es" }),
      },
    });
  });

  it("keeps the global passkey floor in monitor mode and lets named policy only tighten it", async () => {
    const consumeStepUpGrant = vi.fn().mockResolvedValue(true);
    const operation = {
      principal: principal(),
      action: "platform.tenant.provision",
      purpose: "platform_administration" as const,
      method: "POST",
      path: "/v1/platform/tenants/provisioning",
      body: { tenantId: "30000000-0000-4000-8000-000000000001" },
    };
    await expect(assertGovernedOperationStepUp({
      ...operation,
      database: policyDatabase("monitor", consumeStepUpGrant),
      grantToken: undefined,
    })).rejects.toMatchObject({ statusCode: 428, code: "WEBAUTHN_STEP_UP_REQUIRED" });
    expect(consumeStepUpGrant).not.toHaveBeenCalled();

    const strictDatabase = {
      enterpriseAuth: {
        consumeStepUpGrant,
        getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
          enforcementMode: "enforce",
          privilegedMinimumAal: 2,
          actionRequirements: {
            "platform.tenant.provision": { minAal: 3, phishingResistant: true, stepUpRequired: true },
          },
        }),
      },
    } as unknown as DatabaseRuntime;
    await expect(assertGovernedOperationStepUp({
      ...operation,
      database: strictDatabase,
      grantToken: "g".repeat(43),
    })).rejects.toMatchObject({ statusCode: 403, code: "ACTION_ASSURANCE_REQUIRED" });
    expect(consumeStepUpGrant).not.toHaveBeenCalled();
  });
});

function database(consumeStepUpGrant: ReturnType<typeof vi.fn>): DatabaseRuntime {
  return { enterpriseAuth: { consumeStepUpGrant } } as unknown as DatabaseRuntime;
}

function policyDatabase(
  enforcementMode: "monitor" | "enforce",
  consumeStepUpGrant: ReturnType<typeof vi.fn>,
): DatabaseRuntime {
  return {
    enterpriseAuth: {
      consumeStepUpGrant,
      getEffectiveIdentityPolicy: vi.fn().mockResolvedValue({
        enforcementMode,
        privilegedMinimumAal: 2,
        requirePhishingResistantForPrivileged: true,
        actionRequirements: {
          "platform.tenant.suspend": { minAal: 2, phishingResistant: true, stepUpRequired: true },
        },
      }),
    },
  } as unknown as DatabaseRuntime;
}

function principal(overrides: Partial<RequestPrincipal> = {}): RequestPrincipal {
  return {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "fixture@example.invalid",
    displayName: "Fixture",
    tenantSlug: "fixture",
    tenantName: "Fixture tenant",
    tenantKind: "real",
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa",
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions: new Set(),
    ...overrides,
  };
}
