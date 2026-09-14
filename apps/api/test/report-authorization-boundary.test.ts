import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import type { DatabaseRuntime } from "@nombramientos/database";
import { afterEach, describe, expect, it } from "vitest";
import { ApiError } from "../src/lib/errors.js";
import { registerTenantRoutes } from "../src/modules/tenant-routes.js";

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.allSettled(apps.splice(0).map((app) => app.close()));
});

describe("stored report authorization boundary", () => {
  it("reevaluates exact type/audience permissions after revocation", async () => {
    const permissions = new Set(["report.read", "report.export", "member.read", "member.import"]);
    const { app, requestedScopes } = await fixtureApp(permissions);

    const listed = await app.inject({ method: "GET", url: "/v1/reports" });
    expect(listed.statusCode).toBe(200);
    expect(requestedScopes).toContain("roster_import_incidents:committee");
    expect(requestedScopes).not.toContain("roster_import_incidents:auditor");

    const authorized = await app.inject({
      method: "GET",
      url: "/v1/reports/40000000-0000-4000-8000-000000000001/artifact",
    });
    expect(authorized.statusCode).toBe(200);

    permissions.delete("report.export");
    const exportRevoked = await app.inject({
      method: "GET",
      url: "/v1/reports/40000000-0000-4000-8000-000000000001/artifact",
    });
    expect(exportRevoked.statusCode).toBe(403);
    expect(exportRevoked.json<{ error: { code: string } }>().error.code).toBe("PERMISSION_DENIED");
    permissions.add("report.export");

    permissions.delete("member.import");
    const revoked = await app.inject({
      method: "GET",
      url: "/v1/reports/40000000-0000-4000-8000-000000000001/artifact",
    });
    expect(revoked.statusCode).toBe(403);
    expect(revoked.json<{ error: { code: string } }>().error.code).toBe("REPORT_SCOPE_FORBIDDEN");
  });

  it("guards immutable corrections with current scope permissions and recent MFA", async () => {
    const permissions = new Set(["report.read", "report.export", "member.read", "member.import"]);
    const { app, principal, corrections } = await fixtureApp(permissions);
    const body = {
      expectedPreviousVersion: 2,
      reasonCode: "SOURCE_DATA_CORRECTED",
      filters: {
        snapshotSha256: `sha256:${"d".repeat(64)}`,
        snapshotAt: "2026-09-12T12:00:00.000Z",
      },
    };
    const request = () => app.inject({
      method: "POST",
      url: "/v1/reports/40000000-0000-4000-8000-000000000001/corrections",
      headers: { "idempotency-key": "50000000-0000-4000-8000-000000000001" },
      payload: body,
    });

    const created = await request();
    expect(created.statusCode).toBe(201);
    expect(corrections).toEqual([expect.objectContaining({
      previousReportId: "40000000-0000-4000-8000-000000000001",
      expectedPreviousVersion: 2,
      reasonCode: "SOURCE_DATA_CORRECTED",
    })]);

    permissions.delete("member.import");
    const scopeRevoked = await request();
    expect(scopeRevoked.statusCode).toBe(403);
    expect(scopeRevoked.json<{ error: { code: string } }>().error.code).toBe("REPORT_SCOPE_FORBIDDEN");

    permissions.add("member.import");
    principal.mfaVerifiedAt = new Date(Date.now() - 6 * 60_000);
    const staleMfa = await request();
    expect(staleMfa.statusCode).toBe(428);
    expect(staleMfa.json<{ error: { code: string } }>().error.code).toBe("MFA_STEP_UP_REQUIRED");
  });
});

async function fixtureApp(permissions: Set<string>): Promise<{
  readonly app: FastifyInstance;
  readonly requestedScopes: string[];
  readonly principal: { mfaVerifiedAt: Date; permissions: Set<string> };
  readonly corrections: Array<Record<string, unknown>>;
}> {
  const app = Fastify({ logger: false });
  apps.push(app);
  const requestedScopes: string[] = [];
  const corrections: Array<Record<string, unknown>> = [];
  const principal = {
    sessionId: "10000000-0000-4000-8000-000000000001",
    identityId: "20000000-0000-4000-8000-000000000001",
    activeTenantId: "30000000-0000-4000-8000-000000000001",
    email: "report-reader@invalid.example",
    displayName: "Report reader",
    tenantSlug: "report-reader",
    tenantName: "Report reader tenant",
    tenantKind: "real" as const,
    tenantTimezone: "America/La_Paz",
    csrfHash: "fixture",
    expiresAt: new Date(Date.now() + 60_000),
    assuranceLevel: "mfa" as const,
    authenticatedAt: new Date(),
    mfaVerifiedAt: new Date(),
    mfaRequired: true,
    mfaEnabled: true,
    enrollmentOnly: false,
    permissions,
  };
  app.decorateRequest("principal", null);
  app.decorate("authenticate", async (request: FastifyRequest) => { request.principal = principal; });
  app.decorate("verifyCsrf", async () => undefined);
  app.decorate("requirePermission", (permission: string) => async (request: FastifyRequest) => {
    if (!request.principal?.permissions.has(permission)) {
      throw new ApiError(403, "PERMISSION_DENIED", `Missing required permission: ${permission}`);
    }
  });
  const descriptor = {
    id: "40000000-0000-4000-8000-000000000001",
    reportType: "roster_import_incidents",
    audience: "committee",
    locale: "es",
    format: "pdf",
    state: "ready",
    requestedByIdentityId: principal.identityId,
    version: 2,
    snapshotSha256: `sha256:${"a".repeat(64)}`,
    filename: "roster_import_incidents-40000000.pdf",
    mediaType: "application/pdf",
  };
  const tenant = {
    listReports: async (_limit: number, scopes: readonly string[]) => {
      requestedScopes.splice(0, requestedScopes.length, ...scopes);
      return [];
    },
    getReportDescriptor: async () => descriptor,
    getReportArtifact: async () => ({
      envelope: { algorithm: "AES-256-GCM", keyId: "tenant-key", nonce: "opaque", ciphertext: "opaque", aad: "opaque" },
      artifactSha256: `sha256:${"b".repeat(64)}`,
      ciphertextSha256: `sha256:${"c".repeat(64)}`,
      plaintextBytes: 100,
      manifest: {},
      filename: descriptor.filename,
      mediaType: descriptor.mediaType,
      requestVersion: 1,
      reportType: descriptor.reportType,
      audience: descriptor.audience,
      locale: descriptor.locale,
      format: descriptor.format,
      version: 2,
    }),
    correctReport: async (input: Record<string, unknown>) => {
      corrections.push(input);
      return {
        ...descriptor,
        id: "40000000-0000-4000-8000-000000000002",
        state: "pending",
        version: 1,
        filters: input["filters"],
        artifactSha256: null,
        ciphertextSha256: null,
        ciphertextBytes: null,
        plaintextBytes: null,
        manifest: null,
        errorCode: null,
        supersedesReportId: descriptor.id,
        correctedByReportId: null,
        correctionReasonCode: input["reasonCode"],
        lineageRootId: descriptor.id,
        lineageRevision: 2,
        createdAt: new Date(),
        readyAt: null,
        failedAt: null,
      };
    },
  };
  app.decorate("database", {
    enterpriseAuth: {
      getEffectiveIdentityPolicy: async () => ({
        enforcementMode: "monitor",
        privilegedMinimumAal: 2,
        requirePhishingResistantForPrivileged: true,
        actionRequirements: {},
      }),
    },
    withPrincipal: async <T>(_principal: unknown, _requestId: string, work: (store: typeof tenant) => Promise<T>): Promise<T> => work(tenant),
  } as unknown as DatabaseRuntime);
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({ error: { code: error.code, message: error.message }, meta: { requestId: request.id } });
    }
    return reply.status(500).send({ error: { code: "INTERNAL_ERROR", message: "Unexpected" }, meta: { requestId: request.id } });
  });
  await registerTenantRoutes(app);
  return { app, requestedScopes, principal, corrections };
}
