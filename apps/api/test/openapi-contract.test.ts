import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { REPORT_TYPES } from "../src/lib/report-policy.js";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "trace"]);
const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const apiRoot = path.resolve(testDirectory, "..");
const workspaceRoot = path.resolve(apiRoot, "../..");
const contractPath = path.join(workspaceRoot, "docs", "api", "openapi.json");

type OpenApiOperation = {
  readonly operationId?: unknown;
  readonly responses?: unknown;
  readonly security?: unknown;
};

type OpenApiDocument = {
  readonly openapi?: unknown;
  readonly paths?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly components?: {
    readonly schemas?: Readonly<Record<string, unknown>>;
    readonly securitySchemes?: Readonly<Record<string, unknown>>;
    readonly parameters?: Readonly<Record<string, unknown>>;
    readonly responses?: Readonly<Record<string, unknown>>;
  };
};

describe("OpenAPI contract", () => {
  const document = JSON.parse(readFileSync(contractPath, "utf8")) as OpenApiDocument;

  it("matches every literal Fastify path and method in both directions", () => {
    expect(document.openapi).toBe("3.1.0");
    expect(document.paths).toBeTruthy();

    const fastifyRoutes = discoverLiteralFastifyRoutes();
    const documentedRoutes = discoverDocumentedRoutes(document);

    expect([...documentedRoutes].sort()).toEqual([...fastifyRoutes].sort());
  });

  it("resolves every local JSON reference", () => {
    for (const reference of discoverLocalReferences(document)) {
      expect(resolveJsonPointer(document, reference), reference).toBeDefined();
    }
  });

  it("gives every operation an id, responses, security decision and JSON error fallback", () => {
    const operationIds = new Set<string>();
    for (const [routePath, pathItem] of Object.entries(document.paths ?? {})) {
      expect(routePath).not.toContain(":");
      for (const [method, candidate] of Object.entries(pathItem)) {
        if (!HTTP_METHODS.has(method)) continue;
        const operation = candidate as OpenApiOperation;
        expect(operation.operationId, `${method.toUpperCase()} ${routePath}`).toEqual(expect.any(String));
        expect(operationIds.has(operation.operationId as string), `duplicate operationId ${String(operation.operationId)}`).toBe(false);
        operationIds.add(operation.operationId as string);
        expect(operation.responses, `${method.toUpperCase()} ${routePath}`).toEqual(expect.any(Object));
        expect((operation.responses as Record<string, unknown>)["default"], `${method.toUpperCase()} ${routePath}`).toBeTruthy();
        expect(operation.security, `${method.toUpperCase()} ${routePath}`).toEqual(expect.any(Array));
      }
    }
  });

  it("declares the implemented cookie, CSRF, idempotency and error primitives", () => {
    expect(document.components?.securitySchemes).toMatchObject({
      cookieAuth: { type: "apiKey", in: "cookie", name: "nom_session" },
      mfaCookie: { type: "apiKey", in: "cookie", name: "nom_mfa" },
      webauthnCookie: {
        type: "apiKey",
        in: "cookie",
        name: "nom_webauthn_<ceremony-id>",
        "x-cookie-name-pattern": "^nom_webauthn_[0-9a-f]{32}$",
      },
      csrfHeader: { type: "apiKey", in: "header", name: "X-CSRF-Token" },
    });
    expect(document.components?.parameters?.["IdempotencyKey"]).toMatchObject({
      in: "header",
      name: "Idempotency-Key",
      required: true,
    });
    expect(document.components?.schemas?.["ErrorResponse"]).toBeTruthy();
    expect(document.components?.schemas?.["ErrorCode"]).toMatchObject({
      type: "string",
      pattern: "^[A-Z][A-Z0-9_]{2,127}$",
    });
    expect(document.components?.schemas?.["EncryptedEnvelope"]).toBeTruthy();
  });

  it("documents transactional tenant content-key conflicts on every guarded HTTP write", () => {
    expect(document.components?.responses?.["ContentKeyWriteConflict"]).toMatchObject({
      content: {
        "application/json": {
          examples: {
            grantRequired: { value: { error: { code: "KEY_GRANT_REQUIRED" } } },
            keyMismatch: { value: { error: { code: "ENVELOPE_KEY_MISMATCH" } } },
          },
        },
      },
    });
    for (const [method, routePath] of [
      ["post", "/v1/members"],
      ["patch", "/v1/members/{memberId}"],
      ["post", "/v1/members/import/preview"],
      ["post", "/v1/members/import/commit"],
      ["post", "/v1/reports/{reportId}/complete"],
      ["post", "/v1/members/{memberId}/photo"],
      ["post", "/v1/members/{memberId}/qualifications"],
      ["post", "/v1/members/{memberId}/qualifications/{qualificationId}/revisions"],
      ["post", "/v1/cycles/{cycleId}/sessions"],
      ["patch", "/v1/sessions/{sessionId}"],
      ["post", "/v1/sessions/{sessionId}/agenda"],
      ["post", "/v1/sessions/{sessionId}/decisions"],
      ["put", "/v1/cycles/{cycleId}/committee"],
      ["post", "/v1/office-processes/{processId}/eligibility-pause/resolve"],
      ["post", "/v1/office-processes/{processId}/candidacies/{candidacyId}/reviews"],
      ["post", "/v1/office-processes/{processId}/linked-designations"],
      ["post", "/v1/assignments/{assignmentId}/finalize"],
      ["post", "/v1/assignments/{assignmentId}/substitute"],
    ] as const) {
      expect(document.paths?.[routePath]?.[method], `${method.toUpperCase()} ${routePath}`).toMatchObject({
        responses: { "409": { $ref: "#/components/responses/ContentKeyWriteConflict" } },
      });
    }
    const assignmentConflict = document.components?.responses?.["AssignmentEligibilityPaused"];
    expect(assignmentConflict).toMatchObject({
      "x-error-codes": expect.arrayContaining([
        "ASSIGNMENT_ELIGIBILITY_PAUSED",
        "KEY_GRANT_REQUIRED",
        "ENVELOPE_KEY_MISMATCH",
      ]),
    });
    for (const routePath of [
      "/v1/assignments/{assignmentId}/consent",
      "/v1/assignments/{assignmentId}/presentation",
      "/v1/assignments/{assignmentId}/congregational-decision",
    ]) {
      expect(document.paths?.[routePath]?.["post"]).toMatchObject({
        responses: { "409": { $ref: "#/components/responses/AssignmentEligibilityPaused" } },
      });
    }
  });

  it("publishes the active tenant IANA timezone in every authenticated session", () => {
    const session = document.components?.schemas?.["AuthenticatedSession"] as {
      properties?: { tenant?: { required?: readonly string[]; properties?: Readonly<Record<string, unknown>> } };
    } | undefined;
    expect(session?.properties?.tenant?.required).toContain("timezone");
    expect(session?.properties?.tenant?.properties?.["timezone"]).toMatchObject({
      type: "string",
      pattern: "^(?:UTC|[A-Za-z_+-]+(?:/[A-Za-z0-9_+-]+)+)$",
    });
  });

  it("declares the five-minute step-up boundary on every sensitive administration and broad-export operation", () => {
    const sensitiveOperations = new Set([
      "authorizeMemberExport",
      "updateTenantSettings",
      "generateReport",
      "createReportCorrection",
      "downloadReportArtifact",
      "recordReportPrint",
      "createLocalAccessRole",
      "updateLocalAccessRole",
      "grantLocalRoleBinding",
      "revokeLocalRoleBinding",
      "queuePlatformTenantProvisioning",
      "activatePlatformTenantInitialAdmin",
      "suspendPlatformTenant",
      "reactivatePlatformTenant",
      "queuePlatformTenantExport",
      "authorizePlatformTenantExportDownload",
      "downloadPlatformTenantExport",
      "revokePlatformTenantExportDownloadAuthorization",
      "schedulePlatformTenantDecommission",
      "cancelPlatformTenantDecommission",
      "registerCustodyKey",
      "revokeCustodyKey",
      "freezeRoundCustody",
      "downloadCustodyManifest",
    ]);
    const documented = new Map<string, Record<string, unknown>>();
    for (const pathItem of Object.values(document.paths ?? {})) {
      for (const [method, candidate] of Object.entries(pathItem)) {
        if (!HTTP_METHODS.has(method)) continue;
        const operation = candidate as Record<string, unknown>;
        if (typeof operation["operationId"] === "string") documented.set(operation["operationId"], operation);
      }
    }
    for (const operationId of sensitiveOperations) {
      expect(documented.get(operationId), operationId).toMatchObject({
        "x-mfa-required": true,
        "x-mfa-max-age-seconds": 300,
      });
    }
  });

  it("publishes the exact reversible platform lifecycle and encrypted-export contract", () => {
    const paths = document.paths ?? {};
    const operation = (route: string) => paths[route]?.["post"] as Record<string, unknown> | undefined;
    const idempotencyParameter = { $ref: "#/components/parameters/IdempotencyKey" };

    expect(operation("/v1/platform/tenants/{tenantId}/reactivate")).toMatchObject({
      operationId: "reactivatePlatformTenant",
      "x-required-permissions": ["platform.tenant.reactivate"],
      "x-mfa-required": true,
      "x-mfa-max-age-seconds": 300,
      parameters: expect.arrayContaining([idempotencyParameter]),
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantReactivateRequest" } } } },
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantReactivateResponse" } } } },
      },
    });

    expect(operation("/v1/platform/tenants/{tenantId}/exports")).toMatchObject({
      operationId: "queuePlatformTenantExport",
      "x-required-permissions": ["platform.tenant.export.request"],
      parameters: expect.arrayContaining([idempotencyParameter]),
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantExportRequest" } } } },
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantExportQueueResponse" } } } },
        "202": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantExportQueueResponse" } } } },
      },
    });
    expect(operation("/v1/platform/tenants/{tenantId}/exports/{exportId}/download-authorizations")).toMatchObject({
      operationId: "authorizePlatformTenantExportDownload",
      "x-required-permissions": ["platform.tenant.export.download"],
      parameters: expect.arrayContaining([idempotencyParameter]),
      responses: {
        "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantExportDownloadAuthorizationResponse" } } } },
      },
    });
    expect(operation("/v1/platform/tenants/{tenantId}/exports/{exportId}/download")).toMatchObject({
      operationId: "downloadPlatformTenantExport",
      "x-required-permissions": ["platform.tenant.export.download"],
      responses: {
        "200": {
          headers: {
            "Cache-Control": { schema: { const: "private, no-store, max-age=0" } },
            Pragma: { schema: { const: "no-cache" } },
          },
          content: {
            "application/vnd.nombramientos.tenant-backup+aesgcm": { schema: { type: "string", format: "binary" } },
          },
        },
      },
    });
    expect(operation("/v1/platform/export-download-authorizations/{authorizationId}/revoke")).toMatchObject({
      operationId: "revokePlatformTenantExportDownloadAuthorization",
      "x-required-permissions": ["platform.tenant.export.download"],
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantExportDownloadRevokeRequest" } } } },
    });
    expect(operation("/v1/platform/tenants/{tenantId}/decommission")).toMatchObject({
      operationId: "schedulePlatformTenantDecommission",
      "x-required-permissions": ["platform.tenant.decommission.schedule"],
      parameters: expect.arrayContaining([idempotencyParameter]),
      responses: {
        "202": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantDecommissionScheduleResponse" } } } },
      },
    });
    expect(operation("/v1/platform/tenants/{tenantId}/decommission/{decommissionId}/cancel")).toMatchObject({
      operationId: "cancelPlatformTenantDecommission",
      "x-required-permissions": ["platform.tenant.decommission.cancel"],
      parameters: expect.arrayContaining([idempotencyParameter]),
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/PlatformTenantDecommissionCancelResponse" } } } },
      },
    });

    expect(document.components?.schemas?.["PlatformTenantSuspendRequest"]).toMatchObject({
      additionalProperties: false,
      required: ["expectedVersion", "reasonCode"],
      properties: {
        reasonCode: { enum: ["security_review", "operational_hold", "institution_request", "compliance_review"] },
      },
    });
    expect(document.components?.schemas?.["PlatformTenantReactivateRequest"]).toMatchObject({
      additionalProperties: false,
      required: ["expectedVersion", "reasonCode"],
      properties: {
        reasonCode: {
          enum: [
            "security_review_completed",
            "operational_hold_resolved",
            "institution_request_resumed",
            "compliance_review_completed",
          ],
        },
      },
    });
    expect(document.components?.schemas?.["PlatformTenantReactivateData"]).toMatchObject({
      required: expect.arrayContaining(["sessionsRevoked", "sessionsCreated", "reused"]),
      properties: { status: { const: "active" }, sessionsCreated: { const: 0 } },
    });
    expect(document.components?.schemas?.["PlatformTenantExportManifest"]).toMatchObject({
      additionalProperties: false,
      properties: {
        encryption: {
          properties: {
            algorithm: { const: "AES-256-GCM" },
            keyCustody: { const: "platform-managed-not-exported" },
          },
        },
        payload: { properties: { file: { const: "database.dump.aesgcm" } } },
      },
    });
    expect(document.components?.schemas?.["PlatformTenantDecommissionRequest"]).toMatchObject({
      additionalProperties: false,
      required: ["expectedVersion", "exportJobId", "retentionDays", "reasonCode"],
      properties: { retentionDays: { minimum: 7, maximum: 3650 } },
    });
    expect(document.components?.schemas?.["PlatformTenant"]).toMatchObject({
      required: expect.arrayContaining(["latestExport", "decommission"]),
      properties: { status: { enum: expect.arrayContaining(["decommission_pending"]) } },
    });
  });

  it("matches the strict report catalog and snapshot filter contract", () => {
    const request = document.components?.schemas?.["ReportGenerateRequest"] as {
      required?: readonly string[];
      properties?: Readonly<Record<string, unknown>>;
    } | undefined;
    expect(request?.required).toEqual(expect.arrayContaining(["reportType", "locale", "format", "filters"]));
    expect(request?.properties?.["filters"]).toEqual({ $ref: "#/components/schemas/ReportFilters" });
    const filters = document.components?.schemas?.["ReportFilters"] as {
      required?: readonly string[];
      additionalProperties?: unknown;
      properties?: Readonly<Record<string, unknown>>;
    } | undefined;
    expect(filters?.required).toEqual(["snapshotSha256", "snapshotAt"]);
    expect(filters?.additionalProperties).toBe(false);
    expect(filters?.properties?.["snapshotSha256"]).toMatchObject({
      type: "string",
      pattern: "^sha256:[0-9a-f]{64}$",
    });
    expect(filters?.properties?.["snapshotAt"]).toMatchObject({ type: "string", format: "date-time" });
    expect(document.components?.schemas?.["ReportType"]).toEqual({ type: "string", enum: REPORT_TYPES });
    const paths = document.paths ?? {};
    expect(paths["/v1/reports"]?.["get"]).toMatchObject({
      responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/ReportListResponse" } } } } },
    });
    expect(paths["/v1/reports/generate"]?.["post"]).toMatchObject({
      responses: { "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/ReportGenerateResponse" } } } } },
    });
    expect(paths["/v1/reports/workflow-snapshot"]?.["get"]).toMatchObject({
      parameters: expect.arrayContaining([
        { name: "sessionId", in: "query", required: false, description: expect.any(String), schema: { type: "string", format: "uuid" } },
      ]),
      responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowReportSnapshotResponse" } } } } },
    });
    expect(document.components?.schemas?.["WorkflowReportSnapshot"]).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["cycle", "metrics", "organization", "redactions"]),
      properties: {
        metrics: { oneOf: expect.arrayContaining([{ $ref: "#/components/schemas/WorkflowReportMetrics" }]) },
        organization: { type: "array", items: { $ref: "#/components/schemas/WorkflowReportOrganizationItem" } },
      },
    });
  });

  it("documents the unconditional operation-bound WebAuthn floor on every platform mutation", () => {
    const operations = [
      ["/v1/platform/tenants/provisioning", "platform_administration"],
      ["/v1/platform/tenants/{tenantId}/initial-admin-invitation", "platform_administration"],
      ["/v1/platform/tenants/{tenantId}/suspend", "platform_administration"],
      ["/v1/platform/tenants/{tenantId}/reactivate", "platform_administration"],
      ["/v1/platform/tenants/{tenantId}/exports", "data_export"],
      ["/v1/platform/tenants/{tenantId}/exports/{exportId}/download-authorizations", "data_export"],
      ["/v1/platform/export-download-authorizations/{authorizationId}/revoke", "data_export"],
      ["/v1/platform/tenants/{tenantId}/decommission", "platform_administration"],
      ["/v1/platform/tenants/{tenantId}/decommission/{decommissionId}/cancel", "platform_administration"],
    ] as const;
    for (const [route, purpose] of operations) {
      const operation = document.paths?.[route]?.["post"] as Record<string, unknown> | undefined;
      expect(operation, route).toMatchObject({
        "x-operation-step-up": {
          purpose,
          enforcedWhen: expect.stringContaining("global platform security floor"),
        },
        responses: { "428": { $ref: "#/components/responses/WebAuthnStepUpRequired" } },
      });
      expect(operation?.["parameters"]).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: "x-step-up-grant", in: "header", required: false }),
      ]));
    }
  });

  it("documents governed action keys without weakening the unconditional WebAuthn floor", () => {
    const operations = [
      ["/v1/platform/tenants/provisioning", "post", "platform.tenant.provision"],
      ["/v1/platform/tenants/{tenantId}/suspend", "post", "platform.tenant.suspend"],
      ["/v1/platform/tenants/{tenantId}/exports/{exportId}/download-authorizations", "post", "platform.tenant.export.download"],
      ["/v1/platform/tenants/{tenantId}/decommission", "post", "platform.tenant.decommission.schedule"],
      ["/v1/auth/passkeys/{id}", "delete", "auth.passkey.revoke"],
      ["/v1/auth/sessions/revoke-others", "post", "auth.session.revoke_others"],
    ] as const;
    for (const [route, method, action] of operations) {
      expect(document.paths?.[route]?.[method], `${method.toUpperCase()} ${route}`).toMatchObject({
        "x-identity-policy-action": action,
        responses: { "428": { $ref: "#/components/responses/WebAuthnStepUpRequired" } },
      });
    }
    expect(document.components?.schemas?.["StepUpPurpose"]).toMatchObject({
      enum: expect.arrayContaining(["passkey_enrollment", "identity_security_change", "session_revocation"]),
    });
  });

  it("documents policy-aware WebAuthn on tenant, role, custody, export, and key mutations", () => {
    const operations = [
      ["/v1/access/roles", "post", "role.administration", "role_administration"],
      ["/v1/access/roles/{roleId}", "patch", "role.administration", "role_administration"],
      ["/v1/access/bindings", "post", "role.administration", "role_administration"],
      ["/v1/access/bindings/revoke", "post", "role.administration", "role_administration"],
      ["/v1/invitations", "post", "role.administration", "role_administration"],
      ["/v1/invitations/{invitationId}/revoke", "post", "role.administration", "role_administration"],
      ["/v1/members/export-authorizations", "post", "report.export", "data_export"],
      ["/v1/tenant/settings", "patch", "tenant.settings.manage", "tenant_administration"],
      ["/v1/reports/generate", "post", "report.export", "data_export"],
      ["/v1/reports/{reportId}/corrections", "post", "report.export", "data_export"],
      ["/v1/reports/{reportId}/print", "post", "report.export", "data_export"],
      ["/v1/custody/keys", "post", "custody.key.register", "custody_operation"],
      ["/v1/custody/keys/{keyId}/revoke", "post", "custody.key.revoke", "custody_operation"],
      ["/v1/rounds/{roundId}/custody/freeze", "post", "custody.round.freeze", "custody_operation"],
      ["/v1/key-lifecycle/challenges", "post", "key.lifecycle.challenge", "key_lifecycle"],
    ] as const;
    for (const [route, method, action, purpose] of operations) {
      const operation = document.paths?.[route]?.[method] as Record<string, unknown> | undefined;
      expect(operation, `${method.toUpperCase()} ${route}`).toMatchObject({
        "x-policy-operation-step-up": {
          action,
          purpose,
          enforcedWhen: expect.stringContaining("enforcementMode is enforce"),
        },
        responses: { "428": { $ref: "#/components/responses/WebAuthnStepUpRequired" } },
      });
      expect(operation?.["parameters"]).toEqual(expect.arrayContaining([
        { $ref: "#/components/parameters/StepUpGrantHeader" },
      ]));
    }
  });

  it("documents MFA enrollment, restricted assurance and one-use recovery codes", () => {
    const paths = document.paths ?? {};
    for (const route of [
      "/v1/auth/mfa/enrollment/start",
      "/v1/auth/mfa/enrollment/cancel",
      "/v1/auth/mfa/enrollment/confirm",
    ]) {
      expect(paths[route]?.["post"]).toMatchObject({
        security: [{ cookieAuth: [], csrfHeader: [] }],
        responses: { default: { $ref: "#/components/responses/Error" } },
      });
    }
    expect(document.components?.schemas?.["MfaVerifyRequest"]).toMatchObject({
      required: ["challengeId"],
      additionalProperties: false,
      properties: {
        code: { pattern: "^\\d{6}$" },
        recoveryCode: { pattern: "^(?:[A-Za-z2-7]{4}-){3}[A-Za-z2-7]{4}$" },
      },
    });
    expect(document.components?.schemas?.["MfaSecurityState"]).toMatchObject({
      required: expect.arrayContaining(["risk"]),
      properties: {
        assurance: { enum: ["enrollment_only", "password", "mfa", "recovery_limited"] },
        recoveryRestricted: { type: "boolean" },
        authMethod: { enum: ["password", "totp", "recovery_code", "passkey", "federated", "bootstrap"] },
        aal: { enum: [1, 2, 3] },
        phishingResistant: { type: "boolean" },
        risk: {
          required: ["elevated", "userAgentContextChanged", "ipContextChanged"],
        },
      },
    });
    const mfaConfirmation = paths["/v1/auth/mfa/enrollment/confirm"]?.["post"] as {
      readonly parameters?: readonly unknown[];
    } | undefined;
    expect(mfaConfirmation).toMatchObject({
      "x-conditional-operation-step-up": { purpose: "identity_security_change" },
      responses: { "428": { $ref: "#/components/responses/WebAuthnStepUpRequired" } },
    });
    expect(mfaConfirmation?.parameters).toEqual(
      expect.arrayContaining([{ $ref: "#/components/parameters/StepUpGrantHeader" }]),
    );
    const pending = document.components?.schemas?.["MfaEnrollmentPendingResponse"] as {
      properties?: { data?: { oneOf?: Array<Record<string, unknown>> } };
    } | undefined;
    const pendingMetadata = pending?.properties?.data?.oneOf?.find((candidate) => candidate["type"] === "object") as {
      required?: readonly string[];
      properties?: Readonly<Record<string, unknown>>;
    } | undefined;
    expect(pendingMetadata).toMatchObject({
      required: ["enrollmentId", "expiresAt"],
      properties: { enrollmentId: expect.any(Object), expiresAt: expect.any(Object) },
    });
    expect(pendingMetadata?.properties?.["secret"]).toBeUndefined();
    expect(pendingMetadata?.properties?.["otpauthUri"]).toBeUndefined();
    const confirmation = document.components?.schemas?.["MfaEnrollmentConfirmResponse"] as {
      properties?: { data?: { allOf?: Array<{ properties?: { recoveryCodes?: Record<string, unknown> } }> } };
    } | undefined;
    expect(confirmation?.properties?.data?.allOf?.[1]?.properties?.recoveryCodes).toMatchObject({
      minItems: 10,
      maxItems: 10,
      uniqueItems: true,
    });
  });

  it("documents invitation acceptance as an enrollment-only authenticated session", () => {
    expect(document.paths?.["/v1/invitations/recovery-context"]?.["post"]).toMatchObject({
      security: [],
      requestBody: {
        content: {
          "application/json": {
            schema: { type: "object", additionalProperties: false, maxProperties: 0 },
          },
        },
      },
      responses: {
        "200": {
          description: expect.stringContaining("no-store"),
          headers: {
            "Set-Cookie": {
              description: expect.stringMatching(/HttpOnly[\s\S]*SameSite=Strict[\s\S]*86400/u),
            },
          },
        },
      },
    });
    expect(document.paths?.["/v1/invitations/accept"]?.["post"]).toMatchObject({
      security: [],
      responses: {
        "201": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/InvitationAcceptanceResponse" },
            },
          },
        },
        "428": {
          description: expect.stringContaining("remains pending"),
        },
      },
    });
    const request = document.components?.schemas?.["InvitationAcceptRequest"] as {
      required?: readonly string[];
      properties?: Readonly<Record<string, unknown>>;
    } | undefined;
    expect(request?.required).toEqual(["token", "email", "displayName"]);
    expect(request?.properties?.["password"]).toBeTruthy();
    const response = document.components?.schemas?.["InvitationAcceptanceResponse"] as {
      properties?: { data?: { allOf?: Array<Record<string, unknown>> } };
    } | undefined;
    expect(response?.properties?.data?.allOf?.[0]).toEqual({
      $ref: "#/components/schemas/AuthenticatedSession",
    });
    expect(response?.properties?.data?.allOf?.[1]).toMatchObject({
      required: expect.arrayContaining([
        "accepted",
        "signInRequired",
        "enrollmentRequired",
        "tenantId",
        "roles",
      ]),
      properties: {
        accepted: { const: true },
        signInRequired: { const: false },
        enrollmentRequired: { const: true },
      },
    });
  });

  it("requires the exact canonical Origin on every browser flow that issues credential cookies", () => {
    for (const path of [
      "/v1/auth/login",
      "/v1/auth/mfa/verify",
      "/v1/auth/mfa/enrollment/confirm",
      "/v1/auth/passkeys/authentication/options",
      "/v1/auth/passkeys/authentication/verify",
      "/v1/auth/passkeys/registration/options",
      "/v1/auth/passkeys/registration/verify",
      "/v1/auth/passkeys/step-up/options",
      "/v1/auth/passkeys/step-up/verify",
      "/v1/invitations/recovery-context",
      "/v1/invitations/accept",
      "/v1/auth/platform-bootstrap/accept",
      "/v1/session/switch-tenant",
    ]) {
      const operation = document.paths?.[path]?.["post"] as {
        parameters?: Array<{ $ref?: string }>;
      } | undefined;
      expect(operation?.parameters, path).toContainEqual({
        $ref: "#/components/parameters/OriginHeader",
      });
    }
  });

  it("documents the persisted session/minutes lifecycle with explicit response contracts", () => {
    const paths = document.paths ?? {};
    expect(paths["/v1/cycles/{cycleId}/sessions"]?.["post"]).toMatchObject({
      responses: { "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowSessionRecordResponse" } } } } },
    });
    expect(paths["/v1/cycles/{cycleId}/sessions"]?.["get"]).toMatchObject({
      responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowSessionListResponse" } } } } },
    });
    expect(paths["/v1/sessions/{sessionId}"]?.["get"]).toMatchObject({
      responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowSessionDetailResponse" } } } } },
    });
    expect(paths["/v1/sessions/{sessionId}/attendance/{identityId}"]?.["put"]).toMatchObject({
      responses: { "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowSessionAttendanceResponse" } } } } },
    });
    expect(paths["/v1/sessions/{sessionId}/decisions"]?.["post"]).toMatchObject({
      responses: { "201": { content: { "application/json": { schema: { $ref: "#/components/schemas/WorkflowSessionDecisionResponse" } } } } },
    });
    expect(document.components?.schemas?.["WorkflowSessionDetail"]).toBeTruthy();
    expect(document.components?.schemas?.["WorkflowPhotoSnapshot"]).toBeTruthy();

    const create = document.components?.schemas?.["CycleSessionCreateRequest"] as Record<string, any>;
    const update = document.components?.schemas?.["SessionUpdateRequest"] as Record<string, any>;
    const agenda = document.components?.schemas?.["SessionAgendaCreateRequest"] as Record<string, any>;
    const session = document.components?.schemas?.["WorkflowSessionRecord"] as Record<string, any>;
    const agendaItem = document.components?.schemas?.["WorkflowSessionAgendaItem"] as Record<string, any>;
    expect(create).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["sessionId", "titleEnvelope", "titleContentHash"]),
      properties: {
        sessionId: { type: "string", format: "uuid" },
        titleEnvelope: { $ref: "#/components/schemas/EncryptedEnvelope" },
        titleContentHash: { $ref: "#/components/schemas/Sha256Fingerprint" },
      },
    });
    expect(create["properties"].title).toBeUndefined();
    expect(update).toMatchObject({
      dependentRequired: { titleEnvelope: ["titleContentHash"], titleContentHash: ["titleEnvelope"] },
      properties: {
        titleEnvelope: { $ref: "#/components/schemas/EncryptedEnvelope" },
        titleContentHash: { $ref: "#/components/schemas/Sha256Fingerprint" },
      },
    });
    expect(update["properties"].title).toBeUndefined();
    expect(agenda).toMatchObject({
      required: expect.arrayContaining(["itemId", "titleEnvelope", "titleContentHash"]),
      properties: {
        itemId: { type: "string", format: "uuid" },
        titleEnvelope: { $ref: "#/components/schemas/EncryptedEnvelope" },
        titleContentHash: { $ref: "#/components/schemas/Sha256Fingerprint" },
      },
    });
    expect(agenda["properties"].title).toBeUndefined();
    for (const responseSchema of [session, agendaItem]) {
      expect(responseSchema["required"]).toEqual(expect.arrayContaining(["titleEnvelope", "titleVersion", "legacyTitleUnavailable"]));
      expect(responseSchema["properties"].title).toBeUndefined();
      expect(responseSchema["properties"].titleEnvelope).toMatchObject({ oneOf: expect.any(Array) });
      expect(responseSchema["properties"].titleVersion).toMatchObject({ type: "integer", minimum: 0 });
    }
    expect(document.components?.schemas?.["WorkflowReportSnapshot"]).toMatchObject({
      properties: {
        sessions: { items: { $ref: "#/components/schemas/WorkflowReportSession" } },
        sessionMinutes: { oneOf: expect.arrayContaining([{ $ref: "#/components/schemas/WorkflowReportSessionMinutes" }]) },
      },
    });
  });

  it("publishes closed non-sensitive reason-code vocabularies and their outcome mappings", () => {
    const schemas = document.components?.schemas as Record<string, any>;
    const vocabulary = new Map<string, readonly string[]>([
      ["InvitationRevokeRequest", ["ADMIN_ACCESS_REVOCATION", "SECURITY_RESPONSE", "INVITATION_REPLACED"]],
      ["MemberArchiveRequest", ["RECORD_LIFECYCLE_CHANGE", "DUPLICATE_RECORD", "ADMINISTRATIVE_CORRECTION", "RETENTION_POLICY"]],
      ["MemberReactivateRequest", ["RECORD_LIFECYCLE_CHANGE", "ARCHIVE_REVERSED", "ADMINISTRATIVE_CORRECTION"]],
      ["CloseRoundRequest", ["ALL_FROZEN_ELECTORS_RESPONDED"]],
      ["CloseWorkflowRoundRequest", ["ALL_FROZEN_ELECTORS_RESPONDED"]],
      ["RevokeGrantIntent", ["DEVICE_RETIRED", "DEVICE_REPLACED", "ACCESS_REMOVED", "SECURITY_RESPONSE"]],
      ["ChallengedRevokeGrantRequest", ["DEVICE_RETIRED", "DEVICE_REPLACED", "ACCESS_REMOVED", "SECURITY_RESPONSE"]],
      ["RotateKeyIntent", ["SCHEDULED_ROTATION", "DEVICE_ROSTER_CHANGED", "SECURITY_RESPONSE", "RECOVERY_REKEY"]],
      ["ChallengedRotateKeyRequest", ["SCHEDULED_ROTATION", "DEVICE_ROSTER_CHANGED", "SECURITY_RESPONSE", "RECOVERY_REKEY"]],
      ["DeclareKeyLostIntent", ["RECOVERY_MATERIAL_UNAVAILABLE", "AUTHORIZED_DEVICES_UNAVAILABLE", "VERIFIED_RECOVERY_FAILURE"]],
      ["ChallengedDeclareKeyLostRequest", ["RECOVERY_MATERIAL_UNAVAILABLE", "AUTHORIZED_DEVICES_UNAVAILABLE", "VERIFIED_RECOVERY_FAILURE"]],
      ["EligibilityPauseResolutionRequest", ["ELIGIBILITY_ROUND_RESTARTED", "ELIGIBILITY_PROCESS_RESUMED", "ELIGIBILITY_CANDIDACIES_EXCLUDED", "ELIGIBILITY_REPLACEMENT_COMPLETED"]],
      ["CandidacyReviewRequest", ["REVIEW_STARTED", "REVIEW_ACCEPTED", "CANDIDATE_WITHDREW", "COMMITTEE_EXCLUDED", "ELIGIBILITY_FAILED"]],
      ["AssignmentFinalizationRequest", ["TERM_COMPLETED_NO_VACANCY", "TERM_COMPLETED_OPEN_VACANCY"]],
      ["AssignmentSubstitutionRequest", ["ASSIGNMENT_REPLACED"]],
      ["SessionDecisionRequest", ["RESOLUTION", "AGREEMENT", "INFORMATION_NOTED", "ITEM_DEFERRED", "ITEM_REJECTED"]],
    ]);
    for (const [schemaName, expected] of vocabulary) {
      const schema = schemas[schemaName];
      expect(schema, schemaName).toBeTruthy();
      expect(schema.properties.reason, schemaName).toBeUndefined();
      expect(schema.required ?? [], schemaName).not.toContain("reason");
      const field = schemaName === "SessionDecisionRequest" ? schema.properties.decisionCode : schema.properties.reasonCode;
      expect(field?.enum, schemaName).toEqual(expected);
      expect(field?.pattern, schemaName).toBeUndefined();
    }

    expect(schemas["EligibilityPauseResolutionRequest"].allOf).toEqual(expect.arrayContaining([
      { if: { properties: { resolutionCode: { const: "ANNUL_AND_RESTART" } } }, then: { properties: { reasonCode: { const: "ELIGIBILITY_ROUND_RESTARTED" } } } },
      { if: { properties: { resolutionCode: { const: "CLOSE_AFTER_REPLACEMENT" } } }, then: { properties: { reasonCode: { const: "ELIGIBILITY_REPLACEMENT_COMPLETED" } } } },
    ]));
    expect(schemas["CandidacyReviewRequest"].allOf).toEqual(expect.arrayContaining([
      { if: { properties: { toState: { const: "UNDER_REVIEW" } } }, then: { properties: { reasonCode: { const: "REVIEW_STARTED" } } } },
      { if: { properties: { toState: { const: "INELIGIBLE" } } }, then: { properties: { reasonCode: { const: "ELIGIBILITY_FAILED" } } } },
    ]));
    expect(schemas["AssignmentFinalizationRequest"].allOf).toEqual(expect.arrayContaining([
      { if: { properties: { openVacancy: { const: false } } }, then: { properties: { reasonCode: { const: "TERM_COMPLETED_NO_VACANCY" } } } },
      { if: { properties: { openVacancy: { const: true } } }, then: { properties: { reasonCode: { const: "TERM_COMPLETED_OPEN_VACANCY" } } } },
    ]));
    expect(schemas["SessionDecisionRequest"].allOf).toEqual(expect.arrayContaining([
      { if: { properties: { outcome: { const: "APPROVED" } } }, then: { properties: { decisionCode: { enum: ["RESOLUTION", "AGREEMENT"] } } } },
      { if: { properties: { outcome: { const: "RECORDED" } } }, then: { properties: { decisionCode: { enum: ["INFORMATION_NOTED"] } } } },
    ]));

    expect(document.paths?.["/v1/custody/keys/{keyId}/revoke"]?.["post"]).toMatchObject({
      requestBody: { content: { "application/json": { schema: {
        additionalProperties: false,
        required: ["expectedVersion", "reasonCode"],
        properties: { reasonCode: { enum: ["DEVICE_RETIRED", "DEVICE_REPLACED", "SECURITY_RESPONSE", "VERIFIED_KEY_LOSS"] } },
      } } } },
    });
  });

  it("documents the cycle-scoped organization projection without mixing proposal and election", () => {
    const operation = document.paths?.["/v1/organization"]?.["get"] as {
      parameters?: readonly unknown[];
      responses?: Readonly<Record<string, unknown>>;
    } | undefined;
    expect(operation).toMatchObject({
      parameters: expect.arrayContaining([
        { name: "cycleId", in: "query", required: false, schema: { type: "string", format: "uuid" } },
        { name: "stage", in: "query", required: false, schema: { type: "string", enum: ["proposal", "elected"], default: "elected" } },
      ]),
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/OrganizationResponse" } } } },
      },
    });
    expect(document.components?.schemas?.["OrganizationData"]).toMatchObject({
      additionalProperties: false,
      required: ["cycles", "selectedCycle", "cycleName", "stage", "items"],
      properties: {
        stage: { type: "string", enum: ["proposal", "elected"] },
        items: { type: "array", items: { $ref: "#/components/schemas/OrganizationItem" } },
      },
    });
    expect(document.components?.schemas?.["OrganizationItem"]).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["vacancyId", "officeId", "departmentId", "status", "processState"]),
      properties: {
        status: { type: "string", enum: ["vacant", "pending", "recommended", "accepted", "elected"] },
        memberSnapshot: { $ref: "#/components/schemas/OrganizationMemberSnapshot" },
        linkedToId: { type: "string", format: "uuid" },
        independent: { type: "boolean" },
      },
    });
  });

  it("documents eligibility resolution and linked designation as distinct audited workflows", () => {
    const paths = document.paths ?? {};
    expect(paths["/v1/office-processes/{processId}/eligibility-pause/resolve"]?.["post"]).toMatchObject({
      "x-required-permissions": ["workflow.eligibility.resolve"],
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/EligibilityPauseResolutionRequest" } } } },
    });
    expect(paths["/v1/office-processes/{processId}/linked-designations"]?.["post"]).toMatchObject({
      "x-required-permissions": ["linked-designation.record"],
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/LinkedDesignationRequest" } } } },
      responses: { "201": expect.any(Object) },
    });
    expect(document.components?.schemas?.["EligibilityPauseResolutionRequest"]).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["expectedPauseIds", "resolutionCode", "reasonCode", "evidenceEnvelope"]),
    });
    const eligibilitySchema = document.components?.schemas?.["EligibilityPauseResolutionRequest"] as {
      properties?: { resolutionCode?: { enum?: string[] } };
    };
    expect(eligibilitySchema.properties?.resolutionCode?.enum).toContain("CLOSE_AFTER_REPLACEMENT");
    expect(document.components?.schemas?.["LinkedDesignationRequest"]).toMatchObject({
      additionalProperties: false,
      required: ["expectedProcessVersion", "baseAssignmentId", "evidenceEnvelope"],
    });
  });

  it("documents versioned office applicability without deleting historical procedure groups", () => {
    const operation = document.paths?.["/v1/office-processes/{processId}/applicability"]?.["put"];
    expect(operation).toMatchObject({
      operationId: "setOfficeProcessApplicability",
      "x-required-permissions": ["cycle.manage"],
      parameters: expect.arrayContaining([{ $ref: "#/components/parameters/IdempotencyKey" }]),
      requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/OfficeProcessApplicabilityRequest" } } } },
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/OfficeProcessApplicabilityResponse" } } } },
      },
    });
    expect(document.components?.schemas?.["OfficeProcessApplicabilityRequest"]).toMatchObject({
      additionalProperties: false,
      required: ["expectedCycleVersion", "expectedProcessVersion", "enabled", "reasonCode"],
      allOf: expect.arrayContaining([
        { if: { properties: { enabled: { const: false } } }, then: { properties: { reasonCode: { const: "CYCLE_STRUCTURE_NOT_APPLICABLE" } } } },
        { if: { properties: { enabled: { const: true } } }, then: { properties: { reasonCode: { const: "CYCLE_STRUCTURE_APPLICABILITY_RESTORED" } } } },
      ]),
    });
  });

  it("documents dashboard analytics with round-scoped denominators and non-sensitive session counts", () => {
    expect(document.paths?.["/v1/dashboard"]?.["get"]).toMatchObject({
      "x-required-permissions": ["aggregate.read"],
      responses: {
        "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/DashboardResponse" } } } },
      },
    });
    expect(document.components?.schemas?.["DashboardData"]).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["cycle", "metrics", "analytics", "updatedAt"]),
      properties: {
        analytics: {
          required: ["roundParticipation", "departments", "sessions"],
          properties: {
            roundParticipation: {
              maxItems: 2,
              description: expect.stringContaining("never summed"),
              items: { $ref: "#/components/schemas/DashboardRoundParticipation" },
            },
            departments: { items: { $ref: "#/components/schemas/DashboardDepartmentProgress" } },
            sessions: {
              description: expect.stringContaining("Non-cancelled"),
              items: { $ref: "#/components/schemas/DashboardSessionEvolution" },
            },
          },
        },
      },
    });
    expect(document.components?.schemas?.["DashboardData"]).toMatchObject({
      properties: {
        updatedAt: { description: expect.stringContaining("repeated reads do not advance") },
        metrics: {
          properties: {
            membersTotal: { description: expect.stringContaining("Current non-archived member roster") },
            eligibleReference: { description: expect.stringMatching(/frozen.*not the current member roster/i) },
          },
        },
        activeRound: {
          oneOf: expect.arrayContaining([
            expect.objectContaining({ required: expect.arrayContaining(["version"]) }),
          ]),
        },
      },
    });
    expect(document.components?.schemas?.["DashboardRoundParticipation"]).toMatchObject({
      additionalProperties: false,
      required: expect.arrayContaining(["roundId", "kind", "phase", "version", "required", "received", "recordedAt"]),
      properties: {
        kind: { enum: ["proposal", "vote"] },
        required: { description: expect.stringContaining("Frozen") },
      },
    });
    expect(document.components?.schemas?.["DashboardDepartmentProgress"]).toMatchObject({
      required: expect.arrayContaining(["vacanciesTotal", "recommended", "accepted", "elected", "coveragePercent"]),
      properties: { vacanciesTotal: { description: expect.stringContaining("Applicable") } },
    });
    expect(document.components?.schemas?.["DashboardSessionEvolution"]).toMatchObject({
      properties: {
        status: { enum: ["scheduled", "in_progress", "closed"] },
        decisions: { description: expect.stringContaining("agendaItems") },
      },
    });
  });

  it("documents the council-board mechanism as catalogable but unavailable to ordinary election workflow", () => {
    const paths = document.paths ?? {};
    const conflictExample = {
      error: {
        code: "COUNCIL_BOARD_PROCEDURE_REQUIRED",
        message: expect.stringContaining("cannot enter the ordinary proposal or ballot workflow"),
      },
      meta: { requestId: expect.any(String) },
    };
    expect(paths["/v1/cycles/{cycleId}/vacancy-processes"]?.["post"]).toMatchObject({
      description: expect.stringContaining("council_recommendation_board_approval"),
      responses: {
        "409": {
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/ErrorResponse" },
              example: conflictExample,
            },
          },
        },
      },
    });
    expect(paths["/v1/office-processes/{processId}/proposal-rounds"]?.["post"]).toMatchObject({
      description: expect.stringContaining("COUNCIL_BOARD_PROCEDURE_REQUIRED"),
      responses: {
        "409": {
          content: {
            "application/json": {
              example: conflictExample,
            },
          },
        },
      },
    });
    expect(document.components?.schemas?.["AppointmentMechanism"]).toMatchObject({
      description: expect.stringContaining("catalogable"),
      enum: expect.arrayContaining(["council_recommendation_board_approval"]),
    });
  });
});

function discoverLiteralFastifyRoutes(): Set<string> {
  const moduleDirectory = path.join(apiRoot, "src", "modules");
  const sourceFiles = [
    path.join(apiRoot, "src", "server.ts"),
    ...readdirSync(moduleDirectory)
      .filter((filename) => filename.endsWith("-routes.ts"))
      .map((filename) => path.join(moduleDirectory, filename)),
  ];
  const routes = new Set<string>();
  for (const filename of sourceFiles) {
    const source = readFileSync(filename, "utf8");
    const routePattern = /\bapp\.(get|post|put|patch|delete|options|head|trace)\(\s*["'`]([^"'`]+)["'`]/g;
    for (const match of source.matchAll(routePattern)) {
      const method = match[1];
      const routePath = match[2];
      if (!method || !routePath) continue;
      routes.add(`${method.toUpperCase()} ${routePath.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}")}`);
    }
  }
  return routes;
}

function discoverDocumentedRoutes(document: OpenApiDocument): Set<string> {
  const routes = new Set<string>();
  for (const [routePath, pathItem] of Object.entries(document.paths ?? {})) {
    for (const method of Object.keys(pathItem)) {
      if (HTTP_METHODS.has(method)) routes.add(`${method.toUpperCase()} ${routePath}`);
    }
  }
  return routes;
}

function discoverLocalReferences(value: unknown, references = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) discoverLocalReferences(item, references);
    return references;
  }
  if (!value || typeof value !== "object") return references;
  for (const [key, item] of Object.entries(value)) {
    if (key === "$ref" && typeof item === "string" && item.startsWith("#/")) references.add(item);
    else discoverLocalReferences(item, references);
  }
  return references;
}

function resolveJsonPointer(document: unknown, reference: string): unknown {
  let current: unknown = document;
  for (const encodedSegment of reference.slice(2).split("/")) {
    const segment = encodedSegment.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!current || typeof current !== "object" || !(segment in current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}
