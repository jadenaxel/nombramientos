import { createHash } from "node:crypto";
import { DataConflictError, InvitationStoreError, type DatabaseRuntime, type RequestPrincipal } from "@nombramientos/database";
import { describe, expect, it, vi } from "vitest";
import type { ApiConfig } from "../src/config.js";
import type { AuthService } from "../src/modules/auth-service.js";
import { InvitationService, normalizeEmail } from "../src/modules/invitation-service.js";

describe("invitation service boundaries", () => {
  const recoveryProof = "r".repeat(43);
  it("fails closed in production until an approved token delivery channel exists", async () => {
    const service = new InvitationService({} as DatabaseRuntime, productionConfig(), {} as AuthService);
    await expect(service.create({
      principal: {} as RequestPrincipal,
      email: "recipient@example.test",
      roles: ["AUDITOR"],
      expiresInHours: 24,
      idempotencyKey: "10000000-0000-4000-8000-000000000001",
      requestId: "20000000-0000-4000-8000-000000000001",
    })).rejects.toMatchObject({
      statusCode: 503,
      code: "INVITATION_DELIVERY_UNAVAILABLE",
    });
  });

  it("normalizes recipient addresses deterministically before comparison", () => {
    expect(normalizeEmail("  INVITED.User@Example.COM  ")).toBe("invited.user@example.com");
  });

  it("rejects invalid recovery-proof batch shapes before any invitation lookup", async () => {
    const claim = vi.fn();
    const service = new InvitationService({
      invitations: { claim },
    } as unknown as DatabaseRuntime, developmentConfig(), {} as AuthService);
    const proof = "r".repeat(43);
    const base = {
      token: "t".repeat(43),
      email: "recipient@example.test",
      displayName: "Recipient",
      requestId: "60000000-0000-4000-8000-000000000001",
    };
    const invalidInputs = [
      { recoveryProofs: [] },
      { recoveryProofs: [proof], additionalRecoveryProofBatches: [[]] },
      { recoveryProofs: Array.from({ length: 13 }, () => proof) },
      { recoveryProofs: [proof], additionalRecoveryProofBatches: [Array.from({ length: 13 }, () => proof)] },
      {
        recoveryProofs: Array.from({ length: 12 }, () => proof),
        additionalRecoveryProofBatches: [
          ...Array.from({ length: 4 }, () => Array.from({ length: 12 }, () => proof)),
          Array.from({ length: 5 }, () => proof),
        ],
      },
    ];

    for (const input of invalidInputs) {
      await expect(service.accept({ ...base, ...input })).rejects.toMatchObject({
        statusCode: 400,
        code: "INVITATION_INVALID",
      });
    }
    expect(claim).not.toHaveBeenCalled();
  });

  it("recovers an accepted invitation when only a proof in the final bounded batch matches", async () => {
    const identityId = "30000000-0000-4000-8000-000000000001";
    const tenantId = "40000000-0000-4000-8000-000000000001";
    const proofs = Array.from({ length: 13 }, (_, index) =>
      `${String.fromCharCode("A".charCodeAt(0) + index)}${"r".repeat(42)}`);
    const boundProof = proofs[12]!;
    const acceptedClaim = {
      invitationId: "10000000-0000-4000-8000-000000000001",
      acceptanceId: "20000000-0000-4000-8000-000000000001",
      identityId,
      tenantId,
      email: "recipient@example.test",
      normalizedEmail: "recipient@example.test",
      roles: ["AUDITOR"] as const,
      expiresAt: new Date(Date.now() + 60_000),
      createdByIdentityId: "50000000-0000-4000-8000-000000000001",
      authorityKind: "tenant_delegate" as const,
      authorityEpoch: 0,
      acceptanceAttempt: 1,
    };
    const claim = vi.fn().mockResolvedValue(null);
    const inspectRecovery = vi.fn(async (input: { recoveryProof: string }) =>
      input.recoveryProof === boundProof
        ? { action: "finalize" as const, claim: acceptedClaim }
        : null);
    let recoveredSessionId = "";
    const databaseExpiresAt = new Date(Date.now() + 8 * 60_000);
    const recoverAcceptedEnrollmentSession = vi.fn(async (input: {
      recoveryProof: string;
      bootstrapSession: { sessionId: string };
    }) => {
      recoveredSessionId = input.bootstrapSession.sessionId;
      return { expiresAt: databaseExpiresAt };
    });
    const getPrincipal = vi.fn(async () => ({
      sessionId: recoveredSessionId,
      identityId,
      activeTenantId: tenantId,
      assuranceLevel: "enrollment_only",
      enrollmentOnly: true,
    }));
    const publicSession = vi.fn((_principal: RequestPrincipal, csrfToken: string) => ({
      status: "mfa_enrollment_required",
      authenticated: true,
      csrfToken,
    }));
    const service = new InvitationService({
      invitations: { claim, inspectRecovery, recoverAcceptedEnrollmentSession },
      getPrincipal,
    } as unknown as DatabaseRuntime, developmentConfig(), { publicSession } as unknown as AuthService);

    const result = await service.accept({
      token: "t".repeat(43),
      recoveryProofs: proofs.slice(0, 12),
      additionalRecoveryProofBatches: [proofs.slice(12)],
      email: acceptedClaim.email,
      displayName: "Recipient",
      requestId: "60000000-0000-4000-8000-000000000001",
    });

    expect(claim.mock.calls.map(([input]) => input.recoveryProof)).toEqual(proofs);
    expect(inspectRecovery.mock.calls.map(([input]) => input.recoveryProof)).toEqual(proofs);
    expect(recoverAcceptedEnrollmentSession).toHaveBeenCalledOnce();
    expect(recoverAcceptedEnrollmentSession).toHaveBeenCalledWith(expect.objectContaining({
      recoveryProof: boundProof,
    }));
    expect(result).toMatchObject({
      accepted: true,
      tenantId,
      roles: ["AUDITOR"],
      expiresAt: databaseExpiresAt,
    });
  });

  it("rejects non-delegable invitation roles before creating a control-plane row or token", async () => {
    const create = vi.fn();
    const appendAudit = vi.fn().mockResolvedValue(undefined);
    const assertInvitationRoleDelegation = vi.fn().mockRejectedValue(
      new DataConflictError("PERMISSION_ESCALATION", "role contains non-delegable authority"),
    );
    const principal = {
      identityId: "30000000-0000-4000-8000-000000000001",
      activeTenantId: "40000000-0000-4000-8000-000000000001",
    } as RequestPrincipal;
    const service = new InvitationService({
      invitations: { create },
      control: { appendAudit },
      withPrincipal: vi.fn(async (
        _principal: RequestPrincipal,
        _requestId: string,
        callback: (tenant: { assertInvitationRoleDelegation: typeof assertInvitationRoleDelegation }) => Promise<unknown>,
      ) => callback({ assertInvitationRoleDelegation })),
    } as unknown as DatabaseRuntime, developmentConfig(), {} as AuthService);

    await expect(service.create({
      principal,
      email: "recipient@example.test",
      roles: ["CHURCH_ADMIN"],
      expiresInHours: 24,
      idempotencyKey: "10000000-0000-4000-8000-000000000001",
      requestId: "20000000-0000-4000-8000-000000000001",
    })).rejects.toMatchObject({ statusCode: 403, code: "PERMISSION_ESCALATION" });
    expect(assertInvitationRoleDelegation).toHaveBeenCalledWith({
      actorIdentityId: principal.identityId,
      roles: ["CHURCH_ADMIN"],
    });
    expect(create).not.toHaveBeenCalled();
    expect(appendAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: "invitation.delegation_denied",
      result: "denied",
    }));
  });

  it("atomically accepts an invitation into a database-clamped enrollment-only session", async () => {
    const identityId = "30000000-0000-4000-8000-000000000001";
    const tenantId = "40000000-0000-4000-8000-000000000001";
    const invitationId = "10000000-0000-4000-8000-000000000001";
    const databaseExpiresAt = new Date(Date.now() + 8 * 60_000);
    const claim = {
      invitationId,
      acceptanceId: "20000000-0000-4000-8000-000000000001",
      identityId,
      tenantId,
      email: "recipient@example.test",
      normalizedEmail: "recipient@example.test",
      roles: ["AUDITOR"] as const,
      expiresAt: new Date(Date.now() + 60_000),
      createdByIdentityId: "50000000-0000-4000-8000-000000000001",
      authorityKind: "tenant_delegate" as const,
      authorityEpoch: 0,
      acceptanceAttempt: 1,
    };
    const complete = vi.fn(async (input: { passwordHash?: string; disabledPasswordHash: string; bootstrapSession?: {
      sessionId: string;
      tokenHash: string;
      csrfHash: string;
      expiresAt: Date;
      userAgentHash?: string;
      ipPrefixHash?: string;
    } }) => ({
      id: invitationId,
      tenantId,
      email: claim.email,
      roles: claim.roles,
      status: "accepted" as const,
      expiresAt: claim.expiresAt,
      createdAt: new Date(),
      acceptedAt: new Date(),
      revokedAt: null,
      version: 2,
      enrollmentSession: {
        id: input.bootstrapSession!.sessionId,
        expiresAt: databaseExpiresAt,
      },
    }));
    const principal = {
      sessionId: "placeholder",
      identityId,
      activeTenantId: tenantId,
      assuranceLevel: "enrollment_only",
      enrollmentOnly: true,
    } as unknown as RequestPrincipal;
    const publicSession = vi.fn((_principal: RequestPrincipal, csrfToken: string) => ({
      status: "mfa_enrollment_required" as const,
      authenticated: true as const,
      user: { id: identityId, displayName: "Recipient", email: claim.email },
      tenant: { id: tenantId, slug: "fixture", name: "Fixture", kind: "real", timezone: "America/La_Paz" },
      permissions: [],
      csrfToken,
      keyGrant: null,
      security: {
        mfaRequired: true,
        mfaEnabled: false,
        enrollmentOnly: true,
        assurance: "enrollment_only" as const,
        aal: 1 as const,
        authMethod: "bootstrap" as const,
        phishingResistant: false,
        recoveryRestricted: false,
        passkeyEnabled: false,
        strongAuthEnabled: false,
        passkeyCount: 0,
        idleExpiresAt: databaseExpiresAt,
        risk: { elevated: false, userAgentContextChanged: false, ipContextChanged: false },
      },
      expiresAt: databaseExpiresAt,
    }));
    const service = new InvitationService({
      invitations: {
        claim: vi.fn().mockResolvedValue(claim),
        complete,
      },
      withInvitationGrantorTenant: vi.fn(async (
        _context: unknown,
        callback: (tenant: { activateInvitationRoles: () => Promise<void> }) => Promise<unknown>,
      ) => callback({ activateInvitationRoles: vi.fn().mockResolvedValue(undefined) })),
      getPrincipal: vi.fn(async (...args: unknown[]) => {
        const sessionId = complete.mock.calls[0]?.[0].bootstrapSession?.sessionId;
        Object.assign(principal, { sessionId });
        expect(args).toHaveLength(3);
        return principal;
      }),
    } as unknown as DatabaseRuntime, developmentConfig(), { publicSession } as unknown as AuthService);

    const result = await service.accept({
      token: "t".repeat(43),
      recoveryProofs: [recoveryProof],
      email: claim.email,
      displayName: "Recipient",
      requestId: "60000000-0000-4000-8000-000000000001",
      userAgent: "Invitation test browser",
      ip: "203.0.113.42",
    });

    const bootstrap = complete.mock.calls[0]?.[0].bootstrapSession;
    expect(bootstrap).toMatchObject({
      sessionId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
      tokenHash: hashSha256(result.sessionToken),
      csrfHash: hashSha256(result.csrfToken),
      userAgentHash: hashSha256("Invitation test browser"),
      ipPrefixHash: hashSha256("203.0.113"),
    });
    expect(bootstrap?.expiresAt.getTime()).toBeGreaterThan(Date.now() + 9 * 60_000);
    expect(bootstrap?.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 10 * 60_000);
    expect(complete.mock.calls[0]?.[0]).not.toHaveProperty("passwordHash");
    expect(complete.mock.calls[0]?.[0].disabledPasswordHash).toMatch(/^\$argon2id\$/u);
    expect(result).toMatchObject({
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      tenantId,
      roles: ["AUDITOR"],
      status: "mfa_enrollment_required",
      expiresAt: databaseExpiresAt,
    });
    expect(publicSession).toHaveBeenCalledWith(principal, result.csrfToken, null, 0);
  });

  it("keeps a missing policy-required password retryable after compensating tenant roles", async () => {
    const invitationId = "10000000-0000-4000-8000-000000000001";
    const claim = {
      invitationId,
      acceptanceId: "20000000-0000-4000-8000-000000000001",
      identityId: "30000000-0000-4000-8000-000000000001",
      tenantId: "40000000-0000-4000-8000-000000000001",
      email: "recipient@example.test",
      normalizedEmail: "recipient@example.test",
      roles: ["AUDITOR"] as const,
      expiresAt: new Date(Date.now() + 60_000),
      createdByIdentityId: "50000000-0000-4000-8000-000000000001",
      authorityKind: "tenant_delegate" as const,
      authorityEpoch: 0,
      acceptanceAttempt: 1,
    };
    const cleanupInvitationRoles = vi.fn().mockResolvedValue(undefined);
    const abortAcceptance = vi.fn().mockResolvedValue(true);
    const failAcceptance = vi.fn().mockResolvedValue(undefined);
    const complete = vi.fn().mockRejectedValue(
      new InvitationStoreError("PASSWORD_REQUIRED", "password required"),
    );
    const service = new InvitationService({
      invitations: {
        claim: vi.fn().mockResolvedValue(claim),
        complete,
        abortAcceptance,
        failAcceptance,
        getAcceptanceStatus: vi.fn().mockResolvedValue("accepting"),
        beginCompensation: vi.fn().mockResolvedValue(true),
      },
      withInvitationGrantorTenant: vi.fn(async (
        _context: unknown,
        callback: (tenant: { activateInvitationRoles: () => Promise<void> }) => Promise<unknown>,
      ) => callback({ activateInvitationRoles: vi.fn().mockResolvedValue(undefined) })),
      withFencedInvitationSagaTenant: vi.fn(async (
        _context: unknown,
        callback: (tenant: { cleanupInvitationRoles: () => Promise<void> }) => Promise<unknown>,
      ) => callback({ cleanupInvitationRoles })),
    } as unknown as DatabaseRuntime, developmentConfig(), {} as AuthService);

    await expect(service.accept({
      token: "t".repeat(43),
      recoveryProofs: [recoveryProof],
      email: claim.email,
      displayName: "Recipient",
      requestId: "60000000-0000-4000-8000-000000000001",
    })).rejects.toMatchObject({ statusCode: 428, code: "INVITATION_PASSWORD_REQUIRED" });
    expect(cleanupInvitationRoles).toHaveBeenCalledWith(expect.objectContaining({
      invitationId,
      acceptanceAttempt: 1,
    }));
    expect(abortAcceptance).toHaveBeenCalledWith(claim, "PASSWORD_REQUIRED");
    expect(failAcceptance).not.toHaveBeenCalled();
  });

  it("maps an acceptance policy conflict after compensating tenant role activation", async () => {
    const cleanupInvitationRoles = vi.fn().mockResolvedValue(undefined);
    const complete = vi.fn().mockRejectedValue(
      new InvitationStoreError("POLICY_CONFLICT", "passwordless policy requires a passkey"),
    );
    const service = new InvitationService({
      invitations: {
        claim: vi.fn().mockResolvedValue({
          invitationId: "10000000-0000-4000-8000-000000000001",
          acceptanceId: "20000000-0000-4000-8000-000000000001",
          identityId: "30000000-0000-4000-8000-000000000001",
          tenantId: "40000000-0000-4000-8000-000000000001",
          email: "recipient@example.test",
          normalizedEmail: "recipient@example.test",
          roles: ["AUDITOR"],
          expiresAt: new Date(Date.now() + 60_000),
          createdByIdentityId: "50000000-0000-4000-8000-000000000001",
          authorityKind: "tenant_delegate",
          authorityEpoch: 0,
          acceptanceAttempt: 1,
        }),
        complete,
        failAcceptance: vi.fn().mockResolvedValue(undefined),
        getAcceptanceStatus: vi.fn().mockResolvedValue("accepting"),
        beginCompensation: vi.fn().mockResolvedValue(true),
      },
      withInvitationGrantorTenant: vi.fn(async (
        _context: unknown,
        callback: (tenant: { activateInvitationRoles: () => Promise<void> }) => Promise<unknown>,
      ) => callback({
        activateInvitationRoles: vi.fn().mockResolvedValue(undefined),
      })),
      withFencedInvitationSagaTenant: vi.fn(async (
        _context: unknown,
        callback: (tenant: { cleanupInvitationRoles: () => Promise<void> }) => Promise<unknown>,
      ) => callback({
        cleanupInvitationRoles,
      })),
    } as unknown as DatabaseRuntime, developmentConfig(), {} as AuthService);

    await expect(service.accept({
      token: "t".repeat(43),
      recoveryProofs: [recoveryProof],
      email: "recipient@example.test",
      displayName: "Recipient",
      password: "correct horse battery staple",
      requestId: "60000000-0000-4000-8000-000000000001",
    })).rejects.toMatchObject({ statusCode: 409, code: "INVITATION_POLICY_CONFLICT" });
    expect(complete).toHaveBeenCalledOnce();
    expect(cleanupInvitationRoles).toHaveBeenCalledWith(expect.objectContaining({
      invitationId: "10000000-0000-4000-8000-000000000001",
      acceptanceAttempt: 1,
    }));
  });
});

function productionConfig(): ApiConfig {
  return {
    environment: "production",
    host: "127.0.0.1",
    port: 4000,
    corsOrigins: new Set(["https://nombramientos.example.test"]),
    secureCookies: true,
    sessionTtlSeconds: 3_600,
    webauthn: {
      rpName: "Nombramientos",
      rpId: "nombramientos.example.test",
      expectedOrigins: ["https://nombramientos.example.test"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    },
    authEncryptionKey: Buffer.alloc(32),
    controlDatabaseUrl: "postgresql://runtime:unused@127.0.0.1:55432/nombramientos_control",
    secretMasterKey: Buffer.alloc(32),
    secretFile: "unused-in-this-test",
    tenantPoolMax: 1,
    tenantPoolIdleMs: 1_000,
  };
}

function developmentConfig(): ApiConfig {
  return { ...productionConfig(), environment: "development" };
}

function hashSha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
