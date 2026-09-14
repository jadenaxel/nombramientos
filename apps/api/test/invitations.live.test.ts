import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseRuntime, EncryptedFileSecretProvider, encryptServerSecret } from "@nombramientos/database";
import type { FastifyInstance } from "fastify";
import * as OTPAuth from "otpauth";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseApiConfig } from "../src/config.js";
import { INVITATION_RECOVERY_COOKIE_PREFIX } from "../src/modules/invitation-routes.js";
import { buildServer } from "../src/server.js";
import {
  cleanupStageError,
  closePoolOwnerAndConfirmDrained,
  collectCleanupFailure,
  endPoolAndConfirmDrained,
} from "./ephemeral-postgres-cleanup.js";
import { assertExactWorkspaceAdminUrl } from "./local-test-database-boundary.js";
import {
  destroyTemporaryActiveTenant,
  provisionTemporaryActiveTenant,
  type TemporaryActiveTenant,
} from "./temporary-active-tenant.js";

const DEMO_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
const OZAMA_TENANT_ID = "0a2a0000-0000-4000-8000-000000000001";
const CONTROL_DATABASE = "nombramientos_control";
const ORIGIN = "http://localhost:3000";
const USER_AGENT = "nombramientos-ac07-invitation-live-test";
const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const installFile = path.join(workspaceRoot, "packages", "database", ".local", "install.json");
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverLocalAdminUrl();
const liveReady = adminUrl ? await canReachInvitationTargets(adminUrl) : false;

if (requireLiveIntegration && !liveReady) {
  throw new Error(
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires migrated invitation tables/functions on the local PostgreSQL 18 workspace cluster",
  );
}

const live = liveReady ? describe : describe.skip;

live("AC-07 live tenant invitations", () => {
  let fixture: InvitationFixture | undefined;

  beforeAll(async () => {
    if (!adminUrl) throw new Error("The local administrator connection is unavailable");
    fixture = await createFixture(adminUrl);
  }, 45_000);

  afterAll(async () => {
    if (fixture) await cleanupFixture(fixture);
  }, 45_000);

  it("requires authentication, CSRF, and role.manage before creating an invitation", async () => {
    const current = requireFixture(fixture);
    const email = uniqueEmail("authorization");
    const payload = { email, roles: ["AUDITOR"], expiresInHours: 24 };
    const unauthenticated = await current.app.inject({
      method: "POST",
      url: "/v1/invitations",
      headers: { origin: ORIGIN, "user-agent": USER_AGENT, "idempotency-key": randomUUID() },
      payload,
    });
    expect(unauthenticated.statusCode).toBe(401);
    expect(apiErrorCode(unauthenticated)).toBe("AUTHENTICATION_REQUIRED");

    const missingCsrf = await current.app.inject({
      method: "POST",
      url: "/v1/invitations",
      headers: {
        origin: ORIGIN,
        "user-agent": USER_AGENT,
        cookie: `nom_session=${current.demoManager.sessionToken}; nom_csrf=${current.demoManager.csrfToken}`,
        "idempotency-key": randomUUID(),
      },
      payload,
    });
    expect(missingCsrf.statusCode).toBe(403);
    expect(apiErrorCode(missingCsrf)).toBe("CSRF_INVALID");

    const forbidden = await createInvitation(current, current.restrictedManager, payload);
    expect(forbidden.statusCode).toBe(403);
    expect(apiErrorCode(forbidden)).toBe("PERMISSION_DENIED");
    const persisted = await current.control.query(
      "SELECT 1 FROM tenant_invitations WHERE normalized_email=$1",
      [email.toLowerCase()],
    );
    expect(persisted.rowCount).toBe(0);
  });

  it("returns a random token once and replays only non-secret invitation metadata", async () => {
    const current = requireFixture(fixture);
    const idempotencyKey = randomUUID();
    const email = uniqueEmail("once");
    const first = await createInvitation(current, current.demoManager, {
      email,
      roles: ["AUDITOR"],
      expiresInHours: 48,
    }, idempotencyKey);
    expect(first.statusCode, first.body).toBe(201);
    const firstData = first.json<{ data: InvitationCreation }>().data;
    expect(firstData).toMatchObject({ created: true, delivery: "local_one_time_token" });
    expect(firstData.acceptanceToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    current.invitationIds.push(firstData.invitation.id);

    const persisted = await current.control.query<{ token_hash: string }>(
      "SELECT token_hash FROM tenant_invitations WHERE id=$1 AND tenant_id=$2",
      [firstData.invitation.id, DEMO_TENANT_ID],
    );
    expect(persisted.rows[0]?.token_hash).toBe(sha256(requireToken(firstData)));
    expect(persisted.rows[0]?.token_hash).not.toBe(firstData.acceptanceToken);

    const replay = await createInvitation(current, current.demoManager, {
      email,
      roles: ["AUDITOR"],
      expiresInHours: 48,
    }, idempotencyKey);
    expect(replay.statusCode).toBe(200);
    const replayData = replay.json<{ data: InvitationCreation }>().data;
    expect(replayData).toMatchObject({ created: false, delivery: "token_already_issued" });
    expect(replayData.invitation.id).toBe(firstData.invitation.id);
    expect(replayData).not.toHaveProperty("acceptanceToken");
  });

  it("scopes listing and revocation to the authenticated tenant and makes revoked tokens indistinguishable", async () => {
    const current = requireFixture(fixture);
    const demo = await createInvitation(current, current.demoManager, {
      email: uniqueEmail("demo-scope"),
      roles: ["COMMITTEE_MEMBER"],
      expiresInHours: 24,
    });
    const scratch = await createInvitation(current, current.scratchManager, {
      email: uniqueEmail("scratch-scope"),
      roles: ["AUDITOR"],
      expiresInHours: 24,
    });
    expect(
      [demo.statusCode, scratch.statusCode],
      `${apiErrorCode(demo) ?? "ok"}/${apiErrorCode(scratch) ?? "ok"}`,
    ).toEqual([201, 201]);
    const demoData = demo.json<{ data: InvitationCreation }>().data;
    const scratchData = scratch.json<{ data: InvitationCreation }>().data;
    current.invitationIds.push(demoData.invitation.id, scratchData.invitation.id);

    const listed = await current.app.inject({
      method: "GET",
      url: "/v1/invitations?limit=100",
      headers: managerHeaders(current.demoManager),
    });
    expect(listed.statusCode).toBe(200);
    const listedIds = listed.json<{ data: { items: Array<{ id: string }> } }>().data.items.map(({ id }) => id);
    expect(listedIds).toContain(demoData.invitation.id);
    expect(listedIds).not.toContain(scratchData.invitation.id);

    const crossTenant = await revokeInvitation(current, current.demoManager, scratchData.invitation.id);
    const unknown = await revokeInvitation(current, current.demoManager, randomUUID());
    expect(samePublicError(crossTenant, unknown)).toBe(true);
    expect(apiErrorCode(crossTenant)).toBe("INVITATION_NOT_FOUND");

    const revoked = await revokeInvitation(current, current.scratchManager, scratchData.invitation.id, "ADMIN_ACCESS_REVOCATION");
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json<{ data: { status: string } }>().data.status).toBe("revoked");

    const password = strongPassword();
    const revokedAcceptance = await acceptInvitation(current, {
      token: requireToken(scratchData),
      email: scratchData.invitation.email,
      displayName: "Persona Revocada",
      password,
    }, "127.0.0.21");
    const unknownAcceptance = await acceptInvitation(current, {
      token: randomBytes(32).toString("base64url"),
      email: scratchData.invitation.email,
      displayName: "Persona Revocada",
      password,
    }, "127.0.0.21");
    expect(samePublicError(revokedAcceptance, unknownAcceptance)).toBe(true);
    expect(apiErrorCode(revokedAcceptance)).toBe("INVITATION_INVALID");
    const identity = await current.control.query(
      "SELECT 1 FROM platform_identities WHERE normalized_email=$1",
      [scratchData.invitation.email.toLowerCase()],
    );
    expect(identity.rowCount).toBe(0);
  }, 30_000);

  it("expires a pending invitation without creating identity, membership, or tenant roles", async () => {
    const current = requireFixture(fixture);
    const email = uniqueEmail("expired");
    const data = await insertExpiredInvitationFixture(current, current.demoManager, email);
    current.invitationIds.push(data.invitation.id);

    const response = await acceptInvitation(current, {
      token: requireToken(data),
      email,
      displayName: "Persona Expirada",
      password: strongPassword(),
    }, "127.0.0.22");
    expect(response.statusCode).toBe(400);
    expect(apiErrorCode(response)).toBe("INVITATION_INVALID");
    const state = await current.control.query<{ status: string; identities: number; memberships: number }>(
      `SELECT invitation.status,
              (SELECT count(*)::int FROM platform_identities WHERE normalized_email=$2) AS identities,
              (SELECT count(*)::int FROM tenant_memberships membership
                JOIN platform_identities identity ON identity.id=membership.identity_id
               WHERE identity.normalized_email=$2) AS memberships
         FROM tenant_invitations invitation
        WHERE invitation.id=$1`,
      [data.invitation.id, email.toLowerCase()],
    );
    expect(state.rows[0]).toMatchObject({ status: "expired", identities: 0, memberships: 0 });
    const tenantRoles = await current.demo.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM role_bindings WHERE source_invitation_id=$1",
      [data.invitation.id],
    );
    expect(tenantRoles.rows[0]?.count).toBe(0);
  }, 30_000);

  it("revokes a failed cross-database acceptance and removes only its sourced tenant roles", async () => {
    const current = requireFixture(fixture);
    const created = await createInvitation(current, current.demoManager, {
      email: uniqueEmail("failed-compensation"),
      roles: ["AUDITOR"],
      expiresInHours: 24,
    });
    expect(created.statusCode).toBe(201);
    const data = created.json<{ data: InvitationCreation }>().data;
    current.invitationIds.push(data.invitation.id);
    const interruptedIdentityId = randomUUID();
    const acceptanceId = randomUUID();
    const requestId = randomUUID();
    const claim = await current.database.invitations.claim({
      token: requireToken(data),
      normalizedEmail: data.invitation.email.toLowerCase(),
      recoveryProof: randomBytes(32).toString("base64url"),
      acceptanceId,
      identityId: interruptedIdentityId,
    });
    expect(claim).not.toBeNull();
    if (!claim) throw new Error("Failed-compensation fixture could not claim its invitation");
    await current.database.withInvitationGrantorTenant({
      tenantId: claim.tenantId,
      grantorIdentityId: claim.createdByIdentityId,
      acceptanceId: claim.acceptanceId,
      requestId,
    }, (tenant) => tenant.activateInvitationRoles({
      invitationId: claim.invitationId,
      identityId: claim.identityId,
      roles: claim.roles,
      grantedByIdentityId: claim.createdByIdentityId,
      acceptanceAttempt: claim.acceptanceAttempt,
    }));
    expect(await current.database.invitations.beginCompensation(claim)).toBe(true);
    await current.database.invitations.failAcceptance(claim, "TENANT_COMPENSATION_FAILED", requestId);
    const failed = await current.control.query<{ status: string; last_error_code: string | null }>(
      "SELECT status,last_error_code FROM tenant_invitations WHERE id=$1",
      [data.invitation.id],
    );
    expect(failed.rows[0]).toMatchObject({ status: "failed", last_error_code: "TENANT_COMPENSATION_FAILED" });

    const revoked = await revokeInvitation(
      current,
      current.demoManager,
      data.invitation.id,
      "SECURITY_RESPONSE",
    );
    expect(revoked.statusCode).toBe(200);
    expect(revoked.json<{ data: { status: string } }>().data.status).toBe("revoked");
    const remaining = await current.demo.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM role_bindings WHERE source_invitation_id=$1",
      [data.invitation.id],
    );
    expect(remaining.rows[0]?.count).toBe(0);
    const controlAccess = await current.control.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM platform_identities WHERE id=$1)
         + (SELECT count(*) FROM tenant_memberships WHERE identity_id=$1)
       )::int AS count`,
      [interruptedIdentityId],
    );
    expect(controlAccess.rows[0]?.count).toBe(0);
  });

  it("requires the exact email, activates exact roles once, and limits accepted-response recovery to its browser context", async () => {
    const current = requireFixture(fixture);
    const email = uniqueEmail("accepted");
    const created = await createInvitation(current, current.demoManager, {
      email,
      roles: ["AUDITOR", "COMMITTEE_MEMBER"],
      expiresInHours: 24,
    });
    expect(created.statusCode, apiErrorCode(created)).toBe(201);
    const data = created.json<{ data: InvitationCreation }>().data;
    current.invitationIds.push(data.invitation.id);
    const password = strongPassword();

    const missingRecoveryContext = await acceptInvitationWithoutRecoveryContext(current, {
      token: requireToken(data),
      email,
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.25");
    expect(missingRecoveryContext.statusCode).toBe(428);
    expect(apiErrorCode(missingRecoveryContext)).toBe("INVITATION_RECOVERY_CONTEXT_REQUIRED");

    const wrongEmail = await acceptInvitation(current, {
      token: requireToken(data),
      email: uniqueEmail("wrong-recipient"),
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.23");
    expect(wrongEmail.statusCode).toBe(400);
    expect(apiErrorCode(wrongEmail)).toBe("INVITATION_INVALID");
    const stillPending = await current.control.query<{ status: string }>(
      "SELECT status FROM tenant_invitations WHERE id=$1",
      [data.invitation.id],
    );
    expect(stillPending.rows[0]?.status).toBe("pending");

    const passwordRequired = await acceptInvitation(current, {
      token: requireToken(data),
      email,
      displayName: "Marisol Prueba",
    }, "127.0.0.23");
    expect(passwordRequired.statusCode).toBe(428);
    expect(apiErrorCode(passwordRequired)).toBe("INVITATION_PASSWORD_REQUIRED");
    expect(passwordRequired.headers["set-cookie"]).toBeUndefined();
    const retryableState = await current.control.query<{
      status: string;
      acceptance_id: string | null;
      acceptance_identity_id: string | null;
    }>(
      "SELECT status,acceptance_id::text,acceptance_identity_id::text FROM tenant_invitations WHERE id=$1",
      [data.invitation.id],
    );
    expect(retryableState.rows[0]).toMatchObject({
      status: "pending",
      acceptance_id: null,
      acceptance_identity_id: null,
    });

    const accepted = await acceptInvitation(current, {
      token: requireToken(data),
      email,
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.23");
    expect(accepted.statusCode).toBe(201);
    expect(accepted.json<{ data: Record<string, unknown> }>().data).toMatchObject({
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      status: "mfa_enrollment_required",
      permissions: [],
      keyGrant: null,
      tenantId: DEMO_TENANT_ID,
      roles: ["AUDITOR", "COMMITTEE_MEMBER"],
    });
    const acceptanceSession = requireCookie(accepted, "nom_session");
    const acceptanceCsrf = requireCookie(accepted, "nom_csrf");
    const enrollmentSession = await current.app.inject({
      method: "GET",
      url: "/v1/session",
      headers: {
        origin: ORIGIN,
        "user-agent": USER_AGENT,
        cookie: `nom_session=${acceptanceSession}; nom_csrf=${acceptanceCsrf}`,
      },
      remoteAddress: "127.0.0.23",
    });
    expect(enrollmentSession.statusCode, enrollmentSession.body).toBe(200);
    expect(enrollmentSession.json<{ data: Record<string, unknown> }>().data).toMatchObject({
      status: "mfa_enrollment_required",
      permissions: [],
      keyGrant: null,
      security: {
        enrollmentOnly: true,
        assurance: "enrollment_only",
        authMethod: "bootstrap",
      },
    });

    const invitation = await current.control.query<{
      status: string;
      consumed_at: Date | null;
      acceptance_identity_id: string;
      password_hash: string;
      password_provisioned: boolean;
      membership_count: number;
    }>(
      `SELECT invitation.status,invitation.consumed_at,invitation.acceptance_identity_id::text,
              identity.password_hash,identity.password_provisioned,
              (SELECT count(*)::int FROM tenant_memberships
                WHERE identity_id=invitation.acceptance_identity_id
                  AND tenant_id=$2 AND status='active') AS membership_count
         FROM tenant_invitations invitation
         JOIN platform_identities identity ON identity.id=invitation.acceptance_identity_id
        WHERE invitation.id=$1`,
      [data.invitation.id, DEMO_TENANT_ID],
    );
    const invitationRecord = invitation.rows[0];
    expect(invitationRecord).toMatchObject({ status: "accepted", membership_count: 1 });
    expect(invitationRecord?.consumed_at).toBeInstanceOf(Date);
    expect(invitationRecord?.password_hash.startsWith("$argon2id$")).toBe(true);
    expect(invitationRecord?.password_provisioned).toBe(true);

    const demoRoles = await current.demo.query<{ code: string }>(
      `SELECT role.code
         FROM role_bindings binding
         JOIN roles role ON role.id=binding.role_id
        WHERE binding.identity_id=$1 AND binding.source_invitation_id=$2 AND binding.revoked_at IS NULL
        ORDER BY role.code`,
      [invitationRecord?.acceptance_identity_id, data.invitation.id],
    );
    expect(demoRoles.rows.map(({ code }) => code)).toEqual(["AUDITOR", "COMMITTEE_MEMBER"]);
    const crossedRoles = await current.scratch.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM role_bindings WHERE identity_id=$1 OR source_invitation_id=$2",
      [invitationRecord?.acceptance_identity_id, data.invitation.id],
    );
    expect(crossedRoles.rows[0]?.count).toBe(0);
    const crossedMembership = await current.control.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM tenant_memberships WHERE identity_id=$1 AND tenant_id=$2",
      [invitationRecord?.acceptance_identity_id, current.temporaryTenant.tenantId],
    );
    expect(crossedMembership.rows[0]?.count).toBe(0);

    const nonPrivilegedLogin = await current.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: { origin: ORIGIN, "user-agent": USER_AGENT },
      remoteAddress: "127.0.0.23",
      payload: { email, password },
    });
    expect(nonPrivilegedLogin.statusCode).toBe(200);
    expect(nonPrivilegedLogin.json<{ data: {
      status: string;
      permissions: string[];
      keyGrant: unknown;
      security: { mfaRequired: boolean; mfaEnabled: boolean; assurance: string };
    } }>().data).toMatchObject({
      status: "authenticated",
      permissions: expect.arrayContaining(["ballot.submit", "report.read"]),
      keyGrant: null,
      security: { mfaRequired: false, mfaEnabled: false, assurance: "password" },
    });

    const recovered = await acceptInvitation(current, {
      token: requireToken(data),
      email,
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.23");
    expect(recovered.statusCode, recovered.body).toBe(201);
    expect(recovered.json<{ data: Record<string, unknown> }>().data).toMatchObject({
      accepted: true,
      status: "mfa_enrollment_required",
      permissions: [],
    });
    expect(requireCookie(recovered, "nom_session")).not.toBe(acceptanceSession);
    const rotatedOut = await current.app.inject({
      method: "GET",
      url: "/v1/session",
      headers: {
        origin: ORIGIN,
        "user-agent": USER_AGENT,
        cookie: `nom_session=${acceptanceSession}; nom_csrf=${acceptanceCsrf}`,
      },
      remoteAddress: "127.0.0.23",
    });
    expect(rotatedOut.statusCode).toBe(401);

    const crossContextReplay = await acceptInvitation(current, {
      token: requireToken(data),
      email,
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.24");
    const unknown = await acceptInvitation(current, {
      token: randomBytes(32).toString("base64url"),
      email,
      displayName: "Marisol Prueba",
      password,
    }, "127.0.0.24");
    expect(samePublicError(crossContextReplay, unknown)).toBe(true);
    expect(apiErrorCode(crossContextReplay)).toBe("INVITATION_INVALID");

    const audit = await current.control.query<{ action: string }>(
      `SELECT action FROM platform_audit_events
        WHERE entity_type='tenant_invitation' AND entity_id = ANY($1::text[])
          AND action IN ('invitation.created','invitation.revoked','invitation.accepted')`,
      [current.invitationIds],
    );
    expect(audit.rows.some(({ action }) => action === "invitation.created")).toBe(true);
    expect(audit.rows.some(({ action }) => action === "invitation.revoked")).toBe(true);
    expect(audit.rows.some(({ action }) => action === "invitation.accepted")).toBe(true);
  }, 45_000);

  it("withholds invited administrator privileges until MFA enrollment and consumes recovery codes once", async () => {
    const current = requireFixture(fixture);
    const email = uniqueEmail("mfa-admin");
    const password = strongPassword();
    const created = await createInvitation(current, current.demoManager, {
      email,
      roles: ["COMMITTEE_CHAIR"],
      expiresInHours: 24,
    });
    expect(created.statusCode).toBe(201);
    const invitation = created.json<{ data: InvitationCreation }>().data;
    current.invitationIds.push(invitation.invitation.id);
    const accepted = await acceptInvitation(current, {
      token: requireToken(invitation),
      email,
      displayName: "Administración MFA",
      password,
    }, "127.0.0.31");
    expect(accepted.statusCode).toBe(201);

    const identity = await current.control.query<{ id: string; mfa_required: boolean; mfa_enabled: boolean }>(
      "SELECT id::text,mfa_required,mfa_enabled FROM platform_identities WHERE normalized_email=$1",
      [email.toLowerCase()],
    );
    expect(identity.rows[0]).toMatchObject({ mfa_required: true, mfa_enabled: false });

    const authHeaders = { origin: ORIGIN, "user-agent": USER_AGENT };
    const restrictedData = accepted.json<{ data: {
      status: string;
      permissions: string[];
      keyGrant: unknown;
      csrfToken: string;
      security: { enrollmentOnly: boolean; assurance: string };
    } }>().data;
    expect(restrictedData).toMatchObject({
      status: "mfa_enrollment_required",
      permissions: [],
      keyGrant: null,
      security: { enrollmentOnly: true, assurance: "enrollment_only" },
    });
    const restrictedSession = requireCookie(accepted, "nom_session");
    const restrictedCsrf = requireCookie(accepted, "nom_csrf");
    const restrictedCookie = `nom_session=${restrictedSession}; nom_csrf=${restrictedCsrf}`;

    const blocked = await current.app.inject({
      method: "GET",
      url: "/v1/dashboard",
      headers: { ...authHeaders, cookie: restrictedCookie },
      remoteAddress: "127.0.0.31",
    });
    expect(blocked.statusCode).toBe(403);
    expect(apiErrorCode(blocked)).toBe("MFA_ENROLLMENT_REQUIRED");

    const missingCsrf = await current.app.inject({
      method: "POST",
      url: "/v1/auth/mfa/enrollment/start",
      headers: { ...authHeaders, cookie: restrictedCookie },
      remoteAddress: "127.0.0.31",
      payload: {},
    });
    expect(missingCsrf.statusCode).toBe(403);
    expect(apiErrorCode(missingCsrf)).toBe("CSRF_INVALID");

    const enrollment = await current.app.inject({
      method: "POST",
      url: "/v1/auth/mfa/enrollment/start",
      headers: { ...authHeaders, cookie: restrictedCookie, "x-csrf-token": restrictedCsrf },
      remoteAddress: "127.0.0.31",
      payload: {},
    });
    expect(enrollment.statusCode, enrollment.body).toBe(201);
    expect(enrollment.headers["cache-control"]).toBe("no-store");
    const enrollmentData = enrollment.json<{ data: {
      enrollmentId: string;
      secret: string;
      otpauthUri: string;
    } }>().data;
    expect(enrollmentData.secret).toMatch(/^[A-Z2-7]+$/);
    expect(enrollmentData.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    const persistedSecret = await current.control.query<{ ciphertext: string }>(
      "SELECT mfa_enrollment_secret_ciphertext AS ciphertext FROM platform_identities WHERE id=$1",
      [identity.rows[0]!.id],
    );
    expect(persistedSecret.rows[0]?.ciphertext).toMatch(/^v1\./);
    expect(persistedSecret.rows[0]?.ciphertext).not.toContain(enrollmentData.secret);

    const secretReplay = await current.app.inject({
      method: "POST",
      url: "/v1/auth/mfa/enrollment/start",
      headers: { ...authHeaders, cookie: restrictedCookie, "x-csrf-token": restrictedCsrf },
      remoteAddress: "127.0.0.31",
      payload: {},
    });
    expect(secretReplay.statusCode).toBe(409);
    expect(apiErrorCode(secretReplay)).toBe("MFA_ENROLLMENT_ALREADY_STARTED");
    expect(secretReplay.body).not.toContain(enrollmentData.secret);

    const totp = new OTPAuth.TOTP({
      secret: OTPAuth.Secret.fromBase32(enrollmentData.secret),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    const confirmed = await current.app.inject({
      method: "POST",
      url: "/v1/auth/mfa/enrollment/confirm",
      headers: { ...authHeaders, cookie: restrictedCookie, "x-csrf-token": restrictedCsrf },
      remoteAddress: "127.0.0.31",
      payload: { enrollmentId: enrollmentData.enrollmentId, code: totp.generate({ timestamp: Date.now() }) },
    });
    expect(confirmed.statusCode, apiErrorCode(confirmed)).toBe(200);
    expect(confirmed.headers["cache-control"]).toBe("no-store");
    const confirmedData = confirmed.json<{ data: {
      status: string;
      permissions: string[];
      keyGrant: unknown;
      csrfToken: string;
      recoveryCodes: string[];
      security: { enrollmentOnly: boolean; assurance: string; mfaEnabled: boolean };
    } }>().data;
    expect(confirmedData.status).toBe("authenticated");
    expect(confirmedData.permissions).toContain("cycle.manage");
    expect(confirmedData.keyGrant).toBeNull();
    expect(confirmedData.security).toMatchObject({ enrollmentOnly: false, assurance: "mfa", mfaEnabled: true });
    expect(confirmedData.recoveryCodes).toHaveLength(10);
    expect(new Set(confirmedData.recoveryCodes).size).toBe(10);
    expect(confirmedData.recoveryCodes.every((code) => /^(?:[A-Z2-7]{4}-){3}[A-Z2-7]{4}$/.test(code))).toBe(true);
    const enrolledSession = requireCookie(confirmed, "nom_session");
    const enrolledCsrf = requireCookie(confirmed, "nom_csrf");
    expect(enrolledSession).not.toBe(restrictedSession);
    const oldSession = await current.app.inject({
      method: "GET", url: "/v1/session",
      headers: { ...authHeaders, cookie: restrictedCookie }, remoteAddress: "127.0.0.31",
    });
    expect(oldSession.statusCode).toBe(401);

    await waitForNextTotpStep();
    const totpLogin = await current.app.inject({
      method: "POST", url: "/v1/auth/login", headers: authHeaders, remoteAddress: "127.0.0.31",
      payload: { email, password },
    });
    expect(totpLogin.json<{ data: { status: string } }>().data.status).toBe("mfa_required");
    const totpChallenge = totpLogin.json<{ data: { challengeId: string } }>().data.challengeId;
    const totpChallengeCookie = requireCookie(totpLogin, "nom_mfa");
    const totpVerified = await current.app.inject({
      method: "POST", url: "/v1/auth/mfa/verify",
      headers: { ...authHeaders, cookie: `nom_mfa=${totpChallengeCookie}` }, remoteAddress: "127.0.0.31",
      payload: { challengeId: totpChallenge, code: totp.generate() },
    });
    expect(totpVerified.statusCode).toBe(200);
    expect(totpVerified.json<{ data: { permissions: string[]; keyGrant: unknown } }>().data.permissions).toContain("cycle.manage");
    expect(totpVerified.json<{ data: { keyGrant: unknown } }>().data.keyGrant).toBeNull();

    const totpReplayLogin = await current.app.inject({
      method: "POST", url: "/v1/auth/login", headers: authHeaders, remoteAddress: "127.0.0.31",
      payload: { email, password },
    });
    const totpReplayChallenge = totpReplayLogin.json<{ data: { challengeId: string } }>().data.challengeId;
    const totpReplayCookie = requireCookie(totpReplayLogin, "nom_mfa");
    const totpReplay = await current.app.inject({
      method: "POST", url: "/v1/auth/mfa/verify",
      headers: { ...authHeaders, cookie: `nom_mfa=${totpReplayCookie}` }, remoteAddress: "127.0.0.31",
      payload: { challengeId: totpReplayChallenge, code: totp.generate() },
    });
    expect(totpReplay.statusCode).toBe(401);
    expect(apiErrorCode(totpReplay)).toBe("MFA_CODE_INVALID");

    const recoveryLogin = await current.app.inject({
      method: "POST", url: "/v1/auth/login", headers: authHeaders, remoteAddress: "127.0.0.31",
      payload: { email, password },
    });
    const recoveryChallenge = recoveryLogin.json<{ data: { challengeId: string } }>().data.challengeId;
    const recoveryChallengeCookie = requireCookie(recoveryLogin, "nom_mfa");
    const usedRecoveryCode = confirmedData.recoveryCodes[0]!;
    const recovered = await current.app.inject({
      method: "POST", url: "/v1/auth/mfa/verify",
      headers: { ...authHeaders, cookie: `nom_mfa=${recoveryChallengeCookie}` }, remoteAddress: "127.0.0.31",
      payload: { challengeId: recoveryChallenge, recoveryCode: usedRecoveryCode },
    });
    expect(recovered.statusCode).toBe(200);
    expect(recovered.json<{ data: {
      permissions: string[];
      keyGrant: unknown;
      security: { assurance: string; recoveryRestricted: boolean };
    } }>().data).toMatchObject({
      permissions: [],
      keyGrant: null,
      security: { assurance: "recovery_limited", recoveryRestricted: true },
    });

    for (const sessionToken of [enrolledSession, requireCookie(totpVerified, "nom_session")]) {
      const revoked = await current.app.inject({
        method: "GET", url: "/v1/session",
        headers: { ...authHeaders, cookie: `nom_session=${sessionToken}; nom_csrf=${enrolledCsrf}` },
        remoteAddress: "127.0.0.31",
      });
      expect(revoked.statusCode).toBe(401);
    }

    const replayLogin = await current.app.inject({
      method: "POST", url: "/v1/auth/login", headers: authHeaders, remoteAddress: "127.0.0.31",
      payload: { email, password },
    });
    const replayChallenge = replayLogin.json<{ data: { challengeId: string } }>().data.challengeId;
    const replayChallengeCookie = requireCookie(replayLogin, "nom_mfa");
    const recoveryReplay = await current.app.inject({
      method: "POST", url: "/v1/auth/mfa/verify",
      headers: { ...authHeaders, cookie: `nom_mfa=${replayChallengeCookie}` }, remoteAddress: "127.0.0.31",
      payload: { challengeId: replayChallenge, recoveryCode: usedRecoveryCode },
    });
    expect(recoveryReplay.statusCode).toBe(401);
    expect(apiErrorCode(recoveryReplay)).toBe("MFA_CODE_INVALID");

    const recoveryState = await current.control.query<{ active: number; consumed: number; plaintext_hits: number }>(
      `SELECT count(*) FILTER (WHERE consumed_at IS NULL AND revoked_at IS NULL)::int AS active,
              count(*) FILTER (WHERE consumed_at IS NOT NULL)::int AS consumed,
              count(*) FILTER (WHERE code_hash=$2)::int AS plaintext_hits
         FROM mfa_recovery_codes WHERE identity_id=$1`,
      [identity.rows[0]!.id, usedRecoveryCode.replaceAll("-", "")],
    );
    expect(recoveryState.rows[0]).toMatchObject({ active: 9, consumed: 1, plaintext_hits: 0 });
    const secretLeak = await current.control.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM platform_audit_events
        WHERE actor_identity_id=$1
          AND (metadata::text LIKE '%' || $2 || '%' OR metadata::text LIKE '%' || $3 || '%')`,
      [identity.rows[0]!.id, enrollmentData.secret, usedRecoveryCode],
    );
    expect(secretLeak.rows[0]?.count).toBe(0);
  }, 90_000);

  it("accepts a passkey-first invitation without a password when the atomic tenant policy disables passwords", async () => {
    const current = requireFixture(fixture);
    const email = uniqueEmail("passwordless");
    const created = await createInvitation(current, current.scratchManager, {
      email,
      roles: ["AUDITOR"],
      expiresInHours: 24,
    });
    expect(created.statusCode).toBe(201);
    const invitation = created.json<{ data: InvitationCreation }>().data;
    current.invitationIds.push(invitation.invitation.id);

    await current.control.query(
      `INSERT INTO tenant_identity_policies(
         tenant_id,version,enforcement_mode,minimum_aal,privileged_minimum_aal,
         require_user_verification,require_phishing_resistant_for_privileged,
         require_device_bound_for_privileged,require_attestation_for_privileged,
         allow_password,allow_totp_fallback,allow_recovery_codes,allow_synced_passkeys,
         minimum_passkey_count,privileged_minimum_passkey_count,maximum_passkeys,
         maximum_active_sessions,idle_timeout_minutes,absolute_session_minutes,
         step_up_ttl_seconds,action_requirements,changed_by_identity_id
       )
       SELECT $1,1,baseline.enforcement_mode,baseline.minimum_aal,baseline.privileged_minimum_aal,
              baseline.require_user_verification,baseline.require_phishing_resistant_for_privileged,
              baseline.require_device_bound_for_privileged,baseline.require_attestation_for_privileged,
              false,baseline.allow_totp_fallback,baseline.allow_recovery_codes,baseline.allow_synced_passkeys,
              baseline.minimum_passkey_count,baseline.privileged_minimum_passkey_count,baseline.maximum_passkeys,
              baseline.maximum_active_sessions,baseline.idle_timeout_minutes,baseline.absolute_session_minutes,
              baseline.step_up_ttl_seconds,baseline.action_requirements,$2
         FROM identity_policy_baseline baseline
        WHERE baseline.policy_key='global'
       ON CONFLICT (tenant_id) DO UPDATE
         SET version=tenant_identity_policies.version+1,
             allow_password=false,
             changed_by_identity_id=EXCLUDED.changed_by_identity_id,
             updated_at=clock_timestamp()`,
      [current.temporaryTenant.tenantId, current.scratchManager.identityId],
    );

    const accepted = await acceptInvitation(current, {
      token: requireToken(invitation),
      email,
      displayName: "Invitación Passwordless",
    }, "127.0.0.41");
    expect(accepted.statusCode, accepted.body).toBe(201);
    expect(accepted.json<{ data: Record<string, unknown> }>().data).toMatchObject({
      accepted: true,
      signInRequired: false,
      enrollmentRequired: true,
      status: "mfa_enrollment_required",
      permissions: [],
      keyGrant: null,
    });
    expect(requireCookie(accepted, "nom_session")).toBeTruthy();
    expect(requireCookie(accepted, "nom_csrf")).toBeTruthy();

    const identity = await current.control.query<{
      password_hash: string;
      password_provisioned: boolean;
    }>(
      `SELECT identity.password_hash,identity.password_provisioned
         FROM platform_identities identity
         JOIN tenant_invitations invitation ON invitation.acceptance_identity_id=identity.id
        WHERE invitation.id=$1`,
      [invitation.invitation.id],
    );
    expect(identity.rows[0]?.password_hash.startsWith("$argon2id$")).toBe(true);
    expect(identity.rows[0]?.password_provisioned).toBe(false);

    const denied = await current.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: { origin: ORIGIN, "user-agent": USER_AGENT },
      remoteAddress: "127.0.0.41",
      payload: { email, password: strongPassword() },
    });
    const unknown = await current.app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: { origin: ORIGIN, "user-agent": USER_AGENT },
      remoteAddress: "127.0.0.41",
      payload: { email: uniqueEmail("unknown-passwordless"), password: strongPassword() },
    });
    expect(apiErrorCode(denied)).toBe("INVALID_CREDENTIALS");
    expect(samePublicError(denied, unknown)).toBe(true);
  }, 45_000);
});

async function waitForNextTotpStep(): Promise<void> {
  const periodMs = 30_000;
  const currentStep = Math.floor(Date.now() / periodMs);
  const waitMs = ((currentStep + 1) * periodMs) - Date.now() + 25;
  await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
}

interface TestManager {
  readonly identityId: string;
  readonly sessionId: string;
  readonly tenantId: string;
  readonly sessionToken: string;
  readonly csrfToken: string;
}

interface InvitationFixture {
  readonly app: FastifyInstance;
  readonly database: DatabaseRuntime;
  readonly control: Pool;
  readonly demo: Pool;
  readonly scratch: Pool;
  readonly temporaryTenant: TemporaryActiveTenant;
  readonly databaseAdminUrl: string;
  readonly demoManager: TestManager;
  readonly scratchManager: TestManager;
  readonly restrictedManager: TestManager;
  readonly invitationIds: string[];
  readonly invitationRecoveryCookies: Map<string, string>;
}

interface InvitationCreation {
  readonly invitation: { readonly id: string; readonly tenantId: string; readonly email: string; readonly status: string };
  readonly delivery: string;
  readonly acceptanceToken?: string;
  readonly created: boolean;
}

async function createFixture(databaseAdminUrl: string): Promise<InvitationFixture> {
  const control = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE),
    application_name: "nombramientos-ac07-control-admin",
    max: 1,
  });
  let demo: Pool | undefined;
  let scratch: Pool | undefined;
  let temporaryTenant: TemporaryActiveTenant | undefined;
  const demoManager = temporaryManager(DEMO_TENANT_ID);
  let scratchManager: TestManager | undefined;
  const restrictedManager = temporaryManager(DEMO_TENANT_ID);
  let app: FastifyInstance | undefined;
  let database: DatabaseRuntime | undefined;
  try {
    await assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl, control);
    const routes = await control.query<{ id: string; database_name: string; runtime_secret_ref: string }>(
      "SELECT id::text,database_name::text,runtime_secret_ref FROM tenants WHERE id=$1 AND status='active'",
      [DEMO_TENANT_ID],
    );
    const demoRoute = routes.rows[0];
    if (!demoRoute || routes.rowCount !== 1) throw new Error("Expected the active Demo tenant route");
    temporaryTenant = await provisionTemporaryActiveTenant(databaseAdminUrl, control, "ac07");
    demo = new Pool({ connectionString: databaseUrl(databaseAdminUrl, demoRoute.database_name), max: 1 });
    scratch = new Pool({ connectionString: databaseUrl(databaseAdminUrl, temporaryTenant.databaseName), max: 1 });
    scratchManager = temporaryManager(temporaryTenant.tenantId);
    const config = parseApiConfig();
    await insertManager(control, demo, demoManager, "CHURCH_ADMIN", config.authEncryptionKey);
    await insertManager(control, scratch, scratchManager, "CHURCH_ADMIN", config.authEncryptionKey);
    await insertManager(control, demo, restrictedManager, "AUDITOR", config.authEncryptionKey);
    const persistentSecrets = new EncryptedFileSecretProvider(config.secretFile, config.secretMasterKey);
    await temporaryTenant.secrets.putSecret(
      demoRoute.runtime_secret_ref,
      await persistentSecrets.getSecret(demoRoute.runtime_secret_ref),
    );
    database = new DatabaseRuntime({
      control: { connectionString: config.controlDatabaseUrl, application_name: "nombramientos-ac07-api", max: 2, ssl: false },
      secretProvider: temporaryTenant.secrets,
      tenantPoolMax: 1,
      tenantPoolIdleMs: 5_000,
    });
    app = await buildServer({ config, database, logger: false, closeDatabaseOnShutdown: false });
    return {
      app,
      database,
      control,
      demo,
      scratch,
      temporaryTenant,
      databaseAdminUrl,
      demoManager,
      scratchManager,
      restrictedManager,
      invitationIds: [],
      invitationRecoveryCookies: new Map(),
    };
  } catch (error) {
    const cleanupErrors: Error[] = [cleanupStageError("AC-07 fixture setup", error)];
    if (app) {
      const currentApp = app;
      await collectCleanupFailure(cleanupErrors, "AC-07 API close after setup failure", async () => currentApp.close());
    }
    if (database) {
      const currentDatabase = database;
      await collectCleanupFailure(cleanupErrors, "AC-07 runtime close after setup failure", async () => {
        await closePoolOwnerAndConfirmDrained(
          [{ pool: currentDatabase.controlPool, label: "AC-07 runtime control pool" }],
          async () => currentDatabase.close(),
          "AC-07 database runtime close",
        );
      });
    }
    const managers = [demoManager, restrictedManager, ...(scratchManager ? [scratchManager] : [])];
    await collectCleanupFailure(cleanupErrors, "AC-07 emergency row cleanup", async () => {
      await emergencyCleanup(control, demo, scratch, managers);
    });
    if (demo) {
      const currentDemo = demo;
      await collectCleanupFailure(cleanupErrors, "AC-07 Demo pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(currentDemo, "AC-07 Demo admin pool");
      });
    }
    if (scratch) {
      const currentScratch = scratch;
      await collectCleanupFailure(cleanupErrors, "AC-07 scratch pool close after setup failure", async () => {
        await endPoolAndConfirmDrained(currentScratch, "AC-07 scratch admin pool");
      });
    }
    if (temporaryTenant) {
      const currentTemporaryTenant = temporaryTenant;
      await collectCleanupFailure(cleanupErrors, "AC-07 temporary tenant destroy after setup failure", async () => {
        await destroyTemporaryActiveTenant(databaseAdminUrl, control, currentTemporaryTenant);
      });
    }
    await collectCleanupFailure(cleanupErrors, "AC-07 canonical Ozama attestation after setup failure", async () => {
      await assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl, control);
    });
    await collectCleanupFailure(cleanupErrors, "AC-07 control pool close after setup failure", async () => {
      await endPoolAndConfirmDrained(control, "AC-07 control pool");
    });
    throw new AggregateError(cleanupErrors, "AC-07 fixture setup failed closed");
  }
}

async function cleanupFixture(fixture: InvitationFixture): Promise<void> {
  const failures: Error[] = [];
  let runtimeDemoPool: Pool | undefined;
  let runtimeScratchPool: Pool | undefined;
  await collectCleanupFailure(failures, "AC-07 runtime Demo pool lookup", async () => {
    runtimeDemoPool = await fixture.database.tenantPools.getPool(DEMO_TENANT_ID);
  });
  await collectCleanupFailure(failures, "AC-07 runtime scratch pool lookup", async () => {
    runtimeScratchPool = await fixture.database.tenantPools.getPool(fixture.temporaryTenant.tenantId);
  });
  await collectCleanupFailure(failures, "AC-07 API close", async () => fixture.app.close());
  await collectCleanupFailure(failures, "AC-07 database runtime close", async () => {
    await closePoolOwnerAndConfirmDrained(
      [
        { pool: fixture.database.controlPool, label: "AC-07 runtime control pool" },
        ...(runtimeDemoPool ? [{ pool: runtimeDemoPool, label: "AC-07 runtime Demo pool" }] : []),
        ...(runtimeScratchPool ? [{ pool: runtimeScratchPool, label: "AC-07 runtime scratch pool" }] : []),
      ],
      async () => fixture.database.close(),
      "AC-07 database runtime close",
    );
  });
  const managerIds = [
    fixture.demoManager.identityId,
    fixture.scratchManager.identityId,
    fixture.restrictedManager.identityId,
  ];
  let invitationIds = [...fixture.invitationIds];
  let acceptedIdentityIds: string[] = [];
  await collectCleanupFailure(failures, "AC-07 invitation inventory", async () => {
    const invitations = await fixture.control.query<{ id: string; acceptance_identity_id: string | null }>(
      `SELECT id::text,acceptance_identity_id::text
         FROM tenant_invitations
        WHERE created_by_identity_id = ANY($1::uuid[])`,
      [managerIds],
    );
    invitationIds = [...new Set([...invitationIds, ...invitations.rows.map(({ id }) => id)])];
    acceptedIdentityIds = invitations.rows.flatMap(({ acceptance_identity_id }) =>
      acceptance_identity_id ? [acceptance_identity_id] : []);
  });
  const allIdentityIds = [...managerIds, ...acceptedIdentityIds];
  let auditBeforeCleanup: Awaited<ReturnType<typeof invitationAuditSnapshot>> = [];
  let auditAfterCleanup: Awaited<ReturnType<typeof invitationAuditSnapshot>> = [];
  await collectCleanupFailure(failures, "AC-07 audit snapshot before cleanup", async () => {
    auditBeforeCleanup = await invitationAuditSnapshot(fixture.control, invitationIds);
  });
  await collectCleanupFailure(failures, "AC-07 Demo tenant cleanup", async () => {
    await cleanupTenant(fixture.demo, invitationIds, allIdentityIds);
  });
  await collectCleanupFailure(failures, "AC-07 scratch tenant cleanup", async () => {
    await cleanupTenant(fixture.scratch, invitationIds, allIdentityIds);
  });
  await collectCleanupFailure(failures, "AC-07 session cleanup", async () => {
    await fixture.control.query("DELETE FROM auth_sessions WHERE identity_id = ANY($1::uuid[])", [allIdentityIds]);
  });
  await collectCleanupFailure(failures, "AC-07 membership cleanup", async () => {
    await fixture.control.query("DELETE FROM tenant_memberships WHERE identity_id = ANY($1::uuid[])", [allIdentityIds]);
  });
  await collectCleanupFailure(failures, "AC-07 invitation cleanup", async () => {
    await fixture.control.query("DELETE FROM tenant_invitations WHERE created_by_identity_id = ANY($1::uuid[])", [managerIds]);
  });
  await collectCleanupFailure(failures, "AC-07 identity cleanup", async () => {
    await fixture.control.query("DELETE FROM platform_identities WHERE id = ANY($1::uuid[])", [allIdentityIds]);
  });
  await collectCleanupFailure(failures, "AC-07 audit snapshot after cleanup", async () => {
    auditAfterCleanup = await invitationAuditSnapshot(fixture.control, invitationIds);
  });
  await collectCleanupFailure(failures, "AC-07 control residue attestation", async () => {
    const residue = await fixture.control.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM auth_sessions WHERE identity_id = ANY($1::uuid[]))
         + (SELECT count(*) FROM tenant_memberships WHERE identity_id = ANY($1::uuid[]))
         + (SELECT count(*) FROM platform_identities WHERE id = ANY($1::uuid[]))
         + (SELECT count(*) FROM tenant_invitations WHERE created_by_identity_id = ANY($2::uuid[]))
       )::int AS count`,
      [allIdentityIds, managerIds],
    );
    if (residue.rows[0]?.count !== 0) throw new Error("AC-07 control cleanup left residue");
  });
  await collectCleanupFailure(failures, "AC-07 Demo role residue attestation", async () => {
    if (await roleBindingResidue(fixture.demo, invitationIds, allIdentityIds) !== 0) {
      throw new Error("AC-07 Demo role cleanup left residue");
    }
  });
  await collectCleanupFailure(failures, "AC-07 scratch role residue attestation", async () => {
    if (await roleBindingResidue(fixture.scratch, invitationIds, allIdentityIds) !== 0) {
      throw new Error("AC-07 scratch role cleanup left residue");
    }
  });
  if (JSON.stringify(auditAfterCleanup) !== JSON.stringify(auditBeforeCleanup)) {
    failures.push(new Error("AC-07 immutable audit rows changed during cleanup"));
  }
  await collectCleanupFailure(failures, "AC-07 Demo admin pool close", async () => {
    await endPoolAndConfirmDrained(fixture.demo, "AC-07 Demo admin pool");
  });
  await collectCleanupFailure(failures, "AC-07 scratch admin pool close", async () => {
    await endPoolAndConfirmDrained(fixture.scratch, "AC-07 scratch admin pool");
  });
  await collectCleanupFailure(failures, "AC-07 temporary tenant destroy", async () => {
    await destroyTemporaryActiveTenant(fixture.databaseAdminUrl, fixture.control, fixture.temporaryTenant);
  });
  await collectCleanupFailure(failures, "AC-07 canonical Ozama attestation", async () => {
    await assertCanonicalOzamaPendingAndEmpty(fixture.databaseAdminUrl, fixture.control);
  });
  await collectCleanupFailure(failures, "AC-07 control pool close", async () => {
    await endPoolAndConfirmDrained(fixture.control, "AC-07 control pool");
  });
  if (failures.length > 0) throw new AggregateError(failures, "AC-07 fixture cleanup failed closed");
}

async function emergencyCleanup(
  control: Pool,
  demo: Pool | undefined,
  scratch: Pool | undefined,
  managers: readonly TestManager[],
): Promise<void> {
  const ids = managers.map(({ identityId }) => identityId);
  const failures: unknown[] = [];
  const clean = async (work: () => Promise<unknown>): Promise<void> => {
    try {
      await work();
    } catch (error) {
      failures.push(error);
    }
  };
  if (demo) await clean(async () => demo.query("DELETE FROM role_bindings WHERE identity_id = ANY($1::uuid[])", [ids]));
  if (scratch) await clean(async () => scratch.query("DELETE FROM role_bindings WHERE identity_id = ANY($1::uuid[])", [ids]));
  await clean(async () => control.query("DELETE FROM auth_sessions WHERE identity_id = ANY($1::uuid[])", [ids]));
  await clean(async () => control.query("DELETE FROM tenant_memberships WHERE identity_id = ANY($1::uuid[])", [ids]));
  await clean(async () => control.query("DELETE FROM tenant_invitations WHERE created_by_identity_id = ANY($1::uuid[])", [ids]));
  await clean(async () => control.query("DELETE FROM platform_identities WHERE id = ANY($1::uuid[])", [ids]));
  if (failures.length > 0) throw new AggregateError(failures, "AC-07 emergency cleanup was incomplete");
}

async function cleanupTenant(pool: Pool, invitationIds: readonly string[], identityIds: readonly string[]): Promise<void> {
  const failures: unknown[] = [];
  if (invitationIds.length > 0) {
    try {
      await pool.query("DELETE FROM role_bindings WHERE source_invitation_id = ANY($1::uuid[])", [invitationIds]);
    } catch (error) {
      failures.push(error);
    }
  }
  if (identityIds.length > 0) {
    try {
      await pool.query("DELETE FROM role_bindings WHERE identity_id = ANY($1::uuid[])", [identityIds]);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) throw new AggregateError(failures, "AC-07 tenant role cleanup was incomplete");
}

async function insertManager(
  control: Pool,
  tenant: Pool,
  manager: TestManager,
  roleCode: "CHURCH_ADMIN" | "AUDITOR",
  authEncryptionKey: Buffer,
): Promise<void> {
  const email = `ac07-manager-${manager.identityId.replaceAll("-", "")}@invalid.example`;
  const totpSecretCiphertext = encryptServerSecret(randomBytes(20).toString("base64url"), authEncryptionKey);
  await control.query(
    `INSERT INTO platform_identities(
       id,email,normalized_email,display_name,password_hash,mfa_enabled,totp_secret_ciphertext,
       mfa_required,mfa_enrolled_at,status
     ) VALUES (
       $1,$2,$2,'AC-07 temporary manager','AC07_DISABLED_NON_LOGIN_IDENTITY',true,$3,
       true,clock_timestamp(),'active'
     )`,
    [manager.identityId, email, totpSecretCiphertext],
  );
  await control.query(
    "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
    [manager.tenantId, manager.identityId],
  );
  const role = await tenant.query(
    `INSERT INTO role_bindings(identity_id,role_id)
     SELECT $1,id FROM roles WHERE code=$2
     RETURNING identity_id`,
    [manager.identityId, roleCode],
  );
  if (role.rowCount !== 1) throw new Error(`Tenant ${roleCode} role is unavailable`);
  await control.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,user_agent_hash,ip_prefix_hash,
       assurance_level,mfa_verified_at,auth_method,aal,idle_timeout_minutes,idle_expires_at
     ) VALUES (
       $1,$2,$3,$4,$5,clock_timestamp()+interval '15 minutes',$6,$7,
       'mfa',clock_timestamp(),'totp',2,15,clock_timestamp()+interval '15 minutes'
     )`,
    [
      manager.sessionId,
      sha256(manager.sessionToken),
      sha256(manager.csrfToken),
      manager.identityId,
      manager.tenantId,
      sha256(USER_AGENT),
      sha256("127.0.0"),
    ],
  );
}

function temporaryManager(tenantId: string): TestManager {
  return {
    identityId: randomUUID(),
    sessionId: randomUUID(),
    tenantId,
    sessionToken: randomBytes(32).toString("base64url"),
    csrfToken: randomBytes(32).toString("base64url"),
  };
}

async function createInvitation(
  fixture: InvitationFixture,
  manager: TestManager,
  payload: Readonly<Record<string, unknown>>,
  idempotencyKey = randomUUID(),
) {
  return fixture.app.inject({
    method: "POST",
    url: "/v1/invitations",
    headers: { ...managerHeaders(manager), "idempotency-key": idempotencyKey },
    payload,
  });
}

async function insertExpiredInvitationFixture(
  fixture: InvitationFixture,
  manager: TestManager,
  email: string,
): Promise<InvitationCreation> {
  const invitationId = randomUUID();
  const acceptanceToken = randomBytes(32).toString("base64url");
  const normalizedEmail = email.trim().normalize("NFKC").toLocaleLowerCase("en-US");
  const inserted = await fixture.control.query<{ id: string }>(
    `INSERT INTO tenant_invitations(
       id,tenant_id,email,normalized_email,role_codes,token_hash,status,
       idempotency_key,request_hash,created_by_identity_id,created_at,updated_at,expires_at,
       authority_kind,authority_epoch
     ) VALUES (
       $1,$2,$3,$4,ARRAY['AUDITOR']::text[],$5,'pending',
       $6,$7,$8,clock_timestamp()-interval '2 hours',clock_timestamp()-interval '2 hours',
       clock_timestamp()-interval '1 hour','tenant_delegate',0
     )
     RETURNING id::text`,
    [
      invitationId,
      manager.tenantId,
      email,
      normalizedEmail,
      sha256(acceptanceToken),
      randomUUID(),
      sha256(randomBytes(32).toString("base64url")),
      manager.identityId,
    ],
  );
  if (inserted.rows[0]?.id !== invitationId) {
    throw new Error("Expired invitation fixture was not inserted exactly");
  }
  return {
    invitation: { id: invitationId, tenantId: manager.tenantId, email, status: "pending" },
    delivery: "local_one_time_token",
    acceptanceToken,
    created: true,
  };
}

async function revokeInvitation(
  fixture: InvitationFixture,
  manager: TestManager,
  invitationId: string,
  reasonCode?: string,
) {
  return fixture.app.inject({
    method: "POST",
    url: `/v1/invitations/${invitationId}/revoke`,
    headers: managerHeaders(manager),
    payload: reasonCode ? { reasonCode } : {},
  });
}

async function acceptInvitation(
  fixture: InvitationFixture,
  payload: Readonly<Record<string, unknown>>,
  remoteAddress: string,
) {
  const existingCookie = fixture.invitationRecoveryCookies.get(remoteAddress);
  const prepared = await fixture.app.inject({
    method: "POST",
    url: "/v1/invitations/recovery-context",
    headers: {
      origin: ORIGIN,
      "user-agent": USER_AGENT,
      ...(existingCookie ? { cookie: existingCookie } : {}),
    },
    remoteAddress,
    payload: {},
  });
  if (prepared.statusCode !== 200) {
    throw new Error(`Invitation recovery context preparation failed: ${prepared.statusCode} ${prepared.body}`);
  }
  const recoveryCookies = prepared.cookies
    .filter(({ name }) => name.startsWith(INVITATION_RECOVERY_COOKIE_PREFIX))
    .map(({ name, value }) => `${name}=${value}`);
  if (recoveryCookies.length === 0) throw new Error("Invitation recovery context cookie was not returned");
  const cookie = recoveryCookies.join("; ");
  fixture.invitationRecoveryCookies.set(remoteAddress, cookie);
  return fixture.app.inject({
    method: "POST",
    url: "/v1/invitations/accept",
    headers: { origin: ORIGIN, "user-agent": USER_AGENT, cookie },
    remoteAddress,
    payload,
  });
}

async function acceptInvitationWithoutRecoveryContext(
  fixture: InvitationFixture,
  payload: Readonly<Record<string, unknown>>,
  remoteAddress: string,
) {
  return fixture.app.inject({
    method: "POST",
    url: "/v1/invitations/accept",
    headers: { origin: ORIGIN, "user-agent": USER_AGENT },
    remoteAddress,
    payload,
  });
}

function managerHeaders(manager: TestManager): Record<string, string> {
  return {
    origin: ORIGIN,
    "user-agent": USER_AGENT,
    cookie: `nom_session=${manager.sessionToken}; nom_csrf=${manager.csrfToken}`,
    "x-csrf-token": manager.csrfToken,
  };
}

function samePublicError(left: { statusCode: number; json<T>(): T }, right: { statusCode: number; json<T>(): T }): boolean {
  const leftError = left.json<{ error?: { code?: string; message?: string } }>().error;
  const rightError = right.json<{ error?: { code?: string; message?: string } }>().error;
  return left.statusCode === right.statusCode
    && leftError?.code === rightError?.code
    && leftError?.message === rightError?.message;
}

function apiErrorCode(response: { json<T>(): T }): string | undefined {
  return response.json<{ error?: { code?: string } }>().error?.code;
}

function requireToken(data: InvitationCreation): string {
  if (!data.acceptanceToken) throw new Error("The invitation did not return its one-time local token");
  return data.acceptanceToken;
}

function requireCookie(response: { cookies: Array<{ name: string; value: string }> }, name: string): string {
  const value = response.cookies.find((cookie) => cookie.name === name)?.value;
  if (!value) throw new Error(`Expected cookie ${name}`);
  return value;
}

function uniqueEmail(label: string): string {
  return `ac07-${label}-${randomUUID()}@invalid.example`;
}

function strongPassword(): string {
  return `Z9!a-${randomBytes(24).toString("base64url")}`;
}

function requireFixture(value: InvitationFixture | undefined): InvitationFixture {
  if (!value) throw new Error("The AC-07 fixture is unavailable");
  return value;
}

async function roleBindingResidue(
  pool: Pool,
  invitationIds: readonly string[],
  identityIds: readonly string[],
): Promise<number> {
  const result = await pool.query<{ count: number }>(
    `SELECT count(*)::int AS count
       FROM role_bindings
      WHERE source_invitation_id = ANY($1::uuid[])
         OR identity_id = ANY($2::uuid[])`,
    [invitationIds, identityIds],
  );
  const count = result.rows[0]?.count;
  if (count === undefined) throw new Error("Role binding residue count was not returned");
  return count;
}

async function invitationAuditSnapshot(
  pool: Pool,
  invitationIds: readonly string[],
): Promise<readonly { sequence: string; actor_identity_id: string | null; tenant_id: string | null; event_hash: string }[]> {
  if (invitationIds.length === 0) return [];
  const result = await pool.query<{
    sequence: string;
    actor_identity_id: string | null;
    tenant_id: string | null;
    event_hash: string;
  }>(
    `SELECT sequence::text,actor_identity_id::text,tenant_id::text,event_hash
       FROM platform_audit_events
      WHERE entity_type='tenant_invitation' AND entity_id = ANY($1::text[])
      ORDER BY platform_audit_events.sequence`,
    [invitationIds],
  );
  return result.rows;
}

function discoverLocalAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const value: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (value && typeof value === "object" && "DATABASE_ADMIN_URL" in value) {
        const configured = value.DATABASE_ADMIN_URL;
        if (typeof configured === "string") candidate = configured;
      }
    }
    if (!candidate) return undefined;
    return assertExactWorkspaceAdminUrl(candidate);
  } catch {
    return undefined;
  }
}

async function canReachInvitationTargets(databaseAdminUrl: string): Promise<boolean> {
  const pools: Pool[] = [];
  try {
    const control = new Pool({
      connectionString: databaseUrl(databaseAdminUrl, CONTROL_DATABASE),
      application_name: "nombramientos-ac07-prerequisite",
      connectionTimeoutMillis: 1_500,
      max: 1,
    });
    pools.push(control);
    const version = await control.query<{ version: number }>(
      "SELECT current_setting('server_version_num')::int AS version",
    );
    if ((version.rows[0]?.version ?? 0) < 180_000) return false;
    const migration = await control.query(
      "SELECT 1 FROM schema_migrations WHERE name='002_tenant_invitations.sql'",
    );
    if (migration.rowCount !== 1) return false;
    const tenants = await control.query<{ id: string; kind: string; status: string; database_name: string }>(
      "SELECT id::text,kind,status,database_name::text FROM tenants WHERE id = ANY($1::uuid[])",
      [[DEMO_TENANT_ID, OZAMA_TENANT_ID]],
    );
    const demo = tenants.rows.find(({ id }) => id === DEMO_TENANT_ID);
    const ozama = tenants.rows.find(({ id }) => id === OZAMA_TENANT_ID);
    if (!demo || demo.kind !== "demo" || demo.status !== "active"
      || !ozama || ozama.kind !== "real" || ozama.status !== "provisioning"
      || tenants.rowCount !== 2) return false;
    for (const tenant of tenants.rows) {
      const pool = new Pool({
        connectionString: databaseUrl(databaseAdminUrl, tenant.database_name),
        connectionTimeoutMillis: 1_500,
        max: 1,
      });
      pools.push(pool);
      const ready = await pool.query<{ tenant_id: string; migration: boolean }>(
        `SELECT settings.tenant_id::text,
                EXISTS(SELECT 1 FROM schema_migrations WHERE name='005_invitation_roles.sql') AS migration
           FROM tenant_settings settings WHERE singleton=true`,
      );
      if (ready.rows[0]?.tenant_id !== tenant.id || ready.rows[0]?.migration !== true) return false;
    }
    await assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl, control);
    return true;
  } catch {
    return false;
  } finally {
    await closePoolOwnerAndConfirmDrained(
      pools.map((pool, index) => ({ pool, label: `AC-07 reachability pool ${index + 1}` })),
      async () => Promise.all(pools.map(async (pool) => pool.end())),
      "AC-07 reachability pool close",
    );
  }
}

async function assertCanonicalOzamaPendingAndEmpty(databaseAdminUrl: string, control: Pool): Promise<void> {
  const state = await control.query<{
    status: string; provisioning_state: string; database_name: string;
    invitations: number; memberships: number;
  }>(
    `SELECT tenant.status,job.state AS provisioning_state,tenant.database_name::text,
            (SELECT count(*)::int FROM tenant_invitations invitation WHERE invitation.tenant_id=tenant.id) AS invitations,
            (SELECT count(*)::int FROM tenant_memberships membership WHERE membership.tenant_id=tenant.id) AS memberships
       FROM tenants tenant
       JOIN provisioning_jobs job ON job.tenant_id=tenant.id
      WHERE tenant.id=$1`,
    [OZAMA_TENANT_ID],
  );
  const current = state.rows[0];
  if (!current
    || current.status !== "provisioning"
    || current.provisioning_state !== "pending_activation"
    || current.invitations !== 0
    || current.memberships !== 0) {
    throw new Error("Canonical Ozama control state is not untouched and pending activation");
  }
  const ozama = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, current.database_name),
    application_name: "nombramientos-ac07-ozama-readonly-guard",
    max: 1,
  });
  try {
    const operational = await ozama.query<{ count: number }>(
      `SELECT (
         (SELECT count(*) FROM members)
         + (SELECT count(*) FROM role_bindings)
         + (SELECT count(*) FROM election_cycles)
         + (SELECT count(*) FROM committee_memberships)
         + (SELECT count(*) FROM rounds)
         + (SELECT count(*) FROM encrypted_submissions)
         + (SELECT count(*) FROM assignments)
         + (SELECT count(*) FROM report_versions)
         + (SELECT count(*) FROM idempotency_records)
         + (SELECT count(*) FROM outbox_events)
         + (SELECT count(*) FROM audit_events)
       )::int AS count`,
    );
    if (operational.rows[0]?.count !== 0) {
      throw new Error("Canonical Ozama gained operational rows during AC-07");
    }
  } finally {
    await endPoolAndConfirmDrained(ozama, "AC-07 Ozama attestation pool");
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(databaseName)) {
    throw new Error("Refusing an invalid local PostgreSQL database name");
  }
  const value = new URL(databaseAdminUrl);
  value.pathname = `/${databaseName}`;
  return value.toString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
