import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { catalogPackage2025 } from "@nombramientos/catalog";
import { DatabaseRuntime, EncryptedFileSecretProvider } from "@nombramientos/database";
import * as OTPAuth from "otpauth";
import { describe, expect, it } from "vitest";
import { parseApiConfig } from "../src/config.js";
import { buildServer } from "../src/server.js";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const accessFile = path.join(workspaceRoot, "packages", "database", ".local", "demo-access.json");
const requireLiveIntegration = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const liveReady = existsSync(accessFile) && await canReachControlDatabase();
if (requireLiveIntegration && !liveReady) {
  throw new Error(
    "NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION=true requires a seeded demo access file and reachable control PostgreSQL database",
  );
}
const live = liveReady ? describe : describe.skip;

live("live local API contract", () => {
  it("authenticates with bound MFA and serves persisted tenant data without preference leakage", async () => {
    const config = parseApiConfig();
    const database = new DatabaseRuntime({
      control: { connectionString: config.controlDatabaseUrl, application_name: "nombramientos-api-live-test", max: 2, ssl: false },
      secretProvider: new EncryptedFileSecretProvider(config.secretFile, config.secretMasterKey),
      tenantPoolMax: 1,
      tenantPoolIdleMs: 5_000,
    });
    const app = await buildServer({ config, database, logger: false });
    const access = JSON.parse(readFileSync(accessFile, "utf8")) as {
      email: string; password: string; totpEnrollmentUri: string;
    };
    const headers = { origin: "http://localhost:3000", "user-agent": "nombramientos-live-contract-test" };
    try {
      await waitForUnusedTotpStep(database, access.email);
      const login = await app.inject({
        method: "POST",
        url: "/v1/auth/login",
        headers,
        payload: { email: access.email, password: access.password },
      });
      expect(login.statusCode).toBe(200);
      const loginData = login.json<{ data: { status: string; challengeId: string } }>().data;
      expect(loginData.status).toBe("mfa_required");
      const mfa = login.cookies.find(({ name }) => name === "nom_mfa");
      expect(mfa?.httpOnly).toBe(true);

      const enrollment = new URL(access.totpEnrollmentUri);
      const secret = enrollment.searchParams.get("secret");
      if (!secret || !mfa) throw new Error("Local demo access material is incomplete");
      const totp = new OTPAuth.TOTP({
        secret: OTPAuth.Secret.fromBase32(secret),
        algorithm: enrollment.searchParams.get("algorithm") ?? "SHA1",
        digits: Number(enrollment.searchParams.get("digits") ?? "6"),
        period: Number(enrollment.searchParams.get("period") ?? "30"),
      });
      const verified = await app.inject({
        method: "POST",
        url: "/v1/auth/mfa/verify",
        headers: { ...headers, cookie: `nom_mfa=${mfa.value}` },
        payload: { challengeId: loginData.challengeId, code: totp.generate() },
      });
      expect(verified.statusCode).toBe(200);
      const sessionCookie = verified.cookies.find(({ name }) => name === "nom_session");
      const csrfCookie = verified.cookies.find(({ name }) => name === "nom_csrf");
      expect(sessionCookie?.httpOnly).toBe(true);
      expect(csrfCookie?.value).toBeTruthy();
      if (!sessionCookie || !csrfCookie) throw new Error("Session cookies were not issued");
      const cookie = `nom_session=${sessionCookie.value}; nom_csrf=${csrfCookie.value}`;

      const session = await app.inject({ method: "GET", url: "/v1/session", headers: { ...headers, cookie } });
      expect(session.statusCode).toBe(200);
      const sessionPayload = session.json<{
        data: { authenticated: boolean; tenant: { kind: string; timezone: string }; permissions: string[]; csrfToken: string; expiresAt: string };
        meta: { requestId: string };
      }>();
      const sessionData = sessionPayload.data;
      expect(sessionData.authenticated).toBe(true);
      expect(sessionData.tenant.kind).toBe("demo");
      expect(sessionData.tenant.timezone).toBe("America/Santo_Domingo");
      expect(sessionData.csrfToken).toBe(csrfCookie.value);
      expect(sessionData.permissions).toContain("member.manage");
      expect(sessionData.permissions).toContain("proposal.submit");
      expect(sessionData.permissions).not.toContain("round.submit");
      expect(new Date(sessionData.expiresAt).getTime()).toBeGreaterThan(Date.now());
      expect(session.headers["x-request-id"]).toBe(sessionPayload.meta.requestId);

      const [dashboard, members, catalog, activeRound] = await Promise.all([
        app.inject({ method: "GET", url: "/v1/dashboard", headers: { ...headers, cookie } }),
        app.inject({ method: "GET", url: "/v1/members", headers: { ...headers, cookie } }),
        app.inject({ method: "GET", url: "/v1/catalog", headers: { ...headers, cookie } }),
        app.inject({ method: "GET", url: "/v1/rounds/active", headers: { ...headers, cookie } }),
      ]);
      expect([dashboard.statusCode, members.statusCode, catalog.statusCode, activeRound.statusCode]).toEqual([200, 200, 200, 200]);
      const memberData = members.json<{ data: { items: Array<Record<string, unknown>>; total: number } }>().data;
      expect(memberData.total).toBe(180);
      expect(memberData.items[0]).toMatchObject({ archived: false, currentResponsibilities: 3 });
      expect(memberData.items[0]).toHaveProperty("shortId");
      expect(memberData.items[0]).toHaveProperty("displayEnvelope");
      const firstMember = memberData.items[0] as {
        id: string;
        version: number;
        displayEnvelope: TestEnvelope;
      };
      const secondMember = memberData.items[1] as { id: string };
      const crossMemberReplay = await app.inject({
        method: "PATCH",
        url: `/v1/members/${secondMember.id}`,
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:cross-member-replay"),
        },
        payload: {
          expectedVersion: 1,
          displayEnvelope: firstMember.displayEnvelope,
          displayContentHash: envelopeContentHash(firstMember.displayEnvelope),
        },
      });
      expect(crossMemberReplay.statusCode).toBe(409);
      expect(crossMemberReplay.json<{ error: { code: string } }>().error.code).toBe("ENVELOPE_CONTEXT_MISMATCH");

      const corruptedEnvelope = {
        ...firstMember.displayEnvelope,
        ciphertext: `${firstMember.displayEnvelope.ciphertext}A`,
      };
      const corruptedMemberUpdate = await app.inject({
        method: "PATCH",
        url: `/v1/members/${firstMember.id}`,
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:corrupted-member-envelope"),
        },
        payload: {
          expectedVersion: firstMember.version,
          displayEnvelope: corruptedEnvelope,
          displayContentHash: envelopeContentHash(firstMember.displayEnvelope),
        },
      });
      expect(corruptedMemberUpdate.statusCode).toBe(400);
      expect(corruptedMemberUpdate.json<{ error: { code: string } }>().error.code).toBe("CONTENT_HASH_MISMATCH");

      const staleKeyEnvelope = { ...firstMember.displayEnvelope, keyId: "stale-tenant-key-material" };
      const staleKeyUpdate = await app.inject({
        method: "PATCH",
        url: `/v1/members/${firstMember.id}`,
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:stale-member-key"),
        },
        payload: {
          expectedVersion: firstMember.version,
          displayEnvelope: staleKeyEnvelope,
          displayContentHash: envelopeContentHash(staleKeyEnvelope),
        },
      });
      expect(staleKeyUpdate.statusCode).toBe(409);
      expect(staleKeyUpdate.json<{ error: { code: string } }>().error.code).toBe("ENVELOPE_KEY_MISMATCH");
      const catalogData = catalog.json<{ data: {
        departments: Array<{ canonicalCode: string; localExtension: boolean }>;
        offices: Array<{ canonicalCode: string; localExtension: boolean }>;
        normativeVersion: string;
      } }>().data;
      expect(catalogData.departments.filter(({ localExtension }) => !localExtension)).toHaveLength(
        catalogPackage2025.departments.length,
      );
      expect(catalogData.offices.filter(({ localExtension }) => !localExtension)).toHaveLength(
        catalogPackage2025.offices.length,
      );
      expect(catalogData.departments.every(({ canonicalCode }) => canonicalCode.length > 0)).toBe(true);
      expect(catalogData.offices.every(({ canonicalCode }) => canonicalCode.length > 0)).toBe(true);
      expect(catalogData.normativeVersion).not.toBe("unknown");
      const roundData = activeRound.json<{ data: { round: { phase: string; officeName: string }; participation: Record<string, unknown> } }>().data;
      expect(roundData.round.phase).toBe("PROPUESTAS_ABIERTAS");
      expect(typeof roundData.round.officeName).toBe("string");
      expect(roundData.participation).not.toHaveProperty("abstentions");
      const activeRoundId = activeRound.json<{ data: { round: { id: string } } }>().data.round.id;
      const activeReceipt = await app.inject({
        method: "GET",
        url: `/v1/rounds/${activeRoundId}/submissions/me`,
        headers: { ...headers, cookie },
      });
      expect([200, 404]).toContain(activeReceipt.statusCode);
      if (activeReceipt.statusCode === 404) {
        expect(activeReceipt.json<{ error: { code: string } }>().error.code).toBe("SUBMISSION_NOT_FOUND");
      } else {
        expect(activeReceipt.json<{ data: Record<string, unknown> }>().data).toMatchObject({
          roundId: activeRoundId,
          status: "received",
        });
        expect(activeReceipt.json<{ data: Record<string, unknown> }>().data).not.toHaveProperty("envelope");
      }
      const completedRoundId = fixtureUuid("round:reference:round-v01");
      const recoveredReceipt = await app.inject({
        method: "GET",
        url: `/v1/rounds/${completedRoundId}/submissions/me`,
        headers: { ...headers, cookie },
      });
      expect(recoveredReceipt.statusCode).toBe(200);
      expect(recoveredReceipt.json<{ data: Record<string, unknown> }>().data).toMatchObject({
        roundId: completedRoundId,
        status: "received",
      });
      expect(recoveredReceipt.json<{ data: Record<string, unknown> }>().data).not.toHaveProperty("envelope");

      const blockedRotation = await app.inject({
        method: "POST",
        url: "/v1/devices/rotate",
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:blocked-device-rotation"),
        },
        payload: {
          expectedVersion: 1,
          deviceId: fixtureUuid("device:blocked-rotation"),
          tenantKeyId: "tenant-key-v2-disabled",
          version: 2,
          kdf: {
            name: "PBKDF2",
            salt: Buffer.alloc(16, 1).toString("base64url"),
            iterations: 210_000,
            hash: "SHA-256",
          },
          wrap: {
            algorithm: "AES-GCM",
            iv: Buffer.alloc(12, 2).toString("base64url"),
            ciphertext: Buffer.alloc(32, 3).toString("base64url"),
            aad: Buffer.from("step-up-required").toString("base64url"),
          },
        },
      });
      expect(blockedRotation.statusCode).toBe(428);
      expect(blockedRotation.json<{ error: { code: string } }>().error.code).toBe("RECOVERY_STEP_UP_REQUIRED");

      const audit = await app.inject({ method: "GET", url: "/v1/audit", headers: { ...headers, cookie } });
      expect(audit.statusCode).toBe(200);
      const auditData = audit.json<{ data: { verified: boolean; items: Array<{ action: string }> } }>().data;
      expect(auditData.verified).toBe(true);
      expect(auditData.items.some(({ action }) => action === "device-key.rotate.step-up-required")).toBe(true);

      const unknownReport = await app.inject({
        method: "POST",
        url: "/v1/reports/generate",
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:unknown-report-type"),
        },
        payload: {
          reportType: "invented_report",
          audience: "committee",
          locale: "es",
          format: "pdf",
          filters: { snapshotSha256: `sha256:${"0".repeat(64)}`, snapshotAt: "2026-09-11T00:00:00.000Z" },
        },
      });
      expect(unknownReport.statusCode).toBe(400);
      expect(unknownReport.json<{ error: { code: string } }>().error.code).toBe("VALIDATION_ERROR");

      const reportAudienceLeak = await app.inject({
        method: "POST",
        url: "/v1/reports/generate",
        headers: {
          ...headers,
          cookie,
          "x-csrf-token": csrfCookie.value,
          "idempotency-key": fixtureUuid("request:internal-report-church-audience"),
        },
        payload: {
          reportType: "office_round",
          audience: "church",
          locale: "es",
          format: "pdf",
          filters: { snapshotSha256: `sha256:${"0".repeat(64)}`, snapshotAt: "2026-09-11T00:00:00.000Z" },
        },
      });
      expect(reportAudienceLeak.statusCode).toBe(400);
      expect(reportAudienceLeak.json<{ error: { code: string } }>().error.code).toBe("REPORT_AUDIENCE_INVALID");

      // A changed browser context is retained as explicit session risk instead
      // of destroying the session. Keep this probe after the mutation contracts
      // above because elevated risk intentionally requires fresh WebAuthn for
      // subsequent sensitive operations.
      const reboundFromAnotherUserAgent = await app.inject({
        method: "GET",
        url: "/v1/session",
        headers: { ...headers, "user-agent": "different-client-session-context", cookie },
      });
      expect(reboundFromAnotherUserAgent.statusCode).toBe(200);
      const reboundPayload = reboundFromAnotherUserAgent.json<{
        data: { security: { risk: {
          elevated: boolean;
          userAgentContextChanged: boolean;
          ipContextChanged: boolean;
        } } };
        meta: { requestId: string };
      }>();
      expect(reboundPayload.data.security.risk).toEqual({
        elevated: true,
        userAgentContextChanged: true,
        ipContextChanged: false,
      });
      expect(reboundFromAnotherUserAgent.headers["x-request-id"]).toBe(reboundPayload.meta.requestId);

      const logout = await app.inject({
        method: "POST",
        url: "/v1/auth/logout",
        headers: { ...headers, cookie, "x-csrf-token": csrfCookie.value },
        payload: {},
      });
      expect(logout.statusCode).toBe(200);
      expect(logout.json<{ data: { loggedOut: boolean } }>().data.loggedOut).toBe(true);
    } finally {
      await app.close();
    }
  }, 65_000);
});

function fixtureUuid(label: string): string {
  const raw = createHash("sha256").update(`nombramientos-demo:${label}`).digest("hex").slice(0, 32).split("");
  raw[12] = "4";
  raw[16] = "8";
  const hex = raw.join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface TestEnvelope {
  readonly algorithm: string;
  readonly keyId: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly aad: string;
}

function envelopeContentHash(envelope: TestEnvelope): string {
  const canonical = JSON.stringify({
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    aad: envelope.aad,
  });
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

async function waitForUnusedTotpStep(database: DatabaseRuntime, email: string): Promise<void> {
  const normalizedEmail = email.trim().normalize("NFKC").toLocaleLowerCase("en-US");
  const result = await database.controlPool.query<{ last_step: string | null }>(
    "SELECT mfa_last_used_step::text AS last_step FROM platform_identities WHERE normalized_email=$1",
    [normalizedEmail],
  );
  if (result.rowCount !== 1) throw new Error("Local demo MFA identity is unavailable");
  const lastStepText = result.rows[0]?.last_step;
  if (lastStepText === null || lastStepText === undefined) return;

  const periodMs = 30_000;
  const currentStep = BigInt(Math.floor(Date.now() / periodMs));
  const lastStep = BigInt(lastStepText);
  if (lastStep < currentStep) return;
  if (lastStep > currentStep) throw new Error("Local demo MFA counter is ahead of the system clock");

  // The real fixture is intentionally persistent and TOTP replay protection is
  // global to its identity. A repeated verification inside the same time step
  // must wait for a genuinely new code rather than resetting production state.
  const nextStepAt = (Number(lastStep) + 1) * periodMs;
  const waitMs = nextStepAt - Date.now() + 50;
  if (waitMs < 1 || waitMs > periodMs + 50) throw new Error("Local demo MFA wait is outside its bounded period");
  await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
}

async function canReachControlDatabase(): Promise<boolean> {
  try {
    const config = parseApiConfig();
    const database = new DatabaseRuntime({
      control: {
        connectionString: config.controlDatabaseUrl,
        application_name: "nombramientos-api-live-prerequisite",
        max: 1,
        connectionTimeoutMillis: 1_500,
        ssl: false,
      },
      secretProvider: { getSecret: async () => { throw new Error("Tenant secret lookup is not used by the prerequisite check"); } },
      tenantPoolMax: 1,
      tenantPoolIdleMs: 1_000,
    });
    try {
      await database.controlPool.query("SELECT 1");
      return true;
    } finally {
      await database.close();
    }
  } catch {
    return false;
  }
}
