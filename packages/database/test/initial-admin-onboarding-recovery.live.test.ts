import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { assertWorkspacePostgresUrl } from "../scripts/script-config.js";
import { EnterpriseAuthStore, EnterpriseAuthStoreError } from "../src/enterprise-auth-store.js";
import {
  InitialAdminOnboardingRecoveryStore,
  type InitialAdminRecoverySource,
} from "../src/initial-admin-onboarding-recovery-store.js";
import { MfaStore } from "../src/mfa-store.js";
import { cleanupTemporaryDatabases, runWithCleanup } from "./live-database-cleanup.js";

const WORKSPACE_PORT = 55_432;
// Applying 26 DDL-heavy control migrations is intentionally isolated, but a
// full-suite run may contend for PostgreSQL CPU and catalog locks. Thirty
// seconds leaves bounded scheduling headroom without masking a stalled apply.
const CONTROL_MIGRATION_APPLY_TIMEOUT_MS = 30_000;
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDirectory = path.join(packageRoot, "migrations", "control");
const installFile = path.join(packageRoot, ".local", "install.json");
const requireLive = process.env["NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION"] === "true";
const adminUrl = discoverAdminUrl();
const reachable = adminUrl ? await canReachWorkspace(adminUrl) : false;
const RECOVERY_RUNTIME_SIGNATURES = [
  "list_initial_admin_onboarding_recovery_candidates(uuid,uuid,uuid,integer)",
  "expire_stale_initial_admin_onboarding_recoveries(uuid,uuid,uuid,uuid)",
  "list_initial_admin_onboarding_recoveries(uuid,uuid,uuid,text,timestamptz,uuid,integer)",
  "get_initial_admin_onboarding_recovery_approval_context(uuid,uuid,uuid)",
  "get_initial_admin_onboarding_recovery_summary(uuid,uuid,uuid)",
  "request_initial_admin_onboarding_recovery(uuid,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,uuid,text,text,text,timestamptz,uuid)",
  "approve_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,timestamptz,text,text,uuid)",
  "redeem_initial_admin_onboarding_recovery(uuid,text,text[],uuid,text,text,timestamptz,text,text,uuid)",
  "revoke_initial_admin_onboarding_recovery(uuid,integer,uuid,uuid,uuid,uuid,integer,bigint,integer,uuid,uuid,text,text,text,uuid)",
  "authorize_initial_admin_recovery_factor_transaction(uuid,uuid)",
  "finalize_initial_admin_onboarding_recovery(uuid,uuid,uuid)",
] as const;

if (requireLive && !reachable) {
  throw new Error("Initial-admin recovery tests require PostgreSQL 18 on loopback port 55432");
}

const live = reachable ? describe.sequential : describe.skip;

live("governed initial-admin onboarding recovery", () => {
  it("applies every control migration through 026 in an isolated UUID database", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const result = await database.query<{
        recovery_table: string | null;
        queue_function: string | null;
        finalizer: string | null;
      }>(`SELECT
        to_regclass('public.initial_admin_onboarding_recoveries')::text AS recovery_table,
        to_regprocedure('public.list_initial_admin_onboarding_recoveries(uuid,uuid,uuid,text,timestamp with time zone,uuid,integer)')::text AS queue_function,
        to_regprocedure('public.finalize_initial_admin_onboarding_recovery(uuid,uuid,uuid)')::text AS finalizer`);
      expect(result.rows[0]?.recovery_table).toBe("initial_admin_onboarding_recoveries");
      expect(result.rows[0]?.queue_function).toContain("list_initial_admin_onboarding_recoveries");
      expect(result.rows[0]?.finalizer).toContain("finalize_initial_admin_onboarding_recovery");
    });
  }, CONTROL_MIGRATION_APPLY_TIMEOUT_MS);

  it("rotates accepted invitation enrollment only for the exact recovery context", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const fixture = await createInvitationEnrollmentRecoveryFixture(database);
      const runtimeRole = `nom_inv_recovery_runtime_${randomBytes(6).toString("hex")}`;
      const client = await database.connect();
      const recover = (input: { token: string; recoveryProof: string; sessionId: string }) => client.query<{
        recovered: boolean;
        identity_id: string | null;
        tenant_id: string | null;
        session_expires_at: Date | null;
      }>(
        `SELECT * FROM recover_tenant_invitation_enrollment_session(
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
         )`,
        [
          fixture.invitationId,
          input.token,
          input.recoveryProof,
          fixture.normalizedEmail,
          input.sessionId,
          sha256(`session-token-${input.sessionId}`),
          sha256(`session-csrf-${input.sessionId}`),
          futureMinutes(10),
          sha256("recovery-user-agent"),
          sha256("recovery-ip-prefix"),
        ],
      );
      try {
        await executeClientFormatted(
          client,
          "SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', $1::text) AS sql",
          [runtimeRole],
        );
        await executeClientFormatted(
          client,
          "SELECT format('GRANT USAGE ON SCHEMA public TO %I', $1::text) AS sql",
          [runtimeRole],
        );
        await executeClientFormatted(client, "SELECT format('SET ROLE %I', $1::text) AS sql", [runtimeRole]);
        await expectSqlState(recover({
          token: fixture.token,
          recoveryProof: fixture.recoveryProof,
          sessionId: randomUUID(),
        }), "42501");
        await client.query("RESET ROLE");
        await executeClientFormatted(
          client,
          `SELECT format(
             'GRANT EXECUTE ON FUNCTION recover_tenant_invitation_enrollment_session(uuid,text,text,text,uuid,text,text,timestamptz,text,text) TO %I',
             $1::text
           ) AS sql`,
          [runtimeRole],
        );
        await executeClientFormatted(client, "SELECT format('SET ROLE %I', $1::text) AS sql", [runtimeRole]);

        const rotatedSessionId = randomUUID();
        const recovered = await recover({
          token: fixture.token,
          recoveryProof: fixture.recoveryProof,
          sessionId: rotatedSessionId,
        });
        expect(recovered.rows[0]).toMatchObject({
          recovered: true,
          identity_id: fixture.identityId,
          tenant_id: fixture.tenantId,
        });
        expect(recovered.rows[0]?.session_expires_at).toBeInstanceOf(Date);

        const crossContext = await recover({
          token: fixture.token,
          recoveryProof: randomToken(),
          sessionId: randomUUID(),
        });
        const unknown = await recover({
          token: randomToken(),
          recoveryProof: fixture.recoveryProof,
          sessionId: randomUUID(),
        });
        expect(crossContext.rows).toEqual(unknown.rows);
        expect(crossContext.rows).toEqual([{
          recovered: false,
          identity_id: null,
          tenant_id: null,
          session_expires_at: null,
        }]);
        await client.query("RESET ROLE");

        const sessions = await client.query<{
          id: string;
          enrollment_source: string | null;
          revoked: boolean;
        }>(
          `SELECT id::text,enrollment_source,revoked_at IS NOT NULL AS revoked
             FROM auth_sessions
            WHERE identity_id=$1
            ORDER BY id`,
          [fixture.identityId],
        );
        expect(sessions.rows).toEqual(expect.arrayContaining([
          { id: fixture.originalEnrollmentSessionId, enrollment_source: "invitation", revoked: true },
          { id: fixture.passwordSessionId, enrollment_source: null, revoked: false },
          { id: rotatedSessionId, enrollment_source: "invitation", revoked: false },
        ]));
        expect(sessions.rows).toHaveLength(3);
      } finally {
        await client.query("RESET ROLE").catch(() => undefined);
        await executeClientFormatted(
          client,
          "SELECT format('DROP OWNED BY %I', $1::text) AS sql",
          [runtimeRole],
        ).catch(() => undefined);
        await executeClientFormatted(
          client,
          "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql",
          [runtimeRole],
        ).catch(() => undefined);
        client.release();
      }
    });
  }, 60_000);

  it("enforces the recovery runtime ACL against base verifiers and worker-only delivery transitions", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const fixture = await createRecoveryFixture(database, "runtime-acl");
      const pending = await requestRecovery(database, fixture, "runtime-acl");
      const role = `nom_rec_runtime_${randomBytes(6).toString("hex")}`;
      const client = await database.connect();
      try {
        await executeClientFormatted(
          client,
          "SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', $1::text) AS sql",
          [role],
        );
        await executeClientFormatted(
          client,
          "SELECT format('GRANT USAGE ON SCHEMA public TO %I', $1::text) AS sql",
          [role],
        );
        for (const signature of RECOVERY_RUNTIME_SIGNATURES) {
          await executeClientFormatted(
            client,
            "SELECT format('GRANT EXECUTE ON FUNCTION %s TO %I', $1::text, $2::text) AS sql",
            [signature, role],
          );
        }
        await executeClientFormatted(
          client,
          "SELECT format('SET ROLE %I', $1::text) AS sql",
          [role],
        );
        const privileges = await client.query<{
          summary_execute: boolean;
          delivery_execute: boolean;
          failure_execute: boolean;
          base_select: boolean;
          view_select: boolean;
        }>(`SELECT
          has_function_privilege(current_user,
            'get_initial_admin_onboarding_recovery_summary(uuid,uuid,uuid)','EXECUTE')
            AS summary_execute,
          has_function_privilege(current_user,
            'confirm_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)','EXECUTE')
            AS delivery_execute,
          has_function_privilege(current_user,
            'fail_initial_admin_onboarding_recovery_delivery(uuid,integer,uuid,text,uuid)','EXECUTE')
            AS failure_execute,
          has_table_privilege(current_user,'initial_admin_onboarding_recoveries','SELECT')
            AS base_select,
          has_table_privilege(current_user,'initial_admin_onboarding_recovery_summaries','SELECT')
            AS view_select`);
        expect(privileges.rows[0]).toEqual({
          summary_execute: true,
          delivery_execute: false,
          failure_execute: false,
          base_select: false,
          view_select: false,
        });
        const sanitized = await client.query<{ id: string; status: string }>(
          "SELECT id,status FROM get_initial_admin_onboarding_recovery_summary($1,$2,$3)",
          [fixture.requester.identityId, fixture.requester.sessionId, pending.recoveryId],
        );
        expect(sanitized.rows[0]).toEqual({
          id: pending.recoveryId,
          status: "pending",
        });
        await expectSqlState(
          client.query("SELECT token_hash,browser_context_hashes FROM initial_admin_onboarding_recoveries"),
          "42501",
        );
      } finally {
        await client.query("RESET ROLE").catch(() => undefined);
        await executeClientFormatted(
          client,
          "SELECT format('DROP OWNED BY %I', $1::text) AS sql",
          [role],
        ).catch(() => undefined);
        await executeClientFormatted(
          client,
          "SELECT format('DROP ROLE IF EXISTS %I', $1::text) AS sql",
          [role],
        ).catch(() => undefined);
        client.release();
      }
    });
  }, 60_000);

  it("executes the passkey flow with exact fences, bounded multi-root retry, quarantine, and replay safety", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const fixture = await createRecoveryFixture(database, "passkey");
      const store = new InitialAdminOnboardingRecoveryStore(database);
      const requestOperationHash = sha256("passkey-request-operation");
      const requesterGrant = await insertStepUpGrant(
        database,
        fixture.requester,
        requestOperationHash,
      );
      const recoveryId = randomUUID();
      const idempotencyKey = randomUUID();
      const requestExpiresAt = futureMinutes(20);
      const requestBase = {
        recoveryId,
        requesterIdentityId: fixture.requester.identityId,
        requesterSessionId: fixture.requester.sessionId,
        stepUpTokenHash: requesterGrant,
        operationHash: requestOperationHash,
        idempotencyKey,
        reasonCode: "browser_context_lost" as const,
        caseReferenceHash: sha256("case-passkey"),
        expiresAt: requestExpiresAt,
        requestId: randomUUID(),
      };

      await expectSqlState(
        store.request({
          ...requestBase,
          source: { ...fixture.source, invitationVersion: fixture.source.invitationVersion + 1 },
        }),
        "42501",
      );
      await expectGrantUnused(database, requesterGrant);
      await expectSqlState(
        store.request({ ...requestBase, source: fixture.source, operationHash: sha256("mutated-body") }),
        "42501",
      );
      await expectGrantUnused(database, requesterGrant);

      const requested = await store.request({ ...requestBase, source: fixture.source });
      expect(requested).toMatchObject({ recoveryId, version: 1, status: "pending", created: true });
      const replayedRequest = await store.request({ ...requestBase, source: fixture.source });
      expect(replayedRequest).toMatchObject({ recoveryId, version: 1, status: "pending", created: false });

      const persistedRequest = await database.query<{ request_hash: string }>(
        "SELECT request_hash FROM initial_admin_onboarding_recoveries WHERE id=$1",
        [recoveryId],
      );
      const persistedRequestHash = persistedRequest.rows[0]?.request_hash;
      expect(persistedRequestHash).toMatch(/^[0-9a-f]{64}$/u);
      await expectSqlState(
        database.query(
          `SELECT * FROM request_initial_admin_onboarding_recovery(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
           )`,
          [
            recoveryId,
            fixture.source.tenantId,
            fixture.source.invitationId,
            fixture.source.acceptanceId,
            fixture.source.acceptanceIdentityId,
            fixture.source.acceptanceAttempt,
            fixture.source.authorityEpoch,
            fixture.source.invitationVersion,
            fixture.requester.identityId,
            fixture.requester.sessionId,
            requestBase.stepUpTokenHash,
            requestBase.operationHash,
            randomUUID(),
            persistedRequestHash,
            requestBase.reasonCode,
            requestBase.caseReferenceHash,
            requestBase.expiresAt,
            randomUUID(),
          ],
        ),
        "23505",
      );
      const requestInventory = await database.query<{ count: number }>(
        "SELECT count(*)::integer AS count FROM initial_admin_onboarding_recoveries",
      );
      expect(requestInventory.rows[0]?.count).toBe(1);

      const queue = await store.listRecoveries({
        actorIdentityId: fixture.approver.identityId,
        actorSessionId: fixture.approver.sessionId,
        status: "pending",
        limit: 100,
      });
      expect(queue).toHaveLength(1);
      expect(queue[0]).toMatchObject({
        recoveryId,
        invitationId: fixture.source.invitationId,
        acceptanceIdentityId: fixture.targetIdentityId,
        recipientEmail: fixture.targetEmail,
        requesterIdentityId: fixture.requester.identityId,
      });
      expect(JSON.stringify(queue[0])).not.toMatch(/token_hash|context_hash|operation_hash|case_reference/i);

      const approvalOperationHash = sha256("passkey-approval-operation");
      const approverGrant = await insertStepUpGrant(
        database,
        fixture.approver,
        approvalOperationHash,
      );
      const recoveryToken = randomToken();
      const tokenExpiresAt = futureMinutes(15);
      const approvalBase = {
        recoveryId,
        expectedVersion: 1,
        source: fixture.source,
        approverIdentityId: fixture.approver.identityId,
        approverSessionId: fixture.approver.sessionId,
        stepUpTokenHash: approverGrant,
        operationHash: approvalOperationHash,
        recoveryTokenHash: sha256(recoveryToken),
        tokenExpiresAt,
        deliveryChannel: "local_console" as const,
        deliveryReferenceHash: sha256("local-console-passkey"),
        requestId: randomUUID(),
      };

      await expectSqlState(
        store.approve({
          ...approvalBase,
          approverIdentityId: fixture.targetIdentityId,
          approverSessionId: fixture.legacyPasswordSessionId,
        }),
        "42501",
      );
      await expectGrantUnused(database, approverGrant);

      const approved = await store.approve(approvalBase);
      expect(approved).toMatchObject({
        recoveryId,
        version: 2,
        status: "finalization_pending",
        deliveryState: "delivered",
        recipientEmail: fixture.targetEmail,
        reused: false,
      });
      expect(approved.tokenExpiresAt?.getTime()).toBe(tokenExpiresAt.getTime());

      const replayedApproval = await store.approve({
        ...approvalBase,
        expectedVersion: 999,
        stepUpTokenHash: sha256("never-consumed-replay-grant"),
        recoveryTokenHash: sha256(randomToken()),
        requestId: randomUUID(),
      });
      expect(replayedApproval).toMatchObject({ version: 2, reused: true });
      const approvalEvidence = await database.query<{
        token_hash: string;
        revoked_session_count: number;
        revoked_mfa_challenge_count: number;
        revoked_step_up_grant_count: number;
        revoked_webauthn_ceremony_count: number;
      }>(
        `SELECT token_hash,revoked_session_count,revoked_mfa_challenge_count,
                revoked_step_up_grant_count,revoked_webauthn_ceremony_count
           FROM initial_admin_onboarding_recoveries WHERE id=$1`,
        [recoveryId],
      );
      expect(approvalEvidence.rows[0]).toEqual({
        token_hash: sha256(recoveryToken),
        revoked_session_count: 2,
        revoked_mfa_challenge_count: 1,
        revoked_step_up_grant_count: 1,
        revoked_webauthn_ceremony_count: 1,
      });
      await expectTargetQuarantined(database, fixture);

      const contextProofs = Array.from({ length: 12 }, (_, index) =>
        deterministicToken(`passkey-context-${index}`));
      await expectSqlState(
        redeemDirect(database, {
          recoveryId,
          recoveryToken,
          contextProofs: [...contextProofs, deterministicToken("thirteenth-context")],
        }),
        "23514",
      );

      let currentSessionId = randomUUID();
      const firstRedemption = await store.redeem({
        recoveryId,
        recoveryToken,
        contextProofs,
        sessionId: currentSessionId,
        sessionTokenHash: sha256("recovery-session-1"),
        csrfHash: sha256("recovery-csrf-1"),
        sessionExpiresAt: futureMinutes(10),
        requestId: randomUUID(),
        userAgentHash: sha256("ua-passkey"),
        ipPrefixHash: sha256("ip-passkey"),
      });
      expect(firstRedemption).toMatchObject({
        recovered: true,
        identityId: fixture.targetIdentityId,
        tenantId: fixture.tenantId,
        sessionId: currentSessionId,
        rotated: false,
        version: 3,
      });

      for (let rotation = 2; rotation <= 4; rotation += 1) {
        currentSessionId = randomUUID();
        const rotated = await store.redeem({
          recoveryId,
          contextProofs: [contextProofs[11]!, contextProofs[2]!],
          sessionId: currentSessionId,
          sessionTokenHash: sha256(`recovery-session-${rotation}`),
          csrfHash: sha256(`recovery-csrf-${rotation}`),
          sessionExpiresAt: futureMinutes(10),
          requestId: randomUUID(),
          userAgentHash: sha256("ua-passkey"),
          ipPrefixHash: sha256("ip-passkey"),
        });
        expect(rotated).toMatchObject({ recovered: true, rotated: true, version: rotation + 2 });
      }
      const exhausted = await store.redeem({
        recoveryId,
        contextProofs: [contextProofs[0]!],
        sessionId: randomUUID(),
        sessionTokenHash: sha256("recovery-session-5"),
        csrfHash: sha256("recovery-csrf-5"),
        sessionExpiresAt: futureMinutes(10),
        requestId: randomUUID(),
        userAgentHash: sha256("ua-passkey"),
        ipPrefixHash: sha256("ip-passkey"),
      });
      expect(exhausted).toMatchObject({ recovered: false, rotated: false, version: 6 });
      const bounded = await database.query<{
        redemption_count: number;
        root_count: number;
        active_sessions: string;
      }>(
        `SELECT recovery.redemption_count,cardinality(recovery.browser_context_hashes) AS root_count,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.initial_admin_onboarding_recovery_id=recovery.id
                    AND session.revoked_at IS NULL) AS active_sessions
           FROM initial_admin_onboarding_recoveries recovery WHERE recovery.id=$1`,
        [recoveryId],
      );
      expect(bounded.rows[0]).toEqual({ redemption_count: 4, root_count: 12, active_sessions: "1" });

      const passwordSessionId = await insertPasswordSession(
        database,
        fixture.targetIdentityId,
        fixture.tenantId,
        "legacy-password-after-redeem",
      );
      await expectSqlState(
        store.finalizeStrongFactor({
          sourceEnrollmentSessionId: currentSessionId,
          newSessionId: passwordSessionId,
          requestId: randomUUID(),
        }),
        "42501",
      );

      const ceremony = await insertRegistrationCeremony(
        database,
        fixture.targetIdentityId,
        fixture.tenantId,
        currentSessionId,
        "passkey-finalization",
      );
      const enterprise = new EnterpriseAuthStore(database);
      const foreignFixture = await createRecoveryFixture(database, "foreign-source");
      const foreignRecovery = await openRecoveryToEnrollment(
        database,
        foreignFixture,
        "foreign-source",
      );
      await expect(
        enterprise.completeRegistration({
          ...passkeyCompletionInput(ceremony, "mismatched-source"),
          sourceSessionId: foreignRecovery.sessionId,
        }),
      ).rejects.toBeInstanceOf(EnterpriseAuthStoreError);
      expect(await recoveryStatus(database, recoveryId)).toBe("enrollment_pending");
      expect(await recoveryStatus(database, foreignRecovery.recoveryId)).toBe("enrollment_pending");

      const completed = await enterprise.completeRegistration({
        ...passkeyCompletionInput(ceremony, "passkey-success"),
        sourceSessionId: currentSessionId,
      });
      expect(completed).toMatchObject({
        identityId: fixture.targetIdentityId,
        tenantId: fixture.tenantId,
      });
      expect(await recoveryStatus(database, recoveryId)).toBe("admin_active");
      const finalizationReplay = await store.finalizeStrongFactor({
        sourceEnrollmentSessionId: currentSessionId,
        newSessionId: completed.sessionId,
        requestId: randomUUID(),
      });
      expect(finalizationReplay).toMatchObject({
        recoveryId,
        factorMethod: "passkey",
        reused: true,
      });
      const audit = await recoveryAudit(database, recoveryId);
      expect(audit.map(({ action }) => action)).toEqual([
        "platform.initial_admin_onboarding_recovery_requested",
        "platform.initial_admin_onboarding_recovery_approved",
        "platform.initial_admin_onboarding_recovery_redeemed",
        "platform.initial_admin_onboarding_recovery_session_rotated",
        "platform.initial_admin_onboarding_recovery_session_rotated",
        "platform.initial_admin_onboarding_recovery_session_rotated",
        "platform.initial_admin_onboarding_recovery_strong_factor_finalized",
      ]);
    });
  }, 60_000);

  it("finalizes TOTP atomically and fails closed when either administrator loses authority", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const mfa = new MfaStore(database);

      const successFixture = await createRecoveryFixture(database, "totp-success");
      const success = await openRecoveryToEnrollment(database, successFixture, "totp-success");
      const enrollmentId = randomUUID();
      await mfa.startEnrollment({
        sessionId: success.sessionId,
        identityId: successFixture.targetIdentityId,
        enrollmentId,
        secretCiphertext: "encrypted:test-only:totp-seed",
        recentWindowMinutes: 15,
      });
      const strongSessionId = randomUUID();
      const completed = await mfa.completeEnrollment({
        sessionId: success.sessionId,
        identityId: successFixture.targetIdentityId,
        enrollmentId,
        acceptedTimeStep: 123_456,
        recoveryCodeHashes: recoveryCodeHashes("totp-success"),
        recentWindowMinutes: 15,
        tenantId: successFixture.tenantId,
        requestId: randomUUID(),
        newSession: {
          id: strongSessionId,
          tokenHash: sha256("totp-success-strong-session"),
          csrfHash: sha256("totp-success-strong-csrf"),
          expiresAt: futureMinutes(60),
          idleTimeoutMinutes: 30,
          userAgentHash: sha256("totp-success-ua"),
          ipPrefixHash: sha256("totp-success-ip"),
        },
      });
      expect(completed).toEqual({ generation: 1, sessionId: strongSessionId });
      expect(await recoveryStatus(database, success.recoveryId)).toBe("admin_active");
      const successEvidence = await database.query<{
        mfa_enabled: boolean;
        active_strong: string;
        active_enrollment: string;
      }>(
        `SELECT identity.mfa_enabled,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.id=$2 AND session.revoked_at IS NULL
                    AND session.auth_method='totp' AND session.assurance_level='mfa') AS active_strong,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.identity_id=$1 AND session.assurance_level='enrollment_only'
                    AND session.revoked_at IS NULL) AS active_enrollment
           FROM platform_identities identity WHERE identity.id=$1`,
        [successFixture.targetIdentityId, strongSessionId],
      );
      expect(successEvidence.rows[0]).toEqual({
        mfa_enabled: true,
        active_strong: "1",
        active_enrollment: "0",
      });

      const requesterLossFixture = await createRecoveryFixture(database, "requester-loss");
      const pending = await requestRecovery(database, requesterLossFixture, "requester-loss");
      await database.query(
        "DELETE FROM platform_role_bindings WHERE identity_id=$1 AND role_code='platform_admin'",
        [requesterLossFixture.requester.identityId],
      );
      const requesterLossApproval = await approveRecovery(
        database,
        requesterLossFixture,
        pending.recoveryId,
        "requester-loss",
      );
      expect(requesterLossApproval.status).toBe("revoked");
      expect(requesterLossApproval.reused).toBe(true);
      const requesterLossAudit = await recoveryAudit(database, pending.recoveryId);
      expect(requesterLossAudit.at(-1)).toMatchObject({
        action: "platform.initial_admin_onboarding_recovery_revoked",
        actor_identity_id: null,
      });

      const approverLossFixture = await createRecoveryFixture(database, "approver-loss");
      const approverLoss = await openRecoveryToEnrollment(database, approverLossFixture, "approver-loss");
      const invalidatedEnrollmentId = randomUUID();
      await mfa.startEnrollment({
        sessionId: approverLoss.sessionId,
        identityId: approverLossFixture.targetIdentityId,
        enrollmentId: invalidatedEnrollmentId,
        secretCiphertext: "encrypted:test-only:invalidated-seed",
        recentWindowMinutes: 15,
      });
      await database.query(
        "DELETE FROM platform_role_bindings WHERE identity_id=$1 AND role_code='platform_admin'",
        [approverLossFixture.approver.identityId],
      );
      const forbiddenStrongSessionId = randomUUID();
      await expect(
        mfa.completeEnrollment({
          sessionId: approverLoss.sessionId,
          identityId: approverLossFixture.targetIdentityId,
          enrollmentId: invalidatedEnrollmentId,
          acceptedTimeStep: 123_457,
          recoveryCodeHashes: recoveryCodeHashes("approver-loss"),
          recentWindowMinutes: 15,
          tenantId: approverLossFixture.tenantId,
          requestId: randomUUID(),
          newSession: {
            id: forbiddenStrongSessionId,
            tokenHash: sha256("approver-loss-strong-session"),
            csrfHash: sha256("approver-loss-strong-csrf"),
            expiresAt: futureMinutes(60),
            idleTimeoutMinutes: 30,
          },
        }),
      ).rejects.toMatchObject({ code: "RECOVERY_GOVERNANCE_INVALID" });
      expect(await recoveryStatus(database, approverLoss.recoveryId)).toBe("revoked");
      const forbiddenFactor = await database.query<{
        mfa_enabled: boolean;
        strong_session_count: string;
        source_revoked: boolean;
      }>(
        `SELECT identity.mfa_enabled,
                (SELECT count(*)::text FROM auth_sessions WHERE id=$2) AS strong_session_count,
                (SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$3) AS source_revoked
           FROM platform_identities identity WHERE identity.id=$1`,
        [approverLossFixture.targetIdentityId, forbiddenStrongSessionId, approverLoss.sessionId],
      );
      expect(forbiddenFactor.rows[0]).toEqual({
        mfa_enabled: false,
        strong_session_count: "0",
        source_revoked: true,
      });
      const approverLossAudit = await recoveryAudit(database, approverLoss.recoveryId);
      expect(approverLossAudit.at(-1)).toMatchObject({
        action: "platform.initial_admin_onboarding_recovery_revoked",
        actor_identity_id: null,
      });
    });
  }, 60_000);

  it("expires an unauthenticated stale probe as a system transition and releases discovery", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const fixture = await createRecoveryFixture(database, "expiry");
      const pending = await requestRecovery(
        database,
        fixture,
        "expiry",
        new Date(Date.now() + 1_000),
      );
      await new Promise<void>((resolve) => setTimeout(resolve, 1_100));
      const store = new InitialAdminOnboardingRecoveryStore(database);
      const probed = await store.redeem({
        recoveryId: pending.recoveryId,
        recoveryToken: randomToken(),
        contextProofs: [deterministicToken("expired-probe")],
        sessionId: randomUUID(),
        sessionTokenHash: sha256("expired-probe-session"),
        csrfHash: sha256("expired-probe-csrf"),
        sessionExpiresAt: futureMinutes(10),
        requestId: randomUUID(),
      });
      expect(probed).toMatchObject({ recovered: false, version: 2 });
      expect(await recoveryStatus(database, pending.recoveryId)).toBe("expired");
      const audit = await recoveryAudit(database, pending.recoveryId);
      expect(audit.at(-1)).toMatchObject({
        action: "platform.initial_admin_onboarding_recovery_expired",
        actor_identity_id: null,
      });
      const candidates = await store.listCandidates({
        actorIdentityId: fixture.approver.identityId,
        actorSessionId: fixture.approver.sessionId,
        tenantId: fixture.tenantId,
        limit: 100,
      });
      expect(candidates).toHaveLength(1);
      expect(candidates[0]?.acceptanceIdentityId).toBe(fixture.targetIdentityId);
    });
  }, 60_000);

  it("serializes five concurrent bearer redemptions to four bounded rotations and one active session", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const fixture = await createRecoveryFixture(database, "redeem-race");
      const pending = await requestRecovery(database, fixture, "redeem-race");
      const store = new InitialAdminOnboardingRecoveryStore(database);
      const approvalOperationHash = sha256("redeem-race-approval-operation");
      const approvalGrant = await insertStepUpGrant(
        database,
        fixture.approver,
        approvalOperationHash,
      );
      const recoveryToken = deterministicToken("redeem-race-token");
      await store.approve({
        recoveryId: pending.recoveryId,
        expectedVersion: 1,
        source: fixture.source,
        approverIdentityId: fixture.approver.identityId,
        approverSessionId: fixture.approver.sessionId,
        stepUpTokenHash: approvalGrant,
        operationHash: approvalOperationHash,
        recoveryTokenHash: sha256(recoveryToken),
        tokenExpiresAt: futureMinutes(10),
        deliveryChannel: "local_console",
        deliveryReferenceHash: sha256("redeem-race-delivery"),
        requestId: randomUUID(),
      });
      const contextProofs = Array.from({ length: 12 }, (_, index) =>
        deterministicToken(`redeem-race-context-${index}`));
      const requestedSessionIds = Array.from({ length: 5 }, () => randomUUID());
      const settled = await Promise.allSettled(
        requestedSessionIds.map((sessionId, index) => store.redeem({
          recoveryId: pending.recoveryId,
          recoveryToken,
          contextProofs,
          sessionId,
          sessionTokenHash: sha256(`redeem-race-session-${index}`),
          csrfHash: sha256(`redeem-race-csrf-${index}`),
          sessionExpiresAt: futureMinutes(10),
          requestId: randomUUID(),
          userAgentHash: sha256("redeem-race-ua"),
          ipPrefixHash: sha256("redeem-race-ip"),
        })),
      );
      expect(settled.every(({ status }) => status === "fulfilled")).toBe(true);
      const values = settled.flatMap((result) => result.status === "fulfilled" ? [result.value] : []);
      expect(values.filter(({ recovered }) => recovered)).toHaveLength(4);
      expect(values.filter(({ recovered }) => !recovered)).toHaveLength(1);
      const active = await database.query<{
        redemption_count: number;
        active_session_id: string;
        active_session_count: string;
        mfa_enabled: boolean;
        passkey_enabled: boolean;
        active_credentials: string;
      }>(
        `SELECT recovery.redemption_count,
                (SELECT session.id::text FROM auth_sessions session
                  WHERE session.initial_admin_onboarding_recovery_id=recovery.id
                    AND session.revoked_at IS NULL) AS active_session_id,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.initial_admin_onboarding_recovery_id=recovery.id
                    AND session.revoked_at IS NULL) AS active_session_count,
                identity.mfa_enabled,identity.passkey_enabled,
                (SELECT count(*)::text FROM webauthn_credentials credential
                  WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL)
                  AS active_credentials
           FROM initial_admin_onboarding_recoveries recovery
           JOIN platform_identities identity ON identity.id=recovery.acceptance_identity_id
          WHERE recovery.id=$1`,
        [pending.recoveryId],
      );
      expect(active.rows[0]).toMatchObject({
        redemption_count: 4,
        active_session_count: "1",
        mfa_enabled: false,
        passkey_enabled: false,
        active_credentials: "0",
      });
      const successfulSessionIds = values
        .filter(({ recovered }) => recovered)
        .map(({ sessionId }) => sessionId);
      expect(successfulSessionIds).toContain(active.rows[0]?.active_session_id);
    });
  }, 60_000);

  it("serializes original and recovered factor completion against approval and rotation without deadlock", async () => {
    await withTemporaryDatabase(async (database) => {
      await createMigrationTable(database);
      await applyMigrationsThrough(database, 26);
      const store = new InitialAdminOnboardingRecoveryStore(database);
      const mfa = new MfaStore(database);

      const approvalFixture = await createRecoveryFixture(database, "approval-factor-race");
      const pending = await requestRecovery(database, approvalFixture, "approval-factor-race");
      const originalEnrollmentId = randomUUID();
      await mfa.startEnrollment({
        sessionId: approvalFixture.originalEnrollmentSessionId,
        identityId: approvalFixture.targetIdentityId,
        enrollmentId: originalEnrollmentId,
        secretCiphertext: "encrypted:test-only:approval-factor-race",
        recentWindowMinutes: 15,
      });
      const approvalOperationHash = sha256("approval-factor-race-operation");
      const approvalGrant = await insertStepUpGrant(
        database,
        approvalFixture.approver,
        approvalOperationHash,
      );
      const originalStrongSessionId = randomUUID();
      const approvalRace = await Promise.allSettled([
        store.approve({
          recoveryId: pending.recoveryId,
          expectedVersion: 1,
          source: approvalFixture.source,
          approverIdentityId: approvalFixture.approver.identityId,
          approverSessionId: approvalFixture.approver.sessionId,
          stepUpTokenHash: approvalGrant,
          operationHash: approvalOperationHash,
          recoveryTokenHash: sha256(deterministicToken("approval-factor-race-token")),
          tokenExpiresAt: futureMinutes(10),
          deliveryChannel: "local_console",
          deliveryReferenceHash: sha256("approval-factor-race-delivery"),
          requestId: randomUUID(),
        }),
        mfa.completeEnrollment({
          sessionId: approvalFixture.originalEnrollmentSessionId,
          identityId: approvalFixture.targetIdentityId,
          enrollmentId: originalEnrollmentId,
          acceptedTimeStep: 200_001,
          recoveryCodeHashes: recoveryCodeHashes("approval-factor-race"),
          recentWindowMinutes: 15,
          tenantId: approvalFixture.tenantId,
          requestId: randomUUID(),
          newSession: {
            id: originalStrongSessionId,
            tokenHash: sha256("approval-factor-race-strong-token"),
            csrfHash: sha256("approval-factor-race-strong-csrf"),
            expiresAt: futureMinutes(60),
            idleTimeoutMinutes: 30,
          },
        }),
      ]);
      expect(approvalRace.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
      expect(approvalRace.map(sqlStateOf)).not.toContain("40P01");
      const approvalRaceState = await database.query<{
        recovery_status: string;
        mfa_enabled: boolean;
        active_target_sessions: string;
      }>(
        `SELECT recovery.status AS recovery_status,identity.mfa_enabled,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.identity_id=identity.id AND session.revoked_at IS NULL)
                  AS active_target_sessions
           FROM initial_admin_onboarding_recoveries recovery
           JOIN platform_identities identity ON identity.id=recovery.acceptance_identity_id
          WHERE recovery.id=$1`,
        [pending.recoveryId],
      );
      if (approvalRace[0]?.status === "fulfilled") {
        expect(approvalRaceState.rows[0]).toEqual({
          recovery_status: "finalization_pending",
          mfa_enabled: false,
          active_target_sessions: "0",
        });
      } else {
        expect(approvalRaceState.rows[0]).toEqual({
          recovery_status: "pending",
          mfa_enabled: true,
          active_target_sessions: "1",
        });
      }

      const rotationFixture = await createRecoveryFixture(database, "rotation-factor-race");
      const opened = await openRecoveryToEnrollment(database, rotationFixture, "rotation-factor-race");
      const recoveredEnrollmentId = randomUUID();
      await mfa.startEnrollment({
        sessionId: opened.sessionId,
        identityId: rotationFixture.targetIdentityId,
        enrollmentId: recoveredEnrollmentId,
        secretCiphertext: "encrypted:test-only:rotation-factor-race",
        recentWindowMinutes: 15,
      });
      const rotatedSessionId = randomUUID();
      const recoveredStrongSessionId = randomUUID();
      const rotationRace = await Promise.allSettled([
        store.redeem({
          recoveryId: opened.recoveryId,
          contextProofs: [opened.contextProofs[9]!, opened.contextProofs[1]!],
          sessionId: rotatedSessionId,
          sessionTokenHash: sha256("rotation-factor-race-rotated-token"),
          csrfHash: sha256("rotation-factor-race-rotated-csrf"),
          sessionExpiresAt: futureMinutes(10),
          requestId: randomUUID(),
          userAgentHash: sha256("rotation-factor-race-ua"),
          ipPrefixHash: sha256("rotation-factor-race-ip"),
        }),
        mfa.completeEnrollment({
          sessionId: opened.sessionId,
          identityId: rotationFixture.targetIdentityId,
          enrollmentId: recoveredEnrollmentId,
          acceptedTimeStep: 200_002,
          recoveryCodeHashes: recoveryCodeHashes("rotation-factor-race"),
          recentWindowMinutes: 15,
          tenantId: rotationFixture.tenantId,
          requestId: randomUUID(),
          newSession: {
            id: recoveredStrongSessionId,
            tokenHash: sha256("rotation-factor-race-strong-token"),
            csrfHash: sha256("rotation-factor-race-strong-csrf"),
            expiresAt: futureMinutes(60),
            idleTimeoutMinutes: 30,
          },
        }),
      ]);
      expect(rotationRace.map(sqlStateOf)).not.toContain("40P01");
      const redemptionOutcome = rotationRace[0];
      const factorOutcome = rotationRace[1];
      const redemptionWon = redemptionOutcome.status === "fulfilled"
        && redemptionOutcome.value.recovered;
      const factorWon = factorOutcome.status === "fulfilled";
      expect(Number(redemptionWon) + Number(factorWon)).toBe(1);
      const rotationRaceState = await database.query<{
        recovery_status: string;
        redemption_count: number;
        mfa_enabled: boolean;
        active_enrollment: string;
        active_strong: string;
      }>(
        `SELECT recovery.status AS recovery_status,recovery.redemption_count,identity.mfa_enabled,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.identity_id=identity.id AND session.revoked_at IS NULL
                    AND session.assurance_level='enrollment_only') AS active_enrollment,
                (SELECT count(*)::text FROM auth_sessions session
                  WHERE session.identity_id=identity.id AND session.revoked_at IS NULL
                    AND session.assurance_level='mfa') AS active_strong
           FROM initial_admin_onboarding_recoveries recovery
           JOIN platform_identities identity ON identity.id=recovery.acceptance_identity_id
          WHERE recovery.id=$1`,
        [opened.recoveryId],
      );
      if (redemptionWon) {
        expect(rotationRaceState.rows[0]).toEqual({
          recovery_status: "enrollment_pending",
          redemption_count: 2,
          mfa_enabled: false,
          active_enrollment: "1",
          active_strong: "0",
        });
      } else {
        expect(rotationRaceState.rows[0]).toEqual({
          recovery_status: "admin_active",
          redemption_count: 1,
          mfa_enabled: true,
          active_enrollment: "0",
          active_strong: "1",
        });
      }
    });
  }, 60_000);
});

interface FixtureActor {
  readonly identityId: string;
  readonly sessionId: string;
  readonly credentialId: string;
}

interface RecoveryFixture {
  readonly tenantId: string;
  readonly targetIdentityId: string;
  readonly targetEmail: string;
  readonly originalEnrollmentSessionId: string;
  readonly legacyPasswordSessionId: string;
  readonly requester: FixtureActor;
  readonly approver: FixtureActor;
  readonly source: InitialAdminRecoverySource;
}

interface CeremonyFixture {
  readonly id: string;
  readonly tokenHash: string;
  readonly challengeHash: string;
  readonly sourceSessionId: string;
  readonly rpId: string;
}

interface PendingRecovery {
  readonly recoveryId: string;
  readonly requestExpiresAt: Date;
}

interface EnrollmentRecovery extends PendingRecovery {
  readonly recoveryToken: string;
  readonly contextProofs: readonly string[];
  readonly sessionId: string;
}

interface InvitationEnrollmentRecoveryFixture {
  readonly tenantId: string;
  readonly invitationId: string;
  readonly identityId: string;
  readonly normalizedEmail: string;
  readonly token: string;
  readonly recoveryProof: string;
  readonly originalEnrollmentSessionId: string;
  readonly passwordSessionId: string;
}

const DISABLED_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$BlX3TtC3KRRD8kjGx9PwxQ$BRboo0FP4y3RHcgkaHeHuBjXcmcJayVDIp/Qp4qMCIY";

async function createInvitationEnrollmentRecoveryFixture(
  database: Pool,
): Promise<InvitationEnrollmentRecoveryFixture> {
  const suffix = randomBytes(5).toString("hex");
  const tenantId = randomUUID();
  await database.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_port,database_name,
       runtime_role,runtime_secret_ref,activated_at
     ) VALUES ($1,$2,$3,'real','active','UTC','es',55432,$4,$5,$6,clock_timestamp())`,
    [
      tenantId,
      `inv-recovery-${suffix}`,
      `Invitation recovery ${suffix}`,
      `inv_recovery_${suffix}`,
      `inv_recovery_role_${suffix}`,
      `invitation/recovery/${suffix}`,
    ],
  );
  const grantorId = randomUUID();
  const identityId = randomUUID();
  const normalizedEmail = `invitation-recovery-${suffix}@invalid.example`;
  await insertIdentity(database, {
    identityId: grantorId,
    email: `invitation-grantor-${suffix}@invalid.example`,
    displayName: "Invitation recovery grantor",
    mfaRequired: false,
  });
  await insertIdentity(database, {
    identityId,
    email: normalizedEmail,
    displayName: "Invitation recovery recipient",
    mfaRequired: false,
  });
  await database.query(
    `INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default)
     VALUES ($1,$2,'active',true),($1,$3,'active',true)`,
    [tenantId, grantorId, identityId],
  );
  const invitationId = randomUUID();
  const acceptanceId = randomUUID();
  const token = randomToken();
  const recoveryProof = randomToken();
  await database.query(
    `INSERT INTO tenant_invitations(
       id,tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
       request_hash,created_by_identity_id,expires_at,acceptance_id,acceptance_identity_id,
       acceptance_started_at,accepted_at,consumed_at,authority_kind,authority_epoch,
       acceptance_attempt,acceptance_recovery_hash
     ) VALUES (
       $1,$2,$3,$3,ARRAY['AUDITOR']::text[],$4,'accepted',$5,$6,$7,
       clock_timestamp()+interval '1 day',$8,$9,clock_timestamp(),clock_timestamp(),
       clock_timestamp(),'tenant_delegate',0,1,$10
     )`,
    [
      invitationId,
      tenantId,
      normalizedEmail,
      sha256(token),
      randomUUID(),
      sha256(`invitation-request-${suffix}`),
      grantorId,
      acceptanceId,
      identityId,
      sha256(recoveryProof),
    ],
  );
  const originalEnrollmentSessionId = await insertEnrollmentSession(
    database,
    identityId,
    tenantId,
    invitationId,
    `invitation-recovery-${suffix}`,
  );
  const passwordSessionId = await insertPasswordSession(
    database,
    identityId,
    tenantId,
    `invitation-recovery-password-${suffix}`,
  );
  return {
    tenantId,
    invitationId,
    identityId,
    normalizedEmail,
    token,
    recoveryProof,
    originalEnrollmentSessionId,
    passwordSessionId,
  };
}

async function createRecoveryFixture(database: Pool, label: string): Promise<RecoveryFixture> {
  const suffix = randomBytes(5).toString("hex");
  const tenantId = randomUUID();
  await database.query(
    `INSERT INTO tenants(
       id,slug,display_name,kind,status,timezone,locale,database_port,database_name,
       runtime_role,runtime_secret_ref,activated_at,initial_admin_authority_epoch
     ) VALUES ($1,$2,$3,'real','active','UTC','es',55432,$4,$5,$6,clock_timestamp(),1)`,
    [
      tenantId,
      `recovery-${suffix}`,
      `Recovery ${label} ${suffix}`,
      `recovery_${suffix}`,
      `recovery_role_${suffix}`,
      `recovery/secret/${suffix}`,
    ],
  );

  const grantor = await insertAdmin(database, tenantId, `${label}-grantor-${suffix}`);
  const requester = await insertAdmin(database, tenantId, `${label}-requester-${suffix}`);
  const approver = await insertAdmin(database, tenantId, `${label}-approver-${suffix}`);
  const targetIdentityId = randomUUID();
  const targetEmail = `${label}-target-${suffix}@invalid.example`;
  await insertIdentity(database, {
    identityId: targetIdentityId,
    email: targetEmail,
    displayName: `${label} target`,
    mfaRequired: true,
  });
  await database.query(
    "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
    [tenantId, targetIdentityId],
  );

  const invitationId = randomUUID();
  const acceptanceId = randomUUID();
  await database.query(
    `INSERT INTO tenant_invitations(
       id,tenant_id,email,normalized_email,role_codes,token_hash,status,idempotency_key,
       request_hash,created_by_identity_id,expires_at,acceptance_id,acceptance_identity_id,
       acceptance_started_at,accepted_at,consumed_at,version,authority_kind,authority_epoch,
       acceptance_attempt,authority_finalized_at
     ) VALUES (
       $1,$2,$3,$3,ARRAY['CHURCH_ADMIN']::text[],$4,'accepted',$5,$6,$7,
       clock_timestamp()+interval '1 day',$8,$9,clock_timestamp(),clock_timestamp(),
       clock_timestamp(),7,'initial_admin',1,1,clock_timestamp()
     )`,
    [
      invitationId,
      tenantId,
      targetEmail,
      sha256(`invitation-${suffix}`),
      randomUUID(),
      sha256(`invitation-request-${suffix}`),
      grantor.identityId,
      acceptanceId,
      targetIdentityId,
    ],
  );

  const originalEnrollmentSessionId = await insertEnrollmentSession(
    database,
    targetIdentityId,
    tenantId,
    invitationId,
    `original-${suffix}`,
  );
  const legacyPasswordSessionId = await insertPasswordSession(
    database,
    targetIdentityId,
    tenantId,
    `legacy-${suffix}`,
  );
  await database.query(
    `INSERT INTO mfa_challenges(
       token_hash,identity_id,tenant_id,origin_hash,expires_at
     ) VALUES ($1,$2,$3,$4,clock_timestamp()+interval '10 minutes')`,
    [sha256(`challenge-${suffix}`), targetIdentityId, tenantId, sha256(`origin-${suffix}`)],
  );
  await insertRegistrationCeremony(
    database,
    targetIdentityId,
    tenantId,
    originalEnrollmentSessionId,
    `abandoned-${suffix}`,
  );
  const targetCredentialId = await insertCredential(database, targetIdentityId, `retired-${suffix}`);
  const targetGrantHash = sha256(`target-grant-${suffix}`);
  await database.query(
    `INSERT INTO authentication_step_up_grants(
       token_hash,identity_id,tenant_id,session_id,credential_id,purpose,operation_hash,
       expires_at
     ) VALUES ($1,$2,$3,$4,$5,'platform_administration',$6,
       clock_timestamp()+interval '5 minutes')`,
    [
      targetGrantHash,
      targetIdentityId,
      tenantId,
      legacyPasswordSessionId,
      targetCredentialId,
      sha256(`target-operation-${suffix}`),
    ],
  );
  await database.query(
    `UPDATE webauthn_credentials
        SET revoked_at=clock_timestamp(),revocation_reason='replaced'
      WHERE id=$1`,
    [targetCredentialId],
  );

  return {
    tenantId,
    targetIdentityId,
    targetEmail,
    originalEnrollmentSessionId,
    legacyPasswordSessionId,
    requester,
    approver,
    source: {
      tenantId,
      invitationId,
      acceptanceId,
      acceptanceIdentityId: targetIdentityId,
      acceptanceAttempt: 1,
      authorityEpoch: 1,
      invitationVersion: 7,
    },
  };
}

async function requestRecovery(
  database: Pool,
  fixture: RecoveryFixture,
  label: string,
  requestExpiresAt = futureMinutes(20),
): Promise<PendingRecovery> {
  const store = new InitialAdminOnboardingRecoveryStore(database);
  const operationHash = sha256(`${label}-request-operation`);
  const grant = await insertStepUpGrant(database, fixture.requester, operationHash);
  const recoveryId = randomUUID();
  const result = await store.request({
    recoveryId,
    source: fixture.source,
    requesterIdentityId: fixture.requester.identityId,
    requesterSessionId: fixture.requester.sessionId,
    stepUpTokenHash: grant,
    operationHash,
    idempotencyKey: randomUUID(),
    reasonCode: "browser_profile_reset",
    caseReferenceHash: sha256(`${label}-case-reference`),
    expiresAt: requestExpiresAt,
    requestId: randomUUID(),
  });
  expect(result).toMatchObject({ recoveryId, version: 1, status: "pending", created: true });
  return { recoveryId, requestExpiresAt };
}

async function approveRecovery(
  database: Pool,
  fixture: RecoveryFixture,
  recoveryId: string,
  label: string,
): Promise<Awaited<ReturnType<InitialAdminOnboardingRecoveryStore["approve"]>>> {
  const store = new InitialAdminOnboardingRecoveryStore(database);
  const operationHash = sha256(`${label}-approval-operation`);
  const grant = await insertStepUpGrant(database, fixture.approver, operationHash);
  return store.approve({
    recoveryId,
    expectedVersion: 1,
    source: fixture.source,
    approverIdentityId: fixture.approver.identityId,
    approverSessionId: fixture.approver.sessionId,
    stepUpTokenHash: grant,
    operationHash,
    recoveryTokenHash: sha256(deterministicToken(`${label}-recovery-token`)),
    tokenExpiresAt: futureMinutes(10),
    deliveryChannel: "local_console",
    deliveryReferenceHash: sha256(`${label}-delivery-reference`),
    requestId: randomUUID(),
  });
}

async function openRecoveryToEnrollment(
  database: Pool,
  fixture: RecoveryFixture,
  label: string,
): Promise<EnrollmentRecovery> {
  const pending = await requestRecovery(database, fixture, label);
  const store = new InitialAdminOnboardingRecoveryStore(database);
  const operationHash = sha256(`${label}-approval-operation`);
  const grant = await insertStepUpGrant(database, fixture.approver, operationHash);
  const recoveryToken = deterministicToken(`${label}-recovery-token`);
  const approved = await store.approve({
    recoveryId: pending.recoveryId,
    expectedVersion: 1,
    source: fixture.source,
    approverIdentityId: fixture.approver.identityId,
    approverSessionId: fixture.approver.sessionId,
    stepUpTokenHash: grant,
    operationHash,
    recoveryTokenHash: sha256(recoveryToken),
    tokenExpiresAt: futureMinutes(10),
    deliveryChannel: "local_console",
    deliveryReferenceHash: sha256(`${label}-delivery-reference`),
    requestId: randomUUID(),
  });
  expect(approved).toMatchObject({ version: 2, status: "finalization_pending", reused: false });
  const contextProofs = Array.from({ length: 12 }, (_, index) =>
    deterministicToken(`${label}-context-${index}`));
  const sessionId = randomUUID();
  const redeemed = await store.redeem({
    recoveryId: pending.recoveryId,
    recoveryToken,
    contextProofs,
    sessionId,
    sessionTokenHash: sha256(`${label}-recovery-session`),
    csrfHash: sha256(`${label}-recovery-csrf`),
    sessionExpiresAt: futureMinutes(10),
    requestId: randomUUID(),
    userAgentHash: sha256(`${label}-ua`),
    ipPrefixHash: sha256(`${label}-ip`),
  });
  expect(redeemed).toMatchObject({
    recovered: true,
    sessionId,
    rotated: false,
    version: 3,
  });
  return { ...pending, recoveryToken, contextProofs, sessionId };
}

async function insertIdentity(database: Pool, input: {
  identityId: string;
  email: string;
  displayName: string;
  mfaRequired: boolean;
}): Promise<void> {
  await database.query(
    `INSERT INTO platform_identities(
       id,email,normalized_email,display_name,password_hash,password_provisioned,
       mfa_enabled,mfa_required,status
     ) VALUES ($1,$2,lower($2),$3,$4,false,false,$5,'active')`,
    [input.identityId, input.email, input.displayName, DISABLED_PASSWORD_HASH, input.mfaRequired],
  );
}

async function insertAdmin(database: Pool, tenantId: string, label: string): Promise<FixtureActor> {
  const identityId = randomUUID();
  await insertIdentity(database, {
    identityId,
    email: `${label}@invalid.example`,
    displayName: label,
    mfaRequired: false,
  });
  await database.query(
    "INSERT INTO tenant_memberships(tenant_id,identity_id,status,is_default) VALUES ($1,$2,'active',true)",
    [tenantId, identityId],
  );
  await database.query(
    "INSERT INTO platform_role_bindings(identity_id,role_code) VALUES ($1,'platform_admin')",
    [identityId],
  );
  const credentialId = await insertCredential(database, identityId, label);
  await database.query(
    `UPDATE platform_identities
        SET passkey_enabled=true,passkey_enrolled_at=clock_timestamp()
      WHERE id=$1`,
    [identityId],
  );
  const sessionId = randomUUID();
  await database.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
       assurance_level,mfa_verified_at,auth_method,aal,phishing_resistant,
       authenticated_credential_id,recovery_limited,idle_timeout_minutes,idle_expires_at
     ) VALUES (
       $1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour','mfa',clock_timestamp(),
       'passkey',2,true,$6,false,30,clock_timestamp()+interval '30 minutes'
     )`,
    [sessionId, sha256(`${label}-session`), sha256(`${label}-csrf`), identityId, tenantId, credentialId],
  );
  return { identityId, sessionId, credentialId };
}

async function insertCredential(database: Pool, identityId: string, label: string): Promise<string> {
  const credentialId = randomUUID();
  await database.query(
    `INSERT INTO webauthn_credentials(
       id,identity_id,credential_id,public_key,user_handle,device_type,backup_eligible,
       backup_state,discoverable,user_verified,trust_level,rp_id,display_name
     ) VALUES ($1,$2,$3,$4,$5,'multiDevice',true,false,true,true,'attested','localhost',$6)`,
    [
      credentialId,
      identityId,
      deterministicToken(`${label}-credential`),
      Buffer.alloc(32, 7),
      deterministicToken(`${label}-handle`).slice(0, 32),
      `Passkey ${label}`.slice(0, 120),
    ],
  );
  return credentialId;
}

async function insertStepUpGrant(
  database: Pool,
  actor: FixtureActor,
  operationHash: string,
): Promise<string> {
  const tokenHash = sha256(`step-up-${randomUUID()}`);
  await database.query(
    `INSERT INTO authentication_step_up_grants(
       token_hash,identity_id,tenant_id,session_id,credential_id,purpose,operation_hash,
       expires_at
     ) SELECT $1,$2,session.active_tenant_id,$3,$4,'platform_administration',$5,
              clock_timestamp()+interval '5 minutes'
         FROM auth_sessions session WHERE session.id=$3`,
    [tokenHash, actor.identityId, actor.sessionId, actor.credentialId, operationHash],
  );
  return tokenHash;
}

async function insertEnrollmentSession(
  database: Pool,
  identityId: string,
  tenantId: string,
  invitationId: string,
  label: string,
): Promise<string> {
  const sessionId = randomUUID();
  await database.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
       assurance_level,mfa_verified_at,auth_method,aal,phishing_resistant,
       authenticated_credential_id,recovery_limited,idle_timeout_minutes,idle_expires_at,
       enrollment_source,invitation_id
     ) VALUES (
       $1,$2,$3,$4,$5,clock_timestamp()+interval '9 minutes','enrollment_only',NULL,
       'bootstrap',1,false,NULL,false,10,clock_timestamp()+interval '9 minutes',
       'invitation',$6
     )`,
    [sessionId, sha256(`${label}-session`), sha256(`${label}-csrf`), identityId, tenantId, invitationId],
  );
  return sessionId;
}

async function insertPasswordSession(
  database: Pool,
  identityId: string,
  tenantId: string,
  label: string,
): Promise<string> {
  const sessionId = randomUUID();
  await database.query(
    `INSERT INTO auth_sessions(
       id,token_hash,csrf_hash,identity_id,active_tenant_id,expires_at,
       assurance_level,auth_method,aal,phishing_resistant,recovery_limited,
       idle_timeout_minutes,idle_expires_at
     ) VALUES (
       $1,$2,$3,$4,$5,clock_timestamp()+interval '1 hour','password','password',1,
       false,false,30,clock_timestamp()+interval '30 minutes'
     )`,
    [sessionId, sha256(`${label}-session`), sha256(`${label}-csrf`), identityId, tenantId],
  );
  return sessionId;
}

async function insertRegistrationCeremony(
  database: Pool,
  identityId: string,
  tenantId: string,
  sourceSessionId: string,
  label: string,
): Promise<CeremonyFixture> {
  const id = randomUUID();
  const tokenHash = sha256(`${label}-token`);
  const challengeHash = sha256(`${label}-challenge`);
  await database.query(
    `INSERT INTO webauthn_ceremonies(
       id,token_hash,challenge_hash,ceremony_type,identity_id,tenant_id,session_id,
       rp_id,expected_origin,require_user_verification,policy_version,expires_at
     ) VALUES (
       $1,$2,$3,'registration',$4,$5,$6,'localhost','http://localhost:3000',true,1,
       clock_timestamp()+interval '5 minutes'
     )`,
    [id, tokenHash, challengeHash, identityId, tenantId, sourceSessionId],
  );
  return { id, tokenHash, challengeHash, sourceSessionId, rpId: "localhost" };
}

function passkeyCompletionInput(ceremony: CeremonyFixture, label: string) {
  return {
    ceremonyId: ceremony.id,
    tokenHash: ceremony.tokenHash,
    challengeHash: ceremony.challengeHash,
    credential: {
      externalId: deterministicToken(`${label}-external`),
      publicKey: Buffer.alloc(64, 9),
      userHandle: deterministicToken(`${label}-user-handle`).slice(0, 32),
      counter: 0,
      transports: ["internal"] as const,
      aaguid: randomUUID(),
      attachment: "platform" as const,
      deviceType: "multiDevice" as const,
      backupEligible: true,
      backedUp: false,
      discoverable: true,
      userVerified: true,
      attestationFormat: "packed",
      trustLevel: "attested" as const,
      attestationObjectHash: sha256(`${label}-attestation`),
      rpId: ceremony.rpId,
      displayName: `Recovery passkey ${label}`,
    },
    newSession: {
      tokenHash: sha256(`${label}-session-token`),
      csrfHash: sha256(`${label}-session-csrf`),
      expiresAt: futureMinutes(60),
      userAgentHash: sha256(`${label}-ua`),
      ipPrefixHash: sha256(`${label}-ip`),
      deviceLabel: "Recovery security key",
    },
    requestId: randomUUID(),
  };
}

async function expectSqlState(promise: Promise<unknown>, expectedCode: string): Promise<void> {
  try {
    await promise;
    throw new Error(`Expected PostgreSQL SQLSTATE ${expectedCode}`);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Expected PostgreSQL")) throw error;
    expect((error as { code?: string }).code).toBe(expectedCode);
  }
}

function sqlStateOf(result: PromiseSettledResult<unknown>): string | undefined {
  if (result.status === "fulfilled") return undefined;
  return (result.reason as { code?: string }).code;
}

async function expectGrantUnused(database: Pool, tokenHash: string): Promise<void> {
  const result = await database.query<{ consumed_at: Date | null; revoked_at: Date | null }>(
    "SELECT consumed_at,revoked_at FROM authentication_step_up_grants WHERE token_hash=$1",
    [tokenHash],
  );
  expect(result.rows[0]).toEqual({ consumed_at: null, revoked_at: null });
}

async function expectTargetQuarantined(database: Pool, fixture: RecoveryFixture): Promise<void> {
  const target = await database.query<{
    active_sessions: string;
    pending_challenges: string;
    pending_grants: string;
    pending_ceremonies: string;
    admin_sessions: string;
  }>(
    `SELECT
       (SELECT count(*)::text FROM auth_sessions WHERE identity_id=$1 AND revoked_at IS NULL) AS active_sessions,
       (SELECT count(*)::text FROM mfa_challenges WHERE identity_id=$1 AND consumed_at IS NULL) AS pending_challenges,
       (SELECT count(*)::text FROM authentication_step_up_grants
         WHERE identity_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL) AS pending_grants,
       (SELECT count(*)::text FROM webauthn_ceremonies
         WHERE identity_id=$1 AND consumed_at IS NULL AND failed_at IS NULL) AS pending_ceremonies,
       (SELECT count(*)::text FROM auth_sessions
         WHERE identity_id IN ($2,$3) AND revoked_at IS NULL) AS admin_sessions`,
    [fixture.targetIdentityId, fixture.requester.identityId, fixture.approver.identityId],
  );
  expect(target.rows[0]).toEqual({
    active_sessions: "0",
    pending_challenges: "0",
    pending_grants: "0",
    pending_ceremonies: "0",
    admin_sessions: "2",
  });
}

async function redeemDirect(database: Pool, input: {
  recoveryId: string;
  recoveryToken?: string;
  contextProofs: readonly string[];
}): Promise<unknown> {
  return database.query(
    "SELECT * FROM redeem_initial_admin_onboarding_recovery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    [
      input.recoveryId,
      input.recoveryToken ?? null,
      [...input.contextProofs],
      randomUUID(),
      sha256("direct-session"),
      sha256("direct-csrf"),
      futureMinutes(10),
      sha256("direct-ua"),
      sha256("direct-ip"),
      randomUUID(),
    ],
  );
}

async function recoveryStatus(database: Pool, recoveryId: string): Promise<string | undefined> {
  const result = await database.query<{ status: string }>(
    "SELECT status FROM initial_admin_onboarding_recoveries WHERE id=$1",
    [recoveryId],
  );
  return result.rows[0]?.status;
}

async function recoveryAudit(
  database: Pool,
  recoveryId: string,
): Promise<readonly { action: string; actor_identity_id: string | null }[]> {
  const result = await database.query<{ action: string; actor_identity_id: string | null }>(
    `SELECT action,actor_identity_id
       FROM platform_audit_events
      WHERE entity_type='initial_admin_onboarding_recovery' AND entity_id=$1
      ORDER BY sequence`,
    [recoveryId],
  );
  return result.rows;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function deterministicToken(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function recoveryCodeHashes(label: string): readonly string[] {
  return Array.from(
    { length: 10 },
    (_, index) => `${DISABLED_PASSWORD_HASH}.${sha256(`${label}-recovery-code-${index}`)}`,
  );
}

function futureMinutes(minutes: number): Date {
  return new Date(Date.now() + minutes * 60_000);
}

async function withTemporaryDatabase(run: (database: Pool) => Promise<void>): Promise<void> {
  if (!adminUrl) throw new Error("Workspace administrator URL is unavailable");
  const databaseName = `nom_init_admin_recovery_${randomBytes(8).toString("hex")}`;
  const cluster = new Pool({
    connectionString: databaseUrl(adminUrl, "postgres"),
    application_name: "nombramientos-initial-admin-recovery-cluster",
    max: 1,
  });
  const database = new Pool({
    connectionString: databaseUrl(adminUrl, databaseName),
    application_name: "nombramientos-initial-admin-recovery-database",
    max: 4,
  });
  await runWithCleanup(async () => {
    await executeFormatted(
      cluster,
      "SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L', $1::text, 'UTF8') AS sql",
      [databaseName],
    );
    await run(database);
  }, () => cleanupInitialAdminRecoveryDatabase(cluster, database, databaseName), "Initial-admin recovery live case");
}

async function createMigrationTable(database: Pool): Promise<void> {
  await database.query(`CREATE TABLE schema_migrations (
    name text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
  )`);
}

async function applyMigrationsThrough(database: Pool, maximumMigration: number): Promise<void> {
  const migrations = readdirSync(migrationsDirectory)
    .filter((file) => /^\d+_.+\.sql$/u.test(file) && Number(file.slice(0, 3)) <= maximumMigration)
    .sort((left, right) => left.localeCompare(right));
  for (const migration of migrations) {
    const sql = readFileSync(path.join(migrationsDirectory, migration), "utf8");
    const client = await database.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO schema_migrations(name,checksum) VALUES ($1,$2)",
        [migration, createHash("sha256").update(sql).digest("hex")],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}

async function executeFormatted(pool: Pool, query: string, values: readonly unknown[]): Promise<void> {
  const formatted = await pool.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the recovery test statement");
  await pool.query(sql);
}

async function executeClientFormatted(
  client: PoolClient,
  query: string,
  values: readonly unknown[],
): Promise<void> {
  const formatted = await client.query<{ sql: string }>(query, [...values]);
  const sql = formatted.rows[0]?.sql;
  if (!sql) throw new Error("PostgreSQL did not format the recovery ACL statement");
  await client.query(sql);
}

async function cleanupInitialAdminRecoveryDatabase(cluster: Pool, database: Pool, databaseName: string): Promise<void> {
  await cleanupTemporaryDatabases({
    maintenancePool: cluster,
    targets: [{ databaseName, databasePools: [database], assertSafeDatabaseName: assertInitialAdminRecoveryDatabaseName }],
    label: "Temporary initial-admin recovery database",
  });
}

function assertInitialAdminRecoveryDatabaseName(databaseName: string): void {
  if (!/^nom_init_admin_recovery_[0-9a-f]{16}$/u.test(databaseName)) {
    throw new Error("Refusing to drop a non-recovery test database");
  }
}

function discoverAdminUrl(): string | undefined {
  try {
    let candidate = process.env["TEST_DATABASE_ADMIN_URL"];
    if (!candidate && existsSync(installFile)) {
      const parsed: unknown = JSON.parse(readFileSync(installFile, "utf8"));
      if (parsed && typeof parsed === "object" && "DATABASE_ADMIN_URL" in parsed
          && typeof parsed.DATABASE_ADMIN_URL === "string") {
        candidate = parsed.DATABASE_ADMIN_URL;
      }
    }
    if (!candidate) return undefined;
    return assertWorkspacePostgresUrl(candidate, "nom_admin", "postgres").toString();
  } catch {
    return undefined;
  }
}

async function canReachWorkspace(databaseAdminUrl: string): Promise<boolean> {
  const pool = new Pool({
    connectionString: databaseUrl(databaseAdminUrl, "postgres"),
    connectionTimeoutMillis: 1_500,
    max: 1,
  });
  try {
    const result = await pool.query<{ version: number; port: number }>(
      "SELECT current_setting('server_version_num')::int AS version,current_setting('port')::int AS port",
    );
    return (result.rows[0]?.version ?? 0) >= 180_000 && result.rows[0]?.port === WORKSPACE_PORT;
  } catch {
    return false;
  } finally {
    await pool.end();
  }
}

function databaseUrl(databaseAdminUrl: string, databaseName: string): string {
  if (!/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)) throw new Error("Invalid local database name");
  const url = new URL(databaseAdminUrl);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || Number(url.port || "5432") !== WORKSPACE_PORT) {
    throw new Error("Initial-admin recovery tests refuse PostgreSQL outside loopback:55432");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}
