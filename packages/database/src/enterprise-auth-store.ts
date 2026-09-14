import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";

export type WebAuthnCeremonyType = "registration" | "authentication" | "step_up";
export type AuthenticationAssuranceLevel = "enrollment_only" | "password" | "mfa" | "recovery_limited";
export type AuthenticationMethod = "password" | "totp" | "recovery_code" | "passkey" | "federated" | "bootstrap";
export type PasskeyDeviceType = "singleDevice" | "multiDevice";
export type PasskeyTransport = "ble" | "cable" | "hybrid" | "internal" | "nfc" | "smart-card" | "usb";
export type PasskeyTrustLevel = "unverified" | "self" | "attested" | "enterprise_attested";
export type PasskeyRevocationReason = "user_revoked" | "admin_revoked" | "compromised" | "replaced" | "policy_change";

export interface WebAuthnCeremonyCreateInput {
  readonly tokenHash: string;
  readonly challengeHash: string;
  readonly type: WebAuthnCeremonyType;
  readonly identityId?: string;
  readonly tenantId?: string;
  readonly sessionId?: string;
  readonly purpose?: string;
  readonly operationHash?: string;
  readonly rpId: string;
  readonly expectedOrigin: string;
  readonly requireUserVerification: boolean;
  readonly policyVersion: number;
  readonly replacementCredentialId?: string;
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
  readonly expiresAt: Date;
}

export interface WebAuthnCeremonyRecord {
  readonly id: string;
  readonly type: WebAuthnCeremonyType;
  readonly challengeHash: string;
  readonly identityId: string | null;
  readonly tenantId: string | null;
  readonly sessionId: string | null;
  readonly purpose: string | null;
  readonly operationHash: string | null;
  readonly rpId: string;
  readonly expectedOrigin: string;
  readonly requireUserVerification: boolean;
  readonly policyVersion: number;
  readonly replacementCredentialId: string | null;
  readonly userAgentHash: string | null;
  readonly ipPrefixHash: string | null;
  readonly attemptCount: number;
  readonly expiresAt: Date;
}

export interface PasskeyCredentialCreateInput {
  readonly externalId: string;
  readonly publicKey: Buffer;
  readonly userHandle: string;
  readonly counter: number;
  readonly transports: readonly PasskeyTransport[];
  readonly aaguid?: string;
  readonly attachment?: "platform" | "cross-platform";
  readonly deviceType: PasskeyDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly discoverable: boolean;
  readonly userVerified: boolean;
  readonly attestationFormat?: string;
  readonly trustLevel?: PasskeyTrustLevel;
  readonly attestationObjectHash?: string;
  readonly rpId: string;
  readonly displayName: string;
}

export interface PasskeyCredentialVerificationRecord {
  readonly id: string;
  readonly externalId: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly publicKey: Buffer;
  readonly userHandle: string;
  readonly counter: number;
  readonly transports: readonly PasskeyTransport[];
  readonly deviceType: PasskeyDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly userVerified: boolean;
  readonly trustLevel: PasskeyTrustLevel;
  readonly rpId: string;
  readonly revokedAt: Date | null;
}

export interface PasskeyCredentialSummary {
  readonly id: string;
  readonly externalId: string;
  readonly displayName: string;
  readonly attachment: "platform" | "cross-platform" | null;
  readonly deviceType: PasskeyDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly discoverable: boolean;
  readonly userVerified: boolean;
  readonly aaguid: string | null;
  readonly transports: readonly PasskeyTransport[];
  readonly trustLevel: PasskeyTrustLevel;
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly revocationReason: PasskeyRevocationReason | null;
  readonly version: number;
}

export interface EnterpriseSessionCreateInput {
  readonly tokenHash: string;
  readonly csrfHash: string;
  readonly expiresAt: Date;
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
  readonly deviceLabel?: string;
}

export interface IdentitySessionSummary {
  readonly id: string;
  readonly tenantId: string;
  readonly tenantName: string;
  readonly isCurrent: boolean;
  readonly assuranceLevel: AuthenticationAssuranceLevel;
  readonly authMethod: AuthenticationMethod;
  readonly aal: 1 | 2 | 3;
  readonly phishingResistant: boolean;
  readonly recoveryLimited: boolean;
  readonly deviceLabel: string | null;
  readonly credentialId: string | null;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly expiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly ipContextChanged: boolean;
}

export interface IdentityActionRequirement {
  readonly minAal: 1 | 2 | 3;
  readonly phishingResistant?: boolean;
  readonly stepUpRequired?: boolean;
}

export interface IdentityPolicyValues {
  readonly enforcementMode: "monitor" | "enforce";
  readonly minimumAal: 1 | 2 | 3;
  readonly privilegedMinimumAal: 2 | 3;
  readonly requireUserVerification: boolean;
  readonly requirePhishingResistantForPrivileged: boolean;
  readonly requireDeviceBoundForPrivileged: boolean;
  readonly requireAttestationForPrivileged: boolean;
  readonly allowPassword: boolean;
  readonly allowTotpFallback: boolean;
  readonly allowRecoveryCodes: boolean;
  readonly allowSyncedPasskeys: boolean;
  readonly minimumPasskeyCount: number;
  readonly privilegedMinimumPasskeyCount: number;
  readonly maximumPasskeys: number;
  readonly maximumActiveSessions: number;
  readonly idleTimeoutMinutes: number;
  readonly absoluteSessionMinutes: number;
  readonly stepUpTtlSeconds: number;
  readonly actionRequirements: Readonly<Record<string, IdentityActionRequirement>>;
}

export interface EffectiveIdentityPolicy extends IdentityPolicyValues {
  readonly tenantId: string;
  readonly baselineVersion: number;
  readonly tenantVersion: number | null;
}

export class EnterpriseAuthStoreError extends Error {
  public constructor(
    public readonly code:
      | "CEREMONY_INVALID"
      | "CREDENTIAL_CONFLICT"
      | "CREDENTIAL_INVALID"
      | "CREDENTIAL_REPLAYED"
      | "PASSKEY_LIMIT_REACHED"
      | "POLICY_CONFLICT"
      | "RECOVERY_GOVERNANCE_INVALID"
      | "SESSION_INVALID"
      | "STEP_UP_INVALID",
    message: string,
  ) {
    super(message);
    this.name = "EnterpriseAuthStoreError";
  }
}

export class EnterpriseAuthStore {
  public constructor(private readonly pool: Pool) {}

  public async createCeremony(input: WebAuthnCeremonyCreateInput): Promise<WebAuthnCeremonyRecord> {
    assertSha256(input.tokenHash, "ceremony token");
    assertSha256(input.challengeHash, "WebAuthn challenge");
    if (input.operationHash !== undefined) assertSha256(input.operationHash, "operation");
    if (input.expiresAt.getTime() <= Date.now() || input.expiresAt.getTime() > Date.now() + 10 * 60_000) {
      throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony expiry is outside the permitted window");
    }
    assertCeremonyShape(input);

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      if (input.sessionId && input.identityId && input.tenantId) {
        const allowed = await client.query<{ assurance_level: AuthenticationAssuranceLevel }>(
          `SELECT session.assurance_level
             FROM auth_sessions session
             JOIN platform_identities identity ON identity.id=session.identity_id
             JOIN tenants tenant ON tenant.id=session.active_tenant_id
             JOIN tenant_memberships membership
               ON membership.identity_id=identity.id AND membership.tenant_id=tenant.id
            WHERE session.id=$1 AND session.identity_id=$2 AND session.active_tenant_id=$3
              AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
              AND session.idle_expires_at>clock_timestamp()
              AND identity.status='active' AND tenant.status='active' AND membership.status='active'
            FOR UPDATE OF session`,
          [input.sessionId, input.identityId, input.tenantId],
        );
        const assurance = allowed.rows[0]?.assurance_level;
        if (!assurance || (input.type === "step_up" && ["enrollment_only", "recovery_limited"].includes(assurance))) {
          throw new EnterpriseAuthStoreError("SESSION_INVALID", "The source session cannot start this WebAuthn ceremony");
        }
        await client.query(
          `UPDATE webauthn_ceremonies
              SET consumed_at=COALESCE(consumed_at,clock_timestamp())
            WHERE session_id=$1 AND ceremony_type=$2
              AND consumed_at IS NULL AND failed_at IS NULL`,
          [input.sessionId, input.type],
        );
      }
      if (input.replacementCredentialId) {
        const replacement = await client.query(
          `SELECT 1
             FROM webauthn_credentials
            WHERE id=$1 AND identity_id=$2 AND rp_id=$3 AND revoked_at IS NULL
            FOR SHARE`,
          [input.replacementCredentialId, input.identityId ?? null, input.rpId],
        );
        if (replacement.rowCount !== 1) {
          throw new EnterpriseAuthStoreError(
            "CREDENTIAL_INVALID",
            "The passkey selected for replacement is unavailable",
          );
        }
      }
      const created = await client.query<CeremonyRow>(
        `INSERT INTO webauthn_ceremonies(
           token_hash,challenge_hash,ceremony_type,identity_id,tenant_id,session_id,
           purpose,operation_hash,rp_id,expected_origin,require_user_verification,
           policy_version,replacement_credential_id,user_agent_hash,ip_prefix_hash,expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
         RETURNING id,ceremony_type,challenge_hash,identity_id,tenant_id,session_id,
                   purpose,operation_hash,rp_id,expected_origin,require_user_verification,
                   policy_version,replacement_credential_id,user_agent_hash,ip_prefix_hash,
                   attempt_count,expires_at`,
        [
          input.tokenHash,
          input.challengeHash,
          input.type,
          input.identityId ?? null,
          input.tenantId ?? null,
          input.sessionId ?? null,
          input.purpose ?? null,
          input.operationHash ?? null,
          input.rpId,
          input.expectedOrigin,
          input.requireUserVerification,
          input.policyVersion,
          input.replacementCredentialId ?? null,
          input.userAgentHash ?? null,
          input.ipPrefixHash ?? null,
          input.expiresAt,
        ],
      );
      const row = created.rows[0];
      if (!row) throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony was not created");
      await client.query("COMMIT");
      return mapCeremony(row);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony token or challenge was already used");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async getActiveCeremony(input: {
    readonly id: string;
    readonly tokenHash: string;
    readonly type?: WebAuthnCeremonyType;
  }): Promise<WebAuthnCeremonyRecord | null> {
    assertSha256(input.tokenHash, "ceremony token");
    const result = await this.pool.query<CeremonyRow>(
      `SELECT id,ceremony_type,challenge_hash,identity_id,tenant_id,session_id,
              purpose,operation_hash,rp_id,expected_origin,require_user_verification,
              policy_version,replacement_credential_id,user_agent_hash,ip_prefix_hash,
              attempt_count,expires_at
         FROM webauthn_ceremonies
        WHERE id=$1 AND token_hash=$2
          AND ($3::text IS NULL OR ceremony_type=$3)
          AND consumed_at IS NULL AND failed_at IS NULL
          AND expires_at>clock_timestamp() AND attempt_count<6`,
      [input.id, input.tokenHash, input.type ?? null],
    );
    return result.rows[0] ? mapCeremony(result.rows[0]) : null;
  }

  public async failCeremony(input: { readonly id: string; readonly tokenHash: string }): Promise<void> {
    assertSha256(input.tokenHash, "ceremony token");
    await this.pool.query(
      `UPDATE webauthn_ceremonies
          SET attempt_count=LEAST(6,attempt_count+1),
              failed_at=CASE WHEN attempt_count+1>=6 THEN clock_timestamp() ELSE failed_at END
        WHERE id=$1 AND token_hash=$2 AND consumed_at IS NULL AND failed_at IS NULL`,
      [input.id, input.tokenHash],
    );
  }

  public async getCredentialByExternalId(
    externalId: string,
    rpId?: string,
  ): Promise<PasskeyCredentialVerificationRecord | null> {
    const result = await this.pool.query<CredentialVerificationRow>(
      `SELECT credential.id,credential.credential_id,credential.identity_id,membership.tenant_id,
              credential.public_key,credential.user_handle,credential.sign_count::text,
              credential.transports,credential.device_type,credential.backup_eligible,
              credential.backup_state,credential.user_verified,credential.trust_level,
              credential.rp_id,credential.revoked_at
         FROM webauthn_credentials credential
         JOIN LATERAL (
           SELECT candidate.tenant_id
             FROM tenant_memberships candidate
             JOIN tenants tenant ON tenant.id=candidate.tenant_id
            WHERE candidate.identity_id=credential.identity_id
              AND candidate.status='active' AND tenant.status='active'
            ORDER BY candidate.is_default DESC,candidate.created_at,candidate.tenant_id
            LIMIT 1
         ) membership ON true
        WHERE credential.credential_id=$1
          AND ($2::text IS NULL OR credential.rp_id=$2)
          AND credential.revoked_at IS NULL`,
      [externalId, rpId ?? null],
    );
    return result.rows[0] ? mapCredentialVerification(result.rows[0]) : null;
  }

  public async completeRegistration(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly sourceSessionId?: string;
    readonly credential: PasskeyCredentialCreateInput;
    readonly newSession: EnterpriseSessionCreateInput;
    readonly requestId: string;
  }): Promise<{ readonly credentialId: string; readonly sessionId: string; readonly identityId: string; readonly tenantId: string }> {
    assertCompletionHashes(input);
    validateCredentialCreate(input.credential);
    validateSessionInput(input.newSession);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // First lock after BEGIN: serialize all passkey enrollment (including
      // original invitation sessions) with governed recovery approval/redeem.
      const recoveryAuthorization = await client.query<{
        source_session_id: string;
        authorization: string;
      }>(
        `WITH source AS (
           SELECT ceremony.session_id AS source_session_id
             FROM webauthn_ceremonies ceremony
            WHERE ceremony.id=$2 AND ceremony.ceremony_type='registration'
              AND ($1::uuid IS NULL OR ceremony.session_id=$1)
         )
         SELECT source.source_session_id,
                authorize_initial_admin_recovery_factor_transaction(
                  source.source_session_id,$3
                ) AS authorization
           FROM source`,
        [input.sourceSessionId ?? null, input.ceremonyId, input.requestId],
      );
      const authorizationRow = recoveryAuthorization.rows[0];
      const authorization = authorizationRow?.authorization;
      const sourceSessionId = authorizationRow?.source_session_id;
      if (authorization === "governance_invalidated") {
        await client.query("COMMIT");
        throw new EnterpriseAuthStoreError(
          "RECOVERY_GOVERNANCE_INVALID",
          "Initial-admin recovery authority was withdrawn",
        );
      }
      if (authorization !== "authorized" && authorization !== "not_recovery") {
        throw new EnterpriseAuthStoreError("SESSION_INVALID", "Passkey recovery context is unavailable");
      }
      const ceremonyIdentityId = await lockRegistrationIdentity(client, input.ceremonyId);
      const ceremony = await lockCeremony(client, input, "registration");
      if (!ceremony.identity_id || !ceremony.tenant_id || !ceremony.session_id
          || ceremony.session_id !== sourceSessionId
          || ceremony.rp_id !== input.credential.rpId) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Passkey registration ceremony context is invalid");
      }
      if (ceremony.identity_id !== ceremonyIdentityId) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Passkey registration identity changed unexpectedly");
      }
      const source = await client.query<{ assurance_level: AuthenticationAssuranceLevel }>(
        `SELECT assurance_level FROM auth_sessions
          WHERE id=$1 AND identity_id=$2 AND active_tenant_id=$3
            AND revoked_at IS NULL AND expires_at>clock_timestamp()
            AND idle_expires_at>clock_timestamp()
          FOR UPDATE`,
        [ceremony.session_id, ceremony.identity_id, ceremony.tenant_id],
      );
      const sourceAssurance = source.rows[0]?.assurance_level;
      if (!sourceAssurance) throw new EnterpriseAuthStoreError("SESSION_INVALID", "Passkey registration source session is invalid");

      const lockedCredentials = await client.query<CredentialPolicyRow>(
        `SELECT id,device_type,trust_level,user_verified,rp_id
           FROM webauthn_credentials
          WHERE identity_id=$1 AND revoked_at IS NULL
          ORDER BY id FOR UPDATE`,
        [ceremony.identity_id],
      );
      const credentialCount = lockedCredentials.rows.length;
      if (["enrollment_only", "password"].includes(sourceAssurance) && credentialCount !== 0) {
        throw new EnterpriseAuthStoreError(
          "SESSION_INVALID",
          "A password or enrollment-only session cannot add another passkey",
        );
      }
      const policy = await getEffectivePolicyRow(client, ceremony.tenant_id);
      if (Number(ceremony.policy_version) !== Number(policy.tenant_version ?? policy.baseline_version)) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Identity policy changed during WebAuthn registration");
      }
      const replacement = ceremony.replacement_credential_id
        ? lockedCredentials.rows.find(({ id }) => id === ceremony.replacement_credential_id) ?? null
        : null;
      if (ceremony.replacement_credential_id && (!replacement || replacement.rp_id !== ceremony.rp_id)) {
        throw new EnterpriseAuthStoreError(
          "CREDENTIAL_INVALID",
          "The passkey selected for replacement is unavailable or revoked",
        );
      }
      if (credentialCount >= policy.maximum_passkeys && !replacement) {
        throw new EnterpriseAuthStoreError("PASSKEY_LIMIT_REACHED", "The identity reached the active passkey limit");
      }
      if (ceremony.require_user_verification && !input.credential.userVerified) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey registration requires user verification");
      }
      await assertCredentialSetPreservesIdentityPolicies(
        client,
        ceremony.identity_id,
        lockedCredentials.rows,
        lockedCredentials.rows
          .filter(({ id }) => id !== replacement?.id)
          .concat({
            id: "registration-candidate",
            device_type: input.credential.deviceType,
            trust_level: input.credential.trustLevel ?? "unverified",
            user_verified: input.credential.userVerified,
            rp_id: input.credential.rpId,
          }),
        { candidateDeviceType: input.credential.deviceType },
      );

      if (replacement) {
        const revoked = await client.query(
          `UPDATE webauthn_credentials
              SET revoked_at=clock_timestamp(),revoked_by_identity_id=$2,
                  revocation_reason='replaced',version=version+1
            WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL`,
          [replacement.id, ceremony.identity_id],
        );
        if (revoked.rowCount !== 1) {
          throw new EnterpriseAuthStoreError(
            "CREDENTIAL_INVALID",
            "The passkey selected for replacement is no longer active",
          );
        }
      }

      const credential = await client.query<{ id: string }>(
        `INSERT INTO webauthn_credentials(
           identity_id,credential_id,public_key,user_handle,sign_count,transports,aaguid,
           attachment,device_type,backup_eligible,backup_state,discoverable,user_verified,
           attestation_format,trust_level,attestation_object_hash,rp_id,display_name,
           created_by_session_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
         RETURNING id`,
        [
          ceremony.identity_id,
          input.credential.externalId,
          input.credential.publicKey,
          input.credential.userHandle,
          input.credential.counter,
          [...new Set(input.credential.transports)],
          input.credential.aaguid ?? null,
          input.credential.attachment ?? null,
          input.credential.deviceType,
          input.credential.backupEligible,
          input.credential.backedUp,
          input.credential.discoverable,
          input.credential.userVerified,
          input.credential.attestationFormat ?? null,
          input.credential.trustLevel ?? "unverified",
          input.credential.attestationObjectHash ?? null,
          input.credential.rpId,
          input.credential.displayName.trim(),
          ceremony.session_id,
        ],
      );
      const credentialId = credential.rows[0]?.id;
      if (!credentialId) throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey was not persisted");

      await client.query(
        `UPDATE platform_identities
            SET passkey_enabled=true,
                passkey_enrolled_at=COALESCE(passkey_enrolled_at,clock_timestamp()),
                updated_at=clock_timestamp()
          WHERE id=$1`,
        [ceremony.identity_id],
      );
      await revokeAllIdentitySessions(client, ceremony.identity_id, "passkey_enrollment_completed");
      await client.query(
        `UPDATE mfa_challenges SET consumed_at=COALESCE(consumed_at,clock_timestamp())
          WHERE identity_id=$1 AND consumed_at IS NULL`,
        [ceremony.identity_id],
      );
      await client.query(
        `UPDATE webauthn_ceremonies
            SET consumed_at=COALESCE(consumed_at,clock_timestamp())
          WHERE identity_id=$1 AND id<>$2 AND consumed_at IS NULL AND failed_at IS NULL`,
        [ceremony.identity_id, ceremony.id],
      );
      const sessionId = await insertPasskeySession(
        client,
        ceremony.identity_id,
        ceremony.tenant_id,
        credentialId,
        input.newSession,
        policy,
      );
      await client.query(
        `UPDATE webauthn_credentials
            SET last_used_at=clock_timestamp(),last_used_session_id=$2,version=version+1
          WHERE id=$1`,
        [credentialId, sessionId],
      );
      await consumeLockedCeremony(client, ceremony.id);
      const finalization = await client.query<{ recovery_id: string }>(
        "SELECT recovery_id FROM finalize_initial_admin_onboarding_recovery($1,$2,$3)",
        [ceremony.session_id, sessionId, input.requestId],
      );
      if (authorization === "authorized" && finalization.rowCount !== 1) {
        throw new EnterpriseAuthStoreError(
          "RECOVERY_GOVERNANCE_INVALID",
          "Initial-admin recovery could not be finalized atomically",
        );
      }
      await appendPlatformAudit(client, {
        actorIdentityId: ceremony.identity_id,
        tenantId: ceremony.tenant_id,
        action: "auth.passkey_registered",
        entityType: "webauthn_credential",
        entityId: credentialId,
        requestId: input.requestId,
        metadata: {
          deviceType: input.credential.deviceType,
          backupEligible: input.credential.backupEligible,
          backedUp: input.credential.backedUp,
          trustLevel: input.credential.trustLevel ?? "unverified",
          sessionsRotated: true,
          replacement: replacement !== null,
          initialAdminRecoveryFinalized: authorization === "authorized",
          ...(replacement ? { replacedCredentialId: replacement.id } : {}),
        },
      });
      await client.query("COMMIT");
      return { credentialId, sessionId, identityId: ceremony.identity_id, tenantId: ceremony.tenant_id };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_CONFLICT", "The passkey is already registered or its name is in use");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async completeAuthentication(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly credentialId: string;
    readonly newCounter: number;
    readonly assertedDeviceType: PasskeyDeviceType;
    readonly newBackupState: boolean;
    readonly tenantId: string;
    readonly newSession: EnterpriseSessionCreateInput;
    readonly requestId: string;
  }): Promise<{ readonly sessionId: string; readonly identityId: string; readonly tenantId: string }> {
    assertCompletionHashes(input);
    assertCounter(input.newCounter);
    validateSessionInput(input.newSession);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await lockCredentialIdentity(client, input.credentialId);
      const ceremony = await lockCeremony(client, input, "authentication");
      const credential = await lockCredential(client, input.credentialId);
      if (
        credential.rp_id !== ceremony.rp_id
        || (ceremony.identity_id !== null && ceremony.identity_id !== credential.identity_id)
        || (ceremony.tenant_id !== null && ceremony.tenant_id !== input.tenantId)
      ) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey does not match the authentication ceremony");
      }
      assertCounterAdvance(credential.sign_count, input.newCounter);
      assertAuthenticatorProperties(
        credential,
        input.assertedDeviceType,
        input.newBackupState,
        "CREDENTIAL_INVALID",
      );
      await assertActiveMembership(client, credential.identity_id, input.tenantId);
      const policy = await getEffectivePolicyRow(client, input.tenantId);
      if (!policy.allow_synced_passkeys && credential.device_type === "multiDevice") {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Synced passkeys are disabled by identity policy");
      }
      await updateCredentialUsage(client, credential.id, input.newCounter, input.newBackupState);
      const sessionId = await insertPasskeySession(
        client,
        credential.identity_id,
        input.tenantId,
        credential.id,
        input.newSession,
        policy,
      );
      await client.query(
        "UPDATE webauthn_credentials SET last_used_session_id=$2 WHERE id=$1",
        [credential.id, sessionId],
      );
      await revokeExcessSessions(
        client,
        credential.identity_id,
        input.tenantId,
        sessionId,
        policy.maximum_active_sessions,
      );
      await consumeLockedCeremony(client, ceremony.id);
      await appendPlatformAudit(client, {
        actorIdentityId: credential.identity_id,
        tenantId: input.tenantId,
        action: "auth.passkey_authenticated",
        entityType: "auth_session",
        entityId: sessionId,
        requestId: input.requestId,
        metadata: { credentialId: credential.id, aal: 2, phishingResistant: true },
      });
      await client.query("COMMIT");
      return { sessionId, identityId: credential.identity_id, tenantId: input.tenantId };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async completeWebAuthnStepUp(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly credentialId: string;
    readonly newCounter: number;
    readonly assertedDeviceType: PasskeyDeviceType;
    readonly newBackupState: boolean;
    readonly grantTokenHash: string;
    readonly grantExpiresAt: Date;
    readonly requestId: string;
  }): Promise<{ readonly grantId: string; readonly expiresAt: Date }> {
    assertCompletionHashes(input);
    assertSha256(input.grantTokenHash, "step-up grant token");
    assertCounter(input.newCounter);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await lockCredentialIdentity(client, input.credentialId);
      const ceremony = await lockCeremony(client, input, "step_up");
      if (!ceremony.identity_id || !ceremony.tenant_id || !ceremony.session_id || !ceremony.purpose || !ceremony.operation_hash) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Step-up ceremony context is incomplete");
      }
      const session = await client.query<{ expires_at: Date; idle_expires_at: Date }>(
        `SELECT expires_at,idle_expires_at FROM auth_sessions
          WHERE id=$1 AND identity_id=$2 AND active_tenant_id=$3
            AND revoked_at IS NULL AND expires_at>clock_timestamp()
            AND idle_expires_at>clock_timestamp()
            AND assurance_level NOT IN ('enrollment_only','recovery_limited')
          FOR UPDATE`,
        [ceremony.session_id, ceremony.identity_id, ceremony.tenant_id],
      );
      const activeSession = session.rows[0];
      if (!activeSession) throw new EnterpriseAuthStoreError("SESSION_INVALID", "Step-up source session is invalid");
      const credential = await lockCredential(client, input.credentialId);
      if (credential.identity_id !== ceremony.identity_id || credential.rp_id !== ceremony.rp_id) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey does not belong to the step-up identity");
      }
      assertCounterAdvance(credential.sign_count, input.newCounter);
      assertAuthenticatorProperties(
        credential,
        input.assertedDeviceType,
        input.newBackupState,
        "STEP_UP_INVALID",
      );
      const policy = await getEffectivePolicyRow(client, ceremony.tenant_id);
      const effectivePolicyVersion = Number(policy.tenant_version ?? policy.baseline_version);
      if (Number(ceremony.policy_version) !== effectivePolicyVersion) {
        throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Identity policy changed during WebAuthn verification");
      }
      const personalRemediation = ["passkey_enrollment", "session_revocation"].includes(ceremony.purpose);
      if (!personalRemediation && !policy.allow_synced_passkeys && credential.device_type === "multiDevice") {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Synced passkeys are disabled by identity policy");
      }
      const maximumGrantExpiry = Math.min(
        input.grantExpiresAt.getTime(),
        Date.now() + policy.step_up_ttl_seconds * 1_000,
        ceremony.expires_at.getTime(),
        activeSession.expires_at.getTime(),
        activeSession.idle_expires_at.getTime(),
      );
      if (maximumGrantExpiry <= Date.now()) {
        throw new EnterpriseAuthStoreError("STEP_UP_INVALID", "Step-up authorization expiry is invalid");
      }
      const expiresAt = new Date(maximumGrantExpiry);
      await updateCredentialUsage(client, credential.id, input.newCounter, input.newBackupState);
      await client.query(
        `UPDATE authentication_step_up_grants
            SET revoked_at=COALESCE(revoked_at,clock_timestamp())
          WHERE session_id=$1 AND purpose=$2 AND operation_hash=$3
            AND consumed_at IS NULL AND revoked_at IS NULL`,
        [ceremony.session_id, ceremony.purpose, ceremony.operation_hash],
      );
      const grant = await client.query<{ id: string; expires_at: Date }>(
        `INSERT INTO authentication_step_up_grants(
           token_hash,identity_id,tenant_id,session_id,credential_id,purpose,operation_hash,expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING id,expires_at`,
        [
          input.grantTokenHash,
          ceremony.identity_id,
          ceremony.tenant_id,
          ceremony.session_id,
          credential.id,
          ceremony.purpose,
          ceremony.operation_hash,
          expiresAt,
        ],
      );
      const grantRow = grant.rows[0];
      if (!grantRow) throw new EnterpriseAuthStoreError("STEP_UP_INVALID", "Step-up grant was not issued");
      await client.query(
        `UPDATE auth_sessions
            SET step_up_verified_at=clock_timestamp(),step_up_method='passkey',
                step_up_credential_id=$2,step_up_purpose=$3,step_up_operation_hash=$4,
                step_up_expires_at=$5,
                last_user_agent_hash=COALESCE($6,last_user_agent_hash),
                user_agent_change_count=CASE WHEN $6::text IS NULL THEN user_agent_change_count ELSE 0 END,
                user_agent_context_changed_at=CASE WHEN $6::text IS NULL THEN user_agent_context_changed_at ELSE NULL END,
                last_ip_prefix_hash=COALESCE($7,last_ip_prefix_hash),
                ip_change_count=CASE WHEN $7::text IS NULL THEN ip_change_count ELSE 0 END,
                ip_context_changed_at=CASE WHEN $7::text IS NULL THEN ip_context_changed_at ELSE NULL END
          WHERE id=$1`,
        [
          ceremony.session_id,
          credential.id,
          ceremony.purpose,
          ceremony.operation_hash,
          expiresAt,
          ceremony.user_agent_hash,
          ceremony.ip_prefix_hash,
        ],
      );
      await consumeLockedCeremony(client, ceremony.id);
      await appendPlatformAudit(client, {
        actorIdentityId: ceremony.identity_id,
        tenantId: ceremony.tenant_id,
        action: "auth.step_up_completed",
        entityType: "auth_session",
        entityId: ceremony.session_id,
        requestId: input.requestId,
        metadata: {
          purpose: ceremony.purpose,
          credentialId: credential.id,
          aal: 2,
          phishingResistant: true,
          riskContextRebound: Boolean(ceremony.user_agent_hash || ceremony.ip_prefix_hash),
        },
      });
      await client.query("COMMIT");
      return { grantId: grantRow.id, expiresAt: grantRow.expires_at };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new EnterpriseAuthStoreError("STEP_UP_INVALID", "Step-up token was already issued");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async consumeStepUpGrant(input: {
    readonly identityId: string;
    readonly sessionId: string;
    readonly tokenHash: string;
    readonly purpose: string;
    readonly operationHash: string;
  }): Promise<boolean> {
    assertSha256(input.tokenHash, "step-up grant token");
    assertSha256(input.operationHash, "operation");
    const consumed = await this.pool.query(
      `UPDATE authentication_step_up_grants stepup_grant
          SET consumed_at=clock_timestamp()
         FROM auth_sessions session
        WHERE stepup_grant.token_hash=$1 AND stepup_grant.identity_id=$2 AND stepup_grant.session_id=$3
          AND stepup_grant.purpose=$4 AND stepup_grant.operation_hash=$5
          AND stepup_grant.consumed_at IS NULL AND stepup_grant.revoked_at IS NULL
          AND stepup_grant.expires_at>clock_timestamp()
          AND session.id=stepup_grant.session_id AND session.identity_id=stepup_grant.identity_id
          AND session.revoked_at IS NULL AND session.expires_at>clock_timestamp()
          AND session.idle_expires_at>clock_timestamp()
          AND NOT session.recovery_limited
          AND NOT EXISTS (
            SELECT 1 FROM tenant_identity_policies current_policy
             WHERE current_policy.tenant_id=stepup_grant.tenant_id
               AND current_policy.updated_at>stepup_grant.created_at
          )
          AND NOT EXISTS (
            SELECT 1 FROM identity_policy_baseline baseline
             WHERE baseline.policy_key='global' AND baseline.updated_at>stepup_grant.created_at
          )`,
      [input.tokenHash, input.identityId, input.sessionId, input.purpose, input.operationHash],
    );
    return consumed.rowCount === 1;
  }

  public async listCredentials(identityId: string): Promise<readonly PasskeyCredentialSummary[]> {
    const result = await this.pool.query<CredentialSummaryRow>(
      `SELECT id,credential_id,display_name,attachment,device_type,backup_eligible,backup_state,
              discoverable,user_verified,aaguid,transports,trust_level,created_at,last_used_at,
              revoked_at,revocation_reason,version::text
         FROM webauthn_credentials
        WHERE identity_id=$1
        ORDER BY revoked_at NULLS FIRST,last_used_at DESC NULLS LAST,created_at DESC,id`,
      [identityId],
    );
    return result.rows.map(mapCredentialSummary);
  }

  public async renameCredential(input: {
    readonly identityId: string;
    readonly credentialId: string;
    readonly displayName: string;
    readonly expectedVersion: number;
    readonly requestId: string;
  }): Promise<PasskeyCredentialSummary | null> {
    const displayName = input.displayName.trim();
    if (displayName.length < 1 || displayName.length > 120) {
      throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey name must contain 1 to 120 characters");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const updated = await client.query<CredentialSummaryRow>(
        `UPDATE webauthn_credentials
            SET display_name=$3,version=version+1
          WHERE id=$1 AND identity_id=$2 AND version=$4 AND revoked_at IS NULL
        RETURNING id,credential_id,display_name,attachment,device_type,backup_eligible,backup_state,
                  discoverable,user_verified,aaguid,transports,trust_level,created_at,last_used_at,
                  revoked_at,revocation_reason,version::text`,
        [input.credentialId, input.identityId, displayName, input.expectedVersion],
      );
      const row = updated.rows[0];
      if (row) {
        const tenantId = await defaultTenantId(client, input.identityId);
        await appendPlatformAudit(client, {
          actorIdentityId: input.identityId,
          tenantId,
          action: "auth.passkey_renamed",
          entityType: "webauthn_credential",
          entityId: input.credentialId,
          requestId: input.requestId,
          metadata: { version: Number(row.version) },
        });
      }
      await client.query("COMMIT");
      return row ? mapCredentialSummary(row) : null;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isUniqueViolation(error)) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_CONFLICT", "An active passkey already uses that name");
      }
      throw error;
    } finally {
      client.release();
    }
  }

  public async revokeCredential(input: {
    readonly identityId: string;
    readonly credentialId: string;
    readonly reason: PasskeyRevocationReason;
    readonly currentSessionId?: string;
    readonly requestId: string;
  }): Promise<{
    readonly revoked: boolean;
    readonly sessionsRevoked: number;
    readonly currentSessionRevoked: boolean;
  }> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const identityAuth = await client.query<{ mfa_enabled: boolean }>(
        `SELECT mfa_enabled FROM platform_identities
          WHERE id=$1 AND status='active' FOR UPDATE`,
        [input.identityId],
      );
      const identity = identityAuth.rows[0];
      if (!identity) {
        throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey identity is unavailable");
      }
      const lockedCredentials = await client.query<CredentialPolicyRow>(
        `SELECT id,device_type,trust_level,user_verified,rp_id FROM webauthn_credentials
          WHERE identity_id=$1 AND revoked_at IS NULL
          ORDER BY id FOR UPDATE`,
        [input.identityId],
      );
      if (!lockedCredentials.rows.some(({ id }) => id === input.credentialId)) {
        await client.query("COMMIT");
        return { revoked: false, sessionsRevoked: 0, currentSessionRevoked: false };
      }
      const activeRecoveryCodes = await client.query<{ id: string }>(
        `SELECT id FROM mfa_recovery_codes
          WHERE identity_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL
          ORDER BY id FOR UPDATE`,
        [input.identityId],
      );
      const tenantMemberships = await client.query<{ tenant_id: string }>(
        `SELECT membership.tenant_id
           FROM tenant_memberships membership
           JOIN tenants tenant ON tenant.id=membership.tenant_id
          WHERE membership.identity_id=$1 AND membership.status='active' AND tenant.status='active'
          ORDER BY membership.is_default DESC,membership.created_at,membership.tenant_id`,
        [input.identityId],
      );
      const remainingCredentials = lockedCredentials.rows.filter(({ id }) => id !== input.credentialId);
      await assertCredentialSetPreservesIdentityPolicies(
        client,
        input.identityId,
        lockedCredentials.rows,
        remainingCredentials,
        {},
      );
      for (const membership of tenantMemberships.rows) {
        const policy = await getEffectivePolicyRow(client, membership.tenant_id);
        const remainingEligible = eligibleCredentialCount(remainingCredentials, policy, false);
        const usablePasswordPath = policy.allow_password && (
          !identity.mfa_enabled
          || policy.allow_totp_fallback
          || (policy.allow_recovery_codes && activeRecoveryCodes.rows.length > 0)
        );
        if (!usablePasswordPath && remainingEligible === 0) {
          throw new EnterpriseAuthStoreError(
            "POLICY_CONFLICT",
            "Revoking this passkey would violate an active tenant policy or remove the last usable sign-in method",
          );
        }
      }
      const revoked = await client.query(
        `UPDATE webauthn_credentials
            SET revoked_at=clock_timestamp(),revoked_by_identity_id=$2,
                revocation_reason=$3,version=version+1
          WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL`,
        [input.credentialId, input.identityId, input.reason],
      );
      if (revoked.rowCount !== 1) throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey changed during revocation");
      const sessions = await client.query<{ id: string }>(
        `UPDATE auth_sessions
            SET revoked_at=clock_timestamp(),revoke_reason='passkey_revoked'
          WHERE identity_id=$1 AND revoked_at IS NULL
            AND (authenticated_credential_id=$2 OR step_up_credential_id=$2)
        RETURNING id`,
        [input.identityId, input.credentialId],
      );
      await client.query(
        `UPDATE authentication_step_up_grants
            SET revoked_at=COALESCE(revoked_at,clock_timestamp())
          WHERE identity_id=$1 AND credential_id=$2
            AND consumed_at IS NULL AND revoked_at IS NULL`,
        [input.identityId, input.credentialId],
      );
      await client.query(
        `UPDATE platform_identities identity
            SET passkey_enabled=EXISTS (
                  SELECT 1 FROM webauthn_credentials credential
                   WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
                ),
                passkey_enrolled_at=CASE WHEN EXISTS (
                  SELECT 1 FROM webauthn_credentials credential
                   WHERE credential.identity_id=identity.id AND credential.revoked_at IS NULL
                ) THEN passkey_enrolled_at ELSE NULL END,
                updated_at=clock_timestamp()
          WHERE identity.id=$1`,
        [input.identityId],
      );
      const tenantId = await defaultTenantId(client, input.identityId);
      await appendPlatformAudit(client, {
        actorIdentityId: input.identityId,
        tenantId,
        action: "auth.passkey_revoked",
        entityType: "webauthn_credential",
        entityId: input.credentialId,
        requestId: input.requestId,
        metadata: { reason: input.reason, sessionsRevoked: sessions.rowCount ?? 0 },
      });
      await client.query("COMMIT");
      return {
        revoked: true,
        sessionsRevoked: sessions.rowCount ?? 0,
        currentSessionRevoked: input.currentSessionId !== undefined
          && sessions.rows.some(({ id }) => id === input.currentSessionId),
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async listIdentitySessions(
    identityId: string,
    currentSessionId: string,
  ): Promise<readonly IdentitySessionSummary[]> {
    const result = await this.pool.query<IdentitySessionRow>(
      `SELECT session.id,session.active_tenant_id,tenant.display_name AS tenant_name,
              session.assurance_level,session.auth_method,session.aal,session.phishing_resistant,
              session.recovery_limited,session.device_label,session.authenticated_credential_id,
              session.created_at,session.last_seen_at,session.expires_at,session.idle_expires_at,
              session.ip_change_count
         FROM auth_sessions session
         JOIN tenants tenant ON tenant.id=session.active_tenant_id
        WHERE session.identity_id=$1 AND session.revoked_at IS NULL
          AND session.expires_at>clock_timestamp() AND session.idle_expires_at>clock_timestamp()
        ORDER BY (session.id=$2) DESC,session.last_seen_at DESC,session.id`,
      [identityId, currentSessionId],
    );
    return result.rows.map((row) => mapIdentitySession(row, currentSessionId));
  }

  public async revokeIdentitySession(input: {
    readonly identityId: string;
    readonly sessionId: string;
    readonly reason: string;
    readonly requestId: string;
  }): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const revoked = await client.query<{ active_tenant_id: string }>(
        `UPDATE auth_sessions
            SET revoked_at=clock_timestamp(),revoke_reason=$3
          WHERE id=$1 AND identity_id=$2 AND revoked_at IS NULL
        RETURNING active_tenant_id`,
        [input.sessionId, input.identityId, input.reason],
      );
      const row = revoked.rows[0];
      if (row) {
        await revokeSessionGrants(client, input.sessionId);
        await appendPlatformAudit(client, {
          actorIdentityId: input.identityId,
          tenantId: row.active_tenant_id,
          action: "auth.session_revoked",
          entityType: "auth_session",
          entityId: input.sessionId,
          requestId: input.requestId,
          metadata: { reason: input.reason },
        });
      }
      await client.query("COMMIT");
      return Boolean(row);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async revokeOtherIdentitySessions(input: {
    readonly identityId: string;
    readonly currentSessionId: string;
    readonly reason: string;
    readonly requestId: string;
  }): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const revoked = await client.query<{ id: string }>(
        `UPDATE auth_sessions
            SET revoked_at=clock_timestamp(),revoke_reason=$3
          WHERE identity_id=$1 AND id<>$2 AND revoked_at IS NULL
        RETURNING id`,
        [input.identityId, input.currentSessionId, input.reason],
      );
      if (revoked.rows.length > 0) {
        await client.query(
          `UPDATE authentication_step_up_grants
              SET revoked_at=COALESCE(revoked_at,clock_timestamp())
            WHERE session_id=ANY($1::uuid[]) AND consumed_at IS NULL AND revoked_at IS NULL`,
          [revoked.rows.map(({ id }) => id)],
        );
      }
      const tenantId = await defaultTenantId(client, input.identityId);
      await appendPlatformAudit(client, {
        actorIdentityId: input.identityId,
        tenantId,
        action: "auth.sessions_revoked_others",
        entityType: "platform_identity",
        entityId: input.identityId,
        requestId: input.requestId,
        metadata: { reason: input.reason, sessionsRevoked: revoked.rows.length },
      });
      await client.query("COMMIT");
      return revoked.rows.length;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async enforceSessionLimit(
    identityId: string,
    tenantId: string,
    currentSessionId: string,
    maximumActiveSessions: number,
  ): Promise<number> {
    if (!Number.isInteger(maximumActiveSessions) || maximumActiveSessions < 1 || maximumActiveSessions > 100) {
      throw new EnterpriseAuthStoreError("POLICY_CONFLICT", "Active session limit is invalid");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const identity = await client.query(
        "SELECT 1 FROM platform_identities WHERE id=$1 AND status='active' FOR UPDATE",
        [identityId],
      );
      if (identity.rowCount !== 1) {
        throw new EnterpriseAuthStoreError("SESSION_INVALID", "Session identity is unavailable");
      }
      const revokedSessionIds = await revokeExcessSessions(
        client,
        identityId,
        tenantId,
        currentSessionId,
        maximumActiveSessions,
      );
      if (revokedSessionIds.length > 0) {
        await client.query(
          `UPDATE authentication_step_up_grants
              SET revoked_at=COALESCE(revoked_at,clock_timestamp())
            WHERE session_id=ANY($1::uuid[]) AND consumed_at IS NULL AND revoked_at IS NULL`,
          [revokedSessionIds],
        );
      }
      await client.query("COMMIT");
      return revokedSessionIds.length;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async getEffectiveIdentityPolicy(tenantId: string): Promise<EffectiveIdentityPolicy> {
    return mapEffectivePolicy(await getEffectivePolicyRow(this.pool, tenantId));
  }

  public async upsertTenantIdentityPolicy(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly changedByIdentityId: string;
    readonly currentSessionId?: string;
    readonly policy: IdentityPolicyValues;
    readonly requestId: string;
  }): Promise<EffectiveIdentityPolicy | null> {
    const values = policySqlValues(input.policy);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // Invitation completion takes the same transaction lock before it
      // creates an active membership. Without this boundary, a newly accepted
      // password-only identity could arrive after the readiness snapshot.
      await lockTenantIdentityPolicy(client, input.tenantId);
      const persisted = input.expectedVersion === 0
        ? await client.query<{ version: string }>(
          `INSERT INTO tenant_identity_policies(
             tenant_id,enforcement_mode,minimum_aal,privileged_minimum_aal,require_user_verification,
             require_phishing_resistant_for_privileged,require_device_bound_for_privileged,
             require_attestation_for_privileged,allow_password,allow_totp_fallback,
             allow_recovery_codes,allow_synced_passkeys,minimum_passkey_count,
             privileged_minimum_passkey_count,maximum_passkeys,maximum_active_sessions,
             idle_timeout_minutes,absolute_session_minutes,step_up_ttl_seconds,
             action_requirements,changed_by_identity_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
           ON CONFLICT (tenant_id) DO NOTHING RETURNING version::text`,
          [input.tenantId, ...values, input.changedByIdentityId],
        )
        : await client.query<{ version: string }>(
          `UPDATE tenant_identity_policies
              SET enforcement_mode=$3,minimum_aal=$4,privileged_minimum_aal=$5,require_user_verification=$6,
                  require_phishing_resistant_for_privileged=$7,require_device_bound_for_privileged=$8,
                  require_attestation_for_privileged=$9,allow_password=$10,allow_totp_fallback=$11,
                  allow_recovery_codes=$12,allow_synced_passkeys=$13,minimum_passkey_count=$14,
                  privileged_minimum_passkey_count=$15,maximum_passkeys=$16,
                  maximum_active_sessions=$17,idle_timeout_minutes=$18,
                  absolute_session_minutes=$19,step_up_ttl_seconds=$20,action_requirements=$21,
                  changed_by_identity_id=$22,version=version+1,updated_at=clock_timestamp()
            WHERE tenant_id=$1 AND version=$2 RETURNING version::text`,
          [input.tenantId, input.expectedVersion, ...values, input.changedByIdentityId],
        );
      if (!persisted.rows[0]) {
        await client.query("ROLLBACK");
        return null;
      }
      const policy = await getEffectivePolicyRow(client, input.tenantId);
      await assertTenantPolicyActivationReady(client, input.changedByIdentityId, policy);
      const authorizationImpact = await invalidateTenantPolicyAuthorizations(client, input.tenantId);
      const sessionImpact = await reconcileTenantSessionsForPolicy(
        client,
        input.tenantId,
        input.currentSessionId,
        policy,
      );
      await appendPlatformAudit(client, {
        actorIdentityId: input.changedByIdentityId,
        tenantId: input.tenantId,
        action: "auth.identity_policy_updated",
        entityType: "tenant_identity_policy",
        entityId: input.tenantId,
        requestId: input.requestId,
        metadata: {
          version: Number(persisted.rows[0].version),
          sessionsRevoked: sessionImpact.revoked,
          sessionsReconciled: sessionImpact.reconciled,
          ceremoniesInvalidated: authorizationImpact.ceremoniesInvalidated,
          mfaChallengesInvalidated: authorizationImpact.mfaChallengesInvalidated,
          grantsRevoked: authorizationImpact.grantsRevoked,
        },
      });
      await client.query("COMMIT");
      return mapEffectivePolicy(policy);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      if (isCheckViolation(error)) {
        throw new EnterpriseAuthStoreError("POLICY_CONFLICT", "Tenant policy violates the global security floor");
      }
      throw error;
    } finally {
      client.release();
    }
  }
}

/** Serializes policy activation with invitation membership activation. */
async function lockTenantIdentityPolicy(client: PoolClient, tenantId: string): Promise<void> {
  await client.query(
    "SELECT pg_advisory_xact_lock(hashtextextended('tenant_identity_policy:' || $1::text,0))",
    [tenantId],
  );
}

interface CeremonyRow {
  readonly id: string;
  readonly ceremony_type: WebAuthnCeremonyType;
  readonly challenge_hash: string;
  readonly identity_id: string | null;
  readonly tenant_id: string | null;
  readonly session_id: string | null;
  readonly purpose: string | null;
  readonly operation_hash: string | null;
  readonly rp_id: string;
  readonly expected_origin: string;
  readonly require_user_verification: boolean;
  readonly policy_version: string | number;
  readonly replacement_credential_id: string | null;
  readonly user_agent_hash: string | null;
  readonly ip_prefix_hash: string | null;
  readonly attempt_count: number;
  readonly expires_at: Date;
}

interface LockedCeremonyRow extends CeremonyRow {
  readonly token_hash: string;
}

interface CredentialVerificationRow {
  readonly id: string;
  readonly credential_id: string;
  readonly identity_id: string;
  readonly tenant_id: string;
  readonly public_key: Buffer;
  readonly user_handle: string;
  readonly sign_count: string;
  readonly transports: PasskeyTransport[];
  readonly device_type: PasskeyDeviceType;
  readonly backup_eligible: boolean;
  readonly backup_state: boolean;
  readonly user_verified: boolean;
  readonly trust_level: PasskeyTrustLevel;
  readonly rp_id: string;
  readonly revoked_at: Date | null;
}

interface LockedCredentialRow {
  readonly id: string;
  readonly identity_id: string;
  readonly sign_count: string;
  readonly backup_eligible: boolean;
  readonly device_type: PasskeyDeviceType;
  readonly rp_id: string;
}

interface CredentialPolicyRow {
  readonly id: string;
  readonly device_type: PasskeyDeviceType;
  readonly trust_level: PasskeyTrustLevel;
  readonly user_verified: boolean;
  readonly rp_id: string;
}

interface CredentialSummaryRow {
  readonly id: string;
  readonly credential_id: string;
  readonly display_name: string;
  readonly attachment: "platform" | "cross-platform" | null;
  readonly device_type: PasskeyDeviceType;
  readonly backup_eligible: boolean;
  readonly backup_state: boolean;
  readonly discoverable: boolean;
  readonly user_verified: boolean;
  readonly aaguid: string | null;
  readonly transports: PasskeyTransport[];
  readonly trust_level: PasskeyTrustLevel;
  readonly created_at: Date;
  readonly last_used_at: Date | null;
  readonly revoked_at: Date | null;
  readonly revocation_reason: PasskeyRevocationReason | null;
  readonly version: string;
}

interface IdentitySessionRow {
  readonly id: string;
  readonly active_tenant_id: string;
  readonly tenant_name: string;
  readonly assurance_level: AuthenticationAssuranceLevel;
  readonly auth_method: AuthenticationMethod;
  readonly aal: 1 | 2 | 3;
  readonly phishing_resistant: boolean;
  readonly recovery_limited: boolean;
  readonly device_label: string | null;
  readonly authenticated_credential_id: string | null;
  readonly created_at: Date;
  readonly last_seen_at: Date;
  readonly expires_at: Date;
  readonly idle_expires_at: Date;
  readonly ip_change_count: number;
}

interface EffectivePolicyRow {
  readonly tenant_id: string;
  readonly baseline_version: string;
  readonly tenant_version: string | null;
  readonly enforcement_mode: "monitor" | "enforce";
  readonly minimum_aal: 1 | 2 | 3;
  readonly privileged_minimum_aal: 2 | 3;
  readonly require_user_verification: boolean;
  readonly require_phishing_resistant_for_privileged: boolean;
  readonly require_device_bound_for_privileged: boolean;
  readonly require_attestation_for_privileged: boolean;
  readonly allow_password: boolean;
  readonly allow_totp_fallback: boolean;
  readonly allow_recovery_codes: boolean;
  readonly allow_synced_passkeys: boolean;
  readonly minimum_passkey_count: number;
  readonly privileged_minimum_passkey_count: number;
  readonly maximum_passkeys: number;
  readonly maximum_active_sessions: number;
  readonly idle_timeout_minutes: number;
  readonly absolute_session_minutes: number;
  readonly step_up_ttl_seconds: number;
  readonly action_requirements: Record<string, IdentityActionRequirement>;
}

function mapCeremony(row: CeremonyRow): WebAuthnCeremonyRecord {
  return {
    id: row.id,
    type: row.ceremony_type,
    challengeHash: row.challenge_hash,
    identityId: row.identity_id,
    tenantId: row.tenant_id,
    sessionId: row.session_id,
    purpose: row.purpose,
    operationHash: row.operation_hash,
    rpId: row.rp_id,
    expectedOrigin: row.expected_origin,
    requireUserVerification: row.require_user_verification,
    policyVersion: Number(row.policy_version),
    replacementCredentialId: row.replacement_credential_id,
    userAgentHash: row.user_agent_hash,
    ipPrefixHash: row.ip_prefix_hash,
    attemptCount: row.attempt_count,
    expiresAt: row.expires_at,
  };
}

function mapCredentialVerification(row: CredentialVerificationRow): PasskeyCredentialVerificationRecord {
  return {
    id: row.id,
    externalId: row.credential_id,
    identityId: row.identity_id,
    tenantId: row.tenant_id,
    publicKey: row.public_key,
    userHandle: row.user_handle,
    counter: Number(row.sign_count),
    transports: row.transports,
    deviceType: row.device_type,
    backupEligible: row.backup_eligible,
    backedUp: row.backup_state,
    userVerified: row.user_verified,
    trustLevel: row.trust_level,
    rpId: row.rp_id,
    revokedAt: row.revoked_at,
  };
}

function mapCredentialSummary(row: CredentialSummaryRow): PasskeyCredentialSummary {
  return {
    id: row.id,
    externalId: row.credential_id,
    displayName: row.display_name,
    attachment: row.attachment,
    deviceType: row.device_type,
    backupEligible: row.backup_eligible,
    backedUp: row.backup_state,
    discoverable: row.discoverable,
    userVerified: row.user_verified,
    aaguid: row.aaguid,
    transports: row.transports,
    trustLevel: row.trust_level,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
    revocationReason: row.revocation_reason,
    version: Number(row.version),
  };
}

function mapIdentitySession(row: IdentitySessionRow, currentSessionId: string): IdentitySessionSummary {
  return {
    id: row.id,
    tenantId: row.active_tenant_id,
    tenantName: row.tenant_name,
    isCurrent: row.id === currentSessionId,
    assuranceLevel: row.assurance_level,
    authMethod: row.auth_method,
    aal: row.aal,
    phishingResistant: row.phishing_resistant,
    recoveryLimited: row.recovery_limited,
    deviceLabel: row.device_label,
    credentialId: row.authenticated_credential_id,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    expiresAt: row.expires_at,
    idleExpiresAt: row.idle_expires_at,
    ipContextChanged: row.ip_change_count > 0,
  };
}

function mapEffectivePolicy(row: EffectivePolicyRow): EffectiveIdentityPolicy {
  return {
    tenantId: row.tenant_id,
    baselineVersion: Number(row.baseline_version),
    tenantVersion: row.tenant_version === null ? null : Number(row.tenant_version),
    enforcementMode: row.enforcement_mode,
    minimumAal: row.minimum_aal,
    privilegedMinimumAal: row.privileged_minimum_aal,
    requireUserVerification: row.require_user_verification,
    requirePhishingResistantForPrivileged: row.require_phishing_resistant_for_privileged,
    requireDeviceBoundForPrivileged: row.require_device_bound_for_privileged,
    requireAttestationForPrivileged: row.require_attestation_for_privileged,
    allowPassword: row.allow_password,
    allowTotpFallback: row.allow_totp_fallback,
    allowRecoveryCodes: row.allow_recovery_codes,
    allowSyncedPasskeys: row.allow_synced_passkeys,
    minimumPasskeyCount: row.minimum_passkey_count,
    privilegedMinimumPasskeyCount: row.privileged_minimum_passkey_count,
    maximumPasskeys: row.maximum_passkeys,
    maximumActiveSessions: row.maximum_active_sessions,
    idleTimeoutMinutes: row.idle_timeout_minutes,
    absoluteSessionMinutes: row.absolute_session_minutes,
    stepUpTtlSeconds: row.step_up_ttl_seconds,
    actionRequirements: row.action_requirements,
  };
}

async function lockCeremony(
  client: PoolClient,
  input: { readonly ceremonyId: string; readonly tokenHash: string; readonly challengeHash: string },
  type: WebAuthnCeremonyType,
): Promise<LockedCeremonyRow> {
  const result = await client.query<LockedCeremonyRow>(
    `SELECT id,token_hash,ceremony_type,challenge_hash,identity_id,tenant_id,session_id,
            purpose,operation_hash,rp_id,expected_origin,require_user_verification,
            policy_version,replacement_credential_id,user_agent_hash,ip_prefix_hash,
            attempt_count,expires_at
       FROM webauthn_ceremonies
      WHERE id=$1 AND token_hash=$2 AND challenge_hash=$3 AND ceremony_type=$4
        AND consumed_at IS NULL AND failed_at IS NULL
        AND expires_at>clock_timestamp() AND attempt_count<6
      FOR UPDATE`,
    [input.ceremonyId, input.tokenHash, input.challengeHash, type],
  );
  const row = result.rows[0];
  if (!row) throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony is invalid, expired, or already consumed");
  return row;
}

async function lockRegistrationIdentity(client: PoolClient, ceremonyId: string): Promise<string> {
  const result = await client.query<{ identity_id: string }>(
    `SELECT identity.id AS identity_id
       FROM webauthn_ceremonies ceremony
       JOIN platform_identities identity ON identity.id=ceremony.identity_id
      WHERE ceremony.id=$1 AND ceremony.ceremony_type='registration'
        AND identity.status='active'
      FOR UPDATE OF identity`,
    [ceremonyId],
  );
  const identityId = result.rows[0]?.identity_id;
  if (!identityId) {
    throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "Passkey registration identity is unavailable");
  }
  return identityId;
}

async function lockCredentialIdentity(client: PoolClient, credentialId: string): Promise<string> {
  const result = await client.query<{ identity_id: string }>(
    `SELECT identity.id AS identity_id
       FROM webauthn_credentials credential
       JOIN platform_identities identity ON identity.id=credential.identity_id
      WHERE credential.id=$1 AND credential.revoked_at IS NULL AND identity.status='active'
      FOR UPDATE OF identity`,
    [credentialId],
  );
  const identityId = result.rows[0]?.identity_id;
  if (!identityId) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey identity is unavailable");
  }
  return identityId;
}

async function consumeLockedCeremony(client: PoolClient, ceremonyId: string): Promise<void> {
  const consumed = await client.query(
    `UPDATE webauthn_ceremonies SET consumed_at=clock_timestamp()
      WHERE id=$1 AND consumed_at IS NULL AND failed_at IS NULL AND expires_at>clock_timestamp()`,
    [ceremonyId],
  );
  if (consumed.rowCount !== 1) {
    throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony could not be consumed exactly once");
  }
}

async function lockCredential(client: PoolClient, credentialId: string): Promise<LockedCredentialRow> {
  const result = await client.query<LockedCredentialRow>(
    `SELECT id,identity_id,sign_count::text,backup_eligible,device_type,rp_id
       FROM webauthn_credentials WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`,
    [credentialId],
  );
  const row = result.rows[0];
  if (!row) throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey is unavailable or revoked");
  return row;
}

async function assertCredentialSetPreservesIdentityPolicies(
  client: PoolClient,
  identityId: string,
  before: readonly CredentialPolicyRow[],
  after: readonly CredentialPolicyRow[],
  options: { readonly candidateDeviceType?: PasskeyDeviceType },
): Promise<void> {
  const memberships = await client.query<{ tenant_id: string }>(
    `SELECT membership.tenant_id
       FROM tenant_memberships membership
       JOIN tenants tenant ON tenant.id=membership.tenant_id
      WHERE membership.identity_id=$1 AND membership.status='active' AND tenant.status='active'
      ORDER BY membership.is_default DESC,membership.created_at,membership.tenant_id`,
    [identityId],
  );
  if (memberships.rows.length === 0) {
    throw new EnterpriseAuthStoreError("SESSION_INVALID", "Identity has no active tenant membership");
  }
  for (const membership of memberships.rows) {
    const policy = await getEffectivePolicyRow(client, membership.tenant_id);
    if (
      options.candidateDeviceType === "multiDevice"
      && !policy.allow_synced_passkeys
    ) {
      throw new EnterpriseAuthStoreError(
        "POLICY_CONFLICT",
        "An active tenant policy does not permit the candidate synced passkey",
      );
    }
    if (policy.enforcement_mode !== "enforce") continue;
    const beforeGeneral = eligibleCredentialCount(before, policy, false);
    const afterGeneral = eligibleCredentialCount(after, policy, false);
    const beforePrivileged = eligibleCredentialCount(before, policy, true);
    const afterPrivileged = eligibleCredentialCount(after, policy, true);
    if (
      (afterGeneral < policy.minimum_passkey_count && afterGeneral < beforeGeneral)
      || (
        afterPrivileged < policy.privileged_minimum_passkey_count
        && afterPrivileged < beforePrivileged
      )
    ) {
      throw new EnterpriseAuthStoreError(
        "POLICY_CONFLICT",
        "The credential change would weaken an enforced tenant passkey posture",
      );
    }
  }
}

function eligibleCredentialCount(
  credentials: readonly CredentialPolicyRow[],
  policy: EffectivePolicyRow,
  privileged: boolean,
): number {
  return credentials.filter((credential) =>
    credential.user_verified
    && (policy.allow_synced_passkeys || credential.device_type === "singleDevice")
    && (!privileged || !policy.require_device_bound_for_privileged || credential.device_type === "singleDevice")
    && (
      !privileged
      || !policy.require_attestation_for_privileged
      || ["attested", "enterprise_attested"].includes(credential.trust_level)
    )
  ).length;
}

async function updateCredentialUsage(
  client: PoolClient,
  credentialId: string,
  newCounter: number,
  newBackupState: boolean,
): Promise<void> {
  await client.query(
    `UPDATE webauthn_credentials
        SET sign_count=$2,backup_state=$3,last_used_at=clock_timestamp(),version=version+1
      WHERE id=$1`,
    [credentialId, newCounter, newBackupState],
  );
}

function assertAuthenticatorProperties(
  credential: LockedCredentialRow,
  assertedDeviceType: PasskeyDeviceType,
  newBackupState: boolean,
  errorCode: "CREDENTIAL_INVALID" | "STEP_UP_INVALID",
): void {
  const assertedBackupEligible = assertedDeviceType === "multiDevice";
  if (
    assertedDeviceType !== credential.device_type
    || assertedBackupEligible !== credential.backup_eligible
    || (newBackupState && !credential.backup_eligible)
  ) {
    throw new EnterpriseAuthStoreError(
      errorCode,
      "Passkey authenticator properties changed or are inconsistent",
    );
  }
}

async function insertPasskeySession(
  client: PoolClient,
  identityId: string,
  tenantId: string,
  credentialId: string,
  input: EnterpriseSessionCreateInput,
  policy: EffectivePolicyRow,
): Promise<string> {
  const absoluteExpiresAt = new Date(Math.min(
    input.expiresAt.getTime(),
    Date.now() + policy.absolute_session_minutes * 60_000,
  ));
  const idleExpiresAt = new Date(Math.min(
    absoluteExpiresAt.getTime(),
    Date.now() + policy.idle_timeout_minutes * 60_000,
  ));
  const created = await client.query<{ id: string }>(
    `INSERT INTO auth_sessions(
       token_hash,csrf_hash,identity_id,active_tenant_id,user_agent_hash,ip_prefix_hash,
       expires_at,assurance_level,authenticated_at,mfa_verified_at,auth_method,aal,
       phishing_resistant,authenticated_credential_id,recovery_limited,
       idle_timeout_minutes,idle_expires_at,last_ip_prefix_hash,device_label
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,'mfa',clock_timestamp(),clock_timestamp(),
               'passkey',2,true,$8,false,$9,$10,$6,$11)
     RETURNING id`,
    [
      input.tokenHash,
      input.csrfHash,
      identityId,
      tenantId,
      input.userAgentHash ?? null,
      input.ipPrefixHash ?? null,
      absoluteExpiresAt,
      credentialId,
      policy.idle_timeout_minutes,
      idleExpiresAt,
      input.deviceLabel?.trim() ?? null,
    ],
  );
  const sessionId = created.rows[0]?.id;
  if (!sessionId) throw new EnterpriseAuthStoreError("SESSION_INVALID", "Passkey session was not created");
  return sessionId;
}

async function assertActiveMembership(client: PoolClient, identityId: string, tenantId: string): Promise<void> {
  const result = await client.query<{ active: boolean }>(
    "SELECT lock_active_authentication_context($1,$2) AS active",
    [identityId, tenantId],
  );
  if (result.rows[0]?.active !== true) {
    throw new EnterpriseAuthStoreError("SESSION_INVALID", "Identity has no active membership in the selected tenant");
  }
}

async function revokeAllIdentitySessions(client: PoolClient, identityId: string, reason: string): Promise<number> {
  const revoked = await client.query(
    `UPDATE auth_sessions SET revoked_at=clock_timestamp(),revoke_reason=$2
      WHERE identity_id=$1 AND revoked_at IS NULL`,
    [identityId, reason],
  );
  await client.query(
    `UPDATE authentication_step_up_grants
        SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE identity_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL`,
    [identityId],
  );
  return revoked.rowCount ?? 0;
}

async function revokeExcessSessions(
  client: PoolClient,
  identityId: string,
  tenantId: string,
  currentSessionId: string,
  maximumActiveSessions: number,
): Promise<readonly string[]> {
  const revoked = await client.query<{ id: string }>(
    `WITH excess AS (
       SELECT id FROM auth_sessions
        WHERE identity_id=$1 AND active_tenant_id=$2 AND revoked_at IS NULL
          AND expires_at>clock_timestamp() AND idle_expires_at>clock_timestamp()
        ORDER BY (id=$3) DESC,last_seen_at DESC,id
        OFFSET $4
     )
     UPDATE auth_sessions session
        SET revoked_at=clock_timestamp(),revoke_reason='active_session_limit'
       FROM excess WHERE session.id=excess.id
     RETURNING session.id`,
    [identityId, tenantId, currentSessionId, maximumActiveSessions],
  );
  return revoked.rows.map(({ id }) => id);
}

async function revokeSessionGrants(client: PoolClient, sessionId: string): Promise<void> {
  await client.query(
    `UPDATE authentication_step_up_grants
        SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE session_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL`,
    [sessionId],
  );
}

async function defaultTenantId(client: PoolClient, identityId: string): Promise<string> {
  const result = await client.query<{ tenant_id: string }>(
    `SELECT membership.tenant_id
       FROM tenant_memberships membership
       JOIN tenants tenant ON tenant.id=membership.tenant_id
      WHERE membership.identity_id=$1 AND membership.status='active' AND tenant.status='active'
      ORDER BY membership.is_default DESC,membership.created_at,membership.tenant_id LIMIT 1`,
    [identityId],
  );
  const tenantId = result.rows[0]?.tenant_id;
  if (!tenantId) throw new EnterpriseAuthStoreError("SESSION_INVALID", "Identity has no active tenant");
  return tenantId;
}

async function getEffectivePolicyRow(
  queryable: Pick<Pool, "query"> | Pick<PoolClient, "query">,
  tenantId: string,
): Promise<EffectivePolicyRow> {
  const result = await queryable.query<EffectivePolicyRow>(
    `SELECT tenant.id AS tenant_id,baseline.version::text AS baseline_version,
            policy.version::text AS tenant_version,
            COALESCE(policy.enforcement_mode,baseline.enforcement_mode) AS enforcement_mode,
            COALESCE(policy.minimum_aal,baseline.minimum_aal) AS minimum_aal,
            COALESCE(policy.privileged_minimum_aal,baseline.privileged_minimum_aal) AS privileged_minimum_aal,
            COALESCE(policy.require_user_verification,baseline.require_user_verification) AS require_user_verification,
            COALESCE(policy.require_phishing_resistant_for_privileged,baseline.require_phishing_resistant_for_privileged)
              AS require_phishing_resistant_for_privileged,
            COALESCE(policy.require_device_bound_for_privileged,baseline.require_device_bound_for_privileged)
              AS require_device_bound_for_privileged,
            COALESCE(policy.require_attestation_for_privileged,baseline.require_attestation_for_privileged)
              AS require_attestation_for_privileged,
            COALESCE(policy.allow_password,baseline.allow_password) AS allow_password,
            COALESCE(policy.allow_totp_fallback,baseline.allow_totp_fallback) AS allow_totp_fallback,
            COALESCE(policy.allow_recovery_codes,baseline.allow_recovery_codes) AS allow_recovery_codes,
            COALESCE(policy.allow_synced_passkeys,baseline.allow_synced_passkeys) AS allow_synced_passkeys,
            COALESCE(policy.minimum_passkey_count,baseline.minimum_passkey_count) AS minimum_passkey_count,
            COALESCE(policy.privileged_minimum_passkey_count,baseline.privileged_minimum_passkey_count)
              AS privileged_minimum_passkey_count,
            COALESCE(policy.maximum_passkeys,baseline.maximum_passkeys) AS maximum_passkeys,
            COALESCE(policy.maximum_active_sessions,baseline.maximum_active_sessions) AS maximum_active_sessions,
            COALESCE(policy.idle_timeout_minutes,baseline.idle_timeout_minutes) AS idle_timeout_minutes,
            COALESCE(policy.absolute_session_minutes,baseline.absolute_session_minutes) AS absolute_session_minutes,
            COALESCE(policy.step_up_ttl_seconds,baseline.step_up_ttl_seconds) AS step_up_ttl_seconds,
            COALESCE(policy.action_requirements,baseline.action_requirements) AS action_requirements
       FROM tenants tenant
       CROSS JOIN identity_policy_baseline baseline
       LEFT JOIN tenant_identity_policies policy ON policy.tenant_id=tenant.id
      WHERE tenant.id=$1 AND tenant.status='active' AND baseline.policy_key='global'`,
    [tenantId],
  );
  const row = result.rows[0];
  if (!row) throw new EnterpriseAuthStoreError("POLICY_CONFLICT", "Effective identity policy was not found");
  return row;
}

async function invalidateTenantPolicyAuthorizations(
  client: PoolClient,
  tenantId: string,
): Promise<{
  readonly ceremoniesInvalidated: number;
  readonly mfaChallengesInvalidated: number;
  readonly grantsRevoked: number;
}> {
  // Any ceremony or one-use grant created against the previous effective policy
  // must not survive a policy change. The row updates also serialize with an
  // in-flight verification/consumption, giving the two operations a clear
  // transaction order instead of a time-of-check/time-of-use window.
  const ceremonies = await client.query(
    `UPDATE webauthn_ceremonies
        SET failed_at=clock_timestamp()
      WHERE tenant_id=$1 AND consumed_at IS NULL AND failed_at IS NULL`,
    [tenantId],
  );
  const grants = await client.query(
    `UPDATE authentication_step_up_grants
        SET revoked_at=COALESCE(revoked_at,clock_timestamp())
      WHERE tenant_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL`,
    [tenantId],
  );
  const mfaChallenges = await client.query(
    `UPDATE mfa_challenges
        SET consumed_at=clock_timestamp()
      WHERE tenant_id=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp()`,
    [tenantId],
  );
  return {
    ceremoniesInvalidated: ceremonies.rowCount ?? 0,
    mfaChallengesInvalidated: mfaChallenges.rowCount ?? 0,
    grantsRevoked: grants.rowCount ?? 0,
  };
}

async function assertTenantPolicyActivationReady(
  client: PoolClient,
  actorIdentityId: string,
  policy: EffectivePolicyRow,
): Promise<void> {
  if (policy.enforcement_mode === "enforce") {
    const unsupportedAal = policy.minimum_aal > 2
      || policy.privileged_minimum_aal > 2
      || Object.values(policy.action_requirements).some((requirement) => requirement.minAal > 2);
    if (unsupportedAal) {
      throw new EnterpriseAuthStoreError(
        "POLICY_CONFLICT",
        "AAL3 enforcement requires an external authenticator trust service that is not configured",
      );
    }
  }

  // Lock the complete affected identity/authenticator set. This prevents a
  // concurrent revocation, recovery-code consumption, or new FK-backed
  // credential from invalidating the readiness decision before commit.
  const lockedMembers = await client.query<{ identity_id: string }>(
    `SELECT membership.identity_id
       FROM tenant_memberships membership
       JOIN platform_identities identity ON identity.id=membership.identity_id
      WHERE membership.tenant_id=$1 AND membership.status='active' AND identity.status='active'
      ORDER BY membership.identity_id
      FOR UPDATE OF membership,identity`,
    [policy.tenant_id],
  );
  if (lockedMembers.rows.length === 0) {
    throw new EnterpriseAuthStoreError("POLICY_CONFLICT", "Tenant has no active identities for policy activation");
  }
  await client.query(
    `SELECT credential.id
       FROM webauthn_credentials credential
       JOIN tenant_memberships membership ON membership.identity_id=credential.identity_id
      WHERE membership.tenant_id=$1 AND membership.status='active' AND credential.revoked_at IS NULL
      ORDER BY credential.identity_id,credential.id
      FOR UPDATE OF credential`,
    [policy.tenant_id],
  );
  await client.query(
    `SELECT recovery.id
       FROM mfa_recovery_codes recovery
       JOIN tenant_memberships membership ON membership.identity_id=recovery.identity_id
      WHERE membership.tenant_id=$1 AND membership.status='active'
        AND recovery.consumed_at IS NULL AND recovery.revoked_at IS NULL
      ORDER BY recovery.identity_id,recovery.id
      FOR UPDATE OF recovery`,
    [policy.tenant_id],
  );

  const readiness = await client.query<{
    identity_id: string;
    mfa_enabled: boolean;
    active_passkeys: number;
    device_bound_passkeys: number;
    attested_passkeys: number;
    privileged_eligible_passkeys: number;
    active_recovery_codes: number;
  }>(
    `SELECT membership.identity_id,identity.mfa_enabled,
            count(credential.id) FILTER (WHERE credential.user_verified)::integer AS active_passkeys,
            count(credential.id) FILTER (
              WHERE credential.user_verified AND credential.device_type='singleDevice'
            )::integer
              AS device_bound_passkeys,
            count(credential.id) FILTER (
              WHERE credential.user_verified
                AND credential.trust_level IN ('attested','enterprise_attested')
            )::integer AS attested_passkeys,
            count(credential.id) FILTER (
              WHERE credential.user_verified
                AND ($2::boolean OR credential.device_type='singleDevice')
                AND (NOT $3::boolean OR credential.device_type='singleDevice')
                AND (
                  NOT $4::boolean
                  OR credential.trust_level IN ('attested','enterprise_attested')
                )
            )::integer AS privileged_eligible_passkeys,
            (SELECT count(*)::integer
               FROM mfa_recovery_codes recovery
              WHERE recovery.identity_id=membership.identity_id
                AND recovery.consumed_at IS NULL AND recovery.revoked_at IS NULL)
              AS active_recovery_codes
       FROM tenant_memberships membership
       JOIN platform_identities identity ON identity.id=membership.identity_id
       LEFT JOIN webauthn_credentials credential
         ON credential.identity_id=membership.identity_id AND credential.revoked_at IS NULL
      WHERE membership.tenant_id=$1 AND membership.status='active' AND identity.status='active'
      GROUP BY membership.identity_id,identity.mfa_enabled
      ORDER BY membership.identity_id`,
    [
      policy.tenant_id,
      policy.allow_synced_passkeys,
      policy.require_device_bound_for_privileged,
      policy.require_attestation_for_privileged,
    ],
  );

  for (const identity of readiness.rows) {
    const eligiblePasskeys = policy.allow_synced_passkeys
      ? identity.active_passkeys
      : identity.device_bound_passkeys;
    const usablePasswordPath = policy.allow_password && (
      !identity.mfa_enabled
      || policy.allow_totp_fallback
      || (policy.allow_recovery_codes && identity.active_recovery_codes > 0)
    );
    if (eligiblePasskeys === 0 && !usablePasswordPath) {
      throw new EnterpriseAuthStoreError(
        "POLICY_CONFLICT",
        "Identity policy would leave an active tenant identity without a usable authentication path",
      );
    }
    if (policy.enforcement_mode === "enforce" && eligiblePasskeys < policy.minimum_passkey_count) {
      throw new EnterpriseAuthStoreError(
        "POLICY_CONFLICT",
        "Identity policy minimum passkey count is not ready across all active tenant identities",
      );
    }
  }

  const actor = readiness.rows.find((identity) => identity.identity_id === actorIdentityId);
  if (!actor) {
    throw new EnterpriseAuthStoreError("POLICY_CONFLICT", "Policy administrator is not an active tenant identity");
  }
  const actorEligiblePasskeys = policy.allow_synced_passkeys
    ? actor.active_passkeys
    : actor.device_bound_passkeys;
  if (actorEligiblePasskeys < 1) {
    throw new EnterpriseAuthStoreError(
      "POLICY_CONFLICT",
      "Policy administrator must retain a passkey that can reverse the policy",
    );
  }
  if (
    policy.enforcement_mode === "enforce"
    && actor.privileged_eligible_passkeys < policy.privileged_minimum_passkey_count
  ) {
    throw new EnterpriseAuthStoreError(
      "POLICY_CONFLICT",
      "Policy administrator does not meet the privileged passkey minimum",
    );
  }
  if (
    policy.enforcement_mode === "enforce"
    && policy.require_device_bound_for_privileged
    && actor.device_bound_passkeys < 1
  ) {
    throw new EnterpriseAuthStoreError(
      "POLICY_CONFLICT",
      "Policy administrator must retain a device-bound passkey",
    );
  }
  if (
    policy.enforcement_mode === "enforce"
    && policy.require_attestation_for_privileged
    && actor.attested_passkeys < 1
  ) {
    throw new EnterpriseAuthStoreError(
      "POLICY_CONFLICT",
      "Policy administrator must retain an enterprise-attested passkey",
    );
  }
}

async function reconcileTenantSessionsForPolicy(
  client: PoolClient,
  tenantId: string,
  currentSessionId: string | undefined,
  policy: EffectivePolicyRow,
): Promise<{ readonly revoked: number; readonly reconciled: number }> {
  // Lock before changing deadlines or eligibility.  The active-session cap
  // must see the post-policy deadline, otherwise an already-expired current
  // session could evict a healthy session.
  const sessions = await client.query<{ id: string }>(
    `SELECT id FROM auth_sessions
      WHERE active_tenant_id=$1 AND revoked_at IS NULL
      ORDER BY identity_id,id FOR UPDATE`,
    [tenantId],
  );
  const sessionIds = sessions.rows.map(({ id }) => id);
  if (sessionIds.length === 0) return { revoked: 0, reconciled: 0 };

  const reconciled = await client.query(
    `UPDATE auth_sessions
        SET expires_at=LEAST(
              expires_at,
              created_at+make_interval(mins=>$2)
            ),
            idle_timeout_minutes=$3,
            idle_expires_at=LEAST(
              expires_at,
              created_at+make_interval(mins=>$2),
              last_seen_at+make_interval(mins=>$3)
            )
      WHERE id=ANY($1::uuid[]) AND revoked_at IS NULL`,
    [sessionIds, policy.absolute_session_minutes, policy.idle_timeout_minutes],
  );

  const expired = await client.query<{ id: string }>(
    `UPDATE auth_sessions
        SET revoked_at=clock_timestamp(),revoke_reason='identity_policy_session_expired'
      WHERE id=ANY($1::uuid[]) AND revoked_at IS NULL
        AND (expires_at<=clock_timestamp() OR idle_expires_at<=clock_timestamp())
      RETURNING id`,
    [sessionIds],
  );
  // Activation readiness has already locked the tenant identities and proved a
  // compliant sign-in path exists, so there is no broad "current session" or
  // low-assurance remediation exception that could later be resurrected when
  // the policy is relaxed.
  const prohibited = await client.query<{ id: string }>(
    `UPDATE auth_sessions session
        SET revoked_at=clock_timestamp(),revoke_reason='identity_policy_authentication_prohibited'
      WHERE session.id=ANY($1::uuid[]) AND session.revoked_at IS NULL
        AND (
          -- Only a database-bound invitation enrollment session can outlive a
          -- password-method disablement long enough to register its first
          -- passkey. It is always enrollment-only and capped in the database.
          session.enrollment_source IS DISTINCT FROM 'invitation'
          AND (
            (NOT $2::boolean AND session.auth_method IN ('password','totp','recovery_code','bootstrap'))
          OR (NOT $3::boolean AND session.auth_method='totp')
          OR (NOT $4::boolean AND session.auth_method='recovery_code')
          OR (
            NOT $5::boolean AND session.auth_method='passkey'
            AND EXISTS (
              SELECT 1 FROM webauthn_credentials credential
               WHERE credential.id=session.authenticated_credential_id
                 AND credential.device_type='multiDevice'
            )
          )
            OR ($6::boolean AND session.aal<$7::smallint)
          )
        )
      RETURNING session.id`,
    [
      sessionIds,
      policy.allow_password,
      policy.allow_totp_fallback,
      policy.allow_recovery_codes,
      policy.allow_synced_passkeys,
      policy.enforcement_mode === "enforce",
      policy.minimum_aal,
    ],
  );
  const policyRevokedIds = [...expired.rows, ...prohibited.rows].map(({ id }) => id);
  if (policyRevokedIds.length > 0) {
    await client.query(
      `UPDATE authentication_step_up_grants
          SET revoked_at=COALESCE(revoked_at,clock_timestamp())
        WHERE session_id=ANY($1::uuid[]) AND consumed_at IS NULL AND revoked_at IS NULL`,
      [policyRevokedIds],
    );
  }

  const capped = await client.query<{ id: string }>(
    `WITH ranked AS (
       SELECT id,row_number() OVER (
         PARTITION BY identity_id
         ORDER BY ($2::uuid IS NOT NULL AND id=$2::uuid) DESC,last_seen_at DESC,id
       ) AS position
         FROM auth_sessions
        WHERE active_tenant_id=$1 AND revoked_at IS NULL
          AND expires_at>clock_timestamp() AND idle_expires_at>clock_timestamp()
     )
     UPDATE auth_sessions session
        SET revoked_at=clock_timestamp(),revoke_reason='identity_policy_session_limit'
       FROM ranked
      WHERE session.id=ranked.id AND ranked.position>$3
     RETURNING session.id`,
    [tenantId, currentSessionId ?? null, policy.maximum_active_sessions],
  );
  const cappedIds = capped.rows.map(({ id }) => id);
  if (cappedIds.length > 0) {
    await client.query(
      `UPDATE authentication_step_up_grants
          SET revoked_at=COALESCE(revoked_at,clock_timestamp())
        WHERE session_id=ANY($1::uuid[]) AND consumed_at IS NULL AND revoked_at IS NULL`,
      [cappedIds],
    );
  }
  return {
    revoked: policyRevokedIds.length + cappedIds.length,
    reconciled: reconciled.rowCount ?? 0,
  };
}

function policySqlValues(policy: IdentityPolicyValues): readonly unknown[] {
  return [
    policy.enforcementMode,
    policy.minimumAal,
    policy.privilegedMinimumAal,
    policy.requireUserVerification,
    policy.requirePhishingResistantForPrivileged,
    policy.requireDeviceBoundForPrivileged,
    policy.requireAttestationForPrivileged,
    policy.allowPassword,
    policy.allowTotpFallback,
    policy.allowRecoveryCodes,
    policy.allowSyncedPasskeys,
    policy.minimumPasskeyCount,
    policy.privilegedMinimumPasskeyCount,
    policy.maximumPasskeys,
    policy.maximumActiveSessions,
    policy.idleTimeoutMinutes,
    policy.absoluteSessionMinutes,
    policy.stepUpTtlSeconds,
    policy.actionRequirements,
  ];
}

function assertCeremonyShape(input: WebAuthnCeremonyCreateInput): void {
  const hasSessionContext = Boolean(input.identityId && input.tenantId && input.sessionId);
  const hasOperationContext = Boolean(input.purpose && input.operationHash);
  const valid = input.type === "registration"
    ? hasSessionContext && !hasOperationContext
    : input.type === "authentication"
      ? !input.sessionId && !input.purpose && !input.operationHash && !input.replacementCredentialId
      : hasSessionContext && hasOperationContext && !input.replacementCredentialId;
  if (!valid) throw new EnterpriseAuthStoreError("CEREMONY_INVALID", "WebAuthn ceremony context does not match its type");
}

function assertCompletionHashes(input: {
  readonly tokenHash: string;
  readonly challengeHash: string;
}): void {
  assertSha256(input.tokenHash, "ceremony token");
  assertSha256(input.challengeHash, "WebAuthn challenge");
}

function validateCredentialCreate(credential: PasskeyCredentialCreateInput): void {
  if (!/^[A-Za-z0-9_-]{1,2048}$/u.test(credential.externalId)) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey credential identifier is invalid");
  }
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(credential.userHandle)) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey user handle is invalid");
  }
  if (credential.publicKey.byteLength < 16 || credential.publicKey.byteLength > 4096) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey public key size is invalid");
  }
  if (credential.backedUp && !credential.backupEligible) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey backup state is inconsistent");
  }
  if ((credential.deviceType === "multiDevice") !== credential.backupEligible) {
    throw new EnterpriseAuthStoreError(
      "CREDENTIAL_INVALID",
      "Passkey device type and backup eligibility are inconsistent",
    );
  }
  if (credential.displayName.trim().length < 1 || credential.displayName.trim().length > 120) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey name must contain 1 to 120 characters");
  }
  if (credential.attestationObjectHash !== undefined) {
    assertSha256(credential.attestationObjectHash, "attestation object");
  }
  assertCounter(credential.counter);
}

function validateSessionInput(input: EnterpriseSessionCreateInput): void {
  assertSha256(input.tokenHash, "session token");
  assertSha256(input.csrfHash, "CSRF token");
  if (input.expiresAt.getTime() <= Date.now()) {
    throw new EnterpriseAuthStoreError("SESSION_INVALID", "Session expiry must be in the future");
  }
  if (input.userAgentHash !== undefined) assertSha256(input.userAgentHash, "user agent");
  if (input.ipPrefixHash !== undefined) assertSha256(input.ipPrefixHash, "IP context");
  if (input.deviceLabel !== undefined && (input.deviceLabel.trim().length < 1 || input.deviceLabel.trim().length > 120)) {
    throw new EnterpriseAuthStoreError("SESSION_INVALID", "Session device label must contain 1 to 120 characters");
  }
}

function assertCounter(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_INVALID", "Passkey signature counter is invalid");
  }
}

function assertCounterAdvance(previousValue: string, nextValue: number): void {
  const previous = Number(previousValue);
  if (!Number.isSafeInteger(previous) || (previous !== 0 && nextValue <= previous)) {
    throw new EnterpriseAuthStoreError("CREDENTIAL_REPLAYED", "Passkey signature counter did not advance");
  }
}

function assertSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error(`${label} hash must be lowercase SHA-256 hexadecimal`);
}

function isUniqueViolation(error: unknown): boolean {
  return isPgError(error, "23505");
}

function isCheckViolation(error: unknown): boolean {
  return isPgError(error, "23514");
}

function isPgError(error: unknown, code: string): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

async function appendPlatformAudit(client: PoolClient, input: {
  readonly actorIdentityId: string;
  readonly tenantId: string;
  readonly action: string;
  readonly entityType: string;
  readonly entityId: string;
  readonly requestId: string;
  readonly metadata: Readonly<Record<string, unknown>>;
}): Promise<void> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended('platform_audit_chain',0))");
  const previous = await client.query<{ event_hash: string }>(
    "SELECT event_hash FROM platform_audit_events ORDER BY sequence DESC LIMIT 1",
  );
  const previousHash = previous.rows[0]?.event_hash ?? null;
  const canonical = JSON.stringify({
    previousHash,
    action: input.action,
    actorIdentityId: input.actorIdentityId,
    tenantId: input.tenantId,
    entityType: input.entityType,
    entityId: input.entityId,
    result: "success",
    requestId: input.requestId,
    metadata: input.metadata,
  });
  const eventHash = createHash("sha256").update(canonical).digest("hex");
  await client.query(
    `INSERT INTO platform_audit_events(
       actor_identity_id,tenant_id,action,entity_type,entity_id,result,
       request_id,metadata,previous_hash,event_hash
     ) VALUES ($1,$2,$3,$4,$5,'success',$6,$7,$8,$9)`,
    [
      input.actorIdentityId,
      input.tenantId,
      input.action,
      input.entityType,
      input.entityId,
      input.requestId,
      input.metadata,
      previousHash,
      eventHash,
    ],
  );
}
