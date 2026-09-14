import { createHash, randomBytes } from "node:crypto";
import { TextDecoder } from "node:util";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type GenerateAuthenticationOptionsOpts,
  type GenerateRegistrationOptionsOpts,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type VerifyAuthenticationResponseOpts,
  type VerifyRegistrationResponseOpts,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import {
  EnterpriseAuthStoreError,
  type DatabaseRuntime,
  type RequestPrincipal,
} from "@nombramientos/database";
import type { ApiConfig } from "../config.js";
import { ApiError } from "../lib/errors.js";
import { evaluateIdentitySessionPolicy } from "../lib/identity-policy-enforcement.js";
import { assertOperationStepUp } from "../lib/operation-step-up.js";
import { assertRecentMfa, RECENT_MFA_WINDOW_MS } from "../lib/recent-mfa.js";
import {
  challengeMatchesDigest,
  requireExactWebAuthnOrigin,
  type StepUpPurpose,
} from "./enterprise-auth-contract.js";
import {
  type AuthenticatedResult,
  type AuthService,
  createSessionBinding,
  sha256,
} from "./auth-service.js";

export const WEBAUTHN_SUPPORTED_ALGORITHMS = Object.freeze([-7, -257] as const);

type CeremonyType = "registration" | "authentication" | "step_up";
type PasskeyDeviceType = "singleDevice" | "multiDevice";
type PasskeyRevocationReason = "user_revoked" | "compromised" | "replaced";

const PERSONAL_REMEDIATION_PURPOSES = new Set<string>([
  "passkey_enrollment",
  "session_revocation",
]);

export interface WebAuthnEngine {
  generateRegistrationOptions(options: GenerateRegistrationOptionsOpts): Promise<PublicKeyCredentialCreationOptionsJSON>;
  verifyRegistrationResponse(options: VerifyRegistrationResponseOpts): Promise<VerifiedRegistrationResponse>;
  generateAuthenticationOptions(options: GenerateAuthenticationOptionsOpts): Promise<PublicKeyCredentialRequestOptionsJSON>;
  verifyAuthenticationResponse(options: VerifyAuthenticationResponseOpts): Promise<VerifiedAuthenticationResponse>;
}

const defaultWebAuthnEngine: WebAuthnEngine = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
};

interface EnterpriseIdentityPolicy {
  readonly baselineVersion: number;
  readonly tenantVersion: number | null;
  readonly enforcementMode: "monitor" | "enforce";
  readonly minimumAal: 1 | 2 | 3;
  readonly requireUserVerification: boolean;
  readonly privilegedMinimumAal: 2 | 3;
  readonly requireDeviceBoundForPrivileged: boolean;
  readonly requireAttestationForPrivileged: boolean;
  readonly requirePhishingResistantForPrivileged: boolean;
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
  readonly actionRequirements: Readonly<Record<string, {
    readonly minAal: 1 | 2 | 3;
    readonly phishingResistant?: boolean | undefined;
    readonly stepUpRequired?: boolean | undefined;
  }>>;
}

interface CeremonyRecord {
  readonly id: string;
  readonly type: CeremonyType;
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

interface PasskeyVerificationRecord {
  readonly id: string;
  readonly externalId: string;
  readonly identityId: string;
  readonly tenantId: string;
  readonly publicKey: Buffer;
  readonly userHandle: string;
  readonly counter: number;
  readonly transports: readonly string[];
  readonly deviceType: PasskeyDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly userVerified: boolean;
  readonly trustLevel: "unverified" | "self" | "attested" | "enterprise_attested";
  readonly rpId: string;
  readonly revokedAt: Date | null;
}

export interface PublicPasskeyCredential {
  readonly id: string;
  readonly name: string;
  readonly transports: readonly string[];
  readonly deviceType: PasskeyDeviceType;
  readonly backedUp: boolean;
  readonly attachment: "platform" | "cross-platform" | null;
  readonly trustLevel: "unverified" | "self" | "attested" | "enterprise_attested";
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly version: number;
}

interface StoredPasskeyCredential {
  readonly id: string;
  readonly externalId: string;
  readonly displayName: string;
  readonly transports: readonly string[];
  readonly deviceType: PasskeyDeviceType;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly discoverable: boolean;
  readonly userVerified: boolean;
  readonly aaguid: string | null;
  readonly attachment: "platform" | "cross-platform" | null;
  readonly trustLevel: "unverified" | "self" | "attested" | "enterprise_attested";
  readonly createdAt: Date;
  readonly lastUsedAt: Date | null;
  readonly revokedAt: Date | null;
  readonly revocationReason: string | null;
  readonly version: number;
}

export interface PublicAuthSession {
  readonly id: string;
  readonly current: boolean;
  readonly deviceLabel: string | null;
  readonly createdAt: Date;
  readonly lastSeenAt: Date;
  readonly expiresAt: Date;
  readonly idleExpiresAt: Date;
  readonly authMethod: string;
  readonly assurance: string;
  readonly aal: 1 | 2 | 3;
  readonly phishingResistant: boolean;
  readonly revokedAt: Date | null;
  readonly risk: {
    readonly elevated: boolean;
    readonly userAgentContextChanged: boolean | null;
    readonly ipContextChanged: boolean;
  };
}

interface StoredAuthSession {
  readonly id: string;
  readonly tenantId: string;
  readonly tenantName: string;
  readonly isCurrent: boolean;
  readonly assuranceLevel: string;
  readonly authMethod: string;
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

interface SessionMaterial {
  readonly token: string;
  readonly csrfToken: string;
  readonly record: {
    readonly tokenHash: string;
    readonly csrfHash: string;
    readonly expiresAt: Date;
    readonly userAgentHash?: string;
    readonly ipPrefixHash?: string;
    readonly deviceLabel?: string;
  };
}

interface EnterpriseAuthPersistence {
  createCeremony(input: {
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly type: CeremonyType;
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
  }): Promise<CeremonyRecord>;
  getActiveCeremony(input: { readonly id: string; readonly tokenHash: string; readonly type?: CeremonyType }): Promise<CeremonyRecord | null>;
  failCeremony(input: { readonly id: string; readonly tokenHash: string }): Promise<void>;
  getEffectiveIdentityPolicy(tenantId: string): Promise<EnterpriseIdentityPolicy>;
  upsertTenantIdentityPolicy(input: {
    readonly tenantId: string;
    readonly expectedVersion: number;
    readonly changedByIdentityId: string;
    readonly currentSessionId?: string;
    readonly policy: Omit<EnterpriseIdentityPolicy, "baselineVersion" | "tenantVersion">;
    readonly requestId: string;
  }): Promise<EnterpriseIdentityPolicy | null>;
  getCredentialByExternalId(externalId: string, rpId?: string): Promise<PasskeyVerificationRecord | null>;
  listCredentials(identityId: string): Promise<readonly StoredPasskeyCredential[]>;
  completeRegistration(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly sourceSessionId?: string;
    readonly credential: {
      readonly externalId: string;
      readonly publicKey: Buffer;
      readonly userHandle: string;
      readonly counter: number;
      readonly transports: readonly string[];
      readonly aaguid?: string;
      readonly attachment?: "platform" | "cross-platform";
      readonly deviceType: PasskeyDeviceType;
      readonly backupEligible: boolean;
      readonly backedUp: boolean;
      readonly discoverable: boolean;
      readonly userVerified: boolean;
      readonly attestationFormat?: string;
      readonly trustLevel?: "unverified" | "self" | "attested" | "enterprise_attested";
      readonly attestationObjectHash?: string;
      readonly rpId: string;
      readonly displayName: string;
    };
    readonly newSession: SessionMaterial["record"];
    readonly requestId: string;
  }): Promise<{ readonly credentialId: string; readonly sessionId: string; readonly identityId: string; readonly tenantId: string }>;
  completeAuthentication(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly credentialId: string;
    readonly newCounter: number;
    readonly newBackupState: boolean;
    readonly assertedDeviceType: PasskeyDeviceType;
    readonly tenantId: string;
    readonly newSession: SessionMaterial["record"];
    readonly requestId: string;
  }): Promise<{ readonly sessionId: string; readonly identityId: string; readonly tenantId: string }>;
  completeWebAuthnStepUp(input: {
    readonly ceremonyId: string;
    readonly tokenHash: string;
    readonly challengeHash: string;
    readonly credentialId: string;
    readonly newCounter: number;
    readonly newBackupState: boolean;
    readonly assertedDeviceType: PasskeyDeviceType;
    readonly grantTokenHash: string;
    readonly grantExpiresAt: Date;
    readonly requestId: string;
  }): Promise<{ readonly grantId: string; readonly expiresAt: Date }>;
  renameCredential(input: {
    readonly identityId: string;
    readonly credentialId: string;
    readonly displayName: string;
    readonly expectedVersion: number;
    readonly requestId: string;
  }): Promise<StoredPasskeyCredential | null>;
  revokeCredential(input: {
    readonly identityId: string;
    readonly credentialId: string;
    readonly reason: PasskeyRevocationReason;
    readonly currentSessionId?: string;
    readonly requestId: string;
  }): Promise<{
    readonly revoked: boolean;
    readonly sessionsRevoked: number;
    readonly currentSessionRevoked: boolean;
  }>;
  listIdentitySessions(identityId: string, currentSessionId: string): Promise<readonly StoredAuthSession[]>;
  revokeIdentitySession(input: {
    readonly identityId: string;
    readonly sessionId: string;
    readonly reason: "user_revoked";
    readonly requestId: string;
  }): Promise<boolean>;
  revokeOtherIdentitySessions(input: {
    readonly identityId: string;
    readonly currentSessionId: string;
    readonly reason: "user_revoked";
    readonly requestId: string;
  }): Promise<number>;
  enforceSessionLimit(
    identityId: string,
    tenantId: string,
    currentSessionId: string,
    maximumActiveSessions: number,
  ): Promise<number>;
}

export interface CeremonyOptionsResult<TOptions> {
  readonly ceremonyId: string;
  readonly options: TOptions;
  readonly expiresAt: Date;
  /** Kept out of the JSON response; the route writes this to an HttpOnly cookie. */
  readonly ceremonyToken: string;
}

export class EnterpriseAuthService {
  readonly #store: EnterpriseAuthPersistence;

  public constructor(
    private readonly database: DatabaseRuntime,
    private readonly config: ApiConfig,
    private readonly authService: AuthService,
    private readonly engine: WebAuthnEngine = defaultWebAuthnEngine,
  ) {
    this.#store = (database as unknown as { readonly enterpriseAuth: EnterpriseAuthPersistence }).enterpriseAuth;
    if (!this.#store) throw new Error("Enterprise authentication store is not available");
  }

  public async registrationOptions(input: {
    readonly principal: RequestPrincipal;
    readonly requestId: string;
    readonly grantToken?: string;
    readonly replacementCredentialId?: string;
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<CeremonyOptionsResult<PublicKeyCredentialCreationOptionsJSON>> {
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    const [policy, credentials] = await Promise.all([
      this.#store.getEffectiveIdentityPolicy(input.principal.activeTenantId),
      this.#store.listCredentials(input.principal.identityId),
    ]);
    const activeCredentials = credentials.filter((credential) => credential.revokedAt === null);
    const replacementCredential = input.replacementCredentialId
      ? activeCredentials.find((credential) => credential.id === input.replacementCredentialId)
      : undefined;
    if (input.replacementCredentialId && !replacementCredential) {
      throw new ApiError(404, "PASSKEY_REPLACEMENT_INVALID", "The passkey selected for replacement was not found");
    }
    if (activeCredentials.length >= policy.maximumPasskeys && !replacementCredential) {
      throw new ApiError(409, "PASSKEY_LIMIT_REACHED", "The maximum number of passkeys has been reached");
    }
    let firstPasskeyFreshUntil: Date | undefined;
    if (
      activeCredentials.length === 0
      && !["enrollment_only", "recovery_limited"].includes(input.principal.assuranceLevel)
    ) {
      firstPasskeyFreshUntil = assertFreshFirstPasskeyEnrollment(input.principal);
    }
    if (
      activeCredentials.length > 0
      && input.principal.assuranceLevel !== "recovery_limited"
    ) {
      const operationBody = replacementCredential
        ? { replacementCredentialId: replacementCredential.id }
        : {};
      await assertOperationStepUp({
        database: this.database,
        principal: input.principal,
        grantToken: input.grantToken,
        purpose: "passkey_enrollment",
        method: "POST",
        path: "/v1/auth/passkeys/registration/options",
        body: operationBody,
      });
    }

    const ceremonyStartedAt = Date.now();
    const ceremonyTtlMs = Math.min(
      this.config.webauthn.challengeTtlSeconds * 1_000,
      firstPasskeyFreshUntil
        ? Math.max(1, firstPasskeyFreshUntil.getTime() - ceremonyStartedAt)
        : Number.POSITIVE_INFINITY,
    );
    const options = await this.engine.generateRegistrationOptions({
      rpName: this.config.webauthn.rpName,
      rpID: this.config.webauthn.rpId,
      userName: input.principal.email,
      userDisplayName: input.principal.displayName,
      userID: Buffer.from(input.principal.identityId, "utf8"),
      timeout: ceremonyTtlMs,
      attestationType: policy.enforcementMode === "enforce" && policy.requireAttestationForPrivileged
        ? "direct"
        : "none",
      excludeCredentials: activeCredentials
        .filter((credential) => credential.externalId)
        .map((credential) => ({
          id: credential.externalId!,
          transports: [...credential.transports],
        })),
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      supportedAlgorithmIDs: [...WEBAUTHN_SUPPORTED_ALGORITHMS],
      preferredAuthenticatorType: "localDevice",
    });
    const ceremonyToken = randomToken();
    const expiresAt = new Date(ceremonyStartedAt + ceremonyTtlMs);
    const binding = createSessionBinding(input.userAgent, input.ip);
    const ceremony = await this.#store.createCeremony({
      tokenHash: sha256(ceremonyToken),
      challengeHash: sha256(options.challenge),
      type: "registration",
      identityId: input.principal.identityId,
      tenantId: input.principal.activeTenantId,
      sessionId: input.principal.sessionId,
      rpId: this.config.webauthn.rpId,
      expectedOrigin: origin,
      requireUserVerification: true,
      policyVersion: policyVersion(policy),
      ...(replacementCredential ? { replacementCredentialId: replacementCredential.id } : {}),
      ...binding,
      expiresAt,
    });
    return { ceremonyId: ceremony.id, options, expiresAt: ceremony.expiresAt, ceremonyToken };
  }

  public async verifyRegistration(input: {
    readonly principal: RequestPrincipal;
    readonly ceremonyId: string;
    readonly ceremonyToken: string;
    readonly response: RegistrationResponseJSON;
    readonly displayName: string;
    readonly requestId: string;
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<{
    readonly verified: true;
    readonly credential: PublicPasskeyCredential;
    readonly session: AuthenticatedResult;
  }> {
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    const tokenHash = sha256(input.ceremonyToken);
    const ceremony = await this.#activeCeremony(
      input.ceremonyId,
      tokenHash,
      "registration",
      origin,
      input.requestId,
      input.userAgent,
      input.ip,
    );
    if (
      ceremony.identityId !== input.principal.identityId
      || ceremony.tenantId !== input.principal.activeTenantId
      || ceremony.sessionId !== input.principal.sessionId
    ) {
      await this.#denyCeremony(ceremony, tokenHash);
    }

    const verification = await this.#verifyRegistration(input.response, ceremony, tokenHash);
    const info = verification.registrationInfo;
    if (!info.userVerified || info.origin !== ceremony.expectedOrigin || info.rpID !== ceremony.rpId) {
      await this.#denyCeremony(ceremony, tokenHash);
    }
    const policy = await this.#store.getEffectiveIdentityPolicy(input.principal.activeTenantId);
    if (!policy.allowSyncedPasskeys && info.credentialDeviceType === "multiDevice") {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash });
      throw new ApiError(403, "PASSKEY_POLICY_DENIED", "This organization requires a device-bound passkey");
    }

    const sessionMaterial = this.#sessionMaterial(policy, input.userAgent, input.ip);
    const completed = await this.#store.completeRegistration({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash: ceremony.challengeHash,
      sourceSessionId: ceremony.sessionId!,
      credential: {
        externalId: info.credential.id,
        publicKey: Buffer.from(info.credential.publicKey),
        userHandle: Buffer.from(input.principal.identityId, "utf8").toString("base64url"),
        counter: info.credential.counter,
        transports: info.credential.transports ?? input.response.response.transports ?? [],
        aaguid: info.aaguid,
        ...(input.response.authenticatorAttachment ? { attachment: input.response.authenticatorAttachment } : {}),
        deviceType: info.credentialDeviceType,
        backupEligible: info.credentialDeviceType === "multiDevice",
        backedUp: info.credentialBackedUp,
        discoverable: true,
        userVerified: info.userVerified,
        attestationFormat: info.fmt,
        trustLevel: "unverified",
        attestationObjectHash: sha256Bytes(info.attestationObject),
        rpId: ceremony.rpId,
        displayName: input.displayName,
      },
      newSession: sessionMaterial.record,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    await this.#store.enforceSessionLimit(
      completed.identityId,
      completed.tenantId,
      completed.sessionId,
      policy.maximumActiveSessions,
    ).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    const session = await this.#hydrateSession(sessionMaterial, completed.sessionId, input.requestId, input.userAgent, input.ip);
    const credential = await this.#credentialById(input.principal.identityId, completed.credentialId);
    return { verified: true, credential, session };
  }

  public async authenticationOptions(input: {
    readonly email?: string;
    readonly mediation: "conditional" | "optional";
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<CeremonyOptionsResult<PublicKeyCredentialRequestOptionsJSON>> {
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    // Public passkey login is deliberately usernameless. Ignoring the optional
    // identifier keeps option shape, database work, and timing independent of
    // account existence while discoverable credentials identify the account.
    const options = await this.engine.generateAuthenticationOptions({
      rpID: this.config.webauthn.rpId,
      timeout: this.config.webauthn.challengeTtlSeconds * 1_000,
      userVerification: "required",
    });
    const ceremonyToken = randomToken();
    const expiresAt = new Date(Date.now() + this.config.webauthn.challengeTtlSeconds * 1_000);
    const binding = createSessionBinding(input.userAgent, input.ip);
    const ceremony = await this.#store.createCeremony({
      tokenHash: sha256(ceremonyToken),
      challengeHash: sha256(options.challenge),
      type: "authentication",
      rpId: this.config.webauthn.rpId,
      expectedOrigin: origin,
      requireUserVerification: true,
      policyVersion: 1,
      ...binding,
      expiresAt,
    });
    return { ceremonyId: ceremony.id, options, expiresAt: ceremony.expiresAt, ceremonyToken };
  }

  public async verifyAuthentication(input: {
    readonly ceremonyId: string;
    readonly ceremonyToken: string;
    readonly response: AuthenticationResponseJSON;
    readonly requestId: string;
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<AuthenticatedResult> {
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    const tokenHash = sha256(input.ceremonyToken);
    const ceremony = await this.#activeCeremony(
      input.ceremonyId,
      tokenHash,
      "authentication",
      origin,
      input.requestId,
      input.userAgent,
      input.ip,
    );
    const credential = await this.#credentialForResponse(input.response, ceremony, tokenHash);
    const verification = await this.#verifyAuthentication(input.response, credential, ceremony, tokenHash);
    const policy = await this.#store.getEffectiveIdentityPolicy(credential.tenantId);
    if (!policy.allowSyncedPasskeys && credential.deviceType === "multiDevice") {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash });
      throw new ApiError(403, "PASSKEY_POLICY_DENIED", "This organization does not permit synced passkeys");
    }
    const sessionMaterial = this.#sessionMaterial(policy, input.userAgent, input.ip);
    const completed = await this.#store.completeAuthentication({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash: ceremony.challengeHash,
      credentialId: credential.id,
      newCounter: verification.authenticationInfo.newCounter,
      newBackupState: verification.authenticationInfo.credentialBackedUp,
      assertedDeviceType: verification.authenticationInfo.credentialDeviceType,
      tenantId: credential.tenantId,
      newSession: sessionMaterial.record,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    try {
      // A valid passkey is an independent phishing-resistant recovery from a
      // password/MFA lockout and is the terminal point at which its shared
      // identity failure budget may be cleared.
      await this.database.control.recordLoginSuccess(completed.identityId);
    } catch (error) {
      await this.database.control.revokeSession(completed.sessionId, "passkey_login_state_reset_failed").catch(() => undefined);
      throw error;
    }
    await this.#store.enforceSessionLimit(
      completed.identityId,
      completed.tenantId,
      completed.sessionId,
      policy.maximumActiveSessions,
    ).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    return this.#hydrateSession(sessionMaterial, completed.sessionId, input.requestId, input.userAgent, input.ip);
  }

  public async stepUpOptions(input: {
    readonly principal: RequestPrincipal;
    readonly purpose: StepUpPurpose;
    readonly operationHash: string;
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<CeremonyOptionsResult<PublicKeyCredentialRequestOptionsJSON>> {
    if (["enrollment_only", "recovery_limited"].includes(input.principal.assuranceLevel)) {
      throw new ApiError(403, "RECOVERY_RESTRICTED", "Recovery and enrollment sessions cannot request privileged step-up");
    }
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    const [policy, credentials] = await Promise.all([
      this.#store.getEffectiveIdentityPolicy(input.principal.activeTenantId),
      this.#store.listCredentials(input.principal.identityId),
    ]);
    const allActiveCredentials = credentials.filter((credential) => credential.revokedAt === null && credential.externalId);
    const remediationPurpose = PERSONAL_REMEDIATION_PURPOSES.has(input.purpose);
    const activeCredentials = allActiveCredentials.filter((credential) => (
      remediationPurpose || policy.allowSyncedPasskeys || credential.deviceType !== "multiDevice"
    ));
    if (activeCredentials.length === 0) {
      if (allActiveCredentials.length > 0) {
        throw new ApiError(403, "PASSKEY_POLICY_DENIED", "No registered passkey satisfies this operation's authentication policy");
      }
      throw new ApiError(428, "PASSKEY_REQUIRED", "A registered passkey is required for phishing-resistant step-up");
    }
    const options = await this.engine.generateAuthenticationOptions({
      rpID: this.config.webauthn.rpId,
      timeout: Math.min(policy.stepUpTtlSeconds, this.config.webauthn.stepUpTtlSeconds) * 1_000,
      allowCredentials: activeCredentials.map((credential) => ({ id: credential.externalId!, transports: [...credential.transports] })),
      userVerification: "required",
    });
    const ceremonyToken = randomToken();
    const expiresAt = new Date(Date.now() + Math.min(policy.stepUpTtlSeconds, this.config.webauthn.stepUpTtlSeconds) * 1_000);
    const ceremony = await this.#store.createCeremony({
      tokenHash: sha256(ceremonyToken),
      challengeHash: sha256(options.challenge),
      type: "step_up",
      identityId: input.principal.identityId,
      tenantId: input.principal.activeTenantId,
      sessionId: input.principal.sessionId,
      purpose: input.purpose,
      operationHash: input.operationHash,
      rpId: this.config.webauthn.rpId,
      expectedOrigin: origin,
      requireUserVerification: true,
      policyVersion: policyVersion(policy),
      ...createSessionBinding(input.userAgent, input.ip),
      expiresAt,
    });
    return { ceremonyId: ceremony.id, options, expiresAt: ceremony.expiresAt, ceremonyToken };
  }

  public async verifyStepUp(input: {
    readonly principal: RequestPrincipal;
    readonly ceremonyId: string;
    readonly ceremonyToken: string;
    readonly response: AuthenticationResponseJSON;
    readonly requestId: string;
    readonly origin?: string;
    readonly userAgent?: string;
    readonly ip?: string;
  }): Promise<{
    readonly verified: true;
    readonly grantToken: string;
    readonly expiresAt: Date;
    readonly purpose: string;
    readonly operationHash: string;
  }> {
    const origin = requireExactWebAuthnOrigin(input.origin, this.config.webauthn.expectedOrigins);
    const tokenHash = sha256(input.ceremonyToken);
    const ceremony = await this.#activeCeremony(
      input.ceremonyId,
      tokenHash,
      "step_up",
      origin,
      input.requestId,
      input.userAgent,
      input.ip,
    );
    if (
      ceremony.identityId !== input.principal.identityId
      || ceremony.tenantId !== input.principal.activeTenantId
      || ceremony.sessionId !== input.principal.sessionId
      || !ceremony.purpose
      || !ceremony.operationHash
    ) {
      await this.#denyCeremony(ceremony, tokenHash);
    }
    const credential = await this.#credentialForResponse(input.response, ceremony, tokenHash);
    const verification = await this.#verifyAuthentication(input.response, credential, ceremony, tokenHash);
    const [policy, credentials] = await Promise.all([
      this.#store.getEffectiveIdentityPolicy(input.principal.activeTenantId),
      this.#store.listCredentials(input.principal.identityId),
    ]);
    try {
      this.#assertPrivilegedCredentialPolicy(
        policy,
        credential,
        ceremony.purpose!,
        credentials.filter((candidate) =>
          candidate.revokedAt === null
          && candidate.userVerified
          && (policy.allowSyncedPasskeys || candidate.deviceType === "singleDevice")
          && (!policy.requireDeviceBoundForPrivileged || candidate.deviceType === "singleDevice")
          && (
            !policy.requireAttestationForPrivileged
            || ["attested", "enterprise_attested"].includes(candidate.trustLevel)
          )
        ).length,
      );
    } catch (error) {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash });
      throw error;
    }
    const grantToken = randomToken();
    const grantExpiresAt = new Date(Date.now() + Math.min(policy.stepUpTtlSeconds, this.config.webauthn.stepUpTtlSeconds) * 1_000);
    const completed = await this.#store.completeWebAuthnStepUp({
      ceremonyId: ceremony.id,
      tokenHash,
      challengeHash: ceremony.challengeHash,
      credentialId: credential.id,
      newCounter: verification.authenticationInfo.newCounter,
      newBackupState: verification.authenticationInfo.credentialBackedUp,
      assertedDeviceType: verification.authenticationInfo.credentialDeviceType,
      grantTokenHash: sha256(grantToken),
      grantExpiresAt,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    return {
      verified: true,
      grantToken,
      expiresAt: completed.expiresAt,
      purpose: ceremony.purpose!,
      operationHash: ceremony.operationHash!,
    };
  }

  public async listPasskeys(identityId: string): Promise<readonly PublicPasskeyCredential[]> {
    return (await this.#store.listCredentials(identityId)).map(publicPasskey);
  }

  public async renamePasskey(input: {
    readonly principal: RequestPrincipal;
    readonly credentialId: string;
    readonly displayName: string;
    readonly expectedVersion: number;
    readonly requestId: string;
  }): Promise<PublicPasskeyCredential> {
    const credential = await this.#store.renameCredential({
      identityId: input.principal.identityId,
      credentialId: input.credentialId,
      displayName: input.displayName,
      expectedVersion: input.expectedVersion,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    if (!credential) throw new ApiError(409, "PASSKEY_VERSION_CONFLICT", "The passkey changed; refresh and try again");
    return publicPasskey(credential);
  }

  public async revokePasskey(input: {
    readonly principal: RequestPrincipal;
    readonly credentialId: string;
    readonly reason: PasskeyRevocationReason;
    readonly requestId: string;
  }): Promise<{
    readonly revoked: true;
    readonly sessionsRevoked: number;
    readonly currentSessionRevoked: boolean;
  }> {
    const [policy, credentials] = await Promise.all([
      this.#store.getEffectiveIdentityPolicy(input.principal.activeTenantId),
      this.#store.listCredentials(input.principal.identityId),
    ]);
    const activeCredentials = credentials.filter((credential) => credential.revokedAt === null);
    const target = activeCredentials.find((credential) => credential.id === input.credentialId);
    if (target && policy.enforcementMode === "enforce") {
      const requiredCount = Math.max(policy.minimumPasskeyCount, policy.privilegedMinimumPasskeyCount);
      if (activeCredentials.length - 1 < requiredCount) {
        throw new ApiError(
          409,
          "PASSKEY_POLICY_MINIMUM",
          "This passkey cannot be revoked until another compliant passkey is registered",
          { requiredCount, activeCount: activeCredentials.length },
        );
      }
    }
    // TOTP and recovery codes are continuations of a password challenge, not
    // independent login methods. Do not count a merely enabled recovery-code
    // policy as proof that this particular identity has a usable code.
    const hasNonPasskeyRecovery = policy.allowPassword && (
      !input.principal.mfaRequired
      || (input.principal.mfaEnabled && policy.allowTotpFallback)
    );
    if (target && !hasNonPasskeyRecovery && activeCredentials.length < 2) {
      throw new ApiError(
        409,
        "PASSKEY_RECOVERY_PATH_REQUIRED",
        "Register another passkey before revoking the only remaining account authenticator",
      );
    }
    const result = await this.#store.revokeCredential({
      identityId: input.principal.identityId,
      credentialId: input.credentialId,
      reason: input.reason,
      currentSessionId: input.principal.sessionId,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw passkeyRevocationApiError(error); });
    if (!result.revoked) throw new ApiError(404, "PASSKEY_NOT_FOUND", "Passkey was not found");
    return {
      revoked: true,
      sessionsRevoked: result.sessionsRevoked,
      currentSessionRevoked: result.currentSessionRevoked,
    };
  }

  public async listSessions(principal: RequestPrincipal): Promise<readonly PublicAuthSession[]> {
    return (await this.#store.listIdentitySessions(principal.identityId, principal.sessionId)).map((session) => ({
      id: session.id,
      current: session.isCurrent,
      deviceLabel: session.deviceLabel,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt,
      idleExpiresAt: session.idleExpiresAt,
      authMethod: session.authMethod,
      assurance: session.assuranceLevel,
      aal: session.aal,
      phishingResistant: session.phishingResistant,
      revokedAt: null,
      risk: {
        elevated: session.ipContextChanged || (
          session.isCurrent && principal.userAgentContextChanged === true
        ),
        userAgentContextChanged: session.isCurrent
          ? principal.userAgentContextChanged === true
          : null,
        ipContextChanged: session.ipContextChanged,
      },
    }));
  }

  public async revokeSession(input: {
    readonly principal: RequestPrincipal;
    readonly sessionId: string;
    readonly requestId: string;
  }): Promise<{ readonly revoked: true; readonly current: boolean }> {
    const revoked = await this.#store.revokeIdentitySession({
      identityId: input.principal.identityId,
      sessionId: input.sessionId,
      reason: "user_revoked",
      requestId: input.requestId,
    });
    if (!revoked) throw new ApiError(404, "SESSION_NOT_FOUND", "Session was not found");
    return { revoked: true, current: input.sessionId === input.principal.sessionId };
  }

  public async revokeOtherSessions(input: {
    readonly principal: RequestPrincipal;
    readonly requestId: string;
  }): Promise<{ readonly revoked: number }> {
    return {
      revoked: await this.#store.revokeOtherIdentitySessions({
        identityId: input.principal.identityId,
        currentSessionId: input.principal.sessionId,
        reason: "user_revoked",
        requestId: input.requestId,
      }),
    };
  }

  public async getEffectivePolicy(principal: RequestPrincipal): Promise<{
    readonly policy: EnterpriseIdentityPolicy;
    readonly compliance: {
      readonly enforcementMode: "monitor" | "enforce";
      readonly sessionMeetsMinimum: boolean;
      readonly privilegedSessionReady: boolean;
      readonly deviceBoundCredential: boolean | null;
      readonly attestedCredential: boolean | null;
      readonly activePasskeys: number;
      readonly policyEligiblePasskeys: number;
      readonly privilegedEligiblePasskeys: number;
      readonly minimumPasskeys: number;
      readonly privilegedMinimumPasskeys: number;
      readonly findings: readonly string[];
    };
  }> {
    const [policy, credentials] = await Promise.all([
      this.#store.getEffectiveIdentityPolicy(principal.activeTenantId),
      this.#store.listCredentials(principal.identityId),
    ]);
    const activeCredentials = credentials.filter((credential) => credential.revokedAt === null);
    const activePasskeys = activeCredentials.length;
    const policyEligiblePasskeys = activeCredentials.filter((credential) =>
      credential.userVerified
      && (policy.allowSyncedPasskeys || credential.deviceType === "singleDevice")
    ).length;
    const privilegedEligiblePasskeys = activeCredentials.filter((credential) =>
      credential.userVerified
      && (policy.allowSyncedPasskeys || credential.deviceType === "singleDevice")
      && (!policy.requireDeviceBoundForPrivileged || credential.deviceType === "singleDevice")
      && (
        !policy.requireAttestationForPrivileged
        || ["attested", "enterprise_attested"].includes(credential.trustLevel)
      )
    ).length;
    const currentCredential = principal.authenticatedCredentialId
      ? credentials.find((credential) => credential.id === principal.authenticatedCredentialId && credential.revokedAt === null)
      : undefined;
    const aal = principal.aal ?? (principal.assuranceLevel === "mfa" ? 2 : 1);
    const phishingResistant = principal.phishingResistant ?? false;
    const deviceBoundCredential = currentCredential ? currentCredential.deviceType === "singleDevice" : null;
    const attestedCredential = currentCredential
      ? ["attested", "enterprise_attested"].includes(currentCredential.trustLevel)
      : null;
    const sessionMeetsMinimum = aal >= policy.minimumAal && policyEligiblePasskeys >= policy.minimumPasskeyCount;
    const privilegedSessionReady = aal >= policy.privilegedMinimumAal
      && privilegedEligiblePasskeys >= policy.privilegedMinimumPasskeyCount
      && (!policy.requirePhishingResistantForPrivileged || phishingResistant)
      && (!policy.requireDeviceBoundForPrivileged || deviceBoundCredential === true)
      && (!policy.requireAttestationForPrivileged || attestedCredential === true);
    const findings: string[] = [];
    if (aal < policy.minimumAal) findings.push("session_aal_below_minimum");
    if (policyEligiblePasskeys < policy.minimumPasskeyCount) findings.push("passkey_count_below_minimum");
    if (aal < policy.privilegedMinimumAal) findings.push("session_aal_below_privileged_minimum");
    if (privilegedEligiblePasskeys < policy.privilegedMinimumPasskeyCount) findings.push("passkey_count_below_privileged_minimum");
    if (policy.requirePhishingResistantForPrivileged && !phishingResistant) findings.push("phishing_resistant_step_up_required");
    if (policy.requireDeviceBoundForPrivileged && deviceBoundCredential !== true) findings.push("device_bound_passkey_required");
    if (policy.requireAttestationForPrivileged && attestedCredential !== true) findings.push("attested_passkey_required");
    return {
      policy,
      compliance: {
        enforcementMode: policy.enforcementMode,
        sessionMeetsMinimum,
        privilegedSessionReady,
        deviceBoundCredential,
        attestedCredential,
        activePasskeys,
        policyEligiblePasskeys,
        privilegedEligiblePasskeys,
        minimumPasskeys: policy.minimumPasskeyCount,
        privilegedMinimumPasskeys: policy.privilegedMinimumPasskeyCount,
        findings,
      },
    };
  }

  public async updateIdentityPolicy(input: {
    readonly principal: RequestPrincipal;
    readonly expectedVersion: number;
    readonly policy: Omit<EnterpriseIdentityPolicy, "baselineVersion" | "tenantVersion">;
    readonly requestId: string;
  }): Promise<EnterpriseIdentityPolicy> {
    assertSafePolicyActivation(input.policy);
    if (input.policy.enforcementMode === "enforce") {
      const activePasskeyCount = (await this.#store.listCredentials(input.principal.identityId))
        .filter((credential) =>
          credential.revokedAt === null
          && credential.userVerified
          && (
            input.policy.allowSyncedPasskeys
            && !input.policy.requireDeviceBoundForPrivileged
              ? true
              : credential.deviceType === "singleDevice"
          ));
      const requiredPasskeyCount = Math.max(
        input.policy.minimumPasskeyCount,
        input.policy.privilegedMinimumPasskeyCount,
      );
      if (activePasskeyCount.length < requiredPasskeyCount) {
        throw new ApiError(
          409,
          "IDENTITY_POLICY_ACTIVATION_UNSAFE",
          "Register the required passkeys before activating enforcement",
          { activePasskeyCount: activePasskeyCount.length, requiredPasskeyCount },
        );
      }
    }
    const updated = await this.#store.upsertTenantIdentityPolicy({
      tenantId: input.principal.activeTenantId,
      expectedVersion: input.expectedVersion,
      changedByIdentityId: input.principal.identityId,
      currentSessionId: input.principal.sessionId,
      policy: input.policy,
      requestId: input.requestId,
    }).catch((error: unknown) => { throw enterpriseAuthApiError(error); });
    if (!updated) throw new ApiError(409, "IDENTITY_POLICY_VERSION_CONFLICT", "Identity policy changed; refresh and try again");
    return updated;
  }

  async #activeCeremony(
    id: string,
    tokenHash: string,
    type: CeremonyType,
    origin: string,
    requestId: string,
    userAgent?: string,
    ip?: string,
  ): Promise<CeremonyRecord> {
    const ceremony = await this.#store.getActiveCeremony({ id, tokenHash, type });
    if (!ceremony) throw invalidCeremony();
    const binding = createSessionBinding(userAgent, ip);
    const originMismatch = ceremony.expectedOrigin !== origin;
    const userAgentMismatch = ceremony.userAgentHash !== null
      && ceremony.userAgentHash !== binding.userAgentHash;
    const ipContextMismatch = ceremony.ipPrefixHash !== null
      && ceremony.ipPrefixHash !== binding.ipPrefixHash;
    const invalid = ceremony.type !== type
      || ceremony.rpId !== this.config.webauthn.rpId
      || originMismatch
      || userAgentMismatch
      || ipContextMismatch
      || !ceremony.requireUserVerification
      || ceremony.expiresAt <= new Date();
    if (invalid) {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash }).catch(() => undefined);
      await this.database.control.appendAudit({
        ...(ceremony.identityId ? { actorIdentityId: ceremony.identityId } : {}),
        ...(ceremony.tenantId ? { tenantId: ceremony.tenantId } : {}),
        action: "auth.webauthn_ceremony_binding_denied",
        entityType: "webauthn_ceremony",
        entityId: ceremony.id,
        result: "denied",
        requestId,
        metadata: {
          ceremonyType: type,
          originMismatch,
          userAgentMismatch,
          ipContextMismatch,
        },
      }).catch(() => undefined);
      throw invalidCeremony();
    }
    return ceremony;
  }

  #assertPrivilegedCredentialPolicy(
    policy: EnterpriseIdentityPolicy,
    credential: PasskeyVerificationRecord,
    purpose: string,
    activePasskeyCount: number,
  ): void {
    // Personal authenticator/session remediation must remain possible with any
    // cryptographically valid UV passkey, even while privileged posture is not
    // yet compliant. Otherwise a tightened policy becomes self-locking.
    if (PERSONAL_REMEDIATION_PURPOSES.has(purpose)) return;
    // Method allow/deny is an active control in both rollout modes.
    if (!policy.allowSyncedPasskeys && credential.deviceType === "multiDevice") {
      throw new ApiError(403, "PASSKEY_POLICY_DENIED", "This organization does not permit synced passkeys for privileged operations");
    }
    // Monitor mode surfaces posture through GET /v1/auth/policy without
    // interrupting users. Baseline WebAuthn signature and UV checks remain
    // mandatory in every mode.
    if (policy.enforcementMode !== "enforce") return;
    if (policy.privilegedMinimumAal > 2) {
      throw new ApiError(403, "AAL3_REQUIRED", "This organization requires an attested hardware authenticator for privileged operations");
    }
    if (policy.requireDeviceBoundForPrivileged && credential.deviceType !== "singleDevice") {
      throw new ApiError(403, "DEVICE_BOUND_PASSKEY_REQUIRED", "This operation requires a device-bound passkey");
    }
    if (
      policy.requireAttestationForPrivileged
      && !["attested", "enterprise_attested"].includes(credential.trustLevel)
    ) {
      throw new ApiError(403, "ATTESTED_PASSKEY_REQUIRED", "This operation requires an enterprise-attested passkey");
    }
    if (activePasskeyCount < policy.privilegedMinimumPasskeyCount) {
      throw new ApiError(403, "PASSKEY_POLICY_MINIMUM", "More registered passkeys are required for privileged operations");
    }
  }

  async #credentialForResponse(
    response: AuthenticationResponseJSON,
    ceremony: CeremonyRecord,
    tokenHash: string,
  ): Promise<PasskeyVerificationRecord> {
    const credential = await this.#store.getCredentialByExternalId(response.id, ceremony.rpId);
    if (!credential) {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash });
      throw verificationFailed();
    }
    if (
      credential.revokedAt !== null
      || credential.rpId !== ceremony.rpId
      || (ceremony.identityId !== null && credential.identityId !== ceremony.identityId)
      || (!ceremony.identityId && !response.response.userHandle)
      || (response.response.userHandle !== undefined && response.response.userHandle !== credential.userHandle)
    ) {
      await this.#store.failCeremony({ id: ceremony.id, tokenHash });
      throw verificationFailed();
    }
    return credential;
  }

  async #verifyRegistration(
    response: RegistrationResponseJSON,
    ceremony: CeremonyRecord,
    tokenHash: string,
  ): Promise<Extract<VerifiedRegistrationResponse, { readonly verified: true }>> {
    try {
      assertSameOriginWebAuthnClientData(response.response.clientDataJSON);
      const result = await this.engine.verifyRegistrationResponse({
        response,
        expectedChallenge: (candidate) => challengeMatchesDigest(candidate, ceremony.challengeHash),
        expectedOrigin: ceremony.expectedOrigin,
        expectedRPID: ceremony.rpId,
        expectedType: "webauthn.create",
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: [...WEBAUTHN_SUPPORTED_ALGORITHMS],
      });
      if (result.verified) return result;
    } catch {
      // Verification details may contain credential material and are never reflected.
    }
    await this.#store.failCeremony({ id: ceremony.id, tokenHash });
    throw new ApiError(401, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed");
  }

  async #verifyAuthentication(
    response: AuthenticationResponseJSON,
    credential: PasskeyVerificationRecord,
    ceremony: CeremonyRecord,
    tokenHash: string,
  ): Promise<VerifiedAuthenticationResponse> {
    try {
      assertSameOriginWebAuthnClientData(response.response.clientDataJSON);
      const result = await this.engine.verifyAuthenticationResponse({
        response,
        expectedChallenge: (candidate) => challengeMatchesDigest(candidate, ceremony.challengeHash),
        expectedOrigin: ceremony.expectedOrigin,
        expectedRPID: ceremony.rpId,
        expectedType: "webauthn.get",
        requireUserVerification: true,
        credential: {
          id: credential.externalId,
          publicKey: new Uint8Array(credential.publicKey),
          counter: credential.counter,
          transports: [...credential.transports],
        },
      });
      if (
        result.verified
        && result.authenticationInfo.userVerified
        && result.authenticationInfo.origin === ceremony.expectedOrigin
        && result.authenticationInfo.rpID === ceremony.rpId
        && result.authenticationInfo.credentialDeviceType === credential.deviceType
      ) return result;
    } catch {
      // Verification details may contain credential material and are never reflected.
    }
    await this.#store.failCeremony({ id: ceremony.id, tokenHash });
    throw new ApiError(401, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed");
  }

  async #denyCeremony(ceremony: CeremonyRecord, tokenHash: string): Promise<never> {
    await this.#store.failCeremony({ id: ceremony.id, tokenHash });
    throw invalidCeremony();
  }

  #sessionMaterial(policy: EnterpriseIdentityPolicy, userAgent?: string, ip?: string): SessionMaterial {
    const token = randomToken();
    const csrfToken = randomToken();
    const absoluteSeconds = Math.min(this.config.sessionTtlSeconds, policy.absoluteSessionMinutes * 60);
    return {
      token,
      csrfToken,
      record: {
        tokenHash: sha256(token),
        csrfHash: sha256(csrfToken),
        expiresAt: new Date(Date.now() + absoluteSeconds * 1_000),
        ...createSessionBinding(userAgent, ip),
        ...(userAgent ? { deviceLabel: describeDevice(userAgent) } : {}),
      },
    };
  }

  async #hydrateSession(
    material: SessionMaterial,
    expectedSessionId: string,
    requestId: string,
    userAgent?: string,
    ip?: string,
  ): Promise<AuthenticatedResult> {
    const loadedPrincipal = await this.database.getPrincipal(
      sha256(material.token),
      requestId,
      createSessionBinding(userAgent, ip),
    );
    if (!loadedPrincipal || loadedPrincipal.sessionId !== expectedSessionId) {
      if (loadedPrincipal) await this.database.control.revokeSession(loadedPrincipal.sessionId, "webauthn_session_context_failed");
      throw new Error("WebAuthn session could not be loaded");
    }
    const decision = await evaluateIdentitySessionPolicy(this.database, loadedPrincipal);
    const principal = decision.principal;
    const keyGrant = principal.enrollmentOnly || principal.assuranceLevel === "recovery_limited"
      ? null
      : await this.database.withPrincipal(principal, requestId, (tenant) => tenant.getKeyGrant(principal.identityId));
    return {
      ...this.authService.publicSession(principal, material.csrfToken, keyGrant, decision.activePasskeyCount),
      sessionToken: material.token,
      expiresAt: principal.expiresAt,
    };
  }

  async #credentialById(identityId: string, id: string): Promise<PublicPasskeyCredential> {
    const credential = (await this.#store.listCredentials(identityId)).find((candidate) => candidate.id === id);
    if (!credential) throw new Error("Newly registered credential could not be loaded");
    return publicPasskey(credential);
  }
}

function assertSameOriginWebAuthnClientData(clientDataJSON: string): void {
  let clientData: unknown;
  try {
    const encoded = Buffer.from(clientDataJSON, "base64url");
    if (encoded.byteLength === 0 || encoded.toString("base64url") !== clientDataJSON) {
      throw new Error("WebAuthn client data encoding is invalid");
    }
    clientData = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(encoded));
  } catch {
    throw new Error("WebAuthn client data is invalid");
  }
  if (!clientData || typeof clientData !== "object" || Array.isArray(clientData)) {
    throw new Error("WebAuthn client data is invalid");
  }
  const record = clientData as Record<string, unknown>;
  if (
    (Object.hasOwn(record, "crossOrigin") && typeof record["crossOrigin"] !== "boolean")
    || record["crossOrigin"] === true
    || Object.hasOwn(record, "topOrigin")
  ) {
    // This RP never permits WebAuthn from a cross-origin iframe. Validate the
    // signed clientDataJSON explicitly instead of relying on library-version
    // behavior for the WebAuthn Level 3 crossOrigin/topOrigin steps.
    throw new Error("Cross-origin WebAuthn client data is not supported");
  }
}

function assertSafePolicyActivation(
  policy: Omit<EnterpriseIdentityPolicy, "baselineVersion" | "tenantVersion">,
): void {
  // This deployment currently issues AAL2 WebAuthn grants and intentionally
  // records attestation trust as unverified until a real trust service (for
  // example FIDO MDS plus enterprise attestation governance) is configured.
  // Reject an enforce transition that no administrator can satisfy in this
  // deployment. Method controls and device-bound posture are supported: the
  // persistence boundary validates every affected identity under row locks and
  // rolls the policy update back atomically when readiness cannot be proven.
  const unsupportedFields: string[] = [];
  if (policy.enforcementMode === "enforce") {
    if (policy.minimumAal > 2) unsupportedFields.push("minimumAal");
    if (policy.privilegedMinimumAal > 2) unsupportedFields.push("privilegedMinimumAal");
    if (policy.requireAttestationForPrivileged) unsupportedFields.push("requireAttestationForPrivileged");
    for (const [action, requirement] of Object.entries(policy.actionRequirements)) {
      if (requirement.minAal > 2) unsupportedFields.push(`actionRequirements.${action}.minAal`);
    }
  }
  if (unsupportedFields.length > 0) {
    throw new ApiError(
      409,
      "IDENTITY_POLICY_ACTIVATION_UNSAFE",
      "Enforcement cannot be activated until every affected identity has a verified recovery and authenticator path",
      { unsupportedFields },
    );
  }
}

function assertFreshFirstPasskeyEnrollment(principal: RequestPrincipal): Date {
  if (principal.assuranceLevel === "mfa") {
    assertRecentMfa(principal, {
      purpose: "registering the first passkey",
      staleCode: "PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED",
      staleMessage: "Sign in again with MFA before registering the first passkey",
    });
    return new Date(principal.mfaVerifiedAt!.getTime() + RECENT_MFA_WINDOW_MS);
  }
  const authenticatedAt = principal.authenticatedAt.getTime();
  const passwordAuthenticated = principal.assuranceLevel === "password"
    && (principal.authMethod ?? "password") === "password";
  if (
    passwordAuthenticated
    && Number.isFinite(authenticatedAt)
    && authenticatedAt > Date.now() - RECENT_MFA_WINDOW_MS
  ) return new Date(authenticatedAt + RECENT_MFA_WINDOW_MS);
  throw new ApiError(
    428,
    "PASSKEY_ENROLLMENT_REAUTHENTICATION_REQUIRED",
    "Sign in again before registering the first passkey",
    { maxAgeSeconds: RECENT_MFA_WINDOW_MS / 1_000, purpose: "registering the first passkey" },
  );
}

function invalidCeremony(): ApiError {
  return new ApiError(401, "WEBAUTHN_CEREMONY_INVALID", "WebAuthn ceremony is invalid, expired, or already used");
}

function verificationFailed(): ApiError {
  return new ApiError(401, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed");
}

function enterpriseAuthApiError(error: unknown): ApiError {
  if (!(error instanceof EnterpriseAuthStoreError)) throw error;
  switch (error.code) {
    case "CEREMONY_INVALID":
    case "CREDENTIAL_INVALID":
    case "CREDENTIAL_REPLAYED":
      return new ApiError(401, "WEBAUTHN_VERIFICATION_FAILED", "Passkey verification failed");
    case "SESSION_INVALID":
      return new ApiError(401, "SESSION_INVALID", "The authentication session is invalid or expired");
    case "RECOVERY_GOVERNANCE_INVALID":
      return new ApiError(
        409,
        "INITIAL_ADMIN_RECOVERY_GOVERNANCE_WITHDRAWN",
        "The governed recovery was revoked because its dual-control authority changed",
      );
    case "STEP_UP_INVALID":
      return new ApiError(401, "WEBAUTHN_STEP_UP_INVALID", "Step-up verification is invalid, expired, or already used");
    case "PASSKEY_LIMIT_REACHED":
      return new ApiError(409, "PASSKEY_LIMIT_REACHED", "The maximum number of passkeys has been reached");
    case "CREDENTIAL_CONFLICT":
      return new ApiError(409, "PASSKEY_CONFLICT", "The passkey is already registered or its name is in use");
    case "POLICY_CONFLICT":
      return new ApiError(
        409,
        "IDENTITY_POLICY_ACTIVATION_UNSAFE",
        "The requested identity policy cannot be applied without locking out an active identity",
      );
  }
}

function passkeyRevocationApiError(error: unknown): ApiError {
  if (error instanceof EnterpriseAuthStoreError && error.code === "POLICY_CONFLICT") {
    return new ApiError(
      409,
      "PASSKEY_POLICY_MINIMUM",
      "This passkey cannot be revoked because it would violate an active authentication policy",
    );
  }
  return enterpriseAuthApiError(error);
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function policyVersion(policy: EnterpriseIdentityPolicy): number {
  return policy.tenantVersion ?? policy.baselineVersion;
}

function publicPasskey(credential: StoredPasskeyCredential): PublicPasskeyCredential {
  return {
    id: credential.id,
    name: credential.displayName,
    transports: [...credential.transports],
    deviceType: credential.deviceType,
    backedUp: credential.backedUp,
    attachment: credential.attachment,
    trustLevel: credential.trustLevel,
    createdAt: credential.createdAt,
    lastUsedAt: credential.lastUsedAt,
    revokedAt: credential.revokedAt,
    version: credential.version,
  };
}

function describeDevice(userAgent: string): string {
  const device = /iPhone/u.test(userAgent)
    ? "iPhone"
    : /iPad/u.test(userAgent)
      ? "iPad"
      : /Android/u.test(userAgent)
        ? "Android device"
        : /Windows/u.test(userAgent)
          ? "Windows device"
          : /Macintosh|Mac OS/u.test(userAgent)
            ? "Mac"
            : "Browser device";
  const browser = /Edg\//u.test(userAgent)
    ? "Edge"
    : /Chrome\//u.test(userAgent)
      ? "Chrome"
      : /Firefox\//u.test(userAgent)
        ? "Firefox"
        : /Safari\//u.test(userAgent)
          ? "Safari"
          : "Browser";
  return `${device} · ${browser}`;
}
