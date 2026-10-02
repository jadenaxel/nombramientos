import type { PoolClient, PoolConfig } from "pg";
import type { AuthenticationAssuranceLevel, AuthenticationMethod } from "./enterprise-auth-store.js";

export type TenantKind = "demo" | "real";
export type TenantStatus = "provisioning" | "active" | "suspended" | "failed" | "decommission_pending";

export interface SecretProvider {
  getSecret(reference: string): Promise<string>;
}

export interface WritableSecretProvider extends SecretProvider {
  putSecret(reference: string, value: string): Promise<void>;
  hasSecret(reference: string): Promise<boolean>;
}

export interface TenantCredentialRecord {
  readonly tenantId: string;
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly secretReference: string;
  readonly credentialVersion: number;
  readonly sslMode: "disable" | "require" | "verify-full";
}

export interface ResolvedTenantCredential extends Omit<TenantCredentialRecord, "secretReference"> {
  readonly password: string;
}

export interface SessionRecord {
  readonly sessionId: string;
  readonly identityId: string;
  readonly activeTenantId: string;
  readonly email: string;
  readonly displayName: string;
  readonly tenantSlug: string;
  readonly tenantName: string;
  readonly tenantKind: TenantKind;
  readonly tenantTimezone: string;
  readonly csrfHash: string;
  readonly expiresAt: Date;
  readonly assuranceLevel: AuthenticationAssuranceLevel;
  readonly authenticatedAt: Date;
  readonly mfaVerifiedAt: Date | null;
  readonly mfaRequired: boolean;
  readonly mfaEnabled: boolean;
  readonly passkeyEnabled?: boolean;
  readonly strongAuthEnabled?: boolean;
  readonly authMethod?: AuthenticationMethod;
  readonly aal?: 1 | 2 | 3;
  readonly phishingResistant?: boolean;
  readonly authenticatedCredentialId?: string | null;
  readonly recoveryLimited?: boolean;
  readonly idleExpiresAt?: Date;
  readonly deviceLabel?: string | null;
  readonly userAgentContextChanged?: boolean;
  readonly ipContextChanged?: boolean;
  readonly enrollmentOnly: boolean;
}

export interface SessionBinding {
  readonly userAgentHash?: string;
  readonly ipPrefixHash?: string;
}

export interface RequestPrincipal extends SessionRecord {
  readonly permissions: ReadonlySet<string>;
  /** Set only by the API after signature + single-use nonce verification. */
  readonly provenDeviceId?: string;
}

export interface TenantExecutionContext {
  readonly tenantId: string;
  readonly identityId: string;
  readonly sessionId: string;
  readonly requestId: string;
  readonly provenDeviceId?: string;
  readonly deferDevicePin?: boolean;
}

export type TenantWork<T> = (client: PoolClient) => Promise<T>;

export interface DatabaseRuntimeOptions {
  readonly control: PoolConfig;
  readonly secretProvider: SecretProvider;
  readonly tenantPoolMax?: number;
  readonly tenantPoolIdleMs?: number;
}

export interface EncryptedEnvelope {
  readonly algorithm: "XCHACHA20-POLY1305" | "AES-256-GCM";
  readonly keyId: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly aad: string;
}

export interface TenantProvisionRequest {
  readonly idempotencyKey: string;
  readonly tenantId: string;
  readonly slug: string;
  readonly displayName: string;
  readonly kind: TenantKind;
  readonly timezone: string;
  readonly locale: "es" | "en" | "fr";
  readonly initialAdmin?:
    | { readonly mode: "pending" }
    | { readonly mode: "demo_seed" }
    | {
        readonly mode: "invitation";
        readonly email: string;
        readonly normalizedEmail: string;
        readonly expiresInHours: number;
        readonly expiresAt: string;
        readonly tokenHash: string;
        readonly createdByIdentityId: string;
      };
}

export interface TenantProvisionResult {
  readonly tenantId: string;
  readonly database: string;
  readonly runtimeRole: string;
  readonly secretReference: string;
  readonly tenantStatus: TenantStatus;
  readonly state: "active" | "pending_activation";
  readonly reused: boolean;
}
