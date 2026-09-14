import { Pool } from "pg";
import { ControlPlaneStore } from "./control-store.js";
import { CoreWorkflowStore } from "./core-workflow-store.js";
import { CustodyStore } from "./custody-store.js";
import { EnterpriseAuthStore } from "./enterprise-auth-store.js";
import { InvitationStore } from "./invitation-store.js";
import { readInitialAdminCapabilitySecrets } from "./initial-admin-capability.js";
import { InitialAdminOnboardingRecoveryStore } from "./initial-admin-onboarding-recovery-store.js";
import { KeyLifecycleStore } from "./key-lifecycle-store.js";
import { MfaStore } from "./mfa-store.js";
import { MemberQualificationStore } from "./member-qualification-store.js";
import { PhotoStore } from "./photo-store.js";
import { TenantPoolResolver, withResolvedTenantCredential } from "./pools.js";
import { TenantStore } from "./tenant-store.js";
import type {
  DatabaseRuntimeOptions,
  RequestPrincipal,
  SessionBinding,
  SessionRecord,
  TenantExecutionContext,
  SecretProvider,
} from "./types.js";

export class DatabaseRuntime {
  public readonly controlPool: Pool;
  public readonly control: ControlPlaneStore;
  public readonly invitations: InvitationStore;
  public readonly mfa: MfaStore;
  public readonly enterpriseAuth: EnterpriseAuthStore;
  public readonly initialAdminRecovery: InitialAdminOnboardingRecoveryStore;
  public readonly tenantPools: TenantPoolResolver;
  private readonly secretProvider: SecretProvider;

  public constructor(options: DatabaseRuntimeOptions) {
    this.secretProvider = options.secretProvider;
    this.controlPool = new Pool({
      ...options.control,
      application_name: options.control.application_name ?? "nombramientos-control",
    });
    this.control = new ControlPlaneStore(this.controlPool);
    this.invitations = new InvitationStore(this.controlPool);
    this.mfa = new MfaStore(this.controlPool);
    this.enterpriseAuth = new EnterpriseAuthStore(this.controlPool);
    this.initialAdminRecovery = new InitialAdminOnboardingRecoveryStore(this.controlPool);
    this.tenantPools = new TenantPoolResolver(
      (tenantId) => this.control.getTenantCredential(tenantId),
      options.secretProvider,
      options.tenantPoolMax,
      options.tenantPoolIdleMs,
    );
  }

  public async getInitialAdminCapabilitySecrets(tenantId: string): Promise<{
    readonly apply: string;
    readonly cleanup: string;
  }> {
    return readInitialAdminCapabilitySecrets(this.secretProvider, tenantId);
  }

  public async getPrincipal(
    tokenHash: string,
    requestId: string,
    binding: SessionBinding,
  ): Promise<RequestPrincipal | null> {
    const session = await this.control.getSession(tokenHash, binding);
    if (!session) return null;
    const [tenantPermissions, platformPermissions] = session.enrollmentOnly
      ? [[], []] as const
      : await Promise.all([
          this.withSession(session, requestId, (tenant) => tenant.getPermissions(session.identityId)),
          session.assuranceLevel === "mfa" ? this.control.getPlatformPermissions(session.identityId) : Promise.resolve([]),
        ]);
    return { ...session, permissions: new Set([...tenantPermissions, ...platformPermissions]) };
  }

  public async withPrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: TenantStore) => Promise<T>,
  ): Promise<T> {
    return this.withSession(principal, requestId, work);
  }

  public async withCustodyPrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: CustodyStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: principal.activeTenantId,
      identityId: principal.identityId,
      sessionId: principal.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new CustodyStore(client)));
  }

  public async withKeyLifecyclePrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: KeyLifecycleStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: principal.activeTenantId,
      identityId: principal.identityId,
      sessionId: principal.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new KeyLifecycleStore(client)));
  }

  public async withCoreWorkflowPrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: CoreWorkflowStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: principal.activeTenantId,
      identityId: principal.identityId,
      sessionId: principal.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new CoreWorkflowStore(client)));
  }

  public async withPhotoPrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: PhotoStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: principal.activeTenantId,
      identityId: principal.identityId,
      sessionId: principal.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new PhotoStore(client)));
  }

  public async withMemberQualificationPrincipal<T>(
    principal: RequestPrincipal,
    requestId: string,
    work: (store: MemberQualificationStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: principal.activeTenantId,
      identityId: principal.identityId,
      sessionId: principal.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new MemberQualificationStore(client)));
  }

  public async withInvitationTenant<T>(
    input: {
      tenantId: string;
      identityId: string;
      acceptanceId: string;
      requestId: string;
    },
    work: (store: TenantStore) => Promise<T>,
  ): Promise<T> {
    return this.tenantPools.withTenant({
      tenantId: input.tenantId,
      identityId: input.identityId,
      sessionId: input.acceptanceId,
      requestId: input.requestId,
    }, async (client) => work(new TenantStore(client)));
  }

  public async withFencedInvitationSagaTenant<T>(
    input: {
      tenantId: string;
      invitationId: string;
      identityId: string;
      acceptanceId: string;
      acceptanceAttempt: number;
      requestId: string;
      allowedStatuses: readonly ("compensating" | "revoked" | "expired" | "failed" | "accepted")[];
    },
    work: (store: TenantStore) => Promise<T>,
  ): Promise<T> {
    const credential = await this.control.getTenantCredentialForInvitationSaga(input);
    return withResolvedTenantCredential(credential, this.secretProvider, {
      tenantId: input.tenantId,
      identityId: input.identityId,
      sessionId: input.acceptanceId,
      requestId: input.requestId,
    }, async (client) => work(new TenantStore(client)));
  }

  /**
   * Binds the original invitation grantor while activating its roles.  The
   * tenant SECURITY DEFINER boundary compares this context to the recorded
   * grantor before it can create a role binding.
   */
  public async withInvitationGrantorTenant<T>(
    input: {
      tenantId: string;
      grantorIdentityId: string;
      acceptanceId: string;
      requestId: string;
    },
    work: (store: TenantStore) => Promise<T>,
  ): Promise<T> {
    return this.tenantPools.withTenant({
      tenantId: input.tenantId,
      identityId: input.grantorIdentityId,
      sessionId: input.acceptanceId,
      requestId: input.requestId,
    }, async (client) => work(new TenantStore(client)));
  }

  public async withSession<T>(
    session: SessionRecord,
    requestId: string,
    work: (store: TenantStore) => Promise<T>,
  ): Promise<T> {
    const context: TenantExecutionContext = {
      tenantId: session.activeTenantId,
      identityId: session.identityId,
      sessionId: session.sessionId,
      requestId,
    };
    return this.tenantPools.withTenant(context, async (client) => work(new TenantStore(client)));
  }

  public async close(): Promise<void> {
    await Promise.allSettled([this.tenantPools.close(), this.controlPool.end()]);
  }
}
