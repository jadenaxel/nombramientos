import type { DatabaseRuntime, RequestPrincipal } from "@nombramientos/database";
import type { ApiConfig } from "./config.js";
import type { AuthService } from "./modules/auth-service.js";
import type { EnterpriseAuthService } from "./modules/enterprise-auth-service.js";
import type { InvitationService } from "./modules/invitation-service.js";
import type { InitialAdminOnboardingRecoveryService } from "./modules/initial-admin-onboarding-recovery-service.js";

declare module "fastify" {
  interface FastifyInstance {
    database: DatabaseRuntime;
    apiConfig: ApiConfig;
    authService: AuthService;
    enterpriseAuthService: EnterpriseAuthService;
    invitationService: InvitationService;
    initialAdminRecoveryService: InitialAdminOnboardingRecoveryService;
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    verifyCsrf: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requirePermission: (permission: string) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }

  interface FastifyRequest {
    principal: RequestPrincipal | null;
  }
}

export {};
