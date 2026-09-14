import { randomUUID } from "node:crypto";
import Fastify, { LogController, type FastifyInstance } from "fastify";
import {
  ContentKeyWriteGuardError,
  CustodyError,
  DataConflictError,
  DatabaseRuntime,
} from "@nombramientos/database";
import { ZodError } from "zod";
import type { ApiConfig } from "./config.js";
import { ApiError } from "./lib/errors.js";
import { API_LOG_REDACTION_PATHS, API_LOG_SERIALIZERS, safeLogError } from "./lib/log-safety.js";
import { registerAuthRoutes } from "./modules/auth-routes.js";
import { registerEnterpriseAuthRoutes } from "./modules/enterprise-auth-routes.js";
import { registerAccessRoutes } from "./modules/access-routes.js";
import { AuthService } from "./modules/auth-service.js";
import { EnterpriseAuthService } from "./modules/enterprise-auth-service.js";
import { registerEventRoutes } from "./modules/event-routes.js";
import { registerCustodyRoutes } from "./modules/custody-routes.js";
import { registerCoreWorkflowRoutes } from "./modules/core-workflow-routes.js";
import { registerInvitationRoutes } from "./modules/invitation-routes.js";
import { registerKeyLifecycleRoutes } from "./modules/key-lifecycle-routes.js";
import { registerMemberQualificationRoutes } from "./modules/member-qualification-routes.js";
import { InvitationService } from "./modules/invitation-service.js";
import { registerInitialAdminOnboardingRecoveryRoutes } from "./modules/initial-admin-onboarding-recovery-routes.js";
import { InitialAdminOnboardingRecoveryService } from "./modules/initial-admin-onboarding-recovery-service.js";
import { registerPlatformRoutes } from "./modules/platform-routes.js";
import { registerPlatformBootstrapRoutes } from "./modules/platform-bootstrap-routes.js";
import { registerPhotoRoutes } from "./modules/photo-routes.js";
import { registerRoundRoutes } from "./modules/round-routes.js";
import { registerTenantRoutes } from "./modules/tenant-routes.js";
import { registerSecurity } from "./security.js";

export interface BuildServerOptions {
  readonly config: ApiConfig;
  readonly database: DatabaseRuntime;
  readonly logger?: boolean;
  readonly closeDatabaseOnShutdown?: boolean;
}

/**
 * Forwarding headers are disabled unless the immediate socket peer is in this
 * explicit allowlist. Returning a fresh array prevents downstream mutation of
 * the validated configuration object.
 */
export function fastifyTrustProxy(config: Pick<ApiConfig, "trustedProxyCidrs">): false | string[] {
  const trusted = config.trustedProxyCidrs ?? [];
  return trusted.length === 0 ? false : [...trusted];
}

export async function buildServer(options: BuildServerOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: options.logger === false
      ? false
      : {
          level: options.config.environment === "production" ? "info" : "debug",
          redact: {
            paths: [...API_LOG_REDACTION_PATHS],
            censor: "[redacted]",
          },
          serializers: API_LOG_SERIALIZERS,
        },
    genReqId: () => randomUUID(),
    bodyLimit: 12 * 1024 * 1024,
    trustProxy: fastifyTrustProxy(options.config),
    logController: new LogController({
      disableRequestLogging: options.config.environment === "production",
    }),
  });
  app.decorate("database", options.database);
  app.decorate("apiConfig", options.config);
  const authService = new AuthService(options.database, options.config);
  app.decorate("authService", authService);
  app.decorate("enterpriseAuthService", new EnterpriseAuthService(options.database, options.config, authService));
  app.decorate("invitationService", new InvitationService(options.database, options.config, authService));
  app.decorate(
    "initialAdminRecoveryService",
    new InitialAdminOnboardingRecoveryService(options.database, options.config, authService),
  );

  await registerSecurity(app);
  app.addHook("onSend", async (request, reply) => {
    reply.header("x-request-id", request.id);
    if (!reply.hasHeader("cache-control")) reply.header("cache-control", "no-store");
    reply.header("x-content-type-options", "nosniff");
    reply.header("referrer-policy", "no-referrer");
    reply.header("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
  });

  app.get("/healthz", async (_request, reply) => {
    await options.database.controlPool.query("SELECT 1");
    const worker = await options.database.control.getProvisioningWorkerStatus();
    reply.header("cache-control", "no-store");
    return reply.send({ status: "ok", service: "nombramientos-api", worker });
  });
  await registerAuthRoutes(app);
  await registerEnterpriseAuthRoutes(app);
  await registerPlatformBootstrapRoutes(app);
  await registerAccessRoutes(app);
  await registerInvitationRoutes(app);
  await registerInitialAdminOnboardingRecoveryRoutes(app);
  await registerKeyLifecycleRoutes(app);
  await registerCustodyRoutes(app);
  await registerCoreWorkflowRoutes(app);
  await registerPhotoRoutes(app);
  await registerMemberQualificationRoutes(app);
  await registerTenantRoutes(app);
  await registerRoundRoutes(app);
  await registerEventRoutes(app);
  await registerPlatformRoutes(app);

  app.setNotFoundHandler((request, reply) => reply.status(404).send({
    error: { code: "NOT_FOUND", message: "Route not found" },
    meta: { requestId: request.id },
  }));
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ApiError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) },
        meta: { requestId: request.id },
      });
    }
    if (error instanceof DataConflictError) {
      return reply.status(409).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    if (error instanceof ContentKeyWriteGuardError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    if (error instanceof CustodyError) {
      return reply.status(error.statusCode).send({
        error: { code: error.code, message: error.message },
        meta: { requestId: request.id },
      });
    }
    if (error instanceof ZodError) {
      return reply.status(400).send({
        error: { code: "VALIDATION_ERROR", message: "Request is invalid", details: error.flatten() },
        meta: { requestId: request.id },
      });
    }
    const status = typeof error === "object" && error !== null && "statusCode" in error && typeof error.statusCode === "number" && error.statusCode < 500
      ? error.statusCode
      : 500;
    if (status >= 500) request.log.error({ safeError: safeLogError(error), requestId: request.id }, "Unhandled API error");
    return reply.status(status).send({
      error: {
        code: status === 500 ? "INTERNAL_ERROR" : "REQUEST_ERROR",
        message: status === 500
          ? "An unexpected error occurred"
          : error instanceof Error ? error.message : "Request failed",
      },
      meta: { requestId: request.id },
    });
  });

  if (options.closeDatabaseOnShutdown !== false) {
    app.addHook("onClose", async () => options.database.close());
  }
  await app.ready();
  return app;
}
