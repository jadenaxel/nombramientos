import type { FastifyInstance, FastifyRequest } from "fastify";
import { KeyLifecycleError, type KeyLifecycleOperation, type RequestPrincipal } from "@nombramientos/database";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { parseBody, requireIdempotencyKey, respond } from "../lib/http.js";
import { requirePolicyAwareOperationStepUp } from "../lib/operation-step-up.js";
import {
  approveGrantIntentSchema,
  assertGrantEnvelope,
  assertRecoveryAuthorization,
  assertRecoveryPublicKey,
  assertWrappingPublicKey,
  challengedApproveGrantSchema,
  challengedDeclareKeyLostSchema,
  challengedInitializeGrantSchema,
  challengedRecoverKeySchema,
  challengedRegisterDeviceSchema,
  challengedRevokeGrantSchema,
  challengedRotateKeySchema,
  declareKeyLostIntentSchema,
  initializeGrantIntentSchema,
  lifecycleChallengeSchema,
  lifecycleIntentRequestHash,
  lifecycleOperationNeedsManager,
  recoverKeyIntentSchema,
  recoveryPublicKeySchema,
  registerDeviceIntentSchema,
  requestWithoutChallenge,
  revokeGrantIntentSchema,
  rotateKeyIntentSchema,
  type KeyLifecycleIntent,
} from "./key-lifecycle-contract.js";

const CHALLENGE_TTL_SECONDS = 5 * 60;
const DEFAULT_CHALLENGE_RATE_LIMIT = 12;
const GRANT_APPROVAL_CHALLENGE_RATE_LIMIT = 100;

export function lifecycleChallengeRateLimitMax(request: FastifyRequest): number {
  const body = request.body;
  if (
    typeof body === "object"
    && body !== null
    && "operation" in body
    && body.operation === "grant.approve"
  ) return GRANT_APPROVAL_CHALLENGE_RATE_LIMIT;
  return DEFAULT_CHALLENGE_RATE_LIMIT;
}

export async function registerKeyLifecycleRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/key-lifecycle", { preHandler: [app.authenticate] }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const state = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.getState(principal.identityId, principal.permissions.has("recovery.activate")));
    reply.header("cache-control", "no-store");
    return respond(request, reply, state);
  });

  app.post("/v1/key-lifecycle/challenges", {
    preHandler: [app.authenticate, app.verifyCsrf, requirePolicyAwareOperationStepUp({
      action: "key.lifecycle.challenge",
      purpose: "key_lifecycle",
      recentMfaPurpose: "tenant-key lifecycle operations",
    })],
    config: {
      rateLimit: {
        hook: "preValidation",
        max: lifecycleChallengeRateLimitMax,
        timeWindow: "5 minutes",
      },
    },
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.challenge.denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    const body = parseBody(lifecycleChallengeSchema, request);
    assertOperationPermission(principal, body.operation);
    await validateIntent(app, request, body);
    const challenge = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.issueChallenge({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        operation: body.operation,
        requestHash: lifecycleIntentRequestHash(body.request),
        idempotencyKey: requireIdempotencyKey(request),
        ttlSeconds: CHALLENGE_TTL_SECONDS,
      }));
    return respond(request, reply, challenge, 201);
  }));

  app.post("/v1/key-lifecycle/devices", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.device.registration_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    const body = parseBody(challengedRegisterDeviceSchema, request);
    const intent = registerDeviceIntentSchema.parse(requestWithoutChallenge(body));
    assertWrappingPublicKey(intent.wrappingPublicKey, principal.activeTenantId, intent.deviceId);
    const device = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.registerDevice({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        deviceId: intent.deviceId,
        label: intent.label,
        wrappingPublicKey: intent.wrappingPublicKey,
        wrappingKeyFingerprint: intent.wrappingPublicKey.fingerprint,
      }));
    return respond(request, reply, device, 201);
  }));

  app.post("/v1/key-lifecycle/grants/initialize", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.key.initialization_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedInitializeGrantSchema, request);
    const intent = initializeGrantIntentSchema.parse(requestWithoutChallenge(body));
    assertGrantEnvelope(intent.envelope, {
      tenantId: principal.activeTenantId,
      tenantKeyId: intent.tenantKeyId,
      generation: 1,
      identityId: principal.identityId,
      deviceId: intent.deviceId,
      deviceFingerprint: intent.envelope.aad.deviceFingerprint,
    });
    assertRecoveryPublicKey(intent.recoveryPublicKey);
    const grant = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.initializeGrant({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        deviceId: intent.deviceId,
        deviceFingerprint: intent.envelope.aad.deviceFingerprint,
        tenantKeyId: intent.tenantKeyId,
        envelope: intent.envelope,
        envelopeHash: intent.envelope.envelopeHash,
        recoveryPublicKey: intent.recoveryPublicKey,
        recoveryKeyFingerprint: intent.recoveryPublicKey.fingerprint,
      }));
    return respond(request, reply, grant, 201);
  }));

  app.post("/v1/key-lifecycle/grants", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.grant.approval_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedApproveGrantSchema, request);
    const intent = approveGrantIntentSchema.parse(requestWithoutChallenge(body));
    await assertMembership(app, principal, intent.targetIdentityId);
    assertGrantEnvelope(intent.envelope, {
      tenantId: principal.activeTenantId,
      tenantKeyId: intent.tenantKeyId,
      generation: intent.generation,
      identityId: intent.targetIdentityId,
      deviceId: intent.targetDeviceId,
      deviceFingerprint: intent.envelope.aad.deviceFingerprint,
    });
    const grant = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.approveGrant({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        targetIdentityId: intent.targetIdentityId,
        targetDeviceId: intent.targetDeviceId,
        targetDeviceFingerprint: intent.envelope.aad.deviceFingerprint,
        tenantKeyId: intent.tenantKeyId,
        generation: intent.generation,
        envelope: intent.envelope,
        envelopeHash: intent.envelope.envelopeHash,
      }));
    return respond(request, reply, grant, 201);
  }));

  app.post("/v1/key-lifecycle/grants/revoke", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.grant.revocation_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedRevokeGrantSchema, request);
    const intent = revokeGrantIntentSchema.parse(requestWithoutChallenge(body));
    const result = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.revokeGrant({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        grantId: intent.grantId,
        expectedVersion: intent.expectedVersion,
        reasonCode: intent.reasonCode,
        confirmLastActiveGrant: intent.confirmLastActiveGrant,
      }));
    return respond(request, reply, result);
  }));

  app.post("/v1/key-lifecycle/rotations", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.key.rotation_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedRotateKeySchema, request);
    const intent = rotateKeyIntentSchema.parse(requestWithoutChallenge(body));
    if (new Set(intent.grants.map(({ targetDeviceId }) => targetDeviceId)).size !== intent.grants.length) {
      throw new ApiError(400, "DUPLICATE_DEVICE_GRANT", "Rotation targets must be unique");
    }
    await Promise.all(intent.grants.map(({ targetIdentityId }) => assertMembership(app, principal, targetIdentityId)));
    assertRecoveryPublicKey(intent.recoveryPublicKey);
    for (const grant of intent.grants) {
      assertGrantEnvelope(grant.envelope, {
        tenantId: principal.activeTenantId,
        tenantKeyId: intent.newTenantKeyId,
        generation: intent.expectedGeneration + 1,
        identityId: grant.targetIdentityId,
        deviceId: grant.targetDeviceId,
        deviceFingerprint: grant.envelope.aad.deviceFingerprint,
      });
    }
    const result = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.rotateKey({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        expectedTenantKeyId: intent.expectedTenantKeyId,
        expectedGeneration: intent.expectedGeneration,
        newTenantKeyId: intent.newTenantKeyId,
        reasonCode: intent.reasonCode,
        recoveryPublicKey: intent.recoveryPublicKey,
        recoveryKeyFingerprint: intent.recoveryPublicKey.fingerprint,
        grants: intent.grants.map((grant) => ({
          targetIdentityId: grant.targetIdentityId,
          targetDeviceId: grant.targetDeviceId,
          targetDeviceFingerprint: grant.envelope.aad.deviceFingerprint,
          envelope: grant.envelope,
          envelopeHash: grant.envelope.envelopeHash,
        })),
      }));
    return respond(request, reply, result, 201);
  }));

  app.post("/v1/key-lifecycle/recoveries", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.key.recovery_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedRecoverKeySchema, request);
    const intent = recoverKeyIntentSchema.parse(requestWithoutChallenge(body));
    await assertMembership(app, principal, intent.targetIdentityId);
    const material = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.getRecoveryVerificationMaterial(intent.tenantKeyId));
    assertGrantEnvelope(intent.envelope, {
      tenantId: principal.activeTenantId,
      tenantKeyId: intent.tenantKeyId,
      generation: material.generation,
      identityId: intent.targetIdentityId,
      deviceId: intent.targetDeviceId,
      deviceFingerprint: intent.envelope.aad.deviceFingerprint,
    });
    const recoveryPublicKey = recoveryPublicKeySchema.parse(material.recoveryPublicKey);
    assertRecoveryAuthorization(recoveryPublicKey, intent.authorization, {
      tenantId: principal.activeTenantId,
      tenantKeyId: intent.tenantKeyId,
      generation: material.generation,
      recoveryNonce: intent.authorization.context.recoveryNonce,
      targetIdentityId: intent.targetIdentityId,
      targetDeviceId: intent.targetDeviceId,
      targetDeviceFingerprint: intent.envelope.aad.deviceFingerprint,
      envelopeHash: intent.envelope.envelopeHash,
    });
    const grant = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.recoverGrant({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        tenantKeyId: intent.tenantKeyId,
        generation: material.generation,
        recoveryKeyFingerprint: intent.authorization.recoveryKeyFingerprint,
        recoveryNonce: intent.authorization.context.recoveryNonce,
        targetIdentityId: intent.targetIdentityId,
        targetDeviceId: intent.targetDeviceId,
        targetDeviceFingerprint: intent.envelope.aad.deviceFingerprint,
        envelope: intent.envelope,
        envelopeHash: intent.envelope.envelopeHash,
      }));
    return respond(request, reply, grant, 201);
  }));

  app.post("/v1/key-lifecycle/loss-declarations", {
    preHandler: lifecycleMutation(app),
  }, async (request, reply) => runLifecycleBoundary(app, request, "e2ee.key.loss_declaration_denied", async () => {
    const principal = requirePrincipal(request);
    assertRealTenant(principal);
    assertManager(principal);
    const body = parseBody(challengedDeclareKeyLostSchema, request);
    const intent = declareKeyLostIntentSchema.parse(requestWithoutChallenge(body));
    const result = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
      store.declareKeyLost({
        actorIdentityId: principal.identityId,
        sessionId: principal.sessionId,
        idempotencyKey: requireIdempotencyKey(request),
        challengeId: body.challengeId,
        requestHash: lifecycleIntentRequestHash(intent),
        tenantKeyId: intent.tenantKeyId,
        confirmation: intent.confirmation,
        reasonCode: intent.reasonCode,
      }));
    return respond(request, reply, result);
  }));
}

async function validateIntent(app: FastifyInstance, request: FastifyRequest, intent: KeyLifecycleIntent): Promise<void> {
  const principal = requirePrincipal(request);
  switch (intent.operation) {
    case "device.register":
      assertWrappingPublicKey(intent.request.wrappingPublicKey, principal.activeTenantId, intent.request.deviceId);
      return;
    case "grant.initialize":
      assertGrantEnvelope(intent.request.envelope, {
        tenantId: principal.activeTenantId,
        tenantKeyId: intent.request.tenantKeyId,
        generation: 1,
        identityId: principal.identityId,
        deviceId: intent.request.deviceId,
        deviceFingerprint: intent.request.envelope.aad.deviceFingerprint,
      });
      assertRecoveryPublicKey(intent.request.recoveryPublicKey);
      return;
    case "grant.approve":
      await assertMembership(app, principal, intent.request.targetIdentityId);
      assertGrantEnvelope(intent.request.envelope, {
        tenantId: principal.activeTenantId,
        tenantKeyId: intent.request.tenantKeyId,
        generation: intent.request.generation,
        identityId: intent.request.targetIdentityId,
        deviceId: intent.request.targetDeviceId,
        deviceFingerprint: intent.request.envelope.aad.deviceFingerprint,
      });
      return;
    case "grant.revoke":
    case "key.declare_lost":
      return;
    case "key.rotate":
      if (new Set(intent.request.grants.map(({ targetDeviceId }) => targetDeviceId)).size !== intent.request.grants.length) {
        throw new ApiError(400, "DUPLICATE_DEVICE_GRANT", "Rotation targets must be unique");
      }
      await Promise.all(intent.request.grants.map(({ targetIdentityId }) => assertMembership(app, principal, targetIdentityId)));
      assertRecoveryPublicKey(intent.request.recoveryPublicKey);
      for (const grant of intent.request.grants) {
        assertGrantEnvelope(grant.envelope, {
          tenantId: principal.activeTenantId,
          tenantKeyId: intent.request.newTenantKeyId,
          generation: intent.request.expectedGeneration + 1,
          identityId: grant.targetIdentityId,
          deviceId: grant.targetDeviceId,
          deviceFingerprint: grant.envelope.aad.deviceFingerprint,
        });
      }
      return;
    case "key.recover": {
      await assertMembership(app, principal, intent.request.targetIdentityId);
      const material = await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
        store.getRecoveryVerificationMaterial(intent.request.tenantKeyId));
      assertGrantEnvelope(intent.request.envelope, {
        tenantId: principal.activeTenantId,
        tenantKeyId: intent.request.tenantKeyId,
        generation: material.generation,
        identityId: intent.request.targetIdentityId,
        deviceId: intent.request.targetDeviceId,
        deviceFingerprint: intent.request.envelope.aad.deviceFingerprint,
      });
      assertRecoveryAuthorization(recoveryPublicKeySchema.parse(material.recoveryPublicKey), intent.request.authorization, {
        tenantId: principal.activeTenantId,
        tenantKeyId: intent.request.tenantKeyId,
        generation: material.generation,
        recoveryNonce: intent.request.authorization.context.recoveryNonce,
        targetIdentityId: intent.request.targetIdentityId,
        targetDeviceId: intent.request.targetDeviceId,
        targetDeviceFingerprint: intent.request.envelope.aad.deviceFingerprint,
        envelopeHash: intent.request.envelope.envelopeHash,
      });
      return;
    }
  }
}

function lifecycleMutation(app: FastifyInstance) {
  return [app.authenticate, app.verifyCsrf];
}

function requirePrincipal(request: FastifyRequest): RequestPrincipal {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

function assertRealTenant(principal: RequestPrincipal): void {
  if (principal.tenantKind !== "real") {
    throw new ApiError(409, "REAL_TENANT_REQUIRED", "Managed tenant-key lifecycle is only available to real tenants");
  }
}

function assertOperationPermission(principal: RequestPrincipal, operation: KeyLifecycleOperation): void {
  if (lifecycleOperationNeedsManager(operation)) assertManager(principal);
}

function assertManager(principal: RequestPrincipal): void {
  if (!principal.permissions.has("recovery.activate")) throw forbidden("recovery.activate");
}

async function assertMembership(app: FastifyInstance, principal: RequestPrincipal, identityId: string): Promise<void> {
  if (!await app.database.control.hasActiveMembership(identityId, principal.activeTenantId)) {
    throw forbidden("active tenant membership");
  }
}

async function runLifecycleBoundary<T>(
  app: FastifyInstance,
  request: FastifyRequest,
  denialAction: string,
  work: () => Promise<T>,
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    const mapped = error instanceof KeyLifecycleError
      ? new ApiError(error.statusCode, error.code, error.message)
      : error;
    const principal = request.principal;
    if (principal && principal.tenantKind === "real") {
      const code = mapped instanceof ApiError ? mapped.code : "INTERNAL_ERROR";
      await app.database.withKeyLifecyclePrincipal(principal, request.id, (store) =>
        store.recordDenial({ action: denialAction, entityId: request.id, code })).catch(() => undefined);
    }
    throw mapped;
  }
}
