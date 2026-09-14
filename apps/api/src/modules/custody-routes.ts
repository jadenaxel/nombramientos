import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ApiError, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import { custodyHpkeSuiteSchema } from "../lib/hpke-ballot.js";
import { requirePolicyAwareOperationStepUp } from "../lib/operation-step-up.js";
import { requireRecentMfa } from "../lib/recent-mfa.js";
import { custodyKeyRevokeReasonCodeSchema } from "../lib/reason-code.js";

const uuid = z.string().uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const base64url = z.string().min(1).max(1024).regex(/^[A-Za-z0-9_-]+$/);
const registerKeySchema = z.object({
  deviceId: uuid,
  recipientId: z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/),
  expectedVersion: z.number().int().min(0),
  suite: custodyHpkeSuiteSchema,
  hpkePublicKey: base64url,
  hpkeFingerprint: digest,
  signingAlgorithm: z.literal("Ed25519"),
  signingPublicKeySpki: base64url,
  signingFingerprint: digest,
}).strict();
export const revokeKeySchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: custodyKeyRevokeReasonCodeSchema,
}).strict();
const freezeSchema = z.object({
  expectedRoundVersion: z.number().int().positive(),
  keyIds: z.array(uuid).min(2).max(16).refine((items) => new Set(items).size === items.length, "keyIds must be unique"),
}).strict();
const createManifestSchema = z.object({
  expectedRoundVersion: z.number().int().positive(),
  expectedCustodyVersion: z.number().int().positive(),
}).strict();
const aggregateRuleSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("PLURALITY") }).strict(),
  z.object({
    kind: z.literal("STRICT_MAJORITY"),
    threshold: z.number().min(0).lt(1),
    denominator: z.enum(["NON_ABSTAINING_BALLOTS", "ALL_RECEIVED_BALLOTS"]),
  }).strict(),
]);
const aggregateDecisionSchema = z.object({
  status: z.enum(["SELECTED", "PARTIAL_SELECTION", "TIEBREAK_REQUIRED", "NO_SELECTION"]),
  reason: z.enum([
    "TOP_K",
    "CUTOFF_TIE",
    "NO_VALID_CANDIDATE_VOTES",
    "THRESHOLD_NOT_MET",
    "INSUFFICIENT_QUALIFIED_CANDIDATES",
  ]),
  selectedCandidateIds: z.array(uuid),
  tiebreakCandidateIds: z.array(uuid),
  unfilledSeats: z.number().int().min(0),
}).strict();
const tallyAggregateSchema = z.object({
  schemaVersion: z.literal(1),
  receivedBallots: z.number().int().min(0),
  nonAbstainingBallots: z.number().int().min(0),
  abstentions: z.number().int().min(0),
  maxSelections: z.number().int().positive(),
  candidates: z.array(z.object({ candidateId: uuid, votes: z.number().int().min(0) }).strict()),
  rule: aggregateRuleSchema,
  decision: aggregateDecisionSchema,
}).strict();
const attestSchema = z.object({
  expectedManifestVersion: z.number().int().positive(),
  aggregate: tallyAggregateSchema,
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();
const publishSchema = z.object({
  expectedRoundVersion: z.number().int().positive(),
  expectedManifestVersion: z.number().int().positive(),
}).strict();
const roundParams = z.object({ roundId: uuid }).strict();
const keyParams = z.object({ keyId: uuid }).strict();

export async function registerCustodyRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/custody/keys", {
    preHandler: [app.authenticate, app.requirePermission("tally.custody")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.listKeys(),
    ));
  });

  app.post("/v1/custody/keys", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("tally.custody"), requirePolicyAwareOperationStepUp({
      action: "custody.key.register",
      purpose: "custody_operation",
      recentMfaPurpose: "registering a custody key",
    })],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(registerKeySchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.registerKey({
        ...body,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ), 201);
  });

  app.post("/v1/custody/keys/:keyId/revoke", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("tally.custody"), requirePolicyAwareOperationStepUp({
      action: "custody.key.revoke",
      purpose: "custody_operation",
      recentMfaPurpose: "revoking a custody key",
    })],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { keyId } = parseParams(keyParams, request);
    const body = parseBody(revokeKeySchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.revokeKey({
        expectedVersion: body.expectedVersion,
        reasonCode: body.reasonCode,
        keyId,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ));
  });

  app.get("/v1/rounds/:roundId/custody", {
    preHandler: [app.authenticate, app.requirePermission("tally.custody")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const result = await app.database.withCustodyPrincipal(principal, request.id, (custody) =>
      custody.getRoundCustody(roundId),
    );
    if (!result) throw new ApiError(404, "CUSTODY_NOT_FROZEN", "Round has no frozen custody set");
    reply.header("cache-control", "no-store");
    return respond(request, reply, result);
  });

  app.get("/v1/rounds/:roundId/custody/recipients", {
    preHandler: [app.authenticate, app.requirePermission("ballot.submit")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const result = await app.database.withCustodyPrincipal(principal, request.id, (custody) =>
      custody.getBallotRecipients(roundId, principal.identityId, principal.activeTenantId),
    );
    reply.header("cache-control", "no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/rounds/:roundId/custody/freeze", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("tally.custody"), requirePolicyAwareOperationStepUp({
      action: "custody.round.freeze",
      purpose: "custody_operation",
      recentMfaPurpose: "freezing round custody",
    })],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(freezeSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.freezeRound({
        ...body,
        roundId,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ), 201);
  });

  app.post("/v1/rounds/:roundId/custody/manifest", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("tally.recount")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(createManifestSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.createManifest({
        ...body,
        roundId,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ), 201);
  });

  app.get("/v1/rounds/:roundId/custody/manifest", {
    preHandler: [app.authenticate, app.requirePermission("tally.recount"), requireRecentMfa("downloading a tally custody manifest")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const result = await app.database.withCustodyPrincipal(principal, request.id, (custody) =>
      custody.downloadManifest(roundId, principal.identityId),
    );
    if (!result) {
      throw new ApiError(403, "CUSTODIAN_NOT_FROZEN", "Only a frozen custodian can download this tally manifest");
    }
    reply.header("cache-control", "no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/rounds/:roundId/custody/attestations", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("tally.recount")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(attestSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.attestManifest({
        ...body,
        roundId,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ), 201);
  });

  app.post("/v1/rounds/:roundId/custody/publication", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("aggregate.publish")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(publishSchema, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.publishAggregate({
        ...body,
        roundId,
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
      }),
    ));
  });

  app.get("/v1/rounds/:roundId/custody/aggregate", {
    preHandler: [app.authenticate, app.requirePermission("aggregate.read")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    reply.header("cache-control", "no-store");
    return respond(request, reply, await app.database.withCustodyPrincipal(
      principal,
      request.id,
      (custody) => custody.getPublishedAggregate(roundId),
    ));
  });
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}
