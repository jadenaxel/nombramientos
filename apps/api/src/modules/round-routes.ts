import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { encryptedEnvelopeSchema, validateEnvelopeContext } from "../lib/envelopes.js";
import { hpkeBallotEnvelopeSchema } from "../lib/hpke-ballot.js";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import { roundCloseReasonCodeSchema } from "../lib/reason-code.js";

const uuid = z.string().uuid();
const proposalSubmissionSchema = z.object({
  kind: z.literal("proposal"),
  expectedVersion: z.number().int().positive(),
  envelope: encryptedEnvelopeSchema,
  contentHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict();
const ballotSubmissionSchema = z.object({
  kind: z.literal("vote"),
  expectedVersion: z.number().int().positive(),
  envelope: hpkeBallotEnvelopeSchema,
  contentHash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict();
const submissionSchema = z.discriminatedUnion("kind", [proposalSubmissionSchema, ballotSubmissionSchema]);
export const closeSchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: roundCloseReasonCodeSchema,
}).strict();
const ACTIVE_ROUND_READ_PERMISSIONS = [
  "aggregate.read",
  "proposal.submit",
  "ballot.submit",
  "proposal.open",
  "ballot.open",
  "proposal.close",
  "ballot.close",
] as const;

export async function registerRoundRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/rounds/active", {
    preHandler: [app.authenticate],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    if (!ACTIVE_ROUND_READ_PERMISSIONS.some((permission) => request.principal!.permissions.has(permission))) {
      throw forbidden(ACTIVE_ROUND_READ_PERMISSIONS.join("|"));
    }
    const activeRound = await app.database.withPrincipal(request.principal, request.id, (tenant) =>
      tenant.getActiveRound(true, request.principal!.identityId),
    );
    if (!activeRound) throw new ApiError(404, "NO_ACTIVE_ROUND", "No active round is available");
    reply.header("cache-control", "no-store");
    return respond(request, reply, activeRound);
  });

  app.get("/v1/rounds/:roundId/submissions/me", {
    preHandler: [app.authenticate],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const { roundId } = parseParams(z.object({ roundId: uuid }), request);
    const receipt = await app.database.withPrincipal(request.principal, request.id, (tenant) =>
      tenant.getOwnSubmissionReceipt(roundId, request.principal!.identityId),
    );
    if (!receipt) {
      throw new ApiError(404, "SUBMISSION_NOT_FOUND", "No submission receipt is available for this elector and round");
    }
    reply.header("cache-control", "no-store");
    return respond(request, reply, receipt);
  });

  app.post("/v1/rounds/:roundId/submissions", {
    preHandler: [app.authenticate, app.verifyCsrf],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const { roundId } = parseParams(z.object({ roundId: uuid }), request);
    const body = parseBody(submissionSchema, request);
    const permission = body.kind === "proposal" ? "proposal.submit" : "ballot.submit";
    if (!request.principal.permissions.has(permission)) throw forbidden(permission);
    const idempotencyKey = requireIdempotencyKey(request);
    const result = body.kind === "proposal"
      ? await app.database.withPrincipal(request.principal, request.id, (tenant) => {
          validateEnvelopeContext(body.envelope, {
            tenantId: request.principal!.activeTenantId,
            roundId,
            purpose: body.kind,
            schemaVersion: 1,
            roundVersion: body.expectedVersion,
          });
          return tenant.submit({
            identityId: request.principal!.identityId,
            idempotencyKey,
            roundId,
            ...body,
          });
        })
      : await app.database.withCustodyPrincipal(request.principal, request.id, (custody) =>
          custody.submitBallot({
            identityId: request.principal!.identityId,
            idempotencyKey,
            roundId,
            expectedVersion: body.expectedVersion,
            envelope: body.envelope,
            contentHash: body.contentHash,
          }),
        );
    return respond(request, reply, result, 201);
  });

  app.post("/v1/rounds/:roundId/close", {
    preHandler: [app.authenticate, app.verifyCsrf],
  }, async (request, reply) => {
    if (!request.principal) throw unauthorized();
    const { roundId } = parseParams(z.object({ roundId: uuid }), request);
    const body = parseBody(closeSchema, request);
    const result = await app.database.withPrincipal(request.principal, request.id, async (tenant) => {
      const submissionKind = await tenant.getRoundSubmissionKind(roundId);
      if (!submissionKind) throw new ApiError(409, "ROUND_UNAVAILABLE", "The requested round is unavailable");
      const permission = submissionKind === "proposal" ? "proposal.close" : "ballot.close";
      if (!request.principal!.permissions.has(permission)) throw forbidden(permission);
      return tenant.closeRound({
        identityId: request.principal!.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        roundId,
        expectedVersion: body.expectedVersion,
        reasonCode: body.reasonCode,
      });
    });
    return respond(request, reply, result);
  });
}
