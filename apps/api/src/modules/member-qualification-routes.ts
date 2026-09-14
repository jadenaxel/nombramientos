import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { MemberQualificationStoreError } from "@nombramientos/database";
import { z } from "zod";
import { ApiError, unauthorized } from "../lib/errors.js";
import { validateEnvelopeContentHash, validateEnvelopeContext } from "../lib/envelopes.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import { requireRecentMfa } from "../lib/recent-mfa.js";
import {
  memberQualificationAadContext,
  memberQualificationCreateSchema,
  memberQualificationRevisionSchema,
} from "./member-qualification-contract.js";

const uuid = z.string().uuid();
const memberParams = z.object({ memberId: uuid });
const qualificationParams = z.object({ memberId: uuid, qualificationId: uuid });

export async function registerMemberQualificationRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/members/:memberId/qualifications", {
    preHandler: [app.authenticate, app.requirePermission("member.qualification.read")],
  }, async (request, reply) => {
    const { memberId } = parseParams(memberParams, request);
    const principal = requirePrincipal(request);
    noStore(reply);
    return withQualificationErrors(async () => respond(
      request,
      reply,
      await app.database.withMemberQualificationPrincipal(
        principal,
        request.id,
        (store) => store.listForMember(memberId),
      ),
    ));
  });

  app.post("/v1/members/:memberId/qualifications", {
    preHandler: [
      app.authenticate,
      app.verifyCsrf,
      app.requirePermission("member.qualification.manage"),
      requireRecentMfa("recording an independent member qualification"),
    ],
  }, async (request, reply) => {
    const { memberId } = parseParams(memberParams, request);
    const body = parseBody(memberQualificationCreateSchema, request);
    const principal = requirePrincipal(request);
    noStore(reply);
    validateQualificationEnvelope(request, {
      memberId,
      version: 1,
      ...body,
    });
    return withQualificationErrors(async () => respond(
      request,
      reply,
      await app.database.withMemberQualificationPrincipal(principal, request.id, (store) => store.create({
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        memberId,
        qualificationId: body.qualificationId,
        type: body.type,
        status: body.status,
        effectiveOn: body.effectiveOn,
        expiresOn: body.expiresOn,
        detailsEnvelope: body.detailsEnvelope,
        detailsContentHash: body.detailsContentHash,
      })),
      201,
    ));
  });

  app.post("/v1/members/:memberId/qualifications/:qualificationId/revisions", {
    preHandler: [
      app.authenticate,
      app.verifyCsrf,
      app.requirePermission("member.qualification.manage"),
      requireRecentMfa("revising an independent member qualification"),
    ],
  }, async (request, reply) => {
    const { memberId, qualificationId } = parseParams(qualificationParams, request);
    const body = parseBody(memberQualificationRevisionSchema, request);
    const principal = requirePrincipal(request);
    noStore(reply);
    const version = body.expectedVersion + 1;
    validateQualificationEnvelope(request, {
      memberId,
      qualificationId,
      version,
      ...body,
    });
    return withQualificationErrors(async () => respond(
      request,
      reply,
      await app.database.withMemberQualificationPrincipal(principal, request.id, (store) => store.revise({
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        memberId,
        qualificationId,
        expectedVersion: body.expectedVersion,
        type: body.type,
        status: body.status,
        effectiveOn: body.effectiveOn,
        expiresOn: body.expiresOn,
        detailsEnvelope: body.detailsEnvelope,
        detailsContentHash: body.detailsContentHash,
      })),
      201,
    ));
  });
}

function validateQualificationEnvelope(
  request: FastifyRequest,
  input: {
    readonly memberId: string;
    readonly qualificationId: string;
    readonly version: number;
    readonly type: "training" | "ordination" | "certification" | "other";
    readonly status: "pending" | "verified" | "expired" | "revoked";
    readonly effectiveOn: string;
    readonly expiresOn: string | null;
    readonly detailsEnvelope: {
      readonly algorithm: "AES-256-GCM" | "XCHACHA20-POLY1305";
      readonly keyId: string;
      readonly nonce: string;
      readonly ciphertext: string;
      readonly aad: string;
    } | null;
    readonly detailsContentHash: string | null;
  },
): void {
  if (!input.detailsEnvelope || !input.detailsContentHash) return;
  const principal = requirePrincipal(request);
  validateEnvelopeContext(input.detailsEnvelope, memberQualificationAadContext({
    tenantId: principal.activeTenantId,
    memberId: input.memberId,
    qualificationId: input.qualificationId,
    version: input.version,
    type: input.type,
    status: input.status,
    effectiveOn: input.effectiveOn,
    expiresOn: input.expiresOn,
  }), { exact: true });
  validateEnvelopeContentHash(input.detailsEnvelope, input.detailsContentHash);
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

async function withQualificationErrors<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof MemberQualificationStoreError) {
      throw new ApiError(error.statusCode, error.code, error.message);
    }
    throw error;
  }
}

function noStore(reply: FastifyReply): void {
  reply.header("cache-control", "private, no-store, max-age=0");
  reply.header("pragma", "no-cache");
  reply.header("vary", "Cookie");
}
