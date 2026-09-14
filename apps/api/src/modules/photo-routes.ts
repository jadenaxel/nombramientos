import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { PhotoStoreError } from "@nombramientos/database";
import { z } from "zod";
import { ApiError, unauthorized } from "../lib/errors.js";
import { validateEnvelopeContentHash, validateEnvelopeContext } from "../lib/envelopes.js";
import { parseBody, parseParams, requireIdempotencyKey, respond } from "../lib/http.js";
import { photoAadContext, photoArchiveSchema, photoPutSchema, photoUuidSchema } from "./photo-contract.js";

export async function registerPhotoRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/members/:memberId/photo/write-context", {
    preHandler: [app.authenticate, app.requirePermission("member.photo.manage")],
  }, async (request, reply) => {
    const { memberId } = parseParams(photoMemberParams, request);
    noStore(reply);
    return withPhotoErrors(async () => {
      const context = await app.database.withPhotoPrincipal(
        requirePrincipal(request),
        request.id,
        (store) => store.getPhotoWriteContext(memberId),
      );
      return respond(request, reply, context);
    });
  });

  app.get("/v1/members/:memberId/photo", {
    preHandler: [app.authenticate, app.requirePermission("member.read")],
  }, async (request, reply) => {
    const { memberId } = parseParams(photoMemberParams, request);
    noStore(reply);
    return withPhotoErrors(async () => {
      const photo = await app.database.withPhotoPrincipal(
        requirePrincipal(request),
        request.id,
        (store) => store.getActivePhoto(memberId),
      );
      return respond(request, reply, photo);
    });
  });

  app.post("/v1/members/:memberId/photo", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("member.photo.manage")],
  }, async (request, reply) => {
    const { memberId } = parseParams(photoMemberParams, request);
    const body = parseBody(photoPutSchema, request);
    const principal = requirePrincipal(request);
    noStore(reply);
    const context = photoAadContext({
      tenantId: principal.activeTenantId,
      memberId,
      photoId: body.photoId,
      version: body.version,
      mediaType: body.mediaType,
      width: body.width,
      height: body.height,
      plaintextBytes: body.plaintextBytes,
    });
    validateEnvelopeContext(body.envelope, context, { exact: true });
    validateEnvelopeContentHash(body.envelope, body.contentHash);
    return withPhotoErrors(async () => {
      const result = await app.database.withPhotoPrincipal(principal, request.id, (store) => store.putPhoto({
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        memberId,
        photoId: body.photoId,
        expectedVersion: body.expectedVersion,
        version: body.version,
        mediaType: body.mediaType,
        width: body.width,
        height: body.height,
        plaintextBytes: body.plaintextBytes,
        envelope: body.envelope,
        contentHash: body.contentHash,
      }));
      return respond(request, reply, result, body.expectedVersion === 0 ? 201 : 200);
    });
  });

  app.post("/v1/members/:memberId/photo/archive", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("member.photo.manage")],
  }, async (request, reply) => {
    const { memberId } = parseParams(photoMemberParams, request);
    const body = parseBody(photoArchiveSchema, request);
    const principal = requirePrincipal(request);
    noStore(reply);
    return withPhotoErrors(async () => {
      const result = await app.database.withPhotoPrincipal(principal, request.id, (store) => store.archivePhoto({
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        memberId,
        expectedVersion: body.expectedVersion,
      }));
      return respond(request, reply, result);
    });
  });
}

const photoMemberParams = z.object({ memberId: photoUuidSchema });

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

async function withPhotoErrors<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof PhotoStoreError) {
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
