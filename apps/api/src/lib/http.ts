import type { FastifyReply, FastifyRequest } from "fastify";
import type { z } from "zod";
import { ApiError } from "./errors.js";

export function parseBody<T extends z.ZodTypeAny>(schema: T, request: FastifyRequest): z.infer<T> {
  const result = schema.safeParse(request.body);
  if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", "Request body is invalid", result.error.flatten());
  return result.data;
}

export function parseParams<T extends z.ZodTypeAny>(schema: T, request: FastifyRequest): z.infer<T> {
  const result = schema.safeParse(request.params);
  if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", "Route parameters are invalid", result.error.flatten());
  return result.data;
}

export function parseQuery<T extends z.ZodTypeAny>(schema: T, request: FastifyRequest): z.infer<T> {
  const result = schema.safeParse(request.query);
  if (!result.success) throw new ApiError(400, "VALIDATION_ERROR", "Query parameters are invalid", result.error.flatten());
  return result.data;
}

export function respond<T>(request: FastifyRequest, reply: FastifyReply, data: T, status = 200): FastifyReply {
  return reply.status(status).send({ data, meta: { requestId: request.id } });
}

export function requireIdempotencyKey(request: FastifyRequest): string {
  const value = request.headers["idempotency-key"];
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new ApiError(400, "IDEMPOTENCY_KEY_REQUIRED", "A UUID Idempotency-Key header is required");
  }
  return value;
}
