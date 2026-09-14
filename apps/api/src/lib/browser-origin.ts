import type { FastifyInstance, FastifyRequest } from "fastify";
import { ApiError } from "./errors.js";

/**
 * Session and ceremony cookies are browser credentials. Require the browser's
 * exact serialized Origin before any credential work or cookie mutation. The
 * WebAuthn origin set is the application's canonical browser-origin contract
 * and is deliberately narrower than a potentially transitional CORS allowlist.
 * Do not normalize attacker-controlled input here.
 */
export function requireTrustedBrowserOrigin(app: FastifyInstance) {
  return async (request: FastifyRequest): Promise<void> => {
    const origin = request.headers.origin;
    if (typeof origin !== "string" || !app.apiConfig.webauthn.expectedOrigins.includes(origin)) {
      throw new ApiError(403, "ORIGIN_NOT_ALLOWED", "Request origin is not allowed");
    }
  };
}
