import type { FastifyInstance } from 'fastify';
import { safeLogError } from '../lib/log-safety.js';

/** Denied proofs belong to the authenticated tenant's audit trail. Raw proofs,
 * URLs/queries, nonce values, request bodies and private keys never enter it.
 * Admission rate limits run before this hook; 429 does not amplify DB writes.
 * Audit unavailability must never turn a denied request into an allowed one. */
export function registerDeviceDenialAudit(app: FastifyInstance): void {
  app.addHook('onError', async (request, _reply, error) => {
    const principal = request.principal;
    if (!principal || principal.tenantKind !== 'real' || typeof error !== 'object' || error === null) return;
    const code = 'code' in error ? error.code : undefined;
    if (typeof code !== 'string' || !/^DEVICE_(?:PROOF|SESSION|SIGNING_KEY)_[A-Z_]{1,60}$/u.test(code)) return;
    const status = 'statusCode' in error ? error.statusCode : undefined;
    if (status === 429 || code === 'DEVICE_PROOF_BUDGET_EXCEEDED') {
      request.log.warn({ requestId: request.id, securityEvent: 'device-proof-throttled', code }, 'Device proof admission budget exceeded');
      return;
    }
    // The registered route template is server-owned; do not fall back to the
    // incoming URL, which may include names, emails or other private values.
    const template = request.routeOptions.url;
    const route = typeof template === 'string' && /^\/v1\/[a-zA-Z0-9_:/.-]{1,200}$/u.test(template) ? template : '/v1/unknown';
    const method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) ? request.method : 'OTHER';
    try {
      await app.database.withDeviceSessionPrincipal(principal, request.id, (store) => store.appendProofDenial({ code, method, route }));
    } catch (auditError) {
      request.log.error({ requestId: request.id, securityEvent: 'device-proof-audit-unavailable', code, safeError: safeLogError(auditError) }, 'Denied device proof audit could not be persisted');
    }
  });
}
