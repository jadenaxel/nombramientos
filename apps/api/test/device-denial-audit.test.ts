import { randomUUID } from 'node:crypto';
import type { DeviceSessionStore, RequestPrincipal } from '@nombramientos/database';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { registerDeviceDenialAudit } from '../src/modules/device-denial-audit.js';

function fixture() {
  let hook: (request: FastifyRequest, reply: unknown, error: unknown) => Promise<void>;
  const recordProofDenial = vi.fn().mockResolvedValue(undefined);
  const withDeviceSessionPrincipal = vi.fn(async (_principal: RequestPrincipal, _requestId: string, work: (store: DeviceSessionStore) => Promise<unknown>) => work({ appendProofDenial: recordProofDenial } as unknown as DeviceSessionStore));
  const app = { addHook: vi.fn((_name: string, value: typeof hook) => { hook = value; }), database: { withDeviceSessionPrincipal } } as unknown as FastifyInstance;
  registerDeviceDenialAudit(app);
  const principal = { sessionId: randomUUID(), identityId: randomUUID(), activeTenantId: randomUUID(), tenantKind: 'real' } as RequestPrincipal;
  const request = { principal, id: randomUUID(), method: 'PATCH', url: '/v1/members/private-email?proof=must-not-log',
    routeOptions: { url: '/v1/members/:id' }, body: { secret: 'must-not-log' }, headers: { 'x-device-proof': 'must-not-log' },
    log: { error: vi.fn(), warn: vi.fn() } } as unknown as FastifyRequest;
  return { run: (error: unknown, override: Partial<FastifyRequest> = {}) => hook({ ...request, ...override } as FastifyRequest, {}, error),
    request, principal, recordProofDenial, withDeviceSessionPrincipal };
}
describe('tenant-local device denial audit', () => {
  it('records a denied proof using only verified source context and registered route metadata', async () => {
    const item = fixture();
    await item.run({ code: 'DEVICE_PROOF_INVALID', statusCode: 401, message: 'must-not-log', details: { secret: 'must-not-log' } });
    expect(item.withDeviceSessionPrincipal).toHaveBeenCalledWith(item.principal, item.request.id, expect.any(Function));
    expect(item.recordProofDenial).toHaveBeenCalledWith({ code: 'DEVICE_PROOF_INVALID', method: 'PATCH', route: '/v1/members/:id' });
    expect(JSON.stringify(item.recordProofDenial.mock.calls)).not.toContain('must-not-log');
  });
  it('does not persist unauthenticated, demo or unrelated failures', async () => {
    const item = fixture();
    await item.run({ code: 'DEVICE_PROOF_INVALID' }, { principal: null });
    await item.run({ code: 'DEVICE_PROOF_INVALID' }, { principal: { ...item.principal, tenantKind: 'demo' } });
    await item.run({ code: 'UNRELATED_ERROR' });
    expect(item.withDeviceSessionPrincipal).not.toHaveBeenCalled();
  });
  it('logs admission exhaustion without amplifying it into durable DB work', async () => {
    const item = fixture();
    await item.run({ code: 'DEVICE_PROOF_BUDGET_EXCEEDED', statusCode: 429 });
    expect(item.request.log.warn).toHaveBeenCalled();
    expect(item.withDeviceSessionPrincipal).not.toHaveBeenCalled();
  });
  it('keeps the original denial when audit storage fails and suppresses diagnostic secrets', async () => {
    const item = fixture();
    item.recordProofDenial.mockRejectedValue(new Error('must-not-log'));
    await expect(item.run({ code: 'DEVICE_SESSION_REVOKED', statusCode: 401 })).resolves.toBeUndefined();
    expect(item.request.log.error).toHaveBeenCalled();
    const calls = JSON.stringify((item.request.log.error as ReturnType<typeof vi.fn>).mock.calls);
    expect(calls).not.toContain('must-not-log');
  });
  it('never substitutes an untrusted URL for a missing route template', async () => {
    const item = fixture();
    await item.run({ code: 'DEVICE_PROOF_INVALID' }, { routeOptions: { url: '/v1/path?secret=must-not-log' } as FastifyRequest['routeOptions'] });
    expect(item.recordProofDenial).toHaveBeenCalledWith(expect.objectContaining({ route: '/v1/unknown' }));
  });
});
