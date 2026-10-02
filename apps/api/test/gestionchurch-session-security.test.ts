import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { RequestPrincipal } from '@nombramientos/database';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getGestionChurchOrganizationDirectory, requireCurrentGestionChurchAccess } from '../src/modules/gestionchurch-integration-routes.js';

afterEach(() => vi.unstubAllGlobals());

function fixture() {
  const tenantId = randomUUID(), identityId = randomUUID(), sessionId = randomUUID(), sourceSessionId = randomUUID();
  const principal = { identityId, sessionId, activeTenantId: tenantId, authMethod: 'federated' } as RequestPrincipal;
  const metadata = { subject: `tenant:${tenantId}:${identityId}`, gestionChurchTenantId: tenantId, roleFingerprint: 'a'.repeat(64) };
  const control = {
    getGestionChurchFederation: vi.fn().mockResolvedValue(metadata),
    getGestionChurchSessionBinding: vi.fn().mockResolvedValue(sourceSessionId),
    revokeSession: vi.fn().mockResolvedValue(undefined),
  };
  const apiConfig = { gestionChurchIntegration: { enabled: true, sharedSecret: 'test-secret', authorizeUrl: 'http://gestionchurch.test/authorize', organizationUrl: 'http://gestionchurch.test/organization' } };
  const app = { apiConfig, database: { control } } as unknown as FastifyInstance;
  return { app, principal, metadata, control, apiConfig, tenantId, identityId, sessionId, sourceSessionId };
}

describe('GestionChurch shared-session security', () => {
  it('binds authorization to the exact source session and active tenant', async () => {
    const item = fixture();
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: true, roleFingerprint: item.metadata.roleFingerprint }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await requireCurrentGestionChurchAccess(item.app, item.principal);
    expect(item.control.getGestionChurchFederation).toHaveBeenCalledWith(item.identityId, item.tenantId);
    expect(item.control.getGestionChurchSessionBinding).toHaveBeenCalledWith(item.sessionId, item.identityId, item.tenantId);
    expect(JSON.parse(fetch.mock.calls[0]![1].body)).toMatchObject({ sourceSessionId: item.sourceSessionId, tenantId: item.tenantId });
    expect(item.control.revokeSession).not.toHaveBeenCalled();
  });
  it('rejects old unbound sessions without calling upstream authorization', async () => {
    const item = fixture(); item.control.getGestionChurchSessionBinding.mockResolvedValue(null);
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/again/);
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.sessionId, 'gestionchurch_session_unbound');
    expect(fetch).not.toHaveBeenCalled();
  });
  it('accepts explicit central commission/custodian assertions only with the matching complete fingerprint', async () => {
    const item = fixture();
    const roles = ['VIEWER', 'NOMINATIONS_COMMISSION_MEMBER', 'NOMINATIONS_BALLOT_CUSTODIAN'];
    item.metadata.roleFingerprint = createHash('sha256').update([...roles].sort().join('\n')).digest('hex');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: true, roles, roleFingerprint: item.metadata.roleFingerprint }), { status: 200 })));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).resolves.toBeUndefined();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: true, roles: ['VIEWER'], roleFingerprint: item.metadata.roleFingerprint }), { status: 200 })));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/changed/);
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.sessionId, 'gestionchurch_access_changed');
  });
  it('revokes only the session whose source was logged out when one identity has two independent sources', async () => {
    const item = fixture();
    const otherSessionId = randomUUID(), otherSourceId = randomUUID();
    item.control.getGestionChurchSessionBinding.mockImplementation(async (sessionId: string) => sessionId === item.sessionId ? item.sourceSessionId : otherSourceId);
    const fetch = vi.fn(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { sourceSessionId: string };
      return new Response(JSON.stringify(body.sourceSessionId === item.sourceSessionId
        ? { authorized: false } : { authorized: true, roleFingerprint: item.metadata.roleFingerprint }), { status: 200 });
    });
    vi.stubGlobal('fetch', fetch);
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/changed/);
    await expect(requireCurrentGestionChurchAccess(item.app, { ...item.principal, sessionId: otherSessionId })).resolves.toBeUndefined();
    expect(item.control.revokeSession).toHaveBeenCalledTimes(1);
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.sessionId, 'gestionchurch_access_changed');
    expect(fetch.mock.calls.map(([, init]) => JSON.parse(init.body as string).sourceSessionId)).toEqual([item.sourceSessionId, otherSourceId]);
  });
  it('fails closed on upstream network or malformed authorization without treating it as a valid grant', async () => {
    const item = fixture();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('synthetic unavailable')));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toMatchObject({ statusCode: 503 });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ authorized: true, roleFingerprint: 42 }), { status: 200 })));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow();
    expect(item.control.revokeSession).not.toHaveBeenCalled();
  });
  it('records a minimized upstream status without logging assertions, URLs or connector credentials', async () => {
    const item = fixture();
    const warn = vi.fn();
    Object.assign(item.app, { log: { warn } });
    const rejectedResponse = new Response(JSON.stringify({
      code: 'sensitive-response-code', body: item.sourceSessionId,
      token: 'must-not-be-logged', detail: item.apiConfig.gestionChurchIntegration.sharedSecret,
    }), { status: 429 });
    const readErrorBody = vi.spyOn(rejectedResponse, 'json');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(rejectedResponse));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toMatchObject({
      statusCode: 502, code: 'GESTIONCHURCH_EXCHANGE_REJECTED',
    });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]![0]).toEqual({
      event: 'gestionchurch.upstream_rejected', operation: 'authorize', upstreamStatus: 429,
      observedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
    const logged = JSON.stringify(warn.mock.calls);
    for (const sensitive of [item.sourceSessionId, item.identityId, item.tenantId,
      item.apiConfig.gestionChurchIntegration.sharedSecret, item.apiConfig.gestionChurchIntegration.authorizeUrl,
      'must-not-be-logged', 'sensitive-response-code']) expect(logged).not.toContain(sensitive);
    expect(readErrorBody).not.toHaveBeenCalled();
    expect(item.control.revokeSession).not.toHaveBeenCalled();
  });
  it.each([
    { authorized: false },
    { authorized: true, roleFingerprint: 'b'.repeat(64) },
  ])('revokes access after source logout, reset or role change', async (authorization) => {
    const item = fixture();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(authorization), { status: 200 })));
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/changed/);
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.sessionId, 'gestionchurch_access_changed');
  });
  it('fails closed when federation metadata or integration is unavailable', async () => {
    const item = fixture(); item.control.getGestionChurchFederation.mockResolvedValue(null);
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/missing/);
    item.apiConfig.gestionChurchIntegration.enabled = false;
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/not available/);
    await expect(requireCurrentGestionChurchAccess(item.app, { ...item.principal, authMethod: 'password' })).resolves.toBeUndefined();
  });
  it('rejects tenant substitution in federation metadata', async () => {
    const item = fixture(); item.control.getGestionChurchFederation.mockResolvedValue({ ...item.metadata, gestionChurchTenantId: randomUUID() });
    await expect(requireCurrentGestionChurchAccess(item.app, item.principal)).rejects.toThrow(/invalid/);
    expect(item.control.revokeSession).toHaveBeenCalledWith(item.sessionId, 'gestionchurch_context_invalid');
  });
  it('does not return an organization directory for a different tenant', async () => {
    const item = fixture();
    const directory = { source: 'gestionchurch', tenantId: randomUUID(), tenantName: 'Other church', generatedAt: new Date().toISOString(), sourceUpdatedAt: null, summary: { departments: 0, people: 0, appointments: 0 }, items: [] };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(directory), { status: 200 })));
    await expect(getGestionChurchOrganizationDirectory(item.app, item.principal)).rejects.toThrow(/different tenant/);
  });
});
