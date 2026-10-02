import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { requireCentralOperationalBindingAuthority } from '../src/modules/access-routes.js';

describe('central federated operational binding authority', () => {
  it.each(['COMMITTEE_MEMBER', 'TALLY_CUSTODIAN'])('rejects local grant/revocation of centrally managed %s', async (role) => {
    const getGestionChurchFederation = vi.fn().mockResolvedValue({ subject: 'synthetic' });
    const app = { database: { control: { getGestionChurchFederation } } } as unknown as FastifyInstance;
    await expect(requireCentralOperationalBindingAuthority(app, 'tenant-fixture', 'identity-fixture', role))
      .rejects.toMatchObject({ statusCode: 403, code: 'GESTIONCHURCH_MANAGED_OPERATIONAL_ROLE' });
    expect(getGestionChurchFederation).toHaveBeenCalledWith('identity-fixture', 'tenant-fixture');
  });
  it.each(['COMMITTEE_MEMBER', 'TALLY_CUSTODIAN'])('preserves local non-federated %s administration', async (role) => {
    const app = { database: { control: { getGestionChurchFederation: vi.fn().mockResolvedValue(null) } } } as unknown as FastifyInstance;
    await expect(requireCentralOperationalBindingAuthority(app, 'tenant-fixture', 'identity-fixture', role)).resolves.toBeUndefined();
  });
  it('preserves other role administration without requiring federation metadata', async () => {
    const getGestionChurchFederation = vi.fn();
    const app = { database: { control: { getGestionChurchFederation } } } as unknown as FastifyInstance;
    await expect(requireCentralOperationalBindingAuthority(app, 'tenant-fixture', 'identity-fixture', 'LOCAL_COORDINATION')).resolves.toBeUndefined();
    expect(getGestionChurchFederation).not.toHaveBeenCalled();
  });
});
