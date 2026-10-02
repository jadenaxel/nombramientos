import { describe, expect, it } from 'vitest';
import { mapNombramientosRoles } from '../src/modules/gestionchurch-integration-routes.js';

describe('explicit central Nombramientos role projection', () => {
  it.each([
    ['TENANT_ADMIN', 'CHURCH_ADMIN'],
    ['GLOBAL_ADMIN', 'CHURCH_ADMIN'],
    ['BOARD_SECRETARY', 'COMMITTEE_SECRETARY'],
    ['AUDITOR', 'AUDITOR'],
  ] as const)('does not make %s an automatic voter or custodian', (source, expected) => {
    expect(mapNombramientosRoles([source])).toEqual([expected]);
  });
  it('preserves historical explicit commission assignment', () => {
    expect(mapNombramientosRoles(['NOMINATIONS_USER'])).toEqual(['COMMITTEE_MEMBER']);
    expect(mapNombramientosRoles(['NOMINATIONS_USER', 'NOMINATIONS_COMMISSION_MEMBER'])).toEqual(['COMMITTEE_MEMBER']);
  });
  it('adds only the operations explicitly assigned centrally', () => {
    expect(mapNombramientosRoles(['TENANT_ADMIN', 'NOMINATIONS_COMMISSION_MEMBER'])).toEqual(['CHURCH_ADMIN', 'COMMITTEE_MEMBER']);
    expect(mapNombramientosRoles(['VIEWER', 'NOMINATIONS_BALLOT_CUSTODIAN'])).toEqual(['TALLY_CUSTODIAN']);
    expect(mapNombramientosRoles(['TENANT_ADMIN', 'BOARD_SECRETARY', 'AUDITOR', 'NOMINATIONS_COMMISSION_MEMBER', 'NOMINATIONS_BALLOT_CUSTODIAN']))
      .toEqual(['CHURCH_ADMIN', 'COMMITTEE_MEMBER', 'TALLY_CUSTODIAN']);
  });
  it('does not infer operational rights from unrelated roles', () => {
    expect(() => mapNombramientosRoles(['VIEWER', 'PASTOR'])).toThrow(/did not grant/);
  });
});
