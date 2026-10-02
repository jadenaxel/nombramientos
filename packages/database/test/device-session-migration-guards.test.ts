import { describe, expect, it } from 'vitest';
// The executable intentionally has a main-module guard: importing it never reads
// installation secrets, opens PostgreSQL, starts services or mutates a tenant.
// @ts-expect-error The narrow operational script is JavaScript, not a library export.
import { assertExpirationCleanupAuthority, assertLocalRoute, assertTargetPlan, LOCAL_TENANTS, TARGET, TABLES } from '../scripts/apply-device-session-migration.mjs';

const original = () => ({ applied: [...Array.from({ length: 39 }, (_, i) => ({ name: `previous-${i}` })),
  { name: '038_gestionchurch_explicit_custodian_role.sql' }], pending: [{ name: TARGET }] });
const route = () => ({ id: LOCAL_TENANTS[0], databaseHost: '127.0.0.1', databasePort: 55432,
  databaseName: `nom_t_${LOCAL_TENANTS[0].replaceAll('-', '')}`, runtimeRole: `nom_r_${LOCAL_TENANTS[0].replaceAll('-', '')}` });
const cleanupAuthority = () => ({ owner: assertLocalRoute(route()), owner_can_login: false,
  prosecdef: true, proconfig: ['search_path=pg_catalog'], public_execute: false,
  runtime_execute: false, tgenabled: 'O', tgtype: 4, index_owner: assertLocalRoute(route()), index_valid: true });
describe('narrow local D10 migration guard', () => {
  it('accepts only the exact previous ledger and target', () => {
    expect(assertTargetPlan(original())).toBe(false);
    expect(assertTargetPlan({ applied: [...original().applied, { name: TARGET }], pending: [] })).toBe(true);
  });
  it.each([
    { applied: original().applied.slice(1), pending: [{ name: TARGET }] },
    { applied: original().applied, pending: [] },
    { applied: original().applied, pending: [{ name: '040_unreviewed.sql' }] },
    { applied: original().applied, pending: [{ name: TARGET }, { name: '040_unreviewed.sql' }] },
    { applied: [...original().applied, { name: TARGET }], pending: [{ name: '040_unreviewed.sql' }] },
  ])('fails closed on a changed or additional migration plan', (plan) => {
    expect(() => assertTargetPlan(plan)).toThrow();
  });
  it('accepts only deterministic owner/runtime routes for the three known local tenants', () => {
    expect(assertLocalRoute(route())).toBe(`nom_o_${LOCAL_TENANTS[0].replaceAll('-', '')}`);
    expect(TABLES).toEqual(['e2ee_http_challenges', 'e2ee_http_devices', 'e2ee_http_session_bindings']);
  });
  it.each([
    { id: '11111111-1111-4111-8111-111111111111' }, { databaseHost: 'remote.example' },
    { databasePort: 5432 }, { databaseName: 'postgres' }, { runtimeRole: 'nom_admin' },
  ])('refuses unknown or nonlocal routing', (mutation) => {
    expect(() => assertLocalRoute({ ...route(), ...mutation })).toThrow();
  });
  it('allows expiration pruning only through the narrowly privileged tenant-owner statement trigger', () => {
    expect(() => assertExpirationCleanupAuthority(cleanupAuthority(), assertLocalRoute(route()))).not.toThrow();
  });
  it.each([
    { owner: 'nom_admin' }, { owner_can_login: true }, { prosecdef: false },
    { proconfig: ['search_path=public,pg_temp'] }, { public_execute: true },
    { runtime_execute: true }, { tgenabled: 'D' }, { tgtype: 5 },
    { index_owner: 'nom_admin' }, { index_valid: false },
  ])('refuses an unsafe cleanup routine or trigger', (mutation) => {
    expect(() => assertExpirationCleanupAuthority({ ...cleanupAuthority(), ...mutation }, assertLocalRoute(route()))).toThrow();
  });
});
