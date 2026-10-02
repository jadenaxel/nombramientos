import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('additive explicit central operational roles', () => {
  const control = readFileSync(path.resolve(import.meta.dirname, '../migrations/control/032_gestionchurch_explicit_operational_roles.sql'), 'utf8');
  const tenant = readFileSync(path.resolve(import.meta.dirname, '../migrations/tenant/038_gestionchurch_explicit_custodian_role.sql'), 'utf8');
  const operation = readFileSync(path.resolve(import.meta.dirname, '../scripts/apply-explicit-operational-role-migrations.mjs'), 'utf8');
  it('adds two source IDs and expands the bounded role assertion while preserving revocation serialization', () => {
    expect(control).toContain('NOMINATIONS_COMMISSION_MEMBER');
    expect(control).toContain('NOMINATIONS_BALLOT_CUSTODIAN');
    expect(control).toContain('BETWEEN 1 AND 14');
    expect(control).toContain('previous_role_fingerprint IS DISTINCT FROM p_role_fingerprint');
    expect(control).toContain('pg_advisory_xact_lock');
  });
  it('only widens the existing tenant system-role whitelist, retaining exact context and count guards', () => {
    expect(tenant).toContain('TALLY_CUSTODIAN');
    expect(tenant).toContain('NOT BETWEEN 1 AND 3');
    expect(tenant).toContain('contextual_identity IS DISTINCT FROM p_identity_id');
    expect(tenant).toContain('source_invitation_id IS NOT NULL');
  });
  it('fails closed, preserves private execution, and contains no assignment or account DML', () => {
    for (const migration of [control, tenant]) {
      expect(migration).toContain('RAISE EXCEPTION');
      expect(migration).toContain('REVOKE ALL ON FUNCTION');
      expect(migration).not.toMatch(/GRANT .* TO PUBLIC|INSERT INTO|DELETE FROM|UPDATE (?:public\.)?(?:role_bindings|platform_identities|tenant_memberships|auth_sessions)|DROP TABLE/iu);
    }
  });
  it('guards every exact ledger before applying and preserves privately saved rollback plus row counts and privileges', () => {
    expect(operation).toContain('assert.equal(entry.plan.pending.length, 1)');
    expect(operation).toContain('assert.equal(entry.plan.pending[0]?.name, entry.target)');
    expect(operation).toContain('expectedPendingMigrations: entry.plan.pending');
    expect(operation).toContain('executionRole: entry.executionRole');
    expect(operation).toContain('flag: "wx", mode: 0o600');
    expect(operation).toContain('"/inheritance:r"');
    expect(operation).toContain('entry.beforeCounts');
    expect(operation).toContain('routinePrivilegesUnchanged: true');
    expect(operation.indexOf('restrictPrivateFile(entry.rollbackPath)')).toBeLessThan(operation.indexOf('await runMigrations'));
    expect(operation).not.toMatch(/console\.(?:log|error)\([^\n]*(?:definition|admin\.href|bytes)/u);
  });
});
