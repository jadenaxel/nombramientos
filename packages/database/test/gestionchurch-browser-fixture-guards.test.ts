import { readFileSync } from 'node:fs';
import path from 'node:path';
import { expect, it } from 'vitest';

it('browser fixture defaults read-only and never discovers or synchronizes all churches', () => {
  const source = readFileSync(path.resolve(import.meta.dirname, '../scripts/gestionchurch-browser-fixture.mjs'), 'utf8');
  expect(source).toContain(': "--check"');
  expect(source).toContain('WHERE id=$1');
  expect(source).toContain('Synthetic premium validation');
  expect(source).toContain('/^premium-[a-f0-9]{16}$/u');
  expect(source).toContain('targetsFresh: true, mutations: 0');
  expect(source).not.toContain('WHERE status=');
  expect(source).not.toContain('sync-gestionchurch');
});

it('cleanup proves nonce and exact route before deleting only the fixture and preserves audit history', () => {
  const source = readFileSync(path.resolve(import.meta.dirname, '../scripts/gestionchurch-browser-fixture.mjs'), 'utf8');
  expect(source).toContain('proof.rows[0].nonce, receipt.nonce');
  expect(source).toContain('job.rows[0].idempotency_key, receipt.nonce');
  expect(source).toContain('never terminate unknown connections');
  expect(source).toContain('DELETE FROM tenants WHERE id=$1 AND slug=$2 AND database_name=$3');
  expect(source).toContain('await secrets.removeSecret(secretReference)');
  expect(source).toContain('retainedAuditTrace: true');
  expect(source).not.toMatch(/pg_terminate_backend|DELETE FROM platform_audit_events|DROP DATABASE IF EXISTS/u);
});

it('read-only cleanup verification requires exact current control/tenant ledgers and validates every owned receipt', () => {
  const source = readFileSync(path.resolve(import.meta.dirname, '../scripts/verify-gestionchurch-browser-cleanup.mjs'), 'utf8');
  expect(source).toContain('verifiedLedger(control, "control", 32, "032_gestionchurch_explicit_operational_roles.sql")');
  expect(source).toContain('verifiedLedger(tenant, "tenant", 41, "039_device_bound_http_sessions.sql")');
  expect(source).toContain('default_transaction_read_only=on');
  expect(source).toContain('assertReadOnly(tenant)');
  expect(source).toContain('originalTenantIds.includes(receipt.tenantId)');
  expect(source).toContain('No owned receipts: cleanup verification would be vacuous');
  expect(source).toContain('remainingOwnedResources: { ...absent, secretReferences: 0 }');
  expect(source).toContain('assert.equal(await secrets.hasSecret(receipt.secretReference), false)');
  expect(source).not.toMatch(/\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+(?:DATABASE|ROLE)|TRUNCATE\s+)\b/u);
});
