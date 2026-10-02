import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { EncryptedFileSecretProvider } from '../src/secrets.js';

it('removes only the selected owned secret reference and keeps unrelated values retrievable', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'nom-secret-removal-'));
  const key = randomBytes(32);
  try {
    const provider = new EncryptedFileSecretProvider(path.join(directory, 'synthetic.enc.json'), key);
    const retained = randomBytes(32).toString('base64url'), owned = randomBytes(32).toString('base64url');
    await provider.putSecret('synthetic-retained', retained);
    await provider.putSecret('synthetic-owned', owned);
    const acl = () => process.platform === 'win32' ? execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '([System.IO.FileInfo]::new($env:NOM_SYNTHETIC_SECRET_FILE)).GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)'], { encoding: 'utf8', windowsHide: true, env: { ...process.env, NOM_SYNTHETIC_SECRET_FILE: path.join(directory, 'synthetic.enc.json') } }).trim() : undefined;
    const originalAcl = acl();
    await provider.removeSecret('synthetic-owned');
    expect(acl() === originalAcl).toBe(true);
    expect(await provider.getSecret('synthetic-retained') === retained).toBe(true);
    expect(await provider.hasSecret('synthetic-owned')).toBe(false);
    await expect(provider.removeSecret('synthetic-owned')).rejects.toThrow(/unavailable/);
    expect(await provider.getSecret('synthetic-retained') === retained).toBe(true);
  } finally {
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

it('serializes independent writers so removal and new references cannot clobber unrelated entries', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'nom-secret-concurrency-'));
  const key = randomBytes(32);
  try {
    const filename = path.join(directory, 'synthetic.enc.json');
    const first = new EncryptedFileSecretProvider(filename, key), second = new EncryptedFileSecretProvider(filename, key);
    await first.putSecret('synthetic-owned', randomBytes(32).toString('base64url'));
    await Promise.all([first.putSecret('synthetic-a', 'synthetic-only-a'), second.putSecret('synthetic-b', 'synthetic-only-b')]);
    await Promise.all([first.removeSecret('synthetic-owned'), second.putSecret('synthetic-c', 'synthetic-only-c')]);
    expect(await first.hasSecret('synthetic-owned')).toBe(false);
    expect(await second.getSecret('synthetic-a') === 'synthetic-only-a').toBe(true);
    expect(await second.getSecret('synthetic-b') === 'synthetic-only-b').toBe(true);
    expect(await first.getSecret('synthetic-c') === 'synthetic-only-c').toBe(true);
  } finally {
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});
