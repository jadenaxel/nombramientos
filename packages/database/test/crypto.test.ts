import { describe, expect, it } from "vitest";
import {
  decryptServerSecret,
  encryptServerSecret,
  generateSecretKey,
  sealAesGcmJson,
  wrapTenantKeyWithPassword,
} from "../src/crypto-envelope.js";
import { redactConnectionString } from "../src/config.js";
import { MemorySecretProvider } from "../src/secrets.js";

describe("cryptographic envelope helpers", () => {
  it("creates a Web Crypto compatible AES-GCM envelope without plaintext", () => {
    const key = generateSecretKey();
    const envelope = sealAesGcmJson(
      { firstName: "Ángela" },
      key,
      "tenant-key-v1",
      { tenantId: "d0000000-0000-4000-8000-000000000001", purpose: "member-display", version: 1 },
    );
    expect(envelope.algorithm).toBe("AES-256-GCM");
    expect(Buffer.from(envelope.nonce, "base64url")).toHaveLength(12);
    expect(envelope.ciphertext).not.toContain("Ángela");
    expect(JSON.parse(Buffer.from(envelope.aad, "base64url").toString("utf8"))).toMatchObject({
      purpose: "member-display",
      version: 1,
    });
  });

  it("wraps a tenant key with PBKDF2 and never returns the password", () => {
    const wrapped = wrapTenantKeyWithPassword(
      generateSecretKey(),
      "correct-horse-battery-staple-demo",
      { tenantId: "d0000000-0000-4000-8000-000000000001", purpose: "tenant-key-wrap" },
    );
    expect(wrapped.kdf).toMatchObject({ name: "PBKDF2", hash: "SHA-256", iterations: 310_000 });
    expect(Buffer.from(wrapped.wrap.iv, "base64url")).toHaveLength(12);
    expect(JSON.stringify(wrapped)).not.toContain("correct-horse");
  });

  it("round-trips server-held TOTP material with an explicit deployment key", () => {
    const key = generateSecretKey();
    const encrypted = encryptServerSecret("JBSWY3DPEHPK3PXP", key);
    expect(encrypted).not.toContain("JBSWY3DPEHPK3PXP");
    expect(decryptServerSecret(encrypted, key)).toBe("JBSWY3DPEHPK3PXP");
  });
});

describe("secret safety utilities", () => {
  it("redacts PostgreSQL credentials", () => {
    // secret-scan: allow-test-fixture -- the literal exercises redaction and is not an accepted credential.
    const redacted = redactConnectionString("postgresql://admin:very-secret@127.0.0.1:55432/control");
    expect(redacted).not.toContain("admin");
    expect(redacted).not.toContain("very-secret");
    expect(redacted).toContain("127.0.0.1");
  });

  it("requires existing secret references", async () => {
    const provider = new MemorySecretProvider({ "tenant/demo": "runtime-secret" });
    await expect(provider.getSecret("tenant/demo")).resolves.toBe("runtime-secret");
    await expect(provider.getSecret("tenant/ozama")).rejects.toThrow("unavailable");
  });
});
