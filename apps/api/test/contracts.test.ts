import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  encryptedEnvelopeSchema,
  validateEnvelopeContentHash,
  validateEnvelopeContext,
} from "../src/lib/envelopes.js";
import { ApiError } from "../src/lib/errors.js";
import { parseApiConfig } from "../src/config.js";

describe("API security contracts", () => {
  it("accepts a 96-bit AES-GCM nonce and rejects a nonce from another algorithm", () => {
    const valid = {
      algorithm: "AES-256-GCM" as const,
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify({ tenantId: "tenant-a", roundId: "round-a" })).toString("base64url"),
    };
    expect(encryptedEnvelopeSchema.safeParse(valid).success).toBe(true);
    expect(encryptedEnvelopeSchema.safeParse({ ...valid, nonce: Buffer.alloc(24).toString("base64url") }).success).toBe(false);
  });

  it("rejects an envelope replayed into another tenant", () => {
    const envelope = encryptedEnvelopeSchema.parse({
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify({ tenantId: "tenant-a", purpose: "member-display" })).toString("base64url"),
    });
    expect(() => validateEnvelopeContext(envelope, { tenantId: "tenant-b" })).toThrow(ApiError);
  });

  it("binds member envelopes to the complete tenant/member/purpose/schema context", () => {
    const expected = {
      tenantId: "d0000000-0000-4000-8000-000000000001",
      memberId: "d2000000-0000-4000-8000-000000000001",
      purpose: "member-display",
      schemaVersion: 1,
    } as const;
    const envelope = encryptedEnvelopeSchema.parse({
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify(expected)).toString("base64url"),
    });
    expect(() => validateEnvelopeContext(envelope, expected, { exact: true })).not.toThrow();
    expect(() => validateEnvelopeContext(envelope, { ...expected, memberId: "d2000000-0000-4000-8000-000000000002" }, { exact: true }))
      .toThrow(ApiError);
    const withUnexpectedField = {
      ...envelope,
      aad: Buffer.from(JSON.stringify({ ...expected, assignmentId: "replay-target" })).toString("base64url"),
    };
    expect(() => validateEnvelopeContext(withUnexpectedField, expected, { exact: true })).toThrow(ApiError);
  });

  it("compares array-valued AAD fields deeply for a frozen eligibility-incident set", () => {
    const expected = {
      tenantId: "tenant-a",
      pauseIds: ["pause-a", "pause-b"],
      purpose: "eligibility-pause-resolution",
      schemaVersion: 1,
    } as const;
    const envelope = encryptedEnvelopeSchema.parse({
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify(expected)).toString("base64url"),
    });
    expect(() => validateEnvelopeContext(envelope, expected, { exact: true })).not.toThrow();
    expect(() => validateEnvelopeContext(envelope, { ...expected, pauseIds: ["pause-b", "pause-a"] }, { exact: true })).toThrow(ApiError);
  });

  it("detects corruption using the canonical full member envelope fingerprint", () => {
    const envelope = encryptedEnvelopeSchema.parse({
      algorithm: "AES-256-GCM",
      keyId: "tenant-key-v1",
      nonce: Buffer.alloc(12).toString("base64url"),
      ciphertext: Buffer.alloc(32).toString("base64url"),
      aad: Buffer.from(JSON.stringify({
        tenantId: "d0000000-0000-4000-8000-000000000001",
        memberId: "d2000000-0000-4000-8000-000000000001",
        purpose: "member-display",
        schemaVersion: 1,
      })).toString("base64url"),
    });
    const canonical = JSON.stringify(envelope);
    const contentHash = `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
    expect(() => validateEnvelopeContentHash(envelope, contentHash)).not.toThrow();
    expect(() => validateEnvelopeContentHash({ ...envelope, ciphertext: `${envelope.ciphertext}A` }, contentHash))
      .toThrow(ApiError);
  });

  it("defaults CORS to the canonical localhost browser origin only", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const config = parseApiConfig({
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
    });
    expect(config.corsOrigins.has("http://localhost:3000")).toBe(true);
    expect(config.corsOrigins.has("http://127.0.0.1:3000")).toBe(false);
    expect(config.trustedProxyCidrs).toEqual([]);
    expect(config.secureCookies).toBe(false);
    expect(config.webauthn).toEqual({
      rpName: "Nombramientos",
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      challengeTtlSeconds: 300,
      stepUpTtlSeconds: 120,
    });
  });

  it("binds WebAuthn to exact CORS origins and the configured RP ID", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const base = {
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
      API_CORS_ORIGINS: "https://login.example.test",
      WEBAUTHN_RP_ID: "example.test",
    } as const;
    expect(parseApiConfig({
      ...base,
      WEBAUTHN_EXPECTED_ORIGINS: "https://login.example.test",
    }).webauthn.expectedOrigins).toEqual(["https://login.example.test"]);
    expect(() => parseApiConfig({
      ...base,
      WEBAUTHN_EXPECTED_ORIGINS: "https://evil.example.invalid",
    })).toThrow(/RP ID|CORS/u);
    expect(() => parseApiConfig({
      ...base,
      API_CORS_ORIGINS: "http://login.example.test",
      WEBAUTHN_EXPECTED_ORIGINS: "http://login.example.test",
    })).toThrow(/HTTP WebAuthn origins/u);
  });

  it("fails closed for insecure production cookies or HTTP origins", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const base = {
      NODE_ENV: "production",
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
      WEBAUTHN_RP_ID: "localhost",
      WEBAUTHN_EXPECTED_ORIGINS: "https://localhost:3000",
    } as const;
    expect(() => parseApiConfig({
      ...base,
      API_COOKIE_SECURE: "false",
      API_CORS_ORIGINS: "https://localhost:3000",
    })).toThrow(/secure/i);
    expect(() => parseApiConfig({
      ...base,
      API_COOKIE_SECURE: "true",
      API_CORS_ORIGINS: "http://localhost:3000",
      WEBAUTHN_EXPECTED_ORIGINS: "http://localhost:3000",
    })).toThrow(/https/i);
    expect(() => parseApiConfig({
      ...base,
      API_COOKIE_SECURE: "true",
      API_CORS_ORIGINS: "https://127.0.0.1",
      WEBAUTHN_RP_ID: "127.0.0.1",
      WEBAUTHN_EXPECTED_ORIGINS: "https://127.0.0.1",
    })).toThrow(/RP_ID|invalid|DNS domain/i);
  });

  it("refuses non-loopback API and database bindings for this local deployment", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const base = {
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@db.example.test:5432/nombramientos_control",
    };
    expect(() => parseApiConfig(base)).toThrow(/loopback/i);
    expect(() => parseApiConfig({
      ...base,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
      API_HOST: "0.0.0.0",
    })).toThrow(/loopback/i);
  });

  it("validates an explicit trusted reverse-proxy allowlist and rejects wildcard trust", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const base = {
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
    };
    expect(parseApiConfig({
      ...base,
      API_TRUSTED_PROXY_CIDRS: "127.0.0.1/32,10.20.0.0/16,::1/128,127.0.0.1/32",
    }).trustedProxyCidrs).toEqual(["127.0.0.1/32", "10.20.0.0/16", "::1/128"]);

    for (const API_TRUSTED_PROXY_CIDRS of [
      "0.0.0.0/0",
      "::/0",
      "127.0.0.1/33",
      "::1/129",
      "127.0.0.1/032",
      "127.0.0.1,,::1",
      "loopback",
      "127.0.0.1:8080",
    ]) {
      expect(
        () => parseApiConfig({ ...base, API_TRUSTED_PROXY_CIDRS }),
        API_TRUSTED_PROXY_CIDRS,
      ).toThrow(/trusted proxy|TRUSTED_PROXY|IP\/CIDR|CIDR prefix/i);
    }
  });

  it("requires production to explicitly name its trusted reverse proxy", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const production = {
      NODE_ENV: "production",
      API_COOKIE_SECURE: "true",
      API_CORS_ORIGINS: "https://login.example.test",
      WEBAUTHN_RP_ID: "example.test",
      WEBAUTHN_EXPECTED_ORIGINS: "https://login.example.test",
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
      DATABASE_CONTROL_URL: "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control",
    };
    expect(() => parseApiConfig(production)).toThrow(/Production.*API_TRUSTED_PROXY_CIDRS/i);
    expect(parseApiConfig({
      ...production,
      API_TRUSTED_PROXY_CIDRS: "127.0.0.1/32",
    }).trustedProxyCidrs).toEqual(["127.0.0.1/32"]);
  });

  it("rejects PostgreSQL query precedence and non-canonical local aliases", () => {
    const key = Buffer.alloc(32, 7).toString("base64url");
    const prefix = {
      AUTH_ENCRYPTION_KEY_B64: key,
      DATABASE_SECRET_MASTER_KEY_B64: key,
    };
    const valid = "postgresql://nom_control:password@127.0.0.1:55432/nombramientos_control";
    for (const DATABASE_CONTROL_URL of [
      `${valid}?host=db.example.invalid`,
      `${valid}?port=5432`,
      `${valid}#host=db.example.invalid`,
      "postgresql://nom_control:password@localhost:55432/nombramientos_control",
      "postgresql://nom_control:password@[::1]:55432/nombramientos_control",
      "postgresql://nom_control:password@2130706433:55432/nombramientos_control",
      "postgresql://nom_control:password@127.0.0.1.:55432/nombramientos_control",
      "postgresql://nom_admin:password@127.0.0.1:55432/nombramientos_control",
      "postgresql://nom_control:password@127.0.0.1:55432/postgres",
      ` ${valid}`,
    ]) expect(() => parseApiConfig({ ...prefix, DATABASE_CONTROL_URL }), DATABASE_CONTROL_URL).toThrow(/exact protected/u);
  });
});
