import { describe, expect, it } from "vitest";
import {
  openWebAuthnCeremonyCookie,
  sealWebAuthnCeremonyCookie,
  webAuthnCeremonyCookieName,
  webAuthnCeremonyCookiePath,
} from "../src/modules/webauthn-ceremony-cookie.js";

const ceremonyId = "50000000-0000-4000-8000-000000000001";
const ceremonyToken = "c".repeat(43);
const encryptionKey = Buffer.alloc(32, 7);
const now = Date.parse("2026-09-14T12:00:00.000Z");
const CONSERVATIVE_COOKIE_HEADER_BUDGET_BYTES = 6 * 1_024;
// Session + CSRF currently need well below 256 bytes. Reserve 1 KiB so this
// contract remains safe as their attributes or token representation evolve.
const SESSION_AND_CSRF_COOKIE_MARGIN_BYTES = 1_024;

describe("WebAuthn ceremony cookie envelope", () => {
  it("round-trips only for the exact ceremony id, type, key, and unexpired lifetime", () => {
    const value = sealWebAuthnCeremonyCookie({
      ceremonyId,
      ceremonyType: "authentication",
      ceremonyToken,
      expiresAt: new Date(now + 60_000),
      encryptionKey,
    });

    expect(value).toHaveLength(95);
    expect(value).not.toContain(ceremonyToken);
    expect(value).not.toContain(ceremonyId);
    expect(webAuthnCeremonyCookieName(ceremonyId)).toBe("nom_webauthn_50000000000040008000000000000001");
    expect(webAuthnCeremonyCookiePath()).toBe("/v1/auth/passkeys");
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId,
      ceremonyType: "authentication",
      encryptionKey,
      now,
    })).toBe(ceremonyToken);
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId,
      ceremonyType: "step_up",
      encryptionKey,
      now,
    })).toBeUndefined();
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId: "50000000-0000-4000-8000-000000000002",
      ceremonyType: "authentication",
      encryptionKey,
      now,
    })).toBeUndefined();
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId,
      ceremonyType: "authentication",
      encryptionKey,
      now: now + 60_000,
    })).toBeUndefined();
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId,
      ceremonyType: "authentication",
      encryptionKey,
      now: Number.NaN,
    })).toBeUndefined();
  });

  it("fails closed for tampering, substitution, malformed encoding, and a different key", () => {
    const value = sealWebAuthnCeremonyCookie({
      ceremonyId,
      ceremonyType: "registration",
      ceremonyToken,
      expiresAt: new Date(now + 60_000),
      encryptionKey,
    });
    const tampered = `${value.slice(0, -1)}${value.endsWith("A") ? "B" : "A"}`;

    for (const candidate of [tampered, "v1.invalid.invalid", "x".repeat(1_025)]) {
      expect(openWebAuthnCeremonyCookie({
        value: candidate,
        ceremonyId,
        ceremonyType: "registration",
        encryptionKey,
        now,
      })).toBeUndefined();
    }
    expect(openWebAuthnCeremonyCookie({
      value,
      ceremonyId,
      ceremonyType: "registration",
      encryptionKey: Buffer.alloc(32, 8),
      now,
    })).toBeUndefined();
  });

  it("rejects non-canonical token material and invalid expiry before encryption", () => {
    expect(() => sealWebAuthnCeremonyCookie({
      ceremonyId,
      ceremonyType: "authentication",
      ceremonyToken: "a".repeat(43),
      expiresAt: new Date(now + 60_000),
      encryptionKey,
    })).toThrow(/token is invalid/u);
    expect(() => sealWebAuthnCeremonyCookie({
      ceremonyId,
      ceremonyType: "authentication",
      ceremonyToken,
      expiresAt: new Date(-1),
      encryptionKey,
    })).toThrow(/expiry is invalid/u);
  });

  it("keeps all 26 independently correlated maximum-overlap cookies below a conservative header budget", () => {
    const ceremonyTypes = [
      ...Array.from({ length: 12 }, () => "authentication" as const),
      ...Array.from({ length: 8 }, () => "step_up" as const),
      ...Array.from({ length: 6 }, () => "registration" as const),
    ];
    const cookiePairs = ceremonyTypes.map((ceremonyType, index) => {
      const id = `50000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
      const token = Buffer.alloc(32, index + 1).toString("base64url");
      const value = sealWebAuthnCeremonyCookie({
        ceremonyId: id,
        ceremonyType,
        ceremonyToken: token,
        expiresAt: new Date(now + 10 * 60_000),
        encryptionKey,
      });
      return `${webAuthnCeremonyCookieName(id)}=${value}`;
    });
    const ceremonyCookieHeaderBytes = Buffer.byteLength(`Cookie: ${cookiePairs.join("; ")}\r\n`, "ascii");
    const budgetedHeaderBytes = ceremonyCookieHeaderBytes + SESSION_AND_CSRF_COOKIE_MARGIN_BYTES;

    expect(cookiePairs).toHaveLength(26);
    expect(new Set(cookiePairs.map((pair) => pair.slice(0, pair.indexOf("=")))).size).toBe(26);
    expect(budgetedHeaderBytes).toBeLessThan(CONSERVATIVE_COOKIE_HEADER_BUDGET_BYTES);
  });
});
