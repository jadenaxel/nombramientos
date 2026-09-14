import { describe, expect, it } from "vitest";
import {
  accessProfile,
  buildDemoAccessFileV2,
  demoAccessPublicManifest,
  DEMO_ACCESS_PROFILE_CODES,
  DEMO_ACCESS_PROFILE_DEFINITIONS,
  DEMO_ACCESS_TENANT_ID,
  parseDemoAccessFile,
  type DemoAccessProfileCode,
} from "../src/demo-access.js";

function credential(index: number) {
  return {
    password: `independent-demo-password-${index}-safe`,
    totpEnrollmentUri: `otpauth://totp/Nombramientos:profile-${index}?secret=${"A".repeat(24)}${index}&issuer=Nombramientos`,
  };
}

function credentials() {
  return Object.fromEntries(DEMO_ACCESS_PROFILE_CODES.map((code, index) => [
    code,
    credential(index),
  ])) as Record<DemoAccessProfileCode, ReturnType<typeof credential>>;
}

describe("protected Demo access-file contract", () => {
  it("keeps version-1 administrator readers compatible while exposing five independent profiles", () => {
    const access = buildDemoAccessFileV2(credentials());
    const parsed = parseDemoAccessFile(JSON.parse(JSON.stringify(access)));

    expect(parsed.version).toBe(2);
    if (parsed.version !== 2) throw new Error("Expected the multi-profile access format");
    expect(parsed).toMatchObject({
      tenantId: DEMO_ACCESS_TENANT_ID,
      defaultProfile: "administrator",
      email: parsed.profiles.administrator.email,
      password: parsed.profiles.administrator.password,
      totpEnrollmentUri: parsed.profiles.administrator.totpEnrollmentUri,
    });
    expect(Object.keys(parsed.profiles)).toEqual(DEMO_ACCESS_PROFILE_CODES);
    expect(new Set(Object.values(parsed.profiles).map(({ password }) => password)).size).toBe(5);
    expect(new Set(Object.values(parsed.profiles).map(({ totpEnrollmentUri }) =>
      new URL(totpEnrollmentUri).searchParams.get("secret"))).size).toBe(5);
  });

  it("upgrades a legacy file in memory only for its administrator profile", () => {
    const legacy = parseDemoAccessFile({
      version: 1,
      email: DEMO_ACCESS_PROFILE_DEFINITIONS.administrator.email,
      password: "legacy-administrator-password-safe",
      totpEnrollmentUri: `otpauth://totp/Nombramientos:admin?secret=${"B".repeat(32)}`,
    });

    expect(accessProfile(legacy, "administrator")).toMatchObject({
      identityId: DEMO_ACCESS_PROFILE_DEFINITIONS.administrator.identityId,
      password: "legacy-administrator-password-safe",
    });
    expect(accessProfile(legacy, "auditor")).toBeNull();
  });

  it("fixes least-privilege role separation and withholds the general content key from custody", () => {
    expect(DEMO_ACCESS_PROFILE_DEFINITIONS).toMatchObject({
      administrator: { roleCodes: ["CHURCH_ADMIN", "COMMITTEE_MEMBER"], tenantContentKey: true },
      secretary: { roleCodes: ["COMMITTEE_SECRETARY"], tenantContentKey: true },
      committee: { roleCodes: ["COMMITTEE_MEMBER"], tenantContentKey: true },
      custodian: { roleCodes: ["TALLY_CUSTODIAN"], tenantContentKey: false },
      auditor: { roleCodes: ["AUDITOR"], tenantContentKey: true },
    });
    const identities = Object.values(DEMO_ACCESS_PROFILE_DEFINITIONS).map(({ identityId }) => identityId);
    const emails = Object.values(DEMO_ACCESS_PROFILE_DEFINITIONS).map(({ email }) => email);
    expect(new Set(identities).size).toBe(5);
    expect(new Set(emails).size).toBe(5);
  });

  it("never includes passwords, TOTP material or email addresses in the non-secret manifest", () => {
    const manifest = demoAccessPublicManifest();
    const serialized = JSON.stringify(manifest);
    expect(serialized).not.toMatch(/password|totpEnrollmentUri|@nombramientos\.local/i);
    expect(manifest).toHaveLength(5);
    for (const item of manifest) {
      expect(Object.keys(item).sort()).toEqual(["identityId", "profile", "roleCodes", "tenantContentKey"]);
    }
  });

  it("rejects alias drift, altered role metadata and shared authenticators", () => {
    const access = buildDemoAccessFileV2(credentials());
    expect(() => parseDemoAccessFile({ ...access, email: "different@nombramientos.local" })).toThrow();
    expect(() => parseDemoAccessFile({
      ...access,
      profiles: {
        ...access.profiles,
        auditor: { ...access.profiles.auditor, roleCodes: ["CHURCH_ADMIN"] },
      },
    })).toThrow();
    expect(() => parseDemoAccessFile({
      ...access,
      profiles: {
        ...access.profiles,
        auditor: {
          ...access.profiles.auditor,
          password: access.profiles.committee.password,
          totpEnrollmentUri: access.profiles.committee.totpEnrollmentUri,
        },
      },
    })).toThrow();
  });
});
