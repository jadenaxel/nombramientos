import { z } from "zod";

export const DEMO_ACCESS_TENANT_ID = "d0000000-0000-4000-8000-000000000001";
export const DEMO_ACCESS_PROFILE_CODES = [
  "administrator",
  "secretary",
  "committee",
  "custodian",
  "auditor",
] as const;

export type DemoAccessProfileCode = (typeof DEMO_ACCESS_PROFILE_CODES)[number];
export type DemoAccessRoleCode =
  | "CHURCH_ADMIN"
  | "COMMITTEE_SECRETARY"
  | "COMMITTEE_MEMBER"
  | "TALLY_CUSTODIAN"
  | "AUDITOR";

export interface DemoAccessProfileDefinition {
  readonly identityId: string;
  readonly email: string;
  readonly displayName: string;
  readonly roleCodes: readonly DemoAccessRoleCode[];
  readonly tenantContentKey: boolean;
}

export const DEMO_ACCESS_PROFILE_DEFINITIONS: Readonly<
  Record<DemoAccessProfileCode, DemoAccessProfileDefinition>
> = Object.freeze({
  administrator: Object.freeze({
    identityId: "d1000000-0000-4000-8000-000000000001",
    email: "admin.demo@nombramientos.local",
    displayName: "Administración Demo",
    // The additional committee role is explicit: this synthetic identity is
    // already part of the frozen active electorate. CHURCH_ADMIN alone still
    // does not confer proposal or ballot submission rights.
    roleCodes: Object.freeze(["CHURCH_ADMIN", "COMMITTEE_MEMBER"] as const),
    tenantContentKey: true,
  }),
  secretary: Object.freeze({
    // This is the identity already used by E02 in the deterministic committee.
    identityId: "055dc27e-6ddb-4d42-88d7-4d2cbc142f28",
    email: "secretaria.demo@nombramientos.local",
    displayName: "Secretaría Demo",
    roleCodes: Object.freeze(["COMMITTEE_SECRETARY"] as const),
    tenantContentKey: true,
  }),
  committee: Object.freeze({
    // This is the identity already used by E03 in the deterministic committee.
    identityId: "91ed9c79-6ff0-419a-8930-88ddff84b455",
    email: "comision.demo@nombramientos.local",
    displayName: "Integrante Demo",
    roleCodes: Object.freeze(["COMMITTEE_MEMBER"] as const),
    tenantContentKey: true,
  }),
  custodian: Object.freeze({
    identityId: "bc3ff7ff-2e7e-4152-8034-bd6d84139199",
    email: "custodio.demo@nombramientos.local",
    displayName: "Custodia Demo",
    roleCodes: Object.freeze(["TALLY_CUSTODIAN"] as const),
    // Tally custody uses its own per-device private keys. The RBAC role must
    // not silently become a recipient of the general tenant content key.
    tenantContentKey: false,
  }),
  auditor: Object.freeze({
    identityId: "9f666276-d66a-4bc0-8bc4-e8cb988d8ec7",
    email: "auditor.demo@nombramientos.local",
    displayName: "Auditoría Demo",
    roleCodes: Object.freeze(["AUDITOR"] as const),
    tenantContentKey: true,
  }),
});

const password = z.string().min(16).max(1_024);
const enrollmentUri = z.string().refine((value) => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "otpauth:" && parsed.searchParams.has("secret");
  } catch {
    return false;
  }
}, "A Demo TOTP enrollment URI is required");
const roleCode = z.enum([
  "CHURCH_ADMIN",
  "COMMITTEE_SECRETARY",
  "COMMITTEE_MEMBER",
  "TALLY_CUSTODIAN",
  "AUDITOR",
]);

const legacyAccessSchema = z.object({
  version: z.literal(1),
  email: z.string().email(),
  password,
  totpEnrollmentUri: enrollmentUri,
}).strict();

const profileSchema = z.object({
  identityId: z.string().uuid(),
  email: z.string().email(),
  displayName: z.string().min(2).max(120),
  roleCodes: z.array(roleCode).min(1).max(3),
  tenantContentKey: z.boolean(),
  password,
  totpEnrollmentUri: enrollmentUri,
}).strict();

const accessV2Schema = z.object({
  version: z.literal(2),
  tenantId: z.literal(DEMO_ACCESS_TENANT_ID),
  defaultProfile: z.literal("administrator"),
  // These aliases deliberately preserve all version-1 readers while the
  // profiles map becomes the authoritative multi-profile representation.
  email: z.string().email(),
  password,
  totpEnrollmentUri: enrollmentUri,
  profiles: z.object({
    administrator: profileSchema,
    secretary: profileSchema,
    committee: profileSchema,
    custodian: profileSchema,
    auditor: profileSchema,
  }).strict(),
}).strict().superRefine((value, context) => {
  const administrator = value.profiles.administrator;
  if (
    value.email !== administrator.email
    || value.password !== administrator.password
    || value.totpEnrollmentUri !== administrator.totpEnrollmentUri
  ) {
    context.addIssue({ code: "custom", message: "Legacy aliases must match the administrator profile" });
  }
  const passwords = new Set<string>();
  const totpSecrets = new Set<string>();
  for (const code of DEMO_ACCESS_PROFILE_CODES) {
    const profile = value.profiles[code];
    const definition = DEMO_ACCESS_PROFILE_DEFINITIONS[code];
    if (
      profile.identityId !== definition.identityId
      || profile.email !== definition.email
      || profile.displayName !== definition.displayName
      || profile.tenantContentKey !== definition.tenantContentKey
      || JSON.stringify(profile.roleCodes) !== JSON.stringify(definition.roleCodes)
    ) {
      context.addIssue({ code: "custom", path: ["profiles", code], message: "Demo profile metadata does not match its fixed definition" });
    }
    if (passwords.has(profile.password)) {
      context.addIssue({ code: "custom", path: ["profiles", code, "password"], message: "Demo profiles require independent passwords" });
    }
    passwords.add(profile.password);
    const secret = new URL(profile.totpEnrollmentUri).searchParams.get("secret")!;
    if (totpSecrets.has(secret)) {
      context.addIssue({ code: "custom", path: ["profiles", code, "totpEnrollmentUri"], message: "Demo profiles require independent TOTP secrets" });
    }
    totpSecrets.add(secret);
  }
});

export type LegacyDemoAccessFile = z.infer<typeof legacyAccessSchema>;
export type DemoAccessProfile = z.infer<typeof profileSchema>;
export type DemoAccessFileV2 = z.infer<typeof accessV2Schema>;
export type DemoAccessFile = LegacyDemoAccessFile | DemoAccessFileV2;

export function parseDemoAccessFile(value: unknown): DemoAccessFile {
  const version = typeof value === "object" && value !== null && "version" in value
    ? value.version
    : undefined;
  return version === 1 ? legacyAccessSchema.parse(value) : accessV2Schema.parse(value);
}

export function buildDemoAccessFileV2(
  credentials: Readonly<Record<DemoAccessProfileCode, {
    readonly password: string;
    readonly totpEnrollmentUri: string;
  }>>,
): DemoAccessFileV2 {
  const profiles = Object.fromEntries(DEMO_ACCESS_PROFILE_CODES.map((code) => [code, {
    ...DEMO_ACCESS_PROFILE_DEFINITIONS[code],
    ...credentials[code],
  }])) as unknown as DemoAccessFileV2["profiles"];
  const administrator = profiles.administrator;
  return accessV2Schema.parse({
    version: 2,
    tenantId: DEMO_ACCESS_TENANT_ID,
    defaultProfile: "administrator",
    email: administrator.email,
    password: administrator.password,
    totpEnrollmentUri: administrator.totpEnrollmentUri,
    profiles,
  });
}

export function accessProfile(
  access: DemoAccessFile,
  code: DemoAccessProfileCode,
): DemoAccessProfile | null {
  if (access.version === 2) return access.profiles[code];
  if (code !== "administrator") return null;
  const definition = DEMO_ACCESS_PROFILE_DEFINITIONS.administrator;
  return profileSchema.parse({
    ...definition,
    email: access.email,
    password: access.password,
    totpEnrollmentUri: access.totpEnrollmentUri,
  });
}

export function demoAccessPublicManifest(): readonly Readonly<{
  profile: DemoAccessProfileCode;
  identityId: string;
  roleCodes: readonly DemoAccessRoleCode[];
  tenantContentKey: boolean;
}>[] {
  return DEMO_ACCESS_PROFILE_CODES.map((profile) => {
    const definition = DEMO_ACCESS_PROFILE_DEFINITIONS[profile];
    return Object.freeze({
      profile,
      identityId: definition.identityId,
      roleCodes: definition.roleCodes,
      tenantContentKey: definition.tenantContentKey,
    });
  });
}
