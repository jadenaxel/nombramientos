import type { Locale } from "./api";

export const tenantNavigationSections = [
  "overview",
  "workflow",
  "session",
  "results",
  "members",
  "catalog",
  "committee",
  "organization",
  "reports",
  "access",
  "custody",
  "history",
] as const;

export type TenantNavigationSection = (typeof tenantNavigationSections)[number];

const contentKeySections = new Set<string>([
  "overview",
  "workflow",
  "session",
  "results",
  "members",
  "committee",
  "organization",
  "reports",
]);

type Capability = { all?: readonly string[]; any?: readonly string[] };

const capabilities: Record<string, Capability> = {
  overview: { all: ["aggregate.read"] },
  workflow: { all: ["cycle.manage"] },
  session: {
    any: ["aggregate.read", "proposal.submit", "ballot.submit", "proposal.open", "ballot.open", "proposal.close", "ballot.close"],
  },
  results: { all: ["aggregate.read"] },
  members: { all: ["member.read"] },
  catalog: {},
  committee: { all: ["member.read"] },
  organization: { all: ["organigram.read"] },
  reports: { all: ["report.read"] },
  access: { all: ["role.manage"] },
  // Every custody ceremony first loads the active round and its custody set.
  // Recount/publication are therefore additive abilities, not substitutes for
  // aggregate.read + tally.custody.
  custody: { all: ["aggregate.read", "tally.custody"] },
  history: { all: ["audit.read"] },
  settings: {},
  library: {},
  onboarding: { any: ["aggregate.read", "member.read", "cycle.manage"] },
  platform: { all: ["platform.operation.read"] },
};

export function canAccessAppSection(section: string, permissions: readonly string[]): boolean {
  const capability = capabilities[section];
  if (!capability) return false;
  const granted = new Set(permissions);
  return (capability.all?.every((permission) => granted.has(permission)) ?? true)
    && (capability.any?.some((permission) => granted.has(permission)) ?? true);
}

export function sectionRequiresContentKey(section: string): boolean {
  return contentKeySections.has(section);
}

const tenantLandingOrder = [
  "overview", "workflow", "session", "results", "members", "committee",
  "organization", "reports", "access", "custody", "history", "catalog",
  "settings", "library",
] as const;

export function firstAccessibleTenantSection(permissions: readonly string[]): string {
  return tenantLandingOrder.find((section) => canAccessAppSection(section, permissions)) ?? "catalog";
}

export function firstAccessibleAppSection(permissions: readonly string[]): string {
  return permissions.includes("platform.operation.read")
    ? "platform"
    : firstAccessibleTenantSection(permissions);
}

export function appLandingPath(locale: Locale, permissions: readonly string[], tenantOnly = false): string {
  const section = tenantOnly
    ? firstAccessibleTenantSection(permissions)
    : firstAccessibleAppSection(permissions);
  return `/${locale}/app/${section}`;
}
