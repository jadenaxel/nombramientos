const LOCAL_QA_TARGETS = {
  workspace: {
    webOrigin: "http://localhost:3000",
    apiOrigin: "http://localhost:4000",
  },
  "container-test": {
    webOrigin: "http://localhost:3301",
    apiOrigin: "http://localhost:4401",
  },
} as const;

export type LocalQaTarget = keyof typeof LOCAL_QA_TARGETS;

export interface LocalQaOrigins {
  readonly target: LocalQaTarget;
  readonly webOrigin: string;
  readonly apiOrigin: string;
}

export function resolveLocalQaOrigins(
  source: Readonly<Record<string, string | undefined>> = process.env,
): LocalQaOrigins {
  const target = source["NOMBRAMIENTOS_E2E_TARGET"] ?? "workspace";
  if (!Object.hasOwn(LOCAL_QA_TARGETS, target)) {
    throw new Error("NOMBRAMIENTOS_E2E_TARGET must be workspace or container-test");
  }

  const selected = LOCAL_QA_TARGETS[target as LocalQaTarget];
  return {
    target: target as LocalQaTarget,
    webOrigin: assertExactOrigin(source["WEB_BASE_URL"] ?? selected.webOrigin, selected.webOrigin, "WEB_BASE_URL"),
    apiOrigin: assertExactOrigin(
      source["NEXT_PUBLIC_API_URL"] ?? selected.apiOrigin,
      selected.apiOrigin,
      "NEXT_PUBLIC_API_URL",
    ),
  };
}

export function assertConfiguredLocalQaWebOrigin(value: string): string {
  const selected = resolveLocalQaOrigins();
  return assertExactOrigin(value, selected.webOrigin, "Playwright baseURL");
}

export function assertExactRealStackOrigin(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid isolated loopback HTTP origin`);
  }
  const schemeEnd = value.indexOf("://");
  const remainder = schemeEnd < 0 ? "" : value.slice(schemeEnd + 3);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  const port = Number(parsed.port);
  if (
    value !== value.trim()
    || parsed.protocol !== "http:"
    || authority !== `localhost:${parsed.port}`
    || parsed.hostname !== "localhost"
    || parsed.host !== authority
    || parsed.origin !== value
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
    || !Number.isInteger(port)
    || port < 1
    || port > 65_535
    || [3_000, 4_000, 55_432].includes(port)
  ) {
    throw new Error(`${label} must be an exact isolated localhost HTTP origin`);
  }
  return parsed.origin;
}

function assertExactOrigin(value: string, expected: string, label: string): string {
  if (value !== expected && value !== `${expected}/`) {
    throw new Error(`${label} does not match the selected local QA target`);
  }
  const parsed = new URL(value);
  if (
    parsed.protocol !== "http:"
    || parsed.hostname !== "localhost"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.origin !== expected
  ) {
    throw new Error(`${label} must be an exact credential-free localhost HTTP origin`);
  }
  return expected;
}
