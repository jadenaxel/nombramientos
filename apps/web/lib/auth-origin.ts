export type PreAuthOriginContext = Readonly<{
  hostname: string;
  port: string;
  protocol: string;
  pathname: string;
  search: string;
  hash: string;
  automated?: boolean;
}>;

export type PreAuthOriginDecision = Readonly<{
  eligible: boolean;
  canonicalUrl?: string;
}>;

/**
 * Local WebAuthn is registered to `localhost`, so accepting credentials on a
 * host-only 127.0.0.1/::1 cookie would strand the new session when the user
 * moves to the canonical passkey origin. Gate only the human-facing operational
 * port before any secret is entered. Isolated browser automation remains able
 * to exercise its explicit 127.0.0.1 QA boundary; this is a UX guard, never an
 * authentication or authorization boundary.
 */
export function evaluatePreAuthOrigin({
  hostname,
  port,
  protocol,
  pathname,
  search,
  hash,
  automated = false,
}: PreAuthOriginContext): PreAuthOriginDecision {
  const loopbackIp = hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  if (automated || !loopbackIp || port !== "3000") return { eligible: true };
  const canonicalProtocol = protocol === "https:" ? "https:" : "http:";
  return {
    eligible: false,
    canonicalUrl: `${canonicalProtocol}//localhost:3000${pathname}${search}${hash}`,
  };
}

export function currentPreAuthOriginDecision(): PreAuthOriginDecision {
  if (typeof window === "undefined") return { eligible: false };
  const { hostname, port, protocol, pathname, search, hash } = window.location;
  return evaluatePreAuthOrigin({
    hostname,
    port,
    protocol,
    pathname,
    search,
    hash,
    automated: navigator.webdriver === true,
  });
}

/** A primitive snapshot suitable for React's external-store hydration API. */
export function currentPreAuthOriginGateUrl(): string {
  const decision = currentPreAuthOriginDecision();
  return decision.eligible ? "" : decision.canonicalUrl ?? "about:blank";
}
