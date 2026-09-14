import { NextResponse, type NextRequest } from "next/server.js";

const CANONICAL_LOCAL_ORIGIN_BY_AUTHORITY: ReadonlyMap<string, string> = new Map([
  ["127.0.0.1:3000", "http://localhost:3000"],
  ["[::1]:3000", "http://localhost:3000"],
  ["127.0.0.1:3300", "http://localhost:3300"],
  ["[::1]:3300", "http://localhost:3300"],
  ["127.0.0.1:3301", "http://localhost:3301"],
  ["[::1]:3301", "http://localhost:3301"],
] as const);

export function proxy(request: NextRequest) {
  const canonicalRedirect = canonicalLocalRedirect(request);
  if (canonicalRedirect) {
    const response = NextResponse.redirect(canonicalRedirect, 307);
    response.headers.set("Cache-Control", "no-store");
    response.headers.delete("Set-Cookie");
    return response;
  }

  const locale = request.nextUrl.pathname.match(/^\/(es|en|fr)(?:\/|$)/)?.[1] ?? "es";
  const nonce = btoa(crypto.randomUUID());
  const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL;
  const apiOrigins = configuredApiUrl
    ? [new URL(configuredApiUrl).origin]
    : ["http://localhost:4000"];
  const scriptPolicy = process.env.NODE_ENV === "development"
    ? `'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval'`
    : `'nonce-${nonce}' 'strict-dynamic'`;
  const csp = [
    "default-src 'self'", "base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'",
    "img-src 'self' data: blob:", "font-src 'self' data:", "style-src 'self' 'unsafe-inline'",
    `script-src 'self' ${scriptPolicy}`,
    `connect-src 'self' ${apiOrigins.join(" ")} ws://localhost:3000`,
    "worker-src 'self' blob:",
  ].join("; ");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nombramientos-locale", locale);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Language", locale);
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

/**
 * Canonicalizes the human-facing local workspace before any authentication UI
 * renders. The destination authority is a fixed application constant: neither
 * Host nor any forwarding header can select a redirect destination. Arbitrary
 * ephemeral QA ports remain outside this finite operational-port boundary.
 */
export function canonicalLocalRedirect(request: Pick<NextRequest, "headers" | "nextUrl">): URL | undefined {
  if (request.nextUrl.pathname === "/healthz") return undefined;
  const authority = request.headers.get("host")?.toLowerCase();
  if (!authority) return undefined;
  const canonicalOrigin = CANONICAL_LOCAL_ORIGIN_BY_AUTHORITY.get(authority);
  if (!canonicalOrigin) return undefined;

  const destination = new URL(canonicalOrigin);
  destination.pathname = request.nextUrl.pathname;
  destination.search = request.nextUrl.search;
  return destination;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.svg).*)"],
};
