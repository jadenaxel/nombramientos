import { resolveLocalQaOrigins } from "../../scripts/local-qa-boundary.ts";

const apiOrigin = resolveLocalQaOrigins().apiOrigin;

export function localQaApiRoute(pathname: string | RegExp): (url: URL) => boolean {
  if (typeof pathname === "string" && !pathname.startsWith("/v1/")) {
    throw new Error("A local QA API route must use an absolute v1 pathname");
  }
  if (pathname instanceof RegExp && (pathname.global || pathname.sticky)) {
    throw new Error("A local QA API route pattern must be stateless");
  }
  return (url) => url.origin === apiOrigin && (
    typeof pathname === "string" ? url.pathname === pathname : pathname.test(url.pathname)
  );
}
