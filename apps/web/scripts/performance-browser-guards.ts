export const EXACT_LOCAL_WEB_BASE_URL = "http://localhost:3000";
export const EXACT_PUBLIC_SIGN_IN_PATH = "/es/auth/sign-in";

export function assertExactLocalWebBaseUrl(value: string): string {
  if (value !== EXACT_LOCAL_WEB_BASE_URL && value !== `${EXACT_LOCAL_WEB_BASE_URL}/`) {
    throw new Error("The browser performance runner requires the exact local web origin http://localhost:3000");
  }

  const parsed = new URL(value);
  if (
    parsed.protocol !== "http:"
    || parsed.hostname !== "localhost"
    || parsed.port !== "3000"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.pathname !== "/"
    || parsed.search !== ""
    || parsed.hash !== ""
    || parsed.origin !== EXACT_LOCAL_WEB_BASE_URL
  ) {
    throw new Error("The browser performance runner requires the exact local web origin http://localhost:3000");
  }

  return EXACT_LOCAL_WEB_BASE_URL;
}

export function isExactPublicSignInUrl(value: string, webBaseUrl: string): boolean {
  const origin = assertExactLocalWebBaseUrl(webBaseUrl);
  if (value !== `${origin}${EXACT_PUBLIC_SIGN_IN_PATH}`) return false;
  try {
    const parsed = new URL(value);
    return parsed.origin === origin
      && parsed.pathname === EXACT_PUBLIC_SIGN_IN_PATH
      && parsed.username === ""
      && parsed.password === ""
      && parsed.search === ""
      && parsed.hash === "";
  } catch {
    return false;
  }
}
