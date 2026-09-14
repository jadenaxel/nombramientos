const WORKSPACE_ADMIN_AUTHORITY = "127.0.0.1:55432";

export function assertExactWorkspaceAdminUrl(value: string): string {
  const parsed = new URL(value);
  const schemeEnd = value.indexOf("://");
  const remainder = schemeEnd < 0 ? "" : value.slice(schemeEnd + 3);
  const authorityEnd = remainder.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? remainder : remainder.slice(0, authorityEnd);
  const userInfoEnd = authority.lastIndexOf("@");
  const userInfo = userInfoEnd < 0 ? "" : authority.slice(0, userInfoEnd);
  const passwordStart = userInfo.indexOf(":");
  const rawUsername = passwordStart < 0 ? userInfo : userInfo.slice(0, passwordStart);
  const rawPassword = passwordStart < 0 ? "" : userInfo.slice(passwordStart + 1);
  const hostPort = userInfoEnd < 0 ? authority : authority.slice(userInfoEnd + 1);

  if (
    value !== value.trim()
    || !["postgres:", "postgresql:"].includes(parsed.protocol)
    || hostPort !== WORKSPACE_ADMIN_AUTHORITY
    || parsed.hostname !== "127.0.0.1"
    || parsed.port !== "55432"
    || rawUsername !== "nom_admin"
    || parsed.username !== "nom_admin"
    || rawPassword.length < 1
    || parsed.password.length < 1
    || rawPassword.includes("@")
    || parsed.pathname !== "/postgres"
    || parsed.search !== ""
    || parsed.hash !== ""
  ) {
    throw new Error("Live API tests require the exact protected workspace administrator URL");
  }

  return parsed.toString();
}
