const SAFE_CODE = /^[A-Z0-9_-]{1,64}$/u;

export function engineLaunchErrorLine(error, profile = process.env.USERPROFILE) {
  const rawFirstLine = error instanceof Error
    ? error.message.split(/\r?\n/u, 1)[0]
    : "Unknown engine launch error";
  return profile ? rawFirstLine.replaceAll(profile, "<profile>") : rawFirstLine;
}

export function classifyEngineLaunchError(error, platform = process.platform) {
  const explicitCode = typeof error === "object" && error !== null && "code" in error
    ? String(error.code).toUpperCase()
    : null;
  if (explicitCode && explicitCode !== "UNKNOWN" && SAFE_CODE.test(explicitCode)) {
    return explicitCode;
  }

  const firstLine = engineLaunchErrorLine(error, null);
  if (platform === "win32" && /\bspawn(?:Sync)? UNKNOWN$/u.test(firstLine)) {
    return "WINDOWS_NATIVE_SPAWN_UNKNOWN";
  }
  if (explicitCode && SAFE_CODE.test(explicitCode)) return explicitCode;
  return "ENGINE_LAUNCH_FAILED";
}
