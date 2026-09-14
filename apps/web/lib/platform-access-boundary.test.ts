import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const shellSource = readFileSync(path.join(webRoot, "components/nombramientos/app-shell.tsx"), "utf8");
const switcherSource = readFileSync(path.join(webRoot, "components/nombramientos/tenant-switcher.tsx"), "utf8");
const platformSource = readFileSync(path.join(webRoot, "components/nombramientos/platform-console.tsx"), "utf8");
const bootstrapSource = readFileSync(path.join(webRoot, "components/nombramientos/platform-bootstrap-form.tsx"), "utf8");
const apiSource = readFileSync(path.join(webRoot, "lib/api.ts"), "utf8");

test("el plano global se monta sólo después de bloquear el vault y purgar datos tenant", () => {
  assert.match(shellSource, /function PlatformIsolationBoundary/);
  assert.match(shellSource, /key=\{platformMode \? "platform" : "tenant"\}/);
  assert.match(shellSource, /useState\(!platformMode\)/);
  assert.match(shellSource, /if \(!platformMode\) \{\s*return;/);
  const lock = shellSource.indexOf("lockVault();");
  const cancel = shellSource.indexOf("await queryClient.cancelQueries();", lock);
  const purge = shellSource.indexOf("queryClient.removeQueries", cancel);
  const ready = shellSource.indexOf("setReady(true)", purge);
  assert.ok(lock >= 0 && cancel > lock && purge > cancel && ready > purge, "lock, cancellation and purge must precede rendering");
  assert.match(shellSource, /query\.queryKey\[0\] !== "session"/);
  assert.match(shellSource, /query\.queryKey\[0\] !== "platform-tenants"/);
  assert.match(shellSource, /if \(!ready\)/);
});

test("el cambio de iglesia destruye el contexto local después de rotar la sesión", () => {
  const rotate = switcherSource.indexOf("await api.switchTenant(tenantId)");
  const lock = switcherSource.indexOf("vault.lock();", rotate);
  const csrf = switcherSource.indexOf("setCsrfToken(undefined);", lock);
  const clear = switcherSource.indexOf("queryClient.clear();", csrf);
  const navigate = switcherSource.indexOf("router.replace", clear);
  assert.ok(rotate >= 0 && lock > rotate && csrf > lock && clear > csrf && navigate > clear);
  assert.match(apiSource, /"\/v1\/memberships"/);
  assert.match(apiSource, /"\/v1\/session\/switch-tenant"/);
});

test("la consola global conecta activación pendiente e invitación inicial de un solo uso", () => {
  assert.match(platformSource, /initialAdminMode/);
  assert.match(platformSource, /mode: "pending"/);
  assert.match(platformSource, /mode: "invitation"/);
  assert.match(platformSource, /acceptanceToken/);
  assert.match(platformSource, /tokenBody/);
  assert.doesNotMatch(platformSource, /localStorage|sessionStorage|console\./);
  assert.match(apiSource, /"\/v1\/platform\/tenants\/provisioning"/);
  assert.match(apiSource, /initial-admin-invitation/);
});

test("suspensión y portapapeles respetan permiso y fallo observable", () => {
  assert.match(platformSource, /const canSuspend = permissions\.includes\("platform\.tenant\.suspend"\)/);
  assert.match(platformSource, /tenant\.status === "active" && canSuspend/);
  assert.match(platformSource, /catch \{\s*setCopiedToken\(false\);\s*setClipboardError/);
  assert.match(platformSource, /query\.isError/);
});

test("el bootstrap global usa body, limpia secretos del formulario y conduce a MFA obligatorio", () => {
  assert.match(bootstrapSource, /"\/v1\/auth\/platform-bootstrap\/accept"/);
  assert.match(bootstrapSource, /setPassword\(""\)/);
  assert.match(bootstrapSource, /setToken\(""\)/);
  assert.match(bootstrapSource, /queryClient\.clear\(\)/);
  assert.match(bootstrapSource, /setCsrfToken\(session\.csrfToken\)/);
  assert.match(bootstrapSource, /app\/settings/);
  assert.doesNotMatch(bootstrapSource, /URLSearchParams|searchParams|localStorage|sessionStorage|console\./);
});
