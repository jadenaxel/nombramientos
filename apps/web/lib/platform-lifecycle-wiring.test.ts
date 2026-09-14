import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

const webRoot = path.resolve(import.meta.dirname, "..");
const workspaceRoot = path.resolve(webRoot, "..", "..");
const platformSource = readFileSync(path.join(webRoot, "components", "nombramientos", "platform-console.tsx"), "utf8");
const apiSource = readFileSync(path.join(webRoot, "lib", "api.ts"), "utf8");
const migrationSource = readFileSync(path.join(workspaceRoot, "packages", "database", "migrations", "control", "009_tenant_lifecycle.sql"), "utf8");
const workerSource = readFileSync(path.join(workspaceRoot, "packages", "database", "scripts", "process-provisioning-jobs.ts"), "utf8");
const startSource = readFileSync(path.join(workspaceRoot, "scripts", "start-local.ps1"), "utf8");
const stopSource = readFileSync(path.join(workspaceRoot, "scripts", "stop-local.ps1"), "utf8");

test("la consola ES/EN/FR conecta exportación cifrada y baja reversible por permisos atómicos", () => {
  assert.match(platformSource, /title: message\("es", "screen\.platformConsole\.be30df8b7913"\)/u);
  assert.match(platformSource, /title: message\("en", "screen\.platformConsole\.be30df8b7913"\)/u);
  assert.match(platformSource, /title: message\("fr", "screen\.platformConsole\.be30df8b7913"\)/u);
  assert.deepEqual(
    ["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.platformConsole.be30df8b7913")),
    ["Exportación y baja protegida", "Protected export and decommission", "Exportation et retrait protégés"],
  );
  for (const permission of [
    "platform.tenant.export.request",
    "platform.tenant.export.download",
    "platform.tenant.decommission.schedule",
    "platform.tenant.decommission.cancel",
    "platform.tenant.reactivate",
  ]) assert.match(platformSource, new RegExp(permission.replaceAll(".", "\\."), "u"));
  assert.match(platformSource, /tenant\.latestExport\?\.state === "ready"/u);
  assert.match(platformSource, /tenant\.latestExport\.tenantVersion !== tenant\.version/u);
  assert.match(platformSource, /new Date\(tenant\.decommission\.retentionUntil\)\.getTime\(\) > query\.dataUpdatedAt/u);
  assert.match(platformSource, /reversible: message\("es", "screen\.platformConsole\.01ca9c32848c"\)/u);
  assert.match(getMessage("es", "screen.platformConsole.01ca9c32848c"), /No se ejecuta ningún borrado automático/u);
  assert.match(getMessage("en", "screen.platformConsole.01ca9c32848c"), /No automatic deletion is performed/u);
  assert.match(getMessage("fr", "screen.platformConsole.01ca9c32848c"), /Aucune suppression automatique n’est exécutée/u);
});

test("la reactivación reversible está localizada y obliga a un nuevo inicio de sesión", () => {
  assert.match(platformSource, /open: message\("es", "screen\.platformConsole\.39202ffa37b7"\), title: message\("es", "screen\.platformConsole\.172705dacc3f"\)/u);
  assert.deepEqual(
    ["es", "en", "fr"].map((locale) => getMessage(locale as "es" | "en" | "fr", "screen.platformConsole.172705dacc3f")),
    ["Reactivación protegida", "Protected reactivation", "Réactivation protégée"],
  );
  assert.match(platformSource, /tenant\.status === "suspended" && canReactivate/u);
  assert.match(platformSource, /<select id=\{`reactivate-\$\{tenant\.id\}`\}/u);
  assert.match(platformSource, /value="security_review_completed"/u);
  assert.match(platformSource, /value="operational_hold_resolved"/u);
  assert.match(platformSource, /value="institution_request_resumed"/u);
  assert.match(platformSource, /value="compliance_review_completed"/u);
  assert.match(platformSource, /api\.reactivatePlatformTenant\(tenant\.id, tenant\.version, reactivationReason\)/u);
  assert.match(apiSource, /\/reactivate/u);
  assert.match(apiSource, /sessionsCreated: 0/u);
  assert.equal(getMessage("en", "screen.platformConsole.eda5a7be86de"), "No session is recreated. Every user must sign in again.");
  assert.doesNotMatch(platformSource, /reactivationReason[^\n]*<Input/u);
});

test("el cliente obtiene autorización de un uso, descarga sólo ciphertext y revoca si falla", () => {
  assert.match(apiSource, /async function downloadBinary/u);
  assert.match(apiSource, /accept: "application\/vnd\.nombramientos\.tenant-backup\+aesgcm"/u);
  assert.match(apiSource, /credentials: "include",[\s\S]*cache: "no-store"/u);
  assert.match(apiSource, /x-csrf-token/u);
  assert.match(apiSource, /download-authorizations/u);
  assert.match(apiSource, /export-download-authorizations\/\$\{encodeURIComponent\(authorizationId\)\}\/revoke/u);
  assert.match(apiSource, /\/decommission\/\$\{encodeURIComponent\(decommissionId\)\}\/cancel/u);
  const authorize = platformSource.indexOf("await api.authorizeTenantExportDownload");
  const download = platformSource.indexOf("await api.downloadTenantExport", authorize);
  const revoke = platformSource.indexOf("await api.revokeTenantExportDownload", download);
  assert.ok(authorize >= 0 && download > authorize && revoke > download);
  assert.match(apiSource, /keyCustody: "platform-managed-not-exported"/u);
  assert.doesNotMatch(platformSource, /databasePassword|runtimeSecret|decryptExport|exportKey/u);
});

test("suspensión y baja sólo envían códigos normalizados, nunca texto libre", () => {
  assert.match(platformSource, /<select id=\{`suspend-\$\{tenant\.id\}`\}/u);
  assert.match(platformSource, /value="security_review"/u);
  assert.match(apiSource, /suspendPlatformTenant:[\s\S]*reasonCode:[\s\S]*JSON\.stringify\(\{ expectedVersion, reasonCode \}\)/u);
  assert.match(platformSource, /<select value=\{decommissionReason\}/u);
  assert.match(platformSource, /reasonCode: decommissionReason/u);
  assert.doesNotMatch(apiSource, /suspendPlatformTenant:[\s\S]{0,500}JSON\.stringify\(\{ expectedVersion, reason \}\)/u);
});

test("el lifecycle local ejecuta el worker real y la baja jamás borra automáticamente", () => {
  assert.match(workerSource, /"tenant-backup\.js"/u);
  assert.match(workerSource, /"--action", "backup"/u);
  assert.match(workerSource, /readBackupManifest/u);
  assert.match(workerSource, /hashFile/u);
  assert.match(workerSource, /keyCustody: "platform-managed-not-exported"/u);
  assert.match(startSource, /\$NomWorkerEntry/u);
  assert.match(startSource, /\$NomHealth\.worker\.healthy -eq \$true/u);
  assert.match(stopSource, /Name = 'provisioning worker'/u);
  assert.match(migrationSource, /status='decommission_pending'/u);
  assert.match(migrationSource, /retention_until>clock_timestamp\(\)/u);
  assert.doesNotMatch(migrationSource, /DELETE\s+FROM\s+tenants|DROP\s+DATABASE|DROP\s+ROLE|DROP\s+SCHEMA/iu);
  assert.doesNotMatch(workerSource, /DELETE\s+FROM\s+tenants|DROP\s+DATABASE|DROP\s+ROLE|DROP\s+SCHEMA/iu);
});
