import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const workspaceRoot = path.resolve(webRoot, "..", "..");
const specSource = readFileSync(path.join(webRoot, "e2e", "real-stack-closure.spec.ts"), "utf8");
const passkeySpecSource = readFileSync(path.join(webRoot, "e2e", "real-stack-passkey.spec.ts"), "utf8");
const configSource = readFileSync(path.join(webRoot, "playwright.real-stack.config.ts"), "utf8");
const generalConfigSource = readFileSync(path.join(webRoot, "playwright.config.ts"), "utf8");
const localQaBoundarySource = readFileSync(path.join(webRoot, "scripts", "local-qa-boundary.ts"), "utf8");
const runnerSource = readFileSync(path.join(workspaceRoot, "apps", "api", "scripts", "real-browser-stack-local.ts"), "utf8");
const guardSource = readFileSync(path.join(workspaceRoot, "apps", "api", "scripts", "real-browser-stack-guards.ts"), "utf8");
const apiPackage = JSON.parse(readFileSync(path.join(workspaceRoot, "apps", "api", "package.json"), "utf8")) as {
  readonly scripts?: Readonly<Record<string, string>>;
};
const workspacePackage = JSON.parse(readFileSync(path.join(workspaceRoot, "package.json"), "utf8")) as {
  readonly scripts?: Readonly<Record<string, string>>;
};

test("el cierre real usa navegador, Fastify y stores PostgreSQL sin fulfill ni rutas interceptadas", () => {
  assert.match(specSource, /page\.evaluate\(async/u);
  assert.match(specSource, /await fetch\(`/u);
  assert.doesNotMatch(specSource, /page\.route|route\.fulfill|page\.request/u);
  assert.match(runnerSource, /new DatabaseRuntime\(/u);
  assert.match(runnerSource, /new TenantProvisioner\(/u);
  assert.match(runnerSource, /await buildServer\(/u);
  assert.match(runnerSource, /listen\(\{ host: "127\.0\.0\.1", port: 0 \}\)/u);
  assert.match(runnerSource, /mechanism: "church_election"/u);
  assert.match(runnerSource, /spawn\(process\.execPath/u);
  assert.match(runnerSource, /"@playwright", "test", "cli\.js"/u);
  assert.match(runnerSource, /shell: false/u);
});

test("importación, homónimo, reintentos, abstención, acuse y escrutinio pasan por endpoints decisivos reales", () => {
  for (const endpoint of [
    "/v1/members/import/preview",
    "/v1/members/import/commit",
    "/submissions`",
    "/submissions/me`",
    "/custody/freeze`",
    "/custody/manifest`",
    "/custody/attestations`",
    "/custody/publication`",
    "/custody/aggregate`",
  ]) assert.ok(specSource.includes(endpoint), `falta endpoint real ${endpoint}`);
  assert.match(specSource, /matchBasis: "normalized_name"/u);
  assert.match(specSource, /expect\(responseData\(previewRetry\)\)\.toEqual\(previewData\)/u);
  assert.match(specSource, /expect\(responseData\(commitRetry\)\)\.toEqual\(commitData\)/u);
  assert.match(specSource, /abstain: true/u);
  assert.match(specSource, /createTallyAggregate/u);
  assert.match(specSource, /signTallyAttestation/u);
});

test("PDF, XLSX y CSV usan el generador productivo, E2EE, persistencia y descarga real del navegador en el tenant efímero", () => {
  for (const endpoint of [
    "/v1/reports/workflow-snapshot",
    "/v1/reports/generate",
    "/complete`",
    "/artifact`",
    "/v1/reports?limit=30",
    "/v1/audit",
  ]) assert.ok(specSource.includes(endpoint), `falta endpoint real de reportes ${endpoint}`);
  assert.match(specSource, /import \{ buildLocalArtifact \} from "\.\.\/lib\/report-export\.ts"/u);
  assert.match(specSource, /encryptReportArtifact/u);
  assert.match(specSource, /decryptReportArtifact/u);
  assert.match(specSource, /page\.waitForEvent\("download"\)/u);
  assert.match(specSource, /download\.createReadStream\(\)/u);
  assert.match(specSource, /PDFDocument\.load/u);
  assert.match(specSource, /descriptor\.has\(PDFName\.of\("FontFile3"\)\)/u);
  assert.match(specSource, /validateTrueTypeSubset\(decodedFont\)/u);
  assert.match(specSource, /parseToUnicodeMap\(decodedPdfStreamText\(unicodeStream\)\)/u);
  assert.match(specSource, /pageText\.replace\(\/\\s\/gu, ""\)\.length < 20/u);
  assert.match(specSource, /workbook\.xlsx\.load/u);
  assert.match(specSource, /report\.requested/u);
  assert.match(specSource, /report\.ready/u);
  assert.match(specSource, /report\.downloaded/u);
  assert.match(runnerSource, /EPHEMERAL_TENANT_NAME/u);
  assert.match(runnerSource, /EPHEMERAL_TENANT_TIMEZONE/u);
  assert.match(runnerSource, /tenant: \{[\s\S]*name: EPHEMERAL_TENANT_NAME,[\s\S]*timezone: EPHEMERAL_TENANT_TIMEZONE/u);
});

test("el runner sólo autoriza recursos UUID efímeros y rehúsa puertos operativos", () => {
  assert.match(guardSource, /REAL_BROWSER_STACK_FLAG = "--ephemeral-only"/u);
  assert.match(guardSource, /REAL_BROWSER_STACK_CHECK_FLAG = "--check"/u);
  assert.match(guardSource, /controlDatabase: `nom_e2e_c_\$\{runSuffix\}`/u);
  assert.match(guardSource, /tenantDatabase: `nom_t_\$\{tenantSuffix\}`/u);
  assert.match(guardSource, /RESERVED_APPLICATION_PORTS = \[3_000, 4_000\]/u);
  assert.match(guardSource, /WORKSPACE_POSTGRES_PORT = 55_432/u);
  assert.match(runnerSource, /assertIsolatedHttpOrigin\(baseUrl, "Fastify API"\)/u);
  assert.match(runnerSource, /assertIsolatedHttpOrigin\(baseUrl, "browser harness"\)/u);
  assert.ok(
    runnerSource.includes("left(datname,length('nom_e2e_c_'))='nom_e2e_c_'"),
    "el inventario debe abarcar cualquier base con prefijo nom_e2e_c_",
  );
  assert.match(runnerSource, /\^nom_t_\[0-9a-f\]\{32\}\$/u);
  assert.match(runnerSource, /\^nom_\[or\]_\[0-9a-f\]\{32\}\$/u);
  assert.equal(apiPackage.scripts?.["e2e:real-stack:local"],
    "node ./scripts/real-browser-stack-prerun.mjs --ephemeral-only && pnpm --filter @nombramientos/database... build && pnpm build && node dist/scripts/real-browser-stack-local.js --ephemeral-only");
  assert.equal(apiPackage.scripts?.["e2e:real-stack:check"],
    "node ./scripts/real-browser-stack-prerun.mjs --check && pnpm --filter @nombramientos/database... build && pnpm build && node dist/scripts/real-browser-stack-local.js --check");
  assert.equal(workspacePackage.scripts?.["test:e2e:real-stack:local"],
    "pnpm --filter @nombramientos/api e2e:real-stack:local");
  assert.equal(workspacePackage.scripts?.["test:e2e:real-stack:check"],
    "pnpm --filter @nombramientos/api e2e:real-stack:check");
});

test("la ceremonia passkey real usa WebAuthn Chromium, credencial residente, AAL2, step-up y revocación", () => {
  assert.match(passkeySpecSource, /WebAuthn\.addVirtualAuthenticator/u);
  assert.match(passkeySpecSource, /protocol: "ctap2"/u);
  assert.match(passkeySpecSource, /transport: "internal"/u);
  assert.match(passkeySpecSource, /hasResidentKey: true/u);
  assert.match(passkeySpecSource, /hasUserVerification: true/u);
  assert.match(passkeySpecSource, /isUserVerified: true/u);
  assert.match(passkeySpecSource, /navigator\.credentials\.create/u);
  assert.match(passkeySpecSource, /navigator\.credentials\.get/u);
  assert.match(passkeySpecSource, /allowCredentials/u);
  assert.match(passkeySpecSource, /phishingResistant: true/u);
  assert.match(passkeySpecSource, /WEBAUTHN_CEREMONY_INVALID/u);
  assert.match(passkeySpecSource, /WEBAUTHN_STEP_UP_REQUIRED/u);
  assert.match(passkeySpecSource, /x-step-up-grant/u);
  assert.match(passkeySpecSource, /signedOut: true/u);
  assert.doesNotMatch(passkeySpecSource, /page\.route|route\.fulfill|page\.request/u);
  assert.match(runnerSource, /readonly passkey: TestSession/u);
  assert.match(runnerSource, /NOMBRAMIENTOS_REAL_STACK_PASSKEY_FIXTURE_B64/u);
  assert.match(runnerSource, /syntheticIdentityEmail\("passkey"/u);
});

test("cleanup queda fail-closed y prueba ausencia más huellas completas de control, Demo y Ozama", () => {
  const before = runnerSource.indexOf('executionStage = "protected-fingerprint-before"');
  const create = runnerSource.indexOf('executionStage = "isolated-control-create"');
  const after = runnerSource.indexOf('executionStage = "protected-fingerprint-after"');
  assert.ok(before >= 0 && create > before && after > create);
  assert.match(runnerSource, /verifyControlMarker\(state\)/u);
  assert.match(runnerSource, /verifyTenantMarker\(state\.tenant!/u);
  assert.match(runnerSource, /Cleanup refused before destructive DDL/u);
  assert.match(runnerSource, /assertCleanupObservation\(observation\)/u);
  assert.match(runnerSource, /global-ephemeral-inventory-before/u);
  assert.match(runnerSource, /global-ephemeral-inventory-after/u);
  assert.match(runnerSource, /assertGlobalEphemeralResourcesAbsent/u);
  assert.match(guardSource, /Object\.keys\(PROTECTED_DATABASES\)\.sort\(\)/u);
  for (const structuralEvidence of [
    "pg_attribute", "pg_constraint", "pg_index", "pg_get_viewdef", "pg_proc",
    "pg_get_functiondef", "pg_trigger", "pg_type", "pg_policy", "pg_default_acl", "aclexplode",
  ]) assert.ok(runnerSource.includes(structuralEvidence), `falta huella estructural ${structuralEvidence}`);
  assert.match(runnerSource, /DROP DATABASE IF EXISTS %I WITH \(FORCE\)/u);
  assert.match(runnerSource, /DROP ROLE IF EXISTS %I/u);
  assert.doesNotMatch(runnerSource, /DELETE\s+FROM|TRUNCATE\s+/u);
});

test("la configuración dedicada desactiva artefactos sensibles y no usa el stack 3000/4000", () => {
  assert.match(generalConfigSource, /testIgnore:\s*\["real-stack-closure\.spec\.ts", "real-stack-passkey\.spec\.ts"\]/u);
  assert.match(configSource, /testMatch:\s*\["real-stack-closure\.spec\.ts", "real-stack-passkey\.spec\.ts"\]/u);
  assert.match(configSource, /workers: 1/u);
  assert.match(configSource, /trace: "off"/u);
  assert.match(configSource, /screenshot: "off"/u);
  assert.match(configSource, /video: "off"/u);
  assert.match(configSource, /import \{ assertExactRealStackOrigin \}/u);
  assert.match(configSource, /return assertExactRealStackOrigin\(value, name\)/u);
  assert.match(localQaBoundarySource, /\[3_000, 4_000, 55_432\]\.includes\(port\)/u);
  assert.match(localQaBoundarySource, /authority !== `localhost:\$\{parsed\.port\}`/u);
  assert.match(specSource, /process\.env\["TEST_WORKER_INDEX"\] !== undefined[\s\S]*delete process\.env\["NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64"\]/u);
  assert.match(specSource, /delete process\.env\["NOMBRAMIENTOS_REAL_STACK_FIXTURE_B64"\]/u);
  assert.match(specSource, /fixture identifiers and sessions must be unique/u);
  assert.match(specSource, /is not a UUIDv4/u);
  assert.match(passkeySpecSource, /delete process\.env\["NOMBRAMIENTOS_REAL_STACK_PASSKEY_FIXTURE_B64"\]/u);
  assert.match(passkeySpecSource, /parsed\.hostname !== "localhost"/u);
});
