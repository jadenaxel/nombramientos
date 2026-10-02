import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { localQaApiRoute } from "../e2e/support/local-api-route.ts";
import { assertExactRealStackOrigin, resolveLocalQaOrigins } from "./local-qa-boundary.ts";
import { resolveStandaloneBinding } from "./standalone-boundary.mjs";

test("selects only the exact workspace or container-test origin pair", () => {
  assert.deepEqual(resolveLocalQaOrigins({}), {
    target: "workspace",
    webOrigin: "http://localhost:3000",
    apiOrigin: "http://localhost:4000",
  });
  assert.deepEqual(resolveLocalQaOrigins({
    NOMBRAMIENTOS_E2E_TARGET: "container-test",
    WEB_BASE_URL: "http://localhost:3301/",
    NEXT_PUBLIC_API_URL: "http://localhost:4401/",
  }), {
    target: "container-test",
    webOrigin: "http://localhost:3301",
    apiOrigin: "http://localhost:4401",
  });
});

test("rejects an absent profile, mixed origin pairs and URL parser bypasses", () => {
  assert.throws(() => resolveLocalQaOrigins({ NOMBRAMIENTOS_E2E_TARGET: "other" }));
  assert.throws(() => resolveLocalQaOrigins({
    NOMBRAMIENTOS_E2E_TARGET: "container-test",
    WEB_BASE_URL: "http://localhost:3000",
    NEXT_PUBLIC_API_URL: "http://localhost:4401",
  }));
  assert.throws(() => resolveLocalQaOrigins({
    WEB_BASE_URL: "http://localhost:3000",
    NEXT_PUBLIC_API_URL: "http://localhost:4401",
  }));

  for (const value of [
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "http://[::1]:3000",
    "http://2130706433:3000",
    "http://localhost.:3000",
    "http://user:password@localhost:3000",
    "http://localhost:3000/es",
    "http://localhost:3000?next=https://example.invalid",
    "http://localhost:3000#external",
    " http://localhost:3000",
  ]) {
    assert.throws(() => resolveLocalQaOrigins({ WEB_BASE_URL: value }), value);
  }
});

test("standalone runtime refuses non-workspace bindings", () => {
  assert.deepEqual(resolveStandaloneBinding({}), { host: "127.0.0.1", port: "3000" });
  assert.deepEqual(resolveStandaloneBinding({
    NOMBRAMIENTOS_WEB_HOST: "127.0.0.1",
    NOMBRAMIENTOS_WEB_PORT: "3000",
  }), { host: "127.0.0.1", port: "3000" });
  assert.deepEqual(resolveStandaloneBinding({
    GESTIONCHURCH_MODULE_MODE: "true",
    NOMBRAMIENTOS_WEB_HOST: "127.0.0.1",
    NOMBRAMIENTOS_WEB_PORT: "3300",
  }), { host: "127.0.0.1", port: "3300" });
  for (const source of [
    { NOMBRAMIENTOS_WEB_HOST: "0.0.0.0" },
    { NOMBRAMIENTOS_WEB_HOST: "localhost" },
    { NOMBRAMIENTOS_WEB_PORT: "3301" },
    { NOMBRAMIENTOS_WEB_PORT: "3000 " },
  ]) assert.throws(() => resolveStandaloneBinding(source));
});

test("closure runner pins routing before build and clears inherited database routes", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  const source = readFileSync(path.join(root, "scripts", "verify-local.ps1"), "utf8");
  const boundary = source.indexOf("$env:NOMBRAMIENTOS_E2E_TARGET = 'workspace'");
  const build = source.indexOf("-Name 'build'");
  assert.ok(boundary >= 0 && boundary < build);
  for (const marker of [
    "$env:WEB_BASE_URL = 'http://localhost:3000'",
    "$env:NEXT_PUBLIC_API_URL = 'http://localhost:4000'",
    "$env:API_HOST = '127.0.0.1'",
    "$env:API_PORT = '4000'",
    "'TEST_DATABASE_ADMIN_URL'",
    "'DATABASE_CONTROL_URL'",
    "Remove-Item Env:NODE_ENV",
  ]) assert.ok(source.includes(marker), marker);
});

test("mocked E2E API routes use the selected local QA profile instead of a workspace-only port", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  for (const filename of ["mfa-enrollment-ui.spec.ts", "key-lifecycle.spec.ts"]) {
    const source = readFileSync(path.join(root, "apps", "web", "e2e", filename), "utf8");
    assert.match(source, /(?:resolveLocalQaOrigins\(\)\.apiOrigin|localQaApiRoute\()/u, filename);
    assert.doesNotMatch(source, /page\.route\(["']http:\/\/127\.0\.0\.1:4000\/\*\*/u, filename);
  }

  const helper = readFileSync(path.join(root, "apps", "web", "e2e", "support", "local-api-route.ts"), "utf8");
  assert.match(helper, /resolveLocalQaOrigins\(\)\.apiOrigin/u);
  assert.match(helper, /url\.origin === apiOrigin/u);
  for (const filename of ["demo-flow.spec.ts", "acceptance-closure.spec.ts", "resilience-races.spec.ts", "custody-ceremony.spec.ts", "photo-flow.spec.ts", "management-flows.spec.ts"]) {
    const source = readFileSync(path.join(root, "apps", "web", "e2e", filename), "utf8");
    const routeCalls = source.match(/page\.route\(/gu)?.length ?? 0;
    const boundedRouteCalls = source.match(/page\.route\(localQaApiRoute\(/gu)?.length ?? 0;
    assert.ok(routeCalls > 0, `${filename} must retain its deterministic API mocks`);
    assert.equal(boundedRouteCalls, routeCalls, `${filename} has a route outside the selected API origin`);
    assert.doesNotMatch(source, /page\.route\(["']\*\*\/v1/u, filename);
    assert.equal(source.includes("page.route(/\\/v1"), false, filename);
  }
});

test("the browser custody ceremony cannot persist its register or revoke writes in Demo", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  const source = readFileSync(path.join(root, "apps", "web", "e2e", "custody-ceremony.spec.ts"), "utf8");
  const registerRoute = source.indexOf('page.route(localQaApiRoute("/v1/custody/keys")');
  const revokeRoute = source.indexOf("page.route(localQaApiRoute(/^\\/v1\\/custody\\/keys\\/[^/]+\\/revoke$/u)");
  const signIn = source.indexOf("signInDemo(page, \"custodian\")");
  const registryHandler = source.slice(registerRoute, revokeRoute);
  const revokeHandler = source.slice(revokeRoute, signIn);

  assert.ok(registerRoute >= 0 && revokeRoute > registerRoute && signIn > revokeRoute);
  assert.equal(source.match(/page\.route\(/gu)?.length, 2);
  assert.equal(source.match(/page\.route\(localQaApiRoute\(/gu)?.length, 2);
  assert.match(registryHandler, /request\.method\(\) === "GET"[\s\S]*?route\.fetch\(\)[\s\S]*?syntheticKey[\s\S]*?route\.fulfill/u);
  assert.match(registryHandler, /expect\(request\.method\(\)\)\.toBe\("POST"\)[\s\S]*?registrationWrites \+= 1[\s\S]*?route\.fulfill/u);
  assert.doesNotMatch(registryHandler, /route\.(?:continue|fallback)\(/u);
  assert.match(revokeHandler, /expect\(request\.method\(\)\)\.toBe\("POST"\)[\s\S]*?revocationWrites \+= 1[\s\S]*?route\.fulfill/u);
  assert.doesNotMatch(revokeHandler, /route\.(?:fetch|continue|fallback)\(/u);
  assert.match(source, /expect\(registrationWrites\)\.toBe\(1\)/u);
  assert.match(source, /expect\(revocationWrites\)\.toBe\(1\)/u);
  assert.match(source, /expect\(syntheticKey\.status\)\.toBe\("revoked"\)/u);
  const reload = source.indexOf('page.reload({ waitUntil: "domcontentloaded" })');
  const restore = source.indexOf('getByRole("button", { name: "Desbloquear en este dispositivo" })');
  assert.ok(reload > signIn && restore > reload, "the backup must be restored only after an in-memory reset");
  assert.match(source.slice(reload, restore), /unlockedStatus\)\.toHaveCount\(0\)/u);
  assert.match(source.slice(restore), /unlockedStatus\)\.toBeVisible\(\)[\s\S]*?browserPersistenceSnapshot\(page\)[\s\S]*?persistenceBaseline/u);
  assert.match(source, /browserPersistenceSnapshot/u);
  assert.match(source, /indexedDB\.databases/u);
  assert.match(source, /caches\.keys/u);
});

test("the browser photo ceremony cannot persist its save or archive writes in Demo", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  const source = readFileSync(path.join(root, "apps", "web", "e2e", "photo-flow.spec.ts"), "utf8");
  const contextRoute = source.indexOf("page.route(localQaApiRoute(/^\\/v1\\/members\\/[^/]+\\/photo\\/write-context$/u)");
  const photoRoute = source.indexOf("page.route(localQaApiRoute(/^\\/v1\\/members\\/[^/]+\\/photo$/u)");
  const archiveRoute = source.indexOf("page.route(localQaApiRoute(/^\\/v1\\/members\\/[^/]+\\/photo\\/archive$/u)");
  const navigation = source.indexOf('page.getByRole("link", { name: "Miembros" })');
  const photoHandler = source.slice(photoRoute, archiveRoute);
  const archiveHandler = source.slice(archiveRoute, navigation);

  assert.ok(contextRoute >= 0 && photoRoute > contextRoute && archiveRoute > photoRoute && navigation > archiveRoute);
  assert.equal(source.match(/page\.route\(/gu)?.length, 3);
  assert.equal(source.match(/page\.route\(localQaApiRoute\(/gu)?.length, 3);
  assert.match(photoHandler, /request\.method\(\) === "GET"[\s\S]*?syntheticPhoto[\s\S]*?route\.fulfill/u);
  assert.match(photoHandler, /expect\(request\.method\(\)\)\.toBe\("POST"\)[\s\S]*?saveWrites \+= 1[\s\S]*?route\.fulfill/u);
  assert.doesNotMatch(photoHandler, /route\.(?:fetch|continue|fallback)\(/u);
  assert.match(archiveHandler, /expect\(request\.method\(\)\)\.toBe\("POST"\)[\s\S]*?archiveWrites \+= 1[\s\S]*?route\.fulfill/u);
  assert.doesNotMatch(archiveHandler, /route\.(?:fetch|continue|fallback)\(/u);
  assert.match(source, /expect\(saveWrites\)\.toBe\(1\)/u);
  assert.match(source, /expect\(archiveWrites\)\.toBe\(1\)/u);
  assert.match(source, /expect\(projectedActiveReads\)\.toBeGreaterThan\(0\)/u);
  assert.match(source, /expect\(syntheticPhoto\?\.archivedAt\)\.toBe\("2026-09-12T12:01:00\.000Z"\)/u);
});

test("browser management flows project every member and catalog mutation without writing to Demo", () => {
  const root = path.resolve(import.meta.dirname, "../../..");
  const source = readFileSync(path.join(root, "apps", "web", "e2e", "management-flows.spec.ts"), "utf8");
  const memberTest = source.slice(source.indexOf('test("member administration'), source.indexOf('test("local catalog extension'));
  const catalogTest = source.slice(source.indexOf('test("local catalog extension'));

  assert.equal(source.match(/page\.route\(/gu)?.length, 5);
  assert.equal(source.match(/page\.route\(localQaApiRoute\(/gu)?.length, 5);
  assert.ok(memberTest.indexOf('localQaApiRoute("/v1/members/manage")') < memberTest.indexOf("signInDemo(page)"));
  assert.ok(memberTest.indexOf("localQaApiRoute(memberMutationPathPattern)") < memberTest.indexOf("signInDemo(page)"));
  assert.match(memberTest, /localQaApiRoute\("\/v1\/members\/manage"\)[\s\S]*?route\.fetch\(\)[\s\S]*?projectedMember[\s\S]*?route\.fulfill/u);
  assert.match(memberTest, /localQaApiRoute\(memberMutationPathPattern\)[\s\S]*?memberMutationPathPattern\.exec\(pathname\)[\s\S]*?memberEdits \+= 1[\s\S]*?memberArchives \+= 1[\s\S]*?memberReactivations \+= 1/u);
  const patternSource = source.match(/const memberMutationPathPattern = \/(.+)\/u;/u)?.[1];
  assert.ok(patternSource, "management flow must declare an inspectable member mutation path boundary");
  const mutationPath = new RegExp(patternSource, "u");
  const memberId = "a1000000-0000-4000-8000-000000000001";
  assert.equal(mutationPath.test("/v1/members/manage"), false);
  assert.equal(mutationPath.test(`/v1/members/${memberId}`), true);
  assert.equal(mutationPath.test(`/v1/members/${memberId}/archive`), true);
  assert.equal(mutationPath.test(`/v1/members/${memberId}/reactivate`), true);
  assert.equal(mutationPath.test(`/v1/members/${memberId}/other`), false);
  assert.doesNotMatch(memberTest, /route\.(?:continue|fallback)\(/u);
  assert.match(memberTest, /expect\(memberEdits\)\.toBe\(1\)/u);
  assert.match(memberTest, /expect\(memberArchives\)\.toBe\(1\)/u);
  assert.match(memberTest, /expect\(memberReactivations\)\.toBe\(1\)/u);

  assert.ok(catalogTest.indexOf('localQaApiRoute("/v1/catalog/manage")') < catalogTest.indexOf("signInDemo(page)"));
  assert.ok(catalogTest.indexOf('localQaApiRoute("/v1/catalog/departments")') < catalogTest.indexOf("signInDemo(page)"));
  assert.ok(catalogTest.indexOf("localQaApiRoute(/^\\/v1\\/catalog\\/departments") < catalogTest.indexOf("signInDemo(page)"));
  assert.match(catalogTest, /localQaApiRoute\("\/v1\/catalog\/manage"\)[\s\S]*?route\.fetch\(\)[\s\S]*?canonicalCode !== code[\s\S]*?projectedDepartment[\s\S]*?route\.fulfill/u);
  assert.doesNotMatch(catalogTest, /route\.(?:continue|fallback)\(/u);
  assert.doesNotMatch(catalogTest, /if \(await row\.count\(\)/u);
  assert.match(catalogTest, /expect\(catalogCreates\)\.toBe\(1\)/u);
  assert.match(catalogTest, /expect\(catalogEdits\)\.toBe\(1\)/u);
  assert.match(catalogTest, /expect\(catalogDeactivations\)\.toBe\(1\)/u);
  assert.match(catalogTest, /expect\(catalogReactivations\)\.toBe\(1\)/u);
});

test("local QA route predicates reject the right API path on every other origin", () => {
  const { apiOrigin, webOrigin } = resolveLocalQaOrigins();
  const exact = localQaApiRoute("/v1/members");
  assert.equal(exact(new URL(`${apiOrigin}/v1/members`)), true);
  assert.equal(exact(new URL(`${apiOrigin}/v1/members/other`)), false);
  assert.equal(exact(new URL(`${webOrigin}/v1/members`)), false);
  assert.equal(exact(new URL("http://127.0.0.1:4000/v1/members")), false);

  const dynamic = localQaApiRoute(/^\/v1\/rounds\/[^/]+\/submissions$/u);
  assert.equal(dynamic(new URL(`${apiOrigin}/v1/rounds/round-id/submissions?retry=1`)), true);
  assert.equal(dynamic(new URL(`${webOrigin}/v1/rounds/round-id/submissions`)), false);
});

test("real-stack Playwright accepts only a literal path-free ephemeral localhost origin", () => {
  const exact = "http://localhost:49152";
  assert.equal(assertExactRealStackOrigin(exact, "real-stack harness"), exact);
  for (const value of [
    "http://127.0.0.1:49152",
    "http://[::1]:49152",
    "http://2130706433:49152",
    "http://127.1:49152",
    "http://127.0.0.1.:49152",
    "http://localhost.:49152",
    "http://user:password@localhost:49152",
    "http://localhost:049152",
    "http://localhost:49152/",
    "http://localhost:49152/path",
    "http://localhost:49152?next=http://example.invalid",
    "http://localhost:49152#external",
    "https://localhost:49152",
    "http://localhost:3000",
    "http://localhost:4000",
    "http://localhost:55432",
    ` ${exact}`,
    `${exact} `,
  ]) assert.throws(() => assertExactRealStackOrigin(value, "real-stack harness"), value);

  const root = path.resolve(import.meta.dirname, "../../..");
  const config = readFileSync(path.join(root, "apps", "web", "playwright.real-stack.config.ts"), "utf8");
  assert.match(config, /return assertExactRealStackOrigin\(value, name\)/u);
});
