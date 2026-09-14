import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  appLandingPath,
  canAccessAppSection,
  firstAccessibleAppSection,
  firstAccessibleTenantSection,
  sectionRequiresContentKey,
} from "./app-navigation.ts";

test("las rutas con lecturas dependientes exigen capacidades compuestas", () => {
  assert.equal(canAccessAppSection("overview", []), false);
  assert.equal(canAccessAppSection("members", ["member.manage"]), false);
  assert.equal(canAccessAppSection("members", ["member.read"]), true);
  assert.equal(canAccessAppSection("committee", ["committee.manage"]), false);
  assert.equal(canAccessAppSection("committee", ["member.read"]), true);
  assert.equal(canAccessAppSection("session", ["ballot.submit"]), true);
  assert.equal(canAccessAppSection("session", ["proposal.submit"]), true);
  assert.equal(canAccessAppSection("session", ["aggregate.read"]), true);
  assert.equal(canAccessAppSection("session", ["aggregate.read", "ballot.submit"]), true);
  assert.equal(canAccessAppSection("session", ["aggregate.read", "ballot.close"]), true);
  assert.equal(canAccessAppSection("custody", ["tally.recount", "aggregate.publish"]), false);
  assert.equal(canAccessAppSection("custody", ["aggregate.read", "tally.custody"]), true);
});

test("el aterrizaje elige la primera superficie realmente accesible", () => {
  assert.equal(firstAccessibleTenantSection([]), "catalog");
  assert.equal(firstAccessibleTenantSection(["role.manage"]), "access");
  assert.equal(firstAccessibleAppSection(["platform.operation.read"]), "platform");
  assert.equal(appLandingPath("fr", ["member.read"]), "/fr/app/members");
});

test("toda superficie que revela contenido cifrado exige desbloquear tras recargar", () => {
  for (const section of [
    "overview", "workflow", "session", "results", "members", "committee", "organization", "reports",
  ]) {
    assert.equal(sectionRequiresContentKey(section), true, section);
  }
  for (const section of ["catalog", "access", "custody", "history", "settings", "library", "platform"]) {
    assert.equal(sectionRequiresContentKey(section), false, section);
  }
  const shell = readFileSync(path.resolve(import.meta.dirname, "../components/nombramientos/app-shell.tsx"), "utf8");
  assert.match(shell, /sectionRequiresContentKey\(section\)/u);
});

test("login, MFA, cambio de iglesia, shell y ruta base comparten el mismo contrato", () => {
  const root = path.resolve(import.meta.dirname, "..");
  for (const relative of [
    "components/nombramientos/app-shell.tsx",
    "components/nombramientos/login-form.tsx",
    "components/nombramientos/mfa-enrollment.tsx",
    "components/nombramientos/tenant-switcher.tsx",
  ]) {
    assert.match(readFileSync(path.join(root, relative), "utf8"), /appLandingPath/);
  }
  assert.match(readFileSync(path.join(root, "app/[locale]/app/page.tsx"), "utf8"), /section="landing"/);
  const roundRoutes = readFileSync(path.join(root, "../api/src/modules/round-routes.ts"), "utf8");
  assert.match(roundRoutes, /ACTIVE_ROUND_READ_PERMISSIONS\.some/);
  assert.doesNotMatch(roundRoutes, /rounds\/active[\s\S]{0,160}requirePermission\("aggregate\.read"\)/);
});
