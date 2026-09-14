import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import { getMessage } from "@nombramientos/i18n";

const root = path.resolve(import.meta.dirname, "..");
const source = (name: string) => readFileSync(path.join(root, "components/nombramientos", name), "utf8");
const historicalEnvelopeSource = readFileSync(path.join(root, "lib/historical-envelope.ts"), "utf8");
const productI18nSource = readFileSync(path.join(root, "lib/product-i18n.ts"), "utf8");

test("el límite multiselección conserva el estado y anuncia el rechazo", () => {
  const round = source("round-view.tsx");
  assert.match(round, /selected\.length >= max/);
  assert.match(round, /setSelectionError\(text\.selectionLimit/);
  assert.doesNotMatch(round, /slice\(-max\)/);
  assert.match(round, /aria-live="assertive"/);
  assert.match(round, /receiptHeadingRef/);
  assert.match(round, /tabIndex=\{-1\}/);
  assert.match(round, /error instanceof ApiError && error\.status === 404\) return null/);
  assert.match(round, /enabled: viewerHasSubmitPermission/);
  assert.match(round, /recover an already-issued[\s\S]*?receipt even when a new response is no longer allowed/);
  assert.match(round, /const maySubmit = data\.viewerCanSubmit && viewerHasSubmitPermission/);
  assert.match(round, /if \(decryptError\) throw new Error\(text\.candidateDecryptFailed\)/);
  assert.match(round, /const canSubmit = maySubmit && !decryptError/);
  assert.ok((round.match(/disabled=\{Boolean\(decryptError\)/g) ?? []).length >= 3);
});

test("el ciclo de claves diferencia error, carga y acciones aplicables", () => {
  const keys = source("key-lifecycle-view.tsx");
  const error = keys.indexOf("if (stateQuery.isError)");
  const loading = keys.indexOf("if (stateQuery.isLoading || !state)", error);
  assert.ok(error >= 0 && loading > error);
  assert.doesNotMatch(keys, /onReauthenticate=\{\(\) => undefined\}/);
  assert.match(keys, /vault\.keyId === state\.currentGeneration\.tenantKeyId[\s\S]*?<Button type="button" variant="ghost" onClick=\{vault\.lock\}/);
});

test("copiar secretos siempre produce confirmación o error visible", () => {
  for (const name of ["invitations-view.tsx", "mfa-enrollment.tsx", "platform-console.tsx"]) {
    const contents = source(name);
    assert.match(contents, /navigator\.clipboard\.writeText/);
    assert.match(contents, /catch \{/);
    assert.match(contents, /copyFailed/);
    assert.match(contents, /role="alert"/);
  }
});

test("el login espera hidratación y precalienta sesiones acotadas por motor", () => {
  const login = source("login-form.tsx");
  assert.match(login, /useSyncExternalStore\(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot\)/);
  assert.match(login, /disabled=\{!preAuthReady \|\| busy \|\| passkeyBusy/);
  assert.match(login, /currentPreAuthOriginGateUrl/);
  assert.match(login, /localizedSignInError\(caught, locale\)/);
  assert.match(productI18nSource, /export function localizedSignInError/);
  assert.match(productI18nSource, /error\.status === 429[\s\S]*?"auth\.tooManyAttempts"[\s\S]*?error\.status === 408 \|\| error\.status >= 500[\s\S]*?"error\.transient"[\s\S]*?error\.status === 401[\s\S]*?"auth\.invalidCredentials"/);
  assert.match(productI18nSource, /error\.requestId \? `\$\{base\} \(\$\{message\(locale, "audit\.correlationId", \{ id: error\.requestId \}\)\}\)` : base/);
  const setup = readFileSync(path.resolve(root, "e2e", "global-setup.ts"), "utf8");
  assert.match(setup, /\{ chromium, firefox, webkit \}/);
  assert.match(setup, /filterSessionCookies/);
  assert.match(setup, /serviceWorkers:\s*"block"/);
  const auth = readFileSync(path.resolve(root, "e2e", "support", "demo-auth.ts"), "utf8");
  assert.match(auth, /cookie\.name === "nom_session" \|\| cookie\.name === "nom_csrf"/);
  assert.match(auth, /did not produce a bounded API response/);
  assert.match(auth, /lastAcceptedTotpCounterByIdentity/);
  assert.match(auth, /profile:\s*DemoProfile/);
  assert.match(auth, /options\.forceFresh/);
  assert.match(auth, /page\.context\(\)\.clearCookies\(\)/);
  assert.match(auth, /getByText\("Iglesia Demostración", \{ exact: true \}\)\.filter\(\{ visible: true \}\)/);
  assert.match(auth, /mfaResponse[\s\S]*?page\.waitForResponse/);
  assert.match(auth, /MFA rate limit is active; refusing to consume additional login challenges/);
  const roles = readFileSync(path.resolve(root, "e2e", "role-access.spec.ts"), "utf8");
  assert.match(roles, /DEFAULT_ROLE_PERMISSIONS/);
  assert.match(roles, /membersStatus/);
  assert.match(roles, /auditStatus/);
  const demoFlow = readFileSync(path.resolve(root, "e2e", "demo-flow.spec.ts"), "utf8");
  assert.match(demoFlow, /requestReportDownload/);
  assert.match(demoFlow, /forceFresh:\s*true/);
  assert.match(demoFlow, /No se descargó el reporte/);
  const localizedFailure = demoFlow.slice(demoFlow.indexOf("authenticated surfaces follow"), demoFlow.indexOf("real demo login loads"));
  const memberCreateMock = localizedFailure.indexOf('page.route(localQaApiRoute("/v1/members")');
  const memberCreateClick = localizedFailure.indexOf('name: "Encrypt and save"');
  assert.ok(memberCreateMock >= 0 && memberCreateClick > memberCreateMock);
  assert.match(localizedFailure, /interceptedMemberCreates/);
  assert.match(localizedFailure, /persistedMemberTotal/);
  assert.match(localizedFailure, /toBe\(180\)/);
  const proposalFlow = demoFlow.slice(demoFlow.indexOf("real demo login loads"), demoFlow.indexOf("authorized browser generates"));
  const submissionMock = proposalFlow.indexOf("localQaApiRoute(/^\\/v1\\/rounds\\/[^/]+\\/submissions$/u)");
  assert.ok(submissionMock >= 0);
  assert.match(proposalFlow, /await signInDemo\(page, "administrator"\);/);
  assert.match(proposalFlow, /explicit COMMITTEE_MEMBER binding grants the[\s\S]*?without broadening CHURCH_ADMIN itself/);
  assert.match(proposalFlow, /navigateToAppSection\(page, "Miembros"\);[\s\S]*?unlockDemoVault\(page, "es", "administrator"\);/);
  assert.match(proposalFlow, /interceptedSubmissions/);
  assert.match(proposalFlow, /route\.fulfill\(/);
  const resilience = readFileSync(path.resolve(root, "e2e", "resilience-races.spec.ts"), "utf8");
  assert.match(resilience, /failedCandidateControls\.evaluateAll[\s\S]*?controls\.every\(\(control\) => control\.disabled\)/);
  assert.equal(resilience.match(/fetchActiveRoundEnvelope\(route\)/gu)?.length, 2);
  assert.match(resilience, /response\.status\(\) === 429[\s\S]*?response\.dispose\(\)[\s\S]*?setTimeout/);
  assert.match(resilience, /response\.status\(\) !== 200[\s\S]*?isActiveRoundEnvelope\(payload\)/);
  const acceptance = readFileSync(path.resolve(root, "e2e", "acceptance-closure.spec.ts"), "utf8");
  const importCommitMock = acceptance.indexOf('page.route(localQaApiRoute("/v1/members/import/commit")');
  const importCommitClick = acceptance.indexOf('name: "Confirmar importación"');
  assert.ok(importCommitMock >= 0 && importCommitClick > importCommitMock);
  assert.match(acceptance.slice(importCommitMock, importCommitClick), /route\.fulfill\(/);
  assert.match(acceptance, /commitPayload\)\.toEqual/);
  const reportDownload = demoFlow.slice(demoFlow.indexOf("async function requestReportDownload"), demoFlow.indexOf("async function validateReportArtifact"));
  assert.match(reportDownload, /MFA_STEP_UP_REQUIRED/);
  assert.match(reportDownload, /page\.on\("download"/);
  assert.match(reportDownload, /page\.off\("download"/);
  assert.doesNotMatch(reportDownload, /waitForEvent/);
  assert.match(demoFlow, /project\.name === "desktop-chromium-es"[\s\S]*?overview-desktop\.png/);
  assert.match(demoFlow, /project\.name === "mobile-small"[\s\S]*?round-receipt-mobile\.png/);
  assert.match(demoFlow, /One isolated client ceremony validates every downloadable report format/);
});

test("la ceremonia local de reportes proyecta historial y artefactos sin mutar Demo", () => {
  const demoFlow = readFileSync(path.resolve(root, "e2e", "demo-flow.spec.ts"), "utf8");
  const scenario = demoFlow.slice(
    demoFlow.indexOf('test("authorized browser generates valid PDF, XLSX and CSV artifacts locally"'),
    demoFlow.indexOf("async function requestReportDownload"),
  );
  const isolation = demoFlow.slice(
    demoFlow.indexOf("async function installIsolatedReportRoutes"),
    demoFlow.indexOf("async function fulfillReportData"),
  );
  const hardening = demoFlow.slice(
    demoFlow.indexOf("function assertReportMutationHeaders"),
    demoFlow.indexOf("function isUnsafeSpreadsheetCell"),
  );
  const setup = scenario.indexOf("installIsolatedReportRoutes(page)");
  const navigation = scenario.indexOf('navigateToAppSection(page, "Reportes")');
  assert.ok(setup >= 0 && navigation > setup);
  for (const fragment of [
    'localQaApiRoute("/v1/reports")',
    'localQaApiRoute("/v1/reports/generate")',
    'action === "complete"',
    'action === "fail"',
    'action === "print"',
    'localQaApiRoute(/^\\/v1\\/reports\\/[^/]+\\/artifact$/u)',
  ]) assert.ok(isolation.includes(fragment), `Missing isolated report route: ${fragment}`);
  assert.match(isolation, /const response = await route\.fetch\(\)/);
  assert.match(isolation, /envelope\.data\.items = \[\.\.\.projected,/);
  assert.match(isolation, /createHash\("sha256"\)\.update\(canonicalEnvelope/);
  assert.match(isolation, /artifacts\.set\(reportId, \{[\s\S]*?envelope: request\.envelope/);
  assert.equal(isolation.match(/assertReportMutationHeaders\(route\)/gu)?.length, 2);
  assert.match(isolation, /canonicalBase64UrlBytes\(request\.envelope\.nonce, "nonce"\)/);
  assert.match(isolation, /expect\(actualAad\)\.toEqual\(expectedAad\)/);
  assert.match(isolation, /request\.plaintextBytes <= 20 \* 1024 \* 1024/);
  assert.match(isolation, /request\.rowCount <= 1_000_000/);
  assert.match(hardening, /headers\["idempotency-key"\]/);
  assert.match(hardening, /headers\["x-csrf-token"\]/);
  assert.match(hardening, /cookieValue\(headers\["cookie"\], "nom_csrf"\)/);
  assert.match(hardening, /contentType !== "application\/json"/);
  assert.match(hardening, /bytes\.toString\("base64url"\) !== value/);
  assert.doesNotMatch(isolation, /route\.continue\(/);
  assert.match(scenario, /expect\(isolatedReports\.operations\)\.toEqual\(\{ generate: 3, complete: 3, fail: 0, print: 0, download: 3 \}\)/);
  assert.match(scenario, /for \(const \{ format, locale, filename \} of generatedReports\)/);
  assert.match(scenario, /validateReportArtifact\(historicalDestination, format, locale\)/);
});

test("los mocks de red bloquean service workers y la ceremonia PWA opta explícitamente", () => {
  const config = readFileSync(path.resolve(root, "playwright.config.ts"), "utf8");
  assert.match(config, /serviceWorkers:\s*"block"/);
  const pwa = readFileSync(path.resolve(root, "e2e", "accessibility-pwa.spec.ts"), "utf8");
  assert.match(pwa, /browser\.newContext\(/);
  assert.match(pwa, /serviceWorkers:\s*"allow"/);
  assert.doesNotMatch(pwa, /(?:page|context)\.route\(/);
  assert.match(pwa, /finally\s*\{[\s\S]*?context\.close\(\)/);
  for (const filename of readdirSync(path.resolve(root, "e2e")).filter((entry) => entry.endsWith(".spec.ts"))) {
    const spec = readFileSync(path.resolve(root, "e2e", filename), "utf8");
    if (/(?:page|context)\.route\(/.test(spec)) assert.doesNotMatch(spec, /serviceWorkers:\s*"allow"/);
  }
});

test("los botones no interpolan pares de color con contraste transitorio", () => {
  const button = readFileSync(path.resolve(root, "components", "ui", "button.tsx"), "utf8");
  assert.doesNotMatch(button, /transition-all/);
  assert.match(button, /transition-\[box-shadow,transform,border-color\]/);
  const badge = readFileSync(path.resolve(root, "components", "ui", "badge.tsx"), "utf8");
  assert.doesNotMatch(badge, /transition-\[color(?:,|\])/);
  assert.match(badge, /transition-\[box-shadow,border-color\]/);
});

test("los diálogos largos permanecen operables en viewports móviles", () => {
  const dialog = readFileSync(path.resolve(root, "components", "ui", "dialog.tsx"), "utf8");
  assert.match(dialog, /max-h-\[calc\(100dvh-2rem\)\]/);
  assert.match(dialog, /overflow-y-auto/);
});

test("los cierres genéricos y el menú móvil mantienen nombre y estructura accesibles", () => {
  const dialog = readFileSync(path.resolve(root, "components", "ui", "dialog.tsx"), "utf8");
  const sheet = readFileSync(path.resolve(root, "components", "ui", "sheet.tsx"), "utf8");
  const command = readFileSync(path.resolve(root, "components", "ui", "command.tsx"), "utf8");
  const sidebar = readFileSync(path.resolve(root, "components", "ui", "sidebar.tsx"), "utf8");
  const appShell = source("app-shell.tsx");

  for (const source of [dialog, sheet]) {
    assert.match(source, /useTranslations\("common"\)/);
    assert.match(source, /closeLabel \?\? common\("close"\)/);
    assert.doesNotMatch(source, />Close</);
  }
  assert.match(sheet, /data-slot="sheet-close"/);
  assert.match(command, /title: string/);
  assert.match(command, /description: string/);
  assert.match(command, /closeLabel: string/);
  assert.ok(command.indexOf("<DialogHeader") > command.indexOf("<DialogContent"));
  assert.ok(command.indexOf("</DialogHeader>") < command.indexOf("</DialogContent>"));
  assert.match(sidebar, /closeLabel=\{mobileCloseLabel\}/);
  assert.doesNotMatch(sidebar, /\[&>button\]:hidden/);
  assert.doesNotMatch(sidebar, /Toggle Sidebar/);
  assert.match(appShell, /mobileMenuOpenerRef = useRef<HTMLButtonElement \| null>\(null\)/);
  assert.match(appShell, /onCloseAutoFocus=\{\(event\) => \{ event\.preventDefault\(\); mobileMenuOpenerRef\.current\?\.focus\(\); \}\}/);
  assert.equal((appShell.match(/mobileMenuOpenerRef\.current = event\.currentTarget/gu) ?? []).length, 2);
});

test("preferencias y consultas auxiliares no presentan éxito o vacío ficticio", () => {
  const preferences = source("accessibility-preferences.tsx");
  assert.match(preferences, /setAnnouncement/);
  assert.match(preferences, /key=\{announcement\.sequence\}/);
  const styles = readFileSync(path.join(root, "app/globals.css"), "utf8");
  assert.match(styles, /\.preference-choice\{position:relative/);
  assert.match(styles, /\.preference-choice input\{position:absolute;z-index:1;inset:0;width:100%;height:100%/);
  const access = source("access-console.tsx");
  assert.match(access, /permissionQuery\.isError \|\| roleQuery\.isError \|\| bindingQuery\.isError/);
  assert.match(access, /permissionDescription\(locale, permission\)/);
  const workspace = source("workspace-view.tsx");
  assert.match(workspace, /roundQuery\.isError\s*\|\|\s*publishedQuery\.isError/);
});

test("el padrón reserva ancho legible a la identidad y acota las acciones", () => {
  const styles = readFileSync(path.join(root, "app/globals.css"), "utf8");
  const mobileMembers = styles.slice(styles.indexOf("@media(max-width:700px)"), styles.indexOf("@media(max-width:470px)"));
  assert.match(styles, /\.member-list article\{[^}]*grid-template-columns:auto minmax\(12rem,1fr\) auto minmax\(0,40%\)/);
  assert.match(styles, /\.member-list>article>div\{min-width:0\}/);
  assert.match(styles, /\.member-list strong,\.member-list small\{[^}]*overflow-wrap:anywhere/);
  assert.match(styles, /\.member-actions\{[^}]*min-width:0;max-width:100%[^}]*justify-self:stretch[^}]*flex-wrap:wrap/);
  assert.match(styles, /\.member-actions>\[data-slot=button\],\.member-actions>\[data-slot=badge\]\{[^}]*max-width:100%[^}]*white-space:normal/);
  assert.match(mobileMembers, /\.member-list article\{grid-template-columns:auto minmax\(0,1fr\)\}/);
  assert.doesNotMatch(styles, /\.member-list article\{[^}]*minmax\(220px,auto\)/);
});

test("el selector de hoja localiza el total de filas según el idioma activo", () => {
  const members = source("members-view.tsx");
  assert.match(members, /sheet\.rowCount\.toLocaleString\(locale\)/);
  assert.doesNotMatch(members, /\{sheet\.rowCount\}\s*\{copy\.rows\}/);
  assert.equal((10_000).toLocaleString("es"), "10.000");
});

test("el escrutinio publicado explica desenlace, desempate y plazas sin cubrir", () => {
  const workspace = source("workspace-view.tsx");
  assert.match(workspace, /aggregateDecisionReasonLabel/);
  assert.match(workspace, /aggregate\.decision\.selectedCandidateIds/);
  assert.match(workspace, /aggregate\.decision\.tiebreakCandidateIds/);
  assert.match(workspace, /aggregate\.decision\.unfilledSeats/);
  assert.match(workspace, /openJsonEnvelope/);
  assert.match(historicalEnvelopeSource, /exactAad: true/);
  assert.match(workspace, /candidateDecryptError/);
});

test("el tablero enumera cargos reales y separa carga independiente de vínculos", () => {
  const workspace = source("workspace-view.tsx");
  const workflow = source("workflow-console.tsx");
  assert.match(workspace, /function ResponsibilityDistribution/);
  assert.match(workspace, /\/v1\/organization\?stage=proposal/);
  assert.match(workspace, /session\.permissions\.includes\("organigram\.read"\)/);
  assert.match(workspace, /organizationWorkload\(items\)/);
  assert.match(workspace, /summary\.responsibilities\.map/);
  assert.match(workspace, /summary\.independent > 1/);
  assert.match(workspace, /openJsonEnvelope/);
  assert.match(historicalEnvelopeSource, /exactAad: true/);
  assert.match(workflow, /independentLoadWarning/);
  assert.match(workflow, /highestNominalLoad/);
  assert.match(workflow, /highestIndependentLoad/);
  assert.match(workflow, /message\(locale, "screen\.workflowConsole\.c1aac190ae15"\)/);
  assert.match(workflow, /message\(locale, "screen\.workflowConsole\.9aaebb31f36b"\)/);
  assert.equal(getMessage("es", "screen.workflowConsole.c1aac190ae15"), "Aviso de segunda función nominal");
  assert.equal(getMessage("es", "screen.workflowConsole.9aaebb31f36b"), "Alerta de acumulación no bloqueante");
});

test("las analíticas usan agregados reales, tablas equivalentes y movimiento reducido", () => {
  const workspace = source("workspace-view.tsx");
  const charts = source("analytics-charts.tsx");
  assert.match(workspace, /<DepartmentProgressAnalytics/);
  assert.match(workspace, /<ResponsibilityDistributionAnalytics/);
  assert.match(workspace, /<SessionEvolutionAnalytics/);
  assert.match(workspace, /<RoundParticipationAnalytics/);
  assert.match(workspace, /<CandidateVoteAnalytics/);
  assert.match(charts, /permission="aggregate\.read"/);
  assert.match(charts, /permission="organigram\.read"/);
  assert.match(charts, /message\(locale, "screen\.analyticsCharts\.f7ad5a0e64cc"\)/);
  assert.match(charts, /message\(locale, "screen\.analyticsCharts\.91eea5daa3f0"\)/);
  assert.match(charts, /message\(locale, "screen\.analyticsCharts\.e55050f49c52"\)/);
  assert.equal(getMessage("es", "screen.analyticsCharts.f7ad5a0e64cc"), "Padrón congelado");
  assert.equal(getMessage("es", "screen.analyticsCharts.91eea5daa3f0"), "Vacantes aplicables");
  assert.equal(getMessage("es", "screen.analyticsCharts.e55050f49c52"), "Decisiones / agenda");
  assert.match(charts, /<caption className="sr-only">/);
  assert.match(charts, /accessibilityLayer/);
  assert.ok((charts.match(/isAnimationActive=\{false\}/g) ?? []).length >= 7);
  assert.doesNotMatch(charts, /PieChart|RadialBarChart|animationDuration/);
});

test("la guía inicial no inventa estados y ofrece un destino que el rol puede abrir", () => {
  const workspace = source("workspace-view.tsx");
  const onboarding = workspace.slice(workspace.indexOf("function OnboardingView"), workspace.indexOf("function PageTitle"));
  assert.match(onboarding, /session\.permissions\.includes\("member\.read"\)/);
  assert.match(onboarding, /session\.permissions\.includes\("cycle\.manage"\)/);
  assert.match(onboarding, /section: "catalog"/);
  assert.doesNotMatch(onboarding, /"Pendiente","Pending","En attente"/);
  assert.match(workspace, /<OnboardingView locale=\{locale\} session=\{session\}/);
});

test("la verificación integral reconstruye y reinicia antes de aceptar E2E", () => {
  const verify = readFileSync(path.resolve(root, "../..", "scripts", "verify-local.ps1"), "utf8");
  const supplyChain = verify.indexOf("-Name 'supply-chain'");
  const audit = verify.indexOf("-Name 'dependency-audit'", supplyChain);
  const stop = verify.indexOf("& $NomStopScript -KeepDatabase");
  const build = verify.indexOf("-Name 'build'", stop);
  const start = verify.indexOf("& $NomStartScript", build);
  const freshHealth = verify.indexOf("$NomFreshHealth", start);
  const engineProbe = verify.indexOf("check-playwright-engines.mjs", freshHealth);
  const clearFirefox = verify.lastIndexOf("Remove-Item Env:NOMBRAMIENTOS_E2E_FIREFOX", engineProbe);
  const e2e = verify.indexOf("-Name 'playwright-e2e'", engineProbe);
  const pdfRender = verify.indexOf("pdftoppm.exe", e2e);
  const finalEvidence = verify.indexOf("verify-local-final.json");
  assert.ok(supplyChain >= 0 && audit > supplyChain && stop > audit && build > stop && start > build && freshHealth > start);
  assert.ok(clearFirefox > freshHealth && engineProbe > clearFirefox && e2e > engineProbe && pdfRender > e2e && finalEvidence >= 0);
  assert.match(verify, /NOMBRAMIENTOS_REQUIRE_LIVE_INTEGRATION = 'true'/);
  assert.match(verify, /NOMBRAMIENTOS_PRIVILEGE_LIVE = 'true'/);
  assert.match(verify, /NOMBRAMIENTOS_E2E_FIREFOX = 'true'/);
  assert.match(verify, /NOMBRAMIENTOS_E2E_FIREFOX = 'false'/);
  assert.match(verify, /mandatory Playwright engine/);
  assert.match(verify, /failed independent Poppler rendering/);
  assert.match(verify, /intentional-skips\.json/);
  assert.match(verify, /verify-local-evidence\.mjs/);
});
