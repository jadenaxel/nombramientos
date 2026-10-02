import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const webRoot = path.resolve(import.meta.dirname, "..");
const preferenceSource = readFileSync(path.join(webRoot, "components/nombramientos/accessibility-preferences.tsx"), "utf8");
const providerSource = readFileSync(path.join(webRoot, "app/providers.tsx"), "utf8");
const cssSource = readFileSync(path.join(webRoot, "app/globals.css"), "utf8");
const responsiveSource = readFileSync(path.join(webRoot, "app/responsive.css"), "utf8");
const serviceWorkerSource = readFileSync(path.join(webRoot, "public/sw.js"), "utf8");
const loginSource = readFileSync(path.join(webRoot, "components/nombramientos/login-form.tsx"), "utf8");
const invitationSource = readFileSync(path.join(webRoot, "components/nombramientos/invitation-accept-form.tsx"), "utf8");
const platformBootstrapSource = readFileSync(path.join(webRoot, "components/nombramientos/platform-bootstrap-form.tsx"), "utf8");
const appShellSource = readFileSync(path.join(webRoot, "components/nombramientos/app-shell.tsx"), "utf8");
const axeSources = [
  "e2e/accessibility-pwa.spec.ts",
  "e2e/demo-flow.spec.ts",
  "e2e/invitation-access.spec.ts",
  "e2e/key-lifecycle.spec.ts",
  "e2e/mfa-enrollment-ui.spec.ts",
  "e2e/organization-flow.spec.ts",
].map((filename) => readFileSync(path.join(webRoot, filename), "utf8"));

const mainContentSources = [
  "components/nombramientos/app-shell.tsx",
  "components/nombramientos/invitation-accept-form.tsx",
  "components/nombramientos/login-form.tsx",
  "components/nombramientos/platform-bootstrap-form.tsx",
].map((filename) => readFileSync(path.join(webRoot, filename), "utf8"));

function cssHexVariable(name: string) {
  const match = cssSource.match(new RegExp(`${name}:\\s*(#[0-9a-f]{6})`, "iu"));
  assert.ok(match, `missing ${name} CSS variable`);
  return match[1];
}

function relativeLuminance(hex: string) {
  const channels = hex
    .slice(1)
    .match(/.{2}/gu)
    ?.map((channel) => Number.parseInt(channel, 16) / 255)
    .map((channel) => (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4));
  assert.equal(channels?.length, 3, `invalid hex color: ${hex}`);
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

test("el diseño compartido refluye por ancho útil sin ocultar información fuera de la pantalla", () => {
  assert.match(responsiveSource, /container-name: nominations-workspace/);
  assert.match(responsiveSource, /@container nominations-workspace/);
  assert.match(responsiveSource, /minmax\(0,1fr\)/);
  assert.match(responsiveSource, /\[data-slot=table-container\]/);
  assert.doesNotMatch(responsiveSource, /(?:html|body)\s*\{[^}]*overflow-x:\s*hidden/);
});

test("diálogos y campos móviles respetan viewport dinámico, áreas seguras y objetivos táctiles", () => {
  assert.match(responsiveSource, /100dvh/);
  assert.match(responsiveSource, /env\(safe-area-inset-bottom\)/);
  assert.match(responsiveSource, /font-size: max\(16px,1rem\)/);
  assert.match(responsiveSource, /min-height: 44px/);
  const alertDialog = readFileSync(path.join(webRoot, "components/ui/alert-dialog.tsx"), "utf8");
  assert.match(alertDialog, /max-h-\[calc\(100dvh-2rem\)\]/);
  assert.match(alertDialog, /overflow-y-auto/);
});

test("el inicio protegido pasa a una columna y el perfil conserva un nombre accesible", () => {
  const workflowSource = readFileSync(path.join(webRoot, "components/nombramientos/workflow-console.tsx"), "utf8");
  assert.match(workflowSource, /flex flex-col items-start gap-4 sm:flex-row/);
  assert.match(workflowSource, /ref=\{startButtonRef\}/);
  assert.match(workflowSource, /onCloseAutoFocus=\{\(event\) => \{ event\.preventDefault\(\); startButtonRef\.current\?\.focus\(\)/);
  assert.match(responsiveSource, /\.unlock-card \{ grid-template-columns: minmax\(0,1fr\)/);
  assert.match(responsiveSource, /\.page-wrap \[data-slot=badge\] \{ max-width: 100%; white-space: normal/);
  assert.match(appShellSource, /className="profile-trigger" aria-label=\{session.user.displayName/);
  assert.match(responsiveSource, /\.session-stats div:last-child \{ display: block/);
});

function contrastRatio(first: string, second: string) {
  const firstLuminance = relativeLuminance(first);
  const secondLuminance = relativeLuminance(second);
  return (Math.max(firstLuminance, secondLuminance) + 0.05) / (Math.min(firstLuminance, secondLuminance) + 0.05);
}

test("las preferencias accesibles persistentes se aplican desde el proveedor global", () => {
  assert.match(providerSource, /AccessibilityPreferencesProvider/);
  assert.match(preferenceSource, /textSize: "standard"/);
  assert.match(preferenceSource, /contrast: "standard"/);
  assert.match(preferenceSource, /motion: "system"/);
  assert.match(preferenceSource, /density: "comfortable"/);
  assert.match(cssSource, /data-text-size="extra-large"/);
  assert.match(cssSource, /data-contrast="high"/);
  assert.match(cssSource, /data-motion="reduced"/);
  assert.match(cssSource, /data-density="compact"/);
  assert.match(preferenceSource, /setAnnouncement/);
  assert.match(preferenceSource, /announcement\.text && <span key=\{announcement\.sequence\}/);
});

test("todos los destinos del enlace de salto aceptan foco sin entrar al orden normal de Tab", () => {
  for (const source of mainContentSources) {
    const targets = source.match(/<main[^>]*id="main-content"[^>]*>/gu) ?? [];
    assert.ok(targets.length > 0);
    for (const target of targets) assert.match(target, /tabIndex=\{-1\}/u);
  }
});

test("el login conserva un h1 visible en móvil y reemplaza la validación nativa por errores localizados accesibles", () => {
  assert.doesNotMatch(loginSource, /<h1>\{copy\.privateSpace\}<\/h1>/u);
  assert.match(loginSource, /<p className="login-story-title">\{copy\.privateSpace\}<\/p>/u);
  assert.match(loginSource, /<h1>\{copy\.signIn\}<\/h1>/u);
  assert.match(loginSource, /<h1>\{copy\.mfa\}<\/h1>/u);
  assert.match(cssSource, /\.login-story-title\{/u);
  assert.match(loginSource, /className="auth-form" noValidate/u);
  assert.match(loginSource, /aria-invalid=\{credentialErrors\.email \? true : undefined\}/u);
  assert.match(loginSource, /aria-describedby=\{credentialErrors\.email \? "email-error" : undefined\}/u);
  assert.match(loginSource, /aria-describedby=\{credentialErrors\.password \? "password-requirements password-error" : "password-requirements"\}/u);
  assert.match(loginSource, /validationSummaryRef[\s\S]*?requestAnimationFrame\(\(\) => validationSummaryRef\.current\?\.focus\(\)\)/u);
  assert.match(loginSource, /message\(locale, "a11y\.errorSummary", \{ count: credentialErrorCount \}\)/u);
  assert.match(loginSource, /setPassword\(""\)[\s\S]*?setCredentialErrors\(nextErrors\)/u);
});

test("el acceso conserva el orden de teclado visible entre correo, llave de acceso y contraseña", () => {
  const emailPosition = loginSource.indexOf('id="email"');
  const passkeyPosition = loginSource.indexOf('className="passkey-login-button"');
  const passwordPosition = loginSource.indexOf('id="password"');
  assert.ok(emailPosition >= 0, "missing email control");
  assert.ok(passkeyPosition > emailPosition, "the passkey action must follow the email field in DOM order");
  assert.ok(passwordPosition > passkeyPosition, "the password fallback must follow the passkey action in DOM order");
  assert.doesNotMatch(loginSource, /tabIndex=\{?-1\}?[^>]*className="passkey-login-button"/u);
});

test("los estados vacío y de carga del centro de seguridad superan contraste AA sobre blanco", () => {
  const match = cssSource.match(/\.security-empty,\.security-loading\{[^}]*color:(#[0-9a-f]{6})/iu);
  assert.ok(match, "missing security state foreground color");
  assert.ok(contrastRatio(match[1], "#ffffff") >= 4.5, `${match[1]} must reach 4.5:1 against white`);
});

test("el divisor de alternativas de acceso supera contraste AA sobre blanco", () => {
  const match = cssSource.match(/\.auth-divider\{[^}]*color:(#[0-9a-f]{6})/iu);
  assert.ok(match, "missing authentication divider foreground color");
  assert.ok(contrastRatio(match[1], "#ffffff") >= 4.5, `${match[1]} must reach 4.5:1 against white`);
});

test("el centro de seguridad reduce sus pistas intrínsecas y permite reflow a 320 px con texto ampliado", () => {
  assert.match(cssSource, /\.security-center-stack\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0;/u);
  assert.match(cssSource, /\.security-center-stack>\*\{min-width:0;max-width:100%\}/u);
  assert.match(cssSource, /\.passkey-onboarding-grid>\*\{min-width:0\}/u);
  assert.match(cssSource, /\.security-management-grid>\*\{min-width:0\}/u);
  assert.match(cssSource, /\.security-center-stack \[data-slot=button\]\{[^}]*min-height:44px;[^}]*white-space:normal;/u);
  assert.match(cssSource, /\.security-center-stack \[data-slot=badge\]\{[^}]*max-width:100%;white-space:normal;/u);
  assert.match(cssSource, /\.identity-policy-actions>div\{grid-template-columns:repeat\(2,minmax\(0,1fr\)\)\}/u);
});

test("la invitación y el desbloqueo reemplazan la validación nativa sin retener contraseñas", () => {
  assert.match(invitationSource, /onSubmit=\{submitInvitation\} noValidate/u);
  assert.match(invitationSource, /useSyncExternalStore\(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot\)/u);
  assert.equal(invitationSource.match(/disabled=\{!preAuthReady \|\| busy\}/gu)?.length, 5);
  assert.match(invitationSource, /\{passwordRequired && <div className="field-stack">/u);
  assert.match(invitationSource, /if \(!passwordRequired \|\| busy \|\| !preAuthReady\) return;[\s\S]*?requestAnimationFrame\(\(\) => passwordRef\.current\?\.focus\(\)\)/u);
  assert.match(invitationSource, /return \(\) => window\.cancelAnimationFrame\(focusFrame\);[\s\S]*?\[busy, passwordRequired, preAuthReady\]/u);
  for (const field of ["token", "email", "displayName", "password"]) {
    assert.match(invitationSource, new RegExp(`aria-invalid=\\{fieldErrors\\.${field} \\? true : undefined\\}`, "u"));
  }
  assert.match(invitationSource, /id="accept-validation-summary"[\s\S]*?tabIndex=\{-1\}/u);
  assert.match(invitationSource, /requestAnimationFrame\(\(\) => validationSummaryRef\.current\?\.focus\(\)\)/u);
  assert.match(invitationSource, /setPassword\(""\);\s*setFieldErrors\(nextErrors\)/u);
  assert.match(invitationSource, /catch \(caught\) \{\s*setPassword\(""\)/u);
  assert.match(invitationSource, /caught\.requestId[\s\S]*?audit\.correlationId/u);

  assert.match(appShellSource, /<form onSubmit=\{submitUnlock\} noValidate>/u);
  assert.match(appShellSource, /aria-invalid=\{passwordError \? true : undefined\}/u);
  assert.match(appShellSource, /aria-describedby=\{passwordError \? "unlock-password-error" : undefined\}/u);
  assert.match(appShellSource, /id="unlock-validation-summary"[\s\S]*?tabIndex=\{-1\}/u);
  assert.match(appShellSource, /requestAnimationFrame\(\(\) => validationSummaryRef\.current\?\.focus\(\)\)/u);
  assert.match(appShellSource, /const submittedPassword = password;\s*setPassword\(""\)/u);
  assert.match(appShellSource, /localizedApiError\(caught, locale, "shell\.unlockError"\)/u);
});

test("el bootstrap global valida el mismo contrato sensible con errores localizados y accesibles", () => {
  assert.match(platformBootstrapSource, /className="auth-form" onSubmit=\{submit\} noValidate/u);
  assert.match(platformBootstrapSource, /useSyncExternalStore\(subscribeToHydration, hydratedClientSnapshot, hydratedServerSnapshot\)/u);
  assert.equal(platformBootstrapSource.match(/disabled=\{!hydrated \|\| busy\}/gu)?.length, 5);
  assert.match(platformBootstrapSource, /const tokenPattern = \/\^\[A-Za-z0-9_-\]\{43\}\$\/u/u);
  assert.match(platformBootstrapSource, /passwordMatchesPolicy\(password, normalizedEmail, normalizedDisplayName\)/u);
  for (const field of ["token", "email", "displayName", "password"]) {
    assert.match(platformBootstrapSource, new RegExp(`aria-invalid=\\{fieldErrors\\.${field} \\? true : undefined\\}`, "u"));
  }
  assert.match(platformBootstrapSource, /validationSummaryRef[\s\S]*?requestAnimationFrame\(\(\) => validationSummaryRef\.current\?\.focus\(\)\)/u);
  assert.match(platformBootstrapSource, /message\(locale, "a11y\.errorSummary", \{ count: fieldErrorCount \}\)/u);
  assert.match(platformBootstrapSource, /setPassword\(""\);\s*setFieldErrors\(nextErrors\)/u);
  assert.match(platformBootstrapSource, /localizedBootstrapError\(caught, locale, text\.error\)/u);
  assert.match(platformBootstrapSource, /error\.requestId[\s\S]*?audit\.correlationId/u);
});

test("los límites funcionales conservan contraste no textual de 3:1 sin oscurecer bordes decorativos", () => {
  const controlBorder = cssHexVariable("--input");
  const decorativeBorder = cssHexVariable("--border");
  assert.ok(contrastRatio(controlBorder, "#ffffff") >= 3, `${controlBorder} must reach 3:1 against white`);
  assert.equal(decorativeBorder.toLowerCase(), "#d9e2ea", "decorative surfaces must keep their lighter border token");
  assert.notEqual(controlBorder, decorativeBorder, "functional and decorative border tokens must remain separate");

  const rule = cssSource.match(/([^{}]+)\{\s*border-color:\s*var\(--input\);\s*\}/u);
  assert.ok(rule, "missing the authored functional-boundary override");
  for (const selector of [
    'input:not([type="hidden"])',
    "select",
    "textarea",
    '[data-slot="input"]',
    '[data-slot="textarea"]',
    '[data-slot="native-select"]',
    '[data-slot="select-trigger"]',
    '[data-slot="checkbox"]',
    '[data-slot="radio-group-item"]',
    '[data-slot="input-group"]',
    '[data-slot="input-otp-slot"]',
    '[data-slot="combobox-chips"]',
    '[data-slot="button"]',
    '[data-slot="toggle"]',
  ]) {
    assert.ok(rule[1].includes(selector), `missing functional boundary selector: ${selector}`);
  }
});

test("el foco en superficies oscuras usa el anillo lateral con contraste de al menos 3:1", () => {
  const sidebarRing = cssHexVariable("--sidebar-ring");
  const sidebar = cssHexVariable("--sidebar");
  const skipBackground = cssSource.match(/\.skip-link\{[^}]*background:(#[0-9a-f]{6})/iu)?.[1];
  assert.ok(skipBackground, "missing skip-link background color");
  assert.ok(contrastRatio(sidebarRing, sidebar) >= 3, `${sidebarRing} must reach 3:1 against ${sidebar}`);
  assert.ok(contrastRatio(sidebarRing, skipBackground) >= 3, `${sidebarRing} must reach 3:1 against ${skipBackground}`);

  const rule = cssSource.match(/([^{}]+)\{\s*outline-color:\s*var\(--sidebar-ring\);\s*\}/u);
  assert.ok(rule, "missing the dark-surface focus override");
  for (const selector of [
    ".skip-link:focus-visible",
    ".sidebar-shell :focus-visible",
    ".mobile-sheet :focus-visible",
    ".mobile-drawer > aside :focus-visible",
  ]) {
    assert.ok(rule[1].includes(selector), `missing dark-surface focus selector: ${selector}`);
  }
});

test("axe aplica reglas WCAG 2.2 AA y no descarta impactos moderados o menores", () => {
  for (const source of axeSources) {
    for (const call of source.matchAll(/withTags\(\[([^\]]+)\]\)/gu)) {
      const tags = call[1] ?? "";
      for (const tag of ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]) {
        assert.match(tags, new RegExp(`['\"]${tag}['\"]`, "u"));
      }
    }
    assert.doesNotMatch(source, /violations\.filter/u);
    assert.doesNotMatch(source, /\["serious", "critical"\]/u);
  }
});

test("el service worker nunca intercepta navegación, API o recursos privados", () => {
  assert.match(serviceWorkerSource, /request\.mode === "navigate"/);
  assert.match(serviceWorkerSource, /url\.pathname\.startsWith\("\/v1\/"\)/);
  assert.match(serviceWorkerSource, /url\.pathname\.startsWith\("\/api\/"\)/);
  assert.match(serviceWorkerSource, /PUBLIC_PATHS\.has\(url\.pathname\) \|\| url\.pathname\.startsWith\("\/_next\/static\/"\)/);
  const privateGuard = serviceWorkerSource.indexOf('request.mode === "navigate"');
  const responseInterception = serviceWorkerSource.indexOf("event.respondWith(");
  assert.ok(privateGuard >= 0 && responseInterception > privateGuard, "the private-resource guard must run before interception");
  assert.match(serviceWorkerSource, /"\/fonts\/report-sans-regular\.ttf"/);
  assert.match(serviceWorkerSource, /"\/fonts\/report-sans-bold\.ttf"/);
});
