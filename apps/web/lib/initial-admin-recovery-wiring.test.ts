import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const apiSource = read("api.ts");
const browserSource = read("initial-admin-recovery-browser.ts");
const formSource = read("../components/nombramientos/initial-admin-onboarding-recovery-form.tsx");
const invitationAcceptSource = read("../components/nombramientos/invitation-accept-form.tsx");
const consoleSource = read("../components/nombramientos/initial-admin-recovery-console.tsx");
const platformSource = read("../components/nombramientos/platform-console.tsx");
const invitationsSource = read("../components/nombramientos/invitations-view.tsx");
const workspaceSource = read("../components/nombramientos/workspace-view.tsx");
const pageSource = read("../app/[locale]/auth/onboarding-recovery/page.tsx");
const securityCenterSource = read("../components/nombramientos/security-center.tsx");
const cssSource = read("../app/globals.css");

test("the governed control plane is fully wired with exact-source and operation-bound calls", () => {
  assert.match(platformSource, /InitialAdminRecoveryConsole/u);
  assert.match(workspaceSource, /currentIdentityId=\{session\.user\.id\}/u);
  assert.match(consoleSource, /item\.requesterIdentityId === currentIdentityId/u);
  assert.match(consoleSource, /ownRequest \? <Alert/u);
  assert.match(consoleSource, /api\.requestInitialAdminRecovery/u);
  assert.match(consoleSource, /api\.approveInitialAdminRecovery/u);
  assert.match(consoleSource, /api\.revokeInitialAdminRecovery/u);
  assert.match(apiSource, /\/v1\/platform\/initial-admin-recoveries\/candidates/u);
  assert.match(apiSource, /x-step-up-grant/u);
  assert.match(apiSource, /status: "finalization_pending" \| "enrollment_pending" \| "revoked"/u);
  assert.match(consoleSource, /result\.status === "revoked"/u);
  assert.match(consoleSource, /recovery\.console\.approvalRevokedBody/u);
  assert.match(apiSource, /body: JSON\.stringify\(body\),\s*idempotent: true/u);
  assert.match(consoleSource, /sourceFromQueueItem\(item\)/u);
});

test("the approver can copy but cannot navigate into the recipient recovery session", () => {
  assert.match(consoleSource, /navigator\.clipboard\.writeText/u);
  assert.match(consoleSource, /\/auth\/onboarding-recovery/u);
  assert.doesNotMatch(consoleSource, /<Link[\s\S]{0,500}\/auth\/onboarding-recovery/u);
  assert.doesNotMatch(consoleSource, /href=\{?[^\n]*\/auth\/onboarding-recovery/u);
  assert.match(consoleSource, /recipientDeviceWarning/u);
  assert.match(consoleSource, /window\.addEventListener\("pagehide", purge\)/u);
  assert.match(consoleSource, /Date\.parse\(oneTime\.expiresAt\) - Date\.now\(\)/u);
  assert.match(platformSource, /navigator\.clipboard\.writeText\(`\$\{invitationUrl\}\\n\$\{oneTime\.token\}`\)/u);
  assert.match(invitationsSource, /navigator\.clipboard\.writeText\(`\$\{invitationUrl\}\\n\$\{oneTime\.token\}`\)/u);
  assert.doesNotMatch(platformSource, /href=\{?[^\n]*\/auth\/invitation/u);
  assert.match(platformSource, /window\.addEventListener\("pagehide", purge\)/u);
  assert.match(invitationsSource, /window\.addEventListener\("pagehide", purge\)/u);
  assert.match(platformSource, /Date\.parse\(oneTime\.expiresAt\) - Date\.now\(\)/u);
  assert.match(invitationsSource, /Date\.parse\(oneTime\.expiresAt\) - Date\.now\(\)/u);
});

test("the public flow prepares context, keeps the bearer volatile, and correlates the installed session", () => {
  assert.match(pageSource, /InitialAdminOnboardingRecoveryForm/u);
  assert.match(formSource, /redeemInitialAdminRecoverySafely/u);
  assert.match(apiSource, /prepareInitialAdminRecoveryContext[\s\S]{0,220}body: "\{\}"[\s\S]{0,100}csrf: false/u);
  assert.match(browserSource, /candidate\.csrfToken === canonicalResponse\.csrfToken/u);
  assert.match(browserSource, /candidate\.user\.id === canonicalResponse\.user\.id/u);
  assert.match(browserSource, /candidate\.tenant\.id === canonicalResponse\.tenant\.id/u);
  assert.match(browserSource, /transport\.redeem\(recoveryId, token\)/u);
  assert.match(browserSource, /transport\.redeem\(recoveryId\)/u);
  assert.match(browserSource, /crypto\.subtle\.digest\("SHA-256"/u);
  assert.doesNotMatch(formSource, /localStorage|sessionStorage|console\.(?:log|error|warn|debug|info)/u);
  assert.doesNotMatch(consoleSource, /localStorage|sessionStorage|console\.(?:log|error|warn|debug|info)/u);
  assert.doesNotMatch(formSource, /URLSearchParams|\?token=|\?recovery/u);
  assert.match(formSource, /window\.addEventListener\("pagehide", purge\)/u);
  assert.match(formSource, /setRecoveryId\(""\)/u);
  assert.match(formSource, /setToken\(""\)/u);
  assert.match(invitationAcceptSource, /window\.addEventListener\("pagehide", purge\)/u);
  for (const setter of ["setToken", "setEmail", "setDisplayName", "setPassword"]) {
    assert.match(invitationAcceptSource, new RegExp(`${setter}\\(\"\"\\)`, "u"));
  }
});

test("mobile, PC, TOTP fallback, accessibility, and responsive presentation remain first-class", () => {
  assert.match(formSource, /continueEnrollment\("passkey-onboarding-title"\)/u);
  assert.match(formSource, /continueEnrollment\("totp-fallback"\)/u);
  assert.match(securityCenterSource, /id="totp-fallback"/u);
  assert.match(formSource, /aria-live="polite"/u);
  assert.match(formSource, /visibilitychange/u);
  assert.match(cssSource, /@media\(max-width:390px\)/u);
  assert.match(cssSource, /@media\(max-width:1023px\)\{\.app-grid\{grid-template-columns:minmax\(0,1fr\)\}/u);
  assert.match(cssSource, /\.platform-console\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0/u);
  assert.match(cssSource, /\.initial-admin-recovery-console\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0/u);
  assert.match(cssSource, /\.recovery-queue-list\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0/u);
  assert.match(cssSource, /\.recovery-queue-list>article\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0/u);
  assert.match(cssSource, /\.recovery-approval-panel\{display:grid;grid-template-columns:minmax\(0,1fr\);min-width:0/u);
  assert.match(cssSource, /recovery-enrollment-actions/u);
  assert.match(cssSource, /\.initial-admin-recovery-console input,\.initial-admin-recovery-console select\{min-height:44px;font-size:1rem\}/u);
  assert.match(cssSource, /\.recovery-one-time \[data-slot=alert-description\]\{min-width:0;justify-items:stretch/u);
  assert.match(cssSource, /\.recovery-one-time code\{[^}]*width:100%;min-width:0;[^}]*word-break:break-all/u);
  assert.match(cssSource, /prefers-reduced-motion:reduce/u);
});

function read(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8");
}
