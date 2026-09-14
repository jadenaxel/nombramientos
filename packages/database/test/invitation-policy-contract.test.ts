import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const invitationStore = readFileSync(path.join(packageRoot, "src", "invitation-store.ts"), "utf8");
const enterpriseAuthStore = readFileSync(path.join(packageRoot, "src", "enterprise-auth-store.ts"), "utf8");
const migration = readFileSync(
  path.join(packageRoot, "migrations", "control", "018_invitation_policy_readiness.sql"),
  "utf8",
);
const passwordlessEnrollmentMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "019_invitation_passwordless_enrollment.sql"),
  "utf8",
);
const passwordProvisioningMigration = readFileSync(
  path.join(packageRoot, "migrations", "control", "021_explicit_password_provisioning.sql"),
  "utf8",
);
const grants = readFileSync(path.join(packageRoot, "scripts", "migrate-control.ts"), "utf8");

describe("invitation identity-policy readiness contract", () => {
  it("serializes completion with policy activation and rejects passwordless or unready enforce policies", () => {
    const completion = invitationStore.slice(
      invitationStore.indexOf("public async complete"),
      invitationStore.indexOf("public async getAcceptanceStatus"),
    );
    expect(invitationStore).toContain('"POLICY_CONFLICT"');
    expect(completion).toContain("lockTenantIdentityPolicy(client, input.claim.tenantId)");
    expect(completion).toContain("bootstrapSession: {");
    expect(completion).not.toContain("$1,$2,$3,$4,$5,$6,$7\n");
    expect(enterpriseAuthStore).toContain("lockTenantIdentityPolicy(client, input.tenantId)");
    expect(enterpriseAuthStore).toContain("tenant_identity_policy:");
  });

  it("enforces the same readiness check at the SECURITY DEFINER membership activation boundary", () => {
    expect(migration).toContain("CREATE OR REPLACE FUNCTION complete_tenant_invitation_acceptance");
    expect(migration).toContain("pg_advisory_xact_lock");
    expect(migration).toContain("tenant_identity_policy:");
    expect(migration).toContain("NOT policy_record.allow_password");
    expect(migration).toContain("policy_record.enforcement_mode='enforce' AND policy_record.minimum_passkey_count > 0");
    expect(migration).toContain("tenant_invitation_identity_policy_readiness");
    expect(migration.indexOf("tenant_invitation_identity_policy_readiness"))
      .toBeLessThan(migration.indexOf("INSERT INTO public.platform_identities"));
  });

  it("issues only a database-bound short enrollment session for passwordless onboarding", () => {
    expect(passwordlessEnrollmentMigration).toContain("enrollment_source = 'invitation'");
    expect(passwordlessEnrollmentMigration).toContain("invitation_id uuid REFERENCES tenant_invitations");
    expect(passwordlessEnrollmentMigration).toContain("auth_sessions_invitation_enrollment_source_guard");
    expect(passwordlessEnrollmentMigration).toContain("invitation.status='accepted'");
    expect(grants).toContain("enrollment_source and invitation_id are intentionally absent");
    expect(grants).toContain("GRANT INSERT(id,token_hash,csrf_hash,identity_id,active_tenant_id");
    expect(passwordlessEnrollmentMigration).toContain("interval '10 minutes'");
    expect(passwordlessEnrollmentMigration).toContain("RETURNS TABLE(completed boolean, session_expires_at timestamptz)");
    expect(passwordlessEnrollmentMigration).toContain("'enrollment_only',NULL");
    expect(passwordlessEnrollmentMigration).toContain("'bootstrap',1,false,NULL,false");
    expect(grants).toContain(
      "uuid,uuid,uuid,integer,uuid,text,text,text,uuid,text,text,timestamptz,text,text,text",
    );
  });

  it("makes password provisioning explicit and decides it atomically from effective policy", () => {
    expect(passwordProvisioningMigration).toContain("password_provisioned boolean NOT NULL DEFAULT true");
    expect(passwordProvisioningMigration).toContain("policy_record.allow_password AND p_password_hash IS NULL");
    expect(passwordProvisioningMigration).toContain("tenant_invitation_password_required");
    expect(passwordProvisioningMigration).toContain("ELSE p_disabled_password_hash");
    expect(passwordProvisioningMigration).toContain("selected_password_hash,selected_password_provisioned");
    expect(passwordProvisioningMigration).toContain(
      "DROP FUNCTION complete_tenant_invitation_acceptance(\n  uuid,uuid,uuid,uuid,text,text,text\n)",
    );
    expect(passwordProvisioningMigration).toContain(
      "uuid,uuid,uuid,uuid,text,text,text,uuid,text,text,timestamptz,text,text\n)",
    );
    expect(passwordProvisioningMigration.indexOf("tenant_invitation_password_required"))
      .toBeLessThan(passwordProvisioningMigration.indexOf("INSERT INTO public.platform_identities"));
    expect(invitationStore).toContain('"PASSWORD_REQUIRED"');
    expect(invitationStore).toContain("disabledPasswordHash: string");
  });
});
