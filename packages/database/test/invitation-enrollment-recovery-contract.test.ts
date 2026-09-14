import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const migration024 = readFileSync(path.resolve(
  process.cwd(),
  "migrations/control/024_invitation_grantor_revocation_boundary.sql",
), "utf8");

const migration026 = readFileSync(path.resolve(
  process.cwd(),
  "migrations/control/026_invitation_enrollment_recovery_qualification.sql",
), "utf8");

describe("invitation enrollment recovery qualification", () => {
  it("replaces only the existing SECURITY DEFINER boundary without widening its ACL", () => {
    expect(migration026).toContain("CREATE OR REPLACE FUNCTION recover_tenant_invitation_enrollment_session(");
    expect(migration026).toContain(
      "RETURNS TABLE(recovered boolean,identity_id uuid,tenant_id uuid,session_expires_at timestamptz)",
    );
    expect(migration026).toContain("LANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog");
    expect(migration026).toContain(
      "REVOKE ALL ON FUNCTION recover_tenant_invitation_enrollment_session(\n  uuid,text,text,text,uuid,text,text,timestamptz,text,text\n) FROM PUBLIC",
    );
    expect(migration026).not.toMatch(/\b(?:DROP|ALTER)\s+(?:TABLE|FUNCTION)\b/iu);
    expect(migration026).not.toMatch(/\bGRANT\b/iu);
  });

  it("qualifies the ambiguous rotation predicate and preserves exact recovery fences", () => {
    expect(migration026).toContain("UPDATE public.auth_sessions session");
    expect(migration026).toContain("WHERE session.invitation_id=p_invitation_id");
    expect(migration026).toContain("AND session.identity_id=invitation_record.identity_id");
    expect(migration026).toContain("AND session.enrollment_source='invitation'");
    expect(migration026).toContain("AND session.revoked_at IS NULL");
    expect(migration026).not.toMatch(/\n\s+AND identity_id=invitation_record\.identity_id/u);

    for (const fence of [
      "invitation.token_hash=encode(sha256(convert_to(p_token,'UTF8')),'hex')",
      "invitation.acceptance_recovery_hash=",
      "invitation.normalized_email=p_normalized_email",
      "invitation.status='accepted'",
      "invitation.accepted_at>clock_timestamp()-interval '24 hours'",
      "identity.mfa_enabled=false",
      "identity.passkey_enabled=false",
      "credential.revoked_at IS NULL",
    ]) expect(migration026).toContain(fence);

    const original = recoveryFunctionDefinition(migration024, "CREATE FUNCTION");
    const replacement = recoveryFunctionDefinition(migration026, "CREATE OR REPLACE FUNCTION")
      .replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION")
      .replace("UPDATE public.auth_sessions session", "UPDATE public.auth_sessions")
      .replaceAll("session.invitation_id", "invitation_id")
      .replaceAll("session.identity_id", "identity_id")
      .replaceAll("session.enrollment_source", "enrollment_source")
      .replaceAll("session.revoked_at", "revoked_at");
    expect(replacement).toBe(original);
  });

  it("rotates only invitation enrollment sessions and mints the bounded enrollment-only replacement atomically", () => {
    expect(migration026.indexOf("UPDATE public.auth_sessions session")).toBeLessThan(
      migration026.indexOf("INSERT INTO public.auth_sessions("),
    );
    expect(migration026).toContain("revoke_reason='invitation_enrollment_rotated'");
    expect(migration026).toContain("clock_timestamp() + interval '10 minutes'");
    expect(migration026).toContain("'enrollment_only',NULL,'bootstrap',1,false,NULL,false,10,issued_expires_at");
    expect(migration026).toContain("p_user_agent_hash,p_ip_prefix_hash,'invitation',p_invitation_id");
    expect(migration026).toContain(
      "RETURN QUERY SELECT true,invitation_record.identity_id,invitation_record.tenant_id,issued_expires_at",
    );
  });
});

function recoveryFunctionDefinition(source: string, declaration: string): string {
  const start = source.indexOf(`${declaration} recover_tenant_invitation_enrollment_session(`);
  if (start < 0) throw new Error("Invitation recovery function declaration is missing");
  const end = source.indexOf("\n$$;", start);
  if (end < 0) throw new Error("Invitation recovery function terminator is missing");
  return source.slice(start, end + "\n$$;".length);
}
