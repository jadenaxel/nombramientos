import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  CANDIDACY_REVIEW_REASON_CODES,
  INVITATION_REVOKE_REASON_CODES,
  KEY_ROTATION_REASON_CODES,
  MEMBER_ARCHIVE_REASON_CODES,
  OFFICE_PROCESS_APPLICABILITY_REASON_CODES,
  SESSION_DECISION_CODES,
  normalizeAllowedReasonCode,
  normalizeNonSensitiveReasonCode,
} from "../src/reason-code.js";

describe("non-sensitive operational reason codes", () => {
  it("canonicalizes bounded machine codes and rejects prose or embedded details", () => {
    expect(normalizeNonSensitiveReasonCode("  SCHEDULED_ROTATION  ")).toBe("SCHEDULED_ROTATION");
    expect(normalizeNonSensitiveReasonCode("AB3")).toBe("AB3");
    expect(normalizeNonSensitiveReasonCode("Scheduled rotation for pastor Alice")).toBeNull();
    expect(normalizeNonSensitiveReasonCode("MEMBER-HAS-SENSITIVE-CONDITION")).toBeNull();
    expect(normalizeNonSensitiveReasonCode(`A${"B".repeat(64)}`)).toBeNull();
  });

  it("rejects well-formed uppercase tokens outside each operation vocabulary", () => {
    for (const allowed of [
      MEMBER_ARCHIVE_REASON_CODES,
      KEY_ROTATION_REASON_CODES,
      INVITATION_REVOKE_REASON_CODES,
      CANDIDACY_REVIEW_REASON_CODES,
      SESSION_DECISION_CODES,
      OFFICE_PROCESS_APPLICABILITY_REASON_CODES,
    ]) {
      expect(normalizeAllowedReasonCode("PERSONA_TIENE_DIAGNOSTICO", allowed)).toBeNull();
    }
    expect(normalizeAllowedReasonCode("  SCHEDULED_ROTATION  ", KEY_ROTATION_REASON_CODES)).toBe("SCHEDULED_ROTATION");
  });

  it("redacts legacy prose and constrains every mutable key-reason column", () => {
    const migration = readFileSync(new URL("../migrations/tenant/023_non_sensitive_reason_codes.sql", import.meta.url), "utf8");
    for (const column of [
      "custodian_device_keys.revocation_reason",
      "e2ee_key_devices.revoke_reason",
      "e2ee_key_generations.rotation_reason",
      "e2ee_key_grants.revoke_reason",
    ]) expect(migration).toContain(column);
    for (const constraint of [
      "custodian_device_keys_reason_code_allowed",
      "e2ee_key_devices_reason_code_allowed",
      "e2ee_key_generations_reason_code_allowed",
      "e2ee_key_grants_reason_code_allowed",
      "session_decisions_decision_code_allowed",
      "candidacy_reviews_reason_code_allowed",
      "member_eligibility_pause_resolution_reason_allowed",
      "assignment_transitions_reason_code_allowed",
    ]) expect(migration).toContain(constraint);
    expect(migration).not.toContain("PERSONA_TIENE_DIAGNOSTICO");
    expect(migration).toContain("NOT VALID");
    expect(migration.match(/\^\[A-Z\]\[A-Z0-9_\]\{2,63\}\$/g)?.length).toBeGreaterThanOrEqual(4);

    const controlMigration = readFileSync(new URL("../migrations/control/010_invitation_reason_codes.sql", import.meta.url), "utf8");
    expect(controlMigration).toContain("UPDATE tenant_invitations");
    expect(controlMigration).toContain("SECURITY_RESPONSE");
    expect(controlMigration).toContain("tenant_invitations_reason_code_format");
    expect(controlMigration).toContain("tenant_invitations_reason_code_allowed");
  });

  it("upgrades the closed candidacy vocabulary with only the internal list-confirmation pair", () => {
    const migration = readFileSync(new URL("../migrations/tenant/026_candidacy_review_internal_reason_code.sql", import.meta.url), "utf8");
    expect(migration).toContain("DROP CONSTRAINT candidacy_reviews_reason_code_allowed");
    expect(migration).toContain("to_state = 'CONFIRMED_FOR_BALLOT' AND reason_code = 'FINAL_LIST_CONFIRMED'");
    expect(migration).toContain("NOT VALID");
    expect(migration).toContain("VALIDATE CONSTRAINT candidacy_reviews_reason_code_allowed");
    expect(migration).not.toContain("PERSONA_TIENE_DIAGNOSTICO");
  });
});
