-- Invitation revocation metadata must never become a free-text PII channel.
-- Preserve immutable audit history, but redact prose in the mutable invitation
-- lifecycle column before enforcing the machine-code format.
UPDATE tenant_invitations
   SET revocation_reason = 'SECURITY_RESPONSE'
 WHERE revocation_reason IS NOT NULL
   AND revocation_reason NOT IN ('ADMIN_ACCESS_REVOCATION','SECURITY_RESPONSE','INVITATION_REPLACED');

ALTER TABLE tenant_invitations
  DROP CONSTRAINT tenant_invitations_revocation_reason_check;

ALTER TABLE tenant_invitations
  ADD CONSTRAINT tenant_invitations_reason_code_format
  CHECK (revocation_reason IS NULL OR revocation_reason ~ '^[A-Z][A-Z0-9_]{2,63}$');

ALTER TABLE tenant_invitations
  ADD CONSTRAINT tenant_invitations_reason_code_allowed
  CHECK (revocation_reason IS NULL OR revocation_reason IN (
    'ADMIN_ACCESS_REVOCATION','SECURITY_RESPONSE','INVITATION_REPLACED'
  ));

COMMENT ON COLUMN tenant_invitations.revocation_reason IS
  'Non-sensitive machine reason code; human justification must be encrypted elsewhere.';
