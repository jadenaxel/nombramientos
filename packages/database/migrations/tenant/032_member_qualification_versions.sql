-- Independent documentary register for training, ordination, certifications
-- and other qualifications. Nothing in this table changes member eligibility,
-- candidacies, assignments, rounds or election results.
CREATE TABLE member_qualification_versions (
  qualification_id uuid NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  qualification_type text NOT NULL CHECK (qualification_type IN (
    'training', 'ordination', 'certification', 'other'
  )),
  status text NOT NULL CHECK (status IN (
    'pending', 'verified', 'expired', 'revoked'
  )),
  effective_on date NOT NULL,
  expires_on date,
  details_envelope jsonb,
  details_content_hash text,
  reviewer_identity_id uuid NOT NULL,
  supersedes_version integer,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (qualification_id, version),
  UNIQUE (qualification_id, version, member_id),
  FOREIGN KEY (qualification_id, supersedes_version, member_id)
    REFERENCES member_qualification_versions(qualification_id, version, member_id)
    ON DELETE RESTRICT,
  CONSTRAINT member_qualification_dates_ordered CHECK (
    expires_on IS NULL OR expires_on >= effective_on
  ),
  CONSTRAINT member_qualification_expired_has_date CHECK (
    status <> 'expired' OR expires_on IS NOT NULL
  ),
  CONSTRAINT member_qualification_details_pair CHECK (
    (details_envelope IS NULL) = (details_content_hash IS NULL)
    AND (
      details_content_hash IS NULL
      OR details_content_hash ~ '^sha256:[0-9a-f]{64}$'
    )
  ),
  CONSTRAINT member_qualification_linear_version CHECK (
    (version = 1 AND supersedes_version IS NULL)
    OR (version > 1 AND supersedes_version = version - 1)
  )
);

CREATE INDEX member_qualification_versions_member_history
  ON member_qualification_versions(member_id, qualification_id, version DESC);

CREATE FUNCTION reject_member_qualification_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog,public
AS $$
BEGIN
  RAISE EXCEPTION 'member qualification versions are append-only'
    USING ERRCODE = '55000';
END
$$;

REVOKE ALL ON FUNCTION reject_member_qualification_version_mutation() FROM PUBLIC;

CREATE TRIGGER member_qualification_versions_immutable_rows
BEFORE UPDATE OR DELETE ON member_qualification_versions
FOR EACH ROW EXECUTE FUNCTION reject_member_qualification_version_mutation();

CREATE TRIGGER member_qualification_versions_immutable_truncate
BEFORE TRUNCATE ON member_qualification_versions
FOR EACH STATEMENT EXECUTE FUNCTION reject_member_qualification_version_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON member_qualification_versions FROM PUBLIC;

INSERT INTO permissions(code, description) VALUES
  ('member.qualification.read', 'Read independent member qualification records'),
  ('member.qualification.manage', 'Append independent member qualification versions')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code, delegable)
SELECT role.id, permission.code, true
  FROM roles role
  JOIN permissions permission ON permission.code IN (
    'member.qualification.read', 'member.qualification.manage'
  )
 WHERE role.code = 'CHURCH_ADMIN'
ON CONFLICT (role_id, permission_code)
DO UPDATE SET delegable = EXCLUDED.delegable;

INSERT INTO role_permissions(role_id, permission_code, delegable)
SELECT role.id, permission.code, false
  FROM roles role
  JOIN permissions permission ON permission.code = 'member.qualification.read'
 WHERE role.code IN ('COMMITTEE_CHAIR', 'COMMITTEE_SECRETARY')
ON CONFLICT (role_id, permission_code) DO NOTHING;

COMMENT ON TABLE member_qualification_versions IS
  'Append-only, independently reviewed documentary records. They never confer, revoke or imply nomination eligibility or election.';
COMMENT ON COLUMN member_qualification_versions.details_envelope IS
  'Optional E2EE title/issuer object bound to tenant, member, record, metadata and version through exact AAD.';
COMMENT ON COLUMN member_qualification_versions.reviewer_identity_id IS
  'Authenticated tenant identity that reviewed and appended this exact version.';
COMMENT ON COLUMN member_qualification_versions.effective_on IS
  'Civil effective date; never converted through a device timezone.';
COMMENT ON COLUMN member_qualification_versions.expires_on IS
  'Optional civil expiration date. Status changes remain explicit and are never inferred automatically.';
