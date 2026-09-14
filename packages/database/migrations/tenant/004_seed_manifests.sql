CREATE TABLE seed_manifests (
  seed_id text PRIMARY KEY,
  version integer NOT NULL CHECK (version > 0),
  fixture_hash text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE assignments
  ADD COLUMN independent boolean NOT NULL DEFAULT true,
  ADD COLUMN linked_to_assignment_id uuid REFERENCES assignments(id) ON DELETE RESTRICT;

ALTER TABLE assignments
  ADD CONSTRAINT assignments_responsibility_link_check CHECK (
    (independent AND linked_to_assignment_id IS NULL)
    OR (NOT independent AND linked_to_assignment_id IS NOT NULL)
  );

ALTER TABLE committee_memberships
  ADD COLUMN pastoral_capacity boolean NOT NULL DEFAULT false;

ALTER TABLE rounds
  ADD COLUMN vacancy_id uuid REFERENCES vacancies(id) ON DELETE RESTRICT,
  ADD COLUMN max_proposal_selections integer NOT NULL DEFAULT 3 CHECK (max_proposal_selections > 0),
  ADD COLUMN max_ballot_selections integer NOT NULL DEFAULT 1 CHECK (max_ballot_selections > 0);

UPDATE rounds
   SET max_proposal_selections = CASE WHEN submission_kind='proposal' THEN max_selections ELSE 3 END,
       max_ballot_selections = CASE WHEN submission_kind='vote' THEN max_selections ELSE 1 END;

CREATE TABLE cycle_member_snapshots (
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  member_version integer NOT NULL CHECK (member_version > 0),
  eligibility_status text NOT NULL CHECK (eligibility_status IN ('eligible', 'ineligible', 'review')),
  available boolean NOT NULL,
  profile_envelope jsonb NOT NULL,
  eligibility_envelope jsonb,
  frozen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (cycle_id, member_id)
);

ALTER TABLE participation_receipts
  ADD COLUMN kind text;

UPDATE participation_receipts receipt
   SET kind = submission.kind
  FROM encrypted_submissions submission
 WHERE submission.id = receipt.submission_id;

ALTER TABLE participation_receipts
  ALTER COLUMN kind SET NOT NULL,
  ADD CONSTRAINT participation_receipts_kind_check CHECK (kind IN ('proposal', 'vote'));

ALTER TABLE participation_receipts
  DROP CONSTRAINT participation_receipts_round_id_elector_identity_id_key;

ALTER TABLE participation_receipts
  ADD CONSTRAINT participation_receipts_round_elector_kind_key
  UNIQUE (round_id, elector_identity_id, kind);

COMMENT ON TABLE seed_manifests IS
  'Non-secret installation markers. Production tenants normally keep this table empty.';
