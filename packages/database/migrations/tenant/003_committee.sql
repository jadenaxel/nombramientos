CREATE TABLE committee_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL,
  member_id uuid REFERENCES members(id) ON DELETE RESTRICT,
  display_envelope jsonb NOT NULL,
  role_code text NOT NULL CHECK (role_code IN ('chair', 'pastor', 'secretary', 'member', 'custodian', 'advisor')),
  voting_right boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'withdrawn', 'substitute')),
  joined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  left_at timestamptz,
  UNIQUE (cycle_id, identity_id)
);

CREATE INDEX committee_memberships_cycle ON committee_memberships(cycle_id, status);
