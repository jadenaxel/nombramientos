ALTER TABLE cycle_sessions
  ADD COLUMN actual_started_at timestamptz,
  ADD COLUMN actual_closed_at timestamptz;

CREATE UNIQUE INDEX cycle_sessions_one_in_progress
  ON cycle_sessions(cycle_id) WHERE status='in_progress';

CREATE TABLE session_attendance (
  session_id uuid NOT NULL REFERENCES cycle_sessions(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL,
  member_id uuid REFERENCES members(id) ON DELETE RESTRICT,
  display_envelope_snapshot jsonb,
  photo_snapshot jsonb,
  presence_status text NOT NULL CHECK (presence_status IN ('PRESENT','REMOTE','ABSENT','EXCUSED')),
  advisory boolean NOT NULL DEFAULT false,
  voting_right boolean NOT NULL DEFAULT false,
  substitute_for_identity_id uuid,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  recorded_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (session_id,identity_id),
  CHECK (substitute_for_identity_id IS NULL OR substitute_for_identity_id <> identity_id),
  CHECK (NOT advisory OR NOT voting_right),
  CHECK (presence_status IN ('PRESENT','REMOTE') OR NOT voting_right),
  CHECK (substitute_for_identity_id IS NULL OR (presence_status IN ('PRESENT','REMOTE') AND NOT advisory))
);

CREATE UNIQUE INDEX session_attendance_one_substitute_per_identity
  ON session_attendance(session_id,substitute_for_identity_id)
  WHERE substitute_for_identity_id IS NOT NULL;

CREATE TABLE session_agenda_items (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES cycle_sessions(id) ON DELETE RESTRICT,
  position integer NOT NULL CHECK (position > 0),
  title text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 240),
  process_id uuid REFERENCES office_processes(id) ON DELETE RESTRICT,
  notes_envelope jsonb,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','in_progress','decided','deferred')),
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (session_id,position),
  UNIQUE (session_id,id)
);

CREATE TABLE session_decisions (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES cycle_sessions(id) ON DELETE RESTRICT,
  agenda_item_id uuid NOT NULL,
  decision_code text NOT NULL CHECK (decision_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  outcome text NOT NULL CHECK (outcome IN ('APPROVED','REJECTED','DEFERRED','RECORDED')),
  evidence_envelope jsonb,
  recorded_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (agenda_item_id),
  FOREIGN KEY (session_id,agenda_item_id)
    REFERENCES session_agenda_items(session_id,id) ON DELETE RESTRICT
);

COMMENT ON TABLE session_decisions IS
  'Institutional decisions are inseparably linked to a session agenda item; assignment transitions may additionally reference the same session.';

CREATE OR REPLACE FUNCTION preserve_session_attendance_snapshots()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF ROW(NEW.member_id,NEW.display_envelope_snapshot,NEW.photo_snapshot,NEW.created_at)
     IS DISTINCT FROM ROW(OLD.member_id,OLD.display_envelope_snapshot,OLD.photo_snapshot,OLD.created_at) THEN
    RAISE EXCEPTION 'session attendance identity snapshots are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER session_attendance_preserve_snapshots
BEFORE UPDATE ON session_attendance
FOR EACH ROW EXECUTE FUNCTION preserve_session_attendance_snapshots();

REVOKE ALL ON FUNCTION preserve_session_attendance_snapshots() FROM PUBLIC;
