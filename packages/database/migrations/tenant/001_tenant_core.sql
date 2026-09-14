CREATE TABLE tenant_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  tenant_id uuid NOT NULL UNIQUE,
  display_name text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('demo', 'real')),
  timezone text NOT NULL,
  locale text NOT NULL CHECK (locale IN ('es', 'en', 'fr')),
  setup_state text NOT NULL DEFAULT 'not_started' CHECK (setup_state IN ('not_started', 'in_progress', 'ready')),
  catalog_version text NOT NULL DEFAULT 'working-2026-09',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE permissions (
  code text PRIMARY KEY,
  description text NOT NULL
);

CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE,
  name_i18n jsonb NOT NULL,
  system_role boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE role_permissions (
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_code text NOT NULL REFERENCES permissions(code) ON DELETE RESTRICT,
  PRIMARY KEY (role_id, permission_code)
);

CREATE TABLE role_bindings (
  identity_id uuid NOT NULL,
  role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  granted_by_identity_id uuid,
  revoked_at timestamptz,
  PRIMARY KEY (identity_id, role_id)
);

CREATE INDEX role_bindings_active_identity ON role_bindings(identity_id)
WHERE revoked_at IS NULL;

CREATE TABLE device_key_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id uuid NOT NULL,
  device_id uuid NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  tenant_key_id text NOT NULL,
  kdf jsonb NOT NULL,
  wrap jsonb NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'superseded')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  UNIQUE (identity_id, device_id, version)
);

CREATE UNIQUE INDEX device_key_grants_one_active
ON device_key_grants(identity_id, device_id)
WHERE status = 'active';

CREATE TABLE members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  stable_code text NOT NULL UNIQUE,
  profile_envelope jsonb NOT NULL,
  eligibility_envelope jsonb,
  eligibility_status text NOT NULL DEFAULT 'eligible' CHECK (eligibility_status IN ('eligible', 'ineligible', 'review')),
  available boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX members_active_id ON members(id) WHERE archived_at IS NULL;

CREATE TABLE departments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  canonical_code text NOT NULL UNIQUE,
  names jsonb NOT NULL,
  parent_id uuid REFERENCES departments(id) ON DELETE RESTRICT,
  local_extension boolean NOT NULL DEFAULT false,
  catalog_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  sort_order integer NOT NULL DEFAULT 0,
  version integer NOT NULL DEFAULT 1
);

CREATE TABLE offices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  department_id uuid REFERENCES departments(id) ON DELETE RESTRICT,
  canonical_code text NOT NULL UNIQUE,
  names jsonb NOT NULL,
  appointment_mechanism text NOT NULL,
  cardinality integer NOT NULL DEFAULT 1 CHECK (cardinality > 0),
  local_extension boolean NOT NULL DEFAULT false,
  catalog_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  active boolean NOT NULL DEFAULT true,
  version integer NOT NULL DEFAULT 1
);

CREATE TABLE election_cycles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  status text NOT NULL CHECK (status IN ('draft', 'active', 'closed', 'archived')),
  locale text NOT NULL CHECK (locale IN ('es', 'en', 'fr')),
  timezone text NOT NULL,
  term_start date NOT NULL,
  term_end date NOT NULL,
  normative_version text NOT NULL,
  eligible_reference_count integer NOT NULL DEFAULT 0 CHECK (eligible_reference_count >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (term_end >= term_start)
);

CREATE UNIQUE INDEX election_cycles_one_active ON election_cycles((true))
WHERE status = 'active';

CREATE TABLE vacancies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  office_id uuid NOT NULL REFERENCES offices(id) ON DELETE RESTRICT,
  ordinal integer NOT NULL CHECK (ordinal > 0),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'recommended', 'accepted', 'elected', 'vacant')),
  UNIQUE (cycle_id, office_id, ordinal)
);

CREATE TABLE rounds (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id uuid NOT NULL REFERENCES election_cycles(id) ON DELETE RESTRICT,
  office_id uuid NOT NULL REFERENCES offices(id) ON DELETE RESTRICT,
  phase text NOT NULL CHECK (phase IN (
    'PENDIENTE', 'CONFIGURADO', 'PROPUESTAS_ABIERTAS', 'PROPUESTAS_CERRADAS',
    'DEPURACION', 'LISTA_CONFIRMADA', 'VOTACION_ABIERTA', 'VOTACION_CERRADA',
    'ESCRUTINIO', 'RESULTADO_INTERNO', 'RECOMENDACION_CONFIRMADA', 'CERRADO',
    'PAUSADO', 'SIN_CANDIDATOS', 'DESEMPATE_PENDIENTE', 'ANULADO',
    'VACANTE_PENDIENTE'
  )),
  submission_kind text NOT NULL CHECK (submission_kind IN ('proposal', 'vote')),
  vacancies integer NOT NULL CHECK (vacancies > 0),
  max_selections integer NOT NULL CHECK (max_selections > 0),
  candidate_set_hash text NOT NULL,
  rules_hash text NOT NULL,
  version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  opened_at timestamptz,
  closed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX rounds_one_open_per_cycle ON rounds(cycle_id)
WHERE phase IN (
  'PROPUESTAS_ABIERTAS', 'PROPUESTAS_CERRADAS', 'DEPURACION', 'LISTA_CONFIRMADA',
  'VOTACION_ABIERTA', 'VOTACION_CERRADA', 'ESCRUTINIO', 'RESULTADO_INTERNO',
  'RECOMENDACION_CONFIRMADA', 'PAUSADO'
);

CREATE TABLE round_elector_snapshots (
  round_id uuid NOT NULL REFERENCES rounds(id) ON DELETE RESTRICT,
  identity_id uuid NOT NULL,
  can_submit boolean NOT NULL DEFAULT true,
  recused boolean NOT NULL DEFAULT false,
  PRIMARY KEY (round_id, identity_id)
);

CREATE TABLE candidate_snapshots (
  round_id uuid NOT NULL REFERENCES rounds(id) ON DELETE RESTRICT,
  candidate_id uuid NOT NULL,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  display_envelope jsonb NOT NULL,
  eligible boolean NOT NULL,
  visible_order integer NOT NULL,
  already_assigned_count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (round_id, candidate_id),
  UNIQUE (round_id, member_id),
  UNIQUE (round_id, visible_order)
);

CREATE TABLE encrypted_submissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  round_id uuid NOT NULL REFERENCES rounds(id) ON DELETE RESTRICT,
  elector_identity_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('proposal', 'vote')),
  envelope jsonb NOT NULL,
  content_hash text NOT NULL,
  round_version integer NOT NULL,
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (round_id, elector_identity_id, kind)
);

CREATE TABLE participation_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id uuid NOT NULL UNIQUE REFERENCES encrypted_submissions(id) ON DELETE RESTRICT,
  round_id uuid NOT NULL REFERENCES rounds(id) ON DELETE RESTRICT,
  elector_identity_id uuid NOT NULL,
  content_hash text NOT NULL,
  received_at timestamptz NOT NULL,
  UNIQUE (round_id, elector_identity_id)
);

CREATE TABLE member_import_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id uuid NOT NULL,
  source_fingerprint text NOT NULL,
  state text NOT NULL CHECK (state IN ('previewed', 'committing', 'completed', 'failed')),
  row_count integer NOT NULL CHECK (row_count >= 0),
  preview_envelopes jsonb NOT NULL,
  summary jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  UNIQUE (identity_id, source_fingerprint)
);

CREATE TABLE assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vacancy_id uuid NOT NULL REFERENCES vacancies(id) ON DELETE RESTRICT,
  member_id uuid NOT NULL REFERENCES members(id) ON DELETE RESTRICT,
  state text NOT NULL CHECK (state IN (
    'PROPUESTA_INTERNA', 'ACEPTACION_PENDIENTE', 'ACEPTADA', 'PRESENTADA_A_IGLESIA',
    'ELEGIDA_POR_IGLESIA', 'VIGENTE', 'FINALIZADA', 'DECLINADA',
    'DEVUELTA_A_COMISION', 'RETIRADA', 'SUSTITUIDA'
  )),
  version integer NOT NULL DEFAULT 1,
  effective boolean NOT NULL DEFAULT true,
  consent_status text CHECK (consent_status IN ('PENDING','CONTACTED','ACCEPTED','DECLINED','WITHDRAWN')),
  congregational_outcome text CHECK (congregational_outcome IN ('ELECTED','RETURNED_TO_COMMITTEE','NOT_ELECTED','DEFERRED')),
  consent_envelope jsonb,
  congregational_decision jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX assignments_one_effective_vacancy ON assignments(vacancy_id)
WHERE effective;

CREATE TABLE report_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  report_type text NOT NULL,
  audience text NOT NULL CHECK (audience IN ('committee', 'auditor', 'church')),
  locale text NOT NULL CHECK (locale IN ('es', 'en', 'fr')),
  format text NOT NULL CHECK (format IN ('pdf', 'xlsx', 'csv', 'html')),
  filters jsonb NOT NULL,
  artifact_envelope jsonb,
  artifact_bytes bytea,
  artifact_sha256 text,
  filename text,
  media_type text,
  state text NOT NULL CHECK (state IN ('queued', 'ready', 'failed', 'expired')),
  requested_by_identity_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  ready_at timestamptz
);

CREATE TABLE idempotency_records (
  identity_id uuid NOT NULL,
  operation text NOT NULL,
  idempotency_key uuid NOT NULL,
  request_hash text NOT NULL,
  response_status integer,
  response_body jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '24 hours'),
  PRIMARY KEY (identity_id, operation, idempotency_key)
);

CREATE TABLE outbox_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  audience text NOT NULL,
  event_type text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id uuid,
  payload jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz
);

CREATE INDEX outbox_unpublished ON outbox_events(sequence) WHERE published_at IS NULL;

CREATE TABLE audit_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_identity_id uuid,
  action text NOT NULL,
  entity_type text,
  entity_id text,
  result text NOT NULL CHECK (result IN ('success', 'denied', 'failure')),
  request_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  previous_hash text,
  event_hash text NOT NULL
);

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;

INSERT INTO permissions(code, description) VALUES
  ('tenant.settings.manage', 'Manage tenant settings'),
  ('member.read', 'Read authorized member envelopes'),
  ('member.manage', 'Create and update member envelopes'),
  ('member.eligibility.manage', 'Manage member eligibility'),
  ('member.photo.manage', 'Manage member photographs'),
  ('member.import', 'Preview and commit member imports'),
  ('committee.manage', 'Manage the committee'),
  ('catalog.manage', 'Manage institutional catalog extensions'),
  ('cycle.manage', 'Manage election cycles'),
  ('proposal.open', 'Open proposal rounds'),
  ('proposal.close', 'Close proposal rounds'),
  ('proposal.submit', 'Submit a proposal as a frozen elector'),
  ('participation.nominal.read', 'Read nominal participation'),
  ('candidate.review', 'Review candidates'),
  ('ballot.open', 'Open ballot rounds'),
  ('ballot.close', 'Close ballot rounds'),
  ('ballot.submit', 'Submit a ballot as a frozen elector'),
  ('tally.custody', 'Access tally custody operations'),
  ('tally.recount', 'Perform an authorized recount'),
  ('aggregate.publish', 'Publish aggregate results'),
  ('aggregate.read', 'Read aggregate results'),
  ('consent.record', 'Record candidate consent'),
  ('congregational-decision.record', 'Record a congregational decision'),
  ('organigram.read', 'Read the organization chart'),
  ('report.read', 'Read report metadata'),
  ('report.export', 'Generate and export reports'),
  ('private-note.read', 'Read authorized private notes'),
  ('audit.read', 'Read sanitized tenant audit metadata'),
  ('role.manage', 'Manage tenant roles'),
  ('recovery.activate', 'Activate key recovery or rotate a device grant')
ON CONFLICT (code) DO NOTHING;

INSERT INTO roles(code, name_i18n, system_role) VALUES
  ('CHURCH_ADMIN', '{"es":"Administrador de iglesia","en":"Church administrator","fr":"Administrateur de l’église"}', true),
  ('COMMITTEE_CHAIR', '{"es":"Presidente de junta","en":"Committee chair","fr":"Président de la commission"}', true),
  ('COMMITTEE_SECRETARY', '{"es":"Secretario de junta","en":"Committee secretary","fr":"Secrétaire de la commission"}', true),
  ('COMMITTEE_MEMBER', '{"es":"Miembro de junta","en":"Committee member","fr":"Membre de la commission"}', true),
  ('TALLY_CUSTODIAN', '{"es":"Custodio de escrutinio","en":"Tally custodian","fr":"Dépositaire du dépouillement"}', true),
  ('AUDITOR', '{"es":"Auditor","en":"Auditor","fr":"Auditeur"}', true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'tenant.settings.manage','member.read','member.manage','member.eligibility.manage',
  'member.photo.manage','member.import','committee.manage','catalog.manage','cycle.manage',
  'proposal.open','proposal.close','participation.nominal.read','candidate.review',
  'ballot.open','ballot.close','aggregate.read','consent.record',
  'congregational-decision.record','organigram.read','report.read','report.export',
  'private-note.read','audit.read','role.manage','recovery.activate'
) WHERE r.code = 'CHURCH_ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'member.read','cycle.manage','proposal.open','proposal.close',
  'participation.nominal.read','candidate.review','ballot.open','ballot.close',
  'aggregate.read','consent.record','organigram.read','report.read'
) WHERE r.code = 'COMMITTEE_CHAIR'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'member.read','cycle.manage','proposal.open','proposal.close',
  'participation.nominal.read','candidate.review','ballot.open','ballot.close',
  'aggregate.read','consent.record','organigram.read','report.read','report.export'
) WHERE r.code = 'COMMITTEE_SECRETARY'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'member.read','proposal.submit','ballot.submit','aggregate.read','organigram.read','report.read'
) WHERE r.code = 'COMMITTEE_MEMBER'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'tally.custody','tally.recount','aggregate.publish','aggregate.read','audit.read'
) WHERE r.code = 'TALLY_CUSTODIAN'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_code)
SELECT r.id, p.code FROM roles r JOIN permissions p ON p.code IN (
  'aggregate.read','organigram.read','report.read','audit.read'
) WHERE r.code = 'AUDITOR'
ON CONFLICT DO NOTHING;
