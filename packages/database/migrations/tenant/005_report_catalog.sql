UPDATE report_versions SET report_type = 'progress' WHERE report_type = 'cycle-coverage';
UPDATE report_versions SET report_type = 'responsibility_distribution' WHERE report_type = 'responsibility-load';
UPDATE report_versions SET report_type = 'committee_participation' WHERE report_type = 'participation-summary';

ALTER TABLE report_versions
  ADD CONSTRAINT report_versions_type_check CHECK (report_type IN (
    'cycle_summary',
    'general_recommendations',
    'elected_board',
    'department',
    'office_round',
    'committee_participation',
    'responsibility_distribution',
    'unconsidered_unassigned',
    'progress',
    'session_minutes',
    'cycle_history',
    'audit_integrity',
    'roster_import_incidents'
  ));

ALTER TABLE report_versions
  ADD CONSTRAINT report_versions_audience_policy_check CHECK (
    (report_type NOT IN ('office_round', 'committee_participation', 'responsibility_distribution', 'unconsidered_unassigned', 'audit_integrity') OR audience <> 'church')
    AND (report_type <> 'roster_import_incidents' OR audience = 'committee')
  );
