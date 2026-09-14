COMMENT ON COLUMN office_processes.enabled IS
  'Current cycle applicability flag. False excludes the entire office procedure group from current denominators and organization projections while preserving its immutable workflow history.';

CREATE INDEX office_processes_applicable_cycle_office
  ON office_processes(cycle_id,office_id,id)
  WHERE enabled;

CREATE INDEX office_processes_applicable_reused_vacancy
  ON office_processes(reused_vacancy_id)
  WHERE enabled AND reused_vacancy_id IS NOT NULL;
