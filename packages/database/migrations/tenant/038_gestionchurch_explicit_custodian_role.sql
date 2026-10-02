-- Allow only the existing system custodian role in the central projection.
-- Context binding, exact replacement, invitation isolation and max-three remain.
DO $$
DECLARE
  original_definition text;
  patched_definition text;
BEGIN
  SELECT pg_get_functiondef('sync_gestionchurch_federated_roles(uuid,text[])'::regprocedure)
    INTO original_definition;
  patched_definition := replace(original_definition,
    '''CHURCH_ADMIN'',''COMMITTEE_SECRETARY'',''COMMITTEE_MEMBER'',''AUDITOR''',
    '''CHURCH_ADMIN'',''COMMITTEE_SECRETARY'',''COMMITTEE_MEMBER'',''AUDITOR'',''TALLY_CUSTODIAN'''
  );
  IF patched_definition = original_definition
     OR position('''TALLY_CUSTODIAN''' IN patched_definition)=0
     OR position('cardinality(p_role_codes) NOT BETWEEN 1 AND 3' IN patched_definition)=0
     OR position('contextual_identity IS DISTINCT FROM p_identity_id' IN patched_definition)=0
     OR position('source_invitation_id IS NOT NULL' IN patched_definition)=0 THEN
    RAISE EXCEPTION 'GestionChurch custodian patch did not match the expected function definition';
  END IF;
  EXECUTE patched_definition;
END
$$;

REVOKE ALL ON FUNCTION sync_gestionchurch_federated_roles(uuid,text[]) FROM PUBLIC;
