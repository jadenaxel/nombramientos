-- The global identity baseline is a compiled security invariant, not runtime
-- configuration. A future baseline change must be an explicit migration that
-- transforms and validates every tenant policy, reconciles existing sessions,
-- and invalidates stale ceremonies/grants in the same transaction.

CREATE OR REPLACE FUNCTION reject_identity_policy_baseline_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION USING
    ERRCODE = '55000',
    MESSAGE = 'identity_policy_baseline is immutable',
    DETAIL = 'Change the global floor only through a dedicated migration that atomically revalidates every tenant policy and active authorization.',
    HINT = 'Do not update, insert, delete, or truncate the baseline at runtime.';
END;
$$;

CREATE TRIGGER identity_policy_baseline_immutable_guard
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON identity_policy_baseline
FOR EACH STATEMENT
EXECUTE FUNCTION reject_identity_policy_baseline_mutation();

REVOKE ALL ON FUNCTION reject_identity_policy_baseline_mutation() FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE identity_policy_baseline FROM PUBLIC;
