-- The provisioner substitutes the generated, validated runtime role identifier
-- before applying this migration. Running this file directly intentionally fails.
DO $$
BEGIN
  IF current_setting('app.runtime_role', true) IS NULL THEN
    RAISE NOTICE 'Runtime grants are applied by the provisioner after migrations';
  END IF;
END
$$;
