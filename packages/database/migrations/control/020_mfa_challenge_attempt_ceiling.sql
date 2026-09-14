-- Keep the persisted challenge budget identical to the application-level
-- reservation ceiling. Rows above six can only predate the atomic reservation
-- implementation and are already unusable, so clamping them cannot restore a
-- challenge or grant another attempt.
UPDATE mfa_challenges
   SET attempt_count = 6
 WHERE attempt_count > 6;

ALTER TABLE mfa_challenges
  DROP CONSTRAINT mfa_challenges_attempt_count_check;

ALTER TABLE mfa_challenges
  ADD CONSTRAINT mfa_challenges_attempt_count_check
  CHECK (attempt_count BETWEEN 0 AND 6) NOT VALID;

ALTER TABLE mfa_challenges
  VALIDATE CONSTRAINT mfa_challenges_attempt_count_check;

COMMENT ON CONSTRAINT mfa_challenges_attempt_count_check ON mfa_challenges IS
  'At most six verification attempts may be atomically reserved for one MFA challenge.';
