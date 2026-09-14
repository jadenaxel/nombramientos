-- Candidate-list confirmation is an internal state transition, not a
-- reviewer-supplied reason. Migration 023 intentionally closed the public
-- review vocabulary but omitted this pre-existing machine transition. Keep
-- the public API vocabulary unchanged and admit only the exact internal pair.
ALTER TABLE candidacy_reviews
  DROP CONSTRAINT candidacy_reviews_reason_code_allowed;

ALTER TABLE candidacy_reviews
  ADD CONSTRAINT candidacy_reviews_reason_code_allowed
  CHECK (
    (to_state = 'UNDER_REVIEW' AND reason_code = 'REVIEW_STARTED')
    OR (to_state = 'PRELIMINARY_ACCEPTED' AND reason_code = 'REVIEW_ACCEPTED')
    OR (to_state = 'WITHDRAWN' AND reason_code = 'CANDIDATE_WITHDREW')
    OR (to_state = 'EXCLUDED' AND reason_code = 'COMMITTEE_EXCLUDED')
    OR (to_state = 'INELIGIBLE' AND reason_code = 'ELIGIBILITY_FAILED')
    OR (to_state = 'CONFIRMED_FOR_BALLOT' AND reason_code = 'FINAL_LIST_CONFIRMED')
  ) NOT VALID;

ALTER TABLE candidacy_reviews
  VALIDATE CONSTRAINT candidacy_reviews_reason_code_allowed;

COMMENT ON CONSTRAINT candidacy_reviews_reason_code_allowed ON candidacy_reviews IS
  'Closed reviewer vocabulary plus the sole internal candidate-list transition CONFIRMED_FOR_BALLOT/FINAL_LIST_CONFIRMED.';
