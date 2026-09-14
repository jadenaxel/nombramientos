import { isAssignmentEligibilityPausedResult } from "@nombramientos/database";
import { ApiError } from "./errors.js";

/**
 * Stores return this discriminated outcome so their transaction can commit the
 * durable pause. Routes translate it to HTTP 409 only after that transaction
 * has closed, avoiding rollback of the incident itself.
 */
export function throwIfAssignmentEligibilityPaused(result: unknown): void {
  if (!isAssignmentEligibilityPausedResult(result)) return;
  throw new ApiError(409, result.code, result.message, {
    eligibilityPaused: true,
    assignmentId: result.assignmentId,
    processId: result.processId,
    roundId: result.roundId,
    pauseIds: result.pauseIds,
    processVersion: result.processVersion,
    roundVersion: result.roundVersion,
  });
}
