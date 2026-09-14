import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { validateEnvelopeContentHash, validateEnvelopeContext } from "../lib/envelopes.js";
import { throwIfAssignmentEligibilityPaused } from "../lib/assignment-eligibility.js";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { parseBody, parseParams, parseQuery, requireIdempotencyKey, respond } from "../lib/http.js";
import {
  assignmentActivationBodySchema,
  assignmentFinalizationBodySchema,
  assignmentPresentationBodySchema,
  assignmentSubstitutionBodySchema,
  candidacyReviewBodySchema,
  candidateListBodySchema,
  closeWorkflowRoundBodySchema,
  committeeBodySchema,
  cycleBodySchema,
  electorateBodySchema,
  eligibilityPauseResolutionBodySchema,
  expectedCycleVersionSchema,
  linkedDesignationBodySchema,
  officeProcessApplicabilityBodySchema,
  prepareRoundBodySchema,
  proposalAggregateBodySchema,
  proposalManifestBodySchema,
  provisionalAssignmentsBodySchema,
  sessionBodySchema,
  sessionTransitionBodySchema,
  sessionUpdateBodySchema,
  sessionAttendanceBodySchema,
  sessionAgendaCreateBodySchema,
  sessionAgendaOrderBodySchema,
  sessionDecisionBodySchema,
  sessionListQuerySchema,
  transitionRoundBodySchema,
  tiebreakRoundBodySchema,
  vacancyProcessBodySchema,
  workflowUuidSchema,
} from "./core-workflow-contract.js";

const cycleParams = z.object({ cycleId: workflowUuidSchema });
const sourceCycleParams = z.object({ sourceCycleId: workflowUuidSchema });
const processParams = z.object({ processId: workflowUuidSchema });
const roundParams = z.object({ roundId: workflowUuidSchema });
const candidacyParams = z.object({ processId: workflowUuidSchema, candidacyId: workflowUuidSchema });
const assignmentParams = z.object({ assignmentId: workflowUuidSchema });
const sessionParams = z.object({ sessionId: workflowUuidSchema });
const attendanceParams = z.object({ sessionId: workflowUuidSchema, identityId: workflowUuidSchema });

export async function registerCoreWorkflowRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/cycles", {
    preHandler: [app.authenticate, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.listCycles());
    reply.header("cache-control", "no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/cycles", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const body = parseBody(cycleBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.createCycle({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      ...body,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/cycles/:sourceCycleId/clone", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sourceCycleId } = parseParams(sourceCycleParams, request);
    const body = parseBody(cycleBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.cloneCycle({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sourceCycleId,
      ...body,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/cycles/:cycleId/activate", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(expectedCycleVersionSchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.activateCycle({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedVersion: body.expectedVersion,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/cycles/:cycleId/close", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(expectedCycleVersionSchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.closeCycle({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedVersion: body.expectedVersion,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/cycles/:cycleId/archive", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(expectedCycleVersionSchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.archiveCycle({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedVersion: body.expectedVersion,
    }));
    return respond(request, reply, result);
  });

  app.get("/v1/cycles/:cycleId/workflow", {
    preHandler: [app.authenticate, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getCycleWorkflow(cycleId));
    if (!result) throw new ApiError(404, "CYCLE_UNAVAILABLE", "Cycle is unavailable");
    reply.header("cache-control", "no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/cycles/:cycleId/sessions", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(sessionBodySchema, request);
    validateEnvelopeContext(body.titleEnvelope, {
      tenantId: principal.activeTenantId,
      cycleId,
      sessionId: body.sessionId,
      purpose: "session-title",
      schemaVersion: 1,
      titleVersion: 1,
    }, { exact: true });
    validateEnvelopeContentHash(body.titleEnvelope, body.titleContentHash);
    if (body.locationEnvelope) {
      validateEnvelopeContext(body.locationEnvelope, {
        tenantId: principal.activeTenantId,
        cycleId,
        sessionSequence: body.sequence,
        purpose: "cycle-session-location",
        schemaVersion: 1,
      }, { exact: true });
    }
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.addSession({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      sessionId: body.sessionId,
      expectedCycleVersion: body.expectedCycleVersion,
      sequence: body.sequence,
      titleEnvelope: body.titleEnvelope,
      startsAt: body.startsAt,
      endsAt: body.endsAt,
      ...(body.locationEnvelope !== undefined ? { locationEnvelope: body.locationEnvelope } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.get("/v1/cycles/:cycleId/sessions", {
    preHandler: [app.authenticate, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const query = parseQuery(sessionListQuerySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.listSessions({
      cycleId,
      ...(query.status !== undefined ? { status: query.status } : {}),
      ...(query.sessionId !== undefined ? { sessionId: query.sessionId } : {}),
    }));
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.get("/v1/sessions/:sessionId", {
    preHandler: [app.authenticate, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId } = parseParams(sessionParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getSession(sessionId));
    if (!result) throw new ApiError(404, "SESSION_UNAVAILABLE", "Session is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.patch("/v1/sessions/:sessionId", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId } = parseParams(sessionParams, request);
    const body = parseBody(sessionUpdateBodySchema, request);
    const current = body.locationEnvelope || body.titleEnvelope
      ? await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getSession(sessionId))
      : null;
    if ((body.locationEnvelope || body.titleEnvelope) && !current) {
      throw new ApiError(404, "SESSION_UNAVAILABLE", "Session is unavailable");
    }
    if (body.locationEnvelope && current) {
      validateEnvelopeContext(body.locationEnvelope, {
        tenantId: principal.activeTenantId,
        cycleId: String(current["cycleId"]),
        sessionSequence: Number(current["sequence"]),
        purpose: "cycle-session-location",
        schemaVersion: 1,
      }, { exact: true });
    }
    if (body.titleEnvelope && body.titleContentHash && current) {
      const currentTitleVersion = Number(current["titleVersion"]);
      if (!Number.isSafeInteger(currentTitleVersion) || currentTitleVersion < 0) {
        throw new ApiError(409, "SESSION_TITLE_VERSION_INVALID", "Session title version is invalid");
      }
      validateEnvelopeContext(body.titleEnvelope, {
        tenantId: principal.activeTenantId,
        cycleId: String(current["cycleId"]),
        sessionId,
        purpose: "session-title",
        schemaVersion: 1,
        titleVersion: currentTitleVersion + 1,
      }, { exact: true });
      validateEnvelopeContentHash(body.titleEnvelope, body.titleContentHash);
    }
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.updateSession({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sessionId,
      expectedVersion: body.expectedVersion,
      ...(body.titleEnvelope !== undefined ? { titleEnvelope: body.titleEnvelope } : {}),
      ...(body.startsAt !== undefined ? { startsAt: body.startsAt } : {}),
      ...(body.endsAt !== undefined ? { endsAt: body.endsAt } : {}),
      ...(body.locationEnvelope !== undefined ? { locationEnvelope: body.locationEnvelope } : {}),
    }));
    return respond(request, reply, result);
  });

  const transitionSession = (operation: "start" | "close") => async (request: FastifyRequest, reply: import("fastify").FastifyReply) => {
      const principal = requirePrincipal(request);
      const { sessionId } = parseParams(sessionParams, request);
      const body = parseBody(sessionTransitionBodySchema, request);
      const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.transitionSession({
        identityId: principal.identityId,
        idempotencyKey: requireIdempotencyKey(request),
        sessionId,
        expectedVersion: body.expectedVersion,
        operation,
      }));
      return respond(request, reply, result);
  };
  app.post("/v1/sessions/:sessionId/start", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, transitionSession("start"));
  app.post("/v1/sessions/:sessionId/close", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, transitionSession("close"));

  app.put("/v1/sessions/:sessionId/attendance/:identityId", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId, identityId } = parseParams(attendanceParams, request);
    const body = parseBody(sessionAttendanceBodySchema, request);
    const active = await app.database.control.listActiveTenantMembershipIdentities(principal.activeTenantId);
    const activeIds = active.map((item) => item.identityId);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.upsertSessionAttendance({
      actorIdentityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sessionId,
      identityId,
      activeTenantIdentityIds: activeIds,
      expectedVersion: body.expectedVersion,
      presenceStatus: body.presenceStatus,
      advisory: body.advisory,
      votingRight: body.votingRight,
      ...(body.memberId !== undefined ? { memberId: body.memberId } : {}),
      ...(body.substituteForIdentityId !== undefined ? { substituteForIdentityId: body.substituteForIdentityId } : {}),
    }));
    return respond(request, reply, result, body.expectedVersion === 0 ? 201 : 200);
  });

  app.post("/v1/sessions/:sessionId/agenda", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId } = parseParams(sessionParams, request);
    const body = parseBody(sessionAgendaCreateBodySchema, request);
    validateEnvelopeContext(body.titleEnvelope, {
      tenantId: principal.activeTenantId,
      sessionId,
      agendaItemId: body.itemId,
      purpose: "session-agenda-title",
      schemaVersion: 1,
      titleVersion: 1,
    }, { exact: true });
    validateEnvelopeContentHash(body.titleEnvelope, body.titleContentHash);
    if (body.notesEnvelope) validateEnvelopeContext(body.notesEnvelope, {
      tenantId: principal.activeTenantId, sessionId, purpose: "session-agenda-notes", schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.addSessionAgendaItem({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sessionId,
      expectedSessionVersion: body.expectedSessionVersion,
      position: body.position,
      itemId: body.itemId,
      titleEnvelope: body.titleEnvelope,
      ...(body.processId !== undefined ? { processId: body.processId } : {}),
      ...(body.notesEnvelope !== undefined ? { notesEnvelope: body.notesEnvelope } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.put("/v1/sessions/:sessionId/agenda/order", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId } = parseParams(sessionParams, request);
    const body = parseBody(sessionAgendaOrderBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.reorderSessionAgenda({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sessionId,
      expectedSessionVersion: body.expectedSessionVersion,
      itemIds: body.itemIds,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/sessions/:sessionId/decisions", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { sessionId } = parseParams(sessionParams, request);
    const body = parseBody(sessionDecisionBodySchema, request);
    if (body.evidenceEnvelope) validateEnvelopeContext(body.evidenceEnvelope, {
      tenantId: principal.activeTenantId, sessionId, agendaItemId: body.agendaItemId,
      purpose: "session-decision-evidence", schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.recordSessionDecision({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sessionId,
      expectedSessionVersion: body.expectedSessionVersion,
      agendaItemId: body.agendaItemId,
      decisionCode: body.decisionCode,
      outcome: body.outcome,
      ...(body.evidenceEnvelope !== undefined ? { evidenceEnvelope: body.evidenceEnvelope } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.put("/v1/cycles/:cycleId/committee", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("committee.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(committeeBodySchema, request);
    const activeIdentities = await app.database.control.listActiveTenantMembershipIdentities(principal.activeTenantId);
    for (const member of body.members) {
      validateEnvelopeContext(member.displayEnvelope, {
        tenantId: principal.activeTenantId,
        cycleId,
        identityId: member.identityId,
        purpose: "committee-display",
        schemaVersion: 1,
      }, { exact: true });
    }
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.configureCommittee({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedCycleVersion: body.expectedCycleVersion,
      activeTenantIdentityIds: activeIdentities.map(({ identityId }) => identityId),
      members: body.members.map((member) => ({
        identityId: member.identityId,
        displayEnvelope: member.displayEnvelope,
        roleCode: member.roleCode,
        votingRight: member.votingRight,
        pastoralCapacity: member.pastoralCapacity,
        ...(member.memberId !== undefined ? { memberId: member.memberId } : {}),
      })),
    }));
    return respond(request, reply, result);
  });

  app.get("/v1/cycles/:cycleId/committee-candidates", {
    preHandler: [app.authenticate, app.requirePermission("committee.manage"), app.requirePermission("member.read")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const [workflow, items] = await Promise.all([
      app.database.withCoreWorkflowPrincipal(principal, request.id, (store) => store.getCycleWorkflow(cycleId)),
      app.database.control.listActiveTenantMembershipIdentities(principal.activeTenantId),
    ]);
    if (!workflow) throw new ApiError(404, "CYCLE_UNAVAILABLE", "Cycle is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, { items });
  });

  app.put("/v1/cycles/:cycleId/electorate", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(electorateBodySchema, request);
    const activeIdentities = await app.database.control.listActiveTenantMembershipIdentities(principal.activeTenantId);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.configureElectorate({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedCycleVersion: body.expectedCycleVersion,
      activeTenantIdentityIds: activeIdentities.map(({ identityId }) => identityId),
      electors: body.electors,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/cycles/:cycleId/vacancy-processes", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { cycleId } = parseParams(cycleParams, request);
    const body = parseBody(vacancyProcessBodySchema, request);
    const { expectedCycleVersion, ...configuration } = body;
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.configureVacancyProcess({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      cycleId,
      expectedCycleVersion,
      configuration,
    }));
    return respond(request, reply, result, 201);
  });

  app.put("/v1/office-processes/:processId/applicability", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("cycle.manage")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(officeProcessApplicabilityBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.setOfficeProcessApplicability({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedCycleVersion: body.expectedCycleVersion,
      expectedProcessVersion: body.expectedProcessVersion,
      enabled: body.enabled,
      reasonCode: body.reasonCode,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/office-processes/:processId/proposal-rounds", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("proposal.open")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(prepareRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.createProposalRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedProcessVersion: body.expectedProcessVersion,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/office-processes/:processId/eligibility-pause/resolve", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("workflow.eligibility.resolve")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(eligibilityPauseResolutionBodySchema, request);
    if (body.resolutionCode === "ANNUL_AND_RESTART" && !principal.permissions.has("proposal.open")) {
      throw forbidden("proposal.open");
    }
    if (body.resolutionCode === "EXCLUDE_AND_REVIEW" && !principal.permissions.has("candidate.review")) {
      throw forbidden("candidate.review");
    }
    const pauseIds = [...body.expectedPauseIds].sort();
    validateEnvelopeContext(body.evidenceEnvelope, {
      tenantId: principal.activeTenantId,
      processId,
      pauseIds,
      resolutionCode: body.resolutionCode,
      reasonCode: body.reasonCode,
      purpose: "eligibility-pause-resolution",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.resolveEligibilityPause({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedProcessVersion: body.expectedProcessVersion,
      ...(body.expectedRoundVersion !== undefined ? { expectedRoundVersion: body.expectedRoundVersion } : {}),
      expectedPauseIds: pauseIds,
      resolutionCode: body.resolutionCode,
      reasonCode: body.reasonCode,
      evidenceEnvelope: body.evidenceEnvelope,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/office-processes/:processId/linked-designations", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("linked-designation.record")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(linkedDesignationBodySchema, request);
    validateEnvelopeContext(body.evidenceEnvelope, {
      tenantId: principal.activeTenantId,
      processId,
      baseAssignmentId: body.baseAssignmentId,
      purpose: "linked-designation",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.createLinkedDesignation({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedProcessVersion: body.expectedProcessVersion,
      baseAssignmentId: body.baseAssignmentId,
      evidenceEnvelope: body.evidenceEnvelope,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/proposal-rounds/:roundId/open", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("proposal.open")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(transitionRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.openProposalRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      ...body,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/proposal-rounds/:roundId/close", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("proposal.close")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(closeWorkflowRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.closeProposalRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      expectedRoundVersion: body.expectedRoundVersion,
      expectedProcessVersion: body.expectedProcessVersion,
      reasonCode: body.reasonCode,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/proposal-rounds/:roundId/aggregate", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("proposal.close"), app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(proposalAggregateBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.consolidateProposals({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      ...body,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/proposal-rounds/:roundId/manifest", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("proposal.close"), app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(proposalManifestBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.createProposalManifest({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      expectedRoundVersion: body.expectedRoundVersion,
    }));
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result, 201);
  });

  app.get("/v1/proposal-rounds/:roundId/manifest", {
    preHandler: [app.authenticate, app.requirePermission("proposal.close"), app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getProposalManifest(roundId));
    if (!result) throw new ApiError(404, "PROPOSAL_MANIFEST_UNAVAILABLE", "Closed proposal manifest is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/office-processes/:processId/candidacies/:candidacyId/reviews", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId, candidacyId } = parseParams(candidacyParams, request);
    const body = parseBody(candidacyReviewBodySchema, request);
    for (const [purpose, envelope] of [
      ["candidacy-rationale", body.rationaleEnvelope],
      ["candidacy-restricted-note", body.restrictedNoteEnvelope],
    ] as const) {
      if (envelope) validateEnvelopeContext(envelope, {
        tenantId: principal.activeTenantId,
        processId,
        candidacyId,
        purpose,
        schemaVersion: 1,
      }, { exact: true });
    }
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.reviewCandidacy({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      candidacyId,
      expectedVersion: body.expectedVersion,
      toState: body.toState,
      reasonCode: body.reasonCode,
      ...(body.rationaleEnvelope !== undefined ? { rationaleEnvelope: body.rationaleEnvelope } : {}),
      ...(body.restrictedNoteEnvelope !== undefined ? { restrictedNoteEnvelope: body.restrictedNoteEnvelope } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.get("/v1/office-processes/:processId/review-board", {
    preHandler: [app.authenticate, app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getReviewBoard(
      processId,
      principal.permissions.has("private-note.read"),
    ));
    if (!result) throw new ApiError(404, "OFFICE_PROCESS_UNAVAILABLE", "Office process is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/office-processes/:processId/candidate-lists", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("candidate.review")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(candidateListBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.confirmCandidateList({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      ...body,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/office-processes/:processId/ballot-rounds", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("ballot.open")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(prepareRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.prepareBallotRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedProcessVersion: body.expectedProcessVersion,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/office-processes/:processId/tiebreak-rounds", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("ballot.open")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(tiebreakRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.prepareTiebreakRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      ...body,
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/ballot-rounds/:roundId/open", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("ballot.open")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(transitionRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.openBallotRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      ...body,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/ballot-rounds/:roundId/close", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("ballot.close")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const body = parseBody(closeWorkflowRoundBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.closeBallotRound({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      roundId,
      expectedRoundVersion: body.expectedRoundVersion,
      expectedProcessVersion: body.expectedProcessVersion,
      reasonCode: body.reasonCode,
    }));
    return respond(request, reply, result);
  });

  app.get("/v1/rounds/:roundId/participation", {
    preHandler: [app.authenticate, app.requirePermission("participation.nominal.read")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { roundId } = parseParams(roundParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getNominalParticipation(roundId));
    if (!result) throw new ApiError(404, "ROUND_UNAVAILABLE", "Round is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/office-processes/:processId/provisional-assignments", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("candidate.review"), app.requirePermission("aggregate.read")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { processId } = parseParams(processParams, request);
    const body = parseBody(provisionalAssignmentsBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.createProvisionalAssignments({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      processId,
      expectedProcessVersion: body.expectedProcessVersion,
      roundId: body.roundId,
      expectedAggregateHash: body.expectedAggregateHash,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/assignments/:assignmentId/presentation", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("congregational-decision.record")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { assignmentId } = parseParams(assignmentParams, request);
    const body = parseBody(assignmentPresentationBodySchema, request);
    validateEnvelopeContext(body.envelope, {
      tenantId: principal.activeTenantId,
      assignmentId,
      purpose: "assignment-presentation",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.presentAssignment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      envelope: body.envelope,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    throwIfAssignmentEligibilityPaused(result);
    return respond(request, reply, result);
  });

  app.post("/v1/assignments/:assignmentId/activate", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("congregational-decision.record")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { assignmentId } = parseParams(assignmentParams, request);
    const body = parseBody(assignmentActivationBodySchema, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.activateAssignment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    throwIfAssignmentEligibilityPaused(result);
    return respond(request, reply, result);
  });

  app.post("/v1/assignments/:assignmentId/finalize", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("congregational-decision.record")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { assignmentId } = parseParams(assignmentParams, request);
    const body = parseBody(assignmentFinalizationBodySchema, request);
    if (body.evidenceEnvelope) validateEnvelopeContext(body.evidenceEnvelope, {
      tenantId: principal.activeTenantId,
      assignmentId,
      purpose: "assignment-finalization",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.finalizeAssignment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      reasonCode: body.reasonCode,
      openVacancy: body.openVacancy,
      ...(body.evidenceEnvelope !== undefined ? { evidenceEnvelope: body.evidenceEnvelope } : {}),
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/assignments/:assignmentId/substitute", {
    preHandler: [app.authenticate, app.verifyCsrf, app.requirePermission("congregational-decision.record")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { assignmentId } = parseParams(assignmentParams, request);
    const body = parseBody(assignmentSubstitutionBodySchema, request);
    if (body.evidenceEnvelope) validateEnvelopeContext(body.evidenceEnvelope, {
      tenantId: principal.activeTenantId,
      assignmentId,
      purpose: "assignment-substitution",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.substituteAssignment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      reasonCode: body.reasonCode,
      ...(body.evidenceEnvelope !== undefined ? { evidenceEnvelope: body.evidenceEnvelope } : {}),
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    return respond(request, reply, result);
  });

  app.get("/v1/assignments/:assignmentId/history", {
    preHandler: [app.authenticate, app.requirePermission("organigram.read")],
  }, async (request, reply) => {
    const principal = requirePrincipal(request);
    const { assignmentId } = parseParams(assignmentParams, request);
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getAssignmentHistory(assignmentId));
    if (!result) throw new ApiError(404, "ASSIGNMENT_UNAVAILABLE", "Assignment is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}
