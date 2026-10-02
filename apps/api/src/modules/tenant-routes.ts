import type { FastifyInstance, FastifyRequest } from "fastify";
import { REPORT_CORRECTION_REASON_CODES } from "@nombramientos/database";
import { z } from "zod";
import { ApiError, forbidden, unauthorized } from "../lib/errors.js";
import { throwIfAssignmentEligibilityPaused } from "../lib/assignment-eligibility.js";
import {
  encryptedEnvelopeSchema,
  validateEnvelopeContentHash,
  validateEnvelopeContext,
} from "../lib/envelopes.js";
import { parseBody, parseParams, parseQuery, requireIdempotencyKey, respond } from "../lib/http.js";
import { requirePolicyAwareOperationStepUp } from "../lib/operation-step-up.js";
import {
  memberArchiveReasonCodeSchema,
  memberReactivateReasonCodeSchema,
} from "../lib/reason-code.js";
import { requireRecentMfa } from "../lib/recent-mfa.js";
import { ianaTimezoneSchema } from "../lib/timezone.js";
import {
  accessibleReportScopes,
  canAccessReport,
  REPORT_TYPES,
  requiredReportPermissions,
  type ReportAudience,
  type ReportType,
} from "../lib/report-policy.js";
import { memberImportCommitSchema, memberImportPreviewSchema } from "./member-import-contract.js";
import {
  assignmentCongregationalDecisionBodySchema,
  assignmentConsentBodySchema,
  workflowReportQuerySchema,
} from "./core-workflow-contract.js";
import { getGestionChurchOrganizationDirectory } from "./gestionchurch-integration-routes.js";

const uuid = z.string().uuid();
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const civilDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((value) => {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed.valueOf()) && parsed.toISOString().slice(0, 10) === value;
}, "Expected a real calendar date in YYYY-MM-DD format");
export const memberExportAuthorizationSchema = z.object({
  format: z.enum(["csv", "xlsx"]),
  rowCount: z.number().int().min(0).max(25_000),
  includeContact: z.boolean().default(false),
  filters: z.object({
    status: z.enum(["all", "active", "archived"]),
    queryApplied: z.boolean(),
  }).strict(),
  selectionSha256: sha256,
}).strict();
const localizedCatalogNamesSchema = z.object({
  es: z.string().trim().min(1).max(160),
  en: z.string().trim().min(1).max(160),
  fr: z.string().trim().min(1).max(160),
}).strict();
const localCatalogCodeSchema = z.string().trim().regex(/^local\.[a-z0-9][a-z0-9._-]{1,78}$/);
const catalogMetadataSchema = z.record(z.unknown());
const appointmentMechanismSchema = z.enum([
  "church_election_after_nominating_report",
  "church_election",
  "board_appointment",
  "council_recommendation_board_approval",
  "conference_appointment",
  "ex_officio",
  "linked_designation",
  "local_configuration_pending",
]);
export const tenantSettingsUpdateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  displayName: z.string().trim().min(2).max(160).optional(),
  timezone: ianaTimezoneSchema.optional(),
  locale: z.enum(["es", "en", "fr"]).optional(),
  jurisdiction: z.string().trim().min(2).max(160).optional(),
}).strict().refine((value) => Object.keys(value).some((key) => key !== "expectedVersion"), {
  message: "At least one tenant setting must change",
});
export const localDepartmentCreateSchema = z.object({
  canonicalCode: localCatalogCodeSchema,
  names: localizedCatalogNamesSchema,
  parentId: uuid.optional(),
  sortOrder: z.number().int().min(0).max(100_000).default(0),
  metadata: catalogMetadataSchema.default({}),
}).strict();
export const localDepartmentUpdateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  names: localizedCatalogNamesSchema.optional(),
  parentId: uuid.nullable().optional(),
  sortOrder: z.number().int().min(0).max(100_000).optional(),
  active: z.boolean().optional(),
  metadata: catalogMetadataSchema.optional(),
}).strict().refine((value) => Object.keys(value).some((key) => key !== "expectedVersion"), {
  message: "At least one department field must change",
});
export const localOfficeCreateSchema = z.object({
  departmentId: uuid,
  canonicalCode: localCatalogCodeSchema,
  names: localizedCatalogNamesSchema,
  appointmentMechanism: appointmentMechanismSchema,
  cardinality: z.number().int().positive().max(10_000),
  metadata: catalogMetadataSchema.default({}),
}).strict();
export const localOfficeUpdateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  departmentId: uuid.optional(),
  names: localizedCatalogNamesSchema.optional(),
  appointmentMechanism: appointmentMechanismSchema.optional(),
  cardinality: z.number().int().positive().max(10_000).optional(),
  active: z.boolean().optional(),
  metadata: catalogMetadataSchema.optional(),
}).strict().refine((value) => Object.keys(value).some((key) => key !== "expectedVersion"), {
  message: "At least one office field must change",
});
export const memberCreateSchema = z.object({
  id: uuid,
  shortId: z.string().trim().min(2).max(64).optional(),
  eligible: z.boolean(),
  displayEnvelope: encryptedEnvelopeSchema,
  displayContentHash: sha256,
  contactEnvelope: encryptedEnvelopeSchema.optional(),
  contactContentHash: sha256.optional(),
  departmentRestriction: uuid.nullable().optional(),
  validUntil: civilDate.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (Boolean(value.contactEnvelope) !== Boolean(value.contactContentHash)) {
    context.addIssue({ code: "custom", message: "contactEnvelope and contactContentHash must be supplied together" });
  }
});
export const memberUpdateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  displayEnvelope: encryptedEnvelopeSchema.optional(),
  displayContentHash: sha256.optional(),
  contactEnvelope: encryptedEnvelopeSchema.nullable().optional(),
  contactContentHash: sha256.optional(),
  resolveLegacyProfile: z.boolean().optional(),
  eligibilityEnvelope: encryptedEnvelopeSchema.nullable().optional(),
  eligibilityContentHash: sha256.optional(),
  eligibilityStatus: z.enum(["eligible", "ineligible", "review"]).optional(),
  available: z.boolean().optional(),
  departmentRestriction: uuid.nullable().optional(),
  validUntil: civilDate.nullable().optional(),
}).strict().superRefine((value, context) => {
  if (!Object.keys(value).some((key) => key !== "expectedVersion")) {
    context.addIssue({ code: "custom", message: "At least one field must change" });
  }
  if (Boolean(value.displayEnvelope) !== Boolean(value.displayContentHash)) {
    context.addIssue({
      code: "custom",
      path: [value.displayEnvelope ? "displayContentHash" : "displayEnvelope"],
      message: "displayEnvelope and displayContentHash must be supplied together",
    });
  }
  if (value.contactEnvelope && !value.contactContentHash) {
    context.addIssue({ code: "custom", path: ["contactContentHash"], message: "contactContentHash is required with contactEnvelope" });
  }
  if (value.contactContentHash && !value.contactEnvelope) {
    context.addIssue({ code: "custom", path: ["contactEnvelope"], message: "contactContentHash requires a non-null contactEnvelope" });
  }
  if (value.resolveLegacyProfile && (!value.displayEnvelope || !Object.prototype.hasOwnProperty.call(value, "contactEnvelope"))) {
    context.addIssue({ code: "custom", path: ["resolveLegacyProfile"], message: "Legacy resolution requires replacement display and an explicit contact envelope or null" });
  }
  if (value.eligibilityEnvelope && !value.eligibilityContentHash) {
    context.addIssue({
      code: "custom",
      path: ["eligibilityContentHash"],
      message: "eligibilityContentHash is required with an eligibilityEnvelope",
    });
  }
  if (value.eligibilityContentHash && !value.eligibilityEnvelope) {
    context.addIssue({
      code: "custom",
      path: ["eligibilityEnvelope"],
      message: "eligibilityContentHash requires a non-null eligibilityEnvelope",
    });
  }
});
const listMembersQuery = z.object({ limit: z.coerce.number().int().min(1).max(250).default(100), cursor: uuid.optional() });
export const memberArchiveSchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: memberArchiveReasonCodeSchema,
}).strict();
export const memberReactivateSchema = z.object({
  expectedVersion: z.number().int().positive(),
  reasonCode: memberReactivateReasonCodeSchema,
}).strict();
const memberImportHistoryQuery = z.object({ limit: z.coerce.number().int().min(1).max(100).default(30) });
const reportQuery = z.object({ limit: z.coerce.number().int().min(1).max(100).default(30) });
export const organizationQuerySchema = z.object({
  cycleId: uuid.optional(),
  stage: z.enum(["proposal", "elected"]).default("elected"),
}).strict();
const reportFiltersSchema = z.object({
  cycleId: uuid.nullable().optional(),
  term: z.string().trim().min(1).max(120).nullable().optional(),
  sessionId: uuid.nullable().optional(),
  department: z.string().trim().min(1).max(240).nullable().optional(),
  office: z.string().trim().min(1).max(240).nullable().optional(),
  personId: uuid.nullable().optional(),
  phase: z.string().trim().min(1).max(80).nullable().optional(),
  assignmentState: z.string().trim().min(1).max(80).nullable().optional(),
  snapshotSha256: sha256,
  snapshotAt: z.string().datetime({ offset: true }),
}).strict();
export const reportGenerateSchema = z.object({
  reportType: z.enum(REPORT_TYPES),
  audience: z.enum(["committee", "auditor", "church"]).default("committee"),
  locale: z.enum(["es", "en", "fr"]),
  format: z.enum(["pdf", "xlsx", "csv"]),
  filters: reportFiltersSchema,
}).superRefine((value, context) => {
  if (value.reportType === "session_minutes" && !value.filters.sessionId) {
    context.addIssue({ code: "custom", path: ["filters", "sessionId"], message: "session_minutes issuance requires a selected session" });
  }
});
export const reportCompleteSchema = z.object({
  expectedVersion: z.number().int().positive(),
  envelope: encryptedEnvelopeSchema,
  artifactSha256: sha256,
  ciphertextSha256: sha256,
  plaintextBytes: z.number().int().positive().max(20 * 1024 * 1024),
  rowCount: z.number().int().nonnegative().max(1_000_000),
  generatedAt: z.string().datetime({ offset: true }),
}).strict().superRefine((value, context) => {
  if (value.envelope.algorithm !== "AES-256-GCM") {
    context.addIssue({ code: "custom", path: ["envelope", "algorithm"], message: "Report artifacts require AES-256-GCM" });
  }
  const ciphertext = Buffer.from(value.envelope.ciphertext, "base64url");
  if (ciphertext.toString("base64url") !== value.envelope.ciphertext
    || ciphertext.byteLength !== value.plaintextBytes + 16) {
    context.addIssue({ code: "custom", path: ["envelope", "ciphertext"], message: "AES-GCM ciphertext must be canonical base64url and contain plaintextBytes plus its 16-byte tag" });
  }
});
export const reportCorrectionSchema = z.object({
  expectedPreviousVersion: z.number().int().positive(),
  reasonCode: z.enum(REPORT_CORRECTION_REASON_CODES),
  filters: reportFiltersSchema,
}).strict();
export const reportFailSchema = z.object({
  expectedVersion: z.number().int().positive(),
  errorCode: z.string().regex(/^[A-Z][A-Z0-9_]{2,63}$/),
}).strict();
export const reportPrintSchema = z.object({ artifactSha256: sha256 }).strict();
const auditQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  beforeSequence: z.coerce.number().int().positive().optional(),
});
const rotateKeySchema = z.object({
  expectedVersion: z.number().int().nonnegative(),
  deviceId: uuid,
  tenantKeyId: z.string().min(8).max(160),
  version: z.number().int().positive(),
  kdf: z.object({
    name: z.literal("PBKDF2"), salt: z.string().min(16), iterations: z.number().int().min(210_000), hash: z.literal("SHA-256"),
  }),
  wrap: z.object({
    algorithm: z.literal("AES-GCM"), iv: z.string().min(16), ciphertext: z.string().min(24), aad: z.string().min(8),
  }),
});

export async function registerTenantRoutes(app: FastifyInstance): Promise<void> {
  app.get("/v1/dashboard", { preHandler: protectedRead(app, "aggregate.read") }, async (request, reply) =>
    withTenant(app, request, async (tenant) => respond(request, reply, await tenant.getDashboard())));

  app.get("/v1/members", { preHandler: protectedRead(app, "member.read") }, async (request, reply) => {
    const query = parseQuery(listMembersQuery, request);
    const principal = requirePrincipal(request);
    const result = await withTenant(app, request, (tenant) => tenant.listMembers(
      query.limit,
      query.cursor,
      false,
      principal.permissions.has("private-note.read"),
      principal.permissions.has("member.contact.read"),
    ));
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.get("/v1/members/manage", { preHandler: protectedRead(app, "member.read") }, async (request, reply) => {
    const query = parseQuery(listMembersQuery, request);
    requireAllPermissions(request, ["member.manage"]);
    const principal = requirePrincipal(request);
    const result = await withTenant(app, request, (tenant) => tenant.listMembers(
      query.limit,
      query.cursor,
      true,
      principal.permissions.has("private-note.read"),
      principal.permissions.has("member.contact.read"),
    ));
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });

  app.post("/v1/members/export-authorizations", {
    preHandler: protectedSensitiveMutation(app, "report.export", "authorizing a roster export", "data_export"),
    config: { rateLimit: { max: 20, timeWindow: "10 minutes" } },
  }, async (request, reply) => {
    const body = parseBody(memberExportAuthorizationSchema, request);
    const principal = requirePrincipal(request);
    if (body.includeContact) requireAllPermissions(request, ["member.contact.read"]);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.authorizeMemberExport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      ...body,
    }));
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result, 201);
  });

  app.post("/v1/members", { preHandler: protectedMutation(app, "member.manage") }, async (request, reply) => {
    const body = parseBody(memberCreateSchema, request);
    const principal = requirePrincipal(request);
    requireAnyPermission(request, ["member.eligibility.manage"]);
    if (body.contactEnvelope) requireAllPermissions(request, ["member.contact.manage"]);
    validateEnvelopeContext(body.displayEnvelope, {
      tenantId: principal.activeTenantId,
      memberId: body.id,
      purpose: "member-display",
      schemaVersion: 1,
    }, { exact: true });
    validateEnvelopeContentHash(body.displayEnvelope, body.displayContentHash);
    if (body.contactEnvelope && body.contactContentHash) {
      validateEnvelopeContext(body.contactEnvelope, {
        tenantId: principal.activeTenantId,
        memberId: body.id,
        purpose: "member-contact",
        schemaVersion: 1,
      }, { exact: true });
      validateEnvelopeContentHash(body.contactEnvelope, body.contactContentHash);
    }
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.createMember({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      memberId: body.id,
      stableCode: body.shortId ?? `MEM-${body.id.slice(0, 12).toUpperCase()}`,
      displayEnvelope: body.displayEnvelope,
      displayContentHash: body.displayContentHash,
      ...(body.contactEnvelope && body.contactContentHash ? { contactEnvelope: body.contactEnvelope, contactContentHash: body.contactContentHash } : {}),
      eligibilityStatus: body.eligible ? "eligible" : "ineligible",
      available: body.eligible,
      ...(Object.prototype.hasOwnProperty.call(body, "departmentRestriction")
        ? { departmentRestriction: body.departmentRestriction ?? null }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, "validUntil") ? { validUntil: body.validUntil ?? null } : {}),
    }));
    return respond(request, reply, result, 201);
  });

  app.patch("/v1/members/:memberId", { preHandler: protectedMutation(app, "member.manage") }, async (request, reply) => {
    const { memberId } = parseParams(z.object({ memberId: uuid }), request);
    const body = parseBody(memberUpdateSchema, request);
    const principal = requirePrincipal(request);
    if (body.eligibilityStatus !== undefined || body.available !== undefined || body.eligibilityEnvelope !== undefined
        || body.departmentRestriction !== undefined || body.validUntil !== undefined) {
      requireAnyPermission(request, ["member.eligibility.manage"]);
    }
    const changesContact = Object.prototype.hasOwnProperty.call(body, "contactEnvelope") || body.resolveLegacyProfile === true;
    if (changesContact) requireAllPermissions(request, ["member.contact.manage"]);
    if (body.displayEnvelope && body.displayContentHash) {
      validateEnvelopeContext(body.displayEnvelope, {
        tenantId: principal.activeTenantId,
        memberId,
        purpose: "member-display",
        schemaVersion: 1,
      }, { exact: true });
      validateEnvelopeContentHash(body.displayEnvelope, body.displayContentHash);
    }
    if (body.contactEnvelope && body.contactContentHash) {
      validateEnvelopeContext(body.contactEnvelope, {
        tenantId: principal.activeTenantId,
        memberId,
        purpose: "member-contact",
        schemaVersion: 1,
      }, { exact: true });
      validateEnvelopeContentHash(body.contactEnvelope, body.contactContentHash);
    }
    if (body.eligibilityEnvelope && body.eligibilityContentHash) {
      validateEnvelopeContext(body.eligibilityEnvelope, {
        tenantId: principal.activeTenantId,
        memberId,
        purpose: "member-eligibility",
        schemaVersion: 1,
      }, { exact: true });
      validateEnvelopeContentHash(body.eligibilityEnvelope, body.eligibilityContentHash);
    }
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.updateMember({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      memberId,
      expectedVersion: body.expectedVersion,
      ...(body.displayEnvelope && body.displayContentHash ? { displayEnvelope: body.displayEnvelope, displayContentHash: body.displayContentHash } : {}),
      ...(Object.prototype.hasOwnProperty.call(body, "contactEnvelope") ? {
        contactEnvelope: body.contactEnvelope ?? null,
        ...(body.contactContentHash ? { contactContentHash: body.contactContentHash } : {}),
      } : {}),
      ...(body.resolveLegacyProfile ? { resolveLegacyProfile: true } : {}),
      ...(Object.prototype.hasOwnProperty.call(body, "eligibilityEnvelope") ? { eligibilityEnvelope: body.eligibilityEnvelope ?? null } : {}),
      ...(body.eligibilityStatus ? { eligibilityStatus: body.eligibilityStatus } : {}),
      ...(body.available !== undefined ? { available: body.available } : {}),
      ...(Object.prototype.hasOwnProperty.call(body, "departmentRestriction")
        ? { departmentRestriction: body.departmentRestriction ?? null }
        : {}),
      ...(Object.prototype.hasOwnProperty.call(body, "validUntil") ? { validUntil: body.validUntil ?? null } : {}),
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/members/:memberId/archive", { preHandler: protectedMutation(app, "member.manage") }, async (request, reply) => {
    const { memberId } = parseParams(z.object({ memberId: uuid }), request);
    const body = parseBody(memberArchiveSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.archiveMember({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      memberId,
      expectedVersion: body.expectedVersion,
      reasonCode: body.reasonCode,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/members/:memberId/reactivate", { preHandler: protectedMutation(app, "member.manage") }, async (request, reply) => {
    const { memberId } = parseParams(z.object({ memberId: uuid }), request);
    const body = parseBody(memberReactivateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.reactivateMember({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      memberId,
      expectedVersion: body.expectedVersion,
      reasonCode: body.reasonCode,
    }));
    return respond(request, reply, result);
  });

  app.post("/v1/members/import/preview", {
    preHandler: protectedMutation(app, "member.import"),
    bodyLimit: 32 * 1024 * 1024,
  }, async (request, reply) => {
    const body = parseBody(memberImportPreviewSchema, request);
    const principal = requirePrincipal(request);
    requireAllPermissions(request, ["member.manage", "member.eligibility.manage"]);
    const actionableRows = body.rows.filter(({ decision }) => decision.action !== "skip");
    for (const row of actionableRows) {
      if (!row.displayEnvelope || !row.displayContentHash) {
        throw new ApiError(400, "IMPORT_ROW_INVALID", "Actionable import row is missing encrypted content");
      }
      validateEnvelopeContext(row.displayEnvelope, {
        tenantId: principal.activeTenantId,
        memberId: row.id,
        purpose: "member-display",
        schemaVersion: 1,
      }, { exact: true });
      validateEnvelopeContentHash(row.displayEnvelope, row.displayContentHash);
      if (row.contactEnvelope && row.contactContentHash) {
        requireAllPermissions(request, ["member.contact.manage"]);
        validateEnvelopeContext(row.contactEnvelope, {
          tenantId: principal.activeTenantId,
          memberId: row.id,
          purpose: "member-contact",
          schemaVersion: 1,
        }, { exact: true });
        validateEnvelopeContentHash(row.contactEnvelope, row.contactContentHash);
      }
    }
    if (body.columnMapping.email !== undefined || body.rows.some((row) => row.decision.matchBasis === "email")) {
      requireAllPermissions(request, ["member.contact.manage"]);
    }
    const columnMapping = Object.fromEntries(
      Object.entries(body.columnMapping).filter((entry): entry is [string, number] => entry[1] !== undefined),
    );
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.previewImport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      sourceFingerprint: body.sourceFingerprint,
      ...(body.sourceFileName ? { sourceFileName: body.sourceFileName } : {}),
      sourceSheetName: body.sourceSheetName,
      columnMapping,
      rows: body.rows.map((row) => ({
        sourceRow: row.sourceRow,
        id: row.id,
        ...(row.shortId ? { shortId: row.shortId } : {}),
        eligible: row.eligible,
        decision: row.decision,
        ...(row.expectedVersion !== undefined ? { expectedVersion: row.expectedVersion } : {}),
        ...(row.displayEnvelope ? { displayEnvelope: row.displayEnvelope } : {}),
        ...(row.displayContentHash ? { displayContentHash: row.displayContentHash } : {}),
        ...(row.contactEnvelope ? { contactEnvelope: row.contactEnvelope } : {}),
        ...(row.contactContentHash ? { contactContentHash: row.contactContentHash } : {}),
      })),
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/members/import/commit", { preHandler: protectedMutation(app, "member.import") }, async (request, reply) => {
    const body = parseBody(memberImportCommitSchema, request);
    const principal = requirePrincipal(request);
    requireAllPermissions(request, ["member.manage", "member.eligibility.manage"]);
    const idempotencyKey = requireIdempotencyKey(request);
    const result = await app.database.withPrincipal(principal, request.id, async (tenant) => {
      if (await tenant.memberImportRequiresContact(body.importId, principal.identityId)) {
        requireAllPermissions(request, ["member.contact.manage"]);
      }
      return tenant.commitImport({
        identityId: principal.identityId,
        idempotencyKey,
        ...body,
      });
    });
    return respond(request, reply, result);
  });

  app.get("/v1/members/imports", { preHandler: protectedRead(app, "member.import") }, async (request, reply) => {
    const { limit } = parseQuery(memberImportHistoryQuery, request);
    return withTenant(app, request, async (tenant) =>
      respond(request, reply, { items: await tenant.listMemberImports(limit) }));
  });

  app.get("/v1/catalog", { preHandler: [app.authenticate] }, async (request, reply) =>
    withTenant(app, request, async (tenant) => respond(request, reply, await tenant.getCatalog())));
  app.get("/v1/catalog/manage", { preHandler: protectedRead(app, "catalog.manage") }, async (request, reply) =>
    withTenant(app, request, async (tenant) => respond(request, reply, await tenant.getCatalog(true))));
  app.get("/v1/tenant/settings", { preHandler: protectedRead(app, "tenant.settings.manage") }, async (request, reply) =>
    withTenant(app, request, async (tenant) => respond(request, reply, await tenant.getTenantSettings())));
  app.patch("/v1/tenant/settings", { preHandler: protectedSensitiveMutation(app, "tenant.settings.manage", "changing tenant configuration", "tenant_administration") }, async (request, reply) => {
    const body = parseBody(tenantSettingsUpdateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.updateTenantSettings({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      expectedVersion: body.expectedVersion,
      ...(body.displayName !== undefined ? { displayName: body.displayName } : {}),
      ...(body.timezone !== undefined ? { timezone: body.timezone } : {}),
      ...(body.locale !== undefined ? { locale: body.locale } : {}),
      ...(body.jurisdiction !== undefined ? { jurisdiction: body.jurisdiction } : {}),
    }));
    return respond(request, reply, result);
  });
  app.post("/v1/catalog/departments", { preHandler: protectedMutation(app, "catalog.manage") }, async (request, reply) => {
    const body = parseBody(localDepartmentCreateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.createLocalDepartment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      canonicalCode: body.canonicalCode,
      names: body.names,
      sortOrder: body.sortOrder,
      metadata: body.metadata,
      ...(body.parentId !== undefined ? { parentId: body.parentId } : {}),
    }));
    return respond(request, reply, result, 201);
  });
  app.patch("/v1/catalog/departments/:departmentId", { preHandler: protectedMutation(app, "catalog.manage") }, async (request, reply) => {
    const { departmentId } = parseParams(z.object({ departmentId: uuid }), request);
    const body = parseBody(localDepartmentUpdateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.updateLocalDepartment({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      departmentId,
      expectedVersion: body.expectedVersion,
      ...(body.names !== undefined ? { names: body.names } : {}),
      ...(body.parentId !== undefined ? { parentId: body.parentId } : {}),
      ...(body.sortOrder !== undefined ? { sortOrder: body.sortOrder } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
      ...(body.metadata !== undefined ? { metadata: body.metadata } : {}),
    }));
    return respond(request, reply, result);
  });
  app.post("/v1/catalog/offices", { preHandler: protectedMutation(app, "catalog.manage") }, async (request, reply) => {
    const body = parseBody(localOfficeCreateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.createLocalOffice({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      departmentId: body.departmentId,
      canonicalCode: body.canonicalCode,
      names: body.names,
      appointmentMechanism: body.appointmentMechanism,
      cardinality: body.cardinality,
      metadata: body.metadata,
    }));
    return respond(request, reply, result, 201);
  });
  app.patch("/v1/catalog/offices/:officeId", { preHandler: protectedMutation(app, "catalog.manage") }, async (request, reply) => {
    const { officeId } = parseParams(z.object({ officeId: uuid }), request);
    const body = parseBody(localOfficeUpdateSchema, request);
    const principal = requirePrincipal(request);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.updateLocalOffice({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      officeId,
      expectedVersion: body.expectedVersion,
      ...(body.departmentId !== undefined ? { departmentId: body.departmentId } : {}),
      ...(body.names !== undefined ? { names: body.names } : {}),
      ...(body.appointmentMechanism !== undefined ? { appointmentMechanism: body.appointmentMechanism } : {}),
      ...(body.cardinality !== undefined ? { cardinality: body.cardinality } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
      ...(body.metadata !== undefined ? { metadata: body.metadata } : {}),
    }));
    return respond(request, reply, result);
  });
  app.get("/v1/organization", { preHandler: protectedRead(app, "organigram.read") }, async (request, reply) => {
    const query = parseQuery(organizationQuerySchema, request);
    const principal = requirePrincipal(request);
    return withTenant(app, request, async (tenant) => {
      const result = await tenant.getOrganization({
        stage: query.stage,
        ...(query.cycleId ? { cycleId: query.cycleId } : {}),
      });
      if (query.cycleId && result["selectedCycle"] === null) {
        throw new ApiError(404, "CYCLE_UNAVAILABLE", "Cycle is unavailable");
      }
      const localItems = Array.isArray(result["items"])
        ? result["items"] as Array<Record<string, unknown>>
        : [];
      const localElectedStructureStarted = localItems.some((item) => typeof item["memberId"] === "string");
      if (query.stage === "elected" && !query.cycleId && !localElectedStructureStarted) {
        const directory = await getGestionChurchOrganizationDirectory(app, principal);
        if (directory?.items.length) {
          reply.header("cache-control", "private, no-store");
          return respond(request, reply, {
            ...result,
            source: directory.source,
            sourceUpdatedAt: directory.sourceUpdatedAt,
            generatedAt: directory.generatedAt,
            directorySummary: directory.summary,
            items: directory.items,
          });
        }
      }
      reply.header("cache-control", "private, no-store");
      return respond(request, reply, result);
    });
  });
  app.get("/v1/committee", { preHandler: [app.authenticate] }, async (request, reply) => {
    requireAnyPermission(request, ["member.read"]);
    return withTenant(app, request, async (tenant) => respond(request, reply, await tenant.getCommittee()));
  });

  app.get("/v1/reports", { preHandler: protectedRead(app, "report.read") }, async (request, reply) => {
    const { limit } = parseQuery(reportQuery, request);
    const principal = requirePrincipal(request);
    const reportScopes = accessibleReportScopes(principal.permissions);
    return withTenant(app, request, async (tenant) =>
      respond(request, reply, { items: await tenant.listReports(limit, reportScopes) }));
  });
  app.get("/v1/reports/workflow-snapshot", { preHandler: protectedRead(app, "report.read") }, async (request, reply) => {
    const query = parseQuery(workflowReportQuerySchema, request);
    const principal = requirePrincipal(request);
    requireAllPermissions(request, requiredReportPermissions(query.reportType, query.audience));
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.getWorkflowReportSnapshot({
      reportType: query.reportType,
      audience: query.audience,
      ...(query.cycleId ? { cycleId: query.cycleId } : {}),
      ...(query.sessionId ? { sessionId: query.sessionId } : {}),
      includeNominalParticipation: query.reportType === "committee_participation"
        && principal.permissions.has("member.read")
        && principal.permissions.has("participation.nominal.read"),
      viewerPermissions: [...principal.permissions],
    }));
    if (query.cycleId && !result["cycle"]) throw new ApiError(404, "CYCLE_UNAVAILABLE", "Cycle is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, result);
  });
  app.get("/v1/reports/:reportId/artifact", {
    preHandler: [...protectedRead(app, "report.read"), app.requirePermission("report.export"), requireRecentMfa("downloading a broad report")],
  }, async (request, reply) => {
    const { reportId } = parseParams(z.object({ reportId: uuid }), request);
    const principal = requirePrincipal(request);
    await requireStoredReportAccess(app, request, reportId);
    const artifact = await app.database.withPrincipal(principal, request.id, (tenant) =>
      tenant.getReportArtifact(reportId, accessibleReportScopes(principal.permissions)));
    if (!artifact) throw new ApiError(404, "REPORT_ARTIFACT_UNAVAILABLE", "Ready report artifact is unavailable");
    reply.header("cache-control", "private, no-store");
    return respond(request, reply, artifact);
  });
  app.post("/v1/reports/generate", {
    preHandler: protectedSensitiveMutation(app, "report.export", "starting a broad report export", "data_export"),
  }, async (request, reply) => {
    const body = parseBody(reportGenerateSchema, request);
    const principal = requirePrincipal(request);
    requireAllPermissions(request, requiredReportPermissions(body.reportType, body.audience));
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.generateReport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      ...body,
    }));
    return respond(request, reply, result, 201);
  });
  app.post("/v1/reports/:reportId/corrections", {
    preHandler: protectedSensitiveMutation(app, "report.export", "issuing a corrected broad report", "data_export"),
  }, async (request, reply) => {
    const { reportId } = parseParams(z.object({ reportId: uuid }), request);
    const body = parseBody(reportCorrectionSchema, request);
    const principal = requirePrincipal(request);
    const previous = await requireStoredReportAccess(app, request, reportId);
    requireAllPermissions(request, requiredReportPermissions(
      previous.reportType as ReportType,
      previous.audience as ReportAudience,
    ));
    if (previous.reportType === "session_minutes" && !body.filters.sessionId) {
      throw new ApiError(400, "REPORT_SESSION_REQUIRED", "A session_minutes correction requires the original selected session");
    }
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.correctReport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      previousReportId: reportId,
      expectedPreviousVersion: body.expectedPreviousVersion,
      reasonCode: body.reasonCode,
      filters: body.filters,
    }));
    return respond(request, reply, result, 201);
  });
  app.post("/v1/reports/:reportId/complete", {
    preHandler: protectedMutation(app, "report.export"),
    bodyLimit: 30 * 1024 * 1024,
  }, async (request, reply) => {
    const { reportId } = parseParams(z.object({ reportId: uuid }), request);
    const body = parseBody(reportCompleteSchema, request);
    const principal = requirePrincipal(request);
    const report = await requireStoredReportAccess(app, request, reportId);
    validateEnvelopeContext(body.envelope, {
      tenantId: principal.activeTenantId,
      reportId,
      requestVersion: body.expectedVersion,
      reportType: report.reportType,
      audience: report.audience,
      locale: report.locale,
      format: report.format,
      filename: report.filename,
      mediaType: report.mediaType,
      snapshotSha256: report.snapshotSha256,
      ...(report.supersedesReportId ? {
        supersedesReportId: report.supersedesReportId,
        correctionReasonCode: report.correctionReasonCode,
        lineageRootId: report.lineageRootId,
        lineageRevision: report.lineageRevision,
      } : {}),
      purpose: "report-artifact",
      schemaVersion: 1,
      plaintextBytes: body.plaintextBytes,
    }, { exact: true });
    validateEnvelopeContentHash(body.envelope, body.artifactSha256);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.completeReport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      reportId,
      expectedVersion: body.expectedVersion,
      envelope: body.envelope,
      artifactSha256: body.artifactSha256,
      ciphertextSha256: body.ciphertextSha256,
      plaintextBytes: body.plaintextBytes,
      rowCount: body.rowCount,
      generatedAt: body.generatedAt,
    }));
    return respond(request, reply, result);
  });
  app.post("/v1/reports/:reportId/fail", { preHandler: protectedMutation(app, "report.export") }, async (request, reply) => {
    const { reportId } = parseParams(z.object({ reportId: uuid }), request);
    const body = parseBody(reportFailSchema, request);
    const principal = requirePrincipal(request);
    await requireStoredReportAccess(app, request, reportId);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.failReport({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      reportId,
      expectedVersion: body.expectedVersion,
      errorCode: body.errorCode,
    }));
    return respond(request, reply, result);
  });
  app.post("/v1/reports/:reportId/print", {
    preHandler: protectedSensitiveMutation(app, "report.export", "printing a broad report", "data_export"),
  }, async (request, reply) => {
    const { reportId } = parseParams(z.object({ reportId: uuid }), request);
    const body = parseBody(reportPrintSchema, request);
    const principal = requirePrincipal(request);
    await requireStoredReportAccess(app, request, reportId);
    const result = await app.database.withPrincipal(principal, request.id, (tenant) => tenant.recordReportPrint({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      reportId,
      artifactSha256: body.artifactSha256,
      permittedReportScopes: accessibleReportScopes(principal.permissions),
    }));
    return respond(request, reply, result, 201);
  });

  app.post("/v1/assignments/:assignmentId/consent", {
    preHandler: protectedMutation(app, "consent.record"),
  }, async (request, reply) => {
    const { assignmentId } = parseParams(z.object({ assignmentId: uuid }), request);
    const body = parseBody(assignmentConsentBodySchema, request);
    const principal = requirePrincipal(request);
    validateEnvelopeContext(body.envelope, {
      tenantId: principal.activeTenantId,
      assignmentId,
      purpose: "assignment-consent",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.recordAssignmentConsent({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      status: body.status,
      envelope: body.envelope,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    throwIfAssignmentEligibilityPaused(result);
    return respond(request, reply, result);
  });

  app.post("/v1/assignments/:assignmentId/congregational-decision", {
    preHandler: protectedMutation(app, "congregational-decision.record"),
  }, async (request, reply) => {
    const { assignmentId } = parseParams(z.object({ assignmentId: uuid }), request);
    const body = parseBody(assignmentCongregationalDecisionBodySchema, request);
    const principal = requirePrincipal(request);
    validateEnvelopeContext(body.envelope, {
      tenantId: principal.activeTenantId,
      assignmentId,
      purpose: "congregational-decision",
      schemaVersion: 1,
    }, { exact: true });
    const result = await app.database.withCoreWorkflowPrincipal(principal, request.id, (workflow) => workflow.recordCongregationalDecision({
      identityId: principal.identityId,
      idempotencyKey: requireIdempotencyKey(request),
      assignmentId,
      expectedVersion: body.expectedVersion,
      outcome: body.outcome,
      envelope: body.envelope,
      ...(body.sessionId !== undefined ? { sessionId: body.sessionId } : {}),
    }));
    throwIfAssignmentEligibilityPaused(result);
    return respond(request, reply, result);
  });

  app.get("/v1/audit", { preHandler: protectedRead(app, "audit.read") }, async (request, reply) => {
    const query = parseQuery(auditQuery, request);
    return withTenant(app, request, async (tenant) => respond(request, reply, await tenant.listAudit(query.limit, query.beforeSequence)));
  });

  app.post("/v1/devices/rotate", { preHandler: protectedMutation(app, "recovery.activate") }, async (request) => {
    const body = parseBody(rotateKeySchema, request);
    requireIdempotencyKey(request);
    const principal = requirePrincipal(request);
    await app.database.withPrincipal(principal, request.id, (tenant) => tenant.recordSecurityDenial(
      "device-key.rotate.step-up-required",
      "device-key-grant",
      body.deviceId,
      { expectedVersion: body.expectedVersion, requestedVersion: body.version },
    ));
    throw new ApiError(
      428,
      "RECOVERY_STEP_UP_REQUIRED",
      "A recent dedicated MFA step-up is required before rotating a device key grant",
    );
  });
}

function protectedRead(app: FastifyInstance, permission: string) {
  return [app.authenticate, app.requirePermission(permission)];
}

function protectedMutation(app: FastifyInstance, permission: string) {
  return [app.authenticate, app.verifyCsrf, app.requirePermission(permission)];
}

function protectedSensitiveMutation(
  app: FastifyInstance,
  permission: string,
  recentMfaPurpose: string,
  purpose: "data_export" | "tenant_administration",
) {
  return [...protectedMutation(app, permission), requirePolicyAwareOperationStepUp({
    action: permission,
    purpose,
    recentMfaPurpose,
  })];
}

function requirePrincipal(request: FastifyRequest) {
  if (!request.principal) throw unauthorized();
  return request.principal;
}

function requireAnyPermission(request: FastifyRequest, permissions: readonly string[]): void {
  const principal = requirePrincipal(request);
  if (!permissions.some((permission) => principal.permissions.has(permission))) {
    throw forbidden(permissions.join("|"));
  }
}

function requireAllPermissions(request: FastifyRequest, permissions: readonly string[]): void {
  const principal = requirePrincipal(request);
  const missing = permissions.find((permission) => !principal.permissions.has(permission));
  if (missing) throw forbidden(missing);
}

async function withTenant<T>(
  app: FastifyInstance,
  request: FastifyRequest,
  work: (tenant: import("@nombramientos/database").TenantStore) => Promise<T>,
): Promise<T> {
  const principal = requirePrincipal(request);
  return app.database.withPrincipal(principal, request.id, work);
}

async function requireStoredReportAccess(
  app: FastifyInstance,
  request: FastifyRequest,
  reportId: string,
): Promise<NonNullable<Awaited<ReturnType<import("@nombramientos/database").TenantStore["getReportDescriptor"]>>>> {
  const principal = requirePrincipal(request);
  const report = await app.database.withPrincipal(principal, request.id, (tenant) =>
    tenant.getReportDescriptor(reportId));
  if (!report) throw new ApiError(404, "REPORT_UNAVAILABLE", "Report is unavailable");
  if (!canAccessReport(principal.permissions, report.reportType, report.audience)) {
    throw new ApiError(403, "REPORT_SCOPE_FORBIDDEN", "Current permissions do not allow this report type and audience");
  }
  return report;
}
