import type {
  PasskeyAuthenticationOptions,
  PasskeyAuthenticationResponse,
  PasskeyRegistrationOptions,
  PasskeyRegistrationResponse,
} from "./webauthn.ts";
import { authenticateWithPasskey, isPasskeyCancellation } from "./webauthn.ts";
import { SESSION_INVALID_EVENT } from "./gestionchurch-session.ts";
import { RequestInterruptedError, TRANSFER_TIMEOUT_MS, withRequestDeadline } from "./request-deadline.ts";
import {
  clearDeviceSigner, currentDeviceProofContext, currentDeviceSigner, deviceRequestRequiresProof, deviceRequestRetryHeaders,
  DeviceSessionClientError, hashDeviceRequestBody, setDeviceProofContext, signDeviceClaims, validateDeviceRequestClaims,
  type DeviceRequestClaims, type DeviceSigningPublicJwk,
} from "./device-session-proof.ts";

export type Locale = "es" | "en" | "fr";

export const REPORT_TYPES = [
  "cycle_summary",
  "general_recommendations",
  "elected_board",
  "department",
  "office_round",
  "committee_participation",
  "responsibility_distribution",
  "unconsidered_unassigned",
  "progress",
  "session_minutes",
  "cycle_history",
  "audit_integrity",
  "roster_import_incidents",
] as const;
export type ReportType = (typeof REPORT_TYPES)[number];
export type ReportAudience = "committee" | "auditor" | "church";
export type ReportFormat = "pdf" | "xlsx" | "csv";
export const REPORT_CORRECTION_REASON_CODES = [
  "SOURCE_DATA_CORRECTED",
  "TRANSLATION_CORRECTED",
  "STRUCTURE_CORRECTED",
  "LAYOUT_CORRECTED",
  "AUTHORIZED_CORRECTION",
] as const;
export type ReportCorrectionReasonCode = (typeof REPORT_CORRECTION_REASON_CODES)[number];
export type ReportFilters = {
  cycleId?: string | null;
  term?: string | null;
  sessionId?: string | null;
  department?: string | null;
  office?: string | null;
  personId?: string | null;
  phase?: string | null;
  assignmentState?: string | null;
  snapshotSha256: `sha256:${string}`;
  snapshotAt: string;
};

export type Envelope = {
  algorithm: "AES-256-GCM" | "XCHACHA20-POLY1305";
  keyId: string;
  nonce: string;
  ciphertext: string;
  aad: string;
};

export type KeyGrant = {
  version: number;
  tenantKeyId: string;
  kdf: { name: "PBKDF2"; salt: string; iterations: number; hash: "SHA-256" };
  wrap: { algorithm: "AES-GCM"; iv: string; ciphertext: string; aad: string };
};

export type AuthenticatedSession = {
  sessionId?: string;
  authenticated: true;
  status: "authenticated" | "mfa_enrollment_required" | "security_recovery_required";
  user: { id: string; displayName: string; email: string };
  tenant: { id: string; slug: string; name: string; kind: "demo" | "real"; timezone: string };
  permissions: string[];
  csrfToken: string;
  expiresAt: string;
  /** Authoritative UTC time returned with this session, not the device wall clock. */
  serverTime?: string;
  /** Client-only monotonic receipt anchor; never sent or persisted. */
  receivedAtMonotonic?: number;
  keyGrant?: KeyGrant | null;
  security: {
    mfaRequired: boolean;
    mfaEnabled: boolean;
    enrollmentOnly: boolean;
    assurance: "enrollment_only" | "password" | "mfa" | "recovery_limited" | "aal1" | "aal2" | "aal3";
    aal?: 1 | 2 | 3;
    authMethod?: "password" | "totp" | "recovery_code" | "passkey" | "federated" | "bootstrap";
    phishingResistant?: boolean;
    recoveryRestricted?: boolean;
    passkeyEnabled?: boolean;
    strongAuthEnabled?: boolean;
    passkeyCount?: number;
    idleExpiresAt?: string | null;
    risk?: {
      elevated: boolean;
      userAgentContextChanged: boolean;
      ipContextChanged: boolean;
    };
  };
};

export type LoginResult =
  | Omit<AuthenticatedSession, "authenticated">
  | { status: "mfa_required"; challengeId: string; expiresAt: string };

export type MfaEnrollmentStarted = {
  enrollmentId: string;
  secret: string;
  otpauthUri: string;
  expiresAt: string;
  algorithm: "SHA1";
  digits: 6;
  period: 30;
};

export type MfaEnrollmentPending = Pick<MfaEnrollmentStarted, "enrollmentId" | "expiresAt">;

export type MfaEnrollmentCompleted = AuthenticatedSession & { recoveryCodes: string[] };

export type PasskeyCredentialSummary = {
  id: string;
  version: number;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  transports: string[];
  deviceType: "singleDevice" | "multiDevice" | "unknown";
  backedUp: boolean;
  attachment: "platform" | "cross-platform" | null;
  trustLevel: "unverified" | "self" | "attested" | "enterprise_attested";
  revokedAt?: string | null;
};

export type AuthSessionSummary = {
  id: string;
  current: boolean;
  deviceLabel: string | null;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  authMethod: "password" | "totp" | "recovery_code" | "passkey" | "federated" | "bootstrap";
  assurance: string;
  aal: 1 | 2 | 3;
  phishingResistant: boolean;
  risk?: {
    elevated: boolean;
    userAgentContextChanged: boolean | null;
    ipContextChanged: boolean;
  };
  revokedAt?: string | null;
};

export type PasskeyAuthenticationCeremony = {
  ceremonyId: string;
  options: PasskeyAuthenticationOptions;
  expiresAt: string;
};

export type PasskeyRegistrationCeremony = {
  ceremonyId: string;
  options: PasskeyRegistrationOptions;
  expiresAt: string;
};

export type PasskeyRegistrationResult = {
  verified: true;
  credential: PasskeyCredentialSummary;
  session?: AuthenticatedSession;
};

export type PasskeyStepUpResult = {
  verified: true;
  grantToken: string;
  expiresAt: string;
  purpose: string;
  operationHash: string;
};

export type IdentityActionRequirement = {
  minAal: 1 | 2 | 3;
  phishingResistant?: boolean;
  stepUpRequired?: boolean;
};

export type EnterpriseIdentityPolicy = {
  baselineVersion: number;
  tenantVersion: number | null;
  enforcementMode: "monitor" | "enforce";
  minimumAal: 1 | 2 | 3;
  privilegedMinimumAal: 2 | 3;
  requireUserVerification: boolean;
  requirePhishingResistantForPrivileged: boolean;
  requireDeviceBoundForPrivileged: boolean;
  requireAttestationForPrivileged: boolean;
  allowPassword: boolean;
  allowTotpFallback: boolean;
  allowRecoveryCodes: boolean;
  allowSyncedPasskeys: boolean;
  minimumPasskeyCount: number;
  privilegedMinimumPasskeyCount: number;
  maximumPasskeys: number;
  maximumActiveSessions: number;
  idleTimeoutMinutes: number;
  absoluteSessionMinutes: number;
  stepUpTtlSeconds: number;
  actionRequirements: Readonly<Record<string, IdentityActionRequirement>>;
};

export type IdentityPolicyState = {
  policy: EnterpriseIdentityPolicy;
  compliance: {
    enforcementMode: "monitor" | "enforce";
    sessionMeetsMinimum: boolean;
    privilegedSessionReady: boolean;
    activePasskeys: number;
    minimumPasskeys: number;
    privilegedMinimumPasskeys: number;
    findings: string[];
  };
};

export type IdentityPolicyValues = Omit<EnterpriseIdentityPolicy, "baselineVersion" | "tenantVersion">;

export type TenantMembership = {
  tenantId: string;
  slug: string;
  displayName: string;
  kind: "demo" | "real";
  tenantStatus: "provisioning" | "active" | "suspended" | "failed";
  membershipStatus: "invited" | "active" | "suspended" | "revoked";
  isDefault: boolean;
  locale: Locale;
  timezone: string;
};

export type AccessPermission = {
  code: string;
  description: string;
  possessed: boolean;
  delegable: boolean;
};

export type AccessRole = {
  id: string;
  code: string;
  name: Record<Locale, string>;
  system: boolean;
  version: number;
  permissions: Array<{ code: string; delegable: boolean }>;
};

export type AccessIdentity = {
  identityId: string;
  displayName: string;
  email: string;
  membershipStatus: string;
  gestionChurchManaged?: boolean;
};

export type AccessBinding = {
  identityId: string;
  roleId: string;
  roleCode: string;
  version: number;
  grantedAt: string;
  grantedByIdentityId: string | null;
  identity: AccessIdentity | null;
};

export type PlatformTenant = {
  id: string;
  slug: string;
  displayName: string;
  kind: "demo" | "real";
  status: "provisioning" | "active" | "suspended" | "failed" | "decommission_pending";
  timezone: string;
  locale: Locale;
  version: number;
  provisioningState: string | null;
  provisioningAttempts: number;
  lastErrorCode: string | null;
  activationState: "pending_activation" | "invitation_pending" | "admin_active" | "active";
  latestExport: PlatformTenantExport | null;
  decommission: PlatformTenantDecommission | null;
  createdAt: string;
  updatedAt: string;
};

export type PlatformTenantExportManifest = {
  format: "nombramientos-tenant-export";
  version: 1;
  backupId: string;
  tenantId: string;
  recoveryPointAt: string;
  completedAt: string;
  encryption: {
    algorithm: "AES-256-GCM";
    authenticatedCoreSha256: `sha256:${string}`;
    keyCustody: "platform-managed-not-exported";
  };
  payload: { file: "database.dump.aesgcm"; bytes: number; sha256: `sha256:${string}` };
};

export type PlatformTenantExport = {
  id: string;
  tenantId: string;
  tenantVersion: number;
  state: "queued" | "running" | "ready" | "failed";
  attemptCount: number;
  revision: number;
  publicManifest: PlatformTenantExportManifest | null;
  encryptedBytes: number | null;
  ciphertextSha256: `sha256:${string}` | null;
  recoveryPointAt: string | null;
  lastErrorCode: string | null;
  createdAt: string;
  updatedAt: string;
  readyAt: string | null;
  failedAt: string | null;
};

export type PlatformTenantDecommission = {
  id: string;
  state: "scheduled" | "cancelled";
  sourceExportJobId: string;
  reasonCode: "institution_request" | "duplicate_tenant" | "service_ended" | "legal_retention";
  retentionUntil: string;
  version: number;
  scheduledAt: string;
  cancelledAt: string | null;
};

export type ProvisioningWorkerStatus = {
  code: "tenant-provisioner";
  status: "starting" | "running" | "stopping" | "stopped" | "failed" | "unavailable";
  healthy: boolean;
  startedAt: string | null;
  heartbeatAt: string | null;
  processedCount: number;
  lastErrorCode: string | null;
};

export type InitialAdminRecoveryStatus =
  | "pending"
  | "finalization_pending"
  | "enrollment_pending"
  | "admin_active"
  | "revoked"
  | "expired"
  | "failed";

export type InitialAdminRecoveryDeliveryChannel =
  | "local_console"
  | "verified_email"
  | "verified_sms"
  | "service_desk";

export type InitialAdminRecoveryDeliveryState = "not_started" | "pending" | "delivered" | "failed";

export type InitialAdminRecoveryReasonCode =
  | "browser_context_lost"
  | "browser_profile_reset"
  | "device_lost"
  | "session_delivery_failure";

export type InitialAdminRecoverySource = {
  tenantId: string;
  invitationId: string;
  acceptanceId: string;
  acceptanceIdentityId: string;
  acceptanceAttempt: number;
  authorityEpoch: number;
  invitationVersion: number;
};

export type InitialAdminRecoveryCandidate = InitialAdminRecoverySource & {
  tenantDisplayName: string;
  recipientEmail: string;
  recipientDisplayName: string;
  authorityFinalizedAt: string;
};

export type InitialAdminRecoveryQueueItem = InitialAdminRecoverySource & {
  recoveryId: string;
  version: number;
  status: InitialAdminRecoveryStatus;
  tenantDisplayName: string;
  recipientEmail: string;
  recipientDisplayName: string;
  requesterIdentityId: string;
  requesterEmail: string;
  requesterDisplayName: string;
  approverIdentityId: string | null;
  approverEmail: string | null;
  approverDisplayName: string | null;
  reasonCode: InitialAdminRecoveryReasonCode;
  deliveryChannel: InitialAdminRecoveryDeliveryChannel | null;
  deliveryState: InitialAdminRecoveryDeliveryState;
  requestedAt: string;
  requestExpiresAt: string;
  approvedAt: string | null;
  tokenExpiresAt: string | null;
  redemptionCount: number;
  strongFactorFinalizedAt: string | null;
  revokedAt: string | null;
  revocationReasonCode: "security_response" | "requester_cancelled" | "delivery_reissue" | "governance_invalidated" | null;
  failureCode: string | null;
};

export type InitialAdminRecoveryCursor = {
  beforeRequestedAt: string;
  beforeRecoveryId: string;
};

export type InitialAdminRecoveryRequest = {
  recoveryId: string;
  source: InitialAdminRecoverySource;
  reasonCode: InitialAdminRecoveryReasonCode;
  caseReference: string;
  expiresInMinutes: number;
};

export type InitialAdminRecoveryApproval = {
  recoveryId: string;
  expectedVersion: number;
  source: InitialAdminRecoverySource;
  deliveryChannel: InitialAdminRecoveryDeliveryChannel;
  verifiedChannelReference: string;
};

export type InitialAdminRecoveryRevocationReason = "security_response" | "requester_cancelled" | "delivery_reissue";

export type InitialAdminRecoveryRedemption = AuthenticatedSession & {
  recovered: true;
  status: "mfa_enrollment_required";
};

export type DashboardData = {
  tenant: { id: string; name: string; kind: "demo" | "real" };
  cycle: {
    id: string;
    name: string;
    status: string;
    termStart: string;
    termEnd: string;
    version: number;
    updatedAt: string;
  } | null;
  metrics: {
    membersTotal: number;
    eligibleReference: number;
    vacanciesTotal: number;
    recommended: number;
    accepted: number;
    congregationallyElected: number;
    coveragePercent: number | null;
  };
  activeRound: {
    id: string;
    phase: string;
    version: number;
    officeName: string;
    officeNames?: Partial<Record<Locale, string>>;
    responsesRequired: number;
    responsesReceived: number;
  } | null;
  analytics: {
    roundParticipation: Array<{
      roundId: string;
      kind: "proposal" | "vote";
      officeName: string;
      officeNames?: Partial<Record<Locale, string>>;
      phase: string;
      version: number;
      required: number;
      received: number;
      recordedAt: string;
    }>;
    departments: Array<{
      departmentId: string | null;
      departmentName: string | null;
      departmentNames: Partial<Record<Locale, string>> | null;
      vacanciesTotal: number;
      recommended: number;
      accepted: number;
      elected: number;
      coveragePercent: number | null;
    }>;
    sessions: Array<{
      sessionId: string;
      sequence: number;
      status: "scheduled" | "in_progress" | "closed";
      version: number;
      startsAt: string;
      updatedAt: string;
      agendaItems: number;
      decisions: number;
    }>;
  };
  updatedAt: string;
};

export type CandidateRecord = {
  id: string;
  memberId: string;
  shortId?: string;
  displayEnvelope: Envelope;
  eligible: boolean;
  alreadyAssignedCount: number;
};

export type ActiveRoundData = {
  viewerCanSubmit: boolean;
  round: {
    id: string;
    cycleId: string;
    officeProcessId: string;
    officeCode: string;
    officeName: string;
    officeNames?: Partial<Record<Locale, string>>;
    phase: string;
    version: number;
    vacancies: number;
    maxSelections: number;
    submissionKind: "proposal" | "vote";
    candidateSetHash: string;
    rulesHash: string;
    openedAt: string;
  };
  participation: { required: number; received: number; pending: number; abstentions?: number };
  candidates: CandidateRecord[];
};

export type CustodySuite = {
  kem: "DHKEM(P-256, HKDF-SHA256)";
  kemId: 16;
  kdf: "HKDF-SHA256";
  kdfId: 1;
  aead: "AES-256-GCM";
  aeadId: 2;
};

export type CustodyPublicKey = {
  keyId: string;
  custodianIdentityId: string;
  deviceId: string;
  recipientId: string;
  version: number;
  status: "active" | "superseded" | "revoked";
  suite: CustodySuite;
  hpkePublicKey: string;
  hpkeFingerprint: `sha256:${string}`;
  signingAlgorithm: "Ed25519";
  signingPublicKeySpki: string;
  signingFingerprint: `sha256:${string}`;
  registeredAt?: string;
  revokedAt?: string | null;
};

export type BallotRecipients = {
  roundId: string;
  roundVersion: number;
  custodyVersion: number;
  suite: CustodySuite;
  recipients: Array<{
    recipientId: string;
    fingerprint: `sha256:${string}`;
    hpkePublicKey: string;
  }>;
};

export type TallyDecisionRule =
  | { kind: "PLURALITY" }
  | {
      kind: "STRICT_MAJORITY";
      threshold: number;
      denominator: "NON_ABSTAINING_BALLOTS" | "ALL_RECEIVED_BALLOTS";
    };

export type TallyAggregate = {
  readonly schemaVersion: 1;
  readonly receivedBallots: number;
  readonly nonAbstainingBallots: number;
  readonly abstentions: number;
  readonly maxSelections: number;
  readonly candidates: readonly { readonly candidateId: string; readonly votes: number }[];
  readonly rule: TallyDecisionRule;
  readonly decision: {
    readonly status: "SELECTED" | "PARTIAL_SELECTION" | "TIEBREAK_REQUIRED" | "NO_SELECTION";
    readonly reason: "TOP_K" | "CUTOFF_TIE" | "NO_VALID_CANDIDATE_VOTES" | "THRESHOLD_NOT_MET" | "INSUFFICIENT_QUALIFIED_CANDIDATES";
    readonly selectedCandidateIds: readonly string[];
    readonly tiebreakCandidateIds: readonly string[];
    readonly unfilledSeats: number;
  };
};

export type RoundCustody = {
  roundId: string;
  roundVersion: number;
  version: number;
  decisionRule: TallyDecisionRule;
  frozenAt: string;
  custodians: CustodyPublicKey[];
};

export type TallyManifest = {
  manifest: {
    manifestId: string;
    roundId: string;
    custodyVersion: number;
    roundVersion: number;
    decisionRule: TallyDecisionRule;
    manifestHash: `sha256:${string}`;
    entryCount: number;
    state: "awaiting_attestations" | "publishable" | "disputed" | "published";
    agreedAggregateHash: `sha256:${string}` | null;
    version: number;
    createdAt: string;
    publishedAt: string | null;
  };
  custodian: CustodyPublicKey;
  entries: Array<{
    receiptId: string;
    contentHash: `sha256:${string}`;
    envelopeHash: `sha256:${string}`;
    envelope: unknown;
  }>;
};

export type PublishedAggregate = {
  roundId: string;
  manifestId: string;
  manifestHash: `sha256:${string}`;
  aggregateHash: `sha256:${string}`;
  aggregate: TallyAggregate;
  state: "published";
  version: number;
  publishedAt: string;
};

export type MemberRecord = {
  id: string;
  shortId: string;
  displayEnvelope: Envelope | null;
  /** Present only with member.contact.read. */
  contactEnvelope?: Envelope;
  /** True when a legacy combined envelope is quarantined and needs authorized client-side replacement. */
  profileMigrationRequired: boolean;
  /** Present only when the current principal possesses private-note.read and a review exists. */
  eligibilityEnvelope?: Envelope;
  /** Public, structured operational scope. Null means every active department. */
  departmentRestriction: string | null;
  /** Inclusive tenant civil date; null means no automatic expiry. */
  validUntil: string | null;
  /** Tenant civil date used to compute the returned `eligible` projection. */
  eligibilityEvaluatedOn: string;
  eligible: boolean;
  eligibilityStatus?: "eligible" | "ineligible" | "review";
  available?: boolean;
  archived: boolean;
  archivedAt?: string | null;
  currentResponsibilities: number;
  version: number;
};

export type MemberQualificationType = "training" | "ordination" | "certification" | "other";
export type MemberQualificationStatus = "pending" | "verified" | "expired" | "revoked";

export type MemberQualificationMetadata = {
  qualificationId: string;
  memberId: string;
  version: number;
  type: MemberQualificationType;
  status: MemberQualificationStatus;
  effectiveOn: string;
  expiresOn: string | null;
  hasDetails: boolean;
  reviewerIdentityId: string;
  recordedAt: string;
};

export type MemberQualificationRevision = MemberQualificationMetadata & {
  detailsEnvelope: Envelope | null;
  detailsContentHash: `sha256:${string}` | null;
};

export type MemberQualificationRecord = MemberQualificationRevision & {
  revisions: MemberQualificationRevision[];
};

export type MemberQualificationList = {
  memberId: string;
  eligibilityInference: false;
  items: MemberQualificationRecord[];
};

export type MemberQualificationWrite = {
  type: MemberQualificationType;
  status: MemberQualificationStatus;
  effectiveOn: string;
  expiresOn: string | null;
  detailsEnvelope: Envelope | null;
  detailsContentHash: `sha256:${string}` | null;
};

export type MemberImportRowResult = {
  sourceRow: number;
  action: "create" | "update" | "skip";
  status: "ready" | "error";
  codes: string[];
};

export type MemberImportSummary = {
  importId: string;
  state: "completed";
  created: number;
  updated: number;
  skipped: number;
  rejected: number;
  total: number;
  replayed?: boolean;
};

export type MemberImportPreviewResponse = {
  importId: string;
  rowCount: number;
  state: "previewed" | "completed";
  createdAt: string;
  revision: number;
  counts?: { create: number; update: number; skip: number; errors: number };
  rows: MemberImportRowResult[];
  summary?: Omit<MemberImportSummary, "importId" | "state">;
};

export type MemberExportAuthorization = {
  authorizationId: string;
  format: "csv" | "xlsx";
  rowCount: number;
  includeContact: boolean;
  selectionSha256: `sha256:${string}`;
  authorizedAt: string;
  expiresAt: string;
};

export type MemberImportHistory = {
  id: string;
  sourceFileName: string | null;
  sourceSheetName: string;
  state: "previewed" | "committing" | "completed" | "failed";
  rowCount: number;
  summary: Omit<MemberImportSummary, "importId" | "state"> | null;
  errorCount: number;
  errors: Array<{ sourceRow: number; action: "create" | "update" | "skip"; codes: string[] }>;
  errorsTruncated: boolean;
  revision: number;
  createdAt: string;
  completedAt: string | null;
};

export type OrganizationRecord = {
  id: string;
  memberId?: string;
  departmentId?: string;
  officeName: string;
  departmentName: string;
  officeNames?: Partial<Record<Locale, string>>;
  departmentNames?: Partial<Record<Locale, string>>;
  status: "vacant" | "recommended" | "accepted" | "elected" | string;
  displayEnvelope?: Envelope;
  linkedToId?: string;
  independent?: boolean;
};

export type CommitteeRecord = {
  id: string;
  cycleId: string;
  identityId: string;
  memberId?: string;
  displayEnvelope?: Envelope;
  role: string;
  votingRight: boolean;
  status: string;
};

export type AuditRecord = {
  sequence?: string | number;
  action?: string;
  result?: string;
  createdAt?: string;
};

export type StoredReport = {
  id: string;
  reportType: ReportType;
  format: ReportFormat | "html";
  locale: Locale;
  filename: string;
  mediaType: string;
  createdAt: string;
  createdBy?: string;
  audience: ReportAudience;
  filters: Readonly<Record<string, unknown>>;
  state: "queued" | "pending" | "ready" | "failed" | "expired";
  version: number;
  artifactSha256: `sha256:${string}` | null;
  ciphertextSha256: `sha256:${string}` | null;
  ciphertextBytes: number | null;
  plaintextBytes: number | null;
  manifest: ReportArtifactManifest | null;
  errorCode: string | null;
  supersedesReportId: string | null;
  correctedByReportId: string | null;
  correctionReasonCode: ReportCorrectionReasonCode | null;
  lineageRootId: string;
  lineageRevision: number;
  readyAt: string | null;
  failedAt: string | null;
};

export type ReportArtifactManifest = {
  schemaVersion: 1;
  reportId: string;
  reportType: ReportType;
  audience: ReportAudience;
  locale: Locale;
  format: ReportFormat;
  requestVersion: number;
  snapshotSha256: `sha256:${string}`;
  artifactSha256: `sha256:${string}`;
  ciphertextSha256: `sha256:${string}`;
  ciphertextBytes: number;
  plaintextBytes: number;
  rowCount: number;
  generatedAt: string;
  lineageRootId?: string;
  lineageRevision?: number;
  supersedesReportId?: string | null;
  correctionReasonCode?: ReportCorrectionReasonCode | null;
};

export type PendingReport = Omit<StoredReport,
  "format" | "filters" | "state" | "artifactSha256" | "ciphertextSha256" | "ciphertextBytes" | "plaintextBytes" | "manifest" | "errorCode" | "readyAt" | "failedAt"
> & {
  format: ReportFormat;
  filters: ReportFilters;
  state: "pending";
  artifactSha256: null;
  ciphertextSha256: null;
  ciphertextBytes: null;
  plaintextBytes: null;
  manifest: null;
  errorCode: null;
  readyAt: null;
  failedAt: null;
  mediaType: string;
};

export type GeneratedReport = Omit<PendingReport,
  "state" | "artifactSha256" | "ciphertextSha256" | "ciphertextBytes" | "plaintextBytes" | "manifest" | "readyAt"
> & {
  state: "ready";
  artifactSha256: `sha256:${string}`;
  ciphertextSha256: `sha256:${string}`;
  ciphertextBytes: number;
  plaintextBytes: number;
  manifest: ReportArtifactManifest;
  readyAt: string;
};

export type StoredReportArtifact = {
  envelope: Envelope;
  filename: string;
  mediaType: string;
  artifactSha256: `sha256:${string}`;
  ciphertextSha256: `sha256:${string}`;
  ciphertextBytes: number;
  plaintextBytes: number;
  requestVersion: number;
  manifest: ReportArtifactManifest;
  reportType: ReportType;
  audience: ReportAudience;
  locale: Locale;
  format: ReportFormat;
  version: number;
  supersedesReportId: string | null;
  correctionReasonCode: ReportCorrectionReasonCode | null;
  lineageRootId: string;
  lineageRevision: number;
};

type ApiEnvelope<T> = { data: T; meta?: { requestId?: string } };
type ApiErrorDetails = Readonly<Record<string, unknown>>;
type StepUpRequiredDetails = { purpose: string; operationHash: string };

function isStepUpRequiredDetails(value: unknown): value is StepUpRequiredDetails {
  if (!value || typeof value !== "object") return false;
  const details = value as Record<string, unknown>;
  return typeof details["purpose"] === "string"
    && details["purpose"].length > 0
    && typeof details["operationHash"] === "string"
    && /^[a-f0-9]{64}$/u.test(details["operationHash"]);
}

export class ApiError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly requestId: string | undefined;
  public readonly details: ApiErrorDetails | undefined;

  constructor(
    status: number,
    code: string,
    message: string,
    requestId?: string,
    details?: ApiErrorDetails,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

function defaultApiUrl(): string {
  if (typeof window !== "undefined" && ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname)) {
    const host = window.location.hostname === "[::1]" ? "[::1]" : window.location.hostname;
    return `${window.location.protocol}//${host}:4000`;
  }
  return "http://localhost:4000";
}

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? defaultApiUrl();
export const apiBaseUrl = API_URL;
let csrfToken: string | undefined;
let deviceProofTenantKind: AuthenticatedSession["tenant"]["kind"] | undefined;

export function setCsrfToken(value?: string) {
  csrfToken = value;
  if (!value) setDeviceProofContext(undefined);
}

export function idempotencyKey() {
  return crypto.randomUUID();
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit & { idempotent?: boolean; idempotencyKey?: string; stepUpAttempted?: boolean; csrf?: boolean } = {},
): Promise<T> {
  const {
    idempotent,
    idempotencyKey: logicalIdempotencyKey,
    stepUpAttempted = false,
    csrf: includeCsrf = true,
    ...requestInit
  } = init;
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  const multipart = typeof FormData !== "undefined" && init.body instanceof FormData;
  const multipartTransfer = multipart || /^multipart\/form-data(?:;|$)/iu.test(headers.get("content-type") ?? "");
  if (init.body && !multipart && !headers.has("content-type")) headers.set("content-type", "application/json");
  const method = (init.method ?? "GET").toUpperCase();
  if (includeCsrf && !["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) headers.set("x-csrf-token", csrfToken);
  const resolvedIdempotencyKey = idempotent ? logicalIdempotencyKey ?? idempotencyKey() : undefined;
  if (resolvedIdempotencyKey) headers.set("idempotency-key", resolvedIdempotencyKey);

  const { response, body } = await boundedRequest(async (signal) => {
    // Preparation is inside the same deadline and cancellation boundary as the
    // transfer. Bootstrap/unbound requests keep the browser's multipart behavior.
    if ((currentDeviceProofContext() || (process.env.NEXT_PUBLIC_GESTIONCHURCH_URL && deviceProofTenantKind !== "demo")) && deviceRequestRequiresProof(path, method)) {
      if (multipart) {
        const prepared = new Request(`${API_URL}${path}`, { method, body: init.body });
        headers.set("content-type", prepared.headers.get("content-type")!);
        requestInit.body = await prepared.arrayBuffer();
      }
      await applyDeviceRequestProof(path, method, requestInit.body, headers, signal);
    }
    const response = await fetch(`${API_URL}${path}`, {
      ...requestInit,
      headers,
      signal,
      credentials: "include",
      cache: "no-store",
    });
    const body = response.ok && response.status === 204 ? undefined : await response.json().catch(() => undefined) as
      | ApiEnvelope<T>
      | { error?: { code?: string; message?: string; details?: ApiErrorDetails } }
      | undefined;
    return { response, body };
  }, { signal: init.signal, timeoutMs: multipartTransfer ? TRANSFER_TIMEOUT_MS : undefined }, method);
  const requestId = response.headers.get("x-request-id") ?? undefined;
  if (response.ok && response.status === 204) return undefined as T;
  if (!response.ok) {
    const errorBody = body && "error" in body ? body.error : undefined;
    if (response.status === 401 && typeof window !== "undefined") {
      clearDeviceSigner();
      window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
    }
    const stepUpEndpoint = path.startsWith("/v1/auth/passkeys/step-up/");
    if (
      response.status === 428
      && !stepUpAttempted
      && !stepUpEndpoint
      && isStepUpRequiredDetails(errorBody?.details)
    ) {
      try {
        const ceremony = await apiRequest<PasskeyAuthenticationCeremony>("/v1/auth/passkeys/step-up/options", {
          method: "POST",
          body: JSON.stringify(errorBody.details),
          idempotent: true,
          stepUpAttempted: true,
          signal: init.signal,
        });
        const assertion = await authenticateWithPasskey(ceremony.options);
        const grant = await apiRequest<PasskeyStepUpResult>("/v1/auth/passkeys/step-up/verify", {
          method: "POST",
          body: JSON.stringify({ ceremonyId: ceremony.ceremonyId, response: assertion }),
          idempotent: true,
          stepUpAttempted: true,
          signal: init.signal,
        });
        const retryHeaders = deviceRequestRetryHeaders(headers);
        retryHeaders.set("x-step-up-grant", grant.grantToken);
        return apiRequest<T>(path, {
          ...requestInit,
          headers: retryHeaders,
          idempotent,
          idempotencyKey: resolvedIdempotencyKey,
          stepUpAttempted: true,
          csrf: includeCsrf,
        });
      } catch (stepUpError) {
        if (isPasskeyCancellation(stepUpError)) {
          throw new ApiError(428, "PASSKEY_CEREMONY_CANCELLED", "La confirmación con llave de acceso fue cancelada.", requestId);
        }
        throw stepUpError;
      }
    }
    throw new ApiError(
      response.status,
      errorBody?.code ?? "UNEXPECTED_ERROR",
      errorBody?.message ?? "No fue posible completar la solicitud.",
      requestId,
      errorBody?.details,
    );
  }
  if (!body || !("data" in body)) throw new ApiError(502, ["GET", "HEAD", "OPTIONS"].includes(method) ? "INVALID_RESPONSE" : "INVALID_RESPONSE_UNCERTAIN", "La respuesta del servidor no es válida.", requestId);
  return body.data;
}

async function applyDeviceRequestProof(path: string, method: string, body: BodyInit | null | undefined, headers: Headers, signal?: AbortSignal | null): Promise<void> {
  const context = currentDeviceProofContext();
  if (!deviceRequestRequiresProof(path, method)) return;
  if (!context) {
    if (process.env.NEXT_PUBLIC_GESTIONCHURCH_URL && deviceProofTenantKind !== "demo") throw new ApiError(428, "DEVICE_SESSION_ENROLLMENT_REQUIRED", "Verifica este navegador para continuar.");
    return;
  }
  const signer = currentDeviceSigner();
  if (!signer) throw new ApiError(428, "DEVICE_SESSION_LOCAL_KEY_REQUIRED", "Verifica este navegador para continuar.");
  try {
    const bodyHash = await hashDeviceRequestBody(body);
    const key = headers.get("idempotency-key") ?? "";
    const proof = await apiRequest<{ claims: DeviceRequestClaims; publicJwk: DeviceSigningPublicJwk; issuedAt: number }>("/v1/device-session/proofs", {
      method: "POST", body: JSON.stringify({ method, path, bodyHash, idempotencyKey: key }), signal,
    });
    validateDeviceRequestClaims({ ...proof, signer, context, method, path, url: `${API_URL}${path}`, bodyHash, idempotencyKey: key });
    headers.set("x-device-proof", await signDeviceClaims(signer, proof.claims));
  } catch (error) {
    if (error instanceof DeviceSessionClientError) throw new ApiError(428, error.code, "No se pudo verificar este navegador.");
    throw error;
  }
}

/** Signed streaming transport. No session/proof secret is placed in an SSE URL. */
export async function openDeviceEventStream(path: string, signal: AbortSignal): Promise<Response> {
  const headers = new Headers({ accept: "text/event-stream" });
  return boundedRequest(async (deadlineSignal) => {
    await applyDeviceRequestProof(path, "GET", undefined, headers, deadlineSignal);
    // The caller remains connected to the streaming body after header deadline
    // cleanup, while the one-use nonce and connection share the same deadline.
    const response = await fetch(`${API_URL}${path}`, { method: "GET", headers, signal: AbortSignal.any([signal, deadlineSignal]), credentials: "include", cache: "no-store" });
    if (!response.ok) {
      const value = await response.json().catch(() => undefined) as { error?: { code?: string; message?: string } } | undefined;
      if (response.status === 401 && typeof window !== "undefined") {
        clearDeviceSigner();
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
      }
      throw new ApiError(response.status, value?.error?.code ?? "UNEXPECTED_ERROR", value?.error?.message ?? "No se pudo abrir la actualización en vivo.");
    }
    return response;
  }, { signal }, "GET");
}

async function boundedRequest<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  options: { signal?: AbortSignal | null; timeoutMs?: number },
  method: string,
): Promise<T> {
  try {
    return await withRequestDeadline(operation, options);
  } catch (error) {
    if (error instanceof RequestInterruptedError || error instanceof TypeError) {
      const uncertainWrite = !["GET", "HEAD", "OPTIONS"].includes(method);
      const code = error instanceof RequestInterruptedError ? error.code : "NETWORK_ERROR";
      throw new ApiError(0, uncertainWrite ? `${code}_UNCERTAIN` : code,
        uncertainWrite
          ? "La respuesta no llegó. La operación podría haberse aplicado; verifica su estado antes de repetirla."
          : "La solicitud se interrumpió. Puedes volver a consultar.");
    }
    throw error;
  }
}

async function downloadBinary(path: string, body: Readonly<Record<string, unknown>>): Promise<{
  readonly blob: Blob;
  readonly filename: string;
}> {
  const headers = new Headers({ accept: "application/vnd.nombramientos.tenant-backup+aesgcm", "content-type": "application/json" });
  if (csrfToken) headers.set("x-csrf-token", csrfToken);
  return boundedRequest(async (signal) => {
  await applyDeviceRequestProof(path, "POST", JSON.stringify(body), headers, signal);
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST", headers, signal, credentials: "include", cache: "no-store", body: JSON.stringify(body),
  });
  if (!response.ok) {
    const value = await response.json().catch(() => undefined) as { error?: { code?: string; message?: string } } | undefined;
    throw new ApiError(
      response.status,
      value?.error?.code ?? "UNEXPECTED_ERROR",
      value?.error?.message ?? "No fue posible descargar la exportación cifrada.",
      response.headers.get("x-request-id") ?? undefined,
    );
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = /filename="([a-zA-Z0-9._-]+)"/u.exec(disposition)?.[1] ?? "tenant-export.aesgcm";
  return { blob: await response.blob(), filename };
  }, { timeoutMs: TRANSFER_TIMEOUT_MS }, "POST");
}

export const api = {
  gestionChurchSession: (code: string) =>
    apiRequest<AuthenticatedSession>("/v1/integrations/gestionchurch/session", {
      method: "POST",
      body: JSON.stringify({ code }),
      csrf: false,
    }),
  login: (email: string, password: string) =>
    apiRequest<LoginResult>("/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }), idempotent: true }),
  passkeyAuthenticationOptions: (email?: string, mediation: "conditional" | "optional" = "optional") =>
    apiRequest<PasskeyAuthenticationCeremony>("/v1/auth/passkeys/authentication/options", {
      method: "POST",
      body: JSON.stringify({ ...(email ? { email } : {}), mediation }),
      idempotent: true,
    }),
  verifyPasskeyAuthentication: (ceremonyId: string, response: PasskeyAuthenticationResponse) =>
    apiRequest<LoginResult>("/v1/auth/passkeys/authentication/verify", {
      method: "POST",
      body: JSON.stringify({ ceremonyId, response }),
      idempotent: true,
    }),
  passkeyRegistrationOptions: (replacementCredentialId?: string) =>
    apiRequest<PasskeyRegistrationCeremony>("/v1/auth/passkeys/registration/options", {
      method: "POST",
      body: JSON.stringify(replacementCredentialId ? { replacementCredentialId } : {}),
      idempotent: true,
    }),
  verifyPasskeyRegistration: (ceremonyId: string, response: PasskeyRegistrationResponse, name: string) =>
    apiRequest<PasskeyRegistrationResult>("/v1/auth/passkeys/registration/verify", {
      method: "POST",
      body: JSON.stringify({ ceremonyId, response, name }),
      idempotent: true,
    }),
  identityPolicy: () => apiRequest<IdentityPolicyState>("/v1/auth/policy"),
  updateIdentityPolicy: (expectedVersion: number, policy: IdentityPolicyValues) =>
    apiRequest<EnterpriseIdentityPolicy>("/v1/auth/policy", {
      method: "PATCH",
      body: JSON.stringify({ expectedVersion, policy }),
      idempotent: true,
    }),
  passkeys: async () => (await apiRequest<{ items: PasskeyCredentialSummary[] }>("/v1/auth/passkeys")).items,
  renamePasskey: (credentialId: string, name: string, expectedVersion: number) =>
    apiRequest<PasskeyCredentialSummary>(`/v1/auth/passkeys/${encodeURIComponent(credentialId)}`, {
      method: "PATCH",
      body: JSON.stringify({ name, expectedVersion }),
      idempotent: true,
    }),
  revokePasskey: (credentialId: string, reason: "compromised" | "replaced" | "user_revoked" = "user_revoked") =>
    apiRequest<{ revoked: true; signedOut: boolean; sessionsRevoked: number }>(`/v1/auth/passkeys/${encodeURIComponent(credentialId)}`, {
      method: "DELETE",
      body: JSON.stringify({ reason }),
      idempotent: true,
    }),
  passkeyStepUpOptions: (purpose: string, operationHash: string) =>
    apiRequest<PasskeyAuthenticationCeremony>("/v1/auth/passkeys/step-up/options", {
      method: "POST",
      body: JSON.stringify({ purpose, operationHash }),
      idempotent: true,
      stepUpAttempted: true,
    }),
  verifyPasskeyStepUp: (ceremonyId: string, response: PasskeyAuthenticationResponse) =>
    apiRequest<PasskeyStepUpResult>("/v1/auth/passkeys/step-up/verify", {
      method: "POST",
      body: JSON.stringify({ ceremonyId, response }),
      idempotent: true,
      stepUpAttempted: true,
    }),
  authSessions: async () => (await apiRequest<{ items: AuthSessionSummary[] }>("/v1/auth/sessions")).items,
  revokeAuthSession: (sessionId: string) =>
    apiRequest<{ revoked: true }>(`/v1/auth/sessions/${encodeURIComponent(sessionId)}`, {
      method: "DELETE",
      body: JSON.stringify({ reason: "user_revoked" }),
      idempotent: true,
    }),
  revokeOtherAuthSessions: () =>
    apiRequest<{ revoked: number }>("/v1/auth/sessions/revoke-others", {
      method: "POST",
      body: JSON.stringify({ reason: "user_revoked" }),
      idempotent: true,
    }),
  verifyMfa: (challengeId: string, value: string, method: "totp" | "recovery" = "totp") =>
    apiRequest<LoginResult>("/v1/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify(method === "totp" ? { challengeId, code: value } : { challengeId, recoveryCode: value }),
      idempotent: true,
    }),
  startMfaEnrollment: () => apiRequest<MfaEnrollmentStarted>("/v1/auth/mfa/enrollment/start", { method: "POST", body: "{}", idempotent: true }),
  pendingMfaEnrollment: async () => {
    try {
      return await apiRequest<MfaEnrollmentPending | null>("/v1/auth/mfa/enrollment/pending");
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  },
  cancelMfaEnrollment: (enrollmentId: string) => apiRequest<{ cancelled: true }>("/v1/auth/mfa/enrollment/cancel", { method: "POST", body: JSON.stringify({ enrollmentId }), idempotent: true }),
  confirmMfaEnrollment: (enrollmentId: string, code: string) => apiRequest<MfaEnrollmentCompleted>("/v1/auth/mfa/enrollment/confirm", { method: "POST", body: JSON.stringify({ enrollmentId, code }), idempotent: true }),
  logout: () => apiRequest<{ loggedOut: true }>("/v1/auth/logout", { method: "POST", body: "{}", idempotent: true }),
  session: async () => {
    const session = await apiRequest<AuthenticatedSession>("/v1/session");
    session.receivedAtMonotonic = performance.now();
    deviceProofTenantKind = session.tenant.kind;
    setCsrfToken(session.csrfToken);
    if (session.tenant.kind !== "real") setDeviceProofContext(undefined);
    else if (session.sessionId) setDeviceProofContext({ sessionId: session.sessionId, tenantId: session.tenant.id, identityId: session.user.id });
    else {
      const current = currentDeviceProofContext();
      if (current && (current.tenantId !== session.tenant.id || current.identityId !== session.user.id)) setDeviceProofContext(undefined);
    }
    return session;
  },
  memberships: () => apiRequest<{ items: TenantMembership[]; activeTenantId: string }>("/v1/memberships"),
  switchTenant: (tenantId: string) => apiRequest<AuthenticatedSession>("/v1/session/switch-tenant", {
    method: "POST",
    body: JSON.stringify({ tenantId }),
  }),
  accessPermissions: () => apiRequest<{ items: AccessPermission[] }>("/v1/access/permissions"),
  accessRoles: () => apiRequest<{ items: AccessRole[] }>("/v1/access/roles"),
  accessBindings: () => apiRequest<{ items: AccessBinding[]; identities: AccessIdentity[] }>("/v1/access/bindings"),
  createAccessRole: (body: {
    id: string;
    code: string;
    name: Record<Locale, string>;
    permissionCodes: string[];
    delegablePermissionCodes: string[];
  }) => apiRequest<{ roleId: string; version: number; affectedIdentityIds: string[] }>("/v1/access/roles", {
    method: "POST", body: JSON.stringify(body), idempotent: true,
  }),
  updateAccessRole: (roleId: string, body: {
    expectedVersion: number;
    name: Record<Locale, string>;
    permissionCodes: string[];
    delegablePermissionCodes: string[];
  }) => apiRequest<{ roleId: string; version: number; affectedIdentityIds: string[]; revokedSessions: number }>(
    `/v1/access/roles/${encodeURIComponent(roleId)}`,
    { method: "PATCH", body: JSON.stringify(body), idempotent: true },
  ),
  grantAccessBinding: (targetIdentityId: string, roleId: string) => apiRequest<{
    roleId: string; identityId: string; version: number; active: true; revokedSessions: number;
  }>("/v1/access/bindings", {
    method: "POST", body: JSON.stringify({ targetIdentityId, roleId }), idempotent: true,
  }),
  revokeAccessBinding: (targetIdentityId: string, roleId: string, expectedVersion: number) => apiRequest<{
    roleId: string; identityId: string; version: number; active: false; revokedSessions: number;
  }>("/v1/access/bindings/revoke", {
    method: "POST", body: JSON.stringify({ targetIdentityId, roleId, expectedVersion }), idempotent: true,
  }),
  platformTenants: () => apiRequest<{
    items: PlatformTenant[];
    worker: ProvisioningWorkerStatus;
    contentAccess: false;
    keyAccess: false;
  }>("/v1/platform/tenants"),
  initialAdminRecoveryCandidates: (filters: { tenantId?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (filters.tenantId) query.set("tenantId", filters.tenantId);
    if (filters.limit) query.set("limit", String(filters.limit));
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return apiRequest<{ items: InitialAdminRecoveryCandidate[] }>(`/v1/platform/initial-admin-recoveries/candidates${suffix}`);
  },
  initialAdminRecoveries: (filters: {
    tenantId?: string;
    status?: InitialAdminRecoveryStatus;
    cursor?: InitialAdminRecoveryCursor;
    limit?: number;
  } = {}) => {
    const query = new URLSearchParams();
    if (filters.tenantId) query.set("tenantId", filters.tenantId);
    if (filters.status) query.set("status", filters.status);
    if (filters.cursor) {
      query.set("beforeRequestedAt", filters.cursor.beforeRequestedAt);
      query.set("beforeRecoveryId", filters.cursor.beforeRecoveryId);
    }
    if (filters.limit) query.set("limit", String(filters.limit));
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    return apiRequest<{ items: InitialAdminRecoveryQueueItem[]; nextCursor: InitialAdminRecoveryCursor | null }>(
      `/v1/platform/initial-admin-recoveries${suffix}`,
    );
  },
  requestInitialAdminRecovery: (body: InitialAdminRecoveryRequest, logicalIdempotencyKey?: string) =>
    apiRequest<{ recoveryId: string; version: number; status: "pending"; created: boolean }>(
      "/v1/platform/initial-admin-recoveries",
      { method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey },
    ),
  approveInitialAdminRecovery: (body: InitialAdminRecoveryApproval, logicalIdempotencyKey?: string) =>
    apiRequest<{
      recoveryId: string;
      version: number;
      status: "finalization_pending" | "enrollment_pending" | "revoked";
      reused: boolean;
      delivery: {
        channel: "local_console";
        state: "delivered";
        tokenExpiresAt: string;
      };
      developmentToken?: string;
    }>(`/v1/platform/initial-admin-recoveries/${encodeURIComponent(body.recoveryId)}/approve`, {
      method: "POST",
      body: JSON.stringify(body),
      idempotent: true,
      idempotencyKey: logicalIdempotencyKey,
    }),
  revokeInitialAdminRecovery: (
    recoveryId: string,
    expectedVersion: number,
    source: InitialAdminRecoverySource,
    reasonCode: InitialAdminRecoveryRevocationReason,
    logicalIdempotencyKey?: string,
  ) => apiRequest<{ recoveryId: string; version: number; status: "revoked"; sessionsRevoked: number }>(
    `/v1/platform/initial-admin-recoveries/${encodeURIComponent(recoveryId)}/revoke`,
    {
      method: "POST",
      body: JSON.stringify({ recoveryId, expectedVersion, source, reasonCode }),
      idempotent: true,
      idempotencyKey: logicalIdempotencyKey,
    },
  ),
  prepareInitialAdminRecoveryContext: () => apiRequest<void>(
    "/v1/auth/initial-admin-recovery/prepare-context",
    { method: "POST", body: "{}", csrf: false },
  ),
  redeemInitialAdminRecovery: (recoveryId: string, token?: string) => apiRequest<InitialAdminRecoveryRedemption>(
    "/v1/auth/initial-admin-recovery/redeem",
    { method: "POST", body: JSON.stringify({ recoveryId, ...(token ? { token } : {}) }), csrf: false },
  ),
  queueTenantProvisioning: (body: {
    tenantId: string;
    slug: string;
    displayName: string;
    kind: "demo" | "real";
    timezone: string;
    locale: Locale;
    initialAdmin: { mode: "pending" } | { mode: "invitation"; email: string; expiresInHours: number };
  }) => apiRequest<{
    jobId: string;
    state: string;
    reused: boolean;
    initialAdmin:
      | { mode: "pending"; activationState: "pending_activation" }
      | { mode: "invitation"; activationState: "invitation_queued"; delivery: string; acceptanceToken?: string; expiresAt?: string };
  }>("/v1/platform/tenants/provisioning", {
    method: "POST", body: JSON.stringify(body), idempotent: true,
  }),
  activatePlatformTenantAdmin: (tenantId: string, body: {
    expectedVersion: number;
    email: string;
    expiresInHours: number;
  }) => apiRequest<{
    tenantId: string;
    invitationId: string;
    version: number;
    activationState: "invitation_pending";
    reused: boolean;
    delivery: string;
    acceptanceToken?: string;
    expiresAt?: string;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/initial-admin-invitation`, {
    method: "POST", body: JSON.stringify(body), idempotent: true,
  }),
  suspendPlatformTenant: (tenantId: string, expectedVersion: number, reasonCode: "security_review" | "operational_hold" | "institution_request" | "compliance_review") => apiRequest<{
    tenantId: string; status: "suspended"; version: number; sessionsRevoked: true;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/suspend`, {
    method: "POST", body: JSON.stringify({ expectedVersion, reasonCode }), idempotent: true,
  }),
  reactivatePlatformTenant: (tenantId: string, expectedVersion: number, reasonCode:
    "security_review_completed" | "operational_hold_resolved" | "institution_request_resumed" | "compliance_review_completed",
  logicalIdempotencyKey?: string) => apiRequest<{
    tenantId: string; status: "active"; version: number; sessionsRevoked: number; sessionsCreated: 0; reused: boolean;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/reactivate`, {
    method: "POST", body: JSON.stringify({ expectedVersion, reasonCode }), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  requestTenantExport: (tenantId: string, expectedVersion: number, logicalIdempotencyKey?: string) => apiRequest<{
    tenantId: string; jobId: string; state: "queued" | "running" | "ready" | "failed"; revision: number; reused: boolean;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/exports`, {
    method: "POST", body: JSON.stringify({ expectedVersion }), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  authorizeTenantExportDownload: (tenantId: string, exportJobId: string, logicalIdempotencyKey?: string) => apiRequest<{
    authorizationId: string;
    status: "active" | "consumed" | "revoked" | "expired";
    revision: number;
    expiresAt: string;
    reused: boolean;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/exports/${encodeURIComponent(exportJobId)}/download-authorizations`, {
    method: "POST", body: "{}", idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  downloadTenantExport: (tenantId: string, exportJobId: string, authorizationId: string) => downloadBinary(
    `/v1/platform/tenants/${encodeURIComponent(tenantId)}/exports/${encodeURIComponent(exportJobId)}/download`,
    { authorizationId },
  ),
  revokeTenantExportDownload: (authorizationId: string, expectedRevision: number) => apiRequest<{
    status: "revoked"; revision: number;
  }>(`/v1/platform/export-download-authorizations/${encodeURIComponent(authorizationId)}/revoke`, {
    method: "POST", body: JSON.stringify({ expectedRevision }),
  }),
  scheduleTenantDecommission: (tenantId: string, body: {
    expectedVersion: number;
    exportJobId: string;
    retentionDays: number;
    reasonCode: PlatformTenantDecommission["reasonCode"];
  }, logicalIdempotencyKey?: string) => apiRequest<{
    decommissionId: string;
    state: "scheduled";
    tenantStatus: "decommission_pending";
    version: number;
    retentionUntil: string;
    sessionsRevoked: number;
    reused: boolean;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/decommission`, {
    method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  cancelTenantDecommission: (tenantId: string, decommissionId: string, expectedVersion: number, logicalIdempotencyKey?: string) => apiRequest<{
    decommissionId: string;
    state: "cancelled";
    tenantStatus: "active" | "suspended";
    version: number;
    retentionUntil: null;
    sessionsRevoked: 0;
    reused: boolean;
  }>(`/v1/platform/tenants/${encodeURIComponent(tenantId)}/decommission/${encodeURIComponent(decommissionId)}/cancel`, {
    method: "POST", body: JSON.stringify({ expectedVersion }), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  dashboard: () => apiRequest<DashboardData>("/v1/dashboard"),
  activeRound: () => apiRequest<ActiveRoundData | null>("/v1/rounds/active"),
  ballotRecipients: (roundId: string) => apiRequest<BallotRecipients>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/recipients`),
  submit: (roundId: string, body: object, logicalIdempotencyKey: string) =>
    apiRequest<{ receiptId: string; receivedAt: string; roundId: string; roundVersion: number; contentHash: string; status: "received" }>(
      `/v1/rounds/${encodeURIComponent(roundId)}/submissions`,
      { method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey },
    ),
  mySubmission: async (roundId: string) => {
    try {
      return await apiRequest<{ receiptId: string; receivedAt: string; roundId: string; roundVersion: number; contentHash: string; status: "received" }>(
        `/v1/rounds/${encodeURIComponent(roundId)}/submissions/me`,
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  },
  closeRound: (roundId: string, expectedVersion: number, logicalIdempotencyKey: string) =>
    apiRequest<{ roundId: string; previousPhase: string; newPhase: string; version: number; closedAt: string }>(
      `/v1/rounds/${encodeURIComponent(roundId)}/close`,
      { method: "POST", body: JSON.stringify({ expectedVersion, reasonCode: "ALL_FROZEN_ELECTORS_RESPONDED" }), idempotent: true, idempotencyKey: logicalIdempotencyKey },
    ),
  members: (cursor?: string) => apiRequest<{ items: MemberRecord[]; total: number; nextCursor?: string }>(`/v1/members?limit=250${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
  memberQualifications: (memberId: string) => apiRequest<MemberQualificationList>(
    `/v1/members/${encodeURIComponent(memberId)}/qualifications`,
  ),
  createMemberQualification: (
    memberId: string,
    qualificationId: string,
    body: MemberQualificationWrite,
    logicalIdempotencyKey?: string,
  ) => apiRequest<MemberQualificationMetadata>(
    `/v1/members/${encodeURIComponent(memberId)}/qualifications`,
    {
      method: "POST",
      body: JSON.stringify({ qualificationId, ...body }),
      idempotent: true,
      idempotencyKey: logicalIdempotencyKey,
    },
  ),
  reviseMemberQualification: (
    memberId: string,
    qualificationId: string,
    expectedVersion: number,
    body: MemberQualificationWrite,
    logicalIdempotencyKey?: string,
  ) => apiRequest<MemberQualificationMetadata>(
    `/v1/members/${encodeURIComponent(memberId)}/qualifications/${encodeURIComponent(qualificationId)}/revisions`,
    {
      method: "POST",
      body: JSON.stringify({ expectedVersion, ...body }),
      idempotent: true,
      idempotencyKey: logicalIdempotencyKey,
    },
  ),
  authorizeMemberExport: (body: {
    format: "csv" | "xlsx";
    rowCount: number;
    includeContact: boolean;
    filters: { status: "all" | "active" | "archived"; queryApplied: boolean };
    selectionSha256: `sha256:${string}`;
  }, logicalIdempotencyKey?: string) => apiRequest<MemberExportAuthorization>("/v1/members/export-authorizations", {
    method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  createMember: (body: object, logicalIdempotencyKey?: string) => apiRequest<MemberRecord>("/v1/members", { method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey }),
  previewMemberImport: (body: object, logicalIdempotencyKey?: string) => apiRequest<MemberImportPreviewResponse>("/v1/members/import/preview", { method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey }),
  commitMemberImport: (importId: string, expectedRevision: number, logicalIdempotencyKey?: string) => apiRequest<MemberImportSummary>("/v1/members/import/commit", { method: "POST", body: JSON.stringify({ importId, expectedRevision }), idempotent: true, idempotencyKey: logicalIdempotencyKey }),
  memberImportHistory: (limit = 30) => apiRequest<{ items: MemberImportHistory[] }>(`/v1/members/imports?limit=${encodeURIComponent(limit)}`),
  catalog: () => apiRequest<{ departments: unknown[]; offices: unknown[]; normativeVersion: string }>("/v1/catalog"),
  committee: () => apiRequest<{ items: CommitteeRecord[] }>("/v1/committee"),
  organization: () => apiRequest<{ items: OrganizationRecord[]; cycleName?: string }>("/v1/organization"),
  reports: () => apiRequest<{ items: StoredReport[] }>("/v1/reports"),
  generateReport: (
    reportType: ReportType,
    format: ReportFormat,
    locale: Locale,
    audience: ReportAudience,
    filters: ReportFilters,
    logicalIdempotencyKey?: string,
  ) =>
    apiRequest<PendingReport>("/v1/reports/generate", {
      method: "POST",
      body: JSON.stringify({ reportType, format, locale, audience, filters }),
      idempotent: true,
      idempotencyKey: logicalIdempotencyKey,
    }),
  correctReport: (
    previousReportId: string,
    expectedPreviousVersion: number,
    filters: ReportFilters,
    reasonCode: ReportCorrectionReasonCode,
    logicalIdempotencyKey?: string,
  ) => apiRequest<PendingReport>(`/v1/reports/${encodeURIComponent(previousReportId)}/corrections`, {
    method: "POST",
    body: JSON.stringify({ expectedPreviousVersion, filters, reasonCode }),
    idempotent: true,
    idempotencyKey: logicalIdempotencyKey,
  }),
  completeReport: (reportId: string, body: {
    expectedVersion: number;
    envelope: Envelope;
    artifactSha256: `sha256:${string}`;
    ciphertextSha256: `sha256:${string}`;
    plaintextBytes: number;
    rowCount: number;
    generatedAt: string;
  }, logicalIdempotencyKey?: string) => apiRequest<GeneratedReport>(`/v1/reports/${encodeURIComponent(reportId)}/complete`, {
    method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  failReport: (reportId: string, expectedVersion: number, errorCode: string, logicalIdempotencyKey?: string) => apiRequest<{
    id: string; state: "failed"; version: number; errorCode: string; failedAt: string;
  }>(`/v1/reports/${encodeURIComponent(reportId)}/fail`, {
    method: "POST", body: JSON.stringify({ expectedVersion, errorCode }), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  reportArtifact: (reportId: string) => apiRequest<StoredReportArtifact>(`/v1/reports/${encodeURIComponent(reportId)}/artifact`),
  recordReportPrint: (reportId: string, artifactSha256: `sha256:${string}`, logicalIdempotencyKey?: string) => apiRequest<{
    id: string; artifactSha256: `sha256:${string}`; printedAt: string;
  }>(`/v1/reports/${encodeURIComponent(reportId)}/print`, {
    method: "POST", body: JSON.stringify({ artifactSha256 }), idempotent: true, idempotencyKey: logicalIdempotencyKey,
  }),
  audit: () => apiRequest<{ items: AuditRecord[]; verified: boolean }>("/v1/audit"),
  custodyKeys: () => apiRequest<CustodyPublicKey[]>("/v1/custody/keys"),
  registerCustodyKey: (body: object, logicalIdempotencyKey?: string) => apiRequest<CustodyPublicKey>("/v1/custody/keys", { method: "POST", body: JSON.stringify(body), idempotent: true, idempotencyKey: logicalIdempotencyKey }),
  revokeCustodyKey: (keyId: string, expectedVersion: number, reasonCode: string) => apiRequest<{ keyId: string; version: number; status: "revoked"; revokedAt: string; affectedFrozenRounds: number }>(`/v1/custody/keys/${encodeURIComponent(keyId)}/revoke`, { method: "POST", body: JSON.stringify({ expectedVersion, reasonCode }), idempotent: true }),
  roundCustody: (roundId: string) => apiRequest<RoundCustody>(`/v1/rounds/${encodeURIComponent(roundId)}/custody`),
  freezeRoundCustody: (roundId: string, expectedRoundVersion: number, keyIds: string[]) => apiRequest<RoundCustody>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/freeze`, { method: "POST", body: JSON.stringify({ expectedRoundVersion, keyIds }), idempotent: true }),
  createTallyManifest: (roundId: string, expectedRoundVersion: number, expectedCustodyVersion: number) => apiRequest<{ manifestId: string; roundId: string; roundVersion: number; custodyVersion: number; manifestHash: `sha256:${string}`; entryCount: number; version: number; state: "awaiting_attestations"; createdAt: string }>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/manifest`, { method: "POST", body: JSON.stringify({ expectedRoundVersion, expectedCustodyVersion }), idempotent: true }),
  tallyManifest: (roundId: string) => apiRequest<TallyManifest>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/manifest`),
  attestTallyManifest: (roundId: string, expectedManifestVersion: number, aggregate: TallyAggregate, signature: string) => apiRequest<{ manifestId: string; manifestHash: `sha256:${string}`; aggregateHash: `sha256:${string}`; state: "awaiting_attestations" | "publishable" | "disputed"; version: number }>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/attestations`, { method: "POST", body: JSON.stringify({ expectedManifestVersion, aggregate, signature }), idempotent: true }),
  publishTallyAggregate: (roundId: string, expectedRoundVersion: number, expectedManifestVersion: number) => apiRequest<PublishedAggregate>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/publication`, { method: "POST", body: JSON.stringify({ expectedRoundVersion, expectedManifestVersion }), idempotent: true }),
  publishedAggregate: (roundId: string) => apiRequest<PublishedAggregate>(`/v1/rounds/${encodeURIComponent(roundId)}/custody/aggregate`),
};
