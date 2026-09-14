"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Archive, CheckCircle2, Download, FileSpreadsheet, Image as ImageIcon, LoaderCircle,
  LockKeyhole, Pencil, Plus, RefreshCw, Search, ShieldCheck, Upload, Users,
} from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  api,
  apiRequest,
  idempotencyKey,
  type AuthenticatedSession,
  type Locale,
  type MemberImportPreviewResponse,
  type MemberImportSummary,
  type MemberRecord,
} from "@/lib/api";
import { encryptJson } from "@/lib/crypto-client";
import { keyForEnvelope, openJsonEnvelope } from "@/lib/historical-envelope";
import { loadExcelJsBrowser } from "@/lib/exceljs-browser";
import {
  IMPORT_FIELDS,
  createImportErrorCsv,
  mappingHasName,
  normalizeSearchText,
  suggestColumnMapping,
  type ImportAction,
  type ImportColumnMapping,
  type ImportPreviewRow,
} from "@/lib/member-import";
import {
  createMemberImportWorkerClient,
  type MemberImportWorkerClient,
} from "@/lib/member-import-worker-client";
import type { ImportSheetDescriptor } from "@/lib/member-import-worker-protocol";
import { DataError, EmptyState, LoadingBlock, PageTitle } from "./workspace-view";
import { MemberPhotoEditor } from "./member-photo-editor";
import { MemberQualifications } from "./member-qualifications";
import { message, localizedApiError, localizedName } from "@/lib/product-i18n";
import { revealMemberEligibilityReview, type MemberEligibilityReview } from "@/lib/member-private-note";
import { neutralizeSpreadsheetCell } from "@/lib/spreadsheet-cell";

type MemberDisplay = {
  displayName?: string;
  firstName?: string;
  lastName?: string;
  membershipStatus?: string;
  visibleReason?: string;
  photoReference?: string;
};

type MemberContact = { email?: string };

type EligibilityCatalogDepartment = {
  id: string;
  canonicalCode: string;
  names: Partial<Record<Locale, string>>;
  active: boolean;
};

type DecryptedMember = Omit<MemberRecord, "eligibilityEnvelope" | "contactEnvelope"> & Omit<MemberDisplay, "displayName"> & MemberContact & {
  displayName: string;
  eligibilityReview?: MemberEligibilityReview;
};

type MemberStatusFilter = "all" | "active" | "archived";
type MemberLifecycle = { member: DecryptedMember; action: "archive" | "reactivate" };
type MemberMutationResult = { id: string; version: number; pausedWorkflows?: unknown[] };

const memberLifecycleReasonCodes = {
  archive: ["RECORD_LIFECYCLE_CHANGE", "DUPLICATE_RECORD", "ADMINISTRATIVE_CORRECTION", "RETENTION_POLICY"],
  reactivate: ["RECORD_LIFECYCLE_CHANGE", "ARCHIVE_REVERSED", "ADMINISTRATIVE_CORRECTION"],
} as const;

function memberLifecycleReasonLabel(locale: Locale, reasonCode: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    RECORD_LIFECYCLE_CHANGE: "screen.membersView.c80b263e456f",
    DUPLICATE_RECORD: "screen.membersView.1101847aca44",
    ADMINISTRATIVE_CORRECTION: "screen.membersView.1b47817e6088",
    RETENTION_POLICY: "screen.membersView.e461ba7e4bf0",
    ARCHIVE_REVERSED: "screen.membersView.3585ccb19a04",
  };
  const label = labels[reasonCode];
  return label ? message(locale, label) : reasonCode;
}

const importFieldLabels: Readonly<Record<Locale, Record<(typeof IMPORT_FIELDS)[number], string>>> = {
  es: { sourceId: message("es", "screen.membersView.b789ffad375b"), displayName: message("es", "screen.membersView.d89d816c1d2e"), firstName: message("es", "screen.membersView.8a7a86603063"), lastName: message("es", "screen.membersView.7834b83a8302"), email: message("es", "screen.membersView.27338d87720a"), membershipStatus: message("es", "screen.membersView.56472daaadc6"), eligible: message("es", "screen.membersView.da87ac3fac2d"), visibleReason: message("es", "screen.membersView.43b01a68260f"), photoReference: message("es", "screen.membersView.d79f4ab0c725") },
  en: { sourceId: message("en", "screen.membersView.b789ffad375b"), displayName: message("en", "screen.membersView.d89d816c1d2e"), firstName: message("en", "screen.membersView.8a7a86603063"), lastName: message("en", "screen.membersView.7834b83a8302"), email: message("en", "screen.membersView.27338d87720a"), membershipStatus: message("en", "screen.membersView.56472daaadc6"), eligible: message("en", "screen.membersView.da87ac3fac2d"), visibleReason: message("en", "screen.membersView.43b01a68260f"), photoReference: message("en", "screen.membersView.d79f4ab0c725") },
  fr: { sourceId: message("fr", "screen.membersView.b789ffad375b"), displayName: message("fr", "screen.membersView.d89d816c1d2e"), firstName: message("fr", "screen.membersView.8a7a86603063"), lastName: message("fr", "screen.membersView.7834b83a8302"), email: message("fr", "screen.membersView.27338d87720a"), membershipStatus: message("fr", "screen.membersView.56472daaadc6"), eligible: message("fr", "screen.membersView.da87ac3fac2d"), visibleReason: message("fr", "screen.membersView.43b01a68260f"), photoReference: message("fr", "screen.membersView.d79f4ab0c725") },
};

const issueLabels: Readonly<Record<Locale, Record<string, string>>> = {
  es: { MISSING_NAME: message("es", "screen.membersView.2cf0da46d22e"), INVALID_EMAIL: message("es", "screen.membersView.a494999dd636"), INVALID_ELIGIBILITY: message("es", "screen.membersView.c3ecad749dfa"), INVALID_MEMBERSHIP_STATUS: message("es", "screen.membersView.9d7707806d3b"), UNSAFE_FORMULA_PREFIX: message("es", "screen.membersView.4552c08a7480"), UNSAFE_PHOTO_REFERENCE: message("es", "screen.membersView.09491316f38c"), DUPLICATE_SOURCE_ID: message("es", "screen.membersView.6188e00ae76b"), POSSIBLE_EMAIL_DUPLICATE: message("es", "screen.membersView.b3229fdcd26f"), POSSIBLE_NAME_DUPLICATE: message("es", "screen.membersView.c441108b4aa2"), STABLE_ID_MATCH: message("es", "screen.membersView.99e6ba92dfa4"), HOMONYM_RETAINED: message("es", "screen.membersView.0e2a083a04e9"), DUPLICATE_SOURCE_ROW: message("es", "screen.membersView.98f162228b49"), DUPLICATE_TARGET: message("es", "screen.membersView.6d034ee1380f"), DUPLICATE_STABLE_ID: message("es", "screen.membersView.81ab5c74170d"), TARGET_EXISTS: message("es", "screen.membersView.eeec69caf5de"), TARGET_NOT_FOUND: message("es", "screen.membersView.3426dcbd53e3"), STABLE_ID_EXISTS: message("es", "screen.membersView.c7a7596e8039"), STABLE_ID_MISMATCH: message("es", "screen.membersView.d981573d4388"), VERSION_CONFLICT: message("es", "screen.membersView.76124a18448a") },
  en: { MISSING_NAME: message("en", "screen.membersView.2cf0da46d22e"), INVALID_EMAIL: message("en", "screen.membersView.a494999dd636"), INVALID_ELIGIBILITY: message("en", "screen.membersView.c3ecad749dfa"), INVALID_MEMBERSHIP_STATUS: message("en", "screen.membersView.9d7707806d3b"), UNSAFE_FORMULA_PREFIX: message("en", "screen.membersView.4552c08a7480"), UNSAFE_PHOTO_REFERENCE: message("en", "screen.membersView.09491316f38c"), DUPLICATE_SOURCE_ID: message("en", "screen.membersView.6188e00ae76b"), POSSIBLE_EMAIL_DUPLICATE: message("en", "screen.membersView.b3229fdcd26f"), POSSIBLE_NAME_DUPLICATE: message("en", "screen.membersView.c441108b4aa2"), STABLE_ID_MATCH: message("en", "screen.membersView.99e6ba92dfa4"), HOMONYM_RETAINED: message("en", "screen.membersView.0e2a083a04e9"), DUPLICATE_SOURCE_ROW: message("en", "screen.membersView.98f162228b49"), DUPLICATE_TARGET: message("en", "screen.membersView.6d034ee1380f"), DUPLICATE_STABLE_ID: message("en", "screen.membersView.81ab5c74170d"), TARGET_EXISTS: message("en", "screen.membersView.eeec69caf5de"), TARGET_NOT_FOUND: message("en", "screen.membersView.3426dcbd53e3"), STABLE_ID_EXISTS: message("en", "screen.membersView.c7a7596e8039"), STABLE_ID_MISMATCH: message("en", "screen.membersView.d981573d4388"), VERSION_CONFLICT: message("en", "screen.membersView.76124a18448a") },
  fr: { MISSING_NAME: message("fr", "screen.membersView.2cf0da46d22e"), INVALID_EMAIL: message("fr", "screen.membersView.a494999dd636"), INVALID_ELIGIBILITY: message("fr", "screen.membersView.c3ecad749dfa"), INVALID_MEMBERSHIP_STATUS: message("fr", "screen.membersView.9d7707806d3b"), UNSAFE_FORMULA_PREFIX: message("fr", "screen.membersView.4552c08a7480"), UNSAFE_PHOTO_REFERENCE: message("fr", "screen.membersView.09491316f38c"), DUPLICATE_SOURCE_ID: message("fr", "screen.membersView.6188e00ae76b"), POSSIBLE_EMAIL_DUPLICATE: message("fr", "screen.membersView.b3229fdcd26f"), POSSIBLE_NAME_DUPLICATE: message("fr", "screen.membersView.c441108b4aa2"), STABLE_ID_MATCH: message("fr", "screen.membersView.99e6ba92dfa4"), HOMONYM_RETAINED: message("fr", "screen.membersView.0e2a083a04e9"), DUPLICATE_SOURCE_ROW: message("fr", "screen.membersView.98f162228b49"), DUPLICATE_TARGET: message("fr", "screen.membersView.6d034ee1380f"), DUPLICATE_STABLE_ID: message("fr", "screen.membersView.81ab5c74170d"), TARGET_EXISTS: message("fr", "screen.membersView.eeec69caf5de"), TARGET_NOT_FOUND: message("fr", "screen.membersView.3426dcbd53e3"), STABLE_ID_EXISTS: message("fr", "screen.membersView.c7a7596e8039"), STABLE_ID_MISMATCH: message("fr", "screen.membersView.d981573d4388"), VERSION_CONFLICT: message("fr", "screen.membersView.76124a18448a") },
};

const memberCopy = {
  es: {
    loadingRoster: message("es", "screen.membersView.b2a8d4b20744"), loadFailure: message("es", "screen.membersView.544c70c2ee57"), eyebrow: message("es", "screen.membersView.71f576f8300c"), title: message("es", "screen.membersView.500cd8288ddc"), description: message("es", "screen.membersView.02867baee844"),
    newPerson: message("es", "screen.membersView.d1a3ec510d69"), createPerson: message("es", "screen.membersView.f89e36ab7ca8"), createDescription: message("es", "screen.membersView.78d726d8a6a5"), fullName: message("es", "screen.membersView.d89d816c1d2e"), optionalEmail: message("es", "screen.membersView.225a13674c55"), eligibleRoster: message("es", "screen.membersView.1966c06ba85c"), eligibilityFrozen: message("es", "screen.membersView.23d4b64c3e5d"), saveFailure: message("es", "screen.membersView.3c5eb2b277a7"), cancel: message("es", "screen.membersView.18e29ea869c8"), encryptAndSave: message("es", "screen.membersView.f456a4aa4c43"),
    searchRoster: message("es", "screen.membersView.99dfea08be90"), searchPlaceholder: message("es", "screen.membersView.b80a551965e4"), privateIndex: message("es", "screen.membersView.20b224026d55"), privateIndexBody: message("es", "screen.membersView.5673fb953c9b"), incompleteIndex: message("es", "screen.membersView.78b670cb6095"), authorizedDirectory: message("es", "screen.membersView.fbb9e7b522b0"), indexing: message("es", "screen.membersView.ea5b0ee62e7e"), people: message("es", "screen.membersView.e61e02200658"), responsibilities: message("es", "screen.membersView.3a0335565169"), archived: message("es", "screen.membersView.9cf8b062b4b5"), eligible: message("es", "screen.membersView.92bae68302f7"), ineligible: message("es", "screen.membersView.169ff2291161"), photo: message("es", "screen.membersView.739b63052ea0"), photoOf: message("es", "screen.membersView.5580644333ad"), noMatches: message("es", "screen.membersView.7eb822f89298"), emptyRoster: message("es", "screen.membersView.5ebfc65c3f74"), photograph: message("es", "screen.membersView.8334ebf72909"), photographOf: message("es", "screen.membersView.c99ddce8deb8"), photographDescription: message("es", "screen.membersView.580c692f9625"),
    controlledImport: message("es", "screen.membersView.56bceaa29f4a"), importIntro: message("es", "screen.membersView.47b1184cd5ea"), prepareImport: message("es", "screen.membersView.552e7c1d4cc5"), importTitle: message("es", "screen.membersView.bc92094ef4d9"), importLimits: message("es", "screen.membersView.f40c3099e400"), fileStep: message("es", "screen.membersView.196c62f955c1"), changeFile: message("es", "screen.membersView.d93fb925cf23"), selectFile: message("es", "screen.membersView.586ae2e70264"), mappingStep: message("es", "screen.membersView.736327bc5da3"), explicitMapping: message("es", "screen.membersView.17a1d9350ae4"), sheet: message("es", "screen.membersView.71ab118c2661"), rows: message("es", "screen.membersView.7a4c2c0357fd"), doNotImport: message("es", "screen.membersView.ae142d9ec555"), noHeader: message("es", "screen.membersView.a8ddebb0a316"), validatePreview: message("es", "screen.membersView.e9ea7f4cb796"), cannotContinue: message("es", "screen.membersView.81f3e2b4c5ef"),
    reviewStep: message("es", "screen.membersView.d825a0d89cac"), withError: message("es", "screen.membersView.061234b7e2b1"), undecided: message("es", "screen.membersView.307d7b5a0e43"), applySuggestions: message("es", "screen.membersView.c598dcb9d432"), privacyNote: message("es", "screen.membersView.124440809292"), previewLabel: message("es", "screen.membersView.2825c535e9c0"), row: message("es", "screen.membersView.62cc5db7178e"), person: message("es", "screen.membersView.b792923baa6a"), validation: message("es", "screen.membersView.6d33674f49ac"), decision: message("es", "screen.membersView.57c457729918"), target: message("es", "screen.membersView.69c5eb786923"), unnamed: message("es", "screen.membersView.f00a565cde07"), noId: message("es", "screen.membersView.87aa9c220775"), ready: message("es", "screen.membersView.122ecc645b05"), decisionRow: message("es", "screen.membersView.eba3a2d7de18"), decide: message("es", "screen.membersView.2758c050aea6"), createSeparate: message("es", "screen.membersView.3f2efd6b26f4"), update: message("es", "screen.membersView.c85458aeb753"), skip: message("es", "screen.membersView.4bf53261cc26"), targetRow: message("es", "screen.membersView.629fc466e97b"), select: message("es", "screen.membersView.30360a3bdaf2"), newTarget: message("es", "screen.membersView.d1a3ec510d69"), noContent: message("es", "screen.membersView.d8817f99c380"), previous: message("es", "screen.membersView.737c89700c42"), page: message("es", "screen.membersView.be29af45774e"), of: message("es", "screen.membersView.2fd307b171ad"), next: message("es", "screen.membersView.3751157c79a9"),
    serverConflicts: message("es", "screen.membersView.8c809a54b37f"), persistedPreview: message("es", "screen.membersView.1f2b415429a0"), createVerb: message("es", "screen.membersView.ba345de57a18"), updateVerb: message("es", "screen.membersView.b0d92f798b57"), skipVerb: message("es", "screen.membersView.c4d74355a46f"), replayedPreview: message("es", "screen.membersView.43ea3212dc07"), stageFailure: message("es", "screen.membersView.dc3290d0b462"), commitFailure: message("es", "screen.membersView.598b422e0cfe"), downloadIssues: message("es", "screen.membersView.d12d681321c5"), close: message("es", "screen.membersView.c0b0def8d78c"), encryptValidate: message("es", "screen.membersView.52530ced5213"), confirmImport: message("es", "screen.membersView.fc29d02ef76d"), importConfirmed: message("es", "screen.membersView.30f3a48d2a63"), created: message("es", "screen.membersView.1311b1b3ba58"), updated: message("es", "screen.membersView.35a5ee8d64f1"), skipped: message("es", "screen.membersView.8fcde0cf9232"), retryRecognized: message("es", "screen.membersView.85eff5d47bde"), downloadTemplate: message("es", "screen.membersView.4ea73e9c7a6a"),
    filter: message("es", "screen.membersView.616cb30b61c7"), allStatus: message("es", "screen.membersView.e49424718bbf"), activeOnly: message("es", "screen.membersView.109025b1fb86"), archivedOnly: message("es", "screen.membersView.c107d41c9bd9"), editPerson: message("es", "screen.membersView.10f4da33b515"), editDescription: message("es", "screen.membersView.962eb038dd68"), membershipStatus: message("es", "screen.membersView.cc022e3b7be9"), memberActive: message("es", "screen.membersView.3f9a8d3cda2d"), memberInactive: message("es", "screen.membersView.088c4f6880db"), eligibilityStatus: message("es", "screen.membersView.f029c8c01cae"), underReview: message("es", "screen.membersView.9d52300e262a"), availableForOffice: message("es", "screen.membersView.08a033ae4509"), visibleReason: message("es", "screen.membersView.2ca8eb56a52a"), visibleReasonHelp: message("es", "screen.membersView.32bb45fbbc53"), privateReview: message("es", "screen.membersView.21b472328f1d"), privateReviewHelp: message("es", "screen.membersView.8249432dd21c"), privateNote: message("es", "screen.membersView.0a0823859610"), departmentRestriction: message("es", "screen.membersView.4473bb80574c"), restrictionUntil: message("es", "screen.membersView.dc34b269cd97"), clearPrivateReview: message("es", "screen.membersView.5a934fdea4fa"), saveChanges: message("es", "screen.membersView.b6e865c65192"), archivePerson: message("es", "screen.membersView.d91f72daaade"), reactivatePerson: message("es", "screen.membersView.ebee8ece661d"), archiveHelp: message("es", "screen.membersView.db6fd2dae07c"), reactivateHelp: message("es", "screen.membersView.42e2ed05166e"), reason: message("es", "screen.membersView.3954c2a2dcdb"), reasonPlaceholder: message("es", "screen.membersView.172254b36914"), confirmArchive: message("es", "screen.membersView.e589f11efa82"), confirmReactivate: message("es", "screen.membersView.26e17a71ca03"), lifecycleFailure: message("es", "screen.membersView.e13e249e1d0a"), editFailure: message("es", "screen.membersView.72b99e5588c2"), assignmentBlock: message("es", "screen.membersView.4b88eb4a3de7"), managementActions: message("es", "screen.membersView.d9cc0f8d4f55"),
  },
  en: {
    loadingRoster: message("en", "screen.membersView.b2a8d4b20744"), loadFailure: message("en", "screen.membersView.544c70c2ee57"), eyebrow: message("en", "screen.membersView.71f576f8300c"), title: message("en", "screen.membersView.500cd8288ddc"), description: message("en", "screen.membersView.02867baee844"),
    newPerson: message("en", "screen.membersView.d1a3ec510d69"), createPerson: message("en", "screen.membersView.f89e36ab7ca8"), createDescription: message("en", "screen.membersView.78d726d8a6a5"), fullName: message("en", "screen.membersView.d89d816c1d2e"), optionalEmail: message("en", "screen.membersView.225a13674c55"), eligibleRoster: message("en", "screen.membersView.1966c06ba85c"), eligibilityFrozen: message("en", "screen.membersView.23d4b64c3e5d"), saveFailure: message("en", "screen.membersView.3c5eb2b277a7"), cancel: message("en", "screen.membersView.18e29ea869c8"), encryptAndSave: message("en", "screen.membersView.f456a4aa4c43"),
    searchRoster: message("en", "screen.membersView.99dfea08be90"), searchPlaceholder: message("en", "screen.membersView.b80a551965e4"), privateIndex: message("en", "screen.membersView.20b224026d55"), privateIndexBody: message("en", "screen.membersView.5673fb953c9b"), incompleteIndex: message("en", "screen.membersView.78b670cb6095"), authorizedDirectory: message("en", "screen.membersView.fbb9e7b522b0"), indexing: message("en", "screen.membersView.ea5b0ee62e7e"), people: message("en", "screen.membersView.e61e02200658"), responsibilities: message("en", "screen.membersView.3a0335565169"), archived: message("en", "screen.membersView.9cf8b062b4b5"), eligible: message("en", "screen.membersView.92bae68302f7"), ineligible: message("en", "screen.membersView.169ff2291161"), photo: message("en", "screen.membersView.739b63052ea0"), photoOf: message("en", "screen.membersView.5580644333ad"), noMatches: message("en", "screen.membersView.7eb822f89298"), emptyRoster: message("en", "screen.membersView.5ebfc65c3f74"), photograph: message("en", "screen.membersView.8334ebf72909"), photographOf: message("en", "screen.membersView.c99ddce8deb8"), photographDescription: message("en", "screen.membersView.580c692f9625"),
    controlledImport: message("en", "screen.membersView.56bceaa29f4a"), importIntro: message("en", "screen.membersView.47b1184cd5ea"), prepareImport: message("en", "screen.membersView.552e7c1d4cc5"), importTitle: message("en", "screen.membersView.bc92094ef4d9"), importLimits: message("en", "screen.membersView.f40c3099e400"), fileStep: message("en", "screen.membersView.196c62f955c1"), changeFile: message("en", "screen.membersView.d93fb925cf23"), selectFile: message("en", "screen.membersView.586ae2e70264"), mappingStep: message("en", "screen.membersView.736327bc5da3"), explicitMapping: message("en", "screen.membersView.17a1d9350ae4"), sheet: message("en", "screen.membersView.71ab118c2661"), rows: message("en", "screen.membersView.7a4c2c0357fd"), doNotImport: message("en", "screen.membersView.ae142d9ec555"), noHeader: message("en", "screen.membersView.a8ddebb0a316"), validatePreview: message("en", "screen.membersView.e9ea7f4cb796"), cannotContinue: message("en", "screen.membersView.81f3e2b4c5ef"),
    reviewStep: message("en", "screen.membersView.d825a0d89cac"), withError: message("en", "screen.membersView.061234b7e2b1"), undecided: message("en", "screen.membersView.307d7b5a0e43"), applySuggestions: message("en", "screen.membersView.c598dcb9d432"), privacyNote: message("en", "screen.membersView.124440809292"), previewLabel: message("en", "screen.membersView.2825c535e9c0"), row: message("en", "screen.membersView.62cc5db7178e"), person: message("en", "screen.membersView.b792923baa6a"), validation: message("en", "screen.membersView.6d33674f49ac"), decision: message("en", "screen.membersView.57c457729918"), target: message("en", "screen.membersView.69c5eb786923"), unnamed: message("en", "screen.membersView.f00a565cde07"), noId: message("en", "screen.membersView.87aa9c220775"), ready: message("en", "screen.membersView.122ecc645b05"), decisionRow: message("en", "screen.membersView.eba3a2d7de18"), decide: message("en", "screen.membersView.2758c050aea6"), createSeparate: message("en", "screen.membersView.3f2efd6b26f4"), update: message("en", "screen.membersView.c85458aeb753"), skip: message("en", "screen.membersView.4bf53261cc26"), targetRow: message("en", "screen.membersView.629fc466e97b"), select: message("en", "screen.membersView.30360a3bdaf2"), newTarget: message("en", "screen.membersView.d1a3ec510d69"), noContent: message("en", "screen.membersView.d8817f99c380"), previous: message("en", "screen.membersView.737c89700c42"), page: message("en", "screen.membersView.be29af45774e"), of: message("en", "screen.membersView.2fd307b171ad"), next: message("en", "screen.membersView.3751157c79a9"),
    serverConflicts: message("en", "screen.membersView.8c809a54b37f"), persistedPreview: message("en", "screen.membersView.1f2b415429a0"), createVerb: message("en", "screen.membersView.ba345de57a18"), updateVerb: message("en", "screen.membersView.b0d92f798b57"), skipVerb: message("en", "screen.membersView.c4d74355a46f"), replayedPreview: message("en", "screen.membersView.43ea3212dc07"), stageFailure: message("en", "screen.membersView.dc3290d0b462"), commitFailure: message("en", "screen.membersView.598b422e0cfe"), downloadIssues: message("en", "screen.membersView.d12d681321c5"), close: message("en", "screen.membersView.c0b0def8d78c"), encryptValidate: message("en", "screen.membersView.52530ced5213"), confirmImport: message("en", "screen.membersView.fc29d02ef76d"), importConfirmed: message("en", "screen.membersView.30f3a48d2a63"), created: message("en", "screen.membersView.1311b1b3ba58"), updated: message("en", "screen.membersView.35a5ee8d64f1"), skipped: message("en", "screen.membersView.8fcde0cf9232"), retryRecognized: message("en", "screen.membersView.85eff5d47bde"), downloadTemplate: message("en", "screen.membersView.4ea73e9c7a6a"),
    filter: message("en", "screen.membersView.616cb30b61c7"), allStatus: message("en", "screen.membersView.e49424718bbf"), activeOnly: message("en", "screen.membersView.109025b1fb86"), archivedOnly: message("en", "screen.membersView.c107d41c9bd9"), editPerson: message("en", "screen.membersView.10f4da33b515"), editDescription: message("en", "screen.membersView.962eb038dd68"), membershipStatus: message("en", "screen.membersView.cc022e3b7be9"), memberActive: message("en", "screen.membersView.3f9a8d3cda2d"), memberInactive: message("en", "screen.membersView.088c4f6880db"), eligibilityStatus: message("en", "screen.membersView.f029c8c01cae"), underReview: message("en", "screen.membersView.9d52300e262a"), availableForOffice: message("en", "screen.membersView.08a033ae4509"), visibleReason: message("en", "screen.membersView.2ca8eb56a52a"), visibleReasonHelp: message("en", "screen.membersView.32bb45fbbc53"), privateReview: message("en", "screen.membersView.21b472328f1d"), privateReviewHelp: message("en", "screen.membersView.8249432dd21c"), privateNote: message("en", "screen.membersView.0a0823859610"), departmentRestriction: message("en", "screen.membersView.4473bb80574c"), restrictionUntil: message("en", "screen.membersView.dc34b269cd97"), clearPrivateReview: message("en", "screen.membersView.5a934fdea4fa"), saveChanges: message("en", "screen.membersView.b6e865c65192"), archivePerson: message("en", "screen.membersView.d91f72daaade"), reactivatePerson: message("en", "screen.membersView.ebee8ece661d"), archiveHelp: message("en", "screen.membersView.db6fd2dae07c"), reactivateHelp: message("en", "screen.membersView.42e2ed05166e"), reason: message("en", "screen.membersView.3954c2a2dcdb"), reasonPlaceholder: message("en", "screen.membersView.172254b36914"), confirmArchive: message("en", "screen.membersView.e589f11efa82"), confirmReactivate: message("en", "screen.membersView.26e17a71ca03"), lifecycleFailure: message("en", "screen.membersView.e13e249e1d0a"), editFailure: message("en", "screen.membersView.72b99e5588c2"), assignmentBlock: message("en", "screen.membersView.4b88eb4a3de7"), managementActions: message("en", "screen.membersView.d9cc0f8d4f55"),
  },
  fr: {
    loadingRoster: message("fr", "screen.membersView.b2a8d4b20744"), loadFailure: message("fr", "screen.membersView.544c70c2ee57"), eyebrow: message("fr", "screen.membersView.71f576f8300c"), title: message("fr", "screen.membersView.500cd8288ddc"), description: message("fr", "screen.membersView.02867baee844"),
    newPerson: message("fr", "screen.membersView.d1a3ec510d69"), createPerson: message("fr", "screen.membersView.f89e36ab7ca8"), createDescription: message("fr", "screen.membersView.78d726d8a6a5"), fullName: message("fr", "screen.membersView.d89d816c1d2e"), optionalEmail: message("fr", "screen.membersView.225a13674c55"), eligibleRoster: message("fr", "screen.membersView.1966c06ba85c"), eligibilityFrozen: message("fr", "screen.membersView.23d4b64c3e5d"), saveFailure: message("fr", "screen.membersView.3c5eb2b277a7"), cancel: message("fr", "screen.membersView.18e29ea869c8"), encryptAndSave: message("fr", "screen.membersView.f456a4aa4c43"),
    searchRoster: message("fr", "screen.membersView.99dfea08be90"), searchPlaceholder: message("fr", "screen.membersView.b80a551965e4"), privateIndex: message("fr", "screen.membersView.20b224026d55"), privateIndexBody: message("fr", "screen.membersView.5673fb953c9b"), incompleteIndex: message("fr", "screen.membersView.78b670cb6095"), authorizedDirectory: message("fr", "screen.membersView.fbb9e7b522b0"), indexing: message("fr", "screen.membersView.ea5b0ee62e7e"), people: message("fr", "screen.membersView.e61e02200658"), responsibilities: message("fr", "screen.membersView.3a0335565169"), archived: message("fr", "screen.membersView.9cf8b062b4b5"), eligible: message("fr", "screen.membersView.92bae68302f7"), ineligible: message("fr", "screen.membersView.169ff2291161"), photo: message("fr", "screen.membersView.739b63052ea0"), photoOf: message("fr", "screen.membersView.5580644333ad"), noMatches: message("fr", "screen.membersView.7eb822f89298"), emptyRoster: message("fr", "screen.membersView.5ebfc65c3f74"), photograph: message("fr", "screen.membersView.8334ebf72909"), photographOf: message("fr", "screen.membersView.c99ddce8deb8"), photographDescription: message("fr", "screen.membersView.580c692f9625"),
    controlledImport: message("fr", "screen.membersView.56bceaa29f4a"), importIntro: message("fr", "screen.membersView.47b1184cd5ea"), prepareImport: message("fr", "screen.membersView.552e7c1d4cc5"), importTitle: message("fr", "screen.membersView.bc92094ef4d9"), importLimits: message("fr", "screen.membersView.f40c3099e400"), fileStep: message("fr", "screen.membersView.196c62f955c1"), changeFile: message("fr", "screen.membersView.d93fb925cf23"), selectFile: message("fr", "screen.membersView.586ae2e70264"), mappingStep: message("fr", "screen.membersView.736327bc5da3"), explicitMapping: message("fr", "screen.membersView.17a1d9350ae4"), sheet: message("fr", "screen.membersView.71ab118c2661"), rows: message("fr", "screen.membersView.7a4c2c0357fd"), doNotImport: message("fr", "screen.membersView.ae142d9ec555"), noHeader: message("fr", "screen.membersView.a8ddebb0a316"), validatePreview: message("fr", "screen.membersView.e9ea7f4cb796"), cannotContinue: message("fr", "screen.membersView.81f3e2b4c5ef"),
    reviewStep: message("fr", "screen.membersView.d825a0d89cac"), withError: message("fr", "screen.membersView.061234b7e2b1"), undecided: message("fr", "screen.membersView.307d7b5a0e43"), applySuggestions: message("fr", "screen.membersView.c598dcb9d432"), privacyNote: message("fr", "screen.membersView.124440809292"), previewLabel: message("fr", "screen.membersView.2825c535e9c0"), row: message("fr", "screen.membersView.62cc5db7178e"), person: message("fr", "screen.membersView.b792923baa6a"), validation: message("fr", "screen.membersView.6d33674f49ac"), decision: message("fr", "screen.membersView.57c457729918"), target: message("fr", "screen.membersView.69c5eb786923"), unnamed: message("fr", "screen.membersView.f00a565cde07"), noId: message("fr", "screen.membersView.87aa9c220775"), ready: message("fr", "screen.membersView.122ecc645b05"), decisionRow: message("fr", "screen.membersView.eba3a2d7de18"), decide: message("fr", "screen.membersView.2758c050aea6"), createSeparate: message("fr", "screen.membersView.3f2efd6b26f4"), update: message("fr", "screen.membersView.c85458aeb753"), skip: message("fr", "screen.membersView.4bf53261cc26"), targetRow: message("fr", "screen.membersView.629fc466e97b"), select: message("fr", "screen.membersView.30360a3bdaf2"), newTarget: message("fr", "screen.membersView.d1a3ec510d69"), noContent: message("fr", "screen.membersView.d8817f99c380"), previous: message("fr", "screen.membersView.737c89700c42"), page: message("fr", "screen.membersView.be29af45774e"), of: message("fr", "screen.membersView.2fd307b171ad"), next: message("fr", "screen.membersView.3751157c79a9"),
    serverConflicts: message("fr", "screen.membersView.8c809a54b37f"), persistedPreview: message("fr", "screen.membersView.1f2b415429a0"), createVerb: message("fr", "screen.membersView.ba345de57a18"), updateVerb: message("fr", "screen.membersView.b0d92f798b57"), skipVerb: message("fr", "screen.membersView.c4d74355a46f"), replayedPreview: message("fr", "screen.membersView.43ea3212dc07"), stageFailure: message("fr", "screen.membersView.dc3290d0b462"), commitFailure: message("fr", "screen.membersView.598b422e0cfe"), downloadIssues: message("fr", "screen.membersView.d12d681321c5"), close: message("fr", "screen.membersView.c0b0def8d78c"), encryptValidate: message("fr", "screen.membersView.52530ced5213"), confirmImport: message("fr", "screen.membersView.fc29d02ef76d"), importConfirmed: message("fr", "screen.membersView.30f3a48d2a63"), created: message("fr", "screen.membersView.1311b1b3ba58"), updated: message("fr", "screen.membersView.35a5ee8d64f1"), skipped: message("fr", "screen.membersView.8fcde0cf9232"), retryRecognized: message("fr", "screen.membersView.85eff5d47bde"), downloadTemplate: message("fr", "screen.membersView.4ea73e9c7a6a"),
    filter: message("fr", "screen.membersView.616cb30b61c7"), allStatus: message("fr", "screen.membersView.e49424718bbf"), activeOnly: message("fr", "screen.membersView.109025b1fb86"), archivedOnly: message("fr", "screen.membersView.c107d41c9bd9"), editPerson: message("fr", "screen.membersView.10f4da33b515"), editDescription: message("fr", "screen.membersView.962eb038dd68"), membershipStatus: message("fr", "screen.membersView.cc022e3b7be9"), memberActive: message("fr", "screen.membersView.3f9a8d3cda2d"), memberInactive: message("fr", "screen.membersView.088c4f6880db"), eligibilityStatus: message("fr", "screen.membersView.f029c8c01cae"), underReview: message("fr", "screen.membersView.9d52300e262a"), availableForOffice: message("fr", "screen.membersView.08a033ae4509"), visibleReason: message("fr", "screen.membersView.2ca8eb56a52a"), visibleReasonHelp: message("fr", "screen.membersView.32bb45fbbc53"), privateReview: message("fr", "screen.membersView.21b472328f1d"), privateReviewHelp: message("fr", "screen.membersView.8249432dd21c"), privateNote: message("fr", "screen.membersView.0a0823859610"), departmentRestriction: message("fr", "screen.membersView.4473bb80574c"), restrictionUntil: message("fr", "screen.membersView.dc34b269cd97"), clearPrivateReview: message("fr", "screen.membersView.5a934fdea4fa"), saveChanges: message("fr", "screen.membersView.b6e865c65192"), archivePerson: message("fr", "screen.membersView.d91f72daaade"), reactivatePerson: message("fr", "screen.membersView.ebee8ece661d"), archiveHelp: message("fr", "screen.membersView.db6fd2dae07c"), reactivateHelp: message("fr", "screen.membersView.42e2ed05166e"), reason: message("fr", "screen.membersView.3954c2a2dcdb"), reasonPlaceholder: message("fr", "screen.membersView.172254b36914"), confirmArchive: message("fr", "screen.membersView.e589f11efa82"), confirmReactivate: message("fr", "screen.membersView.26e17a71ca03"), lifecycleFailure: message("fr", "screen.membersView.e13e249e1d0a"), editFailure: message("fr", "screen.membersView.72b99e5588c2"), assignmentBlock: message("fr", "screen.membersView.4b88eb4a3de7"), managementActions: message("fr", "screen.membersView.d9cc0f8d4f55"),
  },
} as const;

async function sha256Bytes(value: ArrayBuffer): Promise<`sha256:${string}`> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return `sha256:${Array.from(new Uint8Array(digest)).map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}

async function opaqueSheetName(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return `sheet-sha256:${Array.from(new Uint8Array(digest)).map((part) => part.toString(16).padStart(2, "0")).join("")}`;
}

function visibleError(error: unknown, locale: Locale, fallback: string): string {
  if (error instanceof ApiError && error.code === "MEMBER_HAS_EFFECTIVE_ASSIGNMENTS") {
    return memberCopy[locale].assignmentBlock;
  }
  if (error instanceof ApiError) return localizedApiError(error, locale);
  return error instanceof Error ? error.message : fallback;
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function initials(name: string) {
  return name.split(/\s+/).filter(Boolean).map((part) => part[0]).slice(0, 2).join("").toLocaleUpperCase();
}

export function MembersView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const vault = useVault();
  const queryClient = useQueryClient();
  const fileInput = useRef<HTMLInputElement>(null);
  const importWorker = useRef<MemberImportWorkerClient | null>(null);
  const createPayload = useRef<object | undefined>(undefined);
  const createIdempotency = useRef(idempotencyKey());
  const importPayload = useRef<object | undefined>(undefined);
  const importJob = useRef<string | undefined>(undefined);
  const importPreviewIdempotency = useRef(idempotencyKey());
  const importCommitIdempotency = useRef(idempotencyKey());
  const editPayload = useRef<object | undefined>(undefined);
  const editIdempotency = useRef(idempotencyKey());
  const lifecycleIdempotency = useRef(idempotencyKey());
  const exportAuthorization = useRef<{ requestFingerprint: string; idempotencyKey: string } | undefined>(undefined);
  const mayManage = session.permissions.includes("member.manage");
  const mayManageEligibility = session.permissions.includes("member.eligibility.manage");
  const mayReadContact = session.permissions.includes("member.contact.read");
  const mayManageContact = session.permissions.includes("member.contact.manage");
  const mayCreate = mayManage && mayManageEligibility;
  const mayImport = ["member.import", "member.manage", "member.eligibility.manage"].every((permission) => session.permissions.includes(permission));
  const mayExport = session.permissions.includes("report.export");
  const mayReadPrivateNote = session.permissions.includes("private-note.read");
  const mayReadQualifications = session.permissions.includes("member.qualification.read");
  const query = useQuery({ queryKey: ["members", mayManage ? "manage" : "read", mayReadPrivateNote ? "private" : "standard", mayReadContact ? "contact" : "no-contact", session.tenant.id, session.user.id], queryFn: async () => {
    const items: MemberRecord[] = []; let cursor: string | undefined; let total = 0; let pages = 0;
    do {
      const endpoint = mayManage ? "/v1/members/manage" : "/v1/members";
      const page = await apiRequest<{ items: MemberRecord[]; total: number; nextCursor?: string | null }>(`${endpoint}?limit=250${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      items.push(...page.items); total = page.total; cursor = page.nextCursor ?? undefined; pages += 1;
      if (pages > 100) throw new Error(message(locale, "screen.membersView.d4a1cfc7862d"));
    } while (cursor);
    return { items, total: total || items.length };
  } });
  const catalogQuery = useQuery({
    queryKey: ["catalog", "member-eligibility", session.tenant.id],
    queryFn: async () => {
      const catalog = await api.catalog();
      return catalog as { departments: EligibilityCatalogDepartment[] };
    },
  });
  const [members, setMembers] = useState<DecryptedMember[]>([]);
  const [indexing, setIndexing] = useState(false);
  const [decryptError, setDecryptError] = useState<string>();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<MemberStatusFilter>(mayManage ? "active" : "all");
  const [newMemberOpen, setNewMemberOpen] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [eligible, setEligible] = useState(true);
  const [visibleReason, setVisibleReason] = useState("");
  const [createRestrictionDepartment, setCreateRestrictionDepartment] = useState("");
  const [createRestrictionUntil, setCreateRestrictionUntil] = useState("");
  const [editingMember, setEditingMember] = useState<DecryptedMember>();
  const [editName, setEditName] = useState("");
  const [editEmail, setEditEmail] = useState("");
  const [editContactChanged, setEditContactChanged] = useState(false);
  const [resolveLegacyProfile, setResolveLegacyProfile] = useState(false);
  const [editMembershipStatus, setEditMembershipStatus] = useState<"active" | "inactive">("active");
  const [editEligibilityStatus, setEditEligibilityStatus] = useState<"eligible" | "ineligible" | "review">("eligible");
  const [editAvailable, setEditAvailable] = useState(true);
  const [editVisibleReason, setEditVisibleReason] = useState("");
  const [privateNote, setPrivateNote] = useState("");
  const [restrictionDepartment, setRestrictionDepartment] = useState("");
  const [restrictionUntil, setRestrictionUntil] = useState("");
  const [clearPrivateReview, setClearPrivateReview] = useState(false);
  const [privateReviewChanged, setPrivateReviewChanged] = useState(false);
  const [lifecycle, setLifecycle] = useState<MemberLifecycle>();
  const [lifecycleReasonCode, setLifecycleReasonCode] = useState("");
  const [memberNotice, setMemberNotice] = useState<string>();
  const [importOpen, setImportOpen] = useState(false);
  const [importSheets, setImportSheets] = useState<readonly ImportSheetDescriptor[]>([]);
  const [importDatasetId, setImportDatasetId] = useState<string>();
  const [selectedSheetName, setSelectedSheetName] = useState<string>();
  const [columnMapping, setColumnMapping] = useState<ImportColumnMapping>({});
  const [preview, setPreview] = useState<readonly ImportPreviewRow[]>([]);
  const [serverPreview, setServerPreview] = useState<MemberImportPreviewResponse>();
  const [importPage, setImportPage] = useState(0);
  const [analyzingImport, setAnalyzingImport] = useState(false);
  const [importName, setImportName] = useState<string>();
  const [sourceFingerprint, setSourceFingerprint] = useState<string>();
  const [importError, setImportError] = useState<string>();
  const [importResult, setImportResult] = useState<MemberImportSummary>();
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string>();
  const [templateExporting, setTemplateExporting] = useState(false);
  const [photoMember, setPhotoMember] = useState<DecryptedMember>();
  const [qualificationMember, setQualificationMember] = useState<DecryptedMember>();

  useEffect(() => () => {
    importWorker.current?.terminate();
    importWorker.current = null;
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function buildIndex() {
      if (!query.data || !vault.key) {
        if (!cancelled) { setMembers([]); setIndexing(false); }
        return;
      }
      setIndexing(true);
      setMembers([]);
      setDecryptError(undefined);
      try {
        let hadFailures = false;
        const decrypted = await Promise.all(query.data.items.map(async (member) => {
          const { eligibilityEnvelope, contactEnvelope, ...memberProjection } = member;
          if (!member.displayEnvelope) {
            return {
              ...memberProjection,
              displayName: message(locale, "screen.membersView.bb0d508d4705"),
            };
          }
          try {
            const profile = await openJsonEnvelope<MemberDisplay>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: member.displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: member.id, purpose: "member-display", schemaVersion: 1 },
            });
            let contact: MemberContact = {};
            if (mayReadContact && contactEnvelope) {
              try {
                contact = await openJsonEnvelope<MemberContact>({
                  resolver: vault,
                  tenantId: session.tenant.id,
                  envelope: contactEnvelope,
                  aad: { tenantId: session.tenant.id, memberId: member.id, purpose: "member-contact", schemaVersion: 1 },
                });
              } catch {
                hadFailures = true;
              }
            }
            let eligibilityReview: MemberEligibilityReview | undefined;
            if (eligibilityEnvelope) {
              try {
                eligibilityReview = await revealMemberEligibilityReview({
                  permissions: session.permissions,
                  key: keyForEnvelope(vault, session.tenant.id, eligibilityEnvelope),
                  keyId: eligibilityEnvelope.keyId,
                  tenantId: session.tenant.id,
                  memberId: member.id,
                  eligibilityEnvelope,
                });
              } catch {
                hadFailures = true;
              }
            }
            const displayName = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!displayName) throw new Error(message(locale, "screen.membersView.266264536765"));
            return { ...memberProjection, ...profile, ...contact, displayName, ...(eligibilityReview ? { eligibilityReview } : {}) };
          } catch {
            hadFailures = true;
            return {
              ...memberProjection,
              displayName: message(locale, "screen.membersView.bb0d508d4705"),
            };
          }
        }));
        if (!cancelled) {
          setMembers(decrypted);
          setDecryptError(hadFailures ? message(locale, "screen.membersView.fd52bfc9f150") : undefined);
        }
      } catch {
        if (!cancelled) {
          setMembers([]);
          setDecryptError(message(locale, "screen.membersView.fd52bfc9f150"));
        }
      } finally {
        if (!cancelled) setIndexing(false);
      }
    }
    void buildIndex();
    return () => { cancelled = true; };
  }, [locale, mayReadContact, mayReadPrivateNote, query.data, session.permissions, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  const filtered = useMemo(() => {
    const term = normalizeSearchText(search);
    return members.filter((member) => {
      if (statusFilter === "active" && member.archived) return false;
      if (statusFilter === "archived" && !member.archived) return false;
      return !term || normalizeSearchText(`${member.displayName} ${member.shortId}${mayReadContact ? ` ${member.email ?? ""}` : ""}`).includes(term);
    });
  }, [mayReadContact, members, search, statusFilter]);
  const eligibilityDepartments = useMemo(
    () => [...(catalogQuery.data?.departments ?? [])]
      .sort((left, right) => localizedName(left.names, locale, left.canonicalCode)
        .localeCompare(localizedName(right.names, locale, right.canonicalCode), locale)),
    [catalogQuery.data?.departments, locale],
  );
  const eligibilityDepartmentName = (departmentId: string): string => {
    const department = eligibilityDepartments.find(({ id }) => id === departmentId);
    return department ? localizedName(department.names, locale, department.canonicalCode) : departmentId;
  };

  const createMutation = useMutation({
    mutationFn: async () => {
      if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.membersView.ee7359753d7e"));
      if (createPayload.current) return api.createMember(createPayload.current, createIdempotency.current);
      const memberId = crypto.randomUUID();
      const display = await encryptJson(
        vault.key,
        vault.keyId,
        { tenantId: session.tenant.id, memberId, purpose: "member-display", schemaVersion: 1 },
        { displayName: displayName.trim(), membershipStatus: "active", ...(!eligible && visibleReason.trim() ? { visibleReason: visibleReason.trim() } : {}) } satisfies MemberDisplay,
      );
      const contact = mayManageContact && email.trim()
        ? await encryptJson(
            vault.key,
            vault.keyId,
            { tenantId: session.tenant.id, memberId, purpose: "member-contact", schemaVersion: 1 },
            { email: email.trim() } satisfies MemberContact,
          )
        : undefined;
      const body = {
        id: memberId,
        eligible,
        displayEnvelope: display.envelope,
        displayContentHash: display.contentHash,
        ...(contact ? { contactEnvelope: contact.envelope, contactContentHash: contact.contentHash } : {}),
        departmentRestriction: createRestrictionDepartment || null,
        validUntil: createRestrictionUntil || null,
      };
      createPayload.current = body;
      return api.createMember(body, createIdempotency.current);
    },
    onSuccess: () => {
      setDisplayName(""); setEmail(""); setEligible(true); setVisibleReason("");
      setCreateRestrictionDepartment(""); setCreateRestrictionUntil(""); setNewMemberOpen(false);
      createPayload.current = undefined; createIdempotency.current = idempotencyKey();
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  function resetEditSubmission() {
    editPayload.current = undefined;
    editIdempotency.current = idempotencyKey();
  }

  function beginEdit(member: DecryptedMember) {
    setEditingMember(member);
    // A quarantined legacy envelope has never been decrypted, so the
    // placeholder must not be accepted as replacement identity content.
    setEditName(member.profileMigrationRequired ? "" : member.displayName);
    setEditEmail(member.email ?? "");
    setEditContactChanged(false);
    setResolveLegacyProfile(false);
    setEditMembershipStatus(member.membershipStatus === "inactive" ? "inactive" : "active");
    setEditEligibilityStatus(member.eligibilityStatus ?? (member.eligible ? "eligible" : "ineligible"));
    setEditAvailable(member.available ?? member.eligible);
    setEditVisibleReason(member.visibleReason ?? "");
    setPrivateNote(member.eligibilityReview?.note ?? "");
    setRestrictionDepartment(member.departmentRestriction ?? "");
    setRestrictionUntil(member.validUntil ?? "");
    setClearPrivateReview(false);
    setPrivateReviewChanged(false);
    resetEditSubmission();
    editMutation.reset();
  }

  const editMutation = useMutation({
    mutationFn: async () => {
      if (!editingMember || !vault.key || !vault.keyId) {
        throw new Error(message(locale, "screen.membersView.ee7359753d7e"));
      }
      if (!editPayload.current) {
        const operationalStatus = editMembershipStatus === "active" ? editEligibilityStatus : "ineligible";
        const operationalAvailability = operationalStatus === "eligible" && editAvailable;
        const display = await encryptJson(
          vault.key,
          vault.keyId,
          { tenantId: session.tenant.id, memberId: editingMember.id, purpose: "member-display", schemaVersion: 1 },
          {
            displayName: editName.trim(),
            ...(editingMember.firstName ? { firstName: editingMember.firstName } : {}),
            ...(editingMember.lastName ? { lastName: editingMember.lastName } : {}),
            membershipStatus: editMembershipStatus,
            ...(editVisibleReason.trim() ? { visibleReason: editVisibleReason.trim() } : {}),
            ...(editingMember.photoReference ? { photoReference: editingMember.photoReference } : {}),
          } satisfies MemberDisplay,
        );
        const body: Record<string, unknown> = {
          expectedVersion: editingMember.version,
          displayEnvelope: display.envelope,
          displayContentHash: display.contentHash,
        };
        if (mayManageContact && (editContactChanged || resolveLegacyProfile)) {
          if (editEmail.trim()) {
            const contact = await encryptJson(
              vault.key,
              vault.keyId,
              { tenantId: session.tenant.id, memberId: editingMember.id, purpose: "member-contact", schemaVersion: 1 },
              { email: editEmail.trim() } satisfies MemberContact,
            );
            body.contactEnvelope = contact.envelope;
            body.contactContentHash = contact.contentHash;
          } else {
            body.contactEnvelope = null;
          }
        }
        if (resolveLegacyProfile) body.resolveLegacyProfile = true;
        if (mayManageEligibility) {
          body.eligibilityStatus = operationalStatus;
          body.available = operationalAvailability;
          const normalizedDepartment = restrictionDepartment || null;
          const normalizedValidUntil = restrictionUntil || null;
          if (normalizedDepartment !== editingMember.departmentRestriction) {
            body.departmentRestriction = normalizedDepartment;
          }
          if (normalizedValidUntil !== editingMember.validUntil) {
            body.validUntil = normalizedValidUntil;
          }
          if (clearPrivateReview) {
            body.eligibilityEnvelope = null;
          } else if (privateReviewChanged && privateNote.trim()) {
            const eligibility = await encryptJson(
              vault.key,
              vault.keyId,
              { tenantId: session.tenant.id, memberId: editingMember.id, purpose: "member-eligibility", schemaVersion: 1 },
              {
                schema: "nombramientos-member-eligibility/v1",
                ...(privateNote.trim() ? { note: privateNote.trim() } : {}),
                reviewedByIdentityId: session.user.id,
                reviewedAt: new Date().toISOString(),
              },
            );
            body.eligibilityEnvelope = eligibility.envelope;
            body.eligibilityContentHash = eligibility.contentHash;
          }
        }
        editPayload.current = body;
      }
      return apiRequest<MemberMutationResult>(`/v1/members/${encodeURIComponent(editingMember.id)}`, {
        method: "PATCH",
        body: JSON.stringify(editPayload.current),
        idempotent: true,
        idempotencyKey: editIdempotency.current,
      });
    },
    retry: 1,
    onSuccess: (result) => {
      const paused = result.pausedWorkflows?.length ?? 0;
      setMemberNotice(paused > 0
        ? message(locale, "members.workflowsPaused", { count: paused })
        : message(locale, "screen.membersView.9ecf6ad16c8c"));
      setEditingMember(undefined);
      resetEditSubmission();
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      void queryClient.invalidateQueries({ queryKey: ["active-round"] });
    },
  });

  function beginLifecycle(member: DecryptedMember, action: MemberLifecycle["action"]) {
    setLifecycle({ member, action });
    setLifecycleReasonCode("");
    lifecycleIdempotency.current = idempotencyKey();
    lifecycleMutation.reset();
  }

  const lifecycleMutation = useMutation({
    mutationFn: async () => {
      if (!lifecycle) throw new Error(memberCopy[locale].lifecycleFailure);
      return apiRequest<MemberMutationResult>(`/v1/members/${encodeURIComponent(lifecycle.member.id)}/${lifecycle.action}`, {
        method: "POST",
        body: JSON.stringify({ expectedVersion: lifecycle.member.version, reasonCode: lifecycleReasonCode }),
        idempotent: true,
        idempotencyKey: lifecycleIdempotency.current,
      });
    },
    retry: 1,
    onSuccess: (result) => {
      const paused = result.pausedWorkflows?.length ?? 0;
      setMemberNotice(paused > 0
        ? message(locale, "members.workflowsPaused", { count: paused })
        : message(locale, "screen.membersView.49c9485a2f49"));
      setLifecycle(undefined);
      setLifecycleReasonCode("");
      lifecycleIdempotency.current = idempotencyKey();
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      void queryClient.invalidateQueries({ queryKey: ["active-round"] });
    },
  });

  const stageImportMutation = useMutation({
    mutationFn: async () => {
      if (!vault.key || !vault.keyId || !importName || !sourceFingerprint || !selectedSheetName) {
        throw new Error(message(locale, "screen.membersView.bc93cc44f29b"));
      }
      if (preview.some(({ action }) => action === "undecided")) {
        throw new Error(message(locale, "screen.membersView.07f8f7dc6076"));
      }
      if (!importPayload.current) {
        const rows = await Promise.all(preview.map(async (item) => {
          if (item.action === "skip") {
            return {
              sourceRow: item.sourceRow,
              id: item.generatedId,
              eligible: item.eligible,
              decision: { action: "skip" as const, matchBasis: item.suggestedMatchBasis },
            };
          }
          const candidate = item.action === "update"
            ? item.candidates.find(({ id }) => id === item.targetId)
            : undefined;
          if (item.action === "update" && !candidate) throw new Error(message(locale, "screen.membersView.ba337bd52ce8", { value0: item.sourceRow }));
          const memberId = candidate?.id ?? item.generatedId;
          const display = await encryptJson(
            vault.key!,
            vault.keyId!,
            { tenantId: session.tenant.id, memberId, purpose: "member-display", schemaVersion: 1 },
            {
              displayName: item.displayName,
              ...(item.firstName ? { firstName: item.firstName } : {}),
              ...(item.lastName ? { lastName: item.lastName } : {}),
              membershipStatus: item.membershipStatus,
              ...(item.visibleReason ? { visibleReason: item.visibleReason } : {}),
              ...(item.photoReference ? { photoReference: item.photoReference } : {}),
            },
          );
          const contact = mayManageContact && item.email
            ? await encryptJson(
                vault.key!,
                vault.keyId!,
                { tenantId: session.tenant.id, memberId, purpose: "member-contact", schemaVersion: 1 },
                { email: item.email } satisfies MemberContact,
              )
            : undefined;
          return {
            sourceRow: item.sourceRow,
            id: memberId,
            ...(candidate?.shortId || item.sourceId ? { shortId: candidate?.shortId ?? item.sourceId } : {}),
            eligible: item.eligible,
            decision: {
              action: item.action,
              matchBasis: candidate?.basis ?? item.suggestedMatchBasis,
            },
            ...(candidate ? { expectedVersion: candidate.version } : {}),
            displayEnvelope: display.envelope,
            displayContentHash: display.contentHash,
            ...(contact ? { contactEnvelope: contact.envelope, contactContentHash: contact.contentHash } : {}),
          };
        }));
        importPayload.current = {
          rows,
          sourceFileName: importName.toLocaleLowerCase().endsWith(".xlsx") ? "roster.xlsx" : "roster.csv",
          sourceFingerprint,
          sourceSheetName: await opaqueSheetName(selectedSheetName),
          columnMapping,
        };
      }
      return api.previewMemberImport(importPayload.current, importPreviewIdempotency.current);
    },
    onSuccess: (result) => {
      importJob.current = result.importId;
      setServerPreview(result);
      if (result.state === "completed" && result.summary) {
        finishImport({ importId: result.importId, state: "completed", ...result.summary, replayed: true });
      }
    },
  });

  const commitImportMutation = useMutation({
    mutationFn: async () => {
      if (!importJob.current || serverPreview?.state !== "previewed" || (serverPreview.counts?.errors ?? 0) > 0) {
        throw new Error(message(locale, "screen.membersView.f0cf8ad217fc"));
      }
      return api.commitMemberImport(importJob.current, serverPreview.revision, importCommitIdempotency.current);
    },
    onSuccess: (result) => finishImport(result),
  });

  function finishImport(result: MemberImportSummary) {
      setImportResult(result);
      setImportOpen(false);
      setPreview([]); setImportSheets([]); setImportDatasetId(undefined); setImportName(undefined); setSourceFingerprint(undefined);
      setSelectedSheetName(undefined); setColumnMapping({}); setServerPreview(undefined); setImportPage(0);
      importPayload.current = undefined; importJob.current = undefined;
      importPreviewIdempotency.current = idempotencyKey(); importCommitIdempotency.current = idempotencyKey();
      if (fileInput.current) fileInput.current.value = "";
      void queryClient.invalidateQueries({ queryKey: ["members"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard"] });
  }

  function resetStagedImport() {
    importPayload.current = undefined;
    importJob.current = undefined;
    importPreviewIdempotency.current = idempotencyKey();
    importCommitIdempotency.current = idempotencyKey();
    setServerPreview(undefined);
    stageImportMutation.reset();
    commitImportMutation.reset();
  }

  async function inspectFile(file?: File) {
    setImportError(undefined); setImportResult(undefined); setPreview([]); setImportSheets([]);
    setImportDatasetId(undefined); setImportName(undefined); setSourceFingerprint(undefined); setSelectedSheetName(undefined); setColumnMapping({}); setImportPage(0);
    resetStagedImport();
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { setImportError(message(locale, "screen.membersView.7a5baecf701a")); return; }
    const extension = file.name.split(".").pop()?.toLocaleLowerCase();
    if (!extension || !["xlsx", "csv"].includes(extension)) { setImportError(message(locale, "screen.membersView.9961a7aea916")); return; }
    try {
      const fileBytes = await file.arrayBuffer();
      importWorker.current ??= createMemberImportWorkerClient();
      const inspected = await importWorker.current.inspect({
        bytes: fileBytes,
        extension: extension as "csv" | "xlsx",
        locale,
      });
      const selected = inspected.sheets[0]!;
      setImportSheets(inspected.sheets); setImportDatasetId(inspected.datasetId); setSelectedSheetName(selected.name);
      setColumnMapping(restrictContactMapping(suggestColumnMapping(selected.headers), mayManageContact));
      setImportName(file.name); setSourceFingerprint(inspected.sourceFingerprint);
    } catch (error) {
      setImportError(visibleError(error, locale, message(locale, "screen.membersView.643e4773a072")));
    }
  }

  async function analyzeSelectedSheet() {
    const sheet = importSheets.find(({ name }) => name === selectedSheetName);
    if (!sheet || !sourceFingerprint || !importDatasetId) return;
    setAnalyzingImport(true); setImportError(undefined); setPreview([]); setImportPage(0); resetStagedImport();
    try {
      importWorker.current ??= createMemberImportWorkerClient();
      const analyzed = await importWorker.current.preview({
        datasetId: importDatasetId,
        sheetName: sheet.name,
        mapping: columnMapping,
        existingMembers: members.map(({ id, shortId, version, displayName: name, email: memberEmail }) => ({
          id, shortId, version, displayName: name, ...(mayReadContact && memberEmail ? { email: memberEmail } : {}),
        })),
        tenantId: session.tenant.id,
        locale,
      });
      if (!analyzed.rows.length) throw new Error(message(locale, "screen.membersView.4614319385cd"));
      setPreview(analyzed.rows);
    } catch (error) {
      setImportError(visibleError(error, locale, message(locale, "screen.membersView.56898151f0a9")));
    } finally {
      setAnalyzingImport(false);
    }
  }

  function changeSheet(name: string) {
    const sheet = importSheets.find((candidate) => candidate.name === name);
    setSelectedSheetName(name); setPreview([]); setImportPage(0); resetStagedImport();
    setColumnMapping(restrictContactMapping(suggestColumnMapping(sheet?.headers ?? []), mayManageContact));
  }

  function changeMapping(importField: (typeof IMPORT_FIELDS)[number], value: string) {
    const index = value === "" ? undefined : Number(value);
    setColumnMapping((current) => {
      const next = Object.fromEntries(Object.entries(current).filter(([field, mapped]) => field !== importField && mapped !== index)) as ImportColumnMapping;
      if (index !== undefined) next[importField] = index;
      return next;
    });
    setPreview([]); setImportPage(0); resetStagedImport();
  }

  function decideImportRow(sourceRow: number, action: ImportAction, targetId?: string) {
    setPreview((current) => current.map((row) => {
      if (row.sourceRow !== sourceRow) return row;
      const base = Object.fromEntries(Object.entries(row).filter(([key]) => key !== "targetId")) as Omit<ImportPreviewRow, "targetId">;
      const nextTarget = action === "update"
        ? targetId ?? row.targetId ?? (row.candidates.length === 1 ? row.candidates[0]?.id : undefined)
        : undefined;
      return { ...base, action, ...(nextTarget ? { targetId: nextTarget } : {}) };
    }));
    resetStagedImport();
  }

  function applyImportSuggestions() {
    setPreview((current) => current.map((row) => ({ ...row, action: row.suggestedAction })));
    resetStagedImport();
  }

  function downloadImportErrors() {
    const serverCodes = new Map(serverPreview?.rows.map((row) => [row.sourceRow, row.codes] as const) ?? []);
    triggerDownload(
      new Blob([createImportErrorCsv(preview, serverCodes, locale)], { type: "text/csv;charset=utf-8" }),
      `${message(locale, "screen.membersView.9e4dcb8f1410")}-${session.tenant.slug}.csv`,
    );
  }

  async function exportMembers(format: "xlsx" | "csv") {
    setExporting(true);
    setExportError(undefined);
    setMemberNotice(undefined);
    try {
      const exportSelection = [...filtered];
      const selectionSha256 = await sha256Bytes(new TextEncoder().encode(JSON.stringify(
        exportSelection
          .map((member) => ({ id: member.id, version: member.version }))
          .sort((left, right) => left.id.localeCompare(right.id)),
      )).buffer);
      const authorizationRequest = {
        format,
        rowCount: exportSelection.length,
        includeContact: mayReadContact,
        filters: { status: statusFilter, queryApplied: Boolean(normalizeSearchText(search)) },
        selectionSha256,
      } as const;
      const requestFingerprint = JSON.stringify(authorizationRequest);
      if (exportAuthorization.current?.requestFingerprint !== requestFingerprint) {
        exportAuthorization.current = { requestFingerprint, idempotencyKey: idempotencyKey() };
      }
      const authorization = await api.authorizeMemberExport(
        authorizationRequest,
        exportAuthorization.current.idempotencyKey,
      );
      const authorizationExpiresAt = Date.parse(authorization.expiresAt);
      if (
        authorization.format !== format
        || authorization.rowCount !== exportSelection.length
        || authorization.includeContact !== mayReadContact
        || authorization.selectionSha256 !== selectionSha256
        || !Number.isFinite(authorizationExpiresAt)
        || authorizationExpiresAt <= Date.now()
      ) throw new Error(message(locale, "screen.membersView.af80b0a5f27a"));
      const assertAuthorizationActive = () => {
        if (authorizationExpiresAt <= Date.now()) {
          throw new Error(message(locale, "screen.membersView.d84dd9682e2d"));
        }
      };

      const exportLabels = {
        headers: ["ID", message(locale, "screen.membersView.15fa7f36eaa5"), ...(mayReadContact ? [message(locale, "screen.membersView.2684d6bc9e11")] : []), message(locale, "screen.membersView.92bae68302f7"), message(locale, "screen.membersView.e71a1bf62a6c"), message(locale, "screen.membersView.10ddb7420e5a")],
        yes: message(locale, "screen.membersView.b057c888cae8"),
        no: message(locale, "screen.membersView.9448170c072f"),
        archived: message(locale, "screen.membersView.9cf8b062b4b5"),
        active: message(locale, "screen.membersView.901bb448bee7"),
        filename: message(locale, "screen.membersView.035677a1020d"),
        worksheet: message(locale, "screen.membersView.c97f6fd9666c"),
      };
      const values = exportSelection.map((member) => [
        neutralizeSpreadsheetCell(member.shortId), neutralizeSpreadsheetCell(member.displayName), ...(mayReadContact ? [neutralizeSpreadsheetCell(member.email ?? "")] : []), member.eligible ? exportLabels.yes : exportLabels.no,
        member.currentResponsibilities, member.archived ? exportLabels.archived : exportLabels.active,
      ]);
      if (format === "csv") {
        const escape = (value: string | number) => `"${String(value).replaceAll('"', '""')}"`;
        const text = [exportLabels.headers, ...values].map((row) => row.map(escape).join(",")).join("\r\n");
        assertAuthorizationActive();
        triggerDownload(new Blob([`\uFEFF${text}`], { type: "text/csv;charset=utf-8" }), `${exportLabels.filename}-${session.tenant.slug}.csv`);
      } else {
        const ExcelJS = await loadExcelJsBrowser();
        const workbook = new ExcelJS.Workbook();
        workbook.creator = "Nombramientos";
        const worksheet = workbook.addWorksheet(exportLabels.worksheet);
        worksheet.columns = exportLabels.headers.map((header, index) => ({
          header,
          key: `column-${index}`,
          width: index === 1 ? 38 : 18,
        }));
        values.forEach((row) => worksheet.addRow(row));
        worksheet.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
        worksheet.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0A5268" } };
        worksheet.autoFilter = `A1:${mayReadContact ? "F" : "E"}1`;
        worksheet.views = [{ state: "frozen", ySplit: 1 }];
        const buffer = await workbook.xlsx.writeBuffer();
        assertAuthorizationActive();
        triggerDownload(new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${exportLabels.filename}-${session.tenant.slug}.xlsx`);
      }
      exportAuthorization.current = undefined;
      setMemberNotice(message(locale, "screen.membersView.57a96f8a1daf"));
    } catch (error) {
      setExportError(visibleError(error, locale, message(locale, "screen.membersView.bba1404357f6")));
    } finally { setExporting(false); }
  }

  async function downloadXlsxTemplate() {
    setTemplateExporting(true);
    try {
      const ExcelJS = await loadExcelJsBrowser();
      const workbook = new ExcelJS.Workbook();
      workbook.creator = "Nombramientos";
      workbook.created = new Date(0);
      workbook.modified = new Date(0);
      const worksheet = workbook.addWorksheet(message(locale, "screen.membersView.423b347ffabe"));
      worksheet.columns = IMPORT_FIELDS.filter((field) => field !== "email" || mayManageContact).map((field) => ({
        header: importFieldLabels[locale][field],
        key: field,
        width: field === "displayName" || field === "visibleReason" ? 34 : 22,
      }));
      worksheet.addRow({
        sourceId: "DEMO-001",
        displayName: message(locale, "screen.membersView.837a44c38e32"),
        firstName: message(locale, "screen.membersView.918543bcaf4c"),
        lastName: message(locale, "screen.membersView.fd78872716dc"),
        email: "demo.person@example.invalid",
        membershipStatus: "active",
        eligible: "yes",
        visibleReason: "",
        photoReference: "",
      });
      worksheet.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
      worksheet.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0A5268" } };
      worksheet.getRow(1).alignment = { vertical: "middle", wrapText: true };
      worksheet.getRow(1).height = 34;
      worksheet.autoFilter = `A1:${String.fromCharCode(64 + IMPORT_FIELDS.length)}1`;
      worksheet.views = [{ state: "frozen", ySplit: 1 }];
      for (let rowIndex = 2; rowIndex <= 1_001; rowIndex += 1) {
        worksheet.getCell(`F${rowIndex}`).dataValidation = { type: "list", allowBlank: true, formulae: ['"active,inactive"'] };
        worksheet.getCell(`G${rowIndex}`).dataValidation = { type: "list", allowBlank: true, formulae: ['"yes,no"'] };
      }
      const instructions = workbook.addWorksheet(message(locale, "screen.membersView.607a41e10875"));
      instructions.columns = [{ width: 26 }, { width: 90 }];
      instructions.addRows([
        [message(locale, "screen.membersView.bc395bacc518"), message(locale, "screen.membersView.05c6adf6f4c0")],
        [message(locale, "screen.membersView.6a1b043ab90e"), message(locale, "screen.membersView.65fb4fcc8102")],
        [message(locale, "screen.membersView.be7efaad1154"), message(locale, "screen.membersView.ccd94e763aaf")],
      ]);
      instructions.getRow(1).font = { bold: true };
      const buffer = await workbook.xlsx.writeBuffer();
      triggerDownload(new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${message(locale, "screen.membersView.c7410eacbb66")}-${session.tenant.slug}.xlsx`);
    } finally {
      setTemplateExporting(false);
    }
  }

  const selectedImportSheet = importSheets.find(({ name }) => name === selectedSheetName);
  const importHeaders = selectedImportSheet?.headers ?? [];
  const importPageSize = 50;
  const importPageCount = Math.max(1, Math.ceil(preview.length / importPageSize));
  const visibleImportRows = preview.slice(importPage * importPageSize, (importPage + 1) * importPageSize);
  const undecidedImportRows = preview.filter(({ action }) => action === "undecided").length;
  const localImportErrors = preview.filter(({ issues }) => issues.some(({ severity }) => severity === "error")).length;
  const serverRowsBySource = new Map(serverPreview?.rows.map((row) => [row.sourceRow, row]) ?? []);
  const copy = memberCopy[locale];
  const editNeedsVisibleReason = editMembershipStatus === "inactive" || editEligibilityStatus !== "eligible" || !editAvailable;

  if (query.isLoading) return <LoadingBlock locale={locale} label={copy.loadingRoster} />;
  if (!query.data) return <DataError locale={locale} title={copy.loadFailure} />;

  return <>
    <PageTitle
      eyebrow={copy.eyebrow}
      title={copy.title}
      description={copy.description}
      action={mayCreate ? <Dialog open={newMemberOpen} onOpenChange={(open) => {
        setNewMemberOpen(open);
        if (open) { createPayload.current = undefined; createIdempotency.current = idempotencyKey(); createMutation.reset(); }
      }}>
        <DialogTrigger asChild><Button><Plus /> {copy.newPerson}</Button></DialogTrigger>
        <DialogContent>
          <DialogHeader><DialogTitle>{copy.createPerson}</DialogTitle><DialogDescription>{copy.createDescription}</DialogDescription></DialogHeader>
          <form id="member-form" className="dialog-form" onSubmit={(event) => { event.preventDefault(); createMutation.mutate(); }}>
            <div className="field-stack"><Label htmlFor="member-name">{copy.fullName}</Label><Input id="member-name" value={displayName} onChange={(event) => { setDisplayName(event.target.value); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }} maxLength={160} autoComplete="off" required /></div>
            {mayManageContact && <div className="field-stack"><Label htmlFor="member-email">{copy.optionalEmail}</Label><Input id="member-email" value={email} onChange={(event) => { setEmail(event.target.value); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }} maxLength={254} type="email" autoComplete="off" /></div>}
            <label className="check-row"><Checkbox checked={eligible} onCheckedChange={(value) => { setEligible(value === true); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }} /><span><strong>{copy.eligibleRoster}</strong><small>{copy.eligibilityFrozen}</small></span></label>
            <section className="rounded-2xl border bg-slate-50 p-4">
              <strong>{message(locale, "members.operationalScope")}</strong>
              <p className="mb-3 text-sm text-slate-600">{message(locale, "members.scopeHelp")}</p>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="field-stack"><Label htmlFor="member-create-restriction-department">{copy.departmentRestriction}</Label><select id="member-create-restriction-department" value={createRestrictionDepartment} disabled={catalogQuery.isLoading || catalogQuery.isError} onChange={(event) => { setCreateRestrictionDepartment(event.target.value); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }}><option value="">{message(locale, "members.scopeAllDepartments")}</option>{eligibilityDepartments.filter(({ active }) => active).map((department) => <option key={department.id} value={department.id}>{localizedName(department.names, locale, department.canonicalCode)}</option>)}</select></div>
                <div className="field-stack"><Label htmlFor="member-create-restriction-until">{copy.restrictionUntil}</Label><Input id="member-create-restriction-until" type="date" value={createRestrictionUntil} onChange={(event) => { setCreateRestrictionUntil(event.target.value); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }} /><small>{message(locale, "members.validUntilHelp")}</small></div>
              </div>
            </section>
            {!eligible && <div className="field-stack"><Label htmlFor="member-visible-reason">{copy.visibleReason}</Label><Input id="member-visible-reason" value={visibleReason} onChange={(event) => { setVisibleReason(event.target.value); createPayload.current = undefined; createIdempotency.current = idempotencyKey(); }} minLength={4} maxLength={240} required /><small>{copy.visibleReasonHelp}</small></div>}
            {createMutation.error && <p className="form-error" role="alert">{visibleError(createMutation.error, locale, copy.saveFailure)}</p>}
          </form>
          <DialogFooter><Button variant="outline" onClick={() => setNewMemberOpen(false)}>{copy.cancel}</Button><Button form="member-form" type="submit" disabled={!displayName.trim() || (!eligible && visibleReason.trim().length < 4) || createMutation.isPending}>{createMutation.isPending && <LoaderCircle className="animate-spin" />} {copy.encryptAndSave}</Button></DialogFooter>
        </DialogContent>
      </Dialog> : undefined}
    />

    <div className="member-toolbar surface-card">
      <label className="search-field"><Search /><span className="sr-only">{copy.searchRoster}</span><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={mayReadContact ? copy.searchPlaceholder : message(locale, "screen.membersView.85487bb55681")} disabled={indexing || Boolean(decryptError)} /></label>
      {mayManage && <label className="field-stack min-w-40"><span className="sr-only">{copy.filter}</span><select aria-label={copy.filter} value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as MemberStatusFilter)}><option value="all">{copy.allStatus}</option><option value="active">{copy.activeOnly}</option><option value="archived">{copy.archivedOnly}</option></select></label>}
      {mayExport && <div className="toolbar-actions"><Button variant="outline" onClick={() => void exportMembers("csv")} disabled={!filtered.length || exporting}><Download /> CSV</Button><Button variant="outline" onClick={() => void exportMembers("xlsx")} disabled={!filtered.length || exporting}>{exporting ? <LoaderCircle className="animate-spin" /> : <FileSpreadsheet />} Excel</Button></div>}
    </div>

    {indexing && <Alert><Search /><AlertTitle>{copy.privateIndex}</AlertTitle><AlertDescription>{copy.privateIndexBody}</AlertDescription></Alert>}
    {decryptError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{copy.incompleteIndex}</AlertTitle><AlertDescription>{decryptError}</AlertDescription></Alert>}
    {exportError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{message(locale, "screen.membersView.61b0d17c9448")}</AlertTitle><AlertDescription>{exportError}</AlertDescription></Alert>}
    {memberNotice && <Alert><ShieldCheck /><AlertTitle>{memberNotice}</AlertTitle></Alert>}

    <div className={mayImport ? "members-layout" : "members-layout single"}>
      <section className="surface-card member-list-card">
        <div className="card-heading"><div><p className="eyebrow">{copy.authorizedDirectory}</p><h2>{indexing ? copy.indexing : `${new Intl.NumberFormat(locale).format(filtered.length)} ${copy.of} ${new Intl.NumberFormat(locale).format(query.data.total)} ${copy.people}`}</h2></div><Badge variant="outline"><ShieldCheck /> E2EE</Badge></div>
        {!indexing && !decryptError && (filtered.length ? <div className="member-list">{filtered.map((member) => <article key={member.id}>
          <span className="member-avatar">{initials(member.displayName)}</span>
          <div><strong>{member.displayName}</strong><small>{member.shortId}{mayReadContact && member.email ? ` · ${member.email}` : ""}</small>{member.profileMigrationRequired && <Badge variant="outline">{message(locale, "screen.membersView.bff05b32e92b")}</Badge>}{member.visibleReason && !member.eligible && <small>{member.visibleReason}</small>}
            {(member.departmentRestriction || member.validUntil) && <div className="mt-2 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700"><strong className="block">{message(locale, "members.operationalScope")}</strong>{member.departmentRestriction && <small className="mt-1 block">{copy.departmentRestriction}: {eligibilityDepartmentName(member.departmentRestriction)}</small>}{member.validUntil && <small className="block">{copy.restrictionUntil}: {member.validUntil}</small>}</div>}
            {mayReadPrivateNote && member.eligibilityReview && <details className="mt-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-950">
              <summary className="flex cursor-pointer items-center gap-2 font-semibold" aria-label={message(locale, "screen.membersView.a33e4106120b")}><LockKeyhole aria-hidden="true" size={15} />{message(locale, "screen.membersView.aaca187a7412")}</summary>
              {member.eligibilityReview.note && <span className="mt-2 block">{member.eligibilityReview.note}</span>}
              {member.eligibilityReview.departmentRestriction && <small className="mt-1 block">{copy.departmentRestriction}: {member.eligibilityReview.departmentRestriction}</small>}
              {member.eligibilityReview.validUntil && <small className="block">{copy.restrictionUntil}: {member.eligibilityReview.validUntil}</small>}
              {member.eligibilityReview.legacyVisibleReason && <small className="mt-1 block">{message(locale, "screen.membersView.b44c9d0a4538")}: {member.eligibilityReview.legacyVisibleReason}</small>}
              {!member.eligibilityReview.note && !member.eligibilityReview.departmentRestriction && !member.eligibilityReview.validUntil && !member.eligibilityReview.legacyVisibleReason && <small className="mt-2 block">{message(locale, "screen.membersView.20715979cefd")}</small>}
            </details>}
          </div>
          <span className="member-load"><strong>{member.currentResponsibilities}</strong><small>{copy.responsibilities}</small></span>
          <span className="member-actions" aria-label={copy.managementActions}>
            {member.archived ? <Badge variant="outline"><Archive /> {copy.archived}</Badge> : member.eligible ? <Badge className="eligible-badge"><CheckCircle2 /> {copy.eligible}</Badge> : <Badge variant="outline">{member.eligibilityStatus === "review" ? copy.underReview : copy.ineligible}</Badge>}
            <Button type="button" variant="outline" size="sm" aria-label={`${copy.photoOf} ${member.displayName}`} onClick={() => setPhotoMember(member)}><ImageIcon aria-hidden="true" /> {copy.photo}</Button>
            {mayReadQualifications && <Button type="button" variant="outline" size="sm" aria-label={`${message(locale, "qualification.open")}: ${member.displayName}`} onClick={() => setQualificationMember(member)}><ShieldCheck aria-hidden="true" /> {message(locale, "qualification.open")}</Button>}
            {mayManage && !member.archived && (!member.profileMigrationRequired || mayManageContact) && <Button type="button" variant="outline" size="sm" aria-label={`${copy.editPerson}: ${member.displayName}`} onClick={() => beginEdit(member)}><Pencil aria-hidden="true" /> {copy.editPerson}</Button>}
            {mayManage && <Button type="button" variant="ghost" size="sm" aria-label={`${member.archived ? copy.reactivatePerson : copy.archivePerson}: ${member.displayName}`} onClick={() => beginLifecycle(member, member.archived ? "reactivate" : "archive")}>{member.archived ? <RefreshCw aria-hidden="true" /> : <Archive aria-hidden="true" />}{member.archived ? copy.reactivatePerson : copy.archivePerson}</Button>}
          </span>
        </article>)}</div> : <EmptyState locale={locale} icon={Users} title={search ? copy.noMatches : copy.emptyRoster} />)}
      </section>

      <Dialog open={Boolean(editingMember)} onOpenChange={(open) => { if (!open) { setEditingMember(undefined); resetEditSubmission(); } }}>
        <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader><DialogTitle>{copy.editPerson}</DialogTitle><DialogDescription>{copy.editDescription}</DialogDescription></DialogHeader>
          {editingMember && <form id="member-edit-form" className="dialog-form" onSubmit={(event) => { event.preventDefault(); editMutation.mutate(); }}>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="field-stack"><Label htmlFor="member-edit-name">{copy.fullName}</Label><Input id="member-edit-name" value={editName} onChange={(event) => { setEditName(event.target.value); resetEditSubmission(); }} maxLength={160} required autoComplete="off" /></div>
              {mayManageContact && <div className="field-stack"><Label htmlFor="member-edit-email">{copy.optionalEmail}</Label><Input id="member-edit-email" value={editEmail} onChange={(event) => { setEditEmail(event.target.value); setEditContactChanged(true); resetEditSubmission(); }} maxLength={254} type="email" autoComplete="off" /></div>}
              <div className="field-stack"><Label htmlFor="member-edit-membership">{copy.membershipStatus}</Label><select id="member-edit-membership" value={editMembershipStatus} onChange={(event) => { setEditMembershipStatus(event.target.value as "active" | "inactive"); resetEditSubmission(); }}><option value="active">{copy.memberActive}</option><option value="inactive">{copy.memberInactive}</option></select></div>
              {mayManageEligibility && <div className="field-stack"><Label htmlFor="member-edit-eligibility">{copy.eligibilityStatus}</Label><select id="member-edit-eligibility" value={editEligibilityStatus} onChange={(event) => { setEditEligibilityStatus(event.target.value as "eligible" | "ineligible" | "review"); resetEditSubmission(); }}><option value="eligible">{copy.eligible}</option><option value="ineligible">{copy.ineligible}</option><option value="review">{copy.underReview}</option></select></div>}
            </div>
            {editingMember.profileMigrationRequired && <Alert><LockKeyhole /><AlertTitle>{message(locale, "screen.membersView.972036420f1a")}</AlertTitle><AlertDescription>{mayManageContact
              ? message(locale, "screen.membersView.d7ad47384d80")
              : message(locale, "screen.membersView.782552c4c609")}</AlertDescription>{mayManageContact && <label className="check-row mt-3"><Checkbox checked={resolveLegacyProfile} onCheckedChange={(value) => { setResolveLegacyProfile(value === true); resetEditSubmission(); }} /><span><strong>{message(locale, "screen.membersView.8459fa0451d4")}</strong></span></label>}</Alert>}
            {mayManageEligibility && <>
              <label className="check-row"><Checkbox checked={editAvailable} onCheckedChange={(value) => { setEditAvailable(value === true); resetEditSubmission(); }} disabled={editEligibilityStatus !== "eligible" || editMembershipStatus !== "active"} /><span><strong>{copy.availableForOffice}</strong><small>{copy.eligibilityFrozen}</small></span></label>
              <div className="field-stack"><Label htmlFor="member-edit-visible-reason">{copy.visibleReason}</Label><Input id="member-edit-visible-reason" value={editVisibleReason} onChange={(event) => { setEditVisibleReason(event.target.value); resetEditSubmission(); }} minLength={editNeedsVisibleReason ? 4 : undefined} maxLength={240} required={editNeedsVisibleReason} /><small>{copy.visibleReasonHelp}</small></div>
              <section className="rounded-2xl border bg-slate-50 p-4">
                <strong>{message(locale, "members.operationalScope")}</strong>
                <p className="mb-3 text-sm text-slate-600">{message(locale, "members.scopeHelp")}</p>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="field-stack"><Label htmlFor="member-restriction-department">{copy.departmentRestriction}</Label><select id="member-restriction-department" value={restrictionDepartment} disabled={catalogQuery.isLoading || catalogQuery.isError} onChange={(event) => { setRestrictionDepartment(event.target.value); resetEditSubmission(); }}><option value="">{message(locale, "members.scopeAllDepartments")}</option>{restrictionDepartment && !eligibilityDepartments.some(({ id }) => id === restrictionDepartment) && <option value={restrictionDepartment}>{restrictionDepartment}</option>}{eligibilityDepartments.map((department) => <option key={department.id} value={department.id} disabled={!department.active}>{localizedName(department.names, locale, department.canonicalCode)}</option>)}</select></div>
                  <div className="field-stack"><Label htmlFor="member-restriction-until">{copy.restrictionUntil}</Label><Input id="member-restriction-until" type="date" value={restrictionUntil} onChange={(event) => { setRestrictionUntil(event.target.value); resetEditSubmission(); }} /><small>{message(locale, "members.validUntilHelp")}</small></div>
                </div>
              </section>
              <section className="rounded-2xl border bg-slate-50 p-4">
                <div className="mb-3 flex items-start gap-3"><LockKeyhole aria-hidden="true" /><div><strong>{copy.privateReview}</strong><p className="text-sm text-slate-600">{mayReadPrivateNote ? message(locale, "screen.membersView.8841fe67afe6") : copy.privateReviewHelp}</p></div></div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="field-stack sm:col-span-2"><Label htmlFor="member-private-note">{copy.privateNote}</Label><Input id="member-private-note" value={privateNote} disabled={clearPrivateReview} onChange={(event) => { setPrivateNote(event.target.value); setPrivateReviewChanged(true); setClearPrivateReview(false); resetEditSubmission(); }} maxLength={500} autoComplete="off" /></div>
                </div>
                <label className="check-row mt-3"><Checkbox checked={clearPrivateReview} onCheckedChange={(value) => { const checked = value === true; setClearPrivateReview(checked); setPrivateReviewChanged(true); if (checked) setPrivateNote(""); resetEditSubmission(); }} /><span><strong>{copy.clearPrivateReview}</strong></span></label>
              </section>
            </>}
            {editMutation.error && <p className="form-error" role="alert">{visibleError(editMutation.error, locale, copy.editFailure)}</p>}
          </form>}
          <DialogFooter><Button type="button" variant="outline" onClick={() => setEditingMember(undefined)}>{copy.cancel}</Button><Button form="member-edit-form" type="submit" disabled={!editName.trim() || Boolean(editingMember?.profileMigrationRequired && !resolveLegacyProfile) || (mayManageEligibility && editNeedsVisibleReason && editVisibleReason.trim().length < 4) || editMutation.isPending}>{editMutation.isPending && <LoaderCircle className="animate-spin" />}{copy.saveChanges}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(lifecycle)} onOpenChange={(open) => { if (!open) { setLifecycle(undefined); setLifecycleReasonCode(""); lifecycleIdempotency.current = idempotencyKey(); } }}>
        <DialogContent>
          <DialogHeader><DialogTitle>{lifecycle?.action === "reactivate" ? copy.reactivatePerson : copy.archivePerson}</DialogTitle><DialogDescription>{lifecycle?.action === "reactivate" ? copy.reactivateHelp : copy.archiveHelp}</DialogDescription></DialogHeader>
          <form id="member-lifecycle-form" className="dialog-form" onSubmit={(event) => { event.preventDefault(); lifecycleMutation.mutate(); }}>
            <div className="field-stack"><Label htmlFor="member-lifecycle-reason">{message(locale, "screen.membersView.523b0405721e")}</Label><select id="member-lifecycle-reason" value={lifecycleReasonCode} onChange={(event) => { setLifecycleReasonCode(event.target.value); lifecycleIdempotency.current = idempotencyKey(); lifecycleMutation.reset(); }} required><option value="">{message(locale, "screen.membersView.30360a3bdaf2")}</option>{(lifecycle ? memberLifecycleReasonCodes[lifecycle.action] : []).map((reasonCode) => <option key={reasonCode} value={reasonCode}>{memberLifecycleReasonLabel(locale, reasonCode)}</option>)}</select></div>
            {lifecycleMutation.error && <p className="form-error" role="alert">{visibleError(lifecycleMutation.error, locale, copy.lifecycleFailure)}</p>}
          </form>
          <DialogFooter><Button type="button" variant="outline" onClick={() => setLifecycle(undefined)}>{copy.cancel}</Button><Button form="member-lifecycle-form" type="submit" disabled={!lifecycleReasonCode || lifecycleMutation.isPending}>{lifecycleMutation.isPending && <LoaderCircle className="animate-spin" />}{lifecycle?.action === "reactivate" ? copy.confirmReactivate : copy.confirmArchive}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(photoMember)} onOpenChange={(open) => { if (!open) setPhotoMember(undefined); }}>
        <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{photoMember ? `${copy.photographOf} ${photoMember.displayName}` : copy.photograph}</DialogTitle>
            <DialogDescription>{copy.photographDescription}</DialogDescription>
          </DialogHeader>
          {photoMember ? <MemberPhotoEditor locale={locale} session={session} memberId={photoMember.id} displayName={photoMember.displayName} /> : null}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(qualificationMember)} onOpenChange={(open) => { if (!open) setQualificationMember(undefined); }}>
        <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{message(locale, "qualification.title")}</DialogTitle>
            <DialogDescription>{message(locale, "qualification.independent.body")}</DialogDescription>
          </DialogHeader>
          {qualificationMember ? <MemberQualifications locale={locale} session={session} memberId={qualificationMember.id} displayName={qualificationMember.displayName} /> : null}
        </DialogContent>
      </Dialog>

      {mayImport && <aside className="surface-card import-card">
        <span className="metric-icon indigo"><Upload /></span>
        <p className="eyebrow">{copy.controlledImport}</p>
        <h2>Excel / CSV</h2>
        <p>{copy.importIntro}</p>
        <Dialog open={importOpen} onOpenChange={setImportOpen}>
          <DialogTrigger asChild><Button variant="outline" className="w-full"><FileSpreadsheet /> {copy.prepareImport}</Button></DialogTrigger>
          <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-6xl">
            <DialogHeader>
              <DialogTitle>{copy.importTitle}</DialogTitle>
              <DialogDescription>{copy.importLimits}</DialogDescription>
            </DialogHeader>

            <div className="import-workflow">
              <section className="import-step">
                <div><p className="eyebrow">{copy.fileStep}</p><h3>XLSX / CSV UTF-8</h3></div>
                <input ref={fileInput} className="sr-only" id="member-import" type="file" accept=".xlsx,.csv,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" onChange={(event) => void inspectFile(event.target.files?.[0])} />
                <Button type="button" variant="outline" onClick={() => fileInput.current?.click()}><FileSpreadsheet /> {importName ? copy.changeFile : copy.selectFile}</Button>
                {importName && <Badge variant="outline">{importName}</Badge>}
              </section>

              {selectedImportSheet && <section className="import-step">
                <div><p className="eyebrow">{copy.mappingStep}</p><h3>{copy.explicitMapping}</h3></div>
                <div className="import-mapping-grid">
                  <div className="field-stack">
                    <Label htmlFor="import-sheet">{copy.sheet}</Label>
                    <select id="import-sheet" value={selectedSheetName} onChange={(event) => changeSheet(event.target.value)}>
                      {importSheets.map((sheet) => <option key={sheet.name} value={sheet.name}>{sheet.name} · {sheet.rowCount.toLocaleString(locale)} {copy.rows}</option>)}
                    </select>
                  </div>
                  {IMPORT_FIELDS.filter((field) => field !== "email" || mayManageContact).map((field) => <div className="field-stack" key={field}>
                    <Label htmlFor={`import-map-${field}`}>{importFieldLabels[locale][field]}</Label>
                    <select id={`import-map-${field}`} value={columnMapping[field] ?? ""} onChange={(event) => changeMapping(field, event.target.value)}>
                      <option value="">{copy.doNotImport}</option>
                      {importHeaders.map((header, index) => <option value={index} key={`${index}-${header}`}>{index + 1}. {header || copy.noHeader}</option>)}
                    </select>
                  </div>)}
                </div>
                <Button type="button" onClick={() => void analyzeSelectedSheet()} disabled={!mappingHasName(columnMapping) || analyzingImport || indexing || Boolean(decryptError)}>
                  {analyzingImport ? <LoaderCircle className="animate-spin" /> : <Search />} {copy.validatePreview}
                </Button>
              </section>}

              {importError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{copy.cannotContinue}</AlertTitle><AlertDescription>{importError}</AlertDescription></Alert>}

              {preview.length > 0 && <section className="import-step">
                <div className="import-review-heading"><div><p className="eyebrow">{copy.reviewStep}</p><h3>{preview.length} {copy.rows} · {localImportErrors} {copy.withError} · {undecidedImportRows} {copy.undecided}</h3></div><Button type="button" variant="outline" onClick={applyImportSuggestions}>{copy.applySuggestions}</Button></div>
                <p className="import-privacy-note"><ShieldCheck /> {copy.privacyNote}</p>
                <div className="responsive-table import-review-table" tabIndex={0} aria-label={copy.previewLabel}>
                  <table>
                    <thead><tr><th>{copy.row}</th><th>{copy.person}</th><th>{copy.validation}</th><th>{copy.decision}</th><th>{copy.target}</th></tr></thead>
                    <tbody>{visibleImportRows.map((row) => {
                      const hasError = row.issues.some(({ severity }) => severity === "error");
                      const stableIdMatch = row.candidates.some(({ basis }) => basis === "stable_id");
                      const serverRow = serverRowsBySource.get(row.sourceRow);
                      return <tr key={row.sourceRow}>
                        <td>{row.sourceRow}</td>
                        <td><strong>{row.displayName || copy.unnamed}</strong><small>{row.sourceId ?? copy.noId}{mayManageContact && row.email ? ` · ${row.email}` : ""}</small></td>
                        <td><div className="import-issues">{row.issues.length === 0 && !serverRow?.codes.length ? <Badge variant="outline">{copy.ready}</Badge> : <>{row.issues.map((issue) => <Badge variant="outline" key={issue.code}>{issueLabels[locale][issue.code] ?? issue.code}</Badge>)}{serverRow?.codes.map((code) => <Badge variant="outline" key={code}>{issueLabels[locale][code] ?? code}</Badge>)}</>}</div></td>
                        <td><select aria-label={`${copy.decisionRow} ${row.sourceRow}`} value={row.action} onChange={(event) => decideImportRow(row.sourceRow, event.target.value as ImportAction)}>
                          <option value="undecided">{copy.decide}</option>
                          {!hasError && !stableIdMatch && <option value="create">{copy.createSeparate}</option>}
                          {!hasError && row.candidates.length > 0 && <option value="update">{copy.update}</option>}
                          <option value="skip">{copy.skip}</option>
                        </select></td>
                        <td>{row.action === "update" ? <select aria-label={`${copy.targetRow} ${row.sourceRow}`} value={row.targetId ?? ""} onChange={(event) => decideImportRow(row.sourceRow, "update", event.target.value)}><option value="">{copy.select}</option>{row.candidates.map((candidate) => <option value={candidate.id} key={candidate.id}>{candidate.displayName} · {candidate.shortId}</option>)}</select> : row.action === "create" ? <span>{copy.newTarget}</span> : row.action === "skip" ? <span>{copy.noContent}</span> : <span>—</span>}</td>
                      </tr>;
                    })}</tbody>
                  </table>
                </div>
                {importPageCount > 1 && <div className="import-pagination"><Button type="button" variant="outline" disabled={importPage === 0} onClick={() => setImportPage((page) => page - 1)}>{copy.previous}</Button><span>{copy.page} {importPage + 1} {copy.of} {importPageCount}</span><Button type="button" variant="outline" disabled={importPage + 1 >= importPageCount} onClick={() => setImportPage((page) => page + 1)}>{copy.next}</Button></div>}
              </section>}

              {serverPreview && <Alert variant={(serverPreview.counts?.errors ?? 0) > 0 ? "destructive" : "default"}><ShieldCheck /><AlertTitle>{(serverPreview.counts?.errors ?? 0) > 0 ? copy.serverConflicts : copy.persistedPreview}</AlertTitle><AlertDescription>{serverPreview.counts ? `${serverPreview.counts.create} ${copy.createVerb}, ${serverPreview.counts.update} ${copy.updateVerb}, ${serverPreview.counts.skip} ${copy.skipVerb}.` : copy.replayedPreview}</AlertDescription></Alert>}
              {stageImportMutation.error && <p className="form-error" role="alert">{visibleError(stageImportMutation.error, locale, copy.stageFailure)}</p>}
              {commitImportMutation.error && <p className="form-error" role="alert">{visibleError(commitImportMutation.error, locale, copy.commitFailure)}</p>}
            </div>

            <DialogFooter className="import-actions">
              {(preview.some((row) => row.issues.length > 0 || row.action === "skip") || (serverPreview?.counts?.errors ?? 0) > 0) && <Button type="button" variant="outline" onClick={downloadImportErrors}><Download /> {copy.downloadIssues}</Button>}
              <Button type="button" variant="outline" onClick={() => setImportOpen(false)}>{copy.close}</Button>
              <Button type="button" disabled={!preview.length || undecidedImportRows > 0 || stageImportMutation.isPending || Boolean(serverPreview)} onClick={() => stageImportMutation.mutate()}>{stageImportMutation.isPending ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />} {copy.encryptValidate}</Button>
              {serverPreview?.state === "previewed" && (serverPreview.counts?.errors ?? 0) === 0 && <Button type="button" disabled={commitImportMutation.isPending} onClick={() => commitImportMutation.mutate()}>{commitImportMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Upload />} {copy.confirmImport}</Button>}
            </DialogFooter>
          </DialogContent>
        </Dialog>
        {importResult && <Alert><CheckCircle2 /><AlertTitle>{copy.importConfirmed}</AlertTitle><AlertDescription>{importResult.created} {copy.created}, {importResult.updated} {copy.updated} {message(locale, "screen.membersView.16a6dfaadfac")} {importResult.skipped} {copy.skipped}{importResult.replayed ? copy.retryRecognized : ""}.</AlertDescription></Alert>}
        <Button type="button" variant="ghost" className="template-link w-full" disabled={templateExporting} onClick={() => void downloadXlsxTemplate()}>{templateExporting ? <LoaderCircle className="animate-spin" /> : <FileSpreadsheet />}{copy.downloadTemplate} (.xlsx)</Button>
        {mayManageContact && <a className="template-link" href="/plantilla-padron.csv" download>{copy.downloadTemplate} (CSV)</a>}
      </aside>}
    </div>
  </>;
}

function restrictContactMapping(mapping: ImportColumnMapping, mayManageContact: boolean): ImportColumnMapping {
  if (mayManageContact) return mapping;
  const displayOnly = { ...mapping };
  delete displayOnly.email;
  return displayOnly;
}
