"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BookOpen, Building2, ExternalLink, FileCheck2, Languages, Layers3, Link2, LoaderCircle, Pencil, Plus, Save, Search, Settings2, ShieldCheck } from "lucide-react";
import { localeMetadata, supportedLocales } from "@nombramientos/i18n";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { apiRequest, idempotencyKey, type AuthenticatedSession, type Locale } from "@/lib/api";
import { readCatalogRichMetadata, type CatalogReviewStatus, type CatalogRichMetadata, type CatalogSourceReference } from "@/lib/catalog-metadata";
import { message, localizedApiError, localizedName } from "@/lib/product-i18n";
import { DataError, EmptyState, LoadingBlock, PageTitle } from "./workspace-view";

type Names = Record<Locale, string>;
type RichFields = Record<string, unknown>;
type Department = RichFields & { id: string; canonicalCode: string; names: Names; parentId: string | null; localExtension: boolean; active: boolean; sortOrder: number; version: number };
type Office = RichFields & { id: string; departmentId: string; canonicalCode: string; names: Names; appointmentMechanism: string; cardinality: number; localExtension: boolean; active: boolean; version: number };
type Catalog = { departments: Department[]; offices: Office[]; normativeVersion: string };
type TenantSettings = { tenantId: string; displayName: string; kind: "demo" | "real"; timezone: string; locale: Locale; jurisdiction: string; setupState: string; catalogVersion: string; version: number; updatedAt: string };
type ItemKind = "department" | "office";
type EditableItem = { kind: ItemKind; item: Department | Office };

const mechanisms = [
  "church_election_after_nominating_report", "church_election", "board_appointment",
  "council_recommendation_board_approval", "conference_appointment", "ex_officio",
  "linked_designation", "local_configuration_pending",
] as const;

const copy = {
  es: {
    eyebrow: message("es", "screen.catalogView.0d541acf7acd"), title: message("es", "screen.catalogView.f2816ff69bab"), description: message("es", "screen.catalogView.acf89c1f2986"),
    departments: message("es", "screen.catalogView.75498c341ba4"), offices: message("es", "screen.catalogView.ea184c535d5d"), emptyDepartments: message("es", "screen.catalogView.e7b91b0ce547"), emptyOffices: message("es", "screen.catalogView.032003eb5b38"), canonical: message("es", "screen.catalogView.ca6695050194"), local: message("es", "screen.catalogView.20b9c57fa29b"), active: message("es", "screen.catalogView.901bb448bee7"), inactive: message("es", "screen.catalogView.5bdf59165f23"), edit: message("es", "screen.catalogView.b38c34b81dc9"), deactivate: message("es", "screen.catalogView.2eb4051136d1"), reactivate: message("es", "screen.catalogView.39202ffa37b7"), add: message("es", "screen.catalogView.12f55049ea27"), create: message("es", "screen.catalogView.08e593985e60"), editTitle: message("es", "screen.catalogView.561818cf04ee"), immutable: message("es", "screen.catalogView.67fb5348b1a8"),
    type: message("es", "screen.catalogView.1656c049b119"), department: message("es", "screen.catalogView.a9c1f5f4089f"), office: message("es", "screen.catalogView.d873162dbc91"), code: message("es", "screen.catalogView.5ce27f5eeda1"), codeHelp: message("es", "screen.catalogView.38a5d0e9f206"), spanish: message("es", "screen.catalogView.895245c9d2cd"), english: message("es", "screen.catalogView.f1287c2717c2"), french: message("es", "screen.catalogView.ceee417eb047"), parent: message("es", "screen.catalogView.245ca087ee6c"), none: message("es", "screen.catalogView.e5e9a83a568f"), order: message("es", "screen.catalogView.e0185aa59b56"), mechanism: message("es", "screen.catalogView.8c94d295da6e"), cardinality: message("es", "screen.catalogView.ad786e8e6544"), cancel: message("es", "screen.catalogView.18e29ea869c8"), save: message("es", "screen.catalogView.21dc7d44ff3c"), settings: message("es", "screen.catalogView.3b4c330201cf"), settingsBody: message("es", "screen.catalogView.b466f683df2f"), displayName: message("es", "screen.catalogView.19c1f3652481"), timezone: message("es", "screen.catalogView.3a950d148d4d"), locale: message("es", "screen.catalogView.eb4b82e9035f"), jurisdiction: message("es", "screen.catalogView.b5fadcae64be"), saveSettings: message("es", "screen.catalogView.a92141e69c18"), saved: message("es", "screen.catalogView.0e694f3ae522"), failure: message("es", "screen.catalogView.9afc881042fc"), loading: message("es", "screen.catalogView.7b16b571fe9b"), loadFailure: message("es", "screen.catalogView.2c0734c652ea"), management: message("es", "screen.catalogView.b6c05a112c16"), readOnly: message("es", "screen.catalogView.667f74ab967b"),
    search: message("es", "screen.catalogView.4a1a6d4df33d"), searchPlaceholder: message("es", "screen.catalogView.ef078697e7fa"), visibleResults: message("es", "screen.catalogView.6043b0bf0991"), noMatches: message("es", "screen.catalogView.c453c2f7c181"), normativePackage: message("es", "screen.catalogView.5c611ae21343"), records: message("es", "screen.catalogView.3ba030d95d42"), reviewed: message("es", "screen.catalogView.aae82de4abb0"), workingTranslation: message("es", "screen.catalogView.5ac67daa0cb8"), details: message("es", "screen.catalogView.943b46852e69"), hideDetails: message("es", "screen.catalogView.7ecbfdbe2556"), purpose: message("es", "screen.catalogView.d9c3965cb310"), responsibilities: message("es", "screen.catalogView.e71a1bf62a6c"), conditions: message("es", "screen.catalogView.3c9452796fa5"), provenance: message("es", "screen.catalogView.0a8f53c3dc5f"), traceability: message("es", "screen.catalogView.05de5f713bb1"), notes: message("es", "screen.catalogView.0123a165bfbf"), aliases: message("es", "screen.catalogView.b7e89e0b5d67"), sourceRules: message("es", "screen.catalogView.afc87ce9609f"), sourceDocument: message("es", "screen.catalogView.98dac21e8389"), opensNewWindow: message("es", "screen.catalogView.f86c2a6bc8c1"), pages: message("es", "screen.catalogView.a433e55bc075"), sourceLanguage: message("es", "screen.catalogView.07de30d3cbdd"), reviewStatus: message("es", "screen.catalogView.971c6ed5eeb1"), catalogVersion: message("es", "screen.catalogView.8da5b42aec64"), territory: message("es", "screen.catalogView.2f0df9f0aa4e"), reportsTo: message("es", "screen.catalogView.980b5cde0090"), linkedTo: message("es", "screen.catalogView.4b5d69d7128f"), applicableByDefault: message("es", "screen.catalogView.88a2d5c6972e"), optionalByDefault: message("es", "screen.catalogView.992fb1bd15de"), noRichMetadata: message("es", "screen.catalogView.e24c66edb113"), positions: message("es", "screen.catalogView.8dfce6b7fbdf"),
  },
  en: {
    eyebrow: message("en", "screen.catalogView.0d541acf7acd"), title: message("en", "screen.catalogView.f2816ff69bab"), description: message("en", "screen.catalogView.acf89c1f2986"),
    departments: message("en", "screen.catalogView.75498c341ba4"), offices: message("en", "screen.catalogView.ea184c535d5d"), emptyDepartments: message("en", "screen.catalogView.e7b91b0ce547"), emptyOffices: message("en", "screen.catalogView.032003eb5b38"), canonical: message("en", "screen.catalogView.ca6695050194"), local: message("en", "screen.catalogView.20b9c57fa29b"), active: message("en", "screen.catalogView.901bb448bee7"), inactive: message("en", "screen.catalogView.5bdf59165f23"), edit: message("en", "screen.catalogView.b38c34b81dc9"), deactivate: message("en", "screen.catalogView.2eb4051136d1"), reactivate: message("en", "screen.catalogView.39202ffa37b7"), add: message("en", "screen.catalogView.12f55049ea27"), create: message("en", "screen.catalogView.08e593985e60"), editTitle: message("en", "screen.catalogView.561818cf04ee"), immutable: message("en", "screen.catalogView.67fb5348b1a8"),
    type: message("en", "screen.catalogView.1656c049b119"), department: message("en", "screen.catalogView.a9c1f5f4089f"), office: message("en", "screen.catalogView.d873162dbc91"), code: message("en", "screen.catalogView.5ce27f5eeda1"), codeHelp: message("en", "screen.catalogView.38a5d0e9f206"), spanish: message("en", "screen.catalogView.895245c9d2cd"), english: message("en", "screen.catalogView.f1287c2717c2"), french: message("en", "screen.catalogView.ceee417eb047"), parent: message("en", "screen.catalogView.245ca087ee6c"), none: message("en", "screen.catalogView.e5e9a83a568f"), order: message("en", "screen.catalogView.e0185aa59b56"), mechanism: message("en", "screen.catalogView.8c94d295da6e"), cardinality: message("en", "screen.catalogView.ad786e8e6544"), cancel: message("en", "screen.catalogView.18e29ea869c8"), save: message("en", "screen.catalogView.21dc7d44ff3c"), settings: message("en", "screen.catalogView.3b4c330201cf"), settingsBody: message("en", "screen.catalogView.b466f683df2f"), displayName: message("en", "screen.catalogView.19c1f3652481"), timezone: message("en", "screen.catalogView.3a950d148d4d"), locale: message("en", "screen.catalogView.eb4b82e9035f"), jurisdiction: message("en", "screen.catalogView.b5fadcae64be"), saveSettings: message("en", "screen.catalogView.a92141e69c18"), saved: message("en", "screen.catalogView.0e694f3ae522"), failure: message("en", "screen.catalogView.9afc881042fc"), loading: message("en", "screen.catalogView.7b16b571fe9b"), loadFailure: message("en", "screen.catalogView.2c0734c652ea"), management: message("en", "screen.catalogView.b6c05a112c16"), readOnly: message("en", "screen.catalogView.667f74ab967b"),
    search: message("en", "screen.catalogView.4a1a6d4df33d"), searchPlaceholder: message("en", "screen.catalogView.ef078697e7fa"), visibleResults: message("en", "screen.catalogView.6043b0bf0991"), noMatches: message("en", "screen.catalogView.c453c2f7c181"), normativePackage: message("en", "screen.catalogView.5c611ae21343"), records: message("en", "screen.catalogView.3ba030d95d42"), reviewed: message("en", "screen.catalogView.aae82de4abb0"), workingTranslation: message("en", "screen.catalogView.5ac67daa0cb8"), details: message("en", "screen.catalogView.943b46852e69"), hideDetails: message("en", "screen.catalogView.7ecbfdbe2556"), purpose: message("en", "screen.catalogView.d9c3965cb310"), responsibilities: message("en", "screen.catalogView.e71a1bf62a6c"), conditions: message("en", "screen.catalogView.3c9452796fa5"), provenance: message("en", "screen.catalogView.0a8f53c3dc5f"), traceability: message("en", "screen.catalogView.05de5f713bb1"), notes: message("en", "screen.catalogView.0123a165bfbf"), aliases: message("en", "screen.catalogView.b7e89e0b5d67"), sourceRules: message("en", "screen.catalogView.afc87ce9609f"), sourceDocument: message("en", "screen.catalogView.98dac21e8389"), opensNewWindow: message("en", "screen.catalogView.f86c2a6bc8c1"), pages: message("en", "screen.catalogView.a433e55bc075"), sourceLanguage: message("en", "screen.catalogView.07de30d3cbdd"), reviewStatus: message("en", "screen.catalogView.971c6ed5eeb1"), catalogVersion: message("en", "screen.catalogView.8da5b42aec64"), territory: message("en", "screen.catalogView.2f0df9f0aa4e"), reportsTo: message("en", "screen.catalogView.980b5cde0090"), linkedTo: message("en", "screen.catalogView.4b5d69d7128f"), applicableByDefault: message("en", "screen.catalogView.88a2d5c6972e"), optionalByDefault: message("en", "screen.catalogView.992fb1bd15de"), noRichMetadata: message("en", "screen.catalogView.e24c66edb113"), positions: message("en", "screen.catalogView.8dfce6b7fbdf"),
  },
  fr: {
    eyebrow: message("fr", "screen.catalogView.0d541acf7acd"), title: message("fr", "screen.catalogView.f2816ff69bab"), description: message("fr", "screen.catalogView.acf89c1f2986"),
    departments: message("fr", "screen.catalogView.75498c341ba4"), offices: message("fr", "screen.catalogView.ea184c535d5d"), emptyDepartments: message("fr", "screen.catalogView.e7b91b0ce547"), emptyOffices: message("fr", "screen.catalogView.032003eb5b38"), canonical: message("fr", "screen.catalogView.ca6695050194"), local: message("fr", "screen.catalogView.20b9c57fa29b"), active: message("fr", "screen.catalogView.901bb448bee7"), inactive: message("fr", "screen.catalogView.5bdf59165f23"), edit: message("fr", "screen.catalogView.b38c34b81dc9"), deactivate: message("fr", "screen.catalogView.2eb4051136d1"), reactivate: message("fr", "screen.catalogView.39202ffa37b7"), add: message("fr", "screen.catalogView.12f55049ea27"), create: message("fr", "screen.catalogView.08e593985e60"), editTitle: message("fr", "screen.catalogView.561818cf04ee"), immutable: message("fr", "screen.catalogView.67fb5348b1a8"),
    type: message("fr", "screen.catalogView.1656c049b119"), department: message("fr", "screen.catalogView.a9c1f5f4089f"), office: message("fr", "screen.catalogView.d873162dbc91"), code: message("fr", "screen.catalogView.5ce27f5eeda1"), codeHelp: message("fr", "screen.catalogView.38a5d0e9f206"), spanish: message("fr", "screen.catalogView.895245c9d2cd"), english: message("fr", "screen.catalogView.f1287c2717c2"), french: message("fr", "screen.catalogView.ceee417eb047"), parent: message("fr", "screen.catalogView.245ca087ee6c"), none: message("fr", "screen.catalogView.e5e9a83a568f"), order: message("fr", "screen.catalogView.e0185aa59b56"), mechanism: message("fr", "screen.catalogView.8c94d295da6e"), cardinality: message("fr", "screen.catalogView.ad786e8e6544"), cancel: message("fr", "screen.catalogView.18e29ea869c8"), save: message("fr", "screen.catalogView.21dc7d44ff3c"), settings: message("fr", "screen.catalogView.3b4c330201cf"), settingsBody: message("fr", "screen.catalogView.b466f683df2f"), displayName: message("fr", "screen.catalogView.19c1f3652481"), timezone: message("fr", "screen.catalogView.3a950d148d4d"), locale: message("fr", "screen.catalogView.eb4b82e9035f"), jurisdiction: message("fr", "screen.catalogView.b5fadcae64be"), saveSettings: message("fr", "screen.catalogView.a92141e69c18"), saved: message("fr", "screen.catalogView.0e694f3ae522"), failure: message("fr", "screen.catalogView.9afc881042fc"), loading: message("fr", "screen.catalogView.7b16b571fe9b"), loadFailure: message("fr", "screen.catalogView.2c0734c652ea"), management: message("fr", "screen.catalogView.b6c05a112c16"), readOnly: message("fr", "screen.catalogView.667f74ab967b"),
    search: message("fr", "screen.catalogView.4a1a6d4df33d"), searchPlaceholder: message("fr", "screen.catalogView.ef078697e7fa"), visibleResults: message("fr", "screen.catalogView.6043b0bf0991"), noMatches: message("fr", "screen.catalogView.c453c2f7c181"), normativePackage: message("fr", "screen.catalogView.5c611ae21343"), records: message("fr", "screen.catalogView.3ba030d95d42"), reviewed: message("fr", "screen.catalogView.aae82de4abb0"), workingTranslation: message("fr", "screen.catalogView.5ac67daa0cb8"), details: message("fr", "screen.catalogView.943b46852e69"), hideDetails: message("fr", "screen.catalogView.7ecbfdbe2556"), purpose: message("fr", "screen.catalogView.d9c3965cb310"), responsibilities: message("fr", "screen.catalogView.e71a1bf62a6c"), conditions: message("fr", "screen.catalogView.3c9452796fa5"), provenance: message("fr", "screen.catalogView.0a8f53c3dc5f"), traceability: message("fr", "screen.catalogView.05de5f713bb1"), notes: message("fr", "screen.catalogView.0123a165bfbf"), aliases: message("fr", "screen.catalogView.b7e89e0b5d67"), sourceRules: message("fr", "screen.catalogView.afc87ce9609f"), sourceDocument: message("fr", "screen.catalogView.98dac21e8389"), opensNewWindow: message("fr", "screen.catalogView.f86c2a6bc8c1"), pages: message("fr", "screen.catalogView.a433e55bc075"), sourceLanguage: message("fr", "screen.catalogView.07de30d3cbdd"), reviewStatus: message("fr", "screen.catalogView.971c6ed5eeb1"), catalogVersion: message("fr", "screen.catalogView.8da5b42aec64"), territory: message("fr", "screen.catalogView.2f0df9f0aa4e"), reportsTo: message("fr", "screen.catalogView.980b5cde0090"), linkedTo: message("fr", "screen.catalogView.4b5d69d7128f"), applicableByDefault: message("fr", "screen.catalogView.88a2d5c6972e"), optionalByDefault: message("fr", "screen.catalogView.992fb1bd15de"), noRichMetadata: message("fr", "screen.catalogView.e24c66edb113"), positions: message("fr", "screen.catalogView.8dfce6b7fbdf"),
  },
} as const;

const mechanismLabels: Record<Locale, Record<(typeof mechanisms)[number], string>> = {
  es: { church_election_after_nominating_report: message("es", "screen.catalogView.ebd0dfaa4e8b"), church_election: message("es", "screen.catalogView.b32a73c105cc"), board_appointment: message("es", "screen.catalogView.9dbce2bbc3c5"), council_recommendation_board_approval: message("es", "screen.catalogView.b4edd6f4cffd"), conference_appointment: message("es", "screen.catalogView.9f767885d5e6"), ex_officio: message("es", "screen.catalogView.f9d330a2d4b1"), linked_designation: message("es", "screen.catalogView.83b7e62ad83f"), local_configuration_pending: message("es", "screen.catalogView.6c8a85b5d8fb") },
  en: { church_election_after_nominating_report: message("en", "screen.catalogView.ebd0dfaa4e8b"), church_election: message("en", "screen.catalogView.b32a73c105cc"), board_appointment: message("en", "screen.catalogView.9dbce2bbc3c5"), council_recommendation_board_approval: message("en", "screen.catalogView.b4edd6f4cffd"), conference_appointment: message("en", "screen.catalogView.9f767885d5e6"), ex_officio: message("en", "screen.catalogView.f9d330a2d4b1"), linked_designation: message("en", "screen.catalogView.83b7e62ad83f"), local_configuration_pending: message("en", "screen.catalogView.6c8a85b5d8fb") },
  fr: { church_election_after_nominating_report: message("fr", "screen.catalogView.ebd0dfaa4e8b"), church_election: message("fr", "screen.catalogView.b32a73c105cc"), board_appointment: message("fr", "screen.catalogView.9dbce2bbc3c5"), council_recommendation_board_approval: message("fr", "screen.catalogView.b4edd6f4cffd"), conference_appointment: message("fr", "screen.catalogView.9f767885d5e6"), ex_officio: message("fr", "screen.catalogView.f9d330a2d4b1"), linked_designation: message("fr", "screen.catalogView.83b7e62ad83f"), local_configuration_pending: message("fr", "screen.catalogView.6c8a85b5d8fb") },
};

const reviewStatusLabels: Record<Locale, Record<CatalogReviewStatus, string>> = {
  es: { verified_primary_source: message("es", "screen.catalogView.5ad25c675b90"), verified_official_supporting_source: message("es", "screen.catalogView.7a5409997673"), pending_primary_source_validation: message("es", "screen.catalogView.ba5890296594"), pending_regional_validation: message("es", "screen.catalogView.5012f8397b26"), pending_local_approval: message("es", "screen.catalogView.fa8e21cffb46") },
  en: { verified_primary_source: message("en", "screen.catalogView.5ad25c675b90"), verified_official_supporting_source: message("en", "screen.catalogView.7a5409997673"), pending_primary_source_validation: message("en", "screen.catalogView.ba5890296594"), pending_regional_validation: message("en", "screen.catalogView.5012f8397b26"), pending_local_approval: message("en", "screen.catalogView.fa8e21cffb46") },
  fr: { verified_primary_source: message("fr", "screen.catalogView.5ad25c675b90"), verified_official_supporting_source: message("fr", "screen.catalogView.7a5409997673"), pending_primary_source_validation: message("fr", "screen.catalogView.ba5890296594"), pending_regional_validation: message("fr", "screen.catalogView.5012f8397b26"), pending_local_approval: message("fr", "screen.catalogView.fa8e21cffb46") },
};

function newNames(): Names { return { es: message("es", "screen.catalogView.799c55d702ef"), en: message("en", "screen.catalogView.799c55d702ef"), fr: message("fr", "screen.catalogView.799c55d702ef") }; }
function normalized(value: string): string { return value.normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLocaleLowerCase(); }

function itemMatches(item: Department | Office, locale: Locale, normativeVersion: string, query: string): boolean {
  if (!query.trim()) return true;
  const details = readCatalogRichMetadata(item, locale, normativeVersion);
  const haystack = [item.canonicalCode, ...Object.values(item.names), details.purpose, details.notes, details.territory, details.reportsToOfficeCode, details.linkedBaseOfficeCode, ...details.aliases, ...details.responsibilities, ...details.conditions, ...details.sourceRuleIds].filter((entry): entry is string => Boolean(entry)).join(" ");
  return normalized(haystack).includes(normalized(query.trim()));
}

export function CatalogManagerView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const text = copy[locale];
  const queryClient = useQueryClient();
  const mayManageCatalog = session.permissions.includes("catalog.manage");
  const mayManageSettings = session.permissions.includes("tenant.settings.manage");
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [createKind, setCreateKind] = useState<ItemKind>("department");
  const [createCode, setCreateCode] = useState("local.");
  const [createNames, setCreateNames] = useState<Names>(newNames);
  const [createDepartmentId, setCreateDepartmentId] = useState("");
  const [createParentId, setCreateParentId] = useState("");
  const [createSortOrder, setCreateSortOrder] = useState(0);
  const [createMechanism, setCreateMechanism] = useState<(typeof mechanisms)[number]>("local_configuration_pending");
  const [createCardinality, setCreateCardinality] = useState(1);
  const [editing, setEditing] = useState<EditableItem>();
  const [editNames, setEditNames] = useState<Names>(newNames);
  const [editDepartmentId, setEditDepartmentId] = useState("");
  const [editParentId, setEditParentId] = useState("");
  const [editSortOrder, setEditSortOrder] = useState(0);
  const [editMechanism, setEditMechanism] = useState<(typeof mechanisms)[number]>("local_configuration_pending");
  const [editCardinality, setEditCardinality] = useState(1);
  const [settingsOverrides, setSettingsOverrides] = useState<Partial<{ displayName: string; timezone: string; locale: Locale; jurisdiction: string }>>({});
  const [success, setSuccess] = useState<string>();

  const catalogQuery = useQuery({ queryKey: ["catalog", mayManageCatalog ? "manage" : "public", session.tenant.id], queryFn: () => apiRequest<Catalog>(mayManageCatalog ? "/v1/catalog/manage" : "/v1/catalog") });
  const settingsQuery = useQuery({ queryKey: ["tenant-settings", session.tenant.id], queryFn: () => apiRequest<TenantSettings>("/v1/tenant/settings"), enabled: mayManageSettings });
  const settingsForm = {
    displayName: settingsOverrides.displayName ?? settingsQuery.data?.displayName ?? "",
    timezone: settingsOverrides.timezone ?? settingsQuery.data?.timezone ?? "",
    locale: settingsOverrides.locale ?? settingsQuery.data?.locale ?? "es",
    jurisdiction: settingsOverrides.jurisdiction ?? settingsQuery.data?.jurisdiction ?? "",
  } satisfies { displayName: string; timezone: string; locale: Locale; jurisdiction: string };

  const refresh = async () => {
    setSuccess(text.saved);
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["catalog"] }),
      queryClient.invalidateQueries({ queryKey: ["tenant-settings", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["session"] }),
      queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
    ]);
  };

  const createMutation = useMutation<Department | Office, Error, { kind: ItemKind; key: string }>({
    mutationFn: (input) => input.kind === "department"
      ? apiRequest<Department>("/v1/catalog/departments", { method: "POST", idempotent: true, idempotencyKey: input.key, body: JSON.stringify({ canonicalCode: createCode.trim(), names: createNames, ...(createParentId ? { parentId: createParentId } : {}), sortOrder: createSortOrder, metadata: {} }) })
      : apiRequest<Office>("/v1/catalog/offices", { method: "POST", idempotent: true, idempotencyKey: input.key, body: JSON.stringify({ departmentId: createDepartmentId, canonicalCode: createCode.trim(), names: createNames, appointmentMechanism: createMechanism, cardinality: createCardinality, metadata: {} }) }),
    retry: 1,
    onSuccess: async () => { setCreateOpen(false); setCreateCode("local."); setCreateNames(newNames()); await refresh(); },
  });
  const updateMutation = useMutation({
    mutationFn: (input: { editing: EditableItem; active?: boolean; key: string }) => {
      const { item, kind } = input.editing;
      const body = input.active !== undefined
        ? { expectedVersion: item.version, active: input.active }
        : kind === "department"
          ? { expectedVersion: item.version, names: editNames, parentId: editParentId || null, sortOrder: editSortOrder }
          : { expectedVersion: item.version, names: editNames, departmentId: editDepartmentId, appointmentMechanism: editMechanism, cardinality: editCardinality };
      return apiRequest(kind === "department" ? `/v1/catalog/departments/${encodeURIComponent(item.id)}` : `/v1/catalog/offices/${encodeURIComponent(item.id)}`, { method: "PATCH", idempotent: true, idempotencyKey: input.key, body: JSON.stringify(body) });
    },
    retry: 1,
    onSuccess: async () => { setEditing(undefined); await refresh(); },
  });
  const settingsMutation = useMutation({
    mutationFn: (key: string) => apiRequest<TenantSettings>("/v1/tenant/settings", { method: "PATCH", idempotent: true, idempotencyKey: key, body: JSON.stringify({ expectedVersion: settingsQuery.data!.version, ...settingsForm }) }),
    retry: 1,
    onSuccess: async () => { setSettingsOverrides({}); await refresh(); },
  });

  const catalog = catalogQuery.data;
  const activeDepartments = useMemo(() => catalog?.departments.filter((item) => item.active) ?? [], [catalog?.departments]);
  const visibleDepartments = useMemo(() => catalog?.departments.filter((item) => itemMatches(item, locale, catalog.normativeVersion, search)) ?? [], [catalog, locale, search]);
  const visibleOffices = useMemo(() => catalog?.offices.filter((item) => itemMatches(item, locale, catalog.normativeVersion, search)) ?? [], [catalog, locale, search]);
  const error = catalogQuery.error ?? settingsQuery.error ?? createMutation.error ?? updateMutation.error ?? settingsMutation.error;

  function beginEdit(kind: ItemKind, item: Department | Office) {
    setEditing({ kind, item }); setEditNames({ ...item.names });
    if (kind === "department") { const department = item as Department; setEditParentId(department.parentId ?? ""); setEditSortOrder(department.sortOrder); }
    else { const office = item as Office; setEditDepartmentId(office.departmentId); setEditMechanism(office.appointmentMechanism as (typeof mechanisms)[number]); setEditCardinality(office.cardinality); }
    updateMutation.reset(); setSuccess(undefined);
  }

  if (catalogQuery.isLoading) return <LoadingBlock locale={locale} label={text.loading} />;
  if (!catalog) return <DataError locale={locale} title={text.loadFailure} />;

  const allItems = [...catalog.departments, ...catalog.offices];
  const activeCount = allItems.filter((item) => item.active).length;
  const reviewedCount = allItems.filter((item) => readCatalogRichMetadata(item, locale, catalog.normativeVersion).reviewStatus?.startsWith("verified_")).length;
  const visibleCount = visibleDepartments.length + visibleOffices.length;

  return <>
    <PageTitle eyebrow={`${text.eyebrow} · ${catalog.normativeVersion}`} title={text.title} description={text.description} action={mayManageCatalog
      ? <CreateDialog activeDepartments={activeDepartments} createCardinality={createCardinality} createCode={createCode} createDepartmentId={createDepartmentId} createKind={createKind} createMechanism={createMechanism} createNames={createNames} createOpen={createOpen} createParentId={createParentId} createPending={createMutation.isPending} createSortOrder={createSortOrder} labels={text} locale={locale} setCreateCardinality={setCreateCardinality} setCreateCode={setCreateCode} setCreateDepartmentId={setCreateDepartmentId} setCreateKind={setCreateKind} setCreateMechanism={setCreateMechanism} setCreateNames={setCreateNames} setCreateOpen={setCreateOpen} setCreateParentId={setCreateParentId} setCreateSortOrder={setCreateSortOrder} submit={() => createMutation.mutate({ kind: createKind, key: idempotencyKey() })} />
      : <Badge variant="outline"><ShieldCheck /> {text.readOnly}</Badge>} />

    <section className="grid gap-3 sm:grid-cols-3" aria-label={text.traceability}>
      <Metric icon={Layers3} label={text.normativePackage} value={catalog.normativeVersion} />
      <Metric icon={Building2} label={text.records} value={String(activeCount)} />
      <Metric icon={FileCheck2} label={text.reviewed} value={String(reviewedCount)} />
    </section>
    <Alert className="border-cyan-200 bg-cyan-50/70"><Languages /><AlertTitle>{text.traceability}</AlertTitle><AlertDescription>{text.workingTranslation}</AlertDescription></Alert>
    {mayManageCatalog && <Alert><ShieldCheck /><AlertTitle>{text.management}</AlertTitle><AlertDescription>{text.immutable}</AlertDescription></Alert>}
    {error && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{text.failure}</AlertTitle><AlertDescription>{localizedApiError(error, locale)}</AlertDescription></Alert>}
    {success && <Alert><ShieldCheck /><AlertTitle>{success}</AlertTitle></Alert>}

    {mayManageSettings && settingsQuery.data && <section className="surface-card">
      <div className="card-heading"><div><p className="eyebrow">{text.settings}</p><h2>{settingsQuery.data.displayName}</h2></div><Settings2 /></div><p>{text.settingsBody}</p>
      <form className="mt-5 grid gap-3 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); settingsMutation.mutate(idempotencyKey()); }}>
        <Field label={text.displayName}><Input value={settingsForm.displayName} onChange={(event) => setSettingsOverrides({ ...settingsOverrides, displayName: event.target.value })} required maxLength={160} /></Field>
        <Field label={text.timezone}><Input value={settingsForm.timezone} onChange={(event) => setSettingsOverrides({ ...settingsOverrides, timezone: event.target.value })} required maxLength={80} /></Field>
        <Field label={text.locale}><select value={settingsForm.locale} onChange={(event) => setSettingsOverrides({ ...settingsOverrides, locale: event.target.value as Locale })}>{supportedLocales.map((item) => <option key={item} value={item}>{localeMetadata[item].label}</option>)}</select></Field>
        <Field label={text.jurisdiction}><Input value={settingsForm.jurisdiction} onChange={(event) => setSettingsOverrides({ ...settingsOverrides, jurisdiction: event.target.value })} required maxLength={160} /></Field>
        <div className="md:col-span-2"><Button type="submit" disabled={settingsMutation.isPending}>{settingsMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Save />}{text.saveSettings}</Button></div>
      </form>
    </section>}

    <section className="surface-card border-slate-200 bg-gradient-to-br from-white to-slate-50/80">
      <label className="field-stack max-w-2xl" htmlFor="catalog-search"><span className="text-sm font-medium">{text.search}</span><span className="relative block"><Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" /><Input id="catalog-search" className="pl-10" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder={text.searchPlaceholder} /></span></label>
      <p className="mt-3 text-xs font-medium text-slate-500" aria-live="polite">{visibleCount} {text.visibleResults}</p>
    </section>

    {visibleCount === 0 ? <section className="surface-card"><EmptyState locale={locale} icon={Search} title={text.noMatches} /></section> : <div className="catalog-layout items-start">
      <CatalogList canManage={mayManageCatalog} locale={locale} labels={text} kind="department" title={text.departments} items={visibleDepartments} empty={text.emptyDepartments} normativeVersion={catalog.normativeVersion} beginEdit={beginEdit} toggle={(kind, item) => updateMutation.mutate({ editing: { kind, item }, active: !item.active, key: idempotencyKey() })} />
      <CatalogList canManage={mayManageCatalog} locale={locale} labels={text} kind="office" title={text.offices} items={visibleOffices} empty={text.emptyOffices} normativeVersion={catalog.normativeVersion} beginEdit={beginEdit} toggle={(kind, item) => updateMutation.mutate({ editing: { kind, item }, active: !item.active, key: idempotencyKey() })} />
    </div>}

    <EditDialog activeDepartments={activeDepartments} editing={editing} editCardinality={editCardinality} editDepartmentId={editDepartmentId} editMechanism={editMechanism} editNames={editNames} editParentId={editParentId} editPending={updateMutation.isPending} editSortOrder={editSortOrder} labels={text} locale={locale} setEditing={setEditing} setEditCardinality={setEditCardinality} setEditDepartmentId={setEditDepartmentId} setEditMechanism={setEditMechanism} setEditNames={setEditNames} setEditParentId={setEditParentId} setEditSortOrder={setEditSortOrder} submit={() => editing && updateMutation.mutate({ editing, key: idempotencyKey() })} />
  </>;
}

type Labels = typeof copy.es | typeof copy.en | typeof copy.fr;
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <label className="field-stack"><span className="text-sm font-medium">{label}</span>{children}</label>; }
function NamesFields({ labels, names, setNames }: { labels: Labels; names: Names; setNames: (value: Names) => void }) { return <div className="grid gap-3 sm:grid-cols-3"><Field label={labels.spanish}><Input value={names.es} onChange={(event) => setNames({ ...names, es: event.target.value })} required maxLength={160} /></Field><Field label={labels.english}><Input value={names.en} onChange={(event) => setNames({ ...names, en: event.target.value })} required maxLength={160} /></Field><Field label={labels.french}><Input value={names.fr} onChange={(event) => setNames({ ...names, fr: event.target.value })} required maxLength={160} /></Field></div>; }

function OfficeFields({ locale, labels, departments, departmentId, setDepartmentId, mechanism, setMechanism, cardinality, setCardinality }: { locale: Locale; labels: Labels; departments: Department[]; departmentId: string; setDepartmentId: (value: string) => void; mechanism: (typeof mechanisms)[number]; setMechanism: (value: (typeof mechanisms)[number]) => void; cardinality: number; setCardinality: (value: number) => void }) {
  return <div className="grid gap-3 sm:grid-cols-2"><Field label={labels.department}><select value={departmentId} onChange={(event) => setDepartmentId(event.target.value)} required><option value="">{labels.none}</option>{departments.map((item) => <option key={item.id} value={item.id}>{localizedName(item.names, locale, item.canonicalCode)}</option>)}</select></Field><Field label={labels.mechanism}><select value={mechanism} onChange={(event) => setMechanism(event.target.value as (typeof mechanisms)[number])}>{mechanisms.map((value) => <option key={value} value={value}>{mechanismLabels[locale][value]}</option>)}</select></Field><Field label={labels.cardinality}><Input type="number" min={1} max={10_000} value={cardinality} onChange={(event) => setCardinality(Number(event.target.value))} /></Field></div>;
}

function Metric({ icon: Icon, label, value }: { icon: typeof Building2; label: string; value: string }) {
  return <article className="surface-card flex min-w-0 items-center gap-3 border-slate-200 bg-gradient-to-br from-white to-cyan-50/40 py-4"><span className="metric-icon cyan" aria-hidden="true"><Icon /></span><div className="min-w-0"><small className="block text-[.8rem] font-semibold uppercase tracking-[.12em] text-slate-500">{label}</small><strong className="mt-1 block truncate text-sm text-slate-900">{value}</strong></div></article>;
}

function CatalogList({ canManage, locale, labels, kind, title, items, empty, normativeVersion, beginEdit, toggle }: { canManage: boolean; locale: Locale; labels: Labels; kind: ItemKind; title: string; items: Array<Department | Office>; empty: string; normativeVersion: string; beginEdit: (kind: ItemKind, item: Department | Office) => void; toggle: (kind: ItemKind, item: Department | Office) => void }) {
  const headingId = `catalog-${kind}-heading`;
  return <section className="surface-card min-w-0" aria-labelledby={headingId}><div className="card-heading"><h2 id={headingId}>{title}</h2><Badge variant="outline">{items.length}</Badge></div><div className="mt-4 grid gap-3">{items.length ? items.map((item) => <CatalogRecordCard key={item.id} canManage={canManage} locale={locale} labels={labels} kind={kind} item={item} normativeVersion={normativeVersion} beginEdit={beginEdit} toggle={toggle} />) : <EmptyState locale={locale} icon={Building2} title={empty} />}</div></section>;
}

function CatalogRecordCard({ canManage, locale, labels, kind, item, normativeVersion, beginEdit, toggle }: { canManage: boolean; locale: Locale; labels: Labels; kind: ItemKind; item: Department | Office; normativeVersion: string; beginEdit: (kind: ItemKind, item: Department | Office) => void; toggle: (kind: ItemKind, item: Department | Office) => void }) {
  const details = readCatalogRichMetadata(item, locale, normativeVersion);
  const office = "appointmentMechanism" in item ? item as Office : null;
  const titleId = `catalog-record-${item.id}`;
  const displayName = localizedName(item.names, locale, item.canonicalCode);
  const reviewLabel = details.reviewStatus ? reviewStatusLabels[locale][details.reviewStatus] : null;
  const mechanism = office ? mechanismLabels[locale][office.appointmentMechanism as (typeof mechanisms)[number]] ?? office.appointmentMechanism : null;
  const hasNarrative = Boolean(details.purpose || details.responsibilities.length || details.conditions.length || details.notes || details.sourceRuleIds.length || details.sourceLocators.length);
  return <article className={`min-w-0 overflow-hidden rounded-2xl border bg-white shadow-[0_10px_30px_rgba(15,40,55,.055)] transition hover:border-cyan-200 hover:shadow-[0_16px_38px_rgba(15,75,86,.09)] ${item.active ? "border-slate-200" : "border-slate-200 opacity-65"}`} aria-labelledby={titleId}>
    <div className="flex flex-wrap items-start gap-3 p-4"><span className="metric-icon cyan shrink-0" aria-hidden="true"><Building2 /></span><div className="min-w-0 flex-1"><div className="mb-1.5 flex flex-wrap gap-1.5"><Badge variant={item.localExtension ? "secondary" : "outline"}>{item.localExtension ? labels.local : labels.canonical}</Badge><Badge variant={item.active ? "default" : "outline"}>{item.active ? labels.active : labels.inactive}</Badge>{reviewLabel && <Badge variant="outline"><FileCheck2 />{reviewLabel}</Badge>}</div><h3 id={titleId} className="text-[.92rem] font-semibold leading-snug text-slate-900">{displayName}</h3><code className="mt-1 block break-all text-[.8rem] text-slate-500">{item.canonicalCode}</code></div><div className="flex flex-wrap justify-end gap-2">{item.localExtension && canManage ? <><Button size="sm" variant="outline" aria-label={`${labels.edit}: ${displayName}`} onClick={() => beginEdit(kind, item)}><Pencil />{labels.edit}</Button><Button size="sm" variant="ghost" aria-label={`${item.active ? labels.deactivate : labels.reactivate}: ${displayName}`} onClick={() => toggle(kind, item)}>{item.active ? labels.deactivate : labels.reactivate}</Button></> : <Badge variant="outline"><ShieldCheck />{item.localExtension ? labels.local : labels.canonical}</Badge>}</div></div>
    {details.purpose && <p className="border-t border-slate-100 px-4 py-3 text-[.82rem] leading-6 text-slate-600">{details.purpose}</p>}
    <div className="flex flex-wrap gap-2 px-4 pb-3">{mechanism && <Badge variant="secondary">{mechanism}</Badge>}{office && <Badge variant="outline">{office.cardinality} {labels.positions}</Badge>}{details.applicableByDefault !== null && <Badge variant="outline">{details.applicableByDefault ? labels.applicableByDefault : labels.optionalByDefault}</Badge>}</div>
    <details className="group border-t border-slate-100"><summary aria-label={`${labels.details}: ${displayName}`} className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-[.8rem] font-semibold text-cyan-800 outline-none transition hover:bg-cyan-50 focus-visible:ring-2 focus-visible:ring-cyan-600 focus-visible:ring-inset [&::-webkit-details-marker]:hidden"><span className="flex items-center gap-2"><BookOpen aria-hidden="true" className="size-4" />{labels.details}</span><span aria-hidden="true" className="text-lg leading-none transition group-open:rotate-45">+</span></summary><div className="grid gap-3 bg-slate-50/70 p-4 sm:grid-cols-2">
      {!hasNarrative && <p className="rounded-xl border border-dashed border-slate-300 bg-white p-3 text-xs text-slate-600 sm:col-span-2">{labels.noRichMetadata}</p>}
      {details.purpose && <DetailBlock title={labels.purpose}><p>{details.purpose}</p></DetailBlock>}
      {details.responsibilities.length > 0 && <DetailBlock title={labels.responsibilities}><BulletList items={details.responsibilities} /></DetailBlock>}
      {details.conditions.length > 0 && <DetailBlock title={labels.conditions}><BulletList items={details.conditions} /></DetailBlock>}
      {mechanism && <DetailBlock title={labels.mechanism} icon={Layers3}><p>{mechanism}</p><p className="mt-2"><strong>{labels.cardinality}:</strong> {office?.cardinality}</p></DetailBlock>}
      <ProvenanceBlock details={details} labels={labels} />
      <TraceabilityBlock details={details} labels={labels} locale={locale} />
      {details.aliases.length > 0 && <DetailBlock title={labels.aliases}><BulletList items={details.aliases} /></DetailBlock>}
      {details.notes && <DetailBlock title={labels.notes}><p>{details.notes}</p></DetailBlock>}
    </div></details>
  </article>;
}

function DetailBlock({ title, icon: Icon = BookOpen, children, wide = false }: { title: string; icon?: typeof BookOpen; children: React.ReactNode; wide?: boolean }) { return <section className={`rounded-xl border border-slate-200 bg-white p-3 ${wide ? "sm:col-span-2" : ""}`}><h4 className="mb-2 flex items-center gap-2 text-[.8rem] font-bold uppercase tracking-[.11em] text-slate-500"><Icon aria-hidden="true" className="size-3.5 text-cyan-700" />{title}</h4><div className="text-[.82rem] leading-5 text-slate-700">{children}</div></section>; }
function BulletList({ items }: { items: readonly string[] }) { return <ul className="grid gap-2 pl-4 marker:text-cyan-600">{items.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>; }

function ProvenanceBlock({ details, labels }: { details: CatalogRichMetadata; labels: Labels }) {
  const hasProvenance = details.sourceRuleIds.length > 0 || details.sourceLocators.length > 0 || details.territory;
  if (!hasProvenance) return null;
  return <DetailBlock title={labels.provenance} icon={Link2} wide>{details.territory && <p className="mb-2"><strong>{labels.territory}:</strong> {details.territory.replaceAll("_", " ")}</p>}{details.sourceRuleIds.length > 0 && <div className="mb-3"><strong className="mb-1.5 block">{labels.sourceRules}</strong><div className="flex flex-wrap gap-1.5">{details.sourceRuleIds.map((ruleId) => <Badge key={ruleId} variant="outline">{ruleId}</Badge>)}</div></div>}{details.sourceLocators.length > 0 && <ul className="grid gap-2">{details.sourceLocators.map((reference, index) => <SourceReference key={`${reference.sourceId}-${index}`} reference={reference} labels={labels} />)}</ul>}</DetailBlock>;
}

function SourceReference({ reference, labels }: { reference: CatalogSourceReference; labels: Labels }) {
  const location = [reference.chapter, reference.section, reference.printedPages.length ? `${labels.pages} ${reference.printedPages.join(", ")}` : null].filter(Boolean).join(" · ");
  return <li className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><code className="block break-all text-[.8rem] font-semibold text-slate-800">{reference.sourceId}</code>{location && <span className="mt-1 block text-[.8rem] text-slate-600">{location}</span>}{reference.sourceLanguage && <span className="mt-1 block text-[.8rem] text-slate-500">{labels.sourceLanguage}: {reference.sourceLanguage}</span>}{reference.url && <a className="mt-2 inline-flex min-h-9 items-center gap-1.5 rounded-md font-semibold text-cyan-800 underline decoration-cyan-300 underline-offset-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-600" href={reference.url} target="_blank" rel="noreferrer noopener">{labels.sourceDocument}<ExternalLink aria-hidden="true" className="size-3.5" /><span className="sr-only">({labels.opensNewWindow})</span></a>}</li>;
}

function TraceabilityBlock({ details, labels, locale }: { details: CatalogRichMetadata; labels: Labels; locale: Locale }) {
  return <DetailBlock title={labels.traceability} icon={FileCheck2}><dl className="grid gap-2"><div><dt className="font-semibold">{labels.catalogVersion}</dt><dd className="break-all">{details.catalogVersion}</dd></div>{details.reviewStatus && <div><dt className="font-semibold">{labels.reviewStatus}</dt><dd>{reviewStatusLabels[locale][details.reviewStatus]}</dd></div>}{details.reportsToOfficeCode && <div><dt className="font-semibold">{labels.reportsTo}</dt><dd><code>{details.reportsToOfficeCode}</code></dd></div>}{details.linkedBaseOfficeCode && <div><dt className="font-semibold">{labels.linkedTo}</dt><dd><code>{details.linkedBaseOfficeCode}</code></dd></div>}</dl></DetailBlock>;
}

interface CreateDialogProps {
  activeDepartments: Department[]; createCardinality: number; createCode: string; createDepartmentId: string; createKind: ItemKind; createMechanism: (typeof mechanisms)[number]; createNames: Names; createOpen: boolean; createParentId: string; createPending: boolean; createSortOrder: number; labels: Labels; locale: Locale;
  setCreateCardinality: (value: number) => void; setCreateCode: (value: string) => void; setCreateDepartmentId: (value: string) => void; setCreateKind: (value: ItemKind) => void; setCreateMechanism: (value: (typeof mechanisms)[number]) => void; setCreateNames: (value: Names) => void; setCreateOpen: (value: boolean) => void; setCreateParentId: (value: string) => void; setCreateSortOrder: (value: number) => void; submit: () => void;
}

function CreateDialog(props: CreateDialogProps) {
  return <Dialog open={props.createOpen} onOpenChange={props.setCreateOpen}><DialogTrigger asChild><Button><Plus />{props.labels.add}</Button></DialogTrigger><DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-2xl"><DialogHeader><DialogTitle>{props.labels.create}</DialogTitle><DialogDescription>{props.labels.codeHelp}</DialogDescription></DialogHeader><form id="catalog-create" className="dialog-form" onSubmit={(event) => { event.preventDefault(); props.submit(); }}><div className="grid gap-3 sm:grid-cols-2"><Field label={props.labels.type}><select value={props.createKind} onChange={(event) => props.setCreateKind(event.target.value as ItemKind)}><option value="department">{props.labels.department}</option><option value="office">{props.labels.office}</option></select></Field><Field label={props.labels.code}><Input value={props.createCode} onChange={(event) => props.setCreateCode(event.target.value.toLocaleLowerCase())} pattern="local\.[a-z0-9][a-z0-9._-]{1,78}" required /></Field></div><NamesFields labels={props.labels} names={props.createNames} setNames={props.setCreateNames} />{props.createKind === "department" ? <div className="grid gap-3 sm:grid-cols-2"><Field label={props.labels.parent}><select value={props.createParentId} onChange={(event) => props.setCreateParentId(event.target.value)}><option value="">{props.labels.none}</option>{props.activeDepartments.map((item) => <option key={item.id} value={item.id}>{localizedName(item.names, props.locale, item.canonicalCode)}</option>)}</select></Field><Field label={props.labels.order}><Input type="number" min={0} max={100_000} value={props.createSortOrder} onChange={(event) => props.setCreateSortOrder(Number(event.target.value))} /></Field></div> : <OfficeFields locale={props.locale} labels={props.labels} departments={props.activeDepartments} departmentId={props.createDepartmentId} setDepartmentId={props.setCreateDepartmentId} mechanism={props.createMechanism} setMechanism={props.setCreateMechanism} cardinality={props.createCardinality} setCardinality={props.setCreateCardinality} />}</form><DialogFooter><Button variant="outline" onClick={() => props.setCreateOpen(false)}>{props.labels.cancel}</Button><Button form="catalog-create" type="submit" disabled={props.createPending || !props.createNames.es.trim() || !props.createNames.en.trim() || !props.createNames.fr.trim() || (props.createKind === "office" && !props.createDepartmentId)}>{props.createPending && <LoaderCircle className="animate-spin" />}{props.labels.create}</Button></DialogFooter></DialogContent></Dialog>;
}

interface EditDialogProps {
  activeDepartments: Department[]; editing: EditableItem | undefined; editCardinality: number; editDepartmentId: string; editMechanism: (typeof mechanisms)[number]; editNames: Names; editParentId: string; editPending: boolean; editSortOrder: number; labels: Labels; locale: Locale;
  setEditing: (value: EditableItem | undefined) => void; setEditCardinality: (value: number) => void; setEditDepartmentId: (value: string) => void; setEditMechanism: (value: (typeof mechanisms)[number]) => void; setEditNames: (value: Names) => void; setEditParentId: (value: string) => void; setEditSortOrder: (value: number) => void; submit: () => void;
}

function EditDialog(props: EditDialogProps) {
  return <Dialog open={Boolean(props.editing)} onOpenChange={(open) => { if (!open) props.setEditing(undefined); }}><DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-2xl"><DialogHeader><DialogTitle>{props.labels.editTitle}</DialogTitle><DialogDescription>{props.editing?.item.canonicalCode}</DialogDescription></DialogHeader>{props.editing && <form id="catalog-edit" className="dialog-form" onSubmit={(event) => { event.preventDefault(); props.submit(); }}><NamesFields labels={props.labels} names={props.editNames} setNames={props.setEditNames} />{props.editing.kind === "department" ? <div className="grid gap-3 sm:grid-cols-2"><Field label={props.labels.parent}><select value={props.editParentId} onChange={(event) => props.setEditParentId(event.target.value)}><option value="">{props.labels.none}</option>{props.activeDepartments.filter((item) => item.id !== props.editing?.item.id).map((item) => <option key={item.id} value={item.id}>{localizedName(item.names, props.locale, item.canonicalCode)}</option>)}</select></Field><Field label={props.labels.order}><Input type="number" min={0} max={100_000} value={props.editSortOrder} onChange={(event) => props.setEditSortOrder(Number(event.target.value))} /></Field></div> : <OfficeFields locale={props.locale} labels={props.labels} departments={props.activeDepartments} departmentId={props.editDepartmentId} setDepartmentId={props.setEditDepartmentId} mechanism={props.editMechanism} setMechanism={props.setEditMechanism} cardinality={props.editCardinality} setCardinality={props.setEditCardinality} />}</form>}<DialogFooter><Button variant="outline" onClick={() => props.setEditing(undefined)}>{props.labels.cancel}</Button><Button form="catalog-edit" type="submit" disabled={props.editPending}>{props.editPending && <LoaderCircle className="animate-spin" />}{props.labels.save}</Button></DialogFooter></DialogContent></Dialog>;
}
