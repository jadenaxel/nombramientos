"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Building2,
  CheckCircle2,
  ChevronDown,
  CircleDashed,
  Download,
  LayoutList,
  Link2,
  LockKeyhole,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  UsersRound,
  ZoomIn,
  ZoomOut,
} from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest, type AuthenticatedSession, type Envelope, type Locale, type OrganizationRecord } from "@/lib/api";
import { keyForEnvelope, openJsonEnvelope } from "@/lib/historical-envelope";
import {
  filterOrganizationItems,
  groupOrganizationByDepartment,
  organizationDirectoryInsights,
  organizationReportQuery,
  organizationTotals,
  organizationWorkload,
  type OrganizationStage,
  type ResponsibilitySummary,
} from "@/lib/organization-model";
import { decryptPhoto, type StoredPhotoRecord } from "@/lib/photo-client";
import { localizedName, message } from "@/lib/product-i18n";
import { EmptyState, LoadingBlock, PageTitle } from "./workspace-view";

type AssignmentDisplay = { displayName?: string; firstName?: string; lastName?: string; shortId?: string };
type CycleOption = {
  id: string;
  name: string;
  status: string;
  termStart?: string;
  termEnd?: string;
};
type OrganizationItem = OrganizationRecord & {
  vacancyId?: string;
  officeId?: string;
  departmentId?: string;
  officeCode?: string;
  processState?: string | null;
  effective?: boolean;
  independent?: boolean;
  memberSnapshot?: { displayEnvelope?: Envelope; photo?: StoredPhotoRecord | null } | null;
  photoSnapshot?: StoredPhotoRecord | null;
  displayName?: string;
  source?: string;
};
type OrganizationResponse = {
  items: OrganizationItem[];
  cycles?: CycleOption[];
  selectedCycle?: CycleOption | null;
  cycleName?: string | null;
  stage?: OrganizationStage;
  source?: "gestionchurch";
  sourceUpdatedAt?: string | null;
  generatedAt?: string;
  directorySummary?: { departments: number; people: number; appointments: number };
};
type VisibleAssignment = OrganizationItem & {
  displayName?: string;
  shortId?: string;
  photoUrl?: string;
  officeName: string;
  departmentName: string;
};
type Layout = "graph" | "list";

const statusLabels: Record<Locale, Record<string, string>> = {
  es: { vacant: message("es", "screen.organizationView.eb8c19fc3e89"), pending: message("es", "screen.organizationView.1ff0c0e8e15b"), not_configured: message("es", "screen.organizationView.a8b34b2ae059"), recommended: message("es", "screen.organizationView.07a0dacbeb7f"), accepted: message("es", "screen.organizationView.8a906032a007"), elected: message("es", "screen.organizationView.cb8860f8a573") },
  en: { vacant: message("en", "screen.organizationView.eb8c19fc3e89"), pending: message("en", "screen.organizationView.1ff0c0e8e15b"), not_configured: message("en", "screen.organizationView.a8b34b2ae059"), recommended: message("en", "screen.organizationView.07a0dacbeb7f"), accepted: message("en", "screen.organizationView.8a906032a007"), elected: message("en", "screen.organizationView.cb8860f8a573") },
  fr: { vacant: message("fr", "screen.organizationView.eb8c19fc3e89"), pending: message("fr", "screen.organizationView.1ff0c0e8e15b"), not_configured: message("fr", "screen.organizationView.a8b34b2ae059"), recommended: message("fr", "screen.organizationView.07a0dacbeb7f"), accepted: message("fr", "screen.organizationView.8a906032a007"), elected: message("fr", "screen.organizationView.cb8860f8a573") },
};

function statusClass(status: string): string {
  if (status === "elected") return "elected";
  if (status === "accepted") return "accepted";
  if (status === "recommended") return "recommended";
  return "vacant";
}

function assignmentName(profile: AssignmentDisplay): string {
  return profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
}

function responsibilityKind(item: VisibleAssignment, locale: Locale): string {
  const code = `${item.officeCode ?? ""} ${item.officeName}`.normalize("NFD").replace(/[\u0300-\u036f]/gu, "").toLocaleLowerCase();
  if (code.includes("secretar")) return message(locale, "screen.organizationView.d75ed4c5d2f7");
  if (/(leader|director|head|coordinator|pastor|elder|president|direccion|primer anciano|tesorer|coordinador|responsable)/u.test(code)) {
    return message(locale, "screen.organizationView.12d54a5e8e45");
  }
  return message(locale, "screen.organizationView.ba44ca9183b5");
}

function stageLabel(stage: OrganizationStage, locale: Locale): string {
  return stage === "elected"
    ? message(locale, "screen.organizationView.b9bd1dcc559c")
    : message(locale, "screen.organizationView.07a0dacbeb7f");
}

function AssignmentCard({
  item,
  locale,
  workload,
  compact = false,
}: {
  item: VisibleAssignment;
  locale: Locale;
  workload?: ResponsibilitySummary;
  compact?: boolean;
}) {
  const status = item.source && item.processState === "VIGENTE"
    ? message(locale, "organization.directoryCurrentBadge")
    : statusLabels[locale][item.status] ?? item.status;
  const initials = item.displayName
    ? item.displayName.split(/\s+/u).slice(0, 2).map((part) => part[0]).join("").toLocaleUpperCase()
    : "";
  const hasIndependentLoad = (workload?.independent ?? 0) > 1;
  return <article className={`org-role ${statusClass(item.status)}${compact ? " compact" : ""}`}>
    <span className="org-role-icon" aria-hidden="true">
      {item.photoUrl ? <>
        {/* Authenticated memory-only blob URL, revoked by the parent effect. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={item.photoUrl} alt="" />
      </> : item.displayName ? initials || <UserRound /> : <CircleDashed />}
    </span>
    <div className="min-w-0">
      <small>{responsibilityKind(item, locale)} · {item.officeName}</small>
      <strong>{item.displayName ?? statusLabels[locale].vacant}</strong>
      {item.shortId && <span>{item.shortId}</span>}
    </div>
    <Badge variant="outline">{status}</Badge>
    {item.linkedToId && <span className="linked-marker" title={message(locale, "screen.organizationView.841ac3ef5f0c")}><Link2 /> {message(locale, "screen.organizationView.e28ed5a85223")}</span>}
    {item.memberId && workload && workload.total > 1 && <details className={`org-load-detail${hasIndependentLoad ? " warning" : ""}`}>
      <summary>
        {hasIndependentLoad ? <ShieldAlert aria-hidden="true" /> : <Link2 aria-hidden="true" />}
        {hasIndependentLoad
          ? message(locale, "screen.organizationView.3dd6dfeebb1b", { value0: workload.independent })
          : message(locale, "screen.organizationView.f0af379609e0", { value0: workload.linked })}
        <ChevronDown aria-hidden="true" />
      </summary>
      <ul>{workload.responsibilities.map((responsibility) => <li key={responsibility.assignmentId}><span>{responsibility.officeName}</span><small>{responsibility.departmentName} · {responsibility.linked ? message(locale, "screen.organizationView.e633760049d0") : message(locale, "screen.organizationView.cefb261ac226")}</small></li>)}</ul>
    </details>}
  </article>;
}

export function OrganizationView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const vault = useVault();
  const [cycleId, setCycleId] = useState("");
  const [stage, setStage] = useState<OrganizationStage>("elected");
  const [layout, setLayout] = useState<Layout>("graph");
  const [search, setSearch] = useState("");
  const [department, setDepartment] = useState("all");
  const [status, setStatus] = useState("all");
  const [zoom, setZoom] = useState(100);
  const [items, setItems] = useState<VisibleAssignment[]>([]);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState<string>();
  const query = useQuery({
    queryKey: ["organization", session.tenant.id, cycleId || "current", stage],
    queryFn: () => {
      const parameters = new URLSearchParams({ stage });
      if (cycleId) parameters.set("cycleId", cycleId);
      return apiRequest<OrganizationResponse>(`/v1/organization?${parameters.toString()}`);
    },
    retry: false,
  });

  useEffect(() => {
    let cancelled = false;
    const createdUrls: string[] = [];
    async function reveal(): Promise<void> {
      if (!query.data) return;
      const requiresDecryption = query.data.items.some((item) => Boolean(item.memberId && !item.displayName));
      if (requiresDecryption && (!vault.key || !vault.keyId)) {
        setItems([]);
        setDecryptError(message(locale, "organization.cryptoUnavailable"));
        return;
      }
      setDecrypting(requiresDecryption);
      setDecryptError(undefined);
      try {
        let hadFailures = false;
        const decrypted = await Promise.all(query.data.items.map(async (item): Promise<VisibleAssignment> => {
          const officeName = localizedName(item.officeNames, locale, item.officeName);
          const departmentName = localizedName(item.departmentNames, locale, item.departmentName);
          if (item.displayName) return { ...item, officeName, departmentName, displayName: item.displayName };
          if (!item.memberId) return { ...item, officeName, departmentName };
          const displayEnvelope = item.memberSnapshot?.displayEnvelope ?? item.displayEnvelope;
          try {
            if (!displayEnvelope) throw new Error("ASSIGNMENT_SNAPSHOT_MISSING");
            const profile = await openJsonEnvelope<AssignmentDisplay>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: item.memberId, purpose: "member-display", schemaVersion: 1 },
            });
            const displayName = assignmentName(profile);
            if (!displayName) throw new Error("ASSIGNMENT_DISPLAY_NAME_MISSING");
            const photo = item.memberSnapshot?.photo ?? item.photoSnapshot;
            let photoUrl: string | undefined;
            if (photo) {
              try {
                const blob = await decryptPhoto({
                  key: keyForEnvelope(vault, session.tenant.id, photo.envelope),
                  keyId: photo.envelope.keyId,
                  tenantId: session.tenant.id,
                  memberId: item.memberId,
                  photo,
                });
                photoUrl = URL.createObjectURL(blob);
                createdUrls.push(photoUrl);
              } catch {
                hadFailures = true;
              }
            }
            return { ...item, officeName, departmentName, displayName, ...(profile.shortId ? { shortId: profile.shortId } : {}), ...(photoUrl ? { photoUrl } : {}) };
          } catch {
            hadFailures = true;
            return { ...item, officeName, departmentName, displayName: message(locale, "organization.cryptoUnavailable") };
          }
        }));
        if (!cancelled) {
          setItems(decrypted);
          setDecryptError(hadFailures ? message(locale, "organization.cryptoFailure") : undefined);
        }
      } catch {
        if (!cancelled) setDecryptError(message(locale, "organization.cryptoFailure"));
      } finally {
        if (!cancelled) setDecrypting(false);
      }
    }
    void reveal();
    return () => {
      cancelled = true;
      for (const url of createdUrls) URL.revokeObjectURL(url);
    };
  }, [locale, query.data, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  const securedItems = items;
  const departments = useMemo(() => {
    const values = new Map<string, string>();
    for (const item of securedItems) values.set(item.departmentId ?? item.departmentName, item.departmentName);
    return [...values.entries()].sort(([, left], [, right]) => left.localeCompare(right, locale));
  }, [locale, securedItems]);
  const filtered = useMemo(() => filterOrganizationItems(securedItems, { query: search, department, status }), [department, search, securedItems, status]);
  const grouped = useMemo(() => groupOrganizationByDepartment(filtered, locale), [filtered, locale]);
  const workload = useMemo(() => organizationWorkload(securedItems), [securedItems]);
  const totals = useMemo(() => organizationTotals(securedItems), [securedItems]);
  const directoryInsights = useMemo(() => organizationDirectoryInsights(securedItems), [securedItems]);
  const directoryMode = query.data?.source === "gestionchurch";
  const selectedCycle = query.data?.selectedCycle ?? query.data?.cycles?.find(({ id }) => id === cycleId);
  const selectedCycleId = cycleId || selectedCycle?.id || "";
  const reportHref = `/${locale}/app/reports?${organizationReportQuery({
    ...(selectedCycleId ? { cycleId: selectedCycleId } : {}),
    ...(department !== "all" ? { departmentId: department } : {}),
    stage,
  })}`;
  const reportAllowed = session.permissions.includes("report.export") && !directoryMode;
  const cycleLabel = selectedCycle?.termStart && selectedCycle.termEnd
    ? `${selectedCycle.name} · ${selectedCycle.termStart}–${selectedCycle.termEnd}`
    : selectedCycle?.name ?? query.data?.cycleName ?? (directoryMode ? message(locale, "organization.directoryCurrent") : message(locale, "organization.currentStructure"));
  const directoryUpdated = query.data?.sourceUpdatedAt
    ? new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(query.data.sourceUpdatedAt))
    : message(locale, "organization.directoryLive");

  if (query.isLoading || decrypting) return <LoadingBlock label={message(locale, "organization.loading")} />;

  return <>
    <PageTitle eyebrow={message(locale, "organization.cycleStructure")} title={message(locale, "organization.title")} description={directoryMode ? message(locale, "organization.directoryDescription", { tenant: session.tenant.name }) : message(locale, "organization.description", { cycle: cycleLabel })} />
    {directoryMode && <section className="org-directory-source" aria-label={message(locale, "organization.directoryEyebrow")}>
      <span className="org-source-icon" aria-hidden="true"><ShieldCheck /></span>
      <div className="org-source-copy"><small>{message(locale, "organization.directoryEyebrow")}</small><h2>{message(locale, "organization.directoryTitle")}</h2><p>{message(locale, "organization.directoryBody", { appointments: directoryInsights.appointments, people: directoryInsights.people, departments: directoryInsights.departments })}</p></div>
      <div className="org-source-status"><Badge><ShieldCheck />{message(locale, "organization.directoryPrivate")}</Badge><Badge variant="outline"><RefreshCw />{message(locale, "organization.directoryLive")}</Badge><small>{message(locale, "organization.directoryUpdated", { date: directoryUpdated })}</small></div>
    </section>}
    {session.tenant.kind === "demo" && <Alert className="demo-notice"><ShieldCheck /><AlertTitle>{message(locale, "organization.demoTitle")}</AlertTitle><AlertDescription>{message(locale, "organization.demoHelp")}</AlertDescription></Alert>}
    <section className="org-command surface-card" aria-label={message(locale, "screen.organizationView.c7703fb3fd56")}>
      {!directoryMode && <div className="org-stage-switch" role="group" aria-label={message(locale, "screen.organizationView.b78e16e87299")}>
        {(["proposal", "elected"] as const).map((value) => <Button key={value} type="button" variant={stage === value ? "default" : "outline"} aria-pressed={stage === value} onClick={() => { setStage(value); setStatus("all"); }}>{stageLabel(value, locale)}</Button>)}
      </div>}
      <div className="org-filter-grid">
        <div><Label htmlFor="organization-cycle">{message(locale, "screen.organizationView.4b2b2c08346d")}</Label><select id="organization-cycle" value={directoryMode ? "directory" : selectedCycleId} onChange={(event) => { setCycleId(event.target.value); setDepartment("all"); }} disabled={directoryMode || !query.data?.cycles?.length}>{directoryMode ? <option value="directory">{message(locale, "organization.directoryCurrent")}</option> : query.data?.cycles?.map((cycle) => <option key={cycle.id} value={cycle.id}>{cycle.name}{cycle.termStart && cycle.termEnd ? ` · ${cycle.termStart}–${cycle.termEnd}` : ""}</option>)}</select></div>
        <div><Label htmlFor="organization-department">{message(locale, "screen.organizationView.a9c1f5f4089f")}</Label><select id="organization-department" value={department} onChange={(event) => setDepartment(event.target.value)}><option value="all">{message(locale, "screen.organizationView.62545aee4d81")}</option>{departments.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></div>
        <div><Label htmlFor="organization-status">{message(locale, "screen.organizationView.06977bde9342")}</Label><select id="organization-status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">{message(locale, "screen.organizationView.45e32915a439")}</option>{Object.entries(statusLabels[locale]).filter(([value]) => value !== "not_configured").map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div>
        <div className="org-search"><Label htmlFor="organization-search">{message(locale, "screen.organizationView.f8d4ca1ef03f")}</Label><span><Search aria-hidden="true" /><Input id="organization-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} /></span></div>
      </div>
      <div className="org-view-actions">
        <div role="group" aria-label={message(locale, "screen.organizationView.49dd03f0dc9e")}><Button type="button" size="sm" variant={layout === "graph" ? "default" : "outline"} aria-pressed={layout === "graph"} onClick={() => setLayout("graph")}><Network />{message(locale, "screen.organizationView.6ffb7f2d2e47")}</Button><Button type="button" size="sm" variant={layout === "list" ? "default" : "outline"} aria-pressed={layout === "list"} onClick={() => setLayout("list")}><LayoutList />{message(locale, "screen.organizationView.6956c412cf14")}</Button></div>
        {layout === "graph" && <div role="group" aria-label={message(locale, "screen.organizationView.fea75bb73c5a")}><Button type="button" size="icon-sm" variant="outline" aria-label={message(locale, "screen.organizationView.9d71eda15776")} disabled={zoom <= 75} onClick={() => setZoom((value) => Math.max(75, value - 25))}><ZoomOut /></Button><output aria-live="polite">{zoom}%</output><Button type="button" size="icon-sm" variant="outline" aria-label={message(locale, "screen.organizationView.81aa10b9ff7d")} disabled={zoom >= 150} onClick={() => setZoom((value) => Math.min(150, value + 25))}><ZoomIn /></Button></div>}
        {reportAllowed && <Button asChild variant="outline"><Link href={reportHref}><Download />{message(locale, "screen.organizationView.8c764577936a")}</Link></Button>}
      </div>
      <p className="org-stage-note"><strong>{directoryMode ? message(locale, "organization.directoryCurrent") : stageLabel(stage, locale)}.</strong> {directoryMode ? message(locale, "organization.directorySource") : stage === "proposal" ? message(locale, "screen.organizationView.c959516274b4") : message(locale, "screen.organizationView.ba7fa049e219")}</p>
    </section>
    {query.isError ? <Alert variant="destructive"><Network /><AlertTitle>{message(locale, "organization.loadFailure")}</AlertTitle><AlertDescription>{message(locale, "screen.organizationView.7936df30306d")}</AlertDescription></Alert> : securedItems.length === 0 ? <section className="surface-card"><EmptyState locale={locale} icon={Network} title={message(locale, "organization.empty")} /></section> : <>
      {decryptError ? <Alert variant="destructive"><LockKeyhole /><AlertTitle>{message(locale, "organization.cryptoUnavailable")}</AlertTitle><AlertDescription>{decryptError}</AlertDescription></Alert> : null}
      <section className={`org-overview${directoryMode ? " directory" : ""}`}>
        {directoryMode ? <>
          <div><span><Building2 /></span><p>{message(locale, "organization.departments")}</p><strong>{directoryInsights.departments}</strong><small>{message(locale, "organization.directoryOfficial")}</small></div>
          <div><span><UsersRound /></span><p>{message(locale, "organization.uniquePeople")}</p><strong>{directoryInsights.people}</strong><small>{message(locale, "organization.directoryOfficial")}</small></div>
          <div><span><CheckCircle2 /></span><p>{message(locale, "organization.appointments")}</p><strong>{directoryInsights.appointments}</strong><small>{message(locale, "organization.directoryOfficial")}</small></div>
          <div><span><ShieldCheck /></span><p>{message(locale, "organization.leadership")}</p><strong>{directoryInsights.leadership}</strong><small>{message(locale, "organization.directoryLeadershipHelp")}</small></div>
          <div><span><Link2 /></span><p>{message(locale, "organization.multiRolePeople")}</p><strong>{directoryInsights.multiRolePeople}</strong><small>{message(locale, "organization.directoryMultiRoleHelp")}</small></div>
        </> : <>
        <div><span><Building2 /></span><p>{message(locale, "organization.structure")}</p><strong>{totals.total}</strong><small>{message(locale, "organization.applicableResponsibilities")}</small></div>
        <div><span><UserRound /></span><p>{message(locale, "organization.withPerson")}</p><strong>{totals.occupied}</strong><small>{stageLabel(stage, locale)}</small></div>
        <div><span><CheckCircle2 /></span><p>{stage === "elected" ? message(locale, "organization.electionRecorded") : message(locale, "screen.organizationView.5fde22234e8c")}</p><strong>{stage === "elected" ? totals.elected : totals.recommended}</strong><small>{message(locale, "organization.electionDifferentiated")}</small></div>
        <div><span><UsersRound /></span><p>{message(locale, "screen.organizationView.5a86da5ba888")}</p><strong>{totals.independent}</strong><small>{message(locale, "screen.organizationView.279be1c1739e")}</small></div>
        <div><span><Link2 /></span><p>{message(locale, "screen.organizationView.5d762c6326d6")}</p><strong>{totals.linked}</strong><small>{message(locale, "screen.organizationView.e0e1caa811e5")}</small></div>
        </>}
      </section>
      <p className="sr-only" aria-live="polite">{message(locale, "screen.organizationView.36f4fb078971", { value0: filtered.length })}</p>
      {filtered.length === 0 ? <section className="surface-card"><EmptyState locale={locale} icon={Search} title={message(locale, "screen.organizationView.63d7859af2a5")} /></section> : layout === "graph" ? <div className="org-zoom-viewport"><section className="org-tree" aria-label={message(locale, "organization.byDepartmentAria")} style={{ zoom: `${zoom}%` }}>
        <div className="org-root"><span className="brand-mark">N</span><div><small>{cycleLabel}</small><strong>{session.tenant.name}</strong><span>{stageLabel(stage, locale)}</span></div><Badge>{grouped.length} {message(locale, "organization.areas")}</Badge></div>
        <div className="org-branches">{grouped.map(([departmentName, assignments]) => <section key={departmentName} className="org-department"><header><span><Building2 /></span><div><small>{message(locale, "organization.departmentMinistry")}</small><h2>{departmentName}</h2></div><Badge variant="outline">{assignments.length}</Badge></header><div className="org-roles">{assignments.map((item) => <AssignmentCard key={item.id} item={item} locale={locale} workload={item.memberId ? workload.get(item.memberId) : undefined} />)}</div></section>)}</div>
      </section></div> : <section className="org-accessible-list" aria-label={message(locale, "screen.organizationView.3a6abd40fe82")}>{grouped.map(([departmentName, assignments]) => <details key={departmentName} open><summary><span><Building2 aria-hidden="true" /></span><strong>{departmentName}</strong><Badge variant="outline">{assignments.length}</Badge><ChevronDown aria-hidden="true" /></summary><div>{assignments.map((item) => <AssignmentCard compact key={item.id} item={item} locale={locale} workload={item.memberId ? workload.get(item.memberId) : undefined} />)}</div></details>)}</section>}
      <section className="org-legend surface-card" aria-label={message(locale, "organization.legendAria")}>{Object.entries(statusLabels[locale]).filter(([statusValue]) => statusValue !== "not_configured").map(([statusValue, label]) => <span key={statusValue}><i className={statusClass(statusValue)} />{label}</span>)}<span><Link2 /> {message(locale, "screen.organizationView.b66355564515")}</span></section>
    </>}
  </>;
}
