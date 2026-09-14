"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle, BarChart3, BookOpenText, Check, ChevronRight, CircleCheck,
  Clock3, Fingerprint, KeyRound, Languages, Link2, ListChecks, Search,
  ShieldAlert, ShieldCheck, Users, Vote,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useVault } from "@/app/providers";
import {
  CandidateVoteAnalytics,
  DepartmentProgressAnalytics,
  ResponsibilityDistributionAnalytics,
  RoundParticipationAnalytics,
  SessionEvolutionAnalytics,
} from "@/components/nombramientos/analytics-charts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { api, apiRequest, ApiError, type AuthenticatedSession, type DashboardData, type Envelope, type Locale, type OrganizationRecord } from "@/lib/api";
import { openJsonEnvelope } from "@/lib/historical-envelope";
import { organizationWorkload } from "@/lib/organization-model";
import { message, localizedName, phaseLabel } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";
import { MembersView } from "./members-view";
import { CustodyView } from "./custody-view";
import { AccessibilityPreferencesPanel } from "./accessibility-preferences";
import { AccessConsole } from "./access-console";
import { PlatformConsole } from "./platform-console";
import { OrganizationView } from "./organization-view";
import { ReportsView } from "./reports-view";
import { RoundView } from "./round-view";
import { WorkflowConsole } from "./workflow-console";
import { KeyLifecycleView } from "./key-lifecycle-view";
import { CatalogManagerView } from "./catalog-view";

function catalogValueLabel(locale: Locale, value: string): string {
  const normalized = value.trim().toUpperCase().replaceAll("-", "_").replaceAll(" ", "_");
  const labels: Record<string, Parameters<typeof message>[1]> = {
    ACTIVE: "screen.workspaceView.901bb448bee7", APPLICABLE: "screen.workspaceView.a9a9572132c6", INACTIVE: "screen.workspaceView.5bdf59165f23",
    CANONICAL: "screen.workspaceView.ca6695050194", LOCAL: "screen.workspaceView.20b9c57fa29b", REAL: "screen.workspaceView.0a7c7aceb8fb", DEMO: "screen.workspaceView.59f5eb014e96", APPROVED: "screen.workspaceView.ef2ecb22f2f1",
    REVIEWED: "screen.workspaceView.8871c7fb1ee6", REVIEW_PENDING: "screen.workspaceView.8f0c5c3bb8a5", PENDING_REVIEW: "screen.workspaceView.8f0c5c3bb8a5",
    NOMINATING_COMMITTEE: "screen.workspaceView.1d02b8881f4e", LOCAL_CHURCH_ELECTION: "screen.workspaceView.a3d29225cb07",
    BOARD_APPOINTMENT: "screen.workspaceView.5856c472a13f", EX_OFFICIO: "screen.workspaceView.a7ac464cb858",
  };
  const label = labels[normalized];
  return label ? message(locale, label) : value.replaceAll("_", " ");
}

function committeeValueLabel(locale: Locale, value: string): string {
  const normalized = value.trim().toUpperCase().replaceAll("-", "_").replaceAll(" ", "_");
  const labels: Record<string, Parameters<typeof message>[1]> = {
    MEMBER: "screen.workspaceView.61854ff3e331", VOTING_MEMBER: "screen.workspaceView.b4824e81939e", CHAIR: "screen.workspaceView.89d5e0367cc6",
    SECRETARY: "screen.workspaceView.a8e5562c03b7", ADVISOR: "screen.workspaceView.8b645bb6cb60", EX_OFFICIO: "screen.workspaceView.a7ac464cb858",
  };
  const label = labels[normalized];
  return label ? message(locale, label) : value.replaceAll("_", " ");
}

function aggregateDecisionLabel(locale: Locale, value: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    SELECTED: "screen.workspaceView.2601940352b5", PARTIAL_SELECTION: "screen.workspaceView.f608e2e04f38",
    TIEBREAK_REQUIRED: "screen.workspaceView.5e261568d787", NO_SELECTION: "screen.workspaceView.1539434f3232",
  };
  const label = labels[value];
  return label ? message(locale, label) : value.replaceAll("_", " ");
}

function aggregateDecisionReasonLabel(locale: Locale, value: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    TOP_K: "screen.workspaceView.9cfe556dd31c",
    CUTOFF_TIE: "screen.workspaceView.6b1b66583743",
    NO_VALID_CANDIDATE_VOTES: "screen.workspaceView.debbf3fef057",
    THRESHOLD_NOT_MET: "screen.workspaceView.f2ec5edeb7c6",
    INSUFFICIENT_QUALIFIED_CANDIDATES: "screen.workspaceView.d5f003b35254",
  };
  const label = labels[value];
  return label ? message(locale, label) : value.replaceAll("_", " ");
}

function aggregateRuleLabel(locale: Locale, value: string): string {
  if (value === "PLURALITY") return message(locale, "screen.workspaceView.d576567e1e43");
  if (value === "STRICT_MAJORITY") return message(locale, "screen.workspaceView.c1d352c86cf3");
  return value.replaceAll("_", " ");
}

function auditActionLabel(locale: Locale, value: string): string {
  const normalized = value.toUpperCase().replaceAll(".", "_").replaceAll("-", "_");
  const labels: Record<string, Parameters<typeof message>[1]> = {
    MEMBER_CREATED: "screen.workspaceView.3b84d8027a21", MEMBER_UPDATED: "screen.workspaceView.a0d2d426c010", MEMBER_ARCHIVED: "screen.workspaceView.9fdf946ee15c",
    MEMBER_REACTIVATED: "screen.workspaceView.18ca6db96d5f", MEMBER_PHOTO_UPDATED: "screen.workspaceView.1c8c6e5e651f", MEMBER_PHOTO_REMOVED: "screen.workspaceView.e5bd6508962d",
    MEMBER_IMPORT_PREVIEWED: "screen.workspaceView.8b216e97fca9", MEMBER_IMPORT_COMMITTED: "screen.workspaceView.9389b227b4af",
    PROPOSAL_SUBMITTED: "screen.workspaceView.3a23343f02c2", BALLOT_SUBMITTED: "screen.workspaceView.2b2692e9ca6c",
    ROUND_OPENED: "screen.workspaceView.7176dffd4065", ROUND_CLOSED: "screen.workspaceView.ca7f104f62e2",
    ASSIGNMENT_CREATED: "screen.workspaceView.c845ca2a9a9f", ASSIGNMENT_UPDATED: "screen.workspaceView.17aadd053385",
    SESSION_CREATED: "screen.workspaceView.3c210340279b", SESSION_REVOKED: "screen.workspaceView.235c25e63c6c",
    TENANT_CREATED: "screen.workspaceView.91dec2e715d1", TENANT_UPDATED: "screen.workspaceView.e999aef6c4ef",
    ACCESS_ROLE_CREATED: "screen.workspaceView.d697b73e7917", ACCESS_ROLE_UPDATED: "screen.workspaceView.78cb04bd3e34", ACCESS_BINDING_GRANTED: "screen.workspaceView.d496a9b8978c", ACCESS_BINDING_REVOKED: "screen.workspaceView.001c617fe94c",
    CATALOG_DEPARTMENT_CREATED: "screen.workspaceView.3b5138f5f8c6", CATALOG_DEPARTMENT_UPDATED: "screen.workspaceView.6d5c19413a2c", CATALOG_OFFICE_CREATED: "screen.workspaceView.e11b3ebc2c33", CATALOG_OFFICE_UPDATED: "screen.workspaceView.93e4b0c7d462",
    REPORT_REQUESTED: "screen.workspaceView.b860dace58cc", REPORT_READY: "screen.workspaceView.c925543aae54", REPORT_FAILED: "screen.workspaceView.35c7827a4c3c", REPORT_DOWNLOADED: "screen.workspaceView.88b0282a567d", REPORT_PRINTED: "screen.workspaceView.79fe1231feb5",
    CUSTODY_KEY_REGISTERED: "screen.workspaceView.4512bf43f9e9", CUSTODY_KEY_ROTATED: "screen.workspaceView.5f1357d6032f", CUSTODY_KEY_REVOKED: "screen.workspaceView.e3d26a05c7f4",
    CUSTODY_ROUND_FROZEN: "screen.workspaceView.6f45dccdf77f", CUSTODY_MANIFEST_CREATED: "screen.workspaceView.426772b245b5", CUSTODY_ATTESTATION_RECORDED: "screen.workspaceView.fc0bfde8f9dc", CUSTODY_AGGREGATE_PUBLISHED: "screen.workspaceView.065661381ded",
    KEY_DEVICE_REGISTERED: "screen.workspaceView.9a04425c015f", KEY_DEVICE_APPROVED: "screen.workspaceView.4721a083861b", KEY_GRANT_REVOKED: "screen.workspaceView.71431bcc2f03", KEY_GENERATION_ROTATED: "screen.workspaceView.c88616a99a71", KEY_RECOVERY_COMPLETED: "screen.workspaceView.884a59be24f1",
    CYCLE_CREATED: "screen.workspaceView.b60d01d48fc7", CYCLE_UPDATED: "screen.workspaceView.50d8750bba6a", CYCLE_CLONED: "screen.workspaceView.92c361c22f25", WORKFLOW_PAUSED: "screen.workspaceView.171c75e18086",
    MEMBERS_IMPORT_COMMITTED: "screen.workspaceView.9389b227b4af", TENANT_SETTINGS_UPDATED: "screen.workspaceView.9d40d9bdb98e",
    ROUND_SUBMISSION_RECEIVED: "screen.workspaceView.de02fb0fb139", ROUND_PARTICIPATION_READ: "screen.workspaceView.c687f9a2fadc",
    ASSIGNMENT_ACTIVATED: "screen.workspaceView.249ec5ae9946", ASSIGNMENT_CONGREGATIONAL_DECISION_RECORDED: "screen.workspaceView.75554e91ccec", ASSIGNMENT_CONSENT_RECORDED: "screen.workspaceView.9828adfa0868", ASSIGNMENT_HISTORY_READ: "screen.workspaceView.157be70143f4", ASSIGNMENT_PRESENTED: "screen.workspaceView.ccfcab03973c", ASSIGNMENTS_PROVISIONAL_CREATED: "screen.workspaceView.ec4891b7f747",
    BALLOT_ROUND_PREPARED: "screen.workspaceView.febb2c3b381e", BALLOT_ROUND_OPENED: "screen.workspaceView.8b6512e43318", PROPOSAL_ROUND_PREPARED: "screen.workspaceView.7f546e622ff8", PROPOSAL_ROUND_OPENED: "screen.workspaceView.500e653ffd04", TIEBREAK_ROUND_PREPARED: "screen.workspaceView.e666c6de7d2a",
    CANDIDACY_REVIEWED: "screen.workspaceView.64a29b5defde", CANDIDATE_LIST_CONFIRMED: "screen.workspaceView.63f03a9ef392", PROPOSALS_CONSOLIDATED: "screen.workspaceView.2e5bc0ee35aa",
    COMMITTEE_CONFIGURED: "screen.workspaceView.103bff51a215", ELECTORATE_CONFIGURED: "screen.workspaceView.900c9225ebdc", VACANCY_PROCESS_CONFIGURED: "screen.workspaceView.bb0e37d9cd7c", OFFICE_PROCESS_TALLY_SYNCHRONIZED: "screen.workspaceView.1702c56a1aff",
    CYCLE_ACTIVATED: "screen.workspaceView.be5f8e86ab54", CYCLE_ARCHIVED: "screen.workspaceView.73f0fccacc63", CYCLE_CLOSED: "screen.workspaceView.725de4e54550", CYCLE_SESSION_CREATED: "screen.workspaceView.71ff3deac463",
    SESSION_AGENDA_CREATED: "screen.workspaceView.da3ccce05cc5", SESSION_AGENDA_REORDERED: "screen.workspaceView.92b07f178e56", SESSION_ATTENDANCE_RECORDED: "screen.workspaceView.efa3322450b5", SESSION_DECISION_RECORDED: "screen.workspaceView.06cae11159b6", SESSION_UPDATED: "screen.workspaceView.2d79587230e8",
    PROPOSAL_MANIFEST_CREATED: "screen.workspaceView.fe8f49e3a0cc", PROPOSAL_MANIFEST_READ: "screen.workspaceView.0680a7f14cec", WORKFLOW_REPORT_SNAPSHOT_READ: "screen.workspaceView.f207eb43c4c2",
    CUSTODY_MANIFEST_ATTESTED: "screen.workspaceView.544e21bfcb4f",
    E2EE_CHALLENGE_ISSUED: "screen.workspaceView.2c076bcced36", E2EE_DEVICE_REGISTERED: "screen.workspaceView.9a04425c015f", E2EE_GRANT_APPROVED: "screen.workspaceView.c1b6a789631d", E2EE_GRANT_REVOKED: "screen.workspaceView.71431bcc2f03", E2EE_KEY_INITIALIZED: "screen.workspaceView.4539bc80a3ee", E2EE_KEY_PERMANENTLY_LOST: "screen.workspaceView.401cd693030a", E2EE_KEY_RECOVERED: "screen.workspaceView.15bdf7ccfabc", E2EE_KEY_ROTATED: "screen.workspaceView.917347560ad9",
    MEMBER_PHOTO_ARCHIVED: "screen.workspaceView.2c5cc42ababf", MEMBER_PHOTO_READ: "screen.workspaceView.58a1e2a6d59b",
  };
  const label = labels[normalized];
  return label ? message(locale, label) : value.replaceAll("_"," ").replaceAll("."," · ");
}

function entityTypeLabel(locale: Locale, value: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    member: "screen.workspaceView.b792923baa6a", proposal: "screen.workspaceView.644b20b407ec", ballot: "screen.workspaceView.d924ed21bf4b",
    round: "screen.workspaceView.6dbb1275b1bc", assignment: "screen.workspaceView.c3751b999b69", tenant: "screen.workspaceView.dd287562c7af", session: "screen.workspaceView.cd60d00a1dd0",
    committee: "screen.workspaceView.5abcb28f2788", cycle: "screen.workspaceView.e5992ae2b006", election_cycle: "screen.workspaceView.e5992ae2b006", office_process: "screen.workspaceView.470c31567aac",
    role: "screen.workspaceView.2f7980a7df73", access_role: "screen.workspaceView.2f7980a7df73", identity: "screen.workspaceView.d544eec0d239", access_binding: "screen.workspaceView.98d38ad35f77",
    department: "screen.workspaceView.a9c1f5f4089f", office: "screen.workspaceView.94977dfd3c65", report: "screen.workspaceView.5bb5a3ced508", import: "screen.workspaceView.c05b6832522d",
    device: "screen.workspaceView.847450f6d823", key_grant: "screen.workspaceView.feab44ef08a5", key_generation: "screen.workspaceView.b0ecb2cc6e4f", custodian_key: "screen.workspaceView.427c8a7bd374", tally_manifest: "screen.workspaceView.7a386f478efd",
    cycle_session: "screen.workspaceView.76e6db56ce43", proposal_manifest: "screen.workspaceView.c2198fd12232", proposal_aggregate: "screen.workspaceView.55853bedc06f", candidacy: "screen.workspaceView.f538cb19ab12", candidate_list: "screen.workspaceView.f5505cb53b18", key_challenge: "screen.workspaceView.9b8b2aabda92",
  };
  const label=labels[value.toLocaleLowerCase()];
  return label?message(locale, label):value.replaceAll("_"," ");
}

function LoadingBlock({ label, locale = "es" }: { label?: string; locale?: Locale }) {
  const visibleLabel = label ?? message(locale, "screen.workspaceView.99f6ac274019");
  return <div className="loading-block" role="status"><span className="loading-line w-32" /><span className="loading-line h-9 w-72" /><span className="loading-line h-40 w-full" /><span className="sr-only">{visibleLabel}</span></div>;
}

function DataError({ title, locale = "es" }: { title?: string; locale?: Locale }) {
  const visibleTitle = title ?? message(locale, "screen.workspaceView.8cbe1542135f");
  return <Alert><AlertTriangle /><AlertTitle>{visibleTitle}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.e3f0f5835ad4")}</AlertDescription></Alert>;
}

function percent(value: number | null, locale: Locale) {
  return value === null
    ? message(locale, "screen.workspaceView.14a82ef6df2a")
    : `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value)} %`;
}

function dashboardPeriod(data: DashboardData, locale: Locale): string {
  return data.cycle ? `${data.cycle.termStart} — ${data.cycle.termEnd}` : message(locale, "screen.workspaceView.14a82ef6df2a");
}

function MetricMeta({ locale, timeZone, period, phase, filter, denominator, version, updatedAt }: {
  locale: Locale;
  timeZone: string;
  period: string;
  phase: string;
  filter: string;
  denominator: string | number | null;
  version: string;
  updatedAt: string;
}) {
  const denominatorLabel = denominator === null || denominator === 0 ? message(locale, "screen.workspaceView.14a82ef6df2a") : denominator;
  return <dl className="mt-3 grid gap-1 border-t border-slate-200 pt-3 text-xs text-slate-600 sm:grid-cols-2">
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.0d4ee1b91101")}</dt><dd>{period}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.1d4ee1b91102")}</dt><dd>{phase}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.2d4ee1b91103")}</dt><dd>{filter}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.3d4ee1b91104")}</dt><dd>{denominatorLabel}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.4d4ee1b91105")}</dt><dd>{version}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.workspaceView.5d4ee1b91106")}</dt><dd>{formatInTenantTimeZone(updatedAt, locale, timeZone, { dateStyle: "short", timeStyle: "short" })}</dd></div>
  </dl>;
}

function MetricCard({ icon: Icon, label, value, detail, tone, progress, locale, meta }: { icon: typeof Users; label: string; value: string | number; detail: string; tone: string; progress?: number | null; locale: Locale; meta: ReactNode }) {
  return <article className="metric-card"><span className={`metric-icon ${tone}`}><Icon size={19} /></span><p>{label}</p><strong>{value} <small>{detail}</small></strong><div className="metric-footer">{progress !== undefined ? typeof progress === "number" ? <><Progress value={progress} className="h-1.5" /><span>{percent(progress, locale)}</span></> : <span className="text-slate-500">{percent(null, locale)}</span> : <span className="text-slate-500">{detail}</span>}</div>{meta}</article>;
}

type DashboardOrganizationItem = OrganizationRecord & {
  departmentId?: string;
  independent?: boolean;
  memberSnapshot?: { displayEnvelope?: Envelope } | null;
};

function ResponsibilityDistribution({ locale, session, data }: { locale: Locale; session: AuthenticatedSession; data: DashboardData }) {
  const vault = useVault();
  const allowed = session.permissions.includes("organigram.read");
  const query = useQuery({
    queryKey: ["dashboard-organization", session.tenant.id, "proposal"],
    queryFn: () => apiRequest<{ items: DashboardOrganizationItem[] }>("/v1/organization?stage=proposal"),
    enabled: allowed,
    retry: false,
  });
  const [items, setItems] = useState<Array<DashboardOrganizationItem & { displayName?: string }>>([]);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      if (!allowed || !query.data || !vault.key || !vault.keyId) {
        if (!cancelled) setItems([]);
        return;
      }
      setDecrypting(true);
      setDecryptError(false);
      try {
        let hadFailures = false;
        const visible = await Promise.all(query.data.items.map(async (item) => {
          const localized = {
            ...item,
            officeName: localizedName(item.officeNames, locale, item.officeName),
            departmentName: localizedName(item.departmentNames, locale, item.departmentName),
          };
          if (!item.memberId) return localized;
          const displayEnvelope = item.memberSnapshot?.displayEnvelope ?? item.displayEnvelope;
          try {
            if (!displayEnvelope) throw new Error("ASSIGNMENT_SNAPSHOT_MISSING");
            const profile = await openJsonEnvelope<{ displayName?: string; firstName?: string; lastName?: string }>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: item.memberId, purpose: "member-display", schemaVersion: 1 },
            });
            const displayName = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!displayName) throw new Error("ASSIGNMENT_DISPLAY_NAME_MISSING");
            return { ...localized, displayName };
          } catch {
            hadFailures = true;
            return { ...localized, displayName: message(locale, "screen.workspaceView.3856c994f99d") };
          }
        }));
        if (!cancelled) {
          setItems(visible);
          setDecryptError(hadFailures);
        }
      } catch {
        if (!cancelled) {
          setItems([]);
          setDecryptError(true);
        }
      } finally {
        if (!cancelled) setDecrypting(false);
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [allowed, locale, query.data, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  const workload = useMemo(() => organizationWorkload(items), [items]);
  const names = useMemo(() => new Map(items.filter((item) => item.memberId && item.displayName).map((item) => [item.memberId!, item.displayName!] as const)), [items]);
  const accumulated = useMemo(() => [...workload.entries()].filter(([, summary]) => summary.total > 1).sort((left, right) => (names.get(left[0]) ?? left[0]).localeCompare(names.get(right[0]) ?? right[0], locale)), [locale, names, workload]);

  if (!allowed) return null;
  if (query.isLoading) return <section className="surface-card"><LoadingBlock locale={locale} label={message(locale, "screen.workspaceView.b05303cc76d0")} /></section>;
  if (query.isError || !query.data) return <section className="surface-card"><DataError locale={locale} title={message(locale, "screen.workspaceView.29c7c1c7f1fe")} /></section>;
  return <>
    <ResponsibilityDistributionAnalytics items={query.data.items} data={data} locale={locale} timeZone={session.tenant.timezone} />
    <section className="surface-card" aria-labelledby="responsibility-detail-title">
    <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workspaceView.16ec29ecb429")}</p><h2 id="responsibility-detail-title">{message(locale, "screen.workspaceView.39a047bd9adb")}</h2><p>{message(locale, "screen.workspaceView.51cee99764e0")}</p></div><Badge variant="outline">{accumulated.length} {message(locale, "screen.workspaceView.a0bfef39bc52")}</Badge></div>
    {decrypting ? <LoadingBlock locale={locale} label={message(locale, "screen.workspaceView.e30992ae6cf5")} />
      : !vault.key ? <Alert><KeyRound /><AlertTitle>{message(locale, "screen.workspaceView.22b980c8e3f9")}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.6dd7c9b60d3b")}</AlertDescription></Alert>
        : <>{decryptError ? <Alert variant="destructive"><ShieldAlert /><AlertTitle>{message(locale, "screen.workspaceView.f048a57150df")}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.8e1c39110c34")}</AlertDescription></Alert> : null}
          {accumulated.length === 0 ? <p className="stage-disclaimer">{message(locale, "screen.workspaceView.ab07348c2855")}</p>
            : <div className="grid gap-3 lg:grid-cols-2">{accumulated.map(([memberId, summary]) => <article key={memberId} className={`rounded-2xl border p-4 ${summary.independent > 1 ? "border-amber-300 bg-amber-50/70" : "border-cyan-200 bg-cyan-50/50"}`}>
                <div className="flex flex-wrap items-start justify-between gap-3"><div><strong>{names.get(memberId)}</strong><p className="text-sm text-slate-600">{summary.independent} {message(locale, "screen.workspaceView.c802ebb59442")} · {summary.linked} {message(locale, "screen.workspaceView.61edffac58a3")}</p></div>{summary.independent > 1 ? <Badge variant="destructive"><ShieldAlert /> {message(locale, "screen.workspaceView.03cb9be88208")}</Badge> : <Badge variant="outline"><Link2 /> {message(locale, "screen.workspaceView.6e64f3d0d64f")}</Badge>}</div>
                <ul className="mt-3 grid gap-2">{summary.responsibilities.map((responsibility) => <li key={responsibility.assignmentId} className="rounded-xl bg-white/90 px-3 py-2 text-sm"><span className="font-semibold text-slate-900">{responsibility.officeName}</span><small className="block text-slate-500">{responsibility.departmentName} · {responsibility.linked ? message(locale, "screen.workspaceView.a51a2451c8fc") : message(locale, "screen.workspaceView.2c28359c81a5")}</small></li>)}</ul>
              </article>)}</div>}</>}
    </section>
  </>;
}

function OverviewView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const query = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard, refetchInterval: 15_000 });
  if (query.isLoading) return <LoadingBlock locale={locale} />;
  if (!query.data) return <DataError locale={locale} title={message(locale, "screen.workspaceView.4d9791c262b3")} />;
  const data = query.data;
  const empty = data.metrics.membersTotal === 0 && !data.cycle;
  const stages = [
    [message(locale, "screen.workspaceView.e2863c83371d"), data.metrics.recommended],
    [message(locale, "screen.workspaceView.12921163520d"), data.metrics.accepted],
    [message(locale, "screen.workspaceView.6eb74c1b9b68"), data.metrics.congregationallyElected],
  ] as const;
  const metricMeta = {
    locale,
    timeZone: session.tenant.timezone,
    period: dashboardPeriod(data, locale),
    filter: `${data.cycle?.name ?? message(locale, "screen.workspaceView.390f54c5f235")} · ${message(locale, "screen.workspaceView.ad4ee1b91111")}`,
    version: `v${data.cycle?.version ?? 0}`,
    updatedAt: data.updatedAt,
  };
  return <>
    <div className="page-heading"><div><p className="eyebrow">{formatInTenantTimeZone(new Date(), locale, session.tenant.timezone, { dateStyle: "full" })}</p><h1>{session.tenant.name}</h1><p>{empty ? message(locale, "screen.workspaceView.0e68d81ab1c3") : message(locale, "screen.workspaceView.45231de1619c")}</p></div><Badge variant="outline" className="connection-pill"><span className="status-dot" /> {message(locale, "screen.workspaceView.6bfde7ed2be3")} {formatInTenantTimeZone(data.updatedAt, locale, session.tenant.timezone, { timeStyle: "short" })}</Badge></div>
    {session.tenant.kind === "demo" && <Alert className="demo-notice"><ShieldCheck /><AlertTitle>{message(locale, "screen.workspaceView.b0867d1a2e80")}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.a01eb1713a00")}</AlertDescription></Alert>}
    {empty ? <OnboardingView locale={locale} session={session} embedded /> : <>
      {data.activeRound ? <ActiveRoundCard data={data} locale={locale} timeZone={session.tenant.timezone} /> : <Alert><Clock3 /><AlertTitle>{message(locale, "screen.workspaceView.4cf16f46d56c")}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.d60e51c12422")}</AlertDescription></Alert>}
      <div className="metrics-grid">
        <MetricCard locale={locale} icon={CircleCheck} label={message(locale, "screen.workspaceView.e713fed49470")} value={data.metrics.recommended} detail={`${message(locale, "screen.workspaceView.2fd307b171ad")} ${data.metrics.vacanciesTotal}`} tone="cyan" progress={data.metrics.coveragePercent} meta={<MetricMeta {...metricMeta} phase={message(locale, "screen.workspaceView.e2863c83371d")} denominator={data.metrics.vacanciesTotal || null} />} />
        <MetricCard locale={locale} icon={Users} label={message(locale, "screen.workspaceView.4b0a04428b7d")} value={data.metrics.eligibleReference} detail={message(locale, "screen.workspaceView.9d4ee1b91110")} tone="indigo" meta={<MetricMeta {...metricMeta} phase={message(locale, "screen.workspaceView.8d4ee1b91109")} denominator={null} />} />
        <MetricCard locale={locale} icon={Users} label={message(locale, "screen.workspaceView.6d4ee1b91107")} value={data.metrics.membersTotal} detail={message(locale, "screen.workspaceView.7d4ee1b91108")} tone="indigo" meta={<MetricMeta {...metricMeta} phase={message(locale, "screen.workspaceView.6d4ee1b91107")} denominator={null} />} />
        <MetricCard locale={locale} icon={BarChart3} label={message(locale, "screen.workspaceView.fb8a592f14ae")} value={data.metrics.congregationallyElected} detail={`${data.metrics.accepted} ${message(locale, "screen.workspaceView.c01225e64235")}`} tone="gold" meta={<MetricMeta {...metricMeta} phase={message(locale, "screen.workspaceView.6eb74c1b9b68")} denominator={data.metrics.vacanciesTotal || null} />} />
      </div>
      <DepartmentProgressAnalytics data={data} locale={locale} timeZone={session.tenant.timezone} />
      <ResponsibilityDistribution locale={locale} session={session} data={data} />
      <SessionEvolutionAnalytics data={data} locale={locale} timeZone={session.tenant.timezone} />
      <section className="work-grid"><article className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workspaceView.03798d1ef0f7")}</p><h2>{message(locale, "screen.workspaceView.a1af65d7c909")}</h2></div></div><ol className="status-rail">{stages.map(([item,count],index)=><li key={item} className={count>0?"done":""}><span>{count>0?<Check/>:index+1}</span><div><strong>{item}</strong><small>{count>0?`${count} ${message(locale, "screen.workspaceView.b2d4b232d505")}`:message(locale, "screen.workspaceView.1ef848157e8a")}</small></div></li>)}</ol><p className="stage-disclaimer">{message(locale, "screen.workspaceView.cad620ded68a")}</p></article><aside className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workspaceView.5822a57f6f63")}</p><h2>{data.cycle?.name ?? message(locale, "screen.workspaceView.390f54c5f235")}</h2></div><strong className="text-xl text-primary">{percent(data.metrics.coveragePercent, locale)}</strong></div><dl className="summary-list"><div><dt>{message(locale, "screen.workspaceView.91eea5daa3f0")}</dt><dd>{data.metrics.vacanciesTotal}</dd></div><div><dt>{message(locale, "screen.workspaceView.2de0ec02a2d6")}</dt><dd>{data.metrics.recommended}</dd></div><div><dt>{message(locale, "screen.workspaceView.544908351f2c")}</dt><dd>{data.metrics.accepted}</dd></div><div><dt>{message(locale, "screen.workspaceView.fb8a592f14ae")}</dt><dd>{data.metrics.congregationallyElected}</dd></div></dl><MetricMeta {...metricMeta} phase={catalogValueLabel(locale, data.cycle?.status ?? "draft")} denominator={data.metrics.vacanciesTotal || null} /></aside></section>
    </>}
  </>;
}

function ActiveRoundCard({ data, locale, timeZone }: { data: DashboardData; locale: Locale; timeZone: string }) {
  const round = data.activeRound!;
  const participation = round.responsesRequired ? (round.responsesReceived / round.responsesRequired) * 100 : null;
  return <section className="active-session" aria-labelledby="active-session-title"><div className="session-accent" aria-hidden="true" /><div className="session-main"><div className="flex flex-wrap items-center gap-2"><Badge className="phase-badge">{phaseLabel(locale, round.phase)}</Badge><span className="text-sm text-slate-500">{message(locale, "screen.workspaceView.bc3e4cb0fd34")} · {round.responsesRequired} {message(locale, "screen.workspaceView.15ed228028af")}</span></div><p className="mt-5 text-sm font-medium text-cyan-900">{message(locale, "screen.workspaceView.499015ba14e5")}</p><h2 id="active-session-title">{localizedName(round.officeNames, locale, round.officeName)}</h2><p className="mt-2 max-w-2xl text-slate-600">{message(locale, "screen.workspaceView.6dcf810a4fcb")}</p><div className="session-stats"><div><span>{message(locale, "screen.workspaceView.c614ea57e3e5")}</span><strong>{round.responsesReceived} {message(locale, "screen.workspaceView.2fd307b171ad")} {round.responsesRequired}</strong></div><div><span>{message(locale, "screen.workspaceView.46d13efc67c6")}</span><strong>{Math.max(0, round.responsesRequired-round.responsesReceived)}</strong></div><div><span>{message(locale, "screen.workspaceView.999b5bda6287")}</span><strong>{formatInTenantTimeZone(data.updatedAt, locale, timeZone, { timeStyle: "short" })}</strong></div></div>{participation !== null ? <Progress value={participation} aria-label={`${message(locale, "screen.workspaceView.c614ea57e3e5")}: ${round.responsesReceived} ${message(locale, "screen.workspaceView.2fd307b171ad")} ${round.responsesRequired}`} className="mt-5 h-2 bg-white/60" /> : <p className="mt-5 text-sm font-semibold">{message(locale, "screen.workspaceView.14a82ef6df2a")}</p>}<MetricMeta locale={locale} timeZone={timeZone} period={dashboardPeriod(data, locale)} phase={phaseLabel(locale, round.phase)} filter={localizedName(round.officeNames, locale, round.officeName)} denominator={round.responsesRequired || null} version={`v${round.version}`} updatedAt={data.updatedAt} /></div><div className="session-action"><div className="receipt-orb"><Vote size={24} /></div><div><strong>{message(locale, "screen.workspaceView.8aa9cb0a045e")}</strong><p>{message(locale, "screen.workspaceView.6cb854724506")}</p></div><Button asChild className="primary-cta"><Link href={`/${locale}/app/session`}>{message(locale, "screen.workspaceView.ff6950ae0fff")} <ChevronRight size={17} /></Link></Button></div></section>;
}

function CommitteeView({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  const vault = useVault();
  const query = useQuery({ queryKey: ["committee", session.tenant.id], queryFn: () => apiRequest<{ items: Array<Record<string, unknown>>; cycleName?: string; cycleId?: string }>("/v1/committee") });
  const [items, setItems] = useState<Array<Record<string, unknown>>>([]);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    async function run() {
      if (!query.data || !vault.key) return;
      setDecrypting(true);
      setDecryptError(false);
      try {
        let hadFailures = false;
        const visible = await Promise.all(query.data.items.map(async (item) => {
          if (!item.displayEnvelope) return item;
          const identityId = String(item.identityId ?? item.id);
          const cycleId = String(item.cycleId ?? query.data?.cycleId ?? "");
          try {
            return {
              ...item,
              ...await openJsonEnvelope<{ displayName: string }>({
                resolver: vault,
                tenantId: session.tenant.id,
                envelope: item.displayEnvelope as Envelope,
                aad: { tenantId: session.tenant.id, cycleId, identityId, purpose: "committee-display", schemaVersion: 1 },
              }),
            };
          } catch {
            hadFailures = true;
            return { ...item, displayName: message(locale, "screen.workspaceView.3856c994f99d") };
          }
        }));
        if (!cancelled) {
          setItems(visible);
          setDecryptError(hadFailures);
        }
      } finally {
        if (!cancelled) setDecrypting(false);
      }
    }
    void run();
    return () => { cancelled = true; };
  }, [locale, query.data, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);
  return <><PageTitle eyebrow={message(locale, "screen.workspaceView.9c38c7a7b8de")} title={message(locale, "screen.workspaceView.0a8f0e87e90e")} description={message(locale, "screen.workspaceView.a05a4ee7dca2")} />{query.isLoading || decrypting ? <LoadingBlock locale={locale} /> : !query.data ? <DataError locale={locale} /> : <>{decryptError ? <DataError locale={locale} title={message(locale, "screen.workspaceView.71347e60aa1b")} /> : null}<section className="surface-card"><div className="card-heading"><h2>{query.data.cycleName ?? message(locale, "screen.workspaceView.fc6e8550670c")}</h2><Badge>{items.length} {message(locale, "screen.workspaceView.709056ffbe61")}</Badge></div>{items.length ? <div className="responsive-table"><table><thead><tr><th>{message(locale, "screen.workspaceView.61854ff3e331")}</th><th>{message(locale, "screen.workspaceView.dc022ea29c25")}</th><th>{message(locale, "screen.workspaceView.acade974e70d")}</th><th>{message(locale, "screen.workspaceView.10ddb7420e5a")}</th></tr></thead><tbody>{items.map((item, index) => <tr key={String(item.id ?? index)}><td>{String(item.displayName ?? item.shortId ?? message(locale, "screen.workspaceView.3856c994f99d"))}</td><td>{committeeValueLabel(locale, String(item.role ?? "MEMBER"))}</td><td>{item.votingRight ? <Badge>{message(locale, "screen.workspaceView.b057c888cae8")}</Badge> : <Badge variant="outline">{message(locale, "screen.workspaceView.9448170c072f")}</Badge>}</td><td>{catalogValueLabel(locale, String(item.status ?? "ACTIVE"))}</td></tr>)}</tbody></table></div> : <EmptyState locale={locale} icon={Users} title={message(locale, "screen.workspaceView.e4fed12fc9f3")} />}</section></>}</>;
}

function ResultsView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const vault = useVault();
  const query = useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard });
  const roundQuery = useQuery({
    queryKey: ["active-round", session.tenant.id],
    queryFn: async () => {
      try { return await api.activeRound(); }
      catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error; }
    },
    retry: false,
  });
  const publishedQuery = useQuery({
    queryKey: ["published-aggregate", session.tenant.id, roundQuery.data?.round.id],
    queryFn: async () => {
      try { return await api.publishedAggregate(roundQuery.data!.round.id); }
      catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error; }
    },
    enabled: Boolean(roundQuery.data?.round.id && roundQuery.data.round.phase === "RESULTADO_INTERNO"),
    retry: false,
  });
  const [candidateLabels, setCandidateLabels] = useState<ReadonlyMap<string, string>>(new Map());
  const [candidateDecryptError, setCandidateDecryptError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function revealCandidateLabels(): Promise<void> {
      const active = roundQuery.data;
      if (!active || !vault.key) {
        if (!cancelled) setCandidateLabels(new Map());
        return;
      }
      try {
        let hadFailures = false;
        const values = await Promise.all(active.candidates.map(async (candidate) => {
          try {
            const profile = await openJsonEnvelope<{ displayName?: string; firstName?: string; lastName?: string; shortId?: string }>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: candidate.displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: candidate.memberId, purpose: "member-display", schemaVersion: 1 },
            });
            const displayName = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!displayName) throw new Error("CANDIDATE_DISPLAY_NAME_MISSING");
            return [candidate.id, displayName] as const;
          } catch {
            hadFailures = true;
            return [candidate.id, message(locale, "screen.workspaceView.3856c994f99d")] as const;
          }
        }));
        if (!cancelled) {
          setCandidateLabels(new Map(values));
          setCandidateDecryptError(hadFailures);
        }
      } catch {
        if (!cancelled) {
          setCandidateLabels(new Map());
          setCandidateDecryptError(true);
        }
      }
    }
    void revealCandidateLabels();
    return () => { cancelled = true; };
  }, [locale, roundQuery.data, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  if (query.isLoading) return <LoadingBlock locale={locale} />;
  if (!query.data) return <DataError locale={locale} />;
  const m = query.data.metrics;
  const resultMeta = {
    locale,
    timeZone: session.tenant.timezone,
    period: dashboardPeriod(query.data, locale),
    filter: `${query.data.cycle?.name ?? message(locale, "screen.workspaceView.390f54c5f235")} · ${message(locale, "screen.workspaceView.ad4ee1b91111")}`,
    version: `v${query.data.cycle?.version ?? 0}`,
    updatedAt: query.data.updatedAt,
  };
  return <>
    <PageTitle eyebrow={message(locale, "screen.workspaceView.583b6de0797e")} title={message(locale, "screen.workspaceView.8b55cf22f980")} description={message(locale, "screen.workspaceView.7ef4a35bc0e3")} />
    {roundQuery.isLoading || publishedQuery.isLoading ? <LoadingBlock locale={locale} label={message(locale, "screen.workspaceView.5c67b84d82e1")} /> : roundQuery.isError || publishedQuery.isError ? <DataError locale={locale} title={message(locale, "screen.workspaceView.21ba513efdbe")} /> : null}
    <div className="results-grid">
      <article className="result-hero"><p>{message(locale, "screen.workspaceView.00f84252bffb")}</p><strong>{percent(m.coveragePercent, locale)}</strong><span>{m.recommended} {message(locale, "screen.workspaceView.2fd307b171ad")} {m.vacanciesTotal} {message(locale, "screen.workspaceView.37c844e9e741")}</span>{m.coveragePercent === null ? <span>{message(locale, "screen.workspaceView.14a82ef6df2a")}</span> : <Progress value={m.coveragePercent} />}<MetricMeta {...resultMeta} phase={message(locale, "screen.workspaceView.e2863c83371d")} denominator={m.vacanciesTotal || null} /></article>
      <article className="result-stage"><span><ListChecks /></span><div><strong>{m.recommended}</strong><p>{message(locale, "screen.workspaceView.19c79a30a550")}</p></div><MetricMeta {...resultMeta} phase={message(locale, "screen.workspaceView.e2863c83371d")} denominator={m.vacanciesTotal || null} /></article>
      <article className="result-stage"><span><CircleCheck /></span><div><strong>{m.accepted}</strong><p>{message(locale, "screen.workspaceView.5b4a6c21fdd4")}</p></div><MetricMeta {...resultMeta} phase={message(locale, "screen.workspaceView.12921163520d")} denominator={m.vacanciesTotal || null} /></article>
      <article className="result-stage elected"><span><ShieldCheck /></span><div><strong>{m.congregationallyElected}</strong><p>{message(locale, "screen.workspaceView.fb8a592f14ae")}</p></div><MetricMeta {...resultMeta} phase={message(locale, "screen.workspaceView.6eb74c1b9b68")} denominator={m.vacanciesTotal || null} /></article>
    </div>
    <RoundParticipationAnalytics data={query.data} locale={locale} timeZone={session.tenant.timezone} />
    {candidateDecryptError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{message(locale, "screen.workspaceView.40b99a24b12a")}</AlertTitle><AlertDescription>{message(locale, "screen.workspaceView.54fa1a6d938b")}</AlertDescription></Alert>}
    {publishedQuery.data && roundQuery.data && !roundQuery.isError && !publishedQuery.isError && <PublishedTallyPanel locale={locale} timeZone={session.tenant.timezone} period={dashboardPeriod(query.data, locale)} round={roundQuery.data} publication={publishedQuery.data} candidateLabels={candidateLabels} />}
  </>;
}

function PublishedTallyPanel({ locale, timeZone, period, round, publication, candidateLabels }: {
  locale: Locale;
  timeZone: string;
  period: string;
  round: NonNullable<Awaited<ReturnType<typeof api.activeRound>>>;
  publication: Awaited<ReturnType<typeof api.publishedAggregate>>;
  candidateLabels: ReadonlyMap<string, string>;
}) {
  const aggregate = publication.aggregate;
  const labels = {
    es: { eyebrow: message("es", "screen.workspaceView.83d3d4740ed5"), title: message("es", "screen.workspaceView.802374660e3a"), received: message("es", "screen.workspaceView.509b06a6b11a"), ballots: message("es", "screen.workspaceView.de82511f75ca"), abstentions: message("es", "screen.workspaceView.995af184934e"), votes: message("es", "screen.workspaceView.8fbbffcc0537"), reason: message("es", "screen.workspaceView.7e50dd20c32b"), selected: message("es", "screen.workspaceView.41ed18e681b0"), tiebreak: message("es", "screen.workspaceView.c0379577b780"), unfilled: message("es", "screen.workspaceView.0253cb2bedb7"), none: message("es", "screen.workspaceView.0abf6b342335"), privacy: message("es", "screen.workspaceView.dd1207e8d5e3") },
    en: { eyebrow: message("en", "screen.workspaceView.83d3d4740ed5"), title: message("en", "screen.workspaceView.802374660e3a"), received: message("en", "screen.workspaceView.509b06a6b11a"), ballots: message("en", "screen.workspaceView.de82511f75ca"), abstentions: message("en", "screen.workspaceView.995af184934e"), votes: message("en", "screen.workspaceView.8fbbffcc0537"), reason: message("en", "screen.workspaceView.7e50dd20c32b"), selected: message("en", "screen.workspaceView.41ed18e681b0"), tiebreak: message("en", "screen.workspaceView.c0379577b780"), unfilled: message("en", "screen.workspaceView.0253cb2bedb7"), none: message("en", "screen.workspaceView.0abf6b342335"), privacy: message("en", "screen.workspaceView.dd1207e8d5e3") },
    fr: { eyebrow: message("fr", "screen.workspaceView.83d3d4740ed5"), title: message("fr", "screen.workspaceView.802374660e3a"), received: message("fr", "screen.workspaceView.509b06a6b11a"), ballots: message("fr", "screen.workspaceView.de82511f75ca"), abstentions: message("fr", "screen.workspaceView.995af184934e"), votes: message("fr", "screen.workspaceView.8fbbffcc0537"), reason: message("fr", "screen.workspaceView.7e50dd20c32b"), selected: message("fr", "screen.workspaceView.41ed18e681b0"), tiebreak: message("fr", "screen.workspaceView.c0379577b780"), unfilled: message("fr", "screen.workspaceView.0253cb2bedb7"), none: message("fr", "screen.workspaceView.0abf6b342335"), privacy: message("fr", "screen.workspaceView.dd1207e8d5e3") },
  }[locale];
  const candidateNames = new Map(round.candidates.map((candidate) => [
    candidate.id,
    candidateLabels.get(candidate.id) ?? candidate.shortId ?? candidate.id.slice(0, 8),
  ]));
  const selected = new Set(aggregate.decision.selectedCandidateIds);
  const tiebreak = new Set(aggregate.decision.tiebreakCandidateIds);
  const listNames = (ids: readonly string[]) => ids.length > 0 ? ids.map((id) => candidateNames.get(id) ?? id.slice(0, 8)).join(", ") : labels.none;
  const voteDenominator = aggregate.nonAbstainingBallots;
  const voteCandidates = aggregate.candidates.map((candidate) => ({
    ...candidate,
    label: candidateNames.get(candidate.candidateId) ?? candidate.candidateId.slice(0, 8),
  }));
  return <section className="surface-card published-tally">
    <div className="card-heading"><div><p className="eyebrow">{labels.eyebrow}</p><h2>{labels.title}</h2></div><Badge><ShieldCheck /> {aggregateDecisionLabel(locale, aggregate.decision.status)}</Badge></div>
    <p>{localizedName(round.round.officeNames, locale, round.round.officeName)} · {aggregateRuleLabel(locale, aggregate.rule.kind)}</p>
    <div className="aggregate-metrics"><div><span>{labels.received}</span><strong>{aggregate.receivedBallots}</strong></div><div><span>{labels.ballots}</span><strong>{aggregate.nonAbstainingBallots}</strong></div><div><span>{labels.abstentions}</span><strong>{aggregate.abstentions}</strong></div></div>
    <MetricMeta locale={locale} timeZone={timeZone} period={period} phase={phaseLabel(locale, round.round.phase)} filter={localizedName(round.round.officeNames, locale, round.round.officeName)} denominator={aggregate.nonAbstainingBallots || null} version={`v${publication.version}`} updatedAt={publication.publishedAt} />
    <dl className="summary-list tally-decision"><div><dt>{labels.reason}</dt><dd>{aggregateDecisionReasonLabel(locale, aggregate.decision.reason)}</dd></div><div><dt>{labels.selected}</dt><dd>{listNames(aggregate.decision.selectedCandidateIds)}</dd></div><div><dt>{labels.tiebreak}</dt><dd>{listNames(aggregate.decision.tiebreakCandidateIds)}</dd></div><div><dt>{labels.unfilled}</dt><dd>{aggregate.decision.unfilledSeats}</dd></div></dl>
    <CandidateVoteAnalytics locale={locale} timeZone={timeZone} period={period} candidates={voteCandidates} denominator={voteDenominator} office={localizedName(round.round.officeNames, locale, round.round.officeName)} phase={round.round.phase} roundVersion={round.round.version} publicationVersion={publication.version} publishedAt={publication.publishedAt} />
    <div className="aggregate-list">{aggregate.candidates.map((candidate) => <div key={candidate.candidateId}><span>{candidateNames.get(candidate.candidateId)}</span><strong>{candidate.votes} {labels.votes}</strong>{selected.has(candidate.candidateId) && <Badge>{labels.selected}</Badge>}{tiebreak.has(candidate.candidateId) && <Badge variant="outline">{labels.tiebreak}</Badge>}</div>)}</div>
    <small>{labels.privacy}</small>
  </section>;
}

function HistoryView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const query=useQuery({queryKey:["audit"],queryFn:api.audit});
  return <><PageTitle eyebrow={message(locale, "screen.workspaceView.c53e9c9c5dc9")} title={message(locale, "screen.workspaceView.0af18fb80d63")} description={message(locale, "screen.workspaceView.88e570b88735")}/>{query.isLoading?<LoadingBlock locale={locale}/>:!query.data?<DataError locale={locale}/>:<section className="surface-card"><div className="integrity-banner"><span className={query.data.verified?"ok":"warn"}>{query.data.verified?<ShieldCheck/>:<AlertTriangle/>}</span><div><strong>{query.data.verified?message(locale, "screen.workspaceView.070237d09feb"):message(locale, "screen.workspaceView.01b18bf8cb1d")}</strong><p>{message(locale, "screen.workspaceView.968081f9eebe")}</p></div></div><div className="timeline">{(query.data.items as Array<Record<string,unknown>>).map((item,index)=><article key={String(item.id??index)}><span/><div><strong>{auditActionLabel(locale,String(item.action??message(locale, "screen.workspaceView.54de6cdcdc1f")))}</strong><p>{entityTypeLabel(locale,String(item.entityType??message(locale, "screen.workspaceView.f520300f8b66")))}</p><small>{item.createdAt?formatInTenantTimeZone(String(item.createdAt),locale,session.tenant.timezone,{dateStyle:"short",timeStyle:"short"}):""} · {String(item.actorDisplay??message(locale, "screen.workspaceView.3898b654c9e3"))}</small></div></article>)}</div></section>}</>;
}

function SettingsView({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  return <><PageTitle eyebrow={message(locale, "screen.workspaceView.34e9b2a0a189")} title={message(locale, "screen.workspaceView.1ad1cf1a8f7f")} description={message(locale, "screen.workspaceView.777d4f3dc099")}/><KeyLifecycleView session={session} locale={locale}/><div className="settings-grid"><section className="surface-card"><span className="form-icon"><KeyRound/></span><h2>{message(locale, "screen.workspaceView.9009afda04ec")}</h2><p>{session.tenant.kind==="real"?message(locale, "screen.workspaceView.747a0cf1ec47"):session.keyGrant?message(locale, "screen.workspaceView.844e22eb8faa"):message(locale, "screen.workspaceView.bedbc4ef9ba4")}</p><dl className="summary-list"><div><dt>{message(locale, "screen.workspaceView.a96215184b19")}</dt><dd>{session.tenant.slug}</dd></div><div><dt>{message(locale, "screen.workspaceView.1656c049b119")}</dt><dd>{catalogValueLabel(locale,session.tenant.kind)}</dd></div><div><dt>{message(locale, "screen.workspaceView.f04a808f4703")}</dt><dd>{message(locale, "screen.workspaceView.7dafe5d7202f")}</dd></div></dl></section><section className="surface-card"><span className="form-icon"><Languages/></span><h2>{message(locale, "screen.workspaceView.e2ab3b4117eb")}</h2><p>{message(locale, "screen.workspaceView.e0d2748e7793")}</p><div className="button-row">{([['es','Español'],['en','English'],['fr','Français']] as const).map(([code,label])=><Button asChild key={code} variant={locale===code?"default":"outline"}><Link href={`/${code}/app/settings`}>{label}</Link></Button>)}</div></section><section className="surface-card"><span className="form-icon"><Fingerprint/></span><h2>{message(locale, "screen.workspaceView.2167baadcc07")}</h2><p>{message(locale, "screen.workspaceView.bc0612cc1653")}</p><Badge variant="outline">{session.tenant.kind==="real"?message(locale, "screen.workspaceView.d1906e80b73a"):session.keyGrant?message(locale, "screen.workspaceView.973bfefea02a"):message(locale, "screen.workspaceView.78756a0fd26b")}</Badge></section><AccessibilityPreferencesPanel locale={locale}/></div></>;
}

function LibraryView({ locale }: { locale: Locale }) {
  const [search, setSearch] = useState("");
  const sources = [
    {
      id: "church-manual-2025", title: message(locale, "screen.workspaceView.3b696a7abc1d"),
      edition: message(locale, "screen.workspaceView.d35b0a8c90a7"),
      description: message(locale, "screen.workspaceView.926de47f86b4"),
      topics: message(locale, "screen.workspaceView.ece8acadc8f9"),
      url: "https://gc.adventist.org/church-manual/", badge: message(locale, "screen.workspaceView.0c0a3860f03a"),
    },
    {
      id: "elders-handbook-2016", title: message(locale, "screen.workspaceView.c4946929332c"),
      edition: message(locale, "screen.workspaceView.96767be3cf87"),
      description: message(locale, "screen.workspaceView.9d4fcdb945df"),
      topics: message(locale, "screen.workspaceView.749827118a0b"),
      url: "https://cdn.ministerialassociation.org/docs/ebooks/Seventh-day%20Adventist%20Elder%27s%20Handbook%20%28rev.2016%29.pdf", badge: message(locale, "screen.workspaceView.80a168dc68a3"),
    },
  ];
  const term=search.trim().toLocaleLowerCase(locale);
  const visibleSources=sources.filter((source)=>!term||`${source.title} ${source.edition} ${source.description} ${source.topics}`.toLocaleLowerCase(locale).includes(term));
  const glossary = [
    ["Junta de nombramientos","Nominating Committee","Commission des nominations"], ["Anciano","Elder","Ancien"], ["Diaconisa","Deaconess","Diaconesse"],
    ["Nombramiento","Appointment","Nomination"], ["Recomendación","Recommendation","Recommandation"], ["Elección por la iglesia","Election by the church","Élection par l’Église"],
  ];
  return <><PageTitle eyebrow={message(locale, "screen.workspaceView.90aff54f2dbc")} title={message(locale, "screen.workspaceView.4a75978bd82a")} description={message(locale, "screen.workspaceView.ad4e2487e3c9")}/><div className="member-toolbar surface-card"><label className="search-field"><Search/><span className="sr-only">{message(locale, "screen.workspaceView.bb0d6f40ca79")}</span><Input value={search} onChange={(event)=>setSearch(event.target.value)} placeholder={message(locale, "screen.workspaceView.2831948ad6d6")}/></label><Badge variant="outline">{visibleSources.length} {message(locale, "screen.workspaceView.32b80e147d18")}</Badge></div><div className="library-grid">{visibleSources.length?visibleSources.map((source)=><a key={source.id} className="source-card" href={source.url} target="_blank" rel="noopener noreferrer"><BookOpenText/><div><Badge>{source.badge}</Badge><h2>{source.title}</h2><p>{source.edition}</p><small>{source.description}</small></div><ChevronRight/></a>):<EmptyState locale={locale} icon={BookOpenText} title={message(locale, "screen.workspaceView.18744a11c578")}/>}<section className="surface-card"><p className="eyebrow">{message(locale, "screen.workspaceView.b0ab57ee439f")}</p>{glossary.map(row=><div className="glossary-row" key={row[0]}>{row.map(item=><span key={item}>{item}</span>)}</div>)}</section></div></>;
}

function OnboardingView({ locale, session, embedded=false }: { locale: Locale; session: AuthenticatedSession; embedded?: boolean }) {
  const steps={es:[message("es", "screen.workspaceView.35670c06f35e"),message("es", "screen.workspaceView.9f25ece0c3d6"),message("es", "screen.workspaceView.564a4052c4e1"),message("es", "screen.workspaceView.51d0c8e35390"),message("es", "screen.workspaceView.ed7205eae00e"),message("es", "screen.workspaceView.ddf39b1ab72e"),message("es", "screen.workspaceView.a1112db969c5")],en:[message("en", "screen.workspaceView.35670c06f35e"),message("en", "screen.workspaceView.9f25ece0c3d6"),message("en", "screen.workspaceView.564a4052c4e1"),message("en", "screen.workspaceView.51d0c8e35390"),message("en", "screen.workspaceView.ed7205eae00e"),message("en", "screen.workspaceView.ddf39b1ab72e"),message("en", "screen.workspaceView.a1112db969c5")],fr:[message("fr", "screen.workspaceView.35670c06f35e"),message("fr", "screen.workspaceView.9f25ece0c3d6"),message("fr", "screen.workspaceView.564a4052c4e1"),message("fr", "screen.workspaceView.51d0c8e35390"),message("fr", "screen.workspaceView.ed7205eae00e"),message("fr", "screen.workspaceView.ddf39b1ab72e"),message("fr", "screen.workspaceView.a1112db969c5")]}[locale];
  const start = session.permissions.includes("member.read")
    ? { section: "members", label: message(locale, "screen.workspaceView.b52b1a0d7969") }
    : session.permissions.includes("cycle.manage")
      ? { section: "workflow", label: message(locale, "screen.workspaceView.1bac097d65a5") }
      : { section: "catalog", label: message(locale, "screen.workspaceView.94b1e0ba08f9") };
  return <>{!embedded&&<PageTitle eyebrow={message(locale, "screen.workspaceView.96dd4ab506cc")} title={message(locale, "screen.workspaceView.34aa335ef130")} description={message(locale, "screen.workspaceView.b1ba35b9d2b4")}/>}<section className="onboarding-card"><div><Badge variant="outline">{message(locale, "screen.workspaceView.86f874c9d594")}</Badge><h2>{message(locale, "screen.workspaceView.d54033e02612")}</h2><p>{message(locale, "screen.workspaceView.0cfd3425726b")}</p><Button asChild><Link href={`/${locale}/app/${start.section}`}>{start.label} <ChevronRight/></Link></Button></div><ol>{steps.map((step,index)=><li key={step}><span>{index+1}</span><p>{step}</p><small>{message(locale, "screen.workspaceView.75538dd37390")}</small></li>)}</ol></section></>;
}

function PageTitle({ eyebrow, title, description, action }: { eyebrow:string; title:string; description:string; action?:React.ReactNode }) { return <div className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div>{action}</div>; }
function EmptyState({ icon:Icon,title,locale="es" }: { icon:typeof Users;title:string;locale?:Locale }) { return <div className="empty-state"><Icon/><strong>{title}</strong><p>{message(locale, "screen.workspaceView.6c119e6030f4")}</p></div>; }

export function WorkspaceView({ locale, section, session }: { locale: Locale; section: string; session: AuthenticatedSession }) {
  if (section === "overview") return <OverviewView locale={locale} session={session}/>;
  if (section === "workflow") return <WorkflowConsole locale={locale} session={session}/>;
  if (section === "session") return <RoundView locale={locale} session={session}/>;
  if (section === "members") return <MembersView locale={locale} session={session}/>;
  if (section === "catalog") return <CatalogManagerView locale={locale} session={session}/>;
  if (section === "committee") return <CommitteeView locale={locale} session={session}/>;
  if (section === "organization") return <OrganizationView locale={locale} session={session}/>;
  if (section === "reports") return <ReportsView locale={locale} session={session}/>;
  if (section === "access") return <AccessConsole locale={locale} session={session}/>;
  if (section === "custody") return <CustodyView key={`${session.tenant.id}:${session.user.id}`} locale={locale} session={session}/>;
  if (section === "history") return <HistoryView locale={locale} session={session}/>;
  if (section === "settings") return <SettingsView session={session} locale={locale}/>;
  if (section === "results") return <ResultsView locale={locale} session={session}/>;
  if (section === "library") return <LibraryView locale={locale}/>;
  if (section === "onboarding") return <OnboardingView locale={locale} session={session}/>;
  if (section === "platform" && session.permissions.includes("platform.operation.read")) return <PlatformConsole locale={locale} permissions={session.permissions} currentIdentityId={session.user.id}/>;
  return <DataError locale={locale}/>;
}

export { DataError, EmptyState, LoadingBlock, PageTitle };
