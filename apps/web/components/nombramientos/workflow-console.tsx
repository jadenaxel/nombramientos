"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { classifyAppointmentWorkflow, isConfigurableVacancyProcessMechanism } from "@nombramientos/catalog";
import {
  ArchiveRestore, ArrowRight, CalendarClock, Check, CheckCircle2, ClipboardCheck,
  Copy, FileLock2, Gavel, History, LoaderCircle, Plus, RefreshCw, ShieldAlert, ShieldCheck,
  Sparkles, UserCheck, Users, Vote,
} from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { WorkflowSessionConsole } from "@/components/nombramientos/workflow-session-console";
import { api, ApiError, type AuthenticatedSession, type Envelope, type Locale } from "@/lib/api";
import { encryptJson } from "@/lib/crypto-client";
import { keyForEnvelope, openJsonEnvelope } from "@/lib/historical-envelope";
import { decryptPhoto, type StoredPhotoRecord } from "@/lib/photo-client";
import { message, assignmentLabel, localizedApiError, localizedName, phaseLabel, type LocalizedNames } from "@/lib/product-i18n";
import { isLegacyTitleUnavailable, openSessionTitle, sealSessionTitle } from "@/lib/session-title-crypto";
import { currentYearInTimeZone, formatCalendarDate, formatInTenantTimeZone } from "@/lib/tenant-time";
import { localDateTimeInZoneToIso } from "@/lib/workflow-time";
import {
  buildProposalAggregate,
  verifyProposalManifest,
  workflowApi,
  type CommitteeCandidate,
  type CycleWorkflow,
  type ProposalManifest,
  type ProposalSubmissionPlaintext,
  type ReviewBoard,
  type WorkflowAssignment,
  type WorkflowProcess,
  type WorkflowRound,
} from "@/lib/workflow-api";

type ConsoleStep = "cycle" | "configuration" | "process" | "assignments";
type VisibleCycleWorkflow = Omit<CycleWorkflow, "sessions"> & {
  sessions: Array<CycleWorkflow["sessions"][number] & { title: string }>;
};
type CommitteeDraft = {
  identityId: string; memberId: string; displayName: string;
  roleCode: "chair" | "pastor" | "secretary" | "member" | "custodian" | "advisor";
  votingRight: boolean; pastoralCapacity: boolean;
};

const phaseOrder = [
  "CONFIGURADO", "PROPUESTAS_ABIERTAS", "PROPUESTAS_CERRADAS", "DEPURACION",
  "LISTA_CONFIRMADA", "VOTACION_ABIERTA", "VOTACION_CERRADA", "ESCRUTINIO",
  "RESULTADO_INTERNO", "CERRADO",
];

const eligibilityReasonCodeByResolution = {
  ANNUL_AND_RESTART: "ELIGIBILITY_ROUND_RESTARTED",
  RESUME_UNCHANGED: "ELIGIBILITY_PROCESS_RESUMED",
  EXCLUDE_AND_REVIEW: "ELIGIBILITY_CANDIDACIES_EXCLUDED",
  CLOSE_AFTER_REPLACEMENT: "ELIGIBILITY_REPLACEMENT_COMPLETED",
} as const;

type AssignmentLifecycleReasonCode =
  | "TERM_COMPLETED_NO_VACANCY"
  | "TERM_COMPLETED_OPEN_VACANCY"
  | "ASSIGNMENT_REPLACED";

const assignmentLifecycleReasonCodes = [
  "TERM_COMPLETED_NO_VACANCY",
  "TERM_COMPLETED_OPEN_VACANCY",
  "ASSIGNMENT_REPLACED",
] as const satisfies readonly AssignmentLifecycleReasonCode[];

const emptyCommitteeMember = (): CommitteeDraft => ({
  identityId: "", memberId: "", displayName: "", roleCode: "member", votingRight: true, pastoralCapacity: false,
});

function appointmentMechanismLabel(locale: Locale, mechanism: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    church_election_after_nominating_report: "screen.workflowConsole.5e3b5b8d8aeb",
    church_election: "screen.workflowConsole.87dc521a178d",
    linked_designation: "screen.workflowConsole.89d200bb3518",
    board_appointment: "screen.workflowConsole.a1e594a67585",
    council_recommendation_board_approval: "screen.workflowConsole.0548643d8660",
    conference_appointment: "screen.workflowConsole.8a274f91da90",
    ex_officio: "screen.workflowConsole.53be1f5afc6a",
    local_configuration_pending: "screen.workflowConsole.6c8a85b5d8fb",
  };
  const value = labels[mechanism];
  return value ? message(locale, value) : mechanism.replaceAll("_", " ");
}

function hasPermissions(session: AuthenticatedSession, ...permissions: string[]): boolean {
  return permissions.every((permission) => session.permissions.includes(permission));
}

function cycleStatusLabel(locale: Locale, status: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    draft: "screen.workflowConsole.ce0c560e78ec",
    active: "screen.workflowConsole.901bb448bee7",
    closed: "screen.workflowConsole.2c71b8b7d5f0",
    archived: "screen.workflowConsole.9cf8b062b4b5",
  };
  const value = labels[status];
  return value ? message(locale, value) : status;
}

function candidacyLabel(locale: Locale, state: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    PROPOSED: "screen.workflowConsole.b058355cc920",
    UNDER_REVIEW: "screen.workflowConsole.af23994edd83",
    PRELIMINARY_ACCEPTED: "screen.workflowConsole.61998e6a31d0",
    CONFIRMED_FOR_BALLOT: "screen.workflowConsole.eb7f9e4e99bd",
    WITHDRAWN: "screen.workflowConsole.6be4cbedb6da",
    EXCLUDED: "screen.workflowConsole.3ace37de165b",
    INELIGIBLE: "screen.workflowConsole.cd2cfc3b95fd",
  };
  const value = labels[state];
  return value ? message(locale, value) : state.replaceAll("_", " ");
}

function assignmentReasonCodeLabel(locale: Locale, reasonCode: AssignmentLifecycleReasonCode): string {
  const labels: Record<AssignmentLifecycleReasonCode, Parameters<typeof message>[1]> = {
    TERM_COMPLETED_NO_VACANCY: "screen.workflowConsole.b823277b7702",
    TERM_COMPLETED_OPEN_VACANCY: "screen.workflowConsole.b8f15d8cd4d8",
    ASSIGNMENT_REPLACED: "screen.workflowConsole.550ad8342ed0",
  };
  return message(locale, labels[reasonCode]);
}

function applicabilityError(error: unknown, locale: Locale): string {
  if (!(error instanceof ApiError)) return localizedApiError(error, locale);
  const labels: Readonly<Record<string, Parameters<typeof message>[1]>> = {
    OFFICE_PROCESS_HAS_ACTIVE_ROUNDS: "screen.workflowConsole.03e1cab2600c",
    OFFICE_PROCESS_HAS_ACTIVE_DECISIONS: "screen.workflowConsole.7cf5e2fa95c3",
    OFFICE_PROCESS_HAS_UNRESOLVED_ELIGIBILITY: "screen.workflowConsole.8256ea24da67",
    OFFICE_PROCESS_HAS_OPEN_AGENDA: "screen.workflowConsole.37b4a6676e63",
    OFFICE_PROCESS_REQUIRED_BY_ENABLED_STRUCTURE: "screen.workflowConsole.a247608972ce",
    OFFICE_PROCESS_ACTIVE_WORKFLOW: "screen.workflowConsole.bc22df63ade2",
    LINKED_BASE_UNCONFIGURED: "screen.workflowConsole.ac5c205baaa0",
  };
  const label = labels[error.code];
  if (!label) return localizedApiError(error, locale);
  const text = message(locale, label);
  return error.requestId ? `${text} · ${message(locale, "screen.workflowConsole.e7502e3d7abd")}: ${error.requestId}` : text;
}

function committeeRoleLabel(locale: Locale, role: CommitteeDraft["roleCode"]): string {
  const labels: Record<CommitteeDraft["roleCode"], Parameters<typeof message>[1]> = {
    chair: "screen.workflowConsole.89d5e0367cc6",
    pastor: "screen.workflowConsole.8d30fca7215d",
    secretary: "screen.workflowConsole.a8e5562c03b7",
    member: "screen.workflowConsole.61854ff3e331",
    custodian: "screen.workflowConsole.5959efe72e75",
    advisor: "screen.workflowConsole.8b645bb6cb60",
  };
  return message(locale, labels[role]);
}

export function WorkflowConsole({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const vault = useVault();
  const queryClient = useQueryClient();
  const canManageCycle = hasPermissions(session, "cycle.manage");
  const canReadMembers = hasPermissions(session, "member.read");
  const canManageCommittee = hasPermissions(session, "committee.manage");
  const [step, setStep] = useState<ConsoleStep>("cycle");
  const [selectedCycleId, setSelectedCycleId] = useState("");
  const [selectedProcessId, setSelectedProcessId] = useState("");
  const [selectedAssignmentId, setSelectedAssignmentId] = useState("");
  const [busy, setBusy] = useState<string>();
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string }>();
  const [sessionTitles, setSessionTitles] = useState<Map<string, string>>(new Map());
  const [sessionTitleError, setSessionTitleError] = useState<string>();

  const cyclesQuery = useQuery({ queryKey: ["workflow-cycles", session.tenant.id], queryFn: workflowApi.cycles, enabled: canManageCycle, refetchInterval: 15_000 });
  const selectedCycle = cyclesQuery.data?.items.find((cycle) => cycle.id === selectedCycleId)
    ?? cyclesQuery.data?.items.find((cycle) => cycle.status === "active")
    ?? cyclesQuery.data?.items[0];
  const resolvedCycleId = selectedCycle?.id ?? "";
  const workflowQuery = useQuery({
    queryKey: ["cycle-workflow", session.tenant.id, resolvedCycleId],
    queryFn: () => workflowApi.workflow(resolvedCycleId),
    enabled: canManageCycle && Boolean(resolvedCycleId),
    refetchInterval: 15_000,
  });
  const catalogQuery = useQuery({ queryKey: ["catalog"], queryFn: api.catalog, enabled: canManageCycle });
  const membersQuery = useQuery({ queryKey: ["members", session.tenant.id, "workflow"], queryFn: () => api.members(), enabled: canManageCycle && canReadMembers });
  const committeeCandidatesQuery = useQuery({
    queryKey: ["workflow-committee-candidates", session.tenant.id, resolvedCycleId],
    queryFn: () => workflowApi.committeeCandidates(resolvedCycleId),
    enabled: canManageCommittee && canReadMembers && Boolean(resolvedCycleId),
  });

  const workflow = workflowQuery.data;
  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      setSessionTitleError(undefined);
      if (!workflow) {
        setSessionTitles(new Map());
        return;
      }
      const requiresKey = workflow.sessions.some(({ title_envelope }) => Boolean(title_envelope));
      if (requiresKey && (!vault.key || !vault.keyId || vault.tenantId !== session.tenant.id)) {
        setSessionTitles(new Map());
        setSessionTitleError(message(locale, "screen.workflowConsole.fcc8599726fb"));
        return;
      }
      try {
        const visible = new Map<string, string>();
        let hadFailures = false;
        for (const item of workflow.sessions) {
          const reference = {
            titleEnvelope: item.title_envelope,
            titleVersion: item.title_envelope_version,
            legacyTitleUnavailable: item.legacy_title_unavailable,
          };
          if (isLegacyTitleUnavailable(reference)) {
            visible.set(item.id, message(locale, "screen.workflowConsole.30394ed2ba2b"));
            continue;
          }
          try {
            if (!item.title_envelope) throw new Error("Encrypted session title reference is incomplete");
            visible.set(item.id, await openSessionTitle(
              keyForEnvelope(vault, session.tenant.id, item.title_envelope),
              item.title_envelope.keyId,
              {
                tenantId: session.tenant.id,
                cycleId: workflow.cycle.id,
                sessionId: item.id,
                titleVersion: item.title_envelope_version,
              },
              item.title_envelope,
            ));
          } catch {
            hadFailures = true;
            visible.set(item.id, message(locale, "screen.workflowConsole.6544fdadbe29"));
          }
        }
        if (!cancelled) {
          setSessionTitles(visible);
          setSessionTitleError(hadFailures ? message(locale, "screen.workflowConsole.04b80518b6cc") : undefined);
        }
      } catch {
        if (!cancelled) {
          setSessionTitles(new Map());
          setSessionTitleError(message(locale, "screen.workflowConsole.04b80518b6cc"));
        }
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [locale, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, vault.tenantId, workflow]);
  const visibleWorkflow = useMemo<VisibleCycleWorkflow | undefined>(() => workflow ? {
    ...workflow,
    sessions: workflow.sessions.map((item) => ({
      ...item,
      title: sessionTitles.get(item.id) ?? message(locale, "screen.workflowConsole.6544fdadbe29"),
    })),
  } : undefined, [locale, sessionTitles, workflow]);
  const process = visibleWorkflow?.processes.find((item) => item.id === selectedProcessId)
    ?? visibleWorkflow?.processes.find((item) => item.enabled)
    ?? visibleWorkflow?.processes[0];
  const assignment = visibleWorkflow?.assignments.find((item) => item.id === selectedAssignmentId) ?? visibleWorkflow?.assignments[0];
  const resolvedProcessId = process?.id ?? "";
  const resolvedAssignmentId = assignment?.id ?? "";

  async function refresh() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["workflow-cycles", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["cycle-workflow", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["workflow-review", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
      queryClient.invalidateQueries({ queryKey: ["active-round"] }),
      queryClient.invalidateQueries({ queryKey: ["organization", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["workflow-report-snapshot", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["workflow-report-cycle-comparison", session.tenant.id] }),
    ]);
  }

  async function act(
    label: string,
    action: () => Promise<unknown>,
    success = message(locale, "screen.workflowConsole.5e9cb6770690"),
  ) {
    setBusy(label); setNotice(undefined);
    try {
      await action();
      await refresh();
      setNotice({ tone: "success", text: success });
    } catch (error) {
      setNotice({
        tone: "error",
        text: label.startsWith("applicability:") ? applicabilityError(error, locale) : localizedApiError(error, locale),
      });
    } finally { setBusy(undefined); }
  }

  const readiness = visibleWorkflow ? readinessPercent(visibleWorkflow) : 0;
  if (!canManageCycle) return <PermissionNotice locale={locale} />;
  return <div className="space-y-6">
    <header className="page-title rounded-[2rem] border border-cyan-100 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,.18),transparent_35%),linear-gradient(135deg,#fff,#f8fafc)] p-7 shadow-[0_22px_70px_-45px_rgba(8,145,178,.65)]">
      <div><p className="eyebrow">{message(locale, "screen.workflowConsole.ef588d86a191")}</p><h1>{message(locale, "screen.workflowConsole.cbb4c1757ce0")}</h1><p>{message(locale, "screen.workflowConsole.5ff5798dfa14")}</p></div>
      <div className="flex flex-wrap items-center gap-2"><Badge variant="outline"><ShieldCheck /> {message(locale, "screen.workflowConsole.fc9848803aa5")}</Badge><Badge variant="outline"><FileLock2 /> E2EE</Badge></div>
    </header>

    {notice && <Alert role="status" variant={notice.tone === "error" ? "destructive" : "default"}><CheckCircle2 /><AlertTitle>{notice.tone === "success" ? message(locale, "screen.workflowConsole.c837ac582582") : message(locale, "screen.workflowConsole.0b187cb976ee")}</AlertTitle><AlertDescription>{notice.text}</AlertDescription></Alert>}
    {sessionTitleError && <Alert variant="destructive"><ShieldAlert /><AlertTitle>{message(locale, "screen.workflowConsole.bb40c9288c58")}</AlertTitle><AlertDescription>{sessionTitleError}</AlertDescription></Alert>}

    <nav className="grid grid-cols-2 gap-2 rounded-2xl border bg-white p-2 shadow-sm md:grid-cols-4" aria-label={message(locale, "screen.workflowConsole.cdf724a755fc")}>
      {([
        ["cycle", message(locale, "screen.workflowConsole.f24d3df7f132"), CalendarClock], ["configuration", message(locale, "screen.workflowConsole.24b81fc9fb00"), Users],
        ["process", message(locale, "screen.workflowConsole.b59d840d24d8"), Vote], ["assignments", message(locale, "screen.workflowConsole.cb9ceade830a"), Gavel],
      ] as const).map(([id, label, Icon]) => <button key={id} type="button" onClick={() => setStep(id)} className={`flex items-center justify-center gap-2 rounded-xl px-3 py-3 text-sm font-semibold transition ${step === id ? "bg-slate-950 text-white shadow-lg" : "text-slate-600 hover:bg-slate-100"}`}><Icon size={17} />{label}</button>)}
    </nav>

    {cyclesQuery.isLoading ? <Loading label={message(locale, "screen.workflowConsole.2c8ff076d67c")} /> : step === "cycle" ? <CyclePanel
      locale={locale} cycles={cyclesQuery.data?.items ?? []} selectedCycleId={resolvedCycleId} setSelectedCycleId={setSelectedCycleId}
      tenantTimeZone={session.tenant.timezone}
      busy={busy} act={act} onCreated={(id) => { setSelectedCycleId(id); setStep("configuration"); }}
    /> : !resolvedCycleId ? <Empty title={message(locale, "screen.workflowConsole.ac62c00c4145")} /> : workflowQuery.isLoading ? <Loading label={message(locale, "screen.workflowConsole.1d49b3c4a6f8")} /> : !visibleWorkflow ? <Empty title={message(locale, "screen.workflowConsole.1d1fde09cb84")} /> : <>
      <CycleRibbon workflow={visibleWorkflow} readiness={readiness} locale={locale} busy={busy} act={act} />
      {step === "configuration" && <ConfigurationPanel
        key={visibleWorkflow.cycle.id} workflow={visibleWorkflow} locale={locale} session={session} vault={vault} offices={(catalogQuery.data?.offices ?? []) as Array<Record<string, unknown>>}
        members={membersQuery.data?.items ?? []} committeeCandidates={committeeCandidatesQuery.data?.items ?? []} busy={busy} act={act}
      />}
      {step === "process" && <ProcessPanel
        workflow={visibleWorkflow} process={process} selectedProcessId={resolvedProcessId} setSelectedProcessId={setSelectedProcessId}
        locale={locale} session={session} vault={vault} busy={busy} act={act}
      />}
      {step === "assignments" && <AssignmentsPanel
        workflow={visibleWorkflow} assignment={assignment} selectedAssignmentId={resolvedAssignmentId}
        setSelectedAssignmentId={setSelectedAssignmentId} locale={locale} session={session} vault={vault} busy={busy} act={act}
      />}
    </>}
  </div>;
}

function CyclePanel({ locale, cycles, selectedCycleId, setSelectedCycleId, tenantTimeZone, busy, act, onCreated }: {
  locale: Locale; cycles: Awaited<ReturnType<typeof workflowApi.cycles>>["items"]; selectedCycleId: string;
  setSelectedCycleId: (id: string) => void; tenantTimeZone: string; busy?: string;
  act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>; onCreated: (id: string) => void;
}) {
  const [cloneSource, setCloneSource] = useState("");
  const [form, setForm] = useState(() => {
    const year = currentYearInTimeZone(tenantTimeZone);
    return {
      name: "", locale, timezone: tenantTimeZone, jurisdiction: message(locale, "screen.workflowConsole.a00dfa072b83"),
      termStart: `${year}-01-01`, termEnd: `${year + 1}-12-31`, normativeVersion: "catalog-v1",
    };
  });
  async function submit(event: FormEvent) {
    event.preventDefault();
    await act("cycle-save", async () => {
      const body = { ...form, configuration: { parallelRooms: false } };
      const created = cloneSource ? await workflowApi.cloneCycle(cloneSource, body) : await workflowApi.createCycle(body);
      onCreated(created.id);
    }, cloneSource
      ? message(locale, "screen.workflowConsole.f51746ba9cd3")
      : message(locale, "screen.workflowConsole.410dfec9d2e0"));
  }
  return <div className="grid gap-5 xl:grid-cols-[1.05fr_.95fr]">
    <section className="surface-card">
      <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.bfaff6f41e4d")}</p><h2>{message(locale, "screen.workflowConsole.a4d7a5f145fb")}</h2></div><Badge variant="outline">{cycles.length}</Badge></div>
      <div className="space-y-3">{cycles.length ? cycles.map((cycle) => <button type="button" key={cycle.id} onClick={() => setSelectedCycleId(cycle.id)} className={`w-full rounded-2xl border p-4 text-left transition ${selectedCycleId === cycle.id ? "border-cyan-400 bg-cyan-50/70 shadow-sm" : "border-slate-200 hover:border-slate-300"}`}>
        <div className="flex items-start justify-between gap-3"><div><strong className="block text-slate-950">{cycle.name}</strong><small className="text-slate-500">{formatCalendarDate(cycle.termStart, locale)} → {formatCalendarDate(cycle.termEnd, locale)} · v{cycle.version}</small></div><Badge variant={cycle.status === "active" ? "default" : "outline"}>{cycleStatusLabel(locale, cycle.status)}</Badge></div>
        <div className="mt-3 grid grid-cols-4 gap-2 text-center text-xs text-slate-500"><span>{cycle.readiness.sessions}<b className="block text-slate-900">{message(locale, "screen.workflowConsole.ab6d24acbf23")}</b></span><span>{cycle.readiness.processes}<b className="block text-slate-900">{message(locale, "screen.workflowConsole.d55017975083")}</b></span><span>{cycle.readiness.committeeMembers}<b className="block text-slate-900">{message(locale, "screen.workflowConsole.35cf08a22231")}</b></span><span>{cycle.readiness.electors}<b className="block text-slate-900">{message(locale, "screen.workflowConsole.92e3936e2329")}</b></span></div>
      </button>) : <Empty title={message(locale, "screen.workflowConsole.63bc9ff50206")} />}</div>
    </section>
    <section className="surface-card">
      <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.7e27a40f205a")}</p><h2>{cloneSource ? message(locale, "screen.workflowConsole.9ccfda59dfae") : message(locale, "screen.workflowConsole.45bf8c31b009")}</h2></div><span className="form-icon">{cloneSource ? <Copy /> : <Sparkles />}</span></div>
      <form className="space-y-4" onSubmit={(event) => void submit(event)}>
        <Field label={message(locale, "screen.workflowConsole.15fa7f36eaa5")}><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} minLength={2} maxLength={160} required /></Field>
        <div className="grid gap-3 sm:grid-cols-2"><Field label={message(locale, "screen.workflowConsole.c91ca116b24c")}><Input type="date" value={form.termStart} onChange={(event) => setForm({ ...form, termStart: event.target.value })} required /></Field><Field label={message(locale, "screen.workflowConsole.36f88fc440e3")}><Input type="date" value={form.termEnd} onChange={(event) => setForm({ ...form, termEnd: event.target.value })} required /></Field></div>
        <div className="grid gap-3 sm:grid-cols-2"><Field label={message(locale, "screen.workflowConsole.1f470c29ba5f")}><Input value={form.timezone} onChange={(event) => setForm({ ...form, timezone: event.target.value })} pattern="[A-Za-z_]+(?:/[A-Za-z0-9_+\-]+)+" title={message(locale, "screen.workflowConsole.eec9e3dfe359")} required /></Field><Field label={message(locale, "screen.workflowConsole.9d20d92c5231")}><Input value={form.normativeVersion} onChange={(event) => setForm({ ...form, normativeVersion: event.target.value })} required /></Field></div>
        <Field label={message(locale, "screen.workflowConsole.b5fadcae64be")}><Input value={form.jurisdiction} onChange={(event) => setForm({ ...form, jurisdiction: event.target.value })} required /></Field>
        <Field label={message(locale, "screen.workflowConsole.e6e03a527432")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={cloneSource} onChange={(event) => setCloneSource(event.target.value)}><option value="">{message(locale, "screen.workflowConsole.30fad7c7b1a8")}</option>{cycles.filter((cycle) => cycle.status !== "draft").map((cycle) => <option key={cycle.id} value={cycle.id}>{cycle.name}</option>)}</select></Field>
        <Button className="w-full" disabled={Boolean(busy)} type="submit">{busy === "cycle-save" ? <LoaderCircle className="animate-spin" /> : cloneSource ? <Copy /> : <Plus />} {cloneSource ? message(locale, "screen.workflowConsole.9ccfda59dfae") : message(locale, "screen.workflowConsole.7eda65bdd8ea")}</Button>
      </form>
    </section>
  </div>;
}

function CycleRibbon({ workflow, readiness, locale, busy, act }: {
  workflow: VisibleCycleWorkflow; readiness: number; locale: Locale; busy?: string;
  act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
}) {
  return <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex flex-wrap items-center justify-between gap-4"><div><p className="eyebrow">{cycleStatusLabel(locale, workflow.cycle.status).toUpperCase()} · v{workflow.cycle.version}</p><h2 className="text-xl font-semibold">{workflow.cycle.name}</h2><p className="text-sm text-slate-500">{formatCalendarDate(workflow.cycle.termStart, locale)} → {formatCalendarDate(workflow.cycle.termEnd, locale)}</p></div><div className="min-w-56"><div className="mb-2 flex justify-between text-sm"><span>{message(locale, "screen.workflowConsole.ef71b300cbb8")}</span><strong>{readiness}%</strong></div><Progress value={readiness} /></div><div className="flex flex-wrap gap-2">{workflow.cycle.status === "active" && <Button variant="outline" disabled={Boolean(busy)} onClick={() => void act("close-cycle", () => workflowApi.closeCycle(workflow.cycle.id, workflow.cycle.version), message(locale, "screen.workflowConsole.2b1d0b2ea62a"))}>{busy === "close-cycle" ? <LoaderCircle className="animate-spin" /> : <ArchiveRestore />} {message(locale, "screen.workflowConsole.77166b53684a")}</Button>}{workflow.cycle.status === "closed" && <Button variant="outline" disabled={Boolean(busy)} onClick={() => void act("archive-cycle", () => workflowApi.archiveCycle(workflow.cycle.id, workflow.cycle.version), message(locale, "screen.workflowConsole.ca35218b155d"))}>{busy === "archive-cycle" ? <LoaderCircle className="animate-spin" /> : <ArchiveRestore />} {message(locale, "screen.workflowConsole.76663dcb0541")}</Button>}</div></div></section>;
}

function ConfigurationPanel({ workflow, locale, session, vault, offices, members, committeeCandidates, busy, act }: {
  workflow: VisibleCycleWorkflow; locale: Locale; session: AuthenticatedSession; vault: ReturnType<typeof useVault>;
  offices: Array<Record<string, unknown>>; members: Awaited<ReturnType<typeof api.members>>["items"];
  committeeCandidates: CommitteeCandidate[];
  busy?: string; act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
}) {
  const canManageCommitteeDirectory = hasPermissions(session, "committee.manage", "member.read");
  const [sessionForm, setSessionForm] = useState({ sequence: workflow.sessions.length + 1, title: message(locale, "screen.workflowConsole.d8a40fed4561"), startsAt: "", endsAt: "" });
  const [committee, setCommittee] = useState<CommitteeDraft[]>([
    { ...emptyCommitteeMember(), identityId: session.user.id, displayName: session.user.displayName, roleCode: "chair" },
    { ...emptyCommitteeMember(), roleCode: "secretary" },
  ]);
  const [electors, setElectors] = useState<Array<{ identityId: string; canPropose: boolean; canVote: boolean; recused: boolean }>>(() => workflow.electorate.map((item) => ({
    identityId: item.identity_id, canPropose: item.can_propose, canVote: item.can_vote, recused: item.recused,
  })));
  const [vacancy, setVacancy] = useState({ officeId: "", vacancyCount: 1, maxProposalSelections: 3, maxBallotSelections: 1, agendaOrder: workflow.processes.length + 1 });
  const hydratedCycle = useRef("");
  const version = workflow.cycle.version;
  const configurableOffices = offices.filter((office) => isConfigurableVacancyProcessMechanism(String(office.appointmentMechanism ?? "")));
  const separateProcedureOffices = offices.filter((office) => !isConfigurableVacancyProcessMechanism(String(office.appointmentMechanism ?? "")));

  useEffect(() => {
    if (!canManageCommitteeDirectory) return;
    if (hydratedCycle.current === workflow.cycle.id) return;
    if (workflow.committee.length && !vault.key) return;
    hydratedCycle.current = workflow.cycle.id;
    if (!workflow.committee.length || !vault.key) return;
    let cancelled = false;
    void Promise.all(workflow.committee.map(async (member) => {
      try {
        const visible = await openJsonEnvelope<{ displayName?: string }>({
          resolver: vault,
          tenantId: session.tenant.id,
          envelope: member.display_envelope,
          aad: { tenantId: session.tenant.id, cycleId: workflow.cycle.id, identityId: member.identity_id, purpose: "committee-display", schemaVersion: 1 },
        });
        return {
          identityId: member.identity_id, memberId: member.member_id ?? "", displayName: visible.displayName ?? member.identity_id,
          roleCode: member.role_code as CommitteeDraft["roleCode"], votingRight: member.voting_right, pastoralCapacity: member.pastoral_capacity,
        };
      } catch {
        return {
          identityId: member.identity_id,
          memberId: member.member_id ?? "",
          displayName: member.identity_id,
          roleCode: member.role_code as CommitteeDraft["roleCode"],
          votingRight: member.voting_right,
          pastoralCapacity: member.pastoral_capacity,
        };
      }
    })).then((values) => { if (!cancelled) setCommittee(values); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [canManageCommitteeDirectory, session.tenant.id, vault, vault.key, vault.keyFor, vault.keyringRevision, workflow.committee, workflow.cycle.id, workflow.electorate]);

  async function saveCommittee() {
    if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.workflowConsole.9069d3eebe76"));
    const prepared = await Promise.all(committee.map(async (member) => ({
      identityId: member.identityId,
      ...(member.memberId ? { memberId: member.memberId } : {}),
      displayEnvelope: (await encryptJson(vault.key!, vault.keyId!, {
        tenantId: session.tenant.id, cycleId: workflow.cycle.id, identityId: member.identityId,
        purpose: "committee-display", schemaVersion: 1,
      }, { displayName: member.displayName })).envelope,
      roleCode: member.roleCode,
      votingRight: member.votingRight,
      pastoralCapacity: member.pastoralCapacity,
    })));
    await workflowApi.configureCommittee(workflow.cycle.id, { expectedCycleVersion: version, members: prepared });
  }

  const roster = electors.length ? electors : committee.filter((member) => member.identityId).map((member) => ({ identityId: member.identityId, canPropose: member.votingRight, canVote: member.votingRight, recused: false }));
  return <div className="grid gap-5 xl:grid-cols-2">
    <section className="surface-card">
      <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.40a8140186f0")}</p><h2>{message(locale, "screen.workflowConsole.4ebc1753057a")}</h2></div><Badge variant="outline">{workflow.sessions.length}</Badge></div>
      <div className="mb-4 space-y-2">{workflow.sessions.map((item) => <div key={item.id} className="rounded-xl border p-3"><strong>{item.sequence}. {item.title}</strong><small className="block text-slate-500">{formatInTenantTimeZone(item.starts_at, locale, workflow.cycle.timezone, { dateStyle: "medium", timeStyle: "short" })} · {workflow.cycle.timezone}</small></div>)}</div>
      <form className="grid gap-3" onSubmit={(event) => { event.preventDefault(); void act("session", async () => {
        if (!vault.key || !vault.keyId || vault.tenantId !== session.tenant.id) {
          throw new Error(message(locale, "screen.workflowConsole.1f32d13d9559"));
        }
        const sessionId = crypto.randomUUID();
        const sealedTitle = await sealSessionTitle(vault.key, vault.keyId, {
          tenantId: session.tenant.id,
          cycleId: workflow.cycle.id,
          sessionId,
          titleVersion: 1,
        }, sessionForm.title);
        await workflowApi.addSession(workflow.cycle.id, {
          sessionId,
          expectedCycleVersion: version,
          sequence: sessionForm.sequence,
          titleEnvelope: sealedTitle.envelope,
          titleContentHash: sealedTitle.contentHash,
          startsAt: localDateTimeInZoneToIso(sessionForm.startsAt, workflow.cycle.timezone),
          endsAt: localDateTimeInZoneToIso(sessionForm.endsAt, workflow.cycle.timezone),
        });
        setSessionForm((current) => ({ ...current, sequence: current.sequence + 1, startsAt: "", endsAt: "" }));
      }); }}>
        <div className="grid gap-3 sm:grid-cols-[90px_1fr]"><Field label={message(locale, "screen.workflowConsole.a2c48039feac")}><Input type="number" min={1} value={sessionForm.sequence} onChange={(event) => setSessionForm({ ...sessionForm, sequence: Number(event.target.value) })} /></Field><Field label={message(locale, "screen.workflowConsole.ec25eb1a8707")}><Input value={sessionForm.title} maxLength={160} onChange={(event) => setSessionForm({ ...sessionForm, title: event.target.value })} required /></Field></div>
        <div className="grid gap-3 sm:grid-cols-2"><Field label={message(locale, "screen.workflowConsole.c91ca116b24c")}><Input type="datetime-local" value={sessionForm.startsAt} onChange={(event) => setSessionForm({ ...sessionForm, startsAt: event.target.value })} required /></Field><Field label={message(locale, "screen.workflowConsole.36f88fc440e3")}><Input type="datetime-local" value={sessionForm.endsAt} onChange={(event) => setSessionForm({ ...sessionForm, endsAt: event.target.value })} required /></Field></div>
        <Button disabled={Boolean(busy) || !vault.key || vault.tenantId !== session.tenant.id || !["draft", "active"].includes(workflow.cycle.status)}><Plus /> {message(locale, "screen.workflowConsole.7a19dcb3ff09")}</Button>
      </form>
    </section>

    <section className="surface-card">
      <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.6b110610d3b9")}</p><h2>{message(locale, "screen.workflowConsole.dac15679798c")}</h2></div><Badge variant="outline">{workflow.processes.length}</Badge></div>
      <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); void act("vacancy", () => workflowApi.configureVacancy(workflow.cycle.id, {
        expectedCycleVersion: version, officeId: vacancy.officeId, vacancyCount: vacancy.vacancyCount,
        maxProposalSelections: vacancy.maxProposalSelections, maxBallotSelections: vacancy.maxBallotSelections,
        decisionRule: { kind: "PLURALITY" }, abstentionRule: "EXCLUDED_FROM_CANDIDATE_TOTALS",
        tiebreakPolicy: "NEW_BALLOT_ROUND", quorumRule: { kind: "ALL_REQUIRED" }, aggregateAudience: "committee", agendaOrder: vacancy.agendaOrder,
      })); }}>
        <Field label={message(locale, "screen.workflowConsole.d873162dbc91")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={vacancy.officeId} onChange={(event) => setVacancy({ ...vacancy, officeId: event.target.value })} required><option value="">{message(locale, "screen.workflowConsole.30360a3bdaf2")}</option>{configurableOffices.map((office) => <option key={String(office.id)} value={String(office.id)}>{localizedName(office.names as LocalizedNames, locale, String(office.canonicalCode ?? office.id))} · {appointmentMechanismLabel(locale, String(office.appointmentMechanism ?? ""))}</option>)}</select></Field>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><NumberField label={message(locale, "screen.workflowConsole.01c1bd2abc45")} value={vacancy.vacancyCount} set={(value) => setVacancy({ ...vacancy, vacancyCount: value })} /><NumberField label={message(locale, "screen.workflowConsole.df8e5f4eb9b6")} value={vacancy.maxProposalSelections} set={(value) => setVacancy({ ...vacancy, maxProposalSelections: value })} /><NumberField label={message(locale, "screen.workflowConsole.c9928dee1fb4")} value={vacancy.maxBallotSelections} set={(value) => setVacancy({ ...vacancy, maxBallotSelections: value })} /><NumberField label={message(locale, "screen.workflowConsole.e0185aa59b56")} value={vacancy.agendaOrder} set={(value) => setVacancy({ ...vacancy, agendaOrder: value })} /></div>
        <Button disabled={Boolean(busy) || workflow.cycle.status !== "draft"}><Plus /> {message(locale, "screen.workflowConsole.7952a50484ca")}</Button>
      </form>
      {separateProcedureOffices.length > 0 && <details className="mt-4 overflow-hidden rounded-2xl border border-amber-200 bg-amber-50/70">
        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-amber-950">{message(locale, "screen.workflowConsole.26cea43b62e6")} · {separateProcedureOffices.length}</summary>
        <div className="border-t border-amber-200 px-4 py-3"><p className="text-sm text-amber-900">{message(locale, "screen.workflowConsole.bdba5fb65a24")}</p><ul className="mt-3 grid gap-2 sm:grid-cols-2">{separateProcedureOffices.map((office) => <li key={String(office.id)} className="rounded-xl border border-amber-200 bg-white px-3 py-2 text-xs"><strong className="block text-slate-900">{localizedName(office.names as LocalizedNames, locale, String(office.canonicalCode ?? office.id))}</strong><span className="text-slate-500">{appointmentMechanismLabel(locale, String(office.appointmentMechanism ?? ""))}</span></li>)}</ul></div>
      </details>}
      <div className="mt-4 space-y-2">{workflow.processes.map((item) => <div key={item.id} className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border p-3 ${item.enabled ? "bg-white" : "border-slate-300 bg-slate-100"}`}><span><strong className="block">{localizedName(item.names, locale, item.canonical_code)}</strong><small className="text-slate-500">{message(locale, "screen.workflowConsole.470c31567aac")} {item.procedure_sequence} · {item.vacancy_count} {message(locale, "screen.workflowConsole.499769df80c7")}</small></span><div className="flex flex-wrap items-center gap-2"><Badge variant={item.enabled ? "default" : "outline"}>{item.enabled ? message(locale, "screen.workflowConsole.a9a9572132c6") : message(locale, "screen.workflowConsole.14a82ef6df2a")}</Badge><Badge variant="outline">{phaseLabel(locale, item.phase)}</Badge>{item.procedure_sequence === 1 && ["draft", "active"].includes(workflow.cycle.status) && (item.enabled ? <AlertDialog><AlertDialogTrigger asChild><Button type="button" size="sm" variant="outline" disabled={Boolean(busy)}>{message(locale, "screen.workflowConsole.7d70d55c328a")}</Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{message(locale, "screen.workflowConsole.5c10ed66f592")}</AlertDialogTitle><AlertDialogDescription>{message(locale, "screen.workflowConsole.09aaca31e1be")}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{message(locale, "screen.workflowConsole.18e29ea869c8")}</AlertDialogCancel><AlertDialogAction onClick={() => void act(`applicability:${item.id}`, () => workflowApi.setProcessApplicability(item.id, { expectedCycleVersion: workflow.cycle.version, expectedProcessVersion: item.version, enabled: false, reasonCode: "CYCLE_STRUCTURE_NOT_APPLICABLE" }), message(locale, "screen.workflowConsole.8efb03570b68"))}>{message(locale, "screen.workflowConsole.6a82259433f5")}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog> : <Button type="button" size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => void act(`applicability:${item.id}`, () => workflowApi.setProcessApplicability(item.id, { expectedCycleVersion: workflow.cycle.version, expectedProcessVersion: item.version, enabled: true, reasonCode: "CYCLE_STRUCTURE_APPLICABILITY_RESTORED" }), message(locale, "screen.workflowConsole.c12fb10e9599"))}><ArchiveRestore /> {message(locale, "screen.workflowConsole.0c6514a13b29")}</Button>)}</div></div>)}</div>
    </section>

    <WorkflowSessionConsole
      cycleId={workflow.cycle.id}
      locale={locale}
      tenantId={session.tenant.id}
      timeZone={workflow.cycle.timezone}
      workflowSessions={workflow.sessions}
      processes={workflow.processes.filter(({ enabled }) => enabled)}
      committee={workflow.committee}
      committeeCandidates={committeeCandidates}
      members={members}
      canManageSessions={hasPermissions(session, "cycle.manage")}
      canManageAttendanceDirectory={canManageCommitteeDirectory}
      vaultKey={vault.key}
      vaultKeyId={vault.keyId}
      vaultKeyFor={vault.keyFor}
      vaultKeyringRevision={vault.keyringRevision}
      busy={busy}
      act={act}
    />

    <section className="surface-card xl:col-span-2">
      <div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.abaf995a3b2e")}</p><h2>{message(locale, "screen.workflowConsole.bf62a0372944")}</h2></div><Badge variant="outline">v{version}</Badge></div>
      {canManageCommitteeDirectory ? <>
      <div className="space-y-3">{committee.map((member, index) => <div key={index} className="grid gap-2 rounded-2xl border p-3 md:grid-cols-[1.1fr_1fr_1fr_160px_auto]">
        <select aria-label={message(locale, "screen.workflowConsole.48ba824c0a06")} className="h-10 rounded-md border bg-white px-2 text-sm" value={member.identityId} onChange={(event) => {
          const selected = committeeCandidates.find(({ identityId }) => identityId === event.target.value);
          updateAt(committee, index, { ...member, identityId: event.target.value, displayName: selected?.displayName ?? "" }, setCommittee);
        }} required><option value="">{message(locale, "screen.workflowConsole.15287bb7c0ad")}</option>{committeeCandidates.map((candidate) => <option key={candidate.identityId} value={candidate.identityId}>{candidate.displayName} · {candidate.email}</option>)}</select>
        <select aria-label={message(locale, "screen.workflowConsole.284ddaec5003")} className="h-10 rounded-md border bg-white px-2 text-sm" value={member.memberId} onChange={(event) => updateAt(committee, index, { ...member, memberId: event.target.value }, setCommittee)}><option value="">{message(locale, "screen.workflowConsole.76be0d848eef")}</option>{members.map((item) => <option key={item.id} value={item.id}>{item.shortId}</option>)}</select>
        <Input aria-label={message(locale, "screen.workflowConsole.19c1f3652481")} placeholder={message(locale, "screen.workflowConsole.19c1f3652481")} value={member.displayName} onChange={(event) => updateAt(committee, index, { ...member, displayName: event.target.value }, setCommittee)} required />
        <select aria-label={message(locale, "screen.workflowConsole.dc022ea29c25")} className="h-10 rounded-md border bg-white px-2 text-sm" value={member.roleCode} onChange={(event) => updateAt(committee, index, { ...member, roleCode: event.target.value as CommitteeDraft["roleCode"] }, setCommittee)}>{(["chair","pastor","secretary","member","custodian","advisor"] as const).map((role) => <option key={role} value={role}>{committeeRoleLabel(locale, role)}</option>)}</select>
        <div className="flex items-center gap-2"><label className="flex items-center gap-1 text-xs"><Checkbox checked={member.votingRight} onCheckedChange={(checked) => updateAt(committee, index, { ...member, votingRight: checked === true }, setCommittee)} /> {message(locale, "screen.workflowConsole.e9e17a87ebc1")}</label><label className="flex items-center gap-1 text-xs"><Checkbox checked={member.pastoralCapacity} onCheckedChange={(checked) => updateAt(committee, index, { ...member, pastoralCapacity: checked === true }, setCommittee)} /> {message(locale, "screen.workflowConsole.2fef83acf683")}</label><Button type="button" size="sm" variant="ghost" aria-label={message(locale, "screen.workflowConsole.be83b0fc3bf3")} onClick={() => setCommittee((items) => items.filter((_, itemIndex) => itemIndex !== index))}>×</Button></div>
      </div>)}</div>
      <div className="mt-3 flex flex-wrap gap-2"><Button type="button" variant="outline" onClick={() => setCommittee((items) => [...items, emptyCommitteeMember()])}><Plus /> {message(locale, "screen.workflowConsole.61854ff3e331")}</Button><Button type="button" disabled={Boolean(busy) || workflow.cycle.status !== "draft"} onClick={() => void act("committee", saveCommittee)}>{message(locale, "screen.workflowConsole.5091f29d5a99")}</Button></div>
      </> : <PermissionNotice locale={locale} compact />}
      <div className="my-5 border-t" />
      <div className="grid gap-3 md:grid-cols-2">{roster.map((elector, index) => <div key={`${elector.identityId}:${index}`} className="flex flex-wrap items-center gap-3 rounded-xl border p-3"><strong className="mr-auto text-xs">{committee.find(({ identityId }) => identityId === elector.identityId)?.displayName || message(locale, "screen.workflowConsole.608b5210b6c5")}</strong>{(["canPropose","canVote","recused"] as const).map((field) => <label key={field} className="flex items-center gap-1 text-xs"><Checkbox checked={elector[field]} onCheckedChange={(checked) => { const next = [...roster]; next[index] = { ...elector, [field]: checked === true }; setElectors(next); }} />{field === "canPropose" ? message(locale, "screen.workflowConsole.67ec45c319ed") : field === "canVote" ? message(locale, "screen.workflowConsole.8bc955f026df") : message(locale, "screen.workflowConsole.b1b6b2f5f430")}</label>)}</div>)}</div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-slate-500">{message(locale, "screen.workflowConsole.52aafdd0e625")}</p><Button disabled={Boolean(busy) || workflow.cycle.status !== "draft" || !roster.length} onClick={() => void act("electorate", () => workflowApi.configureElectorate(workflow.cycle.id, { expectedCycleVersion: version, electors: roster }))}>{message(locale, "screen.workflowConsole.1967414d9038")}</Button></div>
    </section>

    <section className="rounded-2xl border border-emerald-200 bg-emerald-50 p-5 xl:col-span-2"><div className="flex flex-wrap items-center gap-4"><span className="grid size-12 place-items-center rounded-2xl bg-emerald-600 text-white"><Check /></span><div className="mr-auto"><strong className="block text-emerald-950">{message(locale, "screen.workflowConsole.fae456934231")}</strong><p className="text-sm text-emerald-800">{message(locale, "screen.workflowConsole.349446a5ed12")}</p></div><Button disabled={Boolean(busy) || workflow.cycle.status !== "draft" || readinessPercent(workflow) < 100} onClick={() => void act("activate-cycle", () => workflowApi.activateCycle(workflow.cycle.id, version), message(locale, "screen.workflowConsole.d5930d212732"))}><ShieldCheck /> {message(locale, "screen.workflowConsole.534ef7839822")}</Button></div></section>
  </div>;
}

function ProcessPanel({ workflow, process, selectedProcessId, setSelectedProcessId, locale, session, vault, busy, act }: {
  workflow: VisibleCycleWorkflow; process?: WorkflowProcess; selectedProcessId: string; setSelectedProcessId: (id: string) => void;
  locale: Locale; session: AuthenticatedSession; vault: ReturnType<typeof useVault>; busy?: string;
  act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
}) {
  const canOpenProposals = hasPermissions(session, "proposal.open");
  const canCloseProposals = hasPermissions(session, "proposal.close");
  const canReviewCandidates = hasPermissions(session, "candidate.review");
  const canOpenBallots = hasPermissions(session, "ballot.open");
  const canCloseBallots = hasPermissions(session, "ballot.close");
  const canReadAggregates = hasPermissions(session, "aggregate.read");
  const canRecordLinkedDesignation = hasPermissions(session, "linked-designation.record");
  const canResolveEligibility = hasPermissions(session, "workflow.eligibility.resolve");
  const canRestartEligibility = canResolveEligibility && canOpenProposals;
  const canExcludeEligibility = canResolveEligibility && canReviewCandidates;
  const processEnabled = process?.enabled !== false;
  const processLane = classifyAppointmentWorkflow(process?.appointment_mechanism ?? "");
  const isOrdinaryWorkflow = processEnabled && processLane === "ordinary_proposal_ballot";
  const isLinkedDesignation = processEnabled && processLane === "linked_designation";
  const isSeparateProcedure = processEnabled && !isOrdinaryWorkflow && !isLinkedDesignation;
  const reviewQuery = useQuery({
    queryKey: ["workflow-review", session.tenant.id, process?.id],
    queryFn: () => workflowApi.reviewBoard(process!.id), enabled: isOrdinaryWorkflow && canReviewCandidates && Boolean(process && ["DEPURACION","LISTA_CONFIRMADA","SIN_CANDIDATOS"].includes(process.phase)),
  });
  const [selectionOverrides, setSelectionOverrides] = useState<Record<string, boolean>>({});
  const [resolutionCode, setResolutionCode] = useState<keyof typeof eligibilityReasonCodeByResolution>("ANNUL_AND_RESTART");
  const [resolutionNote, setResolutionNote] = useState("");
  const [resolutionAcknowledgement, setResolutionAcknowledgement] = useState<string | null>(null);
  const [linkedBaseAssignmentId, setLinkedBaseAssignmentId] = useState("");
  const [linkedDesignationNote, setLinkedDesignationNote] = useState("");
  const [linkedDesignationAcknowledged, setLinkedDesignationAcknowledged] = useState(false);
  const [linkedDesignationSessionId, setLinkedDesignationSessionId] = useState(workflow.sessions[0]?.id ?? "");
  const [workloadNotice, setWorkloadNotice] = useState<{ processId: string; count: number; independentWarningCount: number; highestNominalLoad: number; highestIndependentLoad: number }>();
  const selectedCandidacies = (reviewQuery.data?.candidates ?? []).filter((candidate) => selectionOverrides[candidate.id]
    ?? ["UNDER_REVIEW","PRELIMINARY_ACCEPTED","CONFIRMED_FOR_BALLOT"].includes(candidate.state)).map((candidate) => candidate.id);
  const activeEligibilityPauses = (workflow.eligibilityPauses ?? []).filter((pause) => pause.processId === process?.id && !pause.resolvedAt);
  const linkedBaseOfficeCode = typeof process?.catalog_metadata?.linkedBaseOfficeCode === "string"
    ? process.catalog_metadata.linkedBaseOfficeCode
    : "";
  const linkedBaseAssignments = workflow.assignments.filter((assignment) => assignment.effective
    && assignment.office_snapshot?.canonicalCode === linkedBaseOfficeCode
    && ["PROPUESTA_INTERNA", "ACEPTACION_PENDIENTE", "ACEPTADA", "PRESENTADA_A_IGLESIA", "ELEGIDA_POR_IGLESIA", "VIGENTE"].includes(assignment.state));
  const selectedLinkedBaseAssignmentId = linkedBaseAssignments.some(({ id }) => id === linkedBaseAssignmentId)
    ? linkedBaseAssignmentId
    : linkedBaseAssignments[0]?.id ?? "";
  const pausedOpenRound = activeEligibilityPauses.some((pause) => ["PROPUESTAS_ABIERTAS", "VOTACION_ABIERTA"].includes(pause.previousRoundPhase ?? ""));
  const pausedMemberIds = new Set(activeEligibilityPauses.map(({ memberId }) => memberId));
  const eligibilityAffectedAssignments = workflow.assignments.filter((assignment) => assignment.process_id === process?.id
    && pausedMemberIds.has(assignment.member_id));
  const eligibilityReplacementProcesses = workflow.processes.filter((candidate) => eligibilityAffectedAssignments.some(
    (assignment) => candidate.replacement_for_assignment_id === assignment.id,
  ));
  const canCloseAfterReplacement = canResolveEligibility
    && activeEligibilityPauses.length > 0
    && activeEligibilityPauses.every(({ previousRoundPhase }) => previousRoundPhase === null)
    && eligibilityAffectedAssignments.length === 1
    && eligibilityAffectedAssignments.every(({ effective }) => !effective)
    && eligibilityReplacementProcesses.length === 1;
  const canResumeAffectedAssignments = eligibilityAffectedAssignments.length === 0
    || (eligibilityAffectedAssignments.every(({ effective }) => effective) && eligibilityReplacementProcesses.length === 0);
  const availableResolutions = [
    ...(canRestartEligibility && eligibilityAffectedAssignments.length === 0 ? [{ code: "ANNUL_AND_RESTART" as const, label: message(locale, "screen.workflowConsole.3e5583c78c92") }] : []),
    ...(!pausedOpenRound && canResolveEligibility && canResumeAffectedAssignments ? [{ code: "RESUME_UNCHANGED" as const, label: message(locale, "screen.workflowConsole.31033992f1c4") }] : []),
    ...(canExcludeEligibility && eligibilityAffectedAssignments.length === 0 ? [{ code: "EXCLUDE_AND_REVIEW" as const, label: message(locale, "screen.workflowConsole.516f70f9044e") }] : []),
    ...(canCloseAfterReplacement ? [{ code: "CLOSE_AFTER_REPLACEMENT" as const, label: message(locale, "screen.workflowConsole.d643387a6719") }] : []),
  ];
  const effectiveResolutionCode = availableResolutions.some(({ code }) => code === resolutionCode)
    ? resolutionCode
    : availableResolutions[0]?.code;
  const resolutionContextKey = `${process?.id ?? "none"}:${activeEligibilityPauses.map(({ id }) => id).sort().join(":")}:${effectiveResolutionCode ?? "none"}`;
  const resolutionAcknowledged = resolutionAcknowledgement === resolutionContextKey;
  if (!process) return <Empty title={message(locale, "screen.workflowConsole.b6b837d1b63e")} />;
  const proposalRound = latestRound(workflow.rounds, process.id, "proposal");
  const ballotRound = latestRound(workflow.rounds, process.id, "vote");
  const orderedProcesses = [...workflow.processes].sort((left, right) => Number(right.enabled !== false) - Number(left.enabled !== false) || left.agenda_order - right.agenda_order || left.procedure_sequence - right.procedure_sequence);

  if (!processEnabled) return <div className="space-y-5">
    <section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.b2c81f726404")}</p><h2>{localizedName(process.names, locale, process.canonical_code)}</h2></div><Badge variant="outline">{message(locale, "screen.workflowConsole.14a82ef6df2a")}</Badge></div>
      <Field label={message(locale, "screen.workflowConsole.470c31567aac")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={selectedProcessId} onChange={(event) => setSelectedProcessId(event.target.value)}>{orderedProcesses.map((item) => <option key={item.id} value={item.id}>{item.enabled === false ? `${message(locale, "screen.workflowConsole.9fbc432c3418")} · ` : ""}{item.agenda_order}. {localizedName(item.names, locale, item.canonical_code)} · #{item.procedure_sequence}</option>)}</select></Field>
    </section>
    <Alert><History /><AlertTitle>{message(locale, "screen.workflowConsole.ca99f977e164")}</AlertTitle><AlertDescription>{message(locale, "screen.workflowConsole.050e24160ef6")}</AlertDescription></Alert>
  </div>;

  async function consolidate() {
    if (!proposalRound) throw new Error(message(locale, "screen.workflowConsole.00fc741c650f"));
    if (!vault.key) throw new Error(message(locale, "screen.workflowConsole.dd353469f561"));
    let manifest: ProposalManifest;
    try { manifest = await workflowApi.proposalManifest(proposalRound.id); }
    catch (error) {
      if (!(error instanceof ApiError) || error.status !== 404) throw error;
      manifest = await workflowApi.createProposalManifest(proposalRound.id, proposalRound.version);
    }
    await verifyProposalManifest(manifest);
    const submissions = await Promise.all(manifest.entries.map((entry) => openJsonEnvelope<ProposalSubmissionPlaintext>({
      resolver: vault,
      tenantId: session.tenant.id,
      envelope: entry.envelope,
      aad: {
        tenantId: session.tenant.id, cycleId: workflow.cycle.id, roundId: manifest.roundId,
        purpose: "proposal", schemaVersion: 1, roundVersion: entry.submissionRoundVersion,
        candidateSetHash: manifest.candidateSetHash, rulesHash: manifest.rulesHash,
      },
    })));
    const { aggregate, aggregateHash } = await buildProposalAggregate({ manifest, submissions, maxProposalSelections: process!.max_proposal_selections });
    await workflowApi.consolidateProposals(proposalRound.id, {
      expectedRoundVersion: proposalRound.version,
      expectedProcessVersion: process!.version,
      manifestId: manifest.manifestId,
      manifestHash: manifest.manifestHash,
      effectiveResponseDenominator: aggregate.effectiveResponseDenominator,
      aggregateHash,
      candidates: aggregate.candidates,
    });
  }

  async function createAssignments() {
    if (!ballotRound) throw new Error(message(locale, "screen.workflowConsole.248fa10dc738"));
    const published = await api.publishedAggregate(ballotRound.id);
    const result = await workflowApi.createProvisionalAssignments(process!.id, ballotRound.id, process!.version, published.aggregateHash);
    const warnings = result.assignments.filter(({ warning }) => warning);
    const independentWarnings = warnings.filter(({ independentLoadWarning }) => independentLoadWarning);
    setWorkloadNotice(warnings.length === 0 ? undefined : {
      processId: process!.id,
      count: warnings.length,
      independentWarningCount: independentWarnings.length,
      highestNominalLoad: Math.max(...warnings.map(({ workload }) => workload.nominal_count)),
      highestIndependentLoad: Math.max(...warnings.map(({ workload }) => workload.independent_count)),
    });
    return result;
  }

  async function prepareTiebreak() {
    if (!ballotRound) throw new Error(message(locale, "screen.workflowConsole.5a25c2dfb661"));
    const published = await api.publishedAggregate(ballotRound.id);
    await workflowApi.prepareTiebreakRound(process!.id, process!.version, ballotRound.id, published.aggregateHash);
  }

  async function resolveEligibilityPause() {
    if (!activeEligibilityPauses.length) throw new Error(message(locale, "screen.workflowConsole.3a0052fde333"));
    if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.workflowConsole.96e9a5f4e08e"));
    if (!effectiveResolutionCode) throw new Error(message(locale, "screen.workflowConsole.688c3565ff2b"));
    if (resolutionNote.trim().length < 3 || !resolutionAcknowledged) {
      throw new Error(message(locale, "screen.workflowConsole.989f67518307"));
    }
    const resolutionReasonCode = eligibilityReasonCodeByResolution[effectiveResolutionCode];
    const pauseIds = activeEligibilityPauses.map(({ id }) => id).sort();
    const pausedRoundId = activeEligibilityPauses[0]?.roundId ?? null;
    const pausedRound = pausedRoundId ? workflow.rounds.find(({ id }) => id === pausedRoundId) : undefined;
    if (pausedRoundId && !pausedRound) throw new Error(message(locale, "screen.workflowConsole.bd8cfa838309"));
    const evidenceEnvelope = (await encryptJson(vault.key, vault.keyId, {
      tenantId: session.tenant.id,
      processId: process!.id,
      pauseIds,
      resolutionCode: effectiveResolutionCode,
      reasonCode: resolutionReasonCode,
      purpose: "eligibility-pause-resolution",
      schemaVersion: 1,
    }, { rationale: resolutionNote.trim() })).envelope;
    await workflowApi.resolveEligibilityPause(process!.id, {
      expectedProcessVersion: process!.version,
      ...(pausedRound ? { expectedRoundVersion: pausedRound.version } : {}),
      expectedPauseIds: pauseIds,
      resolutionCode: effectiveResolutionCode,
      reasonCode: resolutionReasonCode,
      evidenceEnvelope,
    });
    setResolutionNote("");
    setResolutionAcknowledgement(null);
  }

  async function createLinkedDesignation() {
    if (!selectedLinkedBaseAssignmentId) throw new Error(message(locale, "screen.workflowConsole.85eb843e2d97"));
    if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.workflowConsole.543cdd7741c8"));
    if (linkedDesignationNote.trim().length < 3 || !linkedDesignationAcknowledged) {
      throw new Error(message(locale, "screen.workflowConsole.a6bbabba21d9"));
    }
    const evidenceEnvelope = (await encryptJson(vault.key, vault.keyId, {
      tenantId: session.tenant.id,
      processId: process!.id,
      baseAssignmentId: selectedLinkedBaseAssignmentId,
      purpose: "linked-designation",
      schemaVersion: 1,
    }, { rationale: linkedDesignationNote.trim() })).envelope;
    await workflowApi.createLinkedDesignation(process!.id, {
      expectedProcessVersion: process!.version,
      baseAssignmentId: selectedLinkedBaseAssignmentId,
      evidenceEnvelope,
      ...(linkedDesignationSessionId ? { sessionId: linkedDesignationSessionId } : {}),
    });
    setLinkedDesignationNote("");
    setLinkedDesignationAcknowledged(false);
  }

  return <div className="space-y-5">
    <section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.685776ec3160")}</p><h2>{localizedName(process.names, locale, process.canonical_code)}</h2></div><Badge>{phaseLabel(locale, process.phase)}</Badge></div>
      <div className="grid gap-3 md:grid-cols-[280px_1fr]"><Field label={message(locale, "screen.workflowConsole.470c31567aac")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={selectedProcessId} onChange={(event) => setSelectedProcessId(event.target.value)}>{orderedProcesses.map((item) => <option key={item.id} value={item.id}>{item.enabled === false ? `${message(locale, "screen.workflowConsole.9fbc432c3418")} · ` : ""}{item.agenda_order}. {localizedName(item.names, locale, item.canonical_code)} · #{item.procedure_sequence}</option>)}</select></Field><PhaseRail locale={locale} phase={process.phase} /></div>
    </section>

    {isSeparateProcedure && <section className="overflow-hidden rounded-[1.5rem] border border-amber-300 bg-gradient-to-br from-amber-50 via-white to-slate-50 shadow-sm" aria-labelledby="separate-procedure-title">
      <div className="flex flex-wrap items-start gap-3 p-5"><span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-amber-600 text-white"><Gavel /></span><div className="min-w-0 flex-1"><p className="eyebrow">{message(locale, "screen.workflowConsole.14fc83d859af")}</p><h2 id="separate-procedure-title" className="text-lg font-bold">{appointmentMechanismLabel(locale, process.appointment_mechanism)}</h2><p className="mt-1 max-w-3xl text-sm text-slate-600">{processLane === "configuration_pending" ? message(locale, "screen.workflowConsole.3fdd9f346bd7") : message(locale, "screen.workflowConsole.0056b8053254")}</p></div><Badge variant="outline">{message(locale, "screen.workflowConsole.d75a06b8956f")}</Badge></div>
    </section>}

    {workloadNotice?.processId === process.id && <Alert className={workloadNotice.independentWarningCount > 0 ? "border-amber-300 bg-amber-50" : "border-cyan-300 bg-cyan-50"} role="status"><ShieldAlert /><AlertTitle>{workloadNotice.independentWarningCount > 0 ? message(locale, "screen.workflowConsole.9aaebb31f36b") : message(locale, "screen.workflowConsole.c1aac190ae15")}</AlertTitle><AlertDescription>{message(locale, "screen.workflowConsole.0dec05d4f538", { value0: workloadNotice.count, value1: workloadNotice.highestNominalLoad, value2: workloadNotice.independentWarningCount, value3: workloadNotice.highestIndependentLoad })}</AlertDescription></Alert>}

    {activeEligibilityPauses.length > 0 && <section className="rounded-[1.5rem] border border-amber-300 bg-gradient-to-br from-amber-50 to-white p-5 shadow-sm" aria-labelledby="eligibility-resolution-title">
      <div className="flex flex-wrap items-start gap-3"><span className="grid size-11 place-items-center rounded-2xl bg-amber-500 text-white"><ShieldCheck /></span><div className="min-w-0 flex-1"><p className="eyebrow">{message(locale, "screen.workflowConsole.9bb3c00bbaec")}</p><h2 id="eligibility-resolution-title" className="text-lg font-bold">{message(locale, "screen.workflowConsole.5017e4e27f62")}</h2><p className="mt-1 text-sm text-slate-600">{message(locale, "screen.workflowConsole.40780bbc7f5e")}</p></div><Badge variant="outline">{activeEligibilityPauses.length} {message(locale, "screen.workflowConsole.e3eede8e86c5")}</Badge></div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{activeEligibilityPauses.map((pause) => <div key={pause.id} className="rounded-xl border border-amber-200 bg-white p-3 text-xs"><strong className="block text-slate-900">{pause.reasonCode.replaceAll("_", " ")}</strong><span className="mt-1 block text-slate-500" title={pause.memberId}>{message(locale, "screen.workflowConsole.604bcfdd71dd")} {pause.memberId.slice(0, 8)}… · v{pause.memberVersion}</span><span className="block text-slate-500">{phaseLabel(locale, pause.previousProcessPhase)}{pause.previousRoundPhase ? ` · ${phaseLabel(locale, pause.previousRoundPhase)}` : ""}</span><time className="mt-1 block text-slate-400">{formatInTenantTimeZone(pause.createdAt, locale, workflow.cycle.timezone, { dateStyle: "short", timeStyle: "short" })}</time></div>)}</div>
      {canResolveEligibility ? <div className="mt-5 grid gap-4 lg:grid-cols-2"><Field label={message(locale, "screen.workflowConsole.f98a8c6e57e8")}><select className="h-10 rounded-md border bg-white px-3 text-sm" value={effectiveResolutionCode ?? ""} onChange={(event) => setResolutionCode(event.target.value as typeof resolutionCode)}>{availableResolutions.map((option) => <option key={option.code} value={option.code}>{option.label}</option>)}</select></Field><Field label={message(locale, "screen.workflowConsole.50aefc6aed7a")}><code className="flex h-10 items-center rounded-md border bg-slate-50 px-3 text-xs">{effectiveResolutionCode ? eligibilityReasonCodeByResolution[effectiveResolutionCode] : "—"}</code></Field><label className="grid gap-1.5 lg:col-span-2"><Label>{message(locale, "screen.workflowConsole.cb0c275a55a3")}</Label><textarea className="min-h-24 rounded-md border bg-white px-3 py-2 text-sm" value={resolutionNote} onChange={(event) => setResolutionNote(event.target.value)} maxLength={2_000} placeholder={message(locale, "screen.workflowConsole.841330a4541c")} /></label><label className="flex items-start gap-2 text-sm lg:col-span-2"><Checkbox checked={resolutionAcknowledged} onCheckedChange={(checked) => setResolutionAcknowledgement(checked === true ? resolutionContextKey : null)} /><span>{message(locale, "screen.workflowConsole.1899258e59f9")}</span></label><div className="lg:col-span-2"><Button disabled={Boolean(busy) || !vault.key || !resolutionAcknowledged || resolutionNote.trim().length < 3 || availableResolutions.length === 0} onClick={() => void act("resolve-eligibility", resolveEligibilityPause, message(locale, "screen.workflowConsole.42c086d78b75"))}>{busy === "resolve-eligibility" ? <LoaderCircle className="animate-spin" /> : <RefreshCw />} {message(locale, "screen.workflowConsole.b7e11a5c818a")}</Button></div></div> : <div className="mt-4"><PermissionNotice locale={locale} compact /></div>}
    </section>}

    {isLinkedDesignation && <section className="overflow-hidden rounded-[1.5rem] border border-cyan-200 bg-gradient-to-br from-cyan-50 via-white to-indigo-50 shadow-sm" aria-labelledby="linked-designation-title">
      <div className="border-b border-cyan-100 p-5 sm:flex sm:items-start sm:justify-between sm:gap-4"><div className="flex items-start gap-3"><span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-gradient-to-br from-cyan-600 to-indigo-600 text-white shadow-sm"><Sparkles /></span><div><p className="eyebrow">{message(locale, "screen.workflowConsole.a8600c67be3b")}</p><h2 id="linked-designation-title" className="text-lg font-bold">{message(locale, "screen.workflowConsole.2f900897b262")}</h2><p className="mt-1 max-w-3xl text-sm text-slate-600">{message(locale, "screen.workflowConsole.e2a2a7070886")}</p></div></div><Badge className="mt-3 sm:mt-0" variant="outline">{message(locale, "screen.workflowConsole.49a5bac6c487")}</Badge></div>
      {!canRecordLinkedDesignation ? <div className="p-5"><PermissionNotice locale={locale} compact /></div> : linkedBaseAssignments.length === 0 ? <div className="p-5"><Alert><FileLock2 /><AlertTitle>{message(locale, "screen.workflowConsole.f3c6489b4dcd")}</AlertTitle><AlertDescription>{message(locale, "screen.workflowConsole.49b5686b181e")}</AlertDescription></Alert></div> : <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(280px,0.8fr)]"><div><Label>{message(locale, "screen.workflowConsole.a303f71893b9")}</Label><div className="mt-2 grid gap-2">{linkedBaseAssignments.map((base) => <button type="button" key={base.id} aria-pressed={selectedLinkedBaseAssignmentId === base.id} onClick={() => { setLinkedBaseAssignmentId(base.id); setLinkedDesignationAcknowledged(false); }} className={`rounded-2xl border p-3 text-left transition ${selectedLinkedBaseAssignmentId === base.id ? "border-cyan-500 bg-cyan-50 ring-2 ring-cyan-100" : "bg-white hover:border-cyan-300"}`}><div className="flex items-start justify-between gap-3"><div className="min-w-0">{base.member_snapshot ? <EncryptedIdentity compact locale={locale} tenantId={session.tenant.id} memberId={base.member_id} displayEnvelope={base.member_snapshot.displayEnvelope ?? null} photo={base.member_snapshot.photo ?? null} vault={vault} /> : <strong>{base.member_id.slice(0, 8)}…</strong>}<small className="mt-1 block text-slate-500">{localizedName(base.office_snapshot?.names, locale, linkedBaseOfficeCode)} · {assignmentLabel(locale, base.state)}</small></div>{selectedLinkedBaseAssignmentId === base.id && <CheckCircle2 className="shrink-0 text-cyan-600" />}</div></button>)}</div></div><div className="space-y-4"><Field label={message(locale, "screen.workflowConsole.ddb5e9fc68af")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={linkedDesignationSessionId} onChange={(event) => setLinkedDesignationSessionId(event.target.value)}><option value="">{message(locale, "screen.workflowConsole.2ff3e2b17025")}</option>{workflow.sessions.filter(({ status }) => status !== "cancelled").map((item) => <option key={item.id} value={item.id}>{item.sequence}. {item.title}</option>)}</select></Field><label className="grid gap-1.5"><Label>{message(locale, "screen.workflowConsole.cb0c275a55a3")}</Label><textarea className="min-h-28 rounded-md border bg-white px-3 py-2 text-sm" value={linkedDesignationNote} onChange={(event) => setLinkedDesignationNote(event.target.value)} maxLength={2_000} /></label><label className="flex items-start gap-2 text-sm"><Checkbox checked={linkedDesignationAcknowledged} onCheckedChange={(checked) => setLinkedDesignationAcknowledged(checked === true)} /><span>{message(locale, "screen.workflowConsole.df74e42a1b10")}</span></label><Button className="w-full" disabled={Boolean(busy) || !vault.key || !selectedLinkedBaseAssignmentId || linkedDesignationNote.trim().length < 3 || !linkedDesignationAcknowledged || !["CONFIGURADO", "VACANTE_PENDIENTE"].includes(process.phase)} onClick={() => void act("linked-designation", createLinkedDesignation, message(locale, "screen.workflowConsole.83a746e84bf7"))}>{busy === "linked-designation" ? <LoaderCircle className="animate-spin" /> : <UserCheck />} {message(locale, "screen.workflowConsole.352a91bbb7d8")}</Button></div></div>}
    </section>}

    {isOrdinaryWorkflow && <section className="grid gap-4 lg:grid-cols-3">
      <StageCard locale={locale} icon={Users} title={message(locale, "screen.workflowConsole.e3cd6351cf2b")} phase={proposalRound?.phase ?? "PENDIENTE"}>
        {canOpenProposals && (!proposalRound || ["CERRADO","ANULADO"].includes(proposalRound.phase)) && ["CONFIGURADO","VACANTE_PENDIENTE","SIN_CANDIDATOS"].includes(process.phase) && <Action busy={busy} id="prepare-proposal" onClick={() => act("prepare-proposal", () => workflowApi.prepareProposalRound(process.id, process.version))}>{message(locale, "screen.workflowConsole.ecff40aaf3ea")}</Action>}
        {canOpenProposals && proposalRound?.phase === "CONFIGURADO" && <Action busy={busy} id="open-proposal" onClick={() => act("open-proposal", () => workflowApi.openProposalRound(proposalRound.id, proposalRound.version, process.version))}>{message(locale, "screen.workflowConsole.ef5989d997ea")}</Action>}
        {canCloseProposals && proposalRound?.phase === "PROPUESTAS_ABIERTAS" && <Action busy={busy} id="close-proposal" onClick={() => act("close-proposal", () => workflowApi.closeProposalRound(proposalRound.id, proposalRound.version, process.version))}>{message(locale, "screen.workflowConsole.0b2ac5bbe195")}</Action>}
        {canCloseProposals && canReviewCandidates && proposalRound?.phase === "PROPUESTAS_CERRADAS" && <Action busy={busy} id="consolidate" onClick={() => act("consolidate", consolidate, message(locale, "screen.workflowConsole.716fd0684364"))}>{message(locale, "screen.workflowConsole.a61d1bd2c72c")}</Action>}
      </StageCard>
      <StageCard locale={locale} icon={ClipboardCheck} title={message(locale, "screen.workflowConsole.bc2b9f925650")} phase={process.phase === "DEPURACION" ? "DEPURACION" : process.phase === "LISTA_CONFIRMADA" ? "LISTA_CONFIRMADA" : "PENDIENTE"}><p className="text-sm text-slate-500">{message(locale, "screen.workflowConsole.f0ec6f1ada93")}</p></StageCard>
      <StageCard locale={locale} icon={Vote} title={message(locale, "screen.workflowConsole.baf2f94535d0")} phase={ballotRound?.phase ?? "PENDIENTE"}>
        {canOpenBallots && process.phase === "LISTA_CONFIRMADA" && !ballotRound && <Action busy={busy} id="prepare-ballot" onClick={() => act("prepare-ballot", () => workflowApi.prepareBallotRound(process.id, process.version))}>{message(locale, "screen.workflowConsole.7cdfaf948a80")}</Action>}
        {canOpenBallots && ballotRound?.phase === "LISTA_CONFIRMADA" && <Action busy={busy} id="open-ballot" onClick={() => act("open-ballot", () => workflowApi.openBallotRound(ballotRound.id, ballotRound.version, process.version))}>{message(locale, "screen.workflowConsole.303238eee85b")}</Action>}
        {canCloseBallots && ballotRound?.phase === "VOTACION_ABIERTA" && <Action busy={busy} id="close-ballot" onClick={() => act("close-ballot", () => workflowApi.closeBallotRound(ballotRound.id, ballotRound.version, process.version))}>{message(locale, "screen.workflowConsole.0b2ac5bbe195")}</Action>}
        {canReviewCandidates && canReadAggregates && ballotRound && ["VOTACION_CERRADA","RESULTADO_INTERNO"].includes(ballotRound.phase) && <Action busy={busy} id="assign" onClick={() => act("assign", createAssignments, message(locale, "screen.workflowConsole.29ac0a40f761"))}>{message(locale, "screen.workflowConsole.0ac7726b40a7")}</Action>}
        {canOpenBallots && canReadAggregates && process.phase === "DESEMPATE_PENDIENTE" && ballotRound?.phase === "CERRADO" && <Action busy={busy} id="prepare-tiebreak" onClick={() => act("prepare-tiebreak", prepareTiebreak, message(locale, "screen.workflowConsole.765bc0bd274b"))}>{message(locale, "screen.workflowConsole.1345aa52529a")}</Action>}
      </StageCard>
    </section>}

    {isOrdinaryWorkflow && reviewQuery.data && <section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.61bd5c764a64")}</p><h2>{message(locale, "screen.workflowConsole.3f859533f860")}</h2>{reviewQuery.data.process.participation && <p className="text-sm text-slate-500">{message(locale, "screen.workflowConsole.c614ea57e3e5")} {reviewQuery.data.process.participation.completedResponses}/{reviewQuery.data.process.participation.electorateDenominator} · {message(locale, "screen.workflowConsole.fa68c7ec33f6")} {reviewQuery.data.process.participation.effectiveResponseDenominator === 0 ? message(locale, "screen.workflowConsole.14a82ef6df2a") : reviewQuery.data.process.participation.effectiveResponseDenominator}</p>}</div><Badge variant="outline">{reviewQuery.data.candidates.length}</Badge></div>
      <div className="space-y-3">{reviewQuery.data.candidates.map((candidate) => <article key={candidate.id} className="grid items-center gap-3 rounded-2xl border p-4 md:grid-cols-[auto_1fr_auto_auto]">
        <Checkbox checked={selectedCandidacies.includes(candidate.id)} disabled={["WITHDRAWN","EXCLUDED","INELIGIBLE"].includes(candidate.state)} onCheckedChange={(checked) => setSelectionOverrides((items) => ({ ...items, [candidate.id]: checked === true }))} />
        <div><EncryptedIdentity locale={locale} tenantId={session.tenant.id} memberId={candidate.memberId} displayEnvelope={candidate.displayEnvelope} photo={candidate.photoSnapshot} vault={vault} /><small className="mt-1 block text-slate-500">{candidate.distinctProponentCount} {message(locale, "screen.workflowConsole.2fd307b171ad")} {candidate.supportDenominator} {message(locale, "screen.workflowConsole.6cf4e4e2de6f")} · {candidate.supportPercent === null ? message(locale, "screen.workflowConsole.14a82ef6df2a") : `${candidate.supportPercent}%`} · {message(locale, "screen.workflowConsole.f7eb61539b8c")} {reviewQuery.data.process.participation?.completedResponses ?? candidate.electorateDenominator}/{candidate.electorateDenominator}</small></div><Badge variant="outline">{candidacyLabel(locale, candidate.state)}</Badge>
        <ReviewActions key={`${candidate.id}:${candidate.state}`} locale={locale} candidate={candidate} processId={process.id} tenantId={session.tenant.id} vault={vault} busy={busy} act={act} />
      </article>)}</div>
      {process.phase === "DEPURACION" && <div className="mt-4 flex justify-end"><Button disabled={Boolean(busy)} onClick={() => void act("confirm-list", () => workflowApi.confirmCandidateList(process.id, { expectedProcessVersion: process.version, orderedCandidacyIds: selectedCandidacies }))}><Check /> {message(locale, "screen.workflowConsole.3195b3e55537")} ({selectedCandidacies.length})</Button></div>}
    </section>}
    {isOrdinaryWorkflow && canOpenBallots && ballotRound?.phase === "LISTA_CONFIRMADA" && <Alert><FileLock2 /><AlertTitle>{message(locale, "screen.workflowConsole.7288a2b5ae2d")}</AlertTitle><AlertDescription>{message(locale, "screen.workflowConsole.f9e30f9fd98c")}</AlertDescription></Alert>}
  </div>;
}

function AssignmentsPanel({ workflow, assignment, selectedAssignmentId, setSelectedAssignmentId, locale, session, vault, busy, act }: {
  workflow: VisibleCycleWorkflow; assignment?: WorkflowAssignment; selectedAssignmentId: string; setSelectedAssignmentId: (id: string) => void;
  locale: Locale; session: AuthenticatedSession; vault: ReturnType<typeof useVault>; busy?: string;
  act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
}) {
  const canReadAssignmentHistory = hasPermissions(session, "organigram.read");
  const canRecordConsent = hasPermissions(session, "consent.record");
  const canRecordCongregationalDecision = hasPermissions(session, "congregational-decision.record");
  const historyQuery = useQuery({ queryKey: ["assignment-history", session.tenant.id, assignment?.id], queryFn: () => workflowApi.assignmentHistory(assignment!.id), enabled: canReadAssignmentHistory && Boolean(assignment) });
  const [assignmentReasonCode, setAssignmentReasonCode] = useState<AssignmentLifecycleReasonCode>("TERM_COMPLETED_NO_VACANCY");
  const [institutionalSessionId, setInstitutionalSessionId] = useState(workflow.sessions[0]?.id ?? "");
  if (!assignment) return <Empty title={message(locale, "screen.workflowConsole.80c0e658a7e2")} />;
  const officeName = localizedName(assignment.office_snapshot?.names, locale, assignment.office_snapshot?.canonicalCode ?? assignment.office_id);
  const assignmentProcessPaused = (workflow.eligibilityPauses ?? []).some((pause) => pause.processId === assignment.process_id && !pause.resolvedAt);
  const availableAssignmentReasonCodes: readonly AssignmentLifecycleReasonCode[] = assignment.state === "VIGENTE"
    ? assignmentLifecycleReasonCodes
    : assignmentLifecycleReasonCodes.filter((reasonCode) => reasonCode === "ASSIGNMENT_REPLACED");
  const effectiveAssignmentReasonCode = availableAssignmentReasonCodes.includes(assignmentReasonCode)
    ? assignmentReasonCode
    : availableAssignmentReasonCodes[0] ?? "ASSIGNMENT_REPLACED";

  async function evidence(purpose: string, value: unknown) {
    if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.workflowConsole.7d7ade13f432"));
    return (await encryptJson(vault.key, vault.keyId, {
      tenantId: session.tenant.id, assignmentId: assignment!.id, purpose, schemaVersion: 1,
    }, value)).envelope;
  }
  const sessionReference = institutionalSessionId ? { sessionId: institutionalSessionId } : {};

  return <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
    <section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.52569b3a19c2")}</p><h2>{message(locale, "screen.workflowConsole.6655c27a6174")}</h2></div><Badge variant="outline">{workflow.assignments.length}</Badge></div><div className="space-y-2">{workflow.assignments.map((item) => <button type="button" key={item.id} onClick={() => setSelectedAssignmentId(item.id)} className={`w-full rounded-xl border p-3 text-left ${selectedAssignmentId === item.id ? "border-cyan-400 bg-cyan-50" : ""}`}><strong className="block">{localizedName(item.office_snapshot?.names, locale, item.office_snapshot?.canonicalCode ?? item.office_id)}</strong>{item.member_snapshot ? <EncryptedIdentity compact locale={locale} tenantId={session.tenant.id} memberId={item.member_id} displayEnvelope={item.member_snapshot.displayEnvelope ?? null} photo={item.member_snapshot.photo ?? null} vault={vault} /> : <small className="text-slate-500">{item.member_id.slice(0, 8)}…</small>}<small className="block text-slate-500">v{item.version}</small><Badge className="mt-2" variant="outline">{assignmentLabel(locale, item.state)}</Badge></button>)}</div></section>
    <div className="space-y-5"><section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{officeName}</p><h2>{assignmentLabel(locale, assignment.state)}</h2></div><Badge>v{assignment.version}</Badge></div>
      <div className="mb-4 rounded-2xl border bg-slate-50 p-4">{assignment.member_snapshot ? <EncryptedIdentity locale={locale} tenantId={session.tenant.id} memberId={assignment.member_id} displayEnvelope={assignment.member_snapshot.displayEnvelope ?? null} photo={assignment.member_snapshot.photo ?? null} vault={vault} /> : <Fact label={message(locale, "screen.workflowConsole.b792923baa6a")} value={assignment.member_id} />}</div>
      <div className="grid gap-3 sm:grid-cols-2"><Fact label={message(locale, "screen.workflowConsole.661e89ec62db")} value={assignment.vacancy_id} /><Fact label={message(locale, "screen.workflowConsole.98d0e410a190")} value={assignment.effective ? message(locale, "screen.workflowConsole.b057c888cae8") : message(locale, "screen.workflowConsole.9448170c072f")} /></div>
      <div className="mt-4"><Field label={message(locale, "screen.workflowConsole.ddb5e9fc68af")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={institutionalSessionId} onChange={(event) => setInstitutionalSessionId(event.target.value)}><option value="">{message(locale, "screen.workflowConsole.2ff3e2b17025")}</option>{workflow.sessions.filter(({ status }) => status !== "cancelled").map((item) => <option key={item.id} value={item.id}>{item.sequence}. {item.title}</option>)}</select></Field></div>
      {assignmentProcessPaused && <Alert className="mt-4"><ShieldCheck /><AlertTitle>{message(locale, "screen.workflowConsole.70eeabc6b4b6")}</AlertTitle><AlertDescription>{message(locale, "screen.workflowConsole.f8d5ebbf262e")}</AlertDescription></Alert>}
      <div className="mt-5 flex flex-wrap gap-2">
        {canRecordConsent && assignment.state === "PROPUESTA_INTERNA" && <>{!assignmentProcessPaused && <Action busy={busy} id="contact" onClick={() => act("contact", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "CONTACTED", envelope: await evidence("assignment-consent", { status: "CONTACTED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.763308058635")}</Action>}<Action busy={busy} id="withdraw" onClick={() => act("withdraw", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "WITHDRAWN", envelope: await evidence("assignment-consent", { status: "WITHDRAWN" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.0dbd33ce5936")}</Action></>}
        {canRecordConsent && assignment.state === "ACEPTACION_PENDIENTE" && <>{!assignmentProcessPaused && <Action busy={busy} id="accept" onClick={() => act("accept", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "ACCEPTED", envelope: await evidence("assignment-consent", { status: "ACCEPTED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.99c404b79b2d")}</Action>}<Action busy={busy} id="decline" onClick={() => act("decline", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "DECLINED", envelope: await evidence("assignment-consent", { status: "DECLINED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.fbd9a4bb54e8")}</Action><Action busy={busy} id="withdraw" onClick={() => act("withdraw", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "WITHDRAWN", envelope: await evidence("assignment-consent", { status: "WITHDRAWN" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.5a3e387650d6")}</Action></>}
        {canRecordConsent && assignment.state === "ACEPTADA" && <><Action busy={busy} id="decline-after-acceptance" onClick={() => act("decline-after-acceptance", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "DECLINED", envelope: await evidence("assignment-consent", { status: "DECLINED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.14496090ad2f")}</Action><Action busy={busy} id="withdraw-after-acceptance" onClick={() => act("withdraw-after-acceptance", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "WITHDRAWN", envelope: await evidence("assignment-consent", { status: "WITHDRAWN" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.5a3e387650d6")}</Action></>}
        {canRecordConsent && assignment.state === "PRESENTADA_A_IGLESIA" && <Action busy={busy} id="withdraw-after-presentation" onClick={() => act("withdraw-after-presentation", async () => workflowApi.recordConsent(assignment.id, { expectedVersion: assignment.version, status: "WITHDRAWN", envelope: await evidence("assignment-consent", { status: "WITHDRAWN" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.44ee4cc04eef")}</Action>}
        {canRecordCongregationalDecision && !assignmentProcessPaused && assignment.state === "ACEPTADA" && <Action busy={busy} id="present" onClick={() => act("present", async () => workflowApi.presentAssignment(assignment.id, { expectedVersion: assignment.version, envelope: await evidence("assignment-presentation", { presented: true }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.123905b80a46")}</Action>}
        {canRecordCongregationalDecision && assignment.state === "PRESENTADA_A_IGLESIA" && <>{!assignmentProcessPaused && <Action busy={busy} id="elect" onClick={() => act("elect", async () => workflowApi.congregationalDecision(assignment.id, { expectedVersion: assignment.version, outcome: "ELECTED", envelope: await evidence("congregational-decision", { outcome: "ELECTED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.08da0a6cbcf2")}</Action>}<Action busy={busy} id="not-elect" onClick={() => act("not-elect", async () => workflowApi.congregationalDecision(assignment.id, { expectedVersion: assignment.version, outcome: "NOT_ELECTED", envelope: await evidence("congregational-decision", { outcome: "NOT_ELECTED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.44d0552b77bd")}</Action>{!assignmentProcessPaused && <Action busy={busy} id="defer" onClick={() => act("defer", async () => workflowApi.congregationalDecision(assignment.id, { expectedVersion: assignment.version, outcome: "DEFERRED", envelope: await evidence("congregational-decision", { outcome: "DEFERRED" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.76e77be0a830")}</Action>}<Action busy={busy} id="return" onClick={() => act("return", async () => workflowApi.congregationalDecision(assignment.id, { expectedVersion: assignment.version, outcome: "RETURNED_TO_COMMITTEE", envelope: await evidence("congregational-decision", { outcome: "RETURNED_TO_COMMITTEE" }), ...sessionReference }))}>{message(locale, "screen.workflowConsole.f4245fe41919")}</Action></>}
        {canRecordCongregationalDecision && !assignmentProcessPaused && assignment.state === "ELEGIDA_POR_IGLESIA" && <Action busy={busy} id="activate-assignment" onClick={() => act("activate-assignment", () => workflowApi.activateAssignment(assignment.id, assignment.version, institutionalSessionId || undefined))}>{message(locale, "screen.workflowConsole.38d4761b9d03")}</Action>}
      </div>
      {canRecordCongregationalDecision && ["ELEGIDA_POR_IGLESIA", "VIGENTE"].includes(assignment.state) && <div className="mt-5 rounded-2xl border bg-slate-50 p-4">
        <Field label={message(locale, "screen.workflowConsole.797721d63d72")}><select className="h-10 w-full rounded-md border bg-white px-3 text-sm" value={effectiveAssignmentReasonCode} onChange={(event) => setAssignmentReasonCode(event.target.value as AssignmentLifecycleReasonCode)}>{availableAssignmentReasonCodes.map((reasonCode) => <option key={reasonCode} value={reasonCode}>{assignmentReasonCodeLabel(locale, reasonCode)}</option>)}</select></Field>
        <div className="mt-3 flex flex-wrap gap-2">
          {assignment.state === "VIGENTE" && !assignmentProcessPaused && <>
            <Button variant="outline" disabled={Boolean(busy) || effectiveAssignmentReasonCode !== "TERM_COMPLETED_NO_VACANCY"} onClick={() => void act("finalize", async () => workflowApi.finalizeAssignment(assignment.id, { expectedVersion: assignment.version, reasonCode: "TERM_COMPLETED_NO_VACANCY", openVacancy: false, evidenceEnvelope: await evidence("assignment-finalization", { reasonCode: "TERM_COMPLETED_NO_VACANCY", openVacancy: false }), ...sessionReference }))}><ArchiveRestore /> {message(locale, "screen.workflowConsole.771fe207dcd0")}</Button>
            <Button variant="outline" disabled={Boolean(busy) || effectiveAssignmentReasonCode !== "TERM_COMPLETED_OPEN_VACANCY"} onClick={() => void act("finalize-vacancy", async () => workflowApi.finalizeAssignment(assignment.id, { expectedVersion: assignment.version, reasonCode: "TERM_COMPLETED_OPEN_VACANCY", openVacancy: true, evidenceEnvelope: await evidence("assignment-finalization", { reasonCode: "TERM_COMPLETED_OPEN_VACANCY", openVacancy: true }), ...sessionReference }))}><ArchiveRestore /> {message(locale, "screen.workflowConsole.f26185aa111a")}</Button>
          </>}
          <Button disabled={Boolean(busy) || effectiveAssignmentReasonCode !== "ASSIGNMENT_REPLACED"} onClick={() => void act("substitute", async () => workflowApi.substituteAssignment(assignment.id, { expectedVersion: assignment.version, reasonCode: "ASSIGNMENT_REPLACED", evidenceEnvelope: await evidence("assignment-substitution", { reasonCode: "ASSIGNMENT_REPLACED" }), ...sessionReference }), message(locale, "screen.workflowConsole.207945411b17"))}><RefreshCw /> {message(locale, "screen.workflowConsole.69be6ababba7")}</Button>
        </div>
      </div>}
    </section>
    {canReadAssignmentHistory && <section className="surface-card"><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.workflowConsole.ff4d7a42c676")}</p><h2>{message(locale, "screen.workflowConsole.7538b2341bec")}</h2></div><History /></div>{historyQuery.isLoading ? <Loading label={message(locale, "screen.workflowConsole.177b93b5db23")} /> : <ol className="space-y-3">{historyQuery.data?.transitions.map((transition) => <li key={transition.id} className="grid grid-cols-[36px_1fr_auto] gap-3 rounded-xl border p-3"><span className="grid size-9 place-items-center rounded-full bg-slate-950 text-white"><Check size={15} /></span><div><strong className="block">{transitionActionLabel(locale, transition.action)}</strong><small className="text-slate-500">{transition.fromState ? assignmentLabel(locale, transition.fromState) : message(locale, "screen.workflowConsole.c91ca116b24c")} → {assignmentLabel(locale, transition.toState)} · {transition.reasonCode ?? message(locale, "screen.workflowConsole.89c371b2f138")}{transition.sessionId ? ` · ${message(locale, "screen.workflowConsole.4b38f60adc4d")} ${workflow.sessions.find(({ id }) => id === transition.sessionId)?.title ?? transition.sessionId}` : ""}</small></div><time className="text-xs text-slate-500">{formatInTenantTimeZone(transition.occurredAt, locale, workflow.cycle.timezone, { dateStyle: "short", timeStyle: "short" })}</time></li>)}</ol>}</section>}</div>
  </div>;
}

function ReviewActions({ locale, candidate, processId, tenantId, vault, busy, act }: {
  locale: Locale; candidate: ReviewBoard["candidates"][number]; processId: string; tenantId: string;
  vault: ReturnType<typeof useVault>; busy?: string;
  act: (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
}) {
  const options = candidacyReviewOptions(candidate.state, locale);
  const [toState, setToState] = useState<string>(options[0]?.state ?? "");
  const [rationale, setRationale] = useState("");
  const [restrictedNote, setRestrictedNote] = useState("");

  if (!options.length) return <small className="max-w-48 text-right text-slate-500">{message(locale, "screen.workflowConsole.405c52c953c2")}</small>;

  async function review() {
    if (!vault.key || !vault.keyId) throw new Error(message(locale, "screen.workflowConsole.96e9a5f4e08e"));
    const selected = options.find((option) => option.state === toState);
    if (!selected) throw new Error(message(locale, "screen.workflowConsole.e90dcca55ebb"));
    if (["WITHDRAWN", "EXCLUDED", "INELIGIBLE"].includes(toState) && rationale.trim().length < 3) {
      throw new Error(message(locale, "screen.workflowConsole.ebc69bd96771"));
    }
    const rationaleEnvelope = (await encryptJson(vault.key, vault.keyId, {
      tenantId, processId, candidacyId: candidate.id, purpose: "candidacy-rationale", schemaVersion: 1,
    }, {
      reasonCode: selected.reasonCode,
      rationale: rationale.trim() || selected.label,
    })).envelope;
    const restrictedNoteEnvelope = restrictedNote.trim()
      ? (await encryptJson(vault.key, vault.keyId, {
          tenantId, processId, candidacyId: candidate.id, purpose: "candidacy-restricted-note", schemaVersion: 1,
        }, { note: restrictedNote.trim() })).envelope
      : undefined;
    await workflowApi.reviewCandidacy(processId, candidate.id, {
      expectedVersion: candidate.version,
      toState,
      reasonCode: selected.reasonCode,
      rationaleEnvelope,
      ...(restrictedNoteEnvelope ? { restrictedNoteEnvelope } : {}),
    });
  }

  return <div className="grid min-w-56 gap-2">
    <select aria-label={message(locale, "screen.workflowConsole.71a461bc73b4")} className="h-9 rounded-md border bg-white px-2 text-xs" value={toState} onChange={(event) => {
      setToState(event.target.value);
    }}>{options.map((option) => <option key={option.state} value={option.state}>{option.label}</option>)}</select>
    <code className="flex h-9 items-center rounded-md border bg-slate-50 px-2 text-[11px]">{options.find((option) => option.state === toState)?.reasonCode ?? "—"}</code>
    <textarea aria-label={message(locale, "screen.workflowConsole.cb0c275a55a3")} className="min-h-16 rounded-md border bg-white px-3 py-2 text-xs" placeholder={message(locale, "screen.workflowConsole.cb0c275a55a3")} value={rationale} onChange={(event) => setRationale(event.target.value)} maxLength={2_000} />
    <textarea aria-label={message(locale, "screen.workflowConsole.6125079be680")} className="min-h-12 rounded-md border bg-white px-3 py-2 text-xs" placeholder={message(locale, "screen.workflowConsole.6d6224573cb8")} value={restrictedNote} onChange={(event) => setRestrictedNote(event.target.value)} maxLength={2_000} />
    <Button size="sm" variant="outline" disabled={Boolean(busy) || !vault.key} onClick={() => void act(`review-${candidate.id}`, review, message(locale, "screen.workflowConsole.3f7b6c93958e"))}>{busy === `review-${candidate.id}` ? <LoaderCircle className="animate-spin" /> : <ClipboardCheck />} {message(locale, "screen.workflowConsole.571bf4ba0e8a")}</Button>
  </div>;
}

function EncryptedIdentity({ locale, tenantId, memberId, displayEnvelope, photo, vault, compact = false }: {
  locale: Locale; tenantId: string; memberId: string; displayEnvelope: Envelope | null;
  photo?: StoredPhotoRecord | null; vault: ReturnType<typeof useVault>; compact?: boolean;
}) {
  const [identity, setIdentity] = useState<{ memberId: string; envelopeCiphertext: string; name: string; photoUrl?: string }>();
  const [unavailableEnvelope, setUnavailableEnvelope] = useState<{ memberId: string; envelopeCiphertext: string }>();

  useEffect(() => {
    let cancelled = false;
    let createdUrl: string | undefined;
    if (!vault.key) return;
    if (!displayEnvelope) return;
    void (async () => {
      const profile = await openJsonEnvelope<{ displayName?: string; firstName?: string; lastName?: string }>({
        resolver: vault,
        tenantId,
        envelope: displayEnvelope,
        aad: { tenantId, memberId, purpose: "member-display", schemaVersion: 1 },
      });
      const visibleName = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
      if (!visibleName) throw new Error(message(locale, "screen.workflowConsole.5e870c9c73b0"));
      if (photo) {
        try {
          const blob = await decryptPhoto({
            key: keyForEnvelope(vault, tenantId, photo.envelope),
            keyId: photo.envelope.keyId,
            tenantId,
            memberId,
            photo,
          });
          createdUrl = URL.createObjectURL(blob);
        } catch {
          createdUrl = undefined;
        }
      }
      if (!cancelled) setIdentity({ memberId, envelopeCiphertext: displayEnvelope.ciphertext, name: visibleName, ...(createdUrl ? { photoUrl: createdUrl } : {}) });
    })().catch(() => { if (!cancelled) setUnavailableEnvelope({ memberId, envelopeCiphertext: displayEnvelope.ciphertext }); });
    return () => { cancelled = true; if (createdUrl) URL.revokeObjectURL(createdUrl); };
  }, [displayEnvelope, locale, memberId, photo, tenantId, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  const current = vault.key && displayEnvelope && identity?.memberId === memberId && identity.envelopeCiphertext === displayEnvelope.ciphertext ? identity : undefined;
  const name = current?.name ?? "";
  const photoUrl = current?.photoUrl;
  const unavailable = Boolean(vault.key && (!displayEnvelope
    || (unavailableEnvelope?.memberId === memberId && unavailableEnvelope.envelopeCiphertext === displayEnvelope.ciphertext)));
  const fallback = name ? name.split(/\s+/u).slice(0, 2).map((part) => part[0]).join("").toUpperCase() : "••";
  return <span className={`flex items-center gap-2 ${compact ? "mt-1" : ""}`}>
    <span className={`${compact ? "size-7 text-[10px]" : "size-11 text-xs"} grid shrink-0 place-items-center overflow-hidden rounded-full bg-gradient-to-br from-cyan-500 to-blue-700 font-bold text-white`}>
      {photoUrl ? <>
        {/* This authenticated blob URL is memory-only and revoked on change/unmount. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img className="size-full object-cover" src={photoUrl} alt="" />
      </> : fallback}
    </span>
    <span className="min-w-0"><strong className={`${compact ? "text-xs" : "text-sm"} block truncate`}>{name || (vault.key ? unavailable ? message(locale, "screen.workflowConsole.d5de935642ed") : message(locale, "screen.workflowConsole.4f7e59550317") : message(locale, "screen.workflowConsole.b10c6b732145"))}</strong><small className="block truncate text-[10px] text-slate-500">{memberId}</small></span>
  </span>;
}

function candidacyReviewOptions(state: string, locale: Locale) {
  const all = {
    UNDER_REVIEW: { state: "UNDER_REVIEW", label: message(locale, "screen.workflowConsole.022d720ba823"), reasonCode: "REVIEW_STARTED" },
    PRELIMINARY_ACCEPTED: { state: "PRELIMINARY_ACCEPTED", label: message(locale, "screen.workflowConsole.1e0bd5818943"), reasonCode: "REVIEW_ACCEPTED" },
    WITHDRAWN: { state: "WITHDRAWN", label: message(locale, "screen.workflowConsole.5a3e387650d6"), reasonCode: "CANDIDATE_WITHDREW" },
    EXCLUDED: { state: "EXCLUDED", label: message(locale, "screen.workflowConsole.49fee9f678b4"), reasonCode: "COMMITTEE_EXCLUDED" },
    INELIGIBLE: { state: "INELIGIBLE", label: message(locale, "screen.workflowConsole.97d5b601a924"), reasonCode: "ELIGIBILITY_FAILED" },
  } as const;
  if (state === "PROPOSED") return [all.UNDER_REVIEW, all.WITHDRAWN, all.INELIGIBLE];
  if (state === "UNDER_REVIEW") return [all.PRELIMINARY_ACCEPTED, all.WITHDRAWN, all.EXCLUDED, all.INELIGIBLE];
  if (state === "PRELIMINARY_ACCEPTED") return [all.WITHDRAWN, all.INELIGIBLE];
  return [];
}

function transitionActionLabel(locale: Locale, action: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    PROVISIONAL_CREATED: "screen.workflowConsole.301477330156",
    CONSENT_RECORDED: "screen.workflowConsole.9828adfa0868",
    PRESENTED_TO_CHURCH: "screen.workflowConsole.b3b1ffeffc18",
    CONGREGATIONAL_DECISION_RECORDED: "screen.workflowConsole.866aaa1f388b",
    TERM_ACTIVATED: "screen.workflowConsole.82b769da5700",
    ASSIGNMENT_FINALIZED: "screen.workflowConsole.5db46654d7bc",
    ASSIGNMENT_SUBSTITUTED: "screen.workflowConsole.550ad8342ed0",
    VACANCY_OPENED: "screen.workflowConsole.b1b6a69e9cd4",
  };
  const value = labels[action];
  return value ? message(locale, value) : action.replaceAll("_", " ");
}

function PhaseRail({ locale, phase }: { locale: Locale; phase: string }) {
  const index = Math.max(0, phaseOrder.indexOf(phase));
  return <div className="flex min-w-0 items-center gap-1 overflow-x-auto py-2" aria-label={`${message(locale, "screen.workflowConsole.955ea3baa08d")}: ${phaseLabel(locale, phase)}`}>{phaseOrder.map((item, itemIndex) => <div key={item} className="flex min-w-20 items-center gap-1" title={phaseLabel(locale, item)}><span className={`grid size-6 shrink-0 place-items-center rounded-full text-[10px] font-bold ${itemIndex <= index ? "bg-cyan-600 text-white" : "bg-slate-100 text-slate-400"}`}>{itemIndex < index ? <Check size={12} /> : itemIndex + 1}</span>{itemIndex < phaseOrder.length - 1 && <span className={`h-px w-full ${itemIndex < index ? "bg-cyan-500" : "bg-slate-200"}`} />}</div>)}</div>;
}

function StageCard({ locale, icon: Icon, title, phase, children }: { locale: Locale; icon: typeof Users; title: string; phase: string; children: ReactNode }) {
  return <article className="surface-card !p-5"><div className="flex items-start gap-3"><span className="metric-icon cyan"><Icon /></span><div className="min-w-0 flex-1"><strong className="block">{title}</strong><Badge className="mt-1" variant="outline">{phaseLabel(locale, phase)}</Badge></div></div><div className="mt-4 space-y-3">{children}</div></article>;
}

function Action({ busy, id, onClick, children }: { busy?: string; id: string; onClick: () => Promise<unknown>; children: ReactNode }) {
  return <Button className="w-full" disabled={Boolean(busy)} onClick={() => void onClick()}>{busy === id ? <LoaderCircle className="animate-spin" /> : <ArrowRight />}{children}</Button>;
}

function Fact({ label, value }: { label: string; value: string }) { return <div className="rounded-xl border bg-slate-50 p-3"><small className="block text-slate-500">{label}</small><strong className="break-all text-sm">{value}</strong></div>; }
function Field({ label, children }: { label: string; children: ReactNode }) { return <label className="grid gap-1.5"><Label>{label}</Label>{children}</label>; }
function NumberField({ label, value, set }: { label: string; value: number; set: (value: number) => void }) { return <Field label={label}><Input type="number" min={1} value={value} onChange={(event) => set(Number(event.target.value))} /></Field>; }
function Loading({ label }: { label: string }) { return <div className="grid min-h-40 place-items-center rounded-2xl border bg-white" role="status"><span className="text-center"><LoaderCircle className="mx-auto animate-spin text-cyan-600" /><small className="mt-2 block text-slate-500">{label}</small></span></div>; }
function Empty({ title }: { title: string }) { return <div className="grid min-h-40 place-items-center rounded-2xl border border-dashed bg-slate-50 p-6 text-center"><span><UserCheck className="mx-auto text-slate-400" /><strong className="mt-2 block">{title}</strong></span></div>; }
function PermissionNotice({ locale, compact = false }: { locale: Locale; compact?: boolean }) {
  return <div className={`${compact ? "rounded-xl p-4" : "rounded-2xl p-6"} border border-amber-200 bg-amber-50 text-sm text-amber-900`} role="status">
    <strong className="block">{message(locale, "screen.workflowConsole.7bfd3b4ec0c1")}</strong>
    <span>{message(locale, "screen.workflowConsole.d4cbb4875397")}</span>
  </div>;
}

function latestRound(rounds: WorkflowRound[], processId: string, kind: "proposal" | "vote") { return [...rounds].reverse().find((round) => round.process_id === processId && round.submission_kind === kind); }
function readinessPercent(workflow: VisibleCycleWorkflow) { return [workflow.sessions.length > 0, workflow.processes.some((process) => process.enabled && process.procedure_sequence === 1), workflow.committee.filter((member) => member.voting_right && member.status === "active").length >= 2, workflow.electorate.some((item) => item.can_propose && !item.recused), workflow.electorate.some((item) => item.can_vote && !item.recused)].filter(Boolean).length * 20; }
function updateAt<T>(items: T[], index: number, value: T, set: (items: T[]) => void) { const next = [...items]; next[index] = value; set(next); }
