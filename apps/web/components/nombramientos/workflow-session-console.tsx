"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown, ArrowUp, CheckCircle2, ClipboardList, FileLock2, LoaderCircle,
  Play, Plus, Square, UserRoundCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import type { Envelope, Locale } from "@/lib/api";
import { decryptJson, encryptJson } from "@/lib/crypto-client";
import { message, localizedApiError } from "@/lib/product-i18n";
import { isLegacyTitleUnavailable, openAgendaTitle, openSessionTitle, sealAgendaTitle, sealSessionTitle } from "@/lib/session-title-crypto";
import { isoToLocalDateTimeInZone, localDateTimeInZoneToIso } from "@/lib/workflow-time";
import {
  workflowApi,
  type CommitteeCandidate,
  type CycleWorkflow,
  type WorkflowSessionAgendaItem,
  type WorkflowSessionAttendance,
  type WorkflowSessionRecord,
  type WorkflowSessionStatus,
} from "@/lib/workflow-api";

type Act = (label: string, action: () => Promise<unknown>, success?: string) => Promise<void>;
type MemberOption = { id: string; shortId: string };
type SessionDecisionOutcome = "APPROVED" | "REJECTED" | "DEFERRED" | "RECORDED";
type SessionDecisionCode = "RESOLUTION" | "AGREEMENT" | "INFORMATION_NOTED" | "ITEM_DEFERRED" | "ITEM_REJECTED";
type WorkflowSessionFallback = CycleWorkflow["sessions"][number] & { title: string };
type VisibleSession = WorkflowSessionRecord & { title: string };
type VisibleAgendaItem = WorkflowSessionAgendaItem & { title: string };

const decisionCodesByOutcome = {
  APPROVED: ["RESOLUTION", "AGREEMENT"],
  REJECTED: ["ITEM_REJECTED"],
  DEFERRED: ["ITEM_DEFERRED"],
  RECORDED: ["INFORMATION_NOTED"],
} as const satisfies Record<SessionDecisionOutcome, readonly SessionDecisionCode[]>;

function statusLabel(locale: Locale, status: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    scheduled: "screen.workflowSessionConsole.39fdf5253e51",
    in_progress: "screen.workflowSessionConsole.4fa7e5d0a2fc",
    closed: "screen.workflowSessionConsole.823c27263108",
    cancelled: "screen.workflowSessionConsole.b2f7998dca15",
    pending: "screen.workflowSessionConsole.1e4142a7f2f5",
    decided: "screen.workflowSessionConsole.f18af41f2070",
    deferred: "screen.workflowSessionConsole.d8aef48b2531",
  };
  const value = labels[status];
  return value ? message(locale, value) : status.replaceAll("_", " ");
}

function presenceLabel(locale: Locale, value: WorkflowSessionAttendance["presenceStatus"]): string {
  const labels: Record<WorkflowSessionAttendance["presenceStatus"], Parameters<typeof message>[1]> = {
    PRESENT: "screen.workflowSessionConsole.5bf711c932ce",
    REMOTE: "screen.workflowSessionConsole.38ce7f0786b9",
    ABSENT: "screen.workflowSessionConsole.ae36561bf709",
    EXCUSED: "screen.workflowSessionConsole.23c08636e7dd",
  };
  return message(locale, labels[value]);
}

function outcomeLabel(locale: Locale, value: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    APPROVED: "screen.workflowSessionConsole.b7418b55d2ca",
    REJECTED: "screen.workflowSessionConsole.1879102901e0",
    DEFERRED: "screen.workflowSessionConsole.476a17d3240a",
    RECORDED: "screen.workflowSessionConsole.6e54e6846eae",
  };
  const label = labels[value];
  return label ? message(locale, label) : value.replaceAll("_", " ");
}

function decisionCodeLabel(locale: Locale, value: SessionDecisionCode): string {
  const labels: Record<SessionDecisionCode, Parameters<typeof message>[1]> = {
    RESOLUTION: "screen.workflowSessionConsole.f58541a81881",
    AGREEMENT: "screen.workflowSessionConsole.a7e145fe78ef",
    INFORMATION_NOTED: "screen.workflowSessionConsole.ed5e0edbb94c",
    ITEM_DEFERRED: "screen.workflowSessionConsole.f9fb7068eba3",
    ITEM_REJECTED: "screen.workflowSessionConsole.0f68927a005a",
  };
  return message(locale, labels[value]);
}

function workflowSessionFallback(session: WorkflowSessionFallback): WorkflowSessionRecord {
  return {
    id: session.id,
    cycleId: "",
    sequence: session.sequence,
    titleEnvelope: session.title_envelope,
    titleVersion: session.title_envelope_version,
    legacyTitleUnavailable: session.legacy_title_unavailable,
    startsAt: session.starts_at,
    endsAt: session.ends_at,
    status: session.status as WorkflowSessionStatus,
    locationEnvelope: null,
    version: session.version,
    actualStartedAt: null,
    actualClosedAt: null,
    createdAt: session.starts_at,
    updatedAt: session.starts_at,
  };
}

export function WorkflowSessionConsole({
  cycleId, locale, tenantId, timeZone, workflowSessions, processes, committee, committeeCandidates,
  members, canManageSessions, canManageAttendanceDirectory, vaultKey, vaultKeyId,
  vaultKeyFor, vaultKeyringRevision, busy, act,
}: {
  cycleId: string;
  locale: Locale;
  tenantId: string;
  timeZone: string;
  workflowSessions: WorkflowSessionFallback[];
  processes: CycleWorkflow["processes"];
  committee: CycleWorkflow["committee"];
  committeeCandidates: CommitteeCandidate[];
  members: MemberOption[];
  canManageSessions: boolean;
  canManageAttendanceDirectory: boolean;
  vaultKey?: CryptoKey;
  vaultKeyId?: string;
  vaultKeyFor: (keyId: string, tenantId: string) => CryptoKey | undefined;
  vaultKeyringRevision: number;
  busy?: string;
  act: Act;
}) {
  const queryClient = useQueryClient();
  const [selectedSessionId, setSelectedSessionId] = useState("");
  const [sessionEdits, setSessionEdits] = useState<Record<string, { title: string; startsAt: string; endsAt: string }>>({});
  const [attendanceForm, setAttendanceForm] = useState({
    identityId: "", memberId: "", presenceStatus: "PRESENT" as WorkflowSessionAttendance["presenceStatus"],
    advisory: false, votingRight: true, substituteForIdentityId: "",
  });
  const [agendaForm, setAgendaForm] = useState({ title: "", processId: "", notes: "" });
  const [decisionForm, setDecisionForm] = useState<{
    agendaItemId: string; decisionCode: SessionDecisionCode; outcome: SessionDecisionOutcome; evidence: string;
  }>({ agendaItemId: "", decisionCode: "INFORMATION_NOTED", outcome: "RECORDED", evidence: "" });
  const [sessionTitles, setSessionTitles] = useState<Map<string, string>>(new Map());
  const [agendaTitles, setAgendaTitles] = useState<Map<string, string>>(new Map());
  const [titleError, setTitleError] = useState<string>();

  const sessionsQuery = useQuery({
    queryKey: ["workflow-sessions", tenantId, cycleId],
    queryFn: () => workflowApi.sessions(cycleId),
    enabled: canManageSessions && Boolean(cycleId),
  });
  const encryptedSessions = useMemo(
    () => sessionsQuery.data?.items ?? workflowSessions.map(workflowSessionFallback),
    [sessionsQuery.data?.items, workflowSessions],
  );
  const resolvedSessionId = encryptedSessions.some(({ id }) => id === selectedSessionId) ? selectedSessionId : encryptedSessions[0]?.id ?? "";
  const detailQuery = useQuery({
    queryKey: ["workflow-session", tenantId, resolvedSessionId],
    queryFn: () => workflowApi.session(resolvedSessionId),
    enabled: canManageSessions && Boolean(resolvedSessionId),
  });
  const encryptedSession = detailQuery.data ?? encryptedSessions.find(({ id }) => id === resolvedSessionId);
  const sessionTitleReferences = useMemo(
    () => encryptedSession
      ? [...encryptedSessions.filter(({ id }) => id !== encryptedSession.id), encryptedSession]
      : encryptedSessions,
    [encryptedSession, encryptedSessions],
  );
  const attendance = detailQuery.data?.attendance ?? [];
  const encryptedAgenda = useMemo(
    () => [...(detailQuery.data?.agendaItems ?? [])].sort((left, right) => left.position - right.position),
    [detailQuery.data?.agendaItems],
  );
  useEffect(() => {
    let cancelled = false;
    async function reveal(): Promise<void> {
      setTitleError(undefined);
      const requiresKey = sessionTitleReferences.some(({ titleEnvelope }) => Boolean(titleEnvelope))
        || encryptedAgenda.some(({ titleEnvelope }) => Boolean(titleEnvelope));
      if (requiresKey && (!vaultKey || !vaultKeyId)) {
        setSessionTitles(new Map());
        setAgendaTitles(new Map());
        setTitleError(message(locale, "screen.workflowSessionConsole.a7e7eaaa313b"));
        return;
      }
      try {
        const visibleSessions = new Map<string, string>();
        const visibleAgenda = new Map<string, string>();
        let hadFailures = false;
        for (const item of sessionTitleReferences) {
          if (isLegacyTitleUnavailable(item)) {
            visibleSessions.set(item.id, message(locale, "screen.workflowSessionConsole.30394ed2ba2b"));
            continue;
          }
          try {
            if (!item.titleEnvelope) throw new Error("Encrypted session title reference is incomplete");
            const itemKey = vaultKeyFor(item.titleEnvelope.keyId, tenantId);
            if (!itemKey) throw new Error("Historical session title key is unavailable");
            visibleSessions.set(item.id, await openSessionTitle(itemKey, item.titleEnvelope.keyId, {
              tenantId,
              cycleId,
              sessionId: item.id,
              titleVersion: item.titleVersion,
            }, item.titleEnvelope));
          } catch {
            hadFailures = true;
            visibleSessions.set(item.id, message(locale, "screen.workflowSessionConsole.6544fdadbe29"));
          }
        }
        for (const item of encryptedAgenda) {
          if (isLegacyTitleUnavailable(item)) {
            visibleAgenda.set(item.id, message(locale, "screen.workflowSessionConsole.30394ed2ba2b"));
            continue;
          }
          try {
            if (!item.titleEnvelope) throw new Error("Encrypted agenda title reference is incomplete");
            const itemKey = vaultKeyFor(item.titleEnvelope.keyId, tenantId);
            if (!itemKey) throw new Error("Historical agenda title key is unavailable");
            visibleAgenda.set(item.id, await openAgendaTitle(itemKey, item.titleEnvelope.keyId, {
              tenantId,
              sessionId: resolvedSessionId,
              agendaItemId: item.id,
              titleVersion: item.titleVersion,
            }, item.titleEnvelope));
          } catch {
            hadFailures = true;
            visibleAgenda.set(item.id, message(locale, "screen.workflowSessionConsole.6544fdadbe29"));
          }
        }
        if (!cancelled) {
          setSessionTitles(visibleSessions);
          setAgendaTitles(visibleAgenda);
          setTitleError(hadFailures ? message(locale, "screen.workflowSessionConsole.d09aba68a7d9") : undefined);
        }
      } catch {
        if (!cancelled) {
          setSessionTitles(new Map());
          setAgendaTitles(new Map());
          setTitleError(message(locale, "screen.workflowSessionConsole.d09aba68a7d9"));
        }
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [cycleId, encryptedAgenda, locale, resolvedSessionId, sessionTitleReferences, tenantId, vaultKey, vaultKeyFor, vaultKeyId, vaultKeyringRevision]);
  const sessions = useMemo<VisibleSession[]>(() => encryptedSessions.map((item) => ({
    ...item,
    title: sessionTitles.get(item.id) ?? message(locale, "screen.workflowSessionConsole.6544fdadbe29"),
  })), [encryptedSessions, locale, sessionTitles]);
  const session = encryptedSession ? {
    ...encryptedSession,
    title: sessionTitles.get(encryptedSession.id) ?? message(locale, "screen.workflowSessionConsole.6544fdadbe29"),
  } satisfies VisibleSession : undefined;
  const agenda = useMemo<VisibleAgendaItem[]>(() => encryptedAgenda.map((item) => ({
    ...item,
    title: agendaTitles.get(item.id) ?? message(locale, "screen.workflowSessionConsole.6544fdadbe29"),
  })), [agendaTitles, encryptedAgenda, locale]);
  const decisions = agenda.flatMap((item) => item.decision ? [{ ...item.decision, agendaItemId: item.id }] : []);
  const editable = Boolean(session && !["closed", "cancelled"].includes(session.status));
  const unresolvedAgenda = agenda.some((item) => !["decided", "deferred"].includes(item.status));
  const sessionEdit = session ? sessionEdits[session.id] ?? {
    title: session.legacyTitleUnavailable ? "" : session.title,
    startsAt: isoToLocalDateTimeInZone(session.startsAt, timeZone),
    endsAt: isoToLocalDateTimeInZone(session.endsAt, timeZone),
  } : undefined;

  if (!canManageSessions) return <p className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900" role="status">{message(locale, "screen.workflowSessionConsole.1f8868f96fa6")}</p>;

  const identityName = (identityId: string) => canManageAttendanceDirectory
    ? committeeCandidates.find((item) => item.identityId === identityId)?.displayName ?? message(locale, "screen.workflowSessionConsole.223522243f09")
    : message(locale, "screen.workflowSessionConsole.223522243f09");

  async function refreshSessionData() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["workflow-sessions", tenantId, cycleId] }),
      queryClient.invalidateQueries({ queryKey: ["workflow-session", tenantId, resolvedSessionId] }),
    ]);
  }

  async function run(label: string, operation: () => Promise<unknown>, success: string) {
    await act(label, async () => {
      await operation();
      await refreshSessionData();
    }, success);
  }

  async function saveAttendance() {
    if (!session || !attendanceForm.identityId) return;
    const existing = attendance.find(({ identityId }) => identityId === attendanceForm.identityId);
    await run("session-attendance", () => workflowApi.upsertSessionAttendance(session.id, attendanceForm.identityId, {
      expectedVersion: existing?.version ?? 0,
      memberId: attendanceForm.memberId || null,
      presenceStatus: attendanceForm.presenceStatus,
      advisory: attendanceForm.advisory,
      votingRight: attendanceForm.votingRight,
      substituteForIdentityId: attendanceForm.substituteForIdentityId || null,
    }), message(locale, "screen.workflowSessionConsole.f1ea96995b81"));
  }

  async function saveSession() {
    if (!session || !sessionEdit) return;
    if (!vaultKey || !vaultKeyId) throw new Error(message(locale, "screen.workflowSessionConsole.4ec5124ba274"));
    await run("session-update", async () => {
      const sealedTitle = await sealSessionTitle(vaultKey, vaultKeyId, {
        tenantId,
        cycleId,
        sessionId: session.id,
        titleVersion: session.titleVersion + 1,
      }, sessionEdit.title);
      await workflowApi.updateSession(session.id, {
        expectedVersion: session.version,
        titleEnvelope: sealedTitle.envelope,
        titleContentHash: sealedTitle.contentHash,
        startsAt: localDateTimeInZoneToIso(sessionEdit.startsAt, timeZone),
        endsAt: localDateTimeInZoneToIso(sessionEdit.endsAt, timeZone),
      });
      setSessionEdits((current) => {
        const next = { ...current };
        delete next[session.id];
        return next;
      });
    }, message(locale, "screen.workflowSessionConsole.8434e7e2156a"));
  }

  async function addAgendaItem() {
    if (!session || !agendaForm.title.trim()) return;
    if (!vaultKey || !vaultKeyId) throw new Error(message(locale, "screen.workflowSessionConsole.681689ded839"));
    const itemId = crypto.randomUUID();
    const sealedTitle = await sealAgendaTitle(vaultKey, vaultKeyId, {
      tenantId,
      sessionId: session.id,
      agendaItemId: itemId,
      titleVersion: 1,
    }, agendaForm.title);
    let notesEnvelope: Envelope | undefined;
    if (agendaForm.notes.trim()) {
      notesEnvelope = (await encryptJson(vaultKey, vaultKeyId, {
        tenantId, sessionId: session.id, purpose: "session-agenda-notes", schemaVersion: 1,
      }, { text: agendaForm.notes.trim() })).envelope;
    }
    await run("session-agenda", async () => {
      await workflowApi.addSessionAgendaItem(session.id, {
        expectedSessionVersion: session.version,
        itemId,
        position: agenda.length + 1,
        titleEnvelope: sealedTitle.envelope,
        titleContentHash: sealedTitle.contentHash,
        processId: agendaForm.processId || null,
        ...(notesEnvelope ? { notesEnvelope } : {}),
      });
      setAgendaForm({ title: "", processId: "", notes: "" });
    }, message(locale, "screen.workflowSessionConsole.33c9eef0c2b7"));
  }

  async function moveAgenda(item: WorkflowSessionAgendaItem, direction: -1 | 1) {
    if (!session) return;
    const currentIndex = agenda.findIndex(({ id }) => id === item.id);
    const targetIndex = currentIndex + direction;
    if (currentIndex < 0 || targetIndex < 0 || targetIndex >= agenda.length) return;
    const itemIds = agenda.map(({ id }) => id);
    [itemIds[currentIndex], itemIds[targetIndex]] = [itemIds[targetIndex]!, itemIds[currentIndex]!];
    await run("session-agenda-order", () => workflowApi.reorderSessionAgenda(session.id, {
      expectedSessionVersion: session.version,
      itemIds,
    }), message(locale, "screen.workflowSessionConsole.e2f9ee036cf4"));
  }

  async function recordDecision() {
    if (!session || !decisionForm.agendaItemId) return;
    let evidenceEnvelope: Envelope | undefined;
    if (decisionForm.evidence.trim()) {
      if (!vaultKey || !vaultKeyId) return;
      evidenceEnvelope = (await encryptJson(vaultKey, vaultKeyId, {
        tenantId, sessionId: session.id, agendaItemId: decisionForm.agendaItemId,
        purpose: "session-decision-evidence", schemaVersion: 1,
      }, { text: decisionForm.evidence.trim() })).envelope;
    }
    await run("session-decision", async () => {
      await workflowApi.recordSessionDecision(session.id, {
        expectedSessionVersion: session.version,
        agendaItemId: decisionForm.agendaItemId,
        decisionCode: decisionForm.decisionCode,
        outcome: decisionForm.outcome,
        ...(evidenceEnvelope ? { evidenceEnvelope } : {}),
      });
      setDecisionForm({ agendaItemId: "", decisionCode: "INFORMATION_NOTED", outcome: "RECORDED", evidence: "" });
    }, message(locale, "screen.workflowSessionConsole.8dd0decb429f"));
  }

  return <section className="surface-card xl:col-span-2">
    <div className="card-heading">
      <div><p className="eyebrow">{message(locale, "screen.workflowSessionConsole.2a745063c91d")}</p><h2>{message(locale, "screen.workflowSessionConsole.c4ef91f345f0")}</h2></div>
      <Badge variant="outline"><ClipboardList /> {agenda.length}</Badge>
    </div>
    {titleError && <p className="mb-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800" role="alert">{titleError}</p>}

    {!sessions.length ? <p className="rounded-xl border border-dashed p-4 text-sm text-slate-500">{message(locale, "screen.workflowSessionConsole.c6a1260d7b5d")}</p> : <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-[1fr_auto]">
        <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.ec1e813ae77d")}
          <select className="h-10 rounded-md border bg-white px-3 text-sm" value={resolvedSessionId} onChange={(event) => setSelectedSessionId(event.target.value)}>
            {sessions.map((item) => <option key={item.id} value={item.id}>{item.sequence}. {item.title} · {statusLabel(locale, item.status)}</option>)}
          </select>
        </label>
        <div className="flex items-end gap-2">
          {session?.status === "scheduled" && <Button disabled={Boolean(busy) || Boolean(titleError)} onClick={() => void run("session-start", () => workflowApi.startSession(session.id, session.version), message(locale, "screen.workflowSessionConsole.434c65d93d2b"))}>{busy === "session-start" ? <LoaderCircle className="animate-spin" /> : <Play />} {message(locale, "screen.workflowSessionConsole.33a3fce07a16")}</Button>}
          {session?.status === "in_progress" && <Button variant="outline" disabled={Boolean(busy) || Boolean(titleError) || unresolvedAgenda} title={unresolvedAgenda ? message(locale, "screen.workflowSessionConsole.4a2c7a1b1e93") : undefined} onClick={() => void run("session-close", () => workflowApi.closeSession(session.id, session.version), message(locale, "screen.workflowSessionConsole.31521dafe7d7"))}>{busy === "session-close" ? <LoaderCircle className="animate-spin" /> : <Square />} {message(locale, "screen.workflowSessionConsole.a5eb9e5b93ff")}</Button>}
          {session && <Badge variant={session.status === "in_progress" ? "default" : "outline"}>{statusLabel(locale, session.status)} · v{session.version}</Badge>}
        </div>
      </div>
      <p className="-mt-3 text-xs text-slate-500">{message(locale, "screen.workflowSessionConsole.66e9eceaf4b1")} <strong>{timeZone}</strong>.</p>

      {session?.status === "scheduled" && sessionEdit && <div className="grid gap-3 rounded-2xl border bg-slate-50 p-4 md:grid-cols-[1fr_220px_220px_auto]">
        <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.1442e2df0b2b")}<Input value={sessionEdit.title} minLength={1} maxLength={160} onChange={(event) => setSessionEdits({ ...sessionEdits, [session.id]: { ...sessionEdit, title: event.target.value } })} /></label>
        <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.2f28b15ff8f4")}<Input type="datetime-local" value={sessionEdit.startsAt} onChange={(event) => setSessionEdits({ ...sessionEdits, [session.id]: { ...sessionEdit, startsAt: event.target.value } })} /></label>
        <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.43d5d2e7ffb9")}<Input type="datetime-local" value={sessionEdit.endsAt} onChange={(event) => setSessionEdits({ ...sessionEdits, [session.id]: { ...sessionEdit, endsAt: event.target.value } })} /></label>
        <Button className="self-end" variant="outline" disabled={Boolean(busy) || Boolean(titleError) || !vaultKey || !vaultKeyId || !sessionEdit.title.trim() || !sessionEdit.startsAt || !sessionEdit.endsAt || sessionEdit.endsAt <= sessionEdit.startsAt} onClick={() => void saveSession()}>{busy === "session-update" ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />}{message(locale, "screen.workflowSessionConsole.32a1cfc446cb")}</Button>
      </div>}

      {detailQuery.isLoading ? <div className="flex items-center gap-2 rounded-xl border p-4 text-sm text-slate-500"><LoaderCircle className="animate-spin" />{message(locale, "screen.workflowSessionConsole.e61f254e654f")}</div> : detailQuery.isError ? <p className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">{localizedApiError(detailQuery.error, locale)}</p> : <>
        <div className="grid gap-5 xl:grid-cols-2">
          <div className="rounded-2xl border p-4">
            <div className="mb-3 flex items-center justify-between"><h3 className="font-semibold">{message(locale, "screen.workflowSessionConsole.8acc743803c0")}</h3><Badge variant="outline"><UserRoundCheck /> {attendance.length}</Badge></div>
            {canManageAttendanceDirectory ? <>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-1 text-sm font-medium sm:col-span-2">{message(locale, "screen.workflowSessionConsole.48ba824c0a06")}
                <select className="h-10 rounded-md border bg-white px-3 text-sm" value={attendanceForm.identityId} onChange={(event) => {
                  const identityId = event.target.value;
                  const linked = committee.find((item) => item.identity_id === identityId);
                  const existing = attendance.find((item) => item.identityId === identityId);
                  setAttendanceForm({
                    identityId,
                    memberId: existing?.memberId ?? linked?.member_id ?? "",
                    presenceStatus: existing?.presenceStatus ?? "PRESENT",
                    advisory: existing?.advisory ?? linked?.role_code === "advisor",
                    votingRight: existing?.votingRight ?? linked?.voting_right ?? false,
                    substituteForIdentityId: existing?.substituteForIdentityId ?? "",
                  });
                }}><option value="">{message(locale, "screen.workflowSessionConsole.30360a3bdaf2")}</option>{committeeCandidates.map((candidate) => <option key={candidate.identityId} value={candidate.identityId}>{candidate.displayName} · {candidate.email}</option>)}</select>
              </label>
              <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.284ddaec5003")}
                <select className="h-10 rounded-md border bg-white px-3 text-sm" value={attendanceForm.memberId} onChange={(event) => setAttendanceForm({ ...attendanceForm, memberId: event.target.value })}><option value="">{message(locale, "screen.workflowSessionConsole.76be0d848eef")}</option>{members.map((member) => <option key={member.id} value={member.id}>{member.shortId}</option>)}</select>
              </label>
              <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.c2b14de7741b")}
                <select className="h-10 rounded-md border bg-white px-3 text-sm" value={attendanceForm.presenceStatus} onChange={(event) => {
                  const presenceStatus = event.target.value as WorkflowSessionAttendance["presenceStatus"];
                  setAttendanceForm({ ...attendanceForm, presenceStatus, votingRight: ["ABSENT", "EXCUSED"].includes(presenceStatus) ? false : attendanceForm.votingRight });
                }}>{(["PRESENT", "REMOTE", "ABSENT", "EXCUSED"] as const).map((value) => <option key={value} value={value}>{presenceLabel(locale, value)}</option>)}</select>
              </label>
              <label className="grid gap-1 text-sm font-medium sm:col-span-2">{message(locale, "screen.workflowSessionConsole.961d5e6e8460")}
                <select className="h-10 rounded-md border bg-white px-3 text-sm" value={attendanceForm.substituteForIdentityId} disabled={attendanceForm.advisory || ["ABSENT", "EXCUSED"].includes(attendanceForm.presenceStatus)} onChange={(event) => setAttendanceForm({ ...attendanceForm, substituteForIdentityId: event.target.value })}><option value="">{message(locale, "screen.workflowSessionConsole.bd80f7183114")}</option>{committeeCandidates.filter(({ identityId }) => identityId !== attendanceForm.identityId && committee.some((seat) => seat.identity_id === identityId && seat.voting_right)).map((candidate) => <option key={candidate.identityId} value={candidate.identityId}>{candidate.displayName}</option>)}</select>
              </label>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-4"><label className="flex items-center gap-2 text-sm"><Checkbox checked={attendanceForm.advisory} onCheckedChange={(checked) => setAttendanceForm({ ...attendanceForm, advisory: checked === true, votingRight: checked === true ? false : attendanceForm.votingRight, substituteForIdentityId: checked === true ? "" : attendanceForm.substituteForIdentityId })} />{message(locale, "screen.workflowSessionConsole.19960d88c983")}</label><label className="flex items-center gap-2 text-sm"><Checkbox checked={attendanceForm.votingRight} disabled={attendanceForm.advisory || ["ABSENT", "EXCUSED"].includes(attendanceForm.presenceStatus)} onCheckedChange={(checked) => setAttendanceForm({ ...attendanceForm, votingRight: checked === true })} />{message(locale, "screen.workflowSessionConsole.acade974e70d")}</label><Button className="ml-auto" disabled={Boolean(busy) || !editable || !attendanceForm.identityId} onClick={() => void saveAttendance()}>{busy === "session-attendance" ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />}{message(locale, "screen.workflowSessionConsole.25112c006a95")}</Button></div>
            </> : <p className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">{message(locale, "screen.workflowSessionConsole.7fedf02cc961")}</p>}
            <div className="mt-4 space-y-2">{attendance.map((item) => <div key={item.identityId} className="flex flex-wrap items-center gap-2 rounded-xl bg-slate-50 p-3 text-sm"><strong className="mr-auto">{identityName(item.identityId)}</strong><Badge variant="outline">{presenceLabel(locale, item.presenceStatus)}</Badge>{item.advisory && <Badge variant="outline">{message(locale, "screen.workflowSessionConsole.19960d88c983")}</Badge>}{item.votingRight && <Badge>{message(locale, "screen.workflowSessionConsole.73646b7d958c")}</Badge>}{item.substituteForIdentityId && <small>{message(locale, "screen.workflowSessionConsole.b0d16efe110b")} {identityName(item.substituteForIdentityId)}</small>}</div>)}</div>
          </div>

          <div className="rounded-2xl border p-4">
            <div className="mb-3 flex items-center justify-between"><h3 className="font-semibold">{message(locale, "screen.workflowSessionConsole.9ce368b3164e")}</h3><FileLock2 className="text-cyan-700" /></div>
            <div className="space-y-3">
              <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.6e73c48528a0")}<Input value={agendaForm.title} maxLength={240} onChange={(event) => setAgendaForm({ ...agendaForm, title: event.target.value })} /></label>
              <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.025bc5e872a5")}<select className="h-10 rounded-md border bg-white px-3 text-sm" value={agendaForm.processId} onChange={(event) => setAgendaForm({ ...agendaForm, processId: event.target.value })}><option value="">{message(locale, "screen.workflowSessionConsole.5140bdceca37")}</option>{processes.map((process) => <option key={process.id} value={process.id}>{process.names[locale] || process.names.es || process.canonical_code}</option>)}</select></label>
              <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.28f216b2092a")}<textarea className="min-h-20 rounded-md border bg-white px-3 py-2 text-sm" value={agendaForm.notes} maxLength={4_000} onChange={(event) => setAgendaForm({ ...agendaForm, notes: event.target.value })} /></label>
              {(!vaultKey || !vaultKeyId) && <p className="text-xs text-amber-700">{message(locale, "screen.workflowSessionConsole.6914b5efa7a1")}</p>}
              <Button disabled={Boolean(busy) || Boolean(titleError) || !editable || !vaultKey || !vaultKeyId || !agendaForm.title.trim()} onClick={() => void addAgendaItem()}>{busy === "session-agenda" ? <LoaderCircle className="animate-spin" /> : <Plus />}{message(locale, "screen.workflowSessionConsole.e1f6b461b7a4")}</Button>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border p-4">
          <h3 className="mb-3 font-semibold">{message(locale, "screen.workflowSessionConsole.ed2800aa9d2b")}</h3>
          <div className="space-y-3">{agenda.length ? agenda.map((item, index) => {
            const decision = decisions.find(({ agendaItemId }) => agendaItemId === item.id);
            return <div key={item.id} className="rounded-xl border bg-slate-50 p-3">
              <div className="flex flex-wrap items-center gap-2"><strong className="mr-auto">{index + 1}. {item.title}</strong><Badge variant="outline">{statusLabel(locale, item.status)}</Badge><Button size="sm" variant="ghost" disabled={Boolean(titleError) || session?.status !== "scheduled" || index === 0 || Boolean(busy)} aria-label={message(locale, "screen.workflowSessionConsole.c8d45b3d46ab")} onClick={() => void moveAgenda(item, -1)}><ArrowUp /></Button><Button size="sm" variant="ghost" disabled={Boolean(titleError) || session?.status !== "scheduled" || index === agenda.length - 1 || Boolean(busy)} aria-label={message(locale, "screen.workflowSessionConsole.3b1d3d9a9e97")} onClick={() => void moveAgenda(item, 1)}><ArrowDown /></Button></div>
              {item.notesEnvelope && <EncryptedText locale={locale} tenantId={tenantId} envelope={item.notesEnvelope} vaultKeyFor={vaultKeyFor} vaultKeyringRevision={vaultKeyringRevision} aad={{ tenantId, sessionId: session!.id, purpose: "session-agenda-notes", schemaVersion: 1 }} />}
              {decision && <div className="mt-2 rounded-lg border border-emerald-200 bg-emerald-50 p-2 text-sm"><strong>{decision.decisionCode}</strong> · {outcomeLabel(locale, decision.outcome)}{decision.evidenceEnvelope && <EncryptedText locale={locale} tenantId={tenantId} envelope={decision.evidenceEnvelope} vaultKeyFor={vaultKeyFor} vaultKeyringRevision={vaultKeyringRevision} aad={{ tenantId, sessionId: session!.id, agendaItemId: item.id, purpose: "session-decision-evidence", schemaVersion: 1 }} />}</div>}
            </div>;
          }) : <p className="text-sm text-slate-500">{message(locale, "screen.workflowSessionConsole.57f93936f5e3")}</p>}</div>

          <div className="mt-5 grid gap-3 border-t pt-4 md:grid-cols-2 xl:grid-cols-4">
            <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.75151be3a8a0")}<select className="h-10 rounded-md border bg-white px-3 text-sm" value={decisionForm.agendaItemId} onChange={(event) => setDecisionForm({ ...decisionForm, agendaItemId: event.target.value })}><option value="">{message(locale, "screen.workflowSessionConsole.30360a3bdaf2")}</option>{agenda.filter((item) => !decisions.some(({ agendaItemId }) => agendaItemId === item.id)).map((item) => <option key={item.id} value={item.id}>{item.position}. {item.title}</option>)}</select></label>
            <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.1668a1179430")}<select className="h-10 rounded-md border bg-white px-3 text-sm" value={decisionForm.decisionCode} onChange={(event) => setDecisionForm({ ...decisionForm, decisionCode: event.target.value as SessionDecisionCode })}>{decisionCodesByOutcome[decisionForm.outcome].map((value) => <option key={value} value={value}>{decisionCodeLabel(locale, value)}</option>)}</select></label>
            <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.14b2162a44b6")}<select className="h-10 rounded-md border bg-white px-3 text-sm" value={decisionForm.outcome} onChange={(event) => { const outcome = event.target.value as SessionDecisionOutcome; setDecisionForm({ ...decisionForm, outcome, decisionCode: decisionCodesByOutcome[outcome][0] }); }}>{(["APPROVED", "REJECTED", "DEFERRED", "RECORDED"] as const).map((value) => <option key={value} value={value}>{outcomeLabel(locale, value)}</option>)}</select></label>
            <label className="grid gap-1 text-sm font-medium">{message(locale, "screen.workflowSessionConsole.e7dd40c16963")}<Input value={decisionForm.evidence} maxLength={4_000} onChange={(event) => setDecisionForm({ ...decisionForm, evidence: event.target.value })} /></label>
          </div>
          {decisionForm.evidence && !vaultKey && <p className="mt-2 text-xs text-amber-700">{message(locale, "screen.workflowSessionConsole.55d0d56e9e69")}</p>}
          <Button className="mt-3" disabled={Boolean(busy) || Boolean(titleError) || session?.status !== "in_progress" || !decisionForm.agendaItemId || !(decisionCodesByOutcome[decisionForm.outcome] as readonly string[]).includes(decisionForm.decisionCode) || Boolean(decisionForm.evidence && !vaultKey)} onClick={() => void recordDecision()}>{busy === "session-decision" ? <LoaderCircle className="animate-spin" /> : <CheckCircle2 />}{message(locale, "screen.workflowSessionConsole.ca303aa49615")}</Button>
        </div>
      </>}
    </div>}
  </section>;
}

function EncryptedText({ locale, tenantId, envelope, vaultKeyFor, vaultKeyringRevision, aad }: {
  locale: Locale;
  tenantId: string;
  envelope: Envelope;
  vaultKeyFor: (keyId: string, tenantId: string) => CryptoKey | undefined;
  vaultKeyringRevision: number;
  aad: Readonly<Record<string, unknown>>;
}) {
  const envelopeKey = vaultKeyFor(envelope.keyId, tenantId);
  const query = useQuery({
    queryKey: ["workflow-session-envelope", envelope.keyId, envelope.nonce, envelope.ciphertext, vaultKeyringRevision],
    queryFn: () => decryptJson<{ text?: string }>(envelopeKey!, envelope, { keyId: envelope.keyId, aad, exactAad: true }),
    enabled: Boolean(envelopeKey),
  });
  if (!envelopeKey) return <p className="mt-2 text-xs text-slate-500"><FileLock2 className="mr-1 inline size-3" />{message(locale, "screen.workflowSessionConsole.671dde7d311f")}</p>;
  if (query.isLoading) return <p className="mt-2 text-xs text-slate-500">{message(locale, "screen.workflowSessionConsole.4f7e59550317")}</p>;
  if (query.isError) return <p className="mt-2 text-xs text-red-700">{message(locale, "screen.workflowSessionConsole.13b2449b0099")}</p>;
  return <p className="mt-2 whitespace-pre-wrap text-sm text-slate-600">{query.data?.text}</p>;
}
