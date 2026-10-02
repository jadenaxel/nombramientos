"use client";

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertCircle, Check, ChevronRight, Clock3, LoaderCircle, LockKeyhole, Receipt, ShieldCheck, Vote, Wifi } from "lucide-react";
import {
  BALLOT_PURPOSE,
  BALLOT_SCHEMA_VERSION,
  computeBallotContentHash,
  createBallotAad,
  importCustodianPublicKey,
  sealBallotEnvelope,
} from "@nombramientos/e2ee";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { api, openDeviceEventStream, ApiError, idempotencyKey, type ActiveRoundData, type AuthenticatedSession, type Locale } from "@/lib/api";
import { consumeDeviceEventStream } from "@/lib/device-event-stream";
import { encryptJson } from "@/lib/crypto-client";
import { openJsonEnvelope } from "@/lib/historical-envelope";
import { localizedApiError, localizedName, message, phaseLabel } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";
import { DataError, LoadingBlock, PageTitle } from "./workspace-view";

type CandidateDisplay = { displayName?: string; firstName?: string; lastName?: string; shortId?: string; visibleReason?: string };
type DecryptedCandidate = ActiveRoundData["candidates"][number] & Omit<CandidateDisplay, "displayName"> & { displayName: string; decryptUnavailable?: boolean };
type LiveStatus = "connecting" | "live" | "offline";

const processPhases = [
  "PROPUESTAS_ABIERTAS", "PROPUESTAS_CERRADAS", "DEPURACION", "LISTA_CONFIRMADA",
  "VOTACION_ABIERTA", "VOTACION_CERRADA", "ESCRUTINIO", "RESULTADO_INTERNO",
  "RECOMENDACION_CONFIRMADA",
];

const roundCopy = {
  es: {
    candidateNameMissing: message("es", "screen.roundView.bb6c92bdc7ba"), candidateDecryptFailed: message("es", "screen.roundView.93fa1d4e4588"),
    custodyChanged: message("es", "screen.roundView.c354f4c58e4a"), frozenMismatch: message("es", "screen.roundView.d885ef880799"),
    keyUnavailable: message("es", "screen.roundView.a0868fbedb8b"), round: message("es", "screen.roundView.399211505d74"), receiptRequired: message("es", "screen.roundView.2f9c8c6a920b"),
    verifying: message("es", "screen.roundView.39f5c50f9d10"), candidatesDecrypting: message("es", "screen.roundView.0660a5cb1025"), encryptedListUnavailable: message("es", "screen.roundView.1ea5d20c1c7b"),
    frozenBallot: message("es", "screen.roundView.e262768a36ce"), eligiblePeople: message("es", "screen.roundView.8503465b2e86"), confirmedCandidates: message("es", "screen.roundView.d346c96853c9"),
    abstainStep: message("es", "screen.roundView.4d0992be00ee"), abstainHelp: message("es", "screen.roundView.e7bc661af460"), serverReceived: message("es", "screen.roundView.cbffc6746a55"),
    receiptHelp: message("es", "screen.roundView.46543586effc"), receipt: message("es", "screen.roundView.b130266ce59c"), time: message("es", "screen.roundView.85900c264635"), fingerprint: message("es", "screen.roundView.2d5afaddbaf6"),
    abstentionReady: message("es", "screen.roundView.f7274d34ebd8"), selection: message("es", "screen.roundView.7b73ce90d57b"), selections: message("es", "screen.roundView.5d53c28eb898"), draft: message("es", "screen.roundView.e8d812baf833"), tracking: message("es", "screen.roundView.5208f02f5281"),
    noCandidate: message("es", "screen.roundView.1106a1f64a25"), selectToReview: message("es", "screen.roundView.8c89f481c203"), noVotingRight: message("es", "screen.roundView.3dec21bcd083"),
    priorCheckFailed: message("es", "screen.roundView.e152b5fa3df5"), priorCheckBlocked: message("es", "screen.roundView.4ad18dc22392"), responseFailed: message("es", "screen.roundView.3b6b7d07bd18"),
    reviewSend: message("es", "screen.roundView.99975fcdb539"), confirmResponse: message("es", "screen.roundView.a271ea0a4d3f"), confirmHelp: message("es", "screen.roundView.d42a97e9d8e2"),
    abstention: message("es", "screen.roundView.26f54a79c760"), explicitNoCandidates: message("es", "screen.roundView.3b926d522b1a"), keepReviewing: message("es", "screen.roundView.36f330deebd3"), encryptSend: message("es", "screen.roundView.297b56c8fbc5"), encryptedHere: message("es", "screen.roundView.ac01c5804376"),
    closeRound: message("es", "screen.roundView.d2df7ab4d59e"), closeTitle: message("es", "screen.roundView.098603ce9fd6"), closeHelp: message("es", "screen.roundView.352d85da0143"), closeFailed: message("es", "screen.roundView.a1f9a434b9bf"),
    responsibilities: message("es", "screen.roundView.3a0335565169"), loadingRound: message("es", "screen.roundView.263905e2d440"), currentSession: message("es", "screen.roundView.66a4e1d31834"), noRound: message("es", "screen.roundView.344784d10203"), noRoundHelp: message("es", "screen.roundView.a6b32d84b694"),
    noTask: message("es", "screen.roundView.a957bd399819"), nextOffice: message("es", "screen.roundView.c4884070a356"), phaseFailure: message("es", "screen.roundView.577844b97d01"),
    selectionLimit: message("es", "screen.roundView.485b51f1c972"),
  },
  en: {
    candidateNameMissing: message("en", "screen.roundView.bb6c92bdc7ba"), candidateDecryptFailed: message("en", "screen.roundView.93fa1d4e4588"),
    custodyChanged: message("en", "screen.roundView.c354f4c58e4a"), frozenMismatch: message("en", "screen.roundView.d885ef880799"),
    keyUnavailable: message("en", "screen.roundView.a0868fbedb8b"), round: message("en", "screen.roundView.399211505d74"), receiptRequired: message("en", "screen.roundView.2f9c8c6a920b"),
    verifying: message("en", "screen.roundView.39f5c50f9d10"), candidatesDecrypting: message("en", "screen.roundView.0660a5cb1025"), encryptedListUnavailable: message("en", "screen.roundView.1ea5d20c1c7b"),
    frozenBallot: message("en", "screen.roundView.e262768a36ce"), eligiblePeople: message("en", "screen.roundView.8503465b2e86"), confirmedCandidates: message("en", "screen.roundView.d346c96853c9"),
    abstainStep: message("en", "screen.roundView.4d0992be00ee"), abstainHelp: message("en", "screen.roundView.e7bc661af460"), serverReceived: message("en", "screen.roundView.cbffc6746a55"),
    receiptHelp: message("en", "screen.roundView.46543586effc"), receipt: message("en", "screen.roundView.b130266ce59c"), time: message("en", "screen.roundView.85900c264635"), fingerprint: message("en", "screen.roundView.2d5afaddbaf6"),
    abstentionReady: message("en", "screen.roundView.f7274d34ebd8"), selection: message("en", "screen.roundView.7b73ce90d57b"), selections: message("en", "screen.roundView.5d53c28eb898"), draft: message("en", "screen.roundView.e8d812baf833"), tracking: message("en", "screen.roundView.5208f02f5281"),
    noCandidate: message("en", "screen.roundView.1106a1f64a25"), selectToReview: message("en", "screen.roundView.8c89f481c203"), noVotingRight: message("en", "screen.roundView.3dec21bcd083"),
    priorCheckFailed: message("en", "screen.roundView.e152b5fa3df5"), priorCheckBlocked: message("en", "screen.roundView.4ad18dc22392"), responseFailed: message("en", "screen.roundView.3b6b7d07bd18"),
    reviewSend: message("en", "screen.roundView.99975fcdb539"), confirmResponse: message("en", "screen.roundView.a271ea0a4d3f"), confirmHelp: message("en", "screen.roundView.d42a97e9d8e2"),
    abstention: message("en", "screen.roundView.26f54a79c760"), explicitNoCandidates: message("en", "screen.roundView.3b926d522b1a"), keepReviewing: message("en", "screen.roundView.36f330deebd3"), encryptSend: message("en", "screen.roundView.297b56c8fbc5"), encryptedHere: message("en", "screen.roundView.ac01c5804376"),
    closeRound: message("en", "screen.roundView.d2df7ab4d59e"), closeTitle: message("en", "screen.roundView.098603ce9fd6"), closeHelp: message("en", "screen.roundView.352d85da0143"), closeFailed: message("en", "screen.roundView.a1f9a434b9bf"),
    responsibilities: message("en", "screen.roundView.3a0335565169"), loadingRound: message("en", "screen.roundView.263905e2d440"), currentSession: message("en", "screen.roundView.66a4e1d31834"), noRound: message("en", "screen.roundView.344784d10203"), noRoundHelp: message("en", "screen.roundView.a6b32d84b694"),
    noTask: message("en", "screen.roundView.a957bd399819"), nextOffice: message("en", "screen.roundView.c4884070a356"), phaseFailure: message("en", "screen.roundView.577844b97d01"),
    selectionLimit: message("en", "screen.roundView.485b51f1c972"),
  },
  fr: {
    candidateNameMissing: message("fr", "screen.roundView.bb6c92bdc7ba"), candidateDecryptFailed: message("fr", "screen.roundView.93fa1d4e4588"),
    custodyChanged: message("fr", "screen.roundView.c354f4c58e4a"), frozenMismatch: message("fr", "screen.roundView.d885ef880799"),
    keyUnavailable: message("fr", "screen.roundView.a0868fbedb8b"), round: message("fr", "screen.roundView.399211505d74"), receiptRequired: message("fr", "screen.roundView.2f9c8c6a920b"),
    verifying: message("fr", "screen.roundView.39f5c50f9d10"), candidatesDecrypting: message("fr", "screen.roundView.0660a5cb1025"), encryptedListUnavailable: message("fr", "screen.roundView.1ea5d20c1c7b"),
    frozenBallot: message("fr", "screen.roundView.e262768a36ce"), eligiblePeople: message("fr", "screen.roundView.8503465b2e86"), confirmedCandidates: message("fr", "screen.roundView.d346c96853c9"),
    abstainStep: message("fr", "screen.roundView.4d0992be00ee"), abstainHelp: message("fr", "screen.roundView.e7bc661af460"), serverReceived: message("fr", "screen.roundView.cbffc6746a55"),
    receiptHelp: message("fr", "screen.roundView.46543586effc"), receipt: message("fr", "screen.roundView.b130266ce59c"), time: message("fr", "screen.roundView.85900c264635"), fingerprint: message("fr", "screen.roundView.2d5afaddbaf6"),
    abstentionReady: message("fr", "screen.roundView.f7274d34ebd8"), selection: message("fr", "screen.roundView.7b73ce90d57b"), selections: message("fr", "screen.roundView.5d53c28eb898"), draft: message("fr", "screen.roundView.e8d812baf833"), tracking: message("fr", "screen.roundView.5208f02f5281"),
    noCandidate: message("fr", "screen.roundView.1106a1f64a25"), selectToReview: message("fr", "screen.roundView.8c89f481c203"), noVotingRight: message("fr", "screen.roundView.3dec21bcd083"),
    priorCheckFailed: message("fr", "screen.roundView.e152b5fa3df5"), priorCheckBlocked: message("fr", "screen.roundView.4ad18dc22392"), responseFailed: message("fr", "screen.roundView.3b6b7d07bd18"),
    reviewSend: message("fr", "screen.roundView.99975fcdb539"), confirmResponse: message("fr", "screen.roundView.a271ea0a4d3f"), confirmHelp: message("fr", "screen.roundView.d42a97e9d8e2"),
    abstention: message("fr", "screen.roundView.26f54a79c760"), explicitNoCandidates: message("fr", "screen.roundView.3b926d522b1a"), keepReviewing: message("fr", "screen.roundView.36f330deebd3"), encryptSend: message("fr", "screen.roundView.297b56c8fbc5"), encryptedHere: message("fr", "screen.roundView.ac01c5804376"),
    closeRound: message("fr", "screen.roundView.d2df7ab4d59e"), closeTitle: message("fr", "screen.roundView.098603ce9fd6"), closeHelp: message("fr", "screen.roundView.352d85da0143"), closeFailed: message("fr", "screen.roundView.a1f9a434b9bf"),
    responsibilities: message("fr", "screen.roundView.3a0335565169"), loadingRound: message("fr", "screen.roundView.263905e2d440"), currentSession: message("fr", "screen.roundView.66a4e1d31834"), noRound: message("fr", "screen.roundView.344784d10203"), noRoundHelp: message("fr", "screen.roundView.a6b32d84b694"),
    noTask: message("fr", "screen.roundView.a957bd399819"), nextOffice: message("fr", "screen.roundView.c4884070a356"), phaseFailure: message("fr", "screen.roundView.577844b97d01"),
    selectionLimit: message("fr", "screen.roundView.485b51f1c972"),
  },
} as const;

function PhaseStepper({ current, locale }: { current: string; locale: Locale }) {
  const index = Math.max(0, processPhases.indexOf(current));
  const ariaLabel = { es: message("es", "screen.roundView.1ddd82bcc5b4"), en: message("en", "screen.roundView.1ddd82bcc5b4"), fr: message("fr", "screen.roundView.1ddd82bcc5b4") }[locale];
  return <ol className="phase-stepper" aria-label={ariaLabel} tabIndex={0}>{processPhases.map((phase, phaseIndex) => <li key={phase} className={phaseIndex < index ? "done" : phaseIndex === index ? "current" : ""} aria-current={phaseIndex === index ? "step" : undefined}><span>{phaseIndex < index ? <Check /> : phaseIndex + 1}</span><small>{phaseLabel(locale, phase)}</small></li>)}</ol>;
}

function useLiveRound(enabled: boolean, tenantId: string) {
  const client = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");
  useEffect(() => {
    if (!enabled) return;
    let source: AbortController | undefined;
    let retryTimer: number | undefined;
    let disposed = false;
    let validationSequence = 0;
    const revalidate = (current: AbortController) => {
      const sequence = ++validationSequence;
      setStatus("connecting");
      void Promise.all([
        client.invalidateQueries({ queryKey: ["active-round"] }, { throwOnError: true }),
        client.invalidateQueries({ queryKey: ["dashboard"] }, { throwOnError: true }),
      ]).then(() => {
        if (!disposed && source === current && validationSequence === sequence) setStatus("live");
      }).catch(() => {
        if (disposed || source !== current || validationSequence !== sequence) return;
        current.abort();
        source = undefined;
        setStatus("offline");
        retryTimer = window.setTimeout(connect, 3_000);
      });
    };
    const connect = () => {
      if (disposed) return;
      if (!navigator.onLine) {
        setStatus("offline");
        return;
      }
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      source?.abort();
      setStatus("connecting");
      const next = new AbortController();
      source = next;
      void (async () => {
        try {
          const response = await openDeviceEventStream(`/v1/events?tenantId=${encodeURIComponent(tenantId)}`, next.signal);
          await consumeDeviceEventStream(response, (event) => {
            if (!disposed && source === next && ["ready", "round.phase", "round.participation", "round.closed"].includes(event)) revalidate(next);
          }, next.signal);
        } catch { /* Stream transport degrades honestly to offline; the API handles revoked sessions. */ }
        finally {
          if (!disposed && source === next) {
            validationSequence += 1; next.abort(); source = undefined;
            setStatus("offline"); retryTimer = window.setTimeout(connect, 3_000);
          }
        }
      })();
    };
    const offline = () => {
      validationSequence += 1;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      source?.abort();
      source = undefined;
      setStatus("offline");
    };
    const online = () => connect();
    window.addEventListener("offline", offline);
    window.addEventListener("online", online);
    connect();
    return () => {
      disposed = true;
      validationSequence += 1;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      window.removeEventListener("offline", offline);
      window.removeEventListener("online", online);
      source?.abort();
    };
  }, [client, enabled, tenantId]);
  return status;
}

function ActiveRoundWorkspace({ data, locale, session, liveStatus }: { data: ActiveRoundData; locale: Locale; session: AuthenticatedSession; liveStatus: LiveStatus }) {
  const vault = useVault();
  const text = roundCopy[locale];
  const client = useQueryClient();
  const [candidates, setCandidates] = useState<DecryptedCandidate[]>([]);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState<string>();
  const [selected, setSelected] = useState<string[]>([]);
  const [abstain, setAbstain] = useState(false);
  const [selectionError, setSelectionError] = useState<string>();
  const [localReceipt, setLocalReceipt] = useState<{ receiptId: string; receivedAt: string; contentHash: string }>();
  const receiptHeadingRef = useRef<HTMLHeadingElement>(null);
  const [submissionIdempotencyKey] = useState(() => idempotencyKey());
  const [closeIdempotencyKey] = useState(() => idempotencyKey());
  const requiredSubmitPermission = data.round.submissionKind === "proposal" ? "proposal.submit" : "ballot.submit";
  const viewerHasSubmitPermission = session.permissions.includes(requiredSubmitPermission);
  const receiptQuery = useQuery({
    queryKey: ["round-receipt", session.tenant.id, data.round.id],
    queryFn: async () => {
      try { return await api.mySubmission(data.round.id); }
      catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    // A frozen electorate may become fail-closed after a candidate eligibility
    // change. The elector must still be able to recover an already-issued
    // receipt even when a new response is no longer allowed.
    enabled: viewerHasSubmitPermission,
    retry: false,
    staleTime: Infinity,
  });
  const receipt = localReceipt ?? receiptQuery.data ?? undefined;

  useEffect(() => {
    if (localReceipt) receiptHeadingRef.current?.focus();
  }, [localReceipt]);

  useEffect(() => {
    let cancelled = false;
    async function run() {
      if (!vault.key) return;
      setDecrypting(true); setDecryptError(undefined);
      try {
        let hadFailures = false;
        const values = await Promise.all(data.candidates.map(async (candidate) => {
          try {
            const profile = await openJsonEnvelope<CandidateDisplay>({
              resolver: vault,
              tenantId: session.tenant.id,
              envelope: candidate.displayEnvelope,
              aad: { tenantId: session.tenant.id, memberId: candidate.memberId, purpose: "member-display", schemaVersion: 1 },
            });
            const displayName = profile.displayName?.trim() || [profile.firstName, profile.lastName].filter(Boolean).join(" ").trim();
            if (!displayName) throw new Error(text.candidateNameMissing);
            return { ...candidate, ...profile, displayName };
          } catch {
            hadFailures = true;
            return { ...candidate, displayName: text.encryptedListUnavailable, decryptUnavailable: true };
          }
        }));
        if (!cancelled) {
          setCandidates(values);
          setDecryptError(hadFailures ? text.candidateDecryptFailed : undefined);
        }
      } catch {
        if (!cancelled) setDecryptError(text.candidateDecryptFailed);
      } finally { if (!cancelled) setDecrypting(false); }
    }
    void run();
    return () => { cancelled = true; };
  }, [data.candidates, session.tenant.id, text.candidateDecryptFailed, text.candidateNameMissing, text.encryptedListUnavailable, vault, vault.key, vault.keyFor, vault.keyringRevision]);

  const submitMutation = useMutation({
    mutationFn: async () => {
      if (decryptError) throw new Error(text.candidateDecryptFailed);
      const { round } = data;
      if (round.submissionKind === "vote") {
        const recipientSet = await api.ballotRecipients(round.id);
        if (recipientSet.roundId !== round.id || recipientSet.roundVersion !== round.version) {
          throw new Error(text.custodyChanged);
        }
        const rules = {
          candidateIds: data.candidates.filter((candidate) => candidate.eligible).map((candidate) => candidate.id),
          minSelections: 1,
          maxSelections: round.maxSelections,
          allowAbstention: true,
        } as const;
        const aad = await createBallotAad({
          tenantId: session.tenant.id,
          cycleId: round.cycleId,
          roundId: round.id,
          purpose: BALLOT_PURPOSE,
          schemaVersion: BALLOT_SCHEMA_VERSION,
          roundVersion: round.version,
        }, rules);
        if (aad.candidateSetHash !== round.candidateSetHash || aad.rulesHash !== round.rulesHash) {
          throw new Error(text.frozenMismatch);
        }
        const recipients = await Promise.all(recipientSet.recipients.map((recipient) => importCustodianPublicKey({
          format: "nombramientos.hpke-public-key",
          version: 1,
          suite: recipientSet.suite,
          recipientId: recipient.recipientId,
          fingerprint: recipient.fingerprint,
          publicKey: recipient.hpkePublicKey,
        })));
        const envelope = await sealBallotEnvelope({
          payload: {
            schemaVersion: BALLOT_SCHEMA_VERSION,
            selections: abstain ? [] : selected,
            abstain,
          },
          aad,
          rules,
          recipients,
        });
        return api.submit(round.id, {
          kind: "vote",
          expectedVersion: round.version,
          envelope,
          contentHash: await computeBallotContentHash(envelope),
        }, submissionIdempotencyKey);
      }
      if (!vault.key || !vault.keyId) throw new Error(text.keyUnavailable);
      const aad = {
        tenantId: session.tenant.id, cycleId: round.cycleId, roundId: round.id,
        purpose: "proposal", schemaVersion: 1, roundVersion: round.version,
        candidateSetHash: round.candidateSetHash,
        rulesHash: round.rulesHash,
      };
      const sealed = await encryptJson(vault.key, vault.keyId, aad, {
        schema: "nombramientos-submission/v1", abstain, selections: abstain ? [] : selected,
      });
      return api.submit(round.id, {
        kind: "proposal", expectedVersion: round.version,
        envelope: sealed.envelope, contentHash: sealed.contentHash,
      }, submissionIdempotencyKey);
    },
    onSuccess: (value) => {
      setLocalReceipt(value);
      client.setQueryData(["round-receipt", session.tenant.id, data.round.id], value);
      void client.invalidateQueries({ queryKey: ["active-round"] });
      void client.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });
  const closeMutation = useMutation({
    mutationFn: () => api.closeRound(data.round.id, data.round.version, closeIdempotencyKey),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["active-round"] });
      void client.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  const { round, participation } = data;
  const max = round.maxSelections;
  const completion = participation.required ? (participation.received / participation.required) * 100 : 0;
  const requiredClosePermission = round.submissionKind === "proposal" ? "proposal.close" : "ballot.close";
  const maySubmit = data.viewerCanSubmit && viewerHasSubmitPermission;
  const open = round.phase === "PROPUESTAS_ABIERTAS" || round.phase === "VOTACION_ABIERTA";
  const canSubmit = maySubmit && !decryptError && liveStatus === "live" && !receiptQuery.isLoading && !receiptQuery.isError && !receipt && !submitMutation.isPending && (abstain || selected.length > 0) && selected.length <= max;
  const updateSelection = (id: string, checked: boolean) => {
    if (max > 1 && checked && !selected.includes(id) && selected.length >= max) {
      setSelectionError(text.selectionLimit.replace("{limit}", String(max)));
      return;
    }
    setSelectionError(undefined);
    setAbstain(false);
    setSelected((current) => checked
      ? max === 1 ? [id] : [...current.filter((item) => item !== id), id]
      : current.filter((item) => item !== id));
  };

  return <>
    <PageTitle eyebrow={`${round.officeCode} · ${text.round} ${round.version}`} title={localizedName(round.officeNames, locale, round.officeName)} description={round.submissionKind === "proposal" ? `${message(locale, "proposal.instruction", { limit: max })} ${message(locale, "proposal.abstainConfirm")}` : message(locale, max === 1 ? "vote.singleInstruction" : "vote.multipleInstruction", { limit: max })} action={<Badge className="phase-badge">{phaseLabel(locale, round.phase)}</Badge>} />
    <div className={`connection-banner ${liveStatus}`} role="status" aria-live="polite"><Wifi /><span><strong>{liveStatus === "live" ? message(locale, "connection.online") : liveStatus === "connecting" ? message(locale, "connection.reconnecting") : message(locale, "connection.offline")}</strong><small>{liveStatus === "offline" ? message(locale, "connection.offlineDraft") : text.receiptRequired}</small></span><Badge variant="outline">{liveStatus === "live" ? message(locale, "connection.online") : liveStatus === "connecting" ? text.verifying : message(locale, "connection.offline")}</Badge></div>
    <PhaseStepper current={round.phase} locale={locale} />
    <section className="round-grid"><div className="candidate-surface">
      <div className="round-summary"><div><p>{message(locale, "participation.title")}</p><strong>{participation.received} / {participation.required}</strong></div><Progress value={completion} aria-label={message(locale, "participation.progress", { received: participation.received, required: participation.required, percent: Math.round(completion) })} /><span>{message(locale, "metrics.pending")}: {participation.pending}{!open && typeof participation.abstentions === "number" ? ` · ${message(locale, "tally.abstentions", { count: participation.abstentions })}` : ""}</span></div>
      {decrypting ? <LoadingBlock locale={locale} label={text.candidatesDecrypting} /> : <>
        {decryptError ? <Alert variant="destructive"><LockKeyhole /><AlertTitle>{text.encryptedListUnavailable}</AlertTitle><AlertDescription>{decryptError}</AlertDescription></Alert> : null}
        <div className="candidate-heading"><div><p className="eyebrow">{text.frozenBallot}</p><h2 id="candidate-group-label">{round.submissionKind === "proposal" ? text.eligiblePeople : text.confirmedCandidates}</h2></div><Badge variant="outline">{selected.length} / {max}</Badge></div>
        {max === 1 ? <RadioGroup aria-labelledby="candidate-group-label" value={selected[0] ?? ""} onValueChange={(value) => updateSelection(value, true)} className="candidate-list">{candidates.map((candidate) => <CandidateCard key={candidate.id} candidate={candidate} locale={locale} selected={selected.includes(candidate.id)} disabled={Boolean(decryptError) || Boolean(candidate.decryptUnavailable) || !candidate.eligible || !open || !maySubmit} kind="radio" onCheckedChange={(checked) => updateSelection(candidate.id, checked)} />)}</RadioGroup> : <div className="candidate-list" role="group" aria-labelledby="candidate-group-label">{candidates.map((candidate) => <CandidateCard key={candidate.id} candidate={candidate} locale={locale} selected={selected.includes(candidate.id)} disabled={Boolean(decryptError) || Boolean(candidate.decryptUnavailable) || !candidate.eligible || !open || !maySubmit} kind="checkbox" onCheckedChange={(checked) => updateSelection(candidate.id, checked)} />)}</div>}
        <div aria-live="assertive">{selectionError && <Alert variant="destructive" role="alert"><AlertCircle /><AlertTitle>{selectionError}</AlertTitle></Alert>}</div>
        <label className={`abstain-card ${abstain ? "selected" : ""}`}><Checkbox checked={abstain} onCheckedChange={(checked) => { setSelectionError(undefined); setAbstain(checked === true); if (checked) setSelected([]); }} disabled={Boolean(decryptError) || !open || !maySubmit} /><span><strong>{text.abstainStep}</strong><small>{text.abstainHelp}</small></span></label>
      </>}
    </div><aside className="submission-panel">
      {receipt ? <div className="receipt-card" role="status" aria-live="polite"><span><Receipt /></span><p className="eyebrow">{text.serverReceived}</p><h2 ref={receiptHeadingRef} tabIndex={-1}>{message(locale, round.submissionKind === "proposal" ? "proposal.received" : "vote.received")}</h2><p>{text.receiptHelp}</p><dl><div><dt>{text.receipt}</dt><dd>{receipt.receiptId.slice(0, 12)}…</dd></div><div><dt>{text.time}</dt><dd>{formatInTenantTimeZone(receipt.receivedAt, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" })}</dd></div><div><dt>{text.fingerprint}</dt><dd>{receipt.contentHash.slice(0, 20)}…</dd></div></dl></div> : <div className="selection-tray"><span className="receipt-orb"><Vote /></span><h2>{maySubmit ? (abstain ? text.abstentionReady : selected.length ? `${selected.length} ${selected.length === 1 ? text.selection : text.selections}` : text.draft) : text.tracking}</h2><p>{maySubmit ? (selected.length ? candidates.filter((candidate) => selected.includes(candidate.id)).map((candidate) => candidate.displayName).join(", ") : abstain ? text.noCandidate : text.selectToReview) : text.noVotingRight}</p>{receiptQuery.error && <Alert variant="destructive"><AlertCircle /><AlertTitle>{text.priorCheckFailed}</AlertTitle><AlertDescription>{text.priorCheckBlocked}</AlertDescription></Alert>}{submitMutation.error && <Alert variant="destructive"><AlertCircle /><AlertTitle>{text.responseFailed}</AlertTitle><AlertDescription>{localizedApiError(submitMutation.error, locale)}</AlertDescription></Alert>}<Dialog><DialogTrigger asChild><Button className="h-12 w-full" disabled={!canSubmit || !open}>{submitMutation.isPending ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />} {text.reviewSend}</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>{text.confirmResponse}</DialogTitle><DialogDescription>{text.confirmHelp}</DialogDescription></DialogHeader><div className="confirmation-box"><strong>{abstain ? text.abstention : `${selected.length} ${selected.length === 1 ? text.selection : text.selections}`}</strong><p>{abstain ? text.explicitNoCandidates : candidates.filter((candidate) => selected.includes(candidate.id)).map((candidate) => candidate.displayName).join(", ")}</p></div><DialogFooter><DialogClose asChild><Button variant="outline">{text.keepReviewing}</Button></DialogClose><DialogClose asChild><Button onClick={() => submitMutation.mutate()}>{text.encryptSend} <ChevronRight /></Button></DialogClose></DialogFooter></DialogContent></Dialog><p className="privacy-caption"><LockKeyhole /> {text.encryptedHere}</p></div>}
      {session.permissions.includes(requiredClosePermission) && <AlertDialog><AlertDialogTrigger asChild><Button variant="outline" className="mt-3 w-full" disabled={closeMutation.isPending || !open}>{text.closeRound}</Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{text.closeTitle}</AlertDialogTitle><AlertDialogDescription>{text.closeHelp}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{message(locale, "common.cancel")}</AlertDialogCancel><AlertDialogAction onClick={() => closeMutation.mutate()}>{text.closeRound}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>}{closeMutation.error && <p className="form-error mt-3" role="alert">{closeMutation.error instanceof ApiError ? localizedApiError(closeMutation.error, locale) : text.closeFailed}</p>}
    </aside></section>
  </>;
}

function CandidateCard({ candidate, locale, selected, disabled, kind, onCheckedChange }: { candidate: DecryptedCandidate; locale: Locale; selected: boolean; disabled: boolean; kind: "radio" | "checkbox"; onCheckedChange: (checked: boolean) => void }) {
  return <label className={`candidate-card ${selected ? "selected" : ""} ${disabled ? "disabled" : ""}`}>{kind === "radio" ? <RadioGroupItem value={candidate.id} disabled={disabled} /> : <Checkbox checked={selected} onCheckedChange={(checked) => onCheckedChange(checked === true)} disabled={disabled} />}<span className="candidate-avatar" aria-hidden="true">{candidate.displayName.split(/\s+/).map((part) => part[0]).slice(0, 2).join("")}</span><span><strong>{candidate.displayName}</strong><small>{candidate.shortId ?? candidate.memberId} · {candidate.alreadyAssignedCount} {roundCopy[locale].responsibilities}</small>{candidate.visibleReason && <em>{candidate.visibleReason}</em>}</span>{selected && <Check />}</label>;
}

export function RoundView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const text = roundCopy[locale];
  const query = useQuery({
    queryKey: ["active-round", session.tenant.id],
    queryFn: async () => {
      try { return await api.activeRound(); }
      catch (error) {
        if (error instanceof ApiError && error.status === 404) return null;
        throw error;
      }
    },
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 1,
  });
  const liveStatus = useLiveRound(Boolean(query.data), session.tenant.id);
  if (query.isLoading) return <LoadingBlock locale={locale} label={text.loadingRound} />;
  if (!query.data) {
    if (!query.error || (query.error instanceof ApiError && query.error.status === 404)) return <><PageTitle eyebrow={text.currentSession} title={text.noRound} description={text.noRoundHelp} /><Alert><Clock3 /><AlertTitle>{text.noTask}</AlertTitle><AlertDescription>{text.nextOffice}</AlertDescription></Alert></>;
    return <DataError locale={locale} title={text.phaseFailure} />;
  }
  return <ActiveRoundWorkspace key={`${query.data.round.id}:${query.data.round.version}`} data={query.data} locale={locale} session={session} liveStatus={liveStatus} />;
}
