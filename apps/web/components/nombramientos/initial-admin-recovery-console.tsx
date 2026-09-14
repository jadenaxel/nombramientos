"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserRoundSearch,
  X,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  idempotencyKey,
  type InitialAdminRecoveryCandidate,
  type InitialAdminRecoveryCursor,
  type InitialAdminRecoveryQueueItem,
  type InitialAdminRecoveryReasonCode,
  type InitialAdminRecoveryRevocationReason,
  type InitialAdminRecoverySource,
  type InitialAdminRecoveryStatus,
  type Locale,
} from "@/lib/api";
import { localizedApiError, message } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";

type Notice = Readonly<{ tone: "success" | "error" | "warning"; title: string; body: string }>;
type OneTimeRecovery = Readonly<{ recoveryId: string; token: string; expiresAt: string }>;
type StableOperation = { signature: string; idempotencyKey: string; recoveryId?: string };

const caseReferencePattern = /^[\p{L}\p{N}][\p{L}\p{N} ._:/-]+$/u;
const controlCharacterPattern = /[\p{Cc}\p{Cf}]/u;

export function InitialAdminRecoveryConsole({
  locale,
  permissions,
  currentIdentityId,
}: {
  locale: Locale;
  permissions: readonly string[];
  currentIdentityId: string;
}) {
  const queryClient = useQueryClient();
  const canManage = permissions.includes("platform.security.manage");
  const [selectedAcceptanceId, setSelectedAcceptanceId] = useState("");
  const [reasonCode, setReasonCode] = useState<InitialAdminRecoveryReasonCode>("browser_context_lost");
  const [caseReference, setCaseReference] = useState("");
  const [expiresInMinutes, setExpiresInMinutes] = useState(1_440);
  const [statusFilter, setStatusFilter] = useState<InitialAdminRecoveryStatus | "">("");
  const [deliveryReferences, setDeliveryReferences] = useState<Record<string, string>>({});
  const [revocationReasons, setRevocationReasons] = useState<Record<string, InitialAdminRecoveryRevocationReason>>({});
  const [busyAction, setBusyAction] = useState<string>();
  const [notice, setNotice] = useState<Notice>();
  const [oneTime, setOneTime] = useState<OneTimeRecovery>();
  const [showOneTimeToken, setShowOneTimeToken] = useState(false);
  const [copied, setCopied] = useState(false);
  const requestOperationRef = useRef<StableOperation | undefined>(undefined);
  const approvalOperationsRef = useRef(new Map<string, StableOperation>());
  const revocationOperationsRef = useRef(new Map<string, StableOperation>());

  const candidatesQuery = useQuery({
    queryKey: ["platform-initial-admin-recovery-candidates"],
    queryFn: () => api.initialAdminRecoveryCandidates({ limit: 100 }),
    enabled: canManage,
    refetchInterval: 15_000,
  });
  const queueQuery = useInfiniteQuery({
    queryKey: ["platform-initial-admin-recoveries", statusFilter],
    queryFn: ({ pageParam }) => api.initialAdminRecoveries({
      status: statusFilter || undefined,
      cursor: pageParam as InitialAdminRecoveryCursor | undefined,
      limit: 20,
    }),
    initialPageParam: undefined as InitialAdminRecoveryCursor | undefined,
    getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    enabled: canManage,
    refetchInterval: 10_000,
  });

  const candidates = candidatesQuery.data?.items ?? [];
  const selectedCandidate = candidates.find((item) => item.acceptanceId === selectedAcceptanceId);
  const queueItems = useMemo(() => {
    const newest = new Map<string, InitialAdminRecoveryQueueItem>();
    for (const page of queueQuery.data?.pages ?? []) {
      for (const item of page.items) {
        const existing = newest.get(item.recoveryId);
        if (!existing || item.version > existing.version) newest.set(item.recoveryId, item);
      }
    }
    return [...newest.values()];
  }, [queueQuery.data]);

  useEffect(() => {
    const conceal = () => { if (document.visibilityState === "hidden") setShowOneTimeToken(false); };
    const purge = () => {
      setOneTime(undefined);
      setShowOneTimeToken(false);
      setCopied(false);
    };
    document.addEventListener("visibilitychange", conceal);
    window.addEventListener("pagehide", purge);
    return () => {
      document.removeEventListener("visibilitychange", conceal);
      window.removeEventListener("pagehide", purge);
    };
  }, []);

  useEffect(() => {
    if (!oneTime) return;
    const remaining = Date.parse(oneTime.expiresAt) - Date.now();
    const timer = window.setTimeout(() => {
      setOneTime(undefined);
      setShowOneTimeToken(false);
      setCopied(false);
    }, Number.isFinite(remaining) ? Math.max(0, Math.min(remaining, 2_147_483_647)) : 0);
    return () => window.clearTimeout(timer);
  }, [oneTime]);

  if (!canManage) return null;

  function resetRequestOperation() {
    requestOperationRef.current = undefined;
    setNotice(undefined);
  }

  async function refreshRecoveryData() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["platform-initial-admin-recovery-candidates"] }),
      queryClient.invalidateQueries({ queryKey: ["platform-initial-admin-recoveries"] }),
    ]);
  }

  async function requestRecovery(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedCandidate || busyAction) return;
    const normalizedReference = caseReference.trim();
    if (normalizedReference.length < 8 || !caseReferencePattern.test(normalizedReference)) {
      setNotice({ tone: "error", title: message(locale, "recovery.console.validationTitle"), body: message(locale, "recovery.console.caseReferenceInvalid") });
      return;
    }
    const source = sourceFromCandidate(selectedCandidate);
    const operationSignature = JSON.stringify({ source, reasonCode, caseReference: normalizedReference, expiresInMinutes });
    if (!requestOperationRef.current || requestOperationRef.current.signature !== operationSignature) {
      requestOperationRef.current = { signature: operationSignature, idempotencyKey: idempotencyKey(), recoveryId: crypto.randomUUID() };
    }
    const operation = requestOperationRef.current;
    setBusyAction("request");
    setNotice(undefined);
    try {
      await api.requestInitialAdminRecovery({
        recoveryId: operation.recoveryId!,
        source,
        reasonCode,
        caseReference: normalizedReference,
        expiresInMinutes,
      }, operation.idempotencyKey);
      requestOperationRef.current = undefined;
      setSelectedAcceptanceId("");
      setCaseReference("");
      setReasonCode("browser_context_lost");
      setExpiresInMinutes(1_440);
      setNotice({ tone: "success", title: message(locale, "recovery.console.requestedTitle"), body: message(locale, "recovery.console.requestedBody") });
      await refreshRecoveryData();
    } catch (caught) {
      setNotice({ tone: "error", title: message(locale, "recovery.console.requestFailedTitle"), body: localizedApiError(caught, locale) });
    } finally {
      setBusyAction(undefined);
    }
  }

  async function approveRecovery(item: InitialAdminRecoveryQueueItem) {
    if (busyAction || item.requesterIdentityId === currentIdentityId) return;
    const verifiedChannelReference = (deliveryReferences[item.recoveryId] ?? "").trim();
    if (verifiedChannelReference.length < 8 || controlCharacterPattern.test(verifiedChannelReference)) {
      setNotice({ tone: "error", title: message(locale, "recovery.console.validationTitle"), body: message(locale, "recovery.console.deliveryReferenceInvalid") });
      return;
    }
    const source = sourceFromQueueItem(item);
    const signature = JSON.stringify({ recoveryId: item.recoveryId, expectedVersion: item.version, source, deliveryChannel: "local_console", verifiedChannelReference });
    const existing = approvalOperationsRef.current.get(item.recoveryId);
    const operation = existing?.signature === signature ? existing : { signature, idempotencyKey: idempotencyKey() };
    approvalOperationsRef.current.set(item.recoveryId, operation);
    setBusyAction(`approve:${item.recoveryId}`);
    setNotice(undefined);
    try {
      const result = await api.approveInitialAdminRecovery({
        recoveryId: item.recoveryId,
        expectedVersion: item.version,
        source,
        deliveryChannel: "local_console",
        verifiedChannelReference,
      }, operation.idempotencyKey);
      approvalOperationsRef.current.delete(item.recoveryId);
      setDeliveryReferences((current) => ({ ...current, [item.recoveryId]: "" }));
      if (result.status === "revoked") {
        setOneTime(undefined);
        setShowOneTimeToken(false);
        setCopied(false);
        setNotice({ tone: "error", title: message(locale, "recovery.console.revokedTitle"), body: message(locale, "recovery.console.approvalRevokedBody") });
      } else if (!result.reused && result.developmentToken) {
        setOneTime({ recoveryId: result.recoveryId, token: result.developmentToken, expiresAt: result.delivery.tokenExpiresAt });
        setShowOneTimeToken(false);
        setCopied(false);
        setNotice({ tone: "success", title: message(locale, "recovery.console.approvedTitle"), body: message(locale, "recovery.console.approvedBody") });
      } else {
        setNotice({ tone: "warning", title: message(locale, "recovery.console.replayTitle"), body: message(locale, "recovery.console.replayBody") });
      }
      await refreshRecoveryData();
    } catch (caught) {
      setNotice({ tone: "error", title: message(locale, "recovery.console.approvalFailedTitle"), body: localizedApiError(caught, locale) });
    } finally {
      setBusyAction(undefined);
    }
  }

  async function revokeRecovery(item: InitialAdminRecoveryQueueItem) {
    if (busyAction) return;
    const reason = revocationReasons[item.recoveryId] ?? "security_response";
    const source = sourceFromQueueItem(item);
    const signature = JSON.stringify({ recoveryId: item.recoveryId, expectedVersion: item.version, source, reason });
    const existing = revocationOperationsRef.current.get(item.recoveryId);
    const operation = existing?.signature === signature ? existing : { signature, idempotencyKey: idempotencyKey() };
    revocationOperationsRef.current.set(item.recoveryId, operation);
    setBusyAction(`revoke:${item.recoveryId}`);
    setNotice(undefined);
    try {
      const result = await api.revokeInitialAdminRecovery(item.recoveryId, item.version, source, reason, operation.idempotencyKey);
      revocationOperationsRef.current.delete(item.recoveryId);
      setNotice({
        tone: "success",
        title: message(locale, "recovery.console.revokedTitle"),
        body: message(locale, "recovery.console.revokedBody", { count: result.sessionsRevoked }),
      });
      if (oneTime?.recoveryId === item.recoveryId) setOneTime(undefined);
      await refreshRecoveryData();
    } catch (caught) {
      setNotice({ tone: "error", title: message(locale, "recovery.console.revokeFailedTitle"), body: localizedApiError(caught, locale) });
    } finally {
      setBusyAction(undefined);
    }
  }

  async function copyOneTimePackage() {
    if (!oneTime) return;
    try {
      const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname);
      const recoveryOrigin = loopback ? `${window.location.protocol}//localhost:3000` : window.location.origin;
      const recoveryUrl = new URL(`/${locale}/auth/onboarding-recovery`, recoveryOrigin).toString();
      await navigator.clipboard.writeText(`${recoveryUrl}\n${oneTime.recoveryId}\n${oneTime.token}`);
      setCopied(true);
    } catch {
      setCopied(false);
      setNotice({ tone: "error", title: message(locale, "recovery.console.copyFailedTitle"), body: message(locale, "recovery.console.copyFailedBody") });
    }
  }

  return <section className="initial-admin-recovery-console" aria-labelledby="initial-admin-recovery-console-title">
    <div className="recovery-console-heading">
      <div><p className="eyebrow">{message(locale, "recovery.console.eyebrow")}</p><h2 id="initial-admin-recovery-console-title">{message(locale, "recovery.console.title")}</h2><p>{message(locale, "recovery.console.description")}</p></div>
      <span><Fingerprint /></span>
    </div>

    <Alert className="recovery-governance-boundary"><ShieldCheck /><AlertTitle>{message(locale, "recovery.console.boundaryTitle")}</AlertTitle><AlertDescription>{message(locale, "recovery.console.boundaryBody")}</AlertDescription></Alert>

    {oneTime && <Alert className="one-time-token recovery-one-time" role="status" aria-live="assertive">
      <KeyRound />
      <AlertTitle>{message(locale, "recovery.console.oneTimeTitle")}</AlertTitle>
      <AlertDescription>
        <p>{message(locale, "recovery.console.oneTimeBody")}</p>
        <strong className="recovery-recipient-device-warning"><ShieldAlert />{message(locale, "recovery.console.recipientDeviceWarning")}</strong>
        <dl><div><dt>{message(locale, "recovery.public.recoveryId")}</dt><dd><code>{oneTime.recoveryId}</code></dd></div><div><dt>{message(locale, "recovery.public.token")}</dt><dd><code>{showOneTimeToken ? oneTime.token : "•••••••••••••••••••••••••••••••••••••••••••"}</code></dd></div></dl>
        <small>{message(locale, "recovery.console.expiresAt", { time: formatUtc(oneTime.expiresAt, locale) })}</small>
        <div className="button-row">
          <Button type="button" variant="outline" onClick={() => setShowOneTimeToken((current) => !current)}>{showOneTimeToken ? <ShieldCheck /> : <KeyRound />}{showOneTimeToken ? message(locale, "recovery.public.hideToken") : message(locale, "recovery.public.showToken")}</Button>
          <Button type="button" variant="outline" onClick={() => void copyOneTimePackage()}>{copied ? <Check /> : <Copy />}{copied ? message(locale, "recovery.console.copied") : message(locale, "recovery.console.copyPackage")}</Button>
          <Button type="button" variant="ghost" onClick={() => { setOneTime(undefined); setShowOneTimeToken(false); setCopied(false); }}><X />{message(locale, "recovery.console.dismissSecret")}</Button>
        </div>
      </AlertDescription>
    </Alert>}

    {notice && <Alert role={notice.tone === "error" ? "alert" : "status"} aria-live={notice.tone === "error" ? "assertive" : "polite"} variant={notice.tone === "error" ? "destructive" : "default"} className={notice.tone === "warning" ? "recovery-warning-notice" : undefined}>
      {notice.tone === "error" ? <AlertTriangle /> : notice.tone === "warning" ? <ShieldAlert /> : <UserCheck />}
      <AlertTitle>{notice.title}</AlertTitle><AlertDescription>{notice.body}</AlertDescription>
    </Alert>}

    <div className="recovery-console-grid">
      <section className="surface-card recovery-request-card" aria-labelledby="recovery-request-title">
        <div className="card-heading"><div><p className="eyebrow">{message(locale, "recovery.console.requestEyebrow")}</p><h3 id="recovery-request-title">{message(locale, "recovery.console.requestTitle")}</h3><p>{message(locale, "recovery.console.requestBody")}</p></div><span className="form-icon"><UserRoundSearch /></span></div>
        {candidatesQuery.isLoading ? <p className="recovery-inline-state" role="status"><LoaderCircle className="animate-spin" />{message(locale, "common.loading")}</p> : candidatesQuery.isError ? <p className="recovery-inline-state error" role="alert"><AlertTriangle />{message(locale, "recovery.console.loadFailed")}</p> : candidates.length === 0 ? <p className="recovery-empty"><ShieldCheck />{message(locale, "recovery.console.noCandidates")}</p> : <form className="recovery-request-form" onSubmit={requestRecovery} noValidate>
          <div className="field-stack"><Label htmlFor="recovery-candidate">{message(locale, "recovery.console.recipient")}</Label><select id="recovery-candidate" value={selectedAcceptanceId} onChange={(event) => { setSelectedAcceptanceId(event.target.value); resetRequestOperation(); }} required disabled={Boolean(busyAction)}><option value="">{message(locale, "recovery.console.chooseRecipient")}</option>{candidates.map((candidate) => <option key={candidate.acceptanceId} value={candidate.acceptanceId}>{candidate.recipientDisplayName} · {candidate.tenantDisplayName}</option>)}</select>{selectedCandidate && <small>{selectedCandidate.recipientEmail} · {selectedCandidate.tenantDisplayName}</small>}</div>
          <div className="field-stack"><Label htmlFor="recovery-reason">{message(locale, "recovery.console.reason")}</Label><select id="recovery-reason" value={reasonCode} onChange={(event) => { setReasonCode(event.target.value as InitialAdminRecoveryReasonCode); resetRequestOperation(); }} disabled={Boolean(busyAction)}>{recoveryRequestReasons.map((value) => <option key={value} value={value}>{requestReasonLabel(locale, value)}</option>)}</select></div>
          <div className="field-stack"><Label htmlFor="recovery-case-reference">{message(locale, "recovery.console.caseReference")}</Label><Input id="recovery-case-reference" value={caseReference} onChange={(event) => { setCaseReference(event.target.value); resetRequestOperation(); }} minLength={8} maxLength={160} autoComplete="off" required disabled={Boolean(busyAction)} aria-describedby="recovery-case-reference-help" /><small id="recovery-case-reference-help">{message(locale, "recovery.console.caseReferenceHelp")}</small></div>
          <div className="field-stack"><Label htmlFor="recovery-expiry">{message(locale, "recovery.console.requestWindow")}</Label><select id="recovery-expiry" value={expiresInMinutes} onChange={(event) => { setExpiresInMinutes(Number(event.target.value)); resetRequestOperation(); }} disabled={Boolean(busyAction)}><option value={60}>{message(locale, "recovery.console.oneHour")}</option><option value={240}>{message(locale, "recovery.console.fourHours")}</option><option value={720}>{message(locale, "recovery.console.twelveHours")}</option><option value={1440}>{message(locale, "recovery.console.twentyFourHours")}</option></select></div>
          <Button type="submit" disabled={!selectedCandidate || Boolean(busyAction)}>{busyAction === "request" ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{message(locale, "recovery.console.requestWithPasskey")}</Button>
        </form>}
      </section>

      <section className="surface-card recovery-queue-card" aria-labelledby="recovery-queue-title">
        <div className="card-heading recovery-queue-heading"><div><p className="eyebrow">{message(locale, "recovery.console.queueEyebrow")}</p><h3 id="recovery-queue-title">{message(locale, "recovery.console.queueTitle")}</h3><p>{message(locale, "recovery.console.queueBody")}</p></div><div><Label className="sr-only" htmlFor="recovery-status-filter">{message(locale, "recovery.console.filterStatus")}</Label><select id="recovery-status-filter" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as InitialAdminRecoveryStatus | "")}><option value="">{message(locale, "recovery.console.allStatuses")}</option>{recoveryStatuses.map((status) => <option key={status} value={status}>{recoveryStatusLabel(locale, status)}</option>)}</select><Button type="button" size="icon" variant="ghost" onClick={() => void queueQuery.refetch()} aria-label={message(locale, "common.refresh")}><RefreshCw /></Button></div></div>
        {queueQuery.isLoading ? <p className="recovery-inline-state" role="status"><LoaderCircle className="animate-spin" />{message(locale, "common.loading")}</p> : queueQuery.isError ? <p className="recovery-inline-state error" role="alert"><AlertTriangle />{message(locale, "recovery.console.loadFailed")}</p> : queueItems.length === 0 ? <p className="recovery-empty"><ShieldCheck />{message(locale, "recovery.console.emptyQueue")}</p> : <div className="recovery-queue-list">{queueItems.map((item) => {
          const ownRequest = item.requesterIdentityId === currentIdentityId;
          const actionOpen = item.status === "pending" || item.status === "finalization_pending" || item.status === "enrollment_pending";
          return <article key={item.recoveryId}>
            <div className="recovery-item-header"><span className={`recovery-state state-${item.status}`}><KeyRound /></span><div><strong>{item.recipientDisplayName}</strong><small>{item.recipientEmail} · {item.tenantDisplayName}</small><code>{item.recoveryId}</code></div><Badge variant={item.status === "admin_active" ? "default" : item.status === "failed" || item.status === "revoked" || item.status === "expired" ? "destructive" : "outline"}>{recoveryStatusLabel(locale, item.status)}</Badge></div>
            <dl className="recovery-item-meta"><div><dt>{message(locale, "recovery.console.requestedBy")}</dt><dd>{item.requesterDisplayName}</dd></div><div><dt>{message(locale, "recovery.console.requestedAt")}</dt><dd>{formatUtc(item.requestedAt, locale)}</dd></div><div><dt>{message(locale, "recovery.console.reason")}</dt><dd>{requestReasonLabel(locale, item.reasonCode)}</dd></div><div><dt>{message(locale, "recovery.console.delivery")}</dt><dd>{deliveryStateLabel(locale, item.deliveryState)}</dd></div></dl>
            {item.status === "pending" && <div className="recovery-approval-panel">
              {ownRequest ? <Alert><UserCheck /><AlertTitle>{message(locale, "recovery.console.secondAdminTitle")}</AlertTitle><AlertDescription>{message(locale, "recovery.console.secondAdminBody")}</AlertDescription></Alert> : <>
                <div className="field-stack"><Label htmlFor={`recovery-delivery-channel-${item.recoveryId}`}>{message(locale, "recovery.console.deliveryChannel")}</Label><select id={`recovery-delivery-channel-${item.recoveryId}`} value="local_console" disabled><option value="local_console">{message(locale, "recovery.console.localConsole")}</option><option disabled>{message(locale, "recovery.console.externalAdapterRequired")}</option></select><small>{message(locale, "recovery.console.localConsoleHelp")}</small></div>
                <div className="field-stack"><Label htmlFor={`recovery-delivery-reference-${item.recoveryId}`}>{message(locale, "recovery.console.deliveryReference")}</Label><Input id={`recovery-delivery-reference-${item.recoveryId}`} value={deliveryReferences[item.recoveryId] ?? ""} onChange={(event) => { setDeliveryReferences((current) => ({ ...current, [item.recoveryId]: event.target.value })); approvalOperationsRef.current.delete(item.recoveryId); }} minLength={8} maxLength={240} autoComplete="off" required disabled={Boolean(busyAction)} aria-describedby={`recovery-delivery-reference-help-${item.recoveryId}`} /><small id={`recovery-delivery-reference-help-${item.recoveryId}`}>{message(locale, "recovery.console.deliveryReferenceHelp")}</small></div>
                <Button type="button" onClick={() => void approveRecovery(item)} disabled={Boolean(busyAction) || (deliveryReferences[item.recoveryId] ?? "").trim().length < 8}>{busyAction === `approve:${item.recoveryId}` ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{message(locale, "recovery.console.approveWithPasskey")}</Button>
              </>}
            </div>}
            {actionOpen && <details className="recovery-revoke-panel"><summary><ShieldAlert />{message(locale, "recovery.console.revokeAction")}</summary><p>{message(locale, "recovery.console.revokeWarning")}</p><div className="field-stack"><Label htmlFor={`recovery-revoke-reason-${item.recoveryId}`}>{message(locale, "recovery.console.revocationReason")}</Label><select id={`recovery-revoke-reason-${item.recoveryId}`} value={revocationReasons[item.recoveryId] ?? "security_response"} onChange={(event) => { setRevocationReasons((current) => ({ ...current, [item.recoveryId]: event.target.value as InitialAdminRecoveryRevocationReason })); revocationOperationsRef.current.delete(item.recoveryId); }} disabled={Boolean(busyAction)}>{recoveryRevocationReasons.map((reason) => <option key={reason} value={reason}>{revocationReasonLabel(locale, reason)}</option>)}</select></div><Button type="button" variant="destructive" onClick={() => void revokeRecovery(item)} disabled={Boolean(busyAction)}>{busyAction === `revoke:${item.recoveryId}` ? <LoaderCircle className="animate-spin" /> : <ShieldAlert />}{message(locale, "recovery.console.confirmRevoke")}</Button></details>}
          </article>;
        })}</div>}
        {queueQuery.hasNextPage && <Button className="recovery-load-more" type="button" variant="outline" disabled={queueQuery.isFetchingNextPage} onClick={() => void queueQuery.fetchNextPage()}>{queueQuery.isFetchingNextPage && <LoaderCircle className="animate-spin" />}{message(locale, "recovery.console.loadMore")}</Button>}
      </section>
    </div>
  </section>;
}

const recoveryRequestReasons: readonly InitialAdminRecoveryReasonCode[] = [
  "browser_context_lost", "browser_profile_reset", "device_lost", "session_delivery_failure",
];
const recoveryRevocationReasons: readonly InitialAdminRecoveryRevocationReason[] = [
  "security_response", "requester_cancelled", "delivery_reissue",
];
const recoveryStatuses: readonly InitialAdminRecoveryStatus[] = [
  "pending", "finalization_pending", "enrollment_pending", "admin_active", "revoked", "expired", "failed",
];

function sourceFromCandidate(candidate: InitialAdminRecoveryCandidate): InitialAdminRecoverySource {
  return sourceFromRecord(candidate);
}

function sourceFromRecord(record: InitialAdminRecoverySource): InitialAdminRecoverySource {
  return {
    tenantId: record.tenantId,
    invitationId: record.invitationId,
    acceptanceId: record.acceptanceId,
    acceptanceIdentityId: record.acceptanceIdentityId,
    acceptanceAttempt: record.acceptanceAttempt,
    authorityEpoch: record.authorityEpoch,
    invitationVersion: record.invitationVersion,
  };
}

function sourceFromQueueItem(item: InitialAdminRecoveryQueueItem): InitialAdminRecoverySource {
  return sourceFromRecord(item);
}

function requestReasonLabel(locale: Locale, reason: InitialAdminRecoveryReasonCode): string {
  if (reason === "browser_profile_reset") return message(locale, "recovery.reason.browserProfileReset");
  if (reason === "device_lost") return message(locale, "recovery.reason.deviceLost");
  if (reason === "session_delivery_failure") return message(locale, "recovery.reason.sessionDeliveryFailure");
  return message(locale, "recovery.reason.browserContextLost");
}

function revocationReasonLabel(locale: Locale, reason: InitialAdminRecoveryRevocationReason): string {
  if (reason === "requester_cancelled") return message(locale, "recovery.revoke.requesterCancelled");
  if (reason === "delivery_reissue") return message(locale, "recovery.revoke.deliveryReissue");
  return message(locale, "recovery.revoke.securityResponse");
}

function recoveryStatusLabel(locale: Locale, status: InitialAdminRecoveryStatus): string {
  if (status === "finalization_pending") return message(locale, "recovery.status.finalizationPending");
  if (status === "enrollment_pending") return message(locale, "recovery.status.enrollmentPending");
  if (status === "admin_active") return message(locale, "recovery.status.adminActive");
  if (status === "revoked") return message(locale, "recovery.status.revoked");
  if (status === "expired") return message(locale, "recovery.status.expired");
  if (status === "failed") return message(locale, "recovery.status.failed");
  return message(locale, "recovery.status.pending");
}

function deliveryStateLabel(locale: Locale, state: InitialAdminRecoveryQueueItem["deliveryState"]): string {
  if (state === "pending") return message(locale, "recovery.delivery.pending");
  if (state === "delivered") return message(locale, "recovery.delivery.delivered");
  if (state === "failed") return message(locale, "recovery.delivery.failed");
  return message(locale, "recovery.delivery.notStarted");
}

function formatUtc(value: string, locale: Locale): string {
  try {
    return `${formatInTenantTimeZone(value, locale, "UTC", { dateStyle: "medium", timeStyle: "short" })} · UTC`;
  } catch {
    return message(locale, "common.notApplicable");
  }
}
