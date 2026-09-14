"use client";

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Award, History, LoaderCircle, LockKeyhole, Pencil, Plus, ShieldCheck } from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  idempotencyKey,
  type AuthenticatedSession,
  type Locale,
  type MemberQualificationRecord,
  type MemberQualificationStatus,
  type MemberQualificationType,
  type MemberQualificationWrite,
} from "@/lib/api";
import { encryptJson } from "@/lib/crypto-client";
import {
  memberQualificationAad,
  openMemberQualificationDetails,
  type QualificationDetails,
} from "@/lib/member-qualification-crypto";
import { localizedApiError, message } from "@/lib/product-i18n";
import { formatCalendarDate, formatInTenantTimeZone } from "@/lib/tenant-time";

type EditableRecord = MemberQualificationRecord | "new";

const typeKeys = {
  training: "qualification.type.training",
  ordination: "qualification.type.ordination",
  certification: "qualification.type.certification",
  other: "qualification.type.other",
} as const;

const statusKeys = {
  pending: "qualification.status.pending",
  verified: "qualification.status.verified",
  expired: "qualification.status.expired",
  revoked: "qualification.status.revoked",
} as const;

export function MemberQualifications({
  locale,
  session,
  memberId,
  displayName,
}: {
  readonly locale: Locale;
  readonly session: AuthenticatedSession;
  readonly memberId: string;
  readonly displayName: string;
}) {
  const vault = useVault();
  const {
    keyFor: qualificationKeyFor,
    keyringRevision,
    tenantId: vaultTenantId,
  } = vault;
  const queryClient = useQueryClient();
  const mayRead = session.permissions.includes("member.qualification.read");
  const mayManage = session.permissions.includes("member.qualification.manage");
  const query = useQuery({
    queryKey: ["member-qualifications", session.tenant.id, memberId],
    enabled: mayRead,
    queryFn: () => api.memberQualifications(memberId),
  });
  const [details, setDetails] = useState<Record<string, QualificationDetails>>({});
  const [unavailableDetails, setUnavailableDetails] = useState<ReadonlySet<string>>(new Set());
  const [editing, setEditing] = useState<EditableRecord>();
  const [type, setType] = useState<MemberQualificationType>("training");
  const [status, setStatus] = useState<MemberQualificationStatus>("pending");
  const [effectiveOn, setEffectiveOn] = useState("");
  const [expiresOn, setExpiresOn] = useState("");
  const [title, setTitle] = useState("");
  const [issuer, setIssuer] = useState("");
  const submission = useRef<{
    readonly qualificationId: string;
    readonly expectedVersion: number | null;
    readonly body: MemberQualificationWrite;
    readonly key: string;
  } | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    async function reveal() {
      setDetails({});
      setUnavailableDetails(new Set());
      if (!query.data || vaultTenantId !== session.tenant.id) return;
      const revealed: Record<string, QualificationDetails> = {};
      const failures = new Set<string>();
      await Promise.all(query.data.items.flatMap((record) => record.revisions).map(async (revision) => {
        if (!revision.detailsEnvelope) return;
        const key = revisionKey(revision.qualificationId, revision.version);
        try {
          revealed[key] = await openMemberQualificationDetails({
            key: qualificationKeyFor(revision.detailsEnvelope.keyId, session.tenant.id),
            envelope: revision.detailsEnvelope,
            context: {
              tenantId: session.tenant.id,
              memberId,
              qualificationId: revision.qualificationId,
              version: revision.version,
              type: revision.type,
              status: revision.status,
              effectiveOn: revision.effectiveOn,
              expiresOn: revision.expiresOn,
            },
          });
        } catch {
          failures.add(key);
        }
      }));
      if (!cancelled) {
        setDetails(revealed);
        setUnavailableDetails(failures);
      }
    }
    void reveal();
    return () => { cancelled = true; };
  }, [keyringRevision, memberId, qualificationKeyFor, query.data, session.tenant.id, vaultTenantId]);

  function resetSubmission(): void {
    submission.current = undefined;
    mutation.reset();
  }

  function beginCreate(): void {
    setEditing("new");
    setType("training");
    setStatus("pending");
    setEffectiveOn("");
    setExpiresOn("");
    setTitle("");
    setIssuer("");
    resetSubmission();
  }

  function beginEdit(record: MemberQualificationRecord): void {
    const revealed = details[revisionKey(record.qualificationId, record.version)];
    if (record.hasDetails && !revealed) return;
    setEditing(record);
    setType(record.type);
    setStatus(record.status);
    setEffectiveOn(record.effectiveOn);
    setExpiresOn(record.expiresOn ?? "");
    setTitle(revealed?.title ?? "");
    setIssuer(revealed?.issuer ?? "");
    resetSubmission();
  }

  const mutation = useMutation({
    mutationFn: async () => {
      if (!editing) throw new Error(message(locale, "qualification.error.missingRecord"));
      if ((title.trim() || issuer.trim()) && (
        !vault.key || !vault.keyId || vault.tenantId !== session.tenant.id
      )) {
        throw new Error(message(locale, "qualification.error.unlock"));
      }
      if (!submission.current) {
        const qualificationId = editing === "new" ? crypto.randomUUID() : editing.qualificationId;
        const expectedVersion = editing === "new" ? null : editing.version;
        const version = (expectedVersion ?? 0) + 1;
        const expiration = expiresOn || null;
        const sealed = title.trim() || issuer.trim()
          ? await encryptJson(
              vault.key!,
              vault.keyId!,
              memberQualificationAad({
                tenantId: session.tenant.id,
                memberId,
                qualificationId,
                version,
                type,
                status,
                effectiveOn,
                expiresOn: expiration,
              }),
              { ...(title.trim() ? { title: title.trim() } : {}), ...(issuer.trim() ? { issuer: issuer.trim() } : {}) },
            )
          : null;
        submission.current = {
          qualificationId,
          expectedVersion,
          key: idempotencyKey(),
          body: {
            type,
            status,
            effectiveOn,
            expiresOn: expiration,
            detailsEnvelope: sealed?.envelope ?? null,
            detailsContentHash: sealed ? sealed.contentHash as `sha256:${string}` : null,
          },
        };
      }
      const pending = submission.current;
      return pending.expectedVersion === null
        ? api.createMemberQualification(memberId, pending.qualificationId, pending.body, pending.key)
        : api.reviseMemberQualification(
            memberId,
            pending.qualificationId,
            pending.expectedVersion,
            pending.body,
            pending.key,
          );
    },
    onSuccess: () => {
      setEditing(undefined);
      submission.current = undefined;
      void queryClient.invalidateQueries({ queryKey: ["member-qualifications", session.tenant.id, memberId] });
    },
  });

  const change = <T,>(setter: (value: T) => void, value: T) => {
    setter(value);
    resetSubmission();
  };
  const expirationInvalid = Boolean(expiresOn && effectiveOn && expiresOn < effectiveOn)
    || (status === "expired" && !expiresOn);

  if (!mayRead) return null;

  return <section className="grid gap-4" aria-labelledby={`qualification-title-${memberId}`}>
    <Alert>
      <ShieldCheck aria-hidden="true" />
      <AlertTitle>{message(locale, "qualification.independent.title")}</AlertTitle>
      <AlertDescription>{message(locale, "qualification.independent.body")}</AlertDescription>
    </Alert>

    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 id={`qualification-title-${memberId}`} className="m-0 flex items-center gap-2"><Award aria-hidden="true" /> {message(locale, "qualification.title")}</h3>
        <p className="text-sm text-slate-600">{displayName}</p>
      </div>
      {mayManage && <Button type="button" onClick={beginCreate}><Plus aria-hidden="true" /> {message(locale, "qualification.add")}</Button>}
    </div>

    {query.isLoading && <p role="status" className="flex items-center gap-2"><LoaderCircle className="animate-spin" aria-hidden="true" /> {message(locale, "qualification.loading")}</p>}
    {query.error && <Alert variant="destructive"><AlertDescription>{localizedApiError(query.error, locale)}</AlertDescription></Alert>}
    {query.data?.items.length === 0 && <p className="rounded-2xl border border-dashed p-5 text-sm text-slate-600">{message(locale, "qualification.empty")}</p>}

    <div className="grid gap-3">
      {query.data?.items.map((record) => {
        const currentDetails = details[revisionKey(record.qualificationId, record.version)];
        const detailsUnavailable = record.hasDetails && !currentDetails;
        return <article key={record.qualificationId} className="rounded-2xl border bg-white p-4 shadow-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2">
                <strong>{currentDetails?.title || message(locale, typeKeys[record.type])}</strong>
                <Badge variant="outline">{message(locale, statusKeys[record.status])}</Badge>
                <Badge variant="outline">v{record.version}</Badge>
              </div>
              {currentDetails?.issuer && <span className="text-sm text-slate-600">{message(locale, "qualification.issuer")}: {currentDetails.issuer}</span>}
              {detailsUnavailable && <span className="flex items-center gap-1 text-sm text-slate-600"><LockKeyhole size={14} aria-hidden="true" /> {vault.key ? message(locale, "qualification.detailsUnavailable") : message(locale, "qualification.detailsLocked")}</span>}
              <span className="text-sm">{message(locale, "qualification.effectiveOn")}: {formatCalendarDate(record.effectiveOn, locale)}</span>
              <span className="text-sm">{message(locale, "qualification.expiresOn")}: {record.expiresOn ? formatCalendarDate(record.expiresOn, locale) : message(locale, "qualification.noExpiration")}</span>
              <small>{message(locale, "qualification.reviewer")}: <code>{record.reviewerIdentityId}</code></small>
            </div>
            {mayManage && <Button type="button" size="sm" variant="outline" disabled={detailsUnavailable} onClick={() => beginEdit(record)}><Pencil aria-hidden="true" /> {message(locale, "common.edit")}</Button>}
          </div>
          <details className="mt-3 rounded-xl bg-slate-50 p-3">
            <summary className="flex cursor-pointer items-center gap-2 font-semibold"><History size={16} aria-hidden="true" /> {message(locale, "qualification.history")} ({record.revisions.length})</summary>
            <ol className="mt-3 grid gap-2">
              {record.revisions.map((revision) => {
                const revisionDetails = details[revisionKey(revision.qualificationId, revision.version)];
                return <li key={revision.version} className="rounded-lg border bg-white p-3 text-sm">
                  <div className="flex flex-wrap gap-2"><strong>v{revision.version}</strong><span>{message(locale, typeKeys[revision.type])}</span><span>{message(locale, statusKeys[revision.status])}</span></div>
                  {revisionDetails?.title && <span className="block">{revisionDetails.title}</span>}
                  {revisionDetails?.issuer && <small className="block">{message(locale, "qualification.issuer")}: {revisionDetails.issuer}</small>}
                  {unavailableDetails.has(revisionKey(revision.qualificationId, revision.version)) && <small>{message(locale, "qualification.detailsUnavailable")}</small>}
                  <small className="block">{formatInTenantTimeZone(revision.recordedAt, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" })}</small>
                </li>;
              })}
            </ol>
          </details>
        </article>;
      })}
    </div>

    <Dialog open={Boolean(editing)} onOpenChange={(open) => { if (!open) { setEditing(undefined); submission.current = undefined; mutation.reset(); } }}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{editing === "new" ? message(locale, "qualification.add") : message(locale, "qualification.edit")}</DialogTitle>
          <DialogDescription>{message(locale, "qualification.formDescription")}</DialogDescription>
        </DialogHeader>
        <form id="qualification-form" className="dialog-form" onSubmit={(event) => { event.preventDefault(); mutation.mutate(); }}>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="field-stack"><Label htmlFor="qualification-type">{message(locale, "qualification.type")}</Label><select id="qualification-type" value={type} onChange={(event) => change(setType, event.target.value as MemberQualificationType)}><option value="training">{message(locale, typeKeys.training)}</option><option value="ordination">{message(locale, typeKeys.ordination)}</option><option value="certification">{message(locale, typeKeys.certification)}</option><option value="other">{message(locale, typeKeys.other)}</option></select></div>
            <div className="field-stack"><Label htmlFor="qualification-status">{message(locale, "qualification.status")}</Label><select id="qualification-status" value={status} onChange={(event) => change(setStatus, event.target.value as MemberQualificationStatus)}><option value="pending">{message(locale, statusKeys.pending)}</option><option value="verified">{message(locale, statusKeys.verified)}</option><option value="expired">{message(locale, statusKeys.expired)}</option><option value="revoked">{message(locale, statusKeys.revoked)}</option></select></div>
            <div className="field-stack"><Label htmlFor="qualification-effective">{message(locale, "qualification.effectiveOn")}</Label><Input id="qualification-effective" type="date" value={effectiveOn} onChange={(event) => change(setEffectiveOn, event.target.value)} required /></div>
            <div className="field-stack"><Label htmlFor="qualification-expiration">{message(locale, "qualification.expiresOn")}</Label><Input id="qualification-expiration" type="date" value={expiresOn} onChange={(event) => change(setExpiresOn, event.target.value)} required={status === "expired"} min={effectiveOn || undefined} /></div>
            <div className="field-stack"><Label htmlFor="qualification-name">{message(locale, "qualification.detailTitle")}</Label><Input id="qualification-name" value={title} onChange={(event) => change(setTitle, event.target.value)} maxLength={160} autoComplete="off" /></div>
            <div className="field-stack"><Label htmlFor="qualification-issuer">{message(locale, "qualification.issuer")}</Label><Input id="qualification-issuer" value={issuer} onChange={(event) => change(setIssuer, event.target.value)} maxLength={160} autoComplete="off" /></div>
          </div>
          <small className="flex items-center gap-1"><LockKeyhole size={14} aria-hidden="true" /> {message(locale, "qualification.encryptedDetails")}</small>
          <Alert><ShieldCheck /><AlertTitle>{message(locale, "qualification.mfaTitle")}</AlertTitle><AlertDescription>{message(locale, "qualification.mfaBody")}</AlertDescription></Alert>
          {expirationInvalid && <p className="form-error" role="alert">{message(locale, "qualification.error.expiration")}</p>}
          {mutation.error && <p className="form-error" role="alert">{mutation.error instanceof Error && !('status' in mutation.error) ? mutation.error.message : localizedApiError(mutation.error, locale)}</p>}
        </form>
        <DialogFooter><Button type="button" variant="outline" onClick={() => setEditing(undefined)}>{message(locale, "common.cancel")}</Button><Button form="qualification-form" type="submit" disabled={!effectiveOn || expirationInvalid || mutation.isPending}>{mutation.isPending && <LoaderCircle className="animate-spin" />}{message(locale, "qualification.saveVersion")}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  </section>;
}

function revisionKey(qualificationId: string, version: number): string {
  return `${qualificationId}:${version}`;
}
