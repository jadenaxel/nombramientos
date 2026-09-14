"use client";

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Clipboard, Clock3, KeyRound, LoaderCircle, MailPlus, ShieldAlert, UserRoundCheck, X } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiRequest, idempotencyKey, type AuthenticatedSession, type Locale } from "@/lib/api";
import { message, localizedApiError } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";
import { DataError, EmptyState, LoadingBlock, PageTitle } from "./workspace-view";

const invitationRoles = [
  ["CHURCH_ADMIN", { es: message("es", "screen.invitationsView.70a38310db80"), en: message("en", "screen.invitationsView.70a38310db80"), fr: message("fr", "screen.invitationsView.70a38310db80") }],
  ["COMMITTEE_CHAIR", { es: message("es", "screen.invitationsView.3d6bff8d63ec"), en: message("en", "screen.invitationsView.3d6bff8d63ec"), fr: message("fr", "screen.invitationsView.3d6bff8d63ec") }],
  ["COMMITTEE_SECRETARY", { es: message("es", "screen.invitationsView.93b7f4753c6e"), en: message("en", "screen.invitationsView.93b7f4753c6e"), fr: message("fr", "screen.invitationsView.93b7f4753c6e") }],
  ["COMMITTEE_MEMBER", { es: message("es", "screen.invitationsView.f31b481e5c0c"), en: message("en", "screen.invitationsView.f31b481e5c0c"), fr: message("fr", "screen.invitationsView.f31b481e5c0c") }],
  ["TALLY_CUSTODIAN", { es: message("es", "screen.invitationsView.10b5a84d4c6a"), en: message("en", "screen.invitationsView.10b5a84d4c6a"), fr: message("fr", "screen.invitationsView.10b5a84d4c6a") }],
  ["AUDITOR", { es: message("es", "screen.invitationsView.626602d3387b"), en: message("en", "screen.invitationsView.626602d3387b"), fr: message("fr", "screen.invitationsView.626602d3387b") }],
] as const;

type InvitationRole = (typeof invitationRoles)[number][0];
const mfaRequiredRoles = new Set<InvitationRole>([
  "CHURCH_ADMIN", "COMMITTEE_CHAIR", "COMMITTEE_SECRETARY", "TALLY_CUSTODIAN",
]);
type InvitationStatus = "pending" | "accepting" | "accepted" | "revoked" | "expired" | "failed";
type Invitation = {
  id: string;
  tenantId: string;
  email: string;
  roles: InvitationRole[];
  status: InvitationStatus;
  expiresAt: string;
  createdAt: string;
  acceptedAt: string | null;
  revokedAt: string | null;
  version: number;
};
type Creation = {
  invitation: Invitation;
  delivery: "local_one_time_token" | "token_already_issued";
  acceptanceToken?: string;
  created: boolean;
};

const copy = {
  es: {
    title: message("es", "screen.invitationsView.99e7b34e8f97"), description: message("es", "screen.invitationsView.82552382ba73"),
    create: message("es", "screen.invitationsView.a45050f1335b"), email: message("es", "screen.invitationsView.7e148d1828ad"), expires: message("es", "screen.invitationsView.28dec6fcfbca"), roles: message("es", "screen.invitationsView.239a10a716f2"),
    hours: message("es", "screen.invitationsView.db98a775be8f"), submit: message("es", "screen.invitationsView.f48a4f0d4d8a"), recent: message("es", "screen.invitationsView.f633c22acefb"), none: message("es", "screen.invitationsView.8563ab263069"),
    tokenTitle: message("es", "screen.invitationsView.539b80f78437"), tokenHelp: message("es", "screen.invitationsView.471d3ab8c724"),
    copy: message("es", "screen.invitationsView.bf024dbcaa05"), copied: message("es", "screen.invitationsView.2b46f63d1ecb"), copyFailed: message("es", "screen.invitationsView.32e121d3c47b"), dismiss: message("es", "screen.invitationsView.78d00decc3f8"), revoke: message("es", "screen.invitationsView.dd1d879556c8"), genericError: message("es", "screen.invitationsView.646024a0aeef"),
    mfaRequired: message("es", "screen.invitationsView.fddcc98b68f8"), leastPrivilege: message("es", "screen.invitationsView.2795525a82f5"), tokenEyebrow: message("es", "screen.invitationsView.ec9e29870764"), auditEyebrow: message("es", "screen.invitationsView.90dd60fd5cfb"),
  },
  en: {
    title: message("en", "screen.invitationsView.99e7b34e8f97"), description: message("en", "screen.invitationsView.82552382ba73"),
    create: message("en", "screen.invitationsView.a45050f1335b"), email: message("en", "screen.invitationsView.7e148d1828ad"), expires: message("en", "screen.invitationsView.28dec6fcfbca"), roles: message("en", "screen.invitationsView.239a10a716f2"),
    hours: message("en", "screen.invitationsView.db98a775be8f"), submit: message("en", "screen.invitationsView.f48a4f0d4d8a"), recent: message("en", "screen.invitationsView.f633c22acefb"), none: message("en", "screen.invitationsView.8563ab263069"),
    tokenTitle: message("en", "screen.invitationsView.539b80f78437"), tokenHelp: message("en", "screen.invitationsView.471d3ab8c724"),
    copy: message("en", "screen.invitationsView.bf024dbcaa05"), copied: message("en", "screen.invitationsView.2b46f63d1ecb"), copyFailed: message("en", "screen.invitationsView.32e121d3c47b"), dismiss: message("en", "screen.invitationsView.78d00decc3f8"), revoke: message("en", "screen.invitationsView.dd1d879556c8"), genericError: message("en", "screen.invitationsView.646024a0aeef"),
    mfaRequired: message("en", "screen.invitationsView.fddcc98b68f8"), leastPrivilege: message("en", "screen.invitationsView.2795525a82f5"), tokenEyebrow: message("en", "screen.invitationsView.ec9e29870764"), auditEyebrow: message("en", "screen.invitationsView.90dd60fd5cfb"),
  },
  fr: {
    title: message("fr", "screen.invitationsView.99e7b34e8f97"), description: message("fr", "screen.invitationsView.82552382ba73"),
    create: message("fr", "screen.invitationsView.a45050f1335b"), email: message("fr", "screen.invitationsView.7e148d1828ad"), expires: message("fr", "screen.invitationsView.28dec6fcfbca"), roles: message("fr", "screen.invitationsView.239a10a716f2"),
    hours: message("fr", "screen.invitationsView.db98a775be8f"), submit: message("fr", "screen.invitationsView.f48a4f0d4d8a"), recent: message("fr", "screen.invitationsView.f633c22acefb"), none: message("fr", "screen.invitationsView.8563ab263069"),
    tokenTitle: message("fr", "screen.invitationsView.539b80f78437"), tokenHelp: message("fr", "screen.invitationsView.471d3ab8c724"),
    copy: message("fr", "screen.invitationsView.bf024dbcaa05"), copied: message("fr", "screen.invitationsView.2b46f63d1ecb"), copyFailed: message("fr", "screen.invitationsView.32e121d3c47b"), dismiss: message("fr", "screen.invitationsView.78d00decc3f8"), revoke: message("fr", "screen.invitationsView.dd1d879556c8"), genericError: message("fr", "screen.invitationsView.646024a0aeef"),
    mfaRequired: message("fr", "screen.invitationsView.fddcc98b68f8"), leastPrivilege: message("fr", "screen.invitationsView.2795525a82f5"), tokenEyebrow: message("fr", "screen.invitationsView.ec9e29870764"), auditEyebrow: message("fr", "screen.invitationsView.90dd60fd5cfb"),
  },
} as const;

const statusCopy: Record<Locale, Record<InvitationStatus, string>> = {
  es: { pending: message("es", "screen.invitationsView.1e4142a7f2f5"), accepting: message("es", "screen.invitationsView.997b61c12d9d"), accepted: message("es", "screen.invitationsView.97e892578441"), revoked: message("es", "screen.invitationsView.f59166b506f3"), expired: message("es", "screen.invitationsView.1264ed4b88e0"), failed: message("es", "screen.invitationsView.4196f3ca62b8") },
  en: { pending: message("en", "screen.invitationsView.1e4142a7f2f5"), accepting: message("en", "screen.invitationsView.997b61c12d9d"), accepted: message("en", "screen.invitationsView.97e892578441"), revoked: message("en", "screen.invitationsView.f59166b506f3"), expired: message("en", "screen.invitationsView.1264ed4b88e0"), failed: message("en", "screen.invitationsView.4196f3ca62b8") },
  fr: { pending: message("fr", "screen.invitationsView.1e4142a7f2f5"), accepting: message("fr", "screen.invitationsView.997b61c12d9d"), accepted: message("fr", "screen.invitationsView.97e892578441"), revoked: message("fr", "screen.invitationsView.f59166b506f3"), expired: message("fr", "screen.invitationsView.1264ed4b88e0"), failed: message("fr", "screen.invitationsView.4196f3ca62b8") },
};

export function InvitationsView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const text = copy[locale];
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [expiresInHours, setExpiresInHours] = useState(48);
  const [roles, setRoles] = useState<InvitationRole[]>([]);
  const [oneTime, setOneTime] = useState<{ token: string; email: string; expiresAt: string }>();
  const [copied, setCopied] = useState(false);
  const [clipboardError, setClipboardError] = useState<string>();

  useEffect(() => {
    const purge = () => {
      setOneTime(undefined);
      setCopied(false);
      setClipboardError(undefined);
    };
    window.addEventListener("pagehide", purge);
    return () => window.removeEventListener("pagehide", purge);
  }, []);

  useEffect(() => {
    if (!oneTime) return;
    const remaining = Date.parse(oneTime.expiresAt) - Date.now();
    const timer = window.setTimeout(() => {
      setOneTime(undefined);
      setCopied(false);
      setClipboardError(undefined);
    }, Number.isFinite(remaining) ? Math.max(0, Math.min(remaining, 2_147_483_647)) : 0);
    return () => window.clearTimeout(timer);
  }, [oneTime]);

  async function copyToken() {
    if (!oneTime) return;
    setClipboardError(undefined);
    try {
      const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname);
      const invitationOrigin = loopback ? `${window.location.protocol}//localhost:3000` : window.location.origin;
      const invitationUrl = new URL(`/${locale}/auth/invitation`, invitationOrigin).toString();
      await navigator.clipboard.writeText(`${invitationUrl}\n${oneTime.token}`);
      setCopied(true);
    } catch {
      setCopied(false);
      setClipboardError(text.copyFailed);
    }
  }

  const query = useQuery({
    queryKey: ["invitations", session.tenant.id],
    queryFn: () => apiRequest<{ items: Invitation[] }>("/v1/invitations?limit=100"),
  });
  const roleNames = useMemo(() => new Map(invitationRoles.map(([code, labels]) => [code, labels[locale]])), [locale]);
  const create = useMutation({
    mutationFn: (input: { email: string; roles: InvitationRole[]; expiresInHours: number; key: string }) =>
      apiRequest<Creation>("/v1/invitations", {
        method: "POST",
        body: JSON.stringify({ email: input.email, roles: input.roles, expiresInHours: input.expiresInHours }),
        idempotent: true,
        idempotencyKey: input.key,
      }),
    onSuccess: async (result) => {
      setEmail("");
      setRoles([]);
      if (result.acceptanceToken) {
        setCopied(false); setClipboardError(undefined);
        setOneTime({ token: result.acceptanceToken, email: result.invitation.email, expiresAt: result.invitation.expiresAt });
      }
      await queryClient.invalidateQueries({ queryKey: ["invitations", session.tenant.id] });
    },
  });
  const revoke = useMutation({
    mutationFn: (invitationId: string) => apiRequest<Invitation>(`/v1/invitations/${encodeURIComponent(invitationId)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reasonCode: "ADMIN_ACCESS_REVOCATION" }),
    }),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ["invitations", session.tenant.id] }),
  });

  const toggleRole = (role: InvitationRole, checked: boolean) => {
    setRoles((current) => checked ? (current.includes(role) || current.length >= 3 ? current : [...current, role]) : current.filter((item) => item !== role));
  };
  const error = create.error ?? revoke.error;

  return <>
    <PageTitle eyebrow={text.leastPrivilege} title={text.title} description={text.description} />
    {oneTime && <Alert className="one-time-token" role="status"><KeyRound /><AlertTitle>{text.tokenTitle}</AlertTitle><AlertDescription>
      <p>{text.tokenHelp}</p><strong>{oneTime.email}</strong>
      <div className="token-copy"><code>{oneTime.token}</code><Button type="button" variant="outline" onClick={() => void copyToken()}>{copied ? <Check /> : <Clipboard />}{copied ? text.copied : text.copy}</Button></div>
      {clipboardError && <p role="alert" className="text-sm text-destructive">{clipboardError}</p>}
      <Button type="button" variant="ghost" onClick={() => { setOneTime(undefined); setCopied(false); setClipboardError(undefined); }}>{text.dismiss}<X /></Button>
    </AlertDescription></Alert>}
    {error && <Alert variant="destructive"><ShieldAlert /><AlertTitle>{text.genericError}</AlertTitle><AlertDescription>{localizedApiError(error, locale)}</AlertDescription></Alert>}
    <div className="access-grid">
      <section className="surface-card invitation-builder"><div className="card-heading"><div><p className="eyebrow">{text.tokenEyebrow}</p><h2>{text.create}</h2></div><MailPlus /></div>
        <form onSubmit={(event) => { event.preventDefault(); if (roles.length < 1) return; create.mutate({ email: email.trim(), roles, expiresInHours, key: idempotencyKey() }); }} className="invitation-form">
          <div className="field-stack"><Label htmlFor="invitation-email">{text.email}</Label><Input id="invitation-email" type="email" autoComplete="off" value={email} onChange={(event) => setEmail(event.target.value)} maxLength={320} required /></div>
          <div className="field-stack"><Label htmlFor="invitation-expiry">{text.expires}</Label><select id="invitation-expiry" value={expiresInHours} onChange={(event) => setExpiresInHours(Number(event.target.value))}>{[12,24,48,72,168].map((hours) => <option key={hours} value={hours}>{hours} {text.hours}</option>)}</select></div>
          <fieldset><legend>{text.roles}</legend><div className="role-picker">{invitationRoles.map(([role, labels]) => <label key={role} className={roles.includes(role) ? "selected" : undefined}><Checkbox checked={roles.includes(role)} disabled={!roles.includes(role) && roles.length >= 3} onCheckedChange={(value) => toggleRole(role, value === true)} /><span><strong>{labels[locale]}</strong><small>{role}{mfaRequiredRoles.has(role) ? ` · ${text.mfaRequired}` : ""}</small></span></label>)}</div></fieldset>
          <Button type="submit" disabled={create.isPending || roles.length === 0}>{create.isPending ? <LoaderCircle className="animate-spin" /> : <UserRoundCheck />}{text.submit}</Button>
        </form>
      </section>
      <section className="surface-card invitation-history"><div className="card-heading"><div><p className="eyebrow">{text.auditEyebrow}</p><h2>{text.recent}</h2></div><Badge variant="outline">{query.data?.items.length ?? 0}</Badge></div>
        {query.isLoading ? <LoadingBlock locale={locale} /> : !query.data ? <DataError locale={locale} /> : query.data.items.length === 0 ? <EmptyState locale={locale} icon={MailPlus} title={text.none} /> : <div className="invitation-list">{query.data.items.map((invitation) => <article key={invitation.id}>
          <span className={`invitation-status status-${invitation.status}`}><Clock3 /></span><div><strong>{invitation.email}</strong><small>{invitation.roles.map((role) => roleNames.get(role) ?? role).join(" · ")}</small><small>{formatInTenantTimeZone(invitation.expiresAt, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" })}</small></div><div><Badge variant={invitation.status === "pending" ? "default" : "outline"}>{statusCopy[locale][invitation.status]}</Badge>{["pending","accepting","failed"].includes(invitation.status) && <Button type="button" size="sm" variant="ghost" disabled={revoke.isPending} onClick={() => revoke.mutate(invitation.id)}>{text.revoke}</Button>}</div>
        </article>)}</div>}
      </section>
    </div>
  </>;
}
