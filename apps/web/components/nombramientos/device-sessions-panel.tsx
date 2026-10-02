"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, LoaderCircle, LogOut, RefreshCw, ShieldAlert, Smartphone } from "lucide-react";
import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, type AuthenticatedSession, type AuthSessionSummary, type Locale } from "@/lib/api";
import { clearDeviceSigner } from "@/lib/device-session-proof";
import { SESSION_INVALID_EVENT } from "@/lib/gestionchurch-session";
import { localizedApiError, message } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";

export function DeviceSessionsPanel({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  const vault = useVault();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<unknown>();
  const [saved, setSaved] = useState(false);
  const query = useQuery({ queryKey: ["device-auth-sessions", session.tenant.id, session.user.id], queryFn: api.authSessions, retry: false,
    refetchOnWindowFocus: true, refetchInterval: 30_000 });
  async function close(target?: AuthSessionSummary) {
    setBusy(target?.id ?? "others"); setError(undefined); setSaved(false);
    try {
      if (target) await api.revokeAuthSession(target.id);
      else await api.revokeOtherAuthSessions();
      if (target?.current) {
        vault.lock(); clearDeviceSigner();
        window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
      } else { setSaved(true); await query.refetch(); }
    } catch (caught) { setError(caught); }
    finally { setBusy(undefined); }
  }
  const date = (value: string) => formatInTenantTimeZone(value, locale, session.tenant.timezone, { dateStyle: "medium", timeStyle: "short" });
  const activeSessions = query.data?.filter((item) => !item.revokedAt) ?? [];
  return <section className="surface-card space-y-5" aria-labelledby="device-sessions-title" data-testid="device-sessions-panel">
    <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start"><div><p className="eyebrow">{message(locale, "deviceSession.sessionsEyebrow")}</p><h2 id="device-sessions-title" className="mt-1 text-xl font-semibold">{message(locale, "deviceSession.sessionsTitle")}</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">{message(locale, "deviceSession.sessionsHelp")}</p></div><Button type="button" variant="outline" className="session-refresh-control shrink-0 whitespace-nowrap" disabled={Boolean(busy)} onClick={() => void query.refetch()}><RefreshCw />{message(locale, "common.refresh")}</Button></div>
    {saved && <p role="status" className="flex items-center gap-2 text-sm font-medium text-emerald-800"><CheckCircle2 size={18} />{message(locale, "deviceSession.sessionClosed")}</p>}
    {(error || query.error) && <Alert variant="destructive"><ShieldAlert /><AlertTitle>{message(locale, "deviceSession.failed")}</AlertTitle><AlertDescription>{localizedApiError(error ?? query.error, locale)}</AlertDescription></Alert>}
    {query.isPending ? <p role="status" className="flex items-center gap-2 text-sm"><LoaderCircle className="animate-spin" />{message(locale, "deviceSession.verifying")}</p> : !query.error && <>
      <div className="max-h-[28rem] space-y-3 overflow-y-auto overscroll-contain pr-1" tabIndex={activeSessions.length > 3 ? 0 : undefined} aria-label={message(locale, "deviceSession.sessionsTitle")}>
        {activeSessions.map((item) => <article key={item.id} data-session-id={item.id} className="flex flex-col justify-between gap-4 rounded-xl border p-4 sm:flex-row sm:items-center"><div className="flex min-w-0 items-start gap-3"><Smartphone className="mt-1 shrink-0 text-primary" size={22} /><div className="min-w-0 space-y-1"><strong className="block break-words">{item.deviceLabel || message(locale, "deviceSession.unknownBrowser")}</strong><Badge variant="outline">{message(locale, item.current ? "deviceSession.current" : "deviceSession.other")}</Badge><p className="text-sm text-muted-foreground">{message(locale, "deviceSession.lastSeen")}: {date(item.lastSeenAt)}</p><p className="text-sm text-muted-foreground">{message(locale, "deviceSession.expires")}: {date(item.expiresAt)}</p></div></div><CloseConfirmation locale={locale} busy={Boolean(busy)} onConfirm={() => void close(item)} label={message(locale, "deviceSession.closeSession")} /></article>)}
        {!activeSessions.length && <p className="text-sm text-muted-foreground">{message(locale, "deviceSession.noSessions")}</p>}
      </div>
      {activeSessions.some((item) => !item.current) && <CloseConfirmation locale={locale} busy={Boolean(busy)} onConfirm={() => void close()} label={message(locale, "deviceSession.closeOthers")} />}
    </>}
    <p className="text-sm leading-6 text-muted-foreground">{message(locale, "deviceSession.revocationScope")}</p>
  </section>;
}
function CloseConfirmation({ locale, busy, onConfirm, label }: { locale: Locale; busy: boolean; onConfirm: () => void; label: string }) {
  return <AlertDialog><AlertDialogTrigger asChild><Button type="button" variant="outline" disabled={busy}><LogOut />{label}</Button></AlertDialogTrigger><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{label}</AlertDialogTitle><AlertDialogDescription>{message(locale, "deviceSession.closeConfirm")}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{message(locale, "common.cancel")}</AlertDialogCancel><AlertDialogAction onClick={onConfirm}>{message(locale, "deviceSession.confirmClose")}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>;
}
