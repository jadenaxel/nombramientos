"use client";

import { useState, type ReactNode } from "react";
import { CheckCircle2, Fingerprint, LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck, Smartphone } from "lucide-react";
import { exportTenantDevicePublicKey, toCustodianPublicKey } from "@nombramientos/e2ee";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { type AuthenticatedSession, type Locale } from "@/lib/api";
import { enrollDeviceSession } from "@/lib/device-session-client";
import { useDeviceSessionReadiness } from "@/lib/device-session-readiness";
import { ensureDeviceRegistration } from "@/lib/device-registration";
import { createLocalTenantDevice, keyLifecycleApi, localDevicePrivateKey, saveLocalTenantDevice } from "@/lib/key-lifecycle-client";
import { localizedApiError, message } from "@/lib/product-i18n";
import { KeyLifecycleView } from "./key-lifecycle-view";

/** Device keys remain local. Enrollment links this HTTP session without issuing
 * content-key grants, changing authority, enabling MFA, or replacing old keys. */
export function DeviceSessionBoundary({ session, locale, children, platformMode = false }: { session: AuthenticatedSession; locale: Locale; children: ReactNode; platformMode?: boolean }) {
  const realTenant = session.tenant.kind === "real" && !platformMode;
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const query = useDeviceSessionReadiness(session, platformMode);
  if (!realTenant) return children;
  if (query.workspaceReady) return children;
  if (query.data?.ready && query.data.state.binding && (query.data.state.binding.deviceStatus === "pending" || !query.data.state.binding.hasActiveGrant)) return <div className="space-y-6">
    <Alert className="border-amber-300 bg-amber-50"><ShieldAlert /><AlertTitle className="line-clamp-none whitespace-normal leading-6">{message(locale, "deviceSession.pendingTitle")}</AlertTitle><AlertDescription><p>{message(locale, session.permissions.includes("recovery.activate") ? "deviceSession.pendingManagerHelp" : "deviceSession.pendingMemberHelp")}</p><Button type="button" className="mt-3" variant="outline" onClick={() => void query.refetch()}><RefreshCw />{message(locale, "common.refresh")}</Button></AlertDescription></Alert>
    {session.permissions.includes("recovery.activate") && <KeyLifecycleView session={session} locale={locale} pendingDeviceOnly />}
  </div>;

  async function verify(deviceId?: string) {
    setBusy(true); setError(undefined);
    try {
      let device = query.data?.devices.find((item) => item.deviceId === deviceId);
      if (!device) {
        const created = await createLocalTenantDevice({ tenantId: session.tenant.id, identityId: session.user.id, label: label.trim() });
        device = created.device;
        await saveLocalTenantDevice(device);
      }
      const savedDevice = device;
      await ensureDeviceRegistration(savedDevice, { state: keyLifecycleApi.state,
        register: async () => keyLifecycleApi.mutate("device.register", { deviceId: savedDevice.deviceId, label: savedDevice.label,
          wrappingPublicKey: await exportTenantDevicePublicKey(toCustodianPublicKey(localDevicePrivateKey(savedDevice))) }) });
      await enrollDeviceSession(session, device, true);
      await query.refetch();
    } catch (caught) {
      setError(caught);
      // Reload locally saved keys even after an uncertain registration response.
      // The next deliberate attempt reconciles this exact device, never a new key.
      await query.refetch();
    }
    finally { setBusy(false); }
  }
  const state = query.data?.state;
  const existing = query.data?.devices.filter((device) => !state?.binding || device.deviceId === state.binding.deviceId) ?? [];
  return <section className="surface-card mx-auto max-w-3xl space-y-5 border-teal-200" aria-labelledby="device-session-guide-title" data-testid="device-session-guide">
    <div className="flex items-start gap-4"><span className="form-icon shrink-0"><ShieldCheck /></span><div className="min-w-0"><p className="eyebrow">{message(locale, "deviceSession.eyebrow")}</p><h2 id="device-session-guide-title" className="mt-1 text-2xl font-semibold">{message(locale, "deviceSession.title")}</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">{message(locale, "deviceSession.description")}</p></div></div>
    {query.isPending ? <div className="flex items-center gap-3" role="status"><LoaderCircle className="animate-spin" /><p>{message(locale, "deviceSession.verifying")}</p></div> : <>
      <ol className="grid gap-3 sm:grid-cols-3" aria-label={message(locale, "deviceSession.steps")}>
        {["identity", "browser", "custody"].map((step, index) => <li key={step} className="rounded-xl border bg-muted/25 p-4"><span className="text-sm font-semibold text-teal-900">{index + 1}. {message(locale, `deviceSession.step.${step}` as "deviceSession.step.identity")}</span><p className="mt-2 text-sm leading-5 text-muted-foreground">{message(locale, `deviceSession.step.${step}Help` as "deviceSession.step.identityHelp")}</p></li>)}
      </ol>
      {error || query.error ? <Alert variant="destructive"><ShieldAlert /><AlertTitle>{message(locale, "deviceSession.failed")}</AlertTitle><AlertDescription><p>{localizedApiError(error ?? query.error, locale, "deviceSession.failedHelp")}</p><Button type="button" className="mt-3" variant="outline" disabled={busy} onClick={() => { setError(undefined); void query.refetch(); }}><RefreshCw />{message(locale, "common.refresh")}</Button></AlertDescription></Alert> : null}
      {!query.error && <div className="space-y-3">
        {existing.length ? <><p className="text-sm text-muted-foreground">{message(locale, "deviceSession.existingHelp")}</p>{existing.map((device) => <Button key={device.deviceId} type="button" className="h-auto min-h-12 w-full justify-start whitespace-normal py-3 text-left sm:w-auto" disabled={busy} onClick={() => void verify(device.deviceId)}>{busy ? <LoaderCircle className="shrink-0 animate-spin" /> : <Fingerprint className="shrink-0" />}{message(locale, "deviceSession.verifyExisting", { label: device.label })}</Button>)}</> : state?.binding ? <Alert><ShieldAlert /><AlertTitle>{message(locale, "deviceSession.keyMissing")}</AlertTitle><AlertDescription>{message(locale, "deviceSession.recoveryHelp")}</AlertDescription></Alert> : <div className="grid items-end gap-3 sm:grid-cols-[1fr_auto]"><div><Label htmlFor="guided-device-label">{message(locale, "deviceSession.label")}</Label><Input id="guided-device-label" value={label} maxLength={80} placeholder={message(locale, "deviceSession.labelExample")} onChange={(event) => setLabel(event.target.value)} /></div><Button type="button" disabled={busy || !label.trim()} onClick={() => void verify()}>{busy ? <LoaderCircle className="animate-spin" /> : <Smartphone />}{message(locale, "deviceSession.register")}</Button></div>}
      </div>}
      <div className="flex items-start gap-2 rounded-xl border border-teal-200 bg-teal-50 p-4 text-sm leading-6 text-teal-950"><CheckCircle2 className="mt-1 shrink-0" size={18} /><p>{message(locale, "deviceSession.preserve")}</p></div>
      <p className="text-sm leading-6 text-muted-foreground">{message(locale, "deviceSession.recoveryHelp")}</p>
    </>}
  </section>;
}
