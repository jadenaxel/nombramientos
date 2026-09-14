"use client";

import { message } from "@/lib/product-i18n";

import {
  createEncryptedTenantKeyRecoveryBackup,
  createTenantKeyGrantEnvelope,
  createTenantKeyRecoveryContext,
  exportTenantDevicePublicKey,
  generateTenantContentKey,
  importCustodianPublicKey,
  openEncryptedTenantKeyRecoveryBackup,
  openTenantKeyGrantEnvelope,
  signTenantKeyRecovery,
  toCustodianPublicKey,
  type EncryptedTenantKeyRecoveryBackup,
  type ExportedCustodianSigningPublicKey,
  type TenantKeyGrantEnvelope,
} from "@nombramientos/e2ee";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArchiveRestore, CheckCircle2, Download, Fingerprint, HardDrive, KeyRound, LoaderCircle,
  LockKeyhole, RefreshCw, RotateCcw, ShieldAlert, ShieldCheck, Smartphone, Trash2, UserCheck,
} from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError, setCsrfToken, type AuthenticatedSession, type Locale } from "@/lib/api";
import {
  createLocalTenantDevice,
  fingerprintConfirmation,
  formatFingerprint,
  keyLifecycleApi,
  listLocalTenantDevices,
  localDevicePrivateKey,
  saveLocalTenantDevice,
  type KeyLifecycleDevice,
  type KeyLifecycleGrant,
  type LocalTenantDevice,
} from "@/lib/key-lifecycle-client";
import {
  delegateHistoricalTenantKeys,
  type HistoricalDelegationResult,
} from "@/lib/historical-key-delegation";
import {
  canUnlockTenantGrant,
  unlockTenantGrantForVault,
} from "@/lib/key-lifecycle-unlock-policy";
import { formatInTenantTimeZone } from "@/lib/tenant-time";

type Notice = {
  kind: "success" | "error" | "warning";
  text: string;
  reauthenticate?: "mfa" | "session";
};
type KeyDraft = {
  tenantKey: Uint8Array<ArrayBuffer>;
  tenantKeyId: string;
  backup: EncryptedTenantKeyRecoveryBackup;
};
type BootstrapDraft = KeyDraft & {
  deviceId: string;
  envelope: TenantKeyGrantEnvelope;
  recoveryPublicKey: ExportedCustodianSigningPublicKey;
};
type RotationDraft = KeyDraft & {
  request: {
    expectedTenantKeyId: string;
    expectedGeneration: number;
    newTenantKeyId: string;
    reasonCode: string;
    recoveryPublicKey: ExportedCustodianSigningPublicKey;
    grants: Array<{ targetIdentityId: string; targetDeviceId: string; envelope: TenantKeyGrantEnvelope }>;
  };
};

const revokeReasonCodes = ["DEVICE_RETIRED", "DEVICE_REPLACED", "ACCESS_REMOVED", "SECURITY_RESPONSE"] as const;
const rotationReasonCodes = ["SCHEDULED_ROTATION", "DEVICE_ROSTER_CHANGED", "SECURITY_RESPONSE", "RECOVERY_REKEY"] as const;
const lossReasonCodes = ["RECOVERY_MATERIAL_UNAVAILABLE", "AUTHORIZED_DEVICES_UNAVAILABLE", "VERIFIED_RECOVERY_FAILURE"] as const;

function reasonCodeLabel(locale: Locale, reasonCode: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    DEVICE_RETIRED: "screen.keyLifecycleView.699677f5e7b3",
    DEVICE_REPLACED: "screen.keyLifecycleView.f621c293757c",
    ACCESS_REMOVED: "screen.keyLifecycleView.707ca339e1f4",
    SECURITY_RESPONSE: "screen.keyLifecycleView.efeb73c2bb1e",
    SCHEDULED_ROTATION: "screen.keyLifecycleView.e40bc298455c",
    DEVICE_ROSTER_CHANGED: "screen.keyLifecycleView.ad89641450f9",
    RECOVERY_REKEY: "screen.keyLifecycleView.55ae6844aae8",
    RECOVERY_MATERIAL_UNAVAILABLE: "screen.keyLifecycleView.f772abe152bb",
    AUTHORIZED_DEVICES_UNAVAILABLE: "screen.keyLifecycleView.1cd34e8c0fdf",
    VERIFIED_RECOVERY_FAILURE: "screen.keyLifecycleView.7ef731e73f0e",
  };
  return labels[reasonCode] ? message(locale, labels[reasonCode]!) : reasonCode;
}

function statusLabel(locale: Locale, status: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    pending: "screen.keyLifecycleView.1e4142a7f2f5",
    active: "screen.keyLifecycleView.901bb448bee7",
    retired: "screen.keyLifecycleView.6af7948d7da3",
    revoked: "screen.keyLifecycleView.06470aaf780a",
    lost: "screen.keyLifecycleView.5a1527c7cbfb",
    initial: "screen.keyLifecycleView.eaa7f5d22a5f",
    admin_approved: "screen.keyLifecycleView.b17ab9edb900",
    rotation: "screen.keyLifecycleView.589ff62847aa",
    recovery: "screen.keyLifecycleView.3d60122d991d",
  };
  const value = labels[status];
  return value ? message(locale, value) : status;
}

function localizedError(locale: Locale, error: unknown): Notice {
  const code = error instanceof ApiError ? error.code : "CLIENT_CRYPTO_ERROR";
  if (["KEY_LIFECYCLE_STEP_UP_REQUIRED", "MFA_ASSURANCE_REQUIRED"].includes(code)) {
    return {
      kind: "warning",
      reauthenticate: "mfa",
      text: message(locale, "screen.keyLifecycleView.a828e2d3b633"),
    };
  }
  if (["AUTHENTICATION_REQUIRED", "UNAUTHORIZED", "CSRF_INVALID"].includes(code)) {
    return {
      kind: "warning",
      reauthenticate: "session",
      text: message(locale, "auth.sessionExpired"),
    };
  }
  if (["KEY_LIFECYCLE_CHALLENGE_INVALID", "CHALLENGE_EXPIRED", "CHALLENGE_ALREADY_USED", "CHALLENGE_NOT_PENDING"].includes(code)) {
    return { kind: "warning", text: message(locale, "screen.keyLifecycleView.8c3eec9ff8dd") };
  }
  if (["VERSION_CONFLICT", "KEY_STATE_CHANGED", "IDEMPOTENCY_CONFLICT"].includes(code)) {
    return { kind: "warning", text: message(locale, "screen.keyLifecycleView.996c4669cf38") };
  }
  if (code === "AUTHORIZED_ADMIN_GRANT_REQUIRED") {
    return { kind: "warning", text: message(locale, "screen.keyLifecycleView.7166cb89a0e0") };
  }
  if (["KEY_BACKUP_DECRYPTION_FAILED", "KEY_BACKUP_INVALID", "CLIENT_CRYPTO_ERROR"].includes(code)) {
    return { kind: "error", text: message(locale, "screen.keyLifecycleView.1a30809228ff") };
  }
  return { kind: "error", text: message(locale, "screen.keyLifecycleView.2f2832457f08") };
}

function friendlyDate(locale: Locale, timeZone: string, value: string): string {
  return formatInTenantTimeZone(value, locale, timeZone, { dateStyle: "medium", timeStyle: "short" });
}

function downloadBackup(tenantSlug: string, generation: number, backup: EncryptedTenantKeyRecoveryBackup): void {
  const blob = new Blob([JSON.stringify(backup)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `nombramientos-${tenantSlug}-e2ee-generation-${generation}.recovery.json`;
  anchor.rel = "noopener";
  anchor.click();
  URL.revokeObjectURL(url);
}

function useLocalDevices(session: AuthenticatedSession) {
  const { data, isError, refetch } = useQuery({
    queryKey: ["local-key-devices", session.tenant.id, session.user.id],
    queryFn: () => listLocalTenantDevices(session.tenant.id, session.user.id),
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const reload = useCallback(async () => {
    await refetch();
  }, [refetch]);
  return { devices: data ?? [], unavailable: isError, reload };
}

function NoticeBanner({ notice, locale, onReauthenticate }: { notice?: Notice; locale: Locale; onReauthenticate: () => void }) {
  if (!notice) return null;
  return <Alert className={notice.kind === "error" ? "border-destructive/40" : notice.kind === "success" ? "border-emerald-500/40" : "border-amber-500/40"}>
    {notice.kind === "success" ? <CheckCircle2 /> : <ShieldAlert />}
    <AlertTitle>{notice.kind === "success" ? message(locale, "screen.keyLifecycleView.7f1eaffefde5") : notice.kind === "warning" ? message(locale, "screen.keyLifecycleView.d25c65f35ea7") : message(locale, "screen.keyLifecycleView.f0e74136a9b6")}</AlertTitle>
    <AlertDescription className="space-y-3"><p>{notice.text}</p>{notice.reauthenticate && <Button type="button" size="sm" onClick={onReauthenticate}><LockKeyhole />{message(locale, notice.reauthenticate === "mfa" ? "screen.keyLifecycleView.39a53766f9a3" : "auth.reauthenticate")}</Button>}</AlertDescription>
  </Alert>;
}

export function TenantKeyUnlockPanel({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const local = useLocalDevices(session);
  const [notice, setNotice] = useState<Notice>();
  const [busy, setBusy] = useState(false);
  const stateQuery = useQuery({ queryKey: ["key-lifecycle", session.tenant.id], queryFn: keyLifecycleApi.state, retry: false });
  const state = stateQuery.data;
  const candidates = useMemo(() => state?.ownGrants
    .filter((grant) => grant.status === "active" && grant.tenantKeyId === state.currentGeneration?.tenantKeyId)
    .flatMap((grant) => {
      const device = local.devices.find((item) => item.deviceId === grant.deviceId);
      return device ? [{ grant, device }] : [];
    }) ?? [], [local.devices, state]);

  async function unlock(grant: KeyLifecycleGrant, device: LocalTenantDevice) {
    setBusy(true); setNotice(undefined);
    try {
      const opened = await openTenantKeyGrantEnvelope({
        envelope: grant.envelope,
        recipient: localDevicePrivateKey(device),
        expected: {
          tenantId: session.tenant.id,
          tenantKeyId: grant.tenantKeyId,
          generation: grant.generation,
          identityId: session.user.id,
          deviceId: device.deviceId,
        },
      });
      try {
        await vault.unlockRaw(opened.keyBytes, opened.tenantKeyId, session.tenant.id);
      } finally {
        opened.keyBytes.fill(0);
      }
      for (const historicalGrant of state?.ownGrants ?? []) {
        if (historicalGrant.status !== "retired" || historicalGrant.tenantKeyId === grant.tenantKeyId) continue;
        const historicalDevice = local.devices.find((item) => item.deviceId === historicalGrant.deviceId);
        if (!historicalDevice) continue;
        try {
          const historical = await openTenantKeyGrantEnvelope({
            envelope: historicalGrant.envelope,
            recipient: localDevicePrivateKey(historicalDevice),
            expected: {
              tenantId: session.tenant.id,
              tenantKeyId: historicalGrant.tenantKeyId,
              generation: historicalGrant.generation,
              identityId: session.user.id,
              deviceId: historicalDevice.deviceId,
            },
          });
          try {
            await vault.rememberRaw(
              historical.keyBytes,
              historical.tenantKeyId,
              session.tenant.id,
            );
          } finally {
            historical.keyBytes.fill(0);
          }
        } catch {
          // A damaged or unavailable historical grant must not block the
          // current generation. Consumers degrade that revision safely.
        }
      }
    } catch (error) {
      setNotice(localizedError(locale, error));
    } finally { setBusy(false); }
  }

  async function reauthenticate() {
    try { await api.logout(); } catch { /* local session teardown must still run */ }
    vault.lock();
    setCsrfToken(undefined);
    queryClient.clear();
    router.replace(`/${locale}/auth/sign-in`);
  }

  if (stateQuery.isError) return <Alert><ShieldAlert /><AlertTitle>{message(locale, "screen.keyLifecycleView.7cb656c7fd84")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.d800336df155")}</AlertDescription></Alert>;
  if (stateQuery.isLoading || !state) return <section className="unlock-card" role="status"><LoaderCircle className="animate-spin" /><p>{message(locale, "screen.keyLifecycleView.b86d98d1cb26")}</p></section>;
  if (state.generations.some((generation) => generation.status === "lost")) return <Alert className="border-destructive/50"><ShieldAlert /><AlertTitle>{message(locale, "screen.keyLifecycleView.d645f47c671f")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.470bd12f87da")}</AlertDescription></Alert>;
  if (!state.currentGeneration) return <Alert><KeyRound /><AlertTitle>{message(locale, "screen.keyLifecycleView.2085f19580c8")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.91b64b98eebe")}</AlertDescription></Alert>;
  return <section className="unlock-card">
    <span className="form-icon"><LockKeyhole /></span>
    <div><p className="eyebrow">{message(locale, "screen.keyLifecycleView.a52a4df7a08f")}</p><h2>{message(locale, "screen.keyLifecycleView.3adaa9efc2c9")}</h2><p>{message(locale, "screen.keyLifecycleView.4eff8da3c53f")}</p></div>
    <div className="space-y-3"><NoticeBanner notice={notice} locale={locale} onReauthenticate={() => void reauthenticate()} />{local.unavailable && <p role="alert" className="text-sm text-destructive">{message(locale, "screen.keyLifecycleView.345b764e4827")}</p>}{candidates.length ? candidates.map(({ grant, device }) => <Button key={grant.grantId} type="button" disabled={busy} onClick={() => void unlock(grant, device)}>{busy ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{message(locale, "screen.keyLifecycleView.190813b8a653", { value0: device.label })}</Button>) : <p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.01abab53d64f")}</p>}</div>
  </section>;
}

export function KeyLifecycleView({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const local = useLocalDevices(session);
  const [busy, setBusy] = useState<string>();
  const [notice, setNotice] = useState<Notice>();
  const [deviceLabel, setDeviceLabel] = useState("");
  const [bootstrapPassphrase, setBootstrapPassphrase] = useState("");
  const [bootstrapConfirm, setBootstrapConfirm] = useState("");
  const [bootstrapDraft, setBootstrapDraft] = useState<BootstrapDraft>();
  const [bootstrapDownloaded, setBootstrapDownloaded] = useState(false);
  const [approvalDeviceId, setApprovalDeviceId] = useState<string>();
  const [approvalCode, setApprovalCode] = useState("");
  const [historicalResult, setHistoricalResult] = useState<HistoricalDelegationResult>();
  const [revokeGrantId, setRevokeGrantId] = useState<string>();
  const [revokeCode, setRevokeCode] = useState("");
  const [revokeReasonCode, setRevokeReasonCode] = useState("");
  const [confirmLastGrant, setConfirmLastGrant] = useState(false);
  const [rotationReasonCode, setRotationReasonCode] = useState("");
  const [rotationPassphrase, setRotationPassphrase] = useState("");
  const [rotationConfirm, setRotationConfirm] = useState("");
  const [rotationDraft, setRotationDraft] = useState<RotationDraft>();
  const [rotationDownloaded, setRotationDownloaded] = useState(false);
  const [recoveryFile, setRecoveryFile] = useState<File>();
  const [recoveryPassphrase, setRecoveryPassphrase] = useState("");
  const [lossConfirmation, setLossConfirmation] = useState("");
  const [lossReasonCode, setLossReasonCode] = useState("");
  const recoveryInput = useRef<HTMLInputElement>(null);
  const canManage = session.permissions.includes("recovery.activate");
  const isRealTenant = session.tenant.kind === "real";
  const stateQuery = useQuery({
    queryKey: ["key-lifecycle", session.tenant.id],
    queryFn: keyLifecycleApi.state,
    retry: false,
    enabled: isRealTenant,
  });
  const state = stateQuery.data;
  const allGrants = state?.managedGrants ?? state?.ownGrants ?? [];
  const activeGrants = allGrants.filter((grant) => grant.status === "active" && grant.tenantKeyId === state?.currentGeneration?.tenantKeyId);
  const retiredGenerations = useMemo(
    () => state?.generations.filter((generation) => generation.status === "retired") ?? [],
    [state?.generations],
  );
  const historicalTargets = useMemo(() => {
    if (!state?.currentGeneration || !state.managedGrants || retiredGenerations.length === 0) return [];
    return state.devices.flatMap((device) => {
      if (device.status !== "active") return [];
      const hasCurrentGrant = state.managedGrants?.some((grant) =>
        grant.identityId === device.identityId
        && grant.deviceId === device.deviceId
        && grant.tenantKeyId === state.currentGeneration?.tenantKeyId
        && grant.status === "active");
      if (!hasCurrentGrant) return [];
      const coveredTenantKeyIds = retiredGenerations.flatMap((generation) =>
        state.managedGrants?.some((grant) =>
          grant.identityId === device.identityId
          && grant.deviceId === device.deviceId
          && grant.tenantKeyId === generation.tenantKeyId
          && grant.generation === generation.generation
          && grant.status === "retired") ? [generation.tenantKeyId] : []);
      return [{ device, coveredTenantKeyIds }];
    });
  }, [retiredGenerations, state]);
  const ownActivePairs = useMemo(() => state?.ownGrants.flatMap((grant) => {
    if (grant.status !== "active") return [];
    const device = local.devices.find((item) => item.deviceId === grant.deviceId);
    return device ? [{ grant, device }] : [];
  }) ?? [], [local.devices, state?.ownGrants]);

  useEffect(() => () => { bootstrapDraft?.tenantKey.fill(0); }, [bootstrapDraft?.tenantKey]);
  useEffect(() => () => { rotationDraft?.tenantKey.fill(0); }, [rotationDraft?.tenantKey]);

  async function refresh() {
    await Promise.all([stateQuery.refetch(), local.reload()]);
  }

  const run = useCallback(async (name: string, work: () => Promise<void>) => {
    setBusy(name); setNotice(undefined);
    try { await work(); }
    catch (error) { setNotice(localizedError(locale, error)); }
    finally { setBusy(undefined); }
  }, [locale]);

  async function reauthenticate() {
    try { await api.logout(); } catch { /* the local lock still applies */ }
    vault.lock(); setCsrfToken(undefined); queryClient.clear();
    router.replace(`/${locale}/auth/sign-in`);
  }

  async function registerDevice() {
    await run("register", async () => {
      const label = deviceLabel.trim();
      if (!label) throw new Error("CLIENT_CRYPTO_ERROR");
      let localDevice = local.devices.find((candidate) => !state?.devices.some(({ deviceId }) => deviceId === candidate.deviceId));
      if (!localDevice) {
        const created = await createLocalTenantDevice({ tenantId: session.tenant.id, identityId: session.user.id, label });
        localDevice = created.device;
        await saveLocalTenantDevice(localDevice);
      }
      const publicKey = await exportTenantDevicePublicKey(toCustodianPublicKey(localDevicePrivateKey(localDevice)));
      await keyLifecycleApi.mutate("device.register", { deviceId: localDevice.deviceId, label, wrappingPublicKey: publicKey });
      setDeviceLabel("");
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.ec1707894627") });
      await refresh();
    });
  }

  async function prepareBootstrap() {
    await run("prepare-bootstrap", async () => {
      if (bootstrapPassphrase !== bootstrapConfirm || bootstrapPassphrase.length < 16) throw new Error("CLIENT_CRYPTO_ERROR");
      const candidate = state?.devices.find((device) => device.identityId === session.user.id && device.status === "pending" && local.devices.some(({ deviceId }) => deviceId === device.deviceId));
      const localDevice = candidate && local.devices.find(({ deviceId }) => deviceId === candidate.deviceId);
      if (!candidate || !localDevice) throw new Error("CLIENT_CRYPTO_ERROR");
      const generated = generateTenantContentKey();
      try {
        const envelope = await createTenantKeyGrantEnvelope({
          tenantId: session.tenant.id, tenantKeyId: generated.tenantKeyId, generation: 1,
          identityId: session.user.id, deviceId: candidate.deviceId, tenantKey: generated.keyBytes,
          recipient: toCustodianPublicKey(localDevicePrivateKey(localDevice)),
        });
        const recovery = await createEncryptedTenantKeyRecoveryBackup({
          tenantId: session.tenant.id, tenantKeyId: generated.tenantKeyId, generation: 1,
          tenantKey: generated.keyBytes, passphrase: bootstrapPassphrase,
        });
        const verified = await openEncryptedTenantKeyRecoveryBackup(recovery.backup, bootstrapPassphrase);
        const verifiedOk = verified.tenantKeyId === generated.tenantKeyId
          && verified.tenantKey.every((byte, index) => byte === generated.keyBytes[index]);
        verified.tenantKey.fill(0);
        if (!verifiedOk) throw new Error("CLIENT_CRYPTO_ERROR");
        setBootstrapDraft({ tenantKey: generated.keyBytes, tenantKeyId: generated.tenantKeyId, deviceId: candidate.deviceId, envelope, recoveryPublicKey: recovery.recoveryPublicKey, backup: recovery.backup });
        setBootstrapDownloaded(false); setBootstrapPassphrase(""); setBootstrapConfirm("");
        setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.7c95a5803fa3") });
      } catch (error) { generated.keyBytes.fill(0); throw error; }
    });
  }

  async function initializeBootstrap() {
    if (!bootstrapDraft || !bootstrapDownloaded) return;
    await run("initialize", async () => {
      await keyLifecycleApi.mutate("grant.initialize", {
        deviceId: bootstrapDraft.deviceId,
        tenantKeyId: bootstrapDraft.tenantKeyId,
        envelope: bootstrapDraft.envelope,
        recoveryPublicKey: bootstrapDraft.recoveryPublicKey,
      });
      try {
        await vault.unlockRaw(bootstrapDraft.tenantKey, bootstrapDraft.tenantKeyId, session.tenant.id);
      } finally {
        bootstrapDraft.tenantKey.fill(0); setBootstrapDraft(undefined); setBootstrapDownloaded(false);
      }
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.0033164e57f3") });
      await refresh();
    });
  }

  async function unlockGrant(grant: KeyLifecycleGrant, device: LocalTenantDevice) {
    await run(`unlock-${grant.grantId}`, async () => {
      const opened = await openTenantKeyGrantEnvelope({ envelope: grant.envelope, recipient: localDevicePrivateKey(device), expected: {
        tenantId: session.tenant.id, tenantKeyId: grant.tenantKeyId, generation: grant.generation,
        identityId: session.user.id, deviceId: device.deviceId,
      } });
      try {
        await unlockTenantGrantForVault({
          grantStatus: grant.status,
          grantTenantKeyId: opened.tenantKeyId,
          currentTenantKeyId: state?.currentGeneration?.tenantKeyId,
          tenantId: session.tenant.id,
          vaultTenantId: vault.tenantId,
          vaultKeyId: vault.keyId,
          keyBytes: opened.keyBytes,
          unlockCurrent: vault.unlockRaw,
          rememberHistorical: vault.rememberRaw,
        });
      } finally {
        opened.keyBytes.fill(0);
      }
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.504855f60710", { value0: grant.generation }) });
    });
  }

  async function delegateHistory(target: KeyLifecycleDevice): Promise<HistoricalDelegationResult> {
    if (!state) throw new Error("CLIENT_CRYPTO_ERROR");
    return delegateHistoricalTenantKeys({
      tenantId: session.tenant.id,
      actorIdentityId: session.user.id,
      target,
      generations: state.generations,
      devices: state.devices,
      ownGrants: state.ownGrants,
      managedGrants: state.managedGrants ?? state.ownGrants,
      localDevices: local.devices,
      approve: (intent) => keyLifecycleApi.mutate("grant.approve", intent),
    });
  }

  function showHistoricalResult(result: HistoricalDelegationResult): void {
    setHistoricalResult(result);
    if (result.total === 0) {
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.809275d98769") });
    } else if (result.complete) {
      setNotice({
        kind: "success",
        text: message(locale, "screen.keyLifecycleView.75d33ca859c0", { value0: result.total }),
      });
    } else {
      const approvalFailed = result.generations.some(
        (generation) => generation.unavailableReason === "approval-failed",
      );
      setNotice({
        kind: "warning",
        text: message(locale, approvalFailed
          ? "screen.keyLifecycleView.8bb21d457c91"
          : "screen.keyLifecycleView.83a17a04f192", {
          value0: result.covered,
          value1: result.total,
        }),
      });
    }
  }

  async function approveDevice(target: KeyLifecycleDevice) {
    await run("approve", async () => {
      const generation = state?.currentGeneration;
      if (!generation || approvalCode.trim().toUpperCase() !== fingerprintConfirmation(target.wrappingKeyFingerprint)) throw new Error("CLIENT_CRYPTO_ERROR");
      const recipient = await importCustodianPublicKey(target.wrappingPublicKey);
      const envelope = await vault.withRawKey(session.tenant.id, (tenantKey) => createTenantKeyGrantEnvelope({
        tenantId: session.tenant.id, tenantKeyId: generation.tenantKeyId, generation: generation.generation,
        identityId: target.identityId, deviceId: target.deviceId, tenantKey, recipient,
      }));
      await keyLifecycleApi.mutate("grant.approve", {
        targetIdentityId: target.identityId, targetDeviceId: target.deviceId,
        tenantKeyId: generation.tenantKeyId, generation: generation.generation, envelope,
      });
      setApprovalDeviceId(undefined); setApprovalCode("");
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.809275d98769") });
      await refresh();
    });
  }

  async function completeHistoricalAccess(target: KeyLifecycleDevice) {
    await run(`history-${target.deviceId}`, async () => {
      if (
        target.status !== "active"
        || approvalCode.trim().toUpperCase() !== fingerprintConfirmation(target.wrappingKeyFingerprint)
      ) throw new Error("CLIENT_CRYPTO_ERROR");
      let result: HistoricalDelegationResult;
      try {
        result = await delegateHistory(target);
      } catch (error) {
        // A fatal authorization or key-state conflict means the server may now
        // be newer than this view. Reconcile without masking the original error.
        await refresh().catch(() => undefined);
        throw error;
      }
      setApprovalDeviceId(undefined); setApprovalCode("");
      showHistoricalResult(result);
      await refresh();
    });
  }

  async function revokeGrant(grant: KeyLifecycleGrant) {
    await run("revoke", async () => {
      const device = state?.devices.find(({ deviceId }) => deviceId === grant.deviceId);
      if (!device || revokeCode.trim().toUpperCase() !== fingerprintConfirmation(device.wrappingKeyFingerprint) || !revokeReasonCodes.includes(revokeReasonCode as (typeof revokeReasonCodes)[number])) throw new Error("CLIENT_CRYPTO_ERROR");
      const isLast = activeGrants.length === 1;
      if (isLast && !confirmLastGrant) throw new Error("CLIENT_CRYPTO_ERROR");
      await keyLifecycleApi.mutate("grant.revoke", { grantId: grant.grantId, expectedVersion: grant.version, reasonCode: revokeReasonCode, confirmLastActiveGrant: isLast && confirmLastGrant });
      if (grant.identityId === session.user.id && grant.tenantKeyId === vault.keyId) vault.lock();
      setRevokeGrantId(undefined); setRevokeCode(""); setRevokeReasonCode(""); setConfirmLastGrant(false);
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.751d695228d5") });
      await refresh();
    });
  }

  async function prepareRotation() {
    await run("prepare-rotation", async () => {
      const generation = state?.currentGeneration;
      const recipients = state?.devices.filter((device) => device.status === "active") ?? [];
      if (!generation || !recipients.length || rotationPassphrase !== rotationConfirm || rotationPassphrase.length < 16 || !rotationReasonCodes.includes(rotationReasonCode as (typeof rotationReasonCodes)[number])) throw new Error("CLIENT_CRYPTO_ERROR");
      const generated = generateTenantContentKey();
      try {
        const recovery = await createEncryptedTenantKeyRecoveryBackup({
          tenantId: session.tenant.id, tenantKeyId: generated.tenantKeyId, generation: generation.generation + 1,
          tenantKey: generated.keyBytes, passphrase: rotationPassphrase,
        });
        const verified = await openEncryptedTenantKeyRecoveryBackup(recovery.backup, rotationPassphrase);
        const verifiedOk = verified.tenantKeyId === generated.tenantKeyId && verified.tenantKey.every((byte, index) => byte === generated.keyBytes[index]);
        verified.tenantKey.fill(0);
        if (!verifiedOk) throw new Error("CLIENT_CRYPTO_ERROR");
        const grants = await Promise.all(recipients.map(async (device) => ({
          targetIdentityId: device.identityId,
          targetDeviceId: device.deviceId,
          envelope: await createTenantKeyGrantEnvelope({
            tenantId: session.tenant.id, tenantKeyId: generated.tenantKeyId, generation: generation.generation + 1,
            identityId: device.identityId, deviceId: device.deviceId, tenantKey: generated.keyBytes,
            recipient: await importCustodianPublicKey(device.wrappingPublicKey),
          }),
        })));
        setRotationDraft({
          tenantKey: generated.keyBytes, tenantKeyId: generated.tenantKeyId, backup: recovery.backup,
          request: { expectedTenantKeyId: generation.tenantKeyId, expectedGeneration: generation.generation, newTenantKeyId: generated.tenantKeyId, reasonCode: rotationReasonCode, recoveryPublicKey: recovery.recoveryPublicKey, grants },
        });
        setRotationDownloaded(false); setRotationPassphrase(""); setRotationConfirm("");
        setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.e8754cb1d838", { value0: grants.length }) });
      } catch (error) { generated.keyBytes.fill(0); throw error; }
    });
  }

  async function commitRotation() {
    if (!rotationDraft || !rotationDownloaded) return;
    await run("rotate", async () => {
      await keyLifecycleApi.mutate("key.rotate", rotationDraft.request);
      try {
        await vault.unlockRaw(rotationDraft.tenantKey, rotationDraft.tenantKeyId, session.tenant.id);
      } finally {
        rotationDraft.tenantKey.fill(0); setRotationDraft(undefined); setRotationDownloaded(false); setRotationReasonCode("");
      }
      setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.e52c625c26a6") });
      await refresh();
    });
  }

  async function recoverFromBackup() {
    await run("recover", async () => {
      if (!recoveryFile || recoveryFile.size > 1_000_000 || recoveryPassphrase.length < 16) throw new Error("CLIENT_CRYPTO_ERROR");
      const targetDevice = state?.devices.find((device) => device.identityId === session.user.id && device.status === "pending" && local.devices.some(({ deviceId }) => deviceId === device.deviceId));
      const localTarget = targetDevice && local.devices.find(({ deviceId }) => deviceId === targetDevice.deviceId);
      if (!targetDevice || !localTarget) throw new Error("CLIENT_CRYPTO_ERROR");
      let parsed: unknown;
      try { parsed = JSON.parse(await recoveryFile.text()) as unknown; } catch { throw new Error("CLIENT_CRYPTO_ERROR"); }
      const recovered = await openEncryptedTenantKeyRecoveryBackup(parsed, recoveryPassphrase);
      try {
        if (recovered.tenantId !== session.tenant.id || recovered.tenantKeyId !== state?.currentGeneration?.tenantKeyId || recovered.generation !== state.currentGeneration.generation) throw new Error("CLIENT_CRYPTO_ERROR");
        const envelope = await createTenantKeyGrantEnvelope({
          tenantId: session.tenant.id, tenantKeyId: recovered.tenantKeyId, generation: recovered.generation,
          identityId: session.user.id, deviceId: targetDevice.deviceId, tenantKey: recovered.tenantKey,
          recipient: toCustodianPublicKey(localDevicePrivateKey(localTarget)),
        });
        const context = createTenantKeyRecoveryContext({
          tenantId: session.tenant.id, tenantKeyId: recovered.tenantKeyId, generation: recovered.generation,
          recoveryNonce: crypto.randomUUID(), targetIdentityId: session.user.id, targetDeviceId: targetDevice.deviceId,
          targetDeviceFingerprint: targetDevice.wrappingKeyFingerprint, envelopeHash: envelope.envelopeHash,
        });
        const authorization = await signTenantKeyRecovery(recovered.recoverySigningKey, context);
        await keyLifecycleApi.mutate("key.recover", { tenantKeyId: recovered.tenantKeyId, targetIdentityId: session.user.id, targetDeviceId: targetDevice.deviceId, envelope, authorization });
        await vault.unlockRaw(recovered.tenantKey, recovered.tenantKeyId, session.tenant.id);
        setRecoveryFile(undefined); setRecoveryPassphrase(""); if (recoveryInput.current) recoveryInput.current.value = "";
        setNotice({ kind: "success", text: message(locale, "screen.keyLifecycleView.0896ba1505db") });
        await refresh();
      } finally { recovered.tenantKey.fill(0); }
    });
  }

  async function declarePermanentLoss() {
    await run("declare-loss", async () => {
      const generation = state?.currentGeneration;
      const phrase = message(locale, "screen.keyLifecycleView.e6008fcb272b");
      if (!generation || generation.activeGrantCount !== 0 || lossConfirmation.trim() !== phrase || !lossReasonCodes.includes(lossReasonCode as (typeof lossReasonCodes)[number])) throw new Error("CLIENT_CRYPTO_ERROR");
      await keyLifecycleApi.mutate("key.declare_lost", { tenantKeyId: generation.tenantKeyId, confirmation: "PERMANENTLY_LOSE_TENANT_KEY", reasonCode: lossReasonCode });
      vault.lock(); setLossConfirmation(""); setLossReasonCode("");
      setNotice({ kind: "warning", text: message(locale, "screen.keyLifecycleView.da267a47bfad") });
      await refresh();
    });
  }

  if (!isRealTenant) return <Alert><ShieldCheck /><AlertTitle>{message(locale, "screen.keyLifecycleView.cb06447d72bd")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.0c126e28efdb")}</AlertDescription></Alert>;
  if (stateQuery.isLoading) return <section className="surface-card" role="status"><LoaderCircle className="animate-spin" /><p>{message(locale, "screen.keyLifecycleView.3d73e3b9b062")}</p></section>;
  if (!state) return <Alert><ShieldAlert /><AlertTitle>{message(locale, "screen.keyLifecycleView.62f50a927ba0")}</AlertTitle><AlertDescription><p>{message(locale, "screen.keyLifecycleView.a82cec8c8773")}</p><Button className="mt-3" type="button" variant="outline" onClick={() => void stateQuery.refetch()}><RefreshCw />{message(locale, "screen.keyLifecycleView.fe0bfb5b9dec")}</Button></AlertDescription></Alert>;

  const latestLost = !state.currentGeneration && state.generations.find((generation) => generation.status === "lost");
  const pendingDevices = state.devices.filter((device) => device.status === "pending");
  const bootstrapDeviceAvailable = state.devices.some((device) => device.status === "pending" && device.identityId === session.user.id && local.devices.some(({ deviceId }) => deviceId === device.deviceId));
  const pendingRecoveryDeviceAvailable = bootstrapDeviceAvailable;
  const lossPhrase = message(locale, "screen.keyLifecycleView.e6008fcb272b");

  return <div className="space-y-6" data-testid="key-lifecycle-view">
    <section className="surface-card overflow-hidden">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="max-w-3xl"><p className="eyebrow">{message(locale, "screen.keyLifecycleView.4b83881936d7")}</p><h2 className="mt-2 text-2xl font-semibold">{message(locale, "screen.keyLifecycleView.a17e9db1c3f1")}</h2><p className="mt-2 text-muted-foreground">{message(locale, "screen.keyLifecycleView.91644ce3851a")}</p></div>
        <div className="flex flex-wrap gap-2"><Badge variant="outline"><ShieldCheck />{message(locale, "screen.keyLifecycleView.b2541bd36a7a")}</Badge><Badge variant="outline"><HardDrive />{message(locale, "screen.keyLifecycleView.72be76fd6793")}</Badge>{state.currentGeneration && <Badge>{message(locale, "screen.keyLifecycleView.944ae9faa259", { value0: state.currentGeneration.generation })}</Badge>}</div>
      </div>
    </section>

    <NoticeBanner notice={notice} locale={locale} onReauthenticate={() => void reauthenticate()} />
    {local.unavailable && <Alert className="border-destructive/50"><ShieldAlert /><AlertTitle>{message(locale, "screen.keyLifecycleView.2d7751116050")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.043363b9a17d")}</AlertDescription></Alert>}

    {latestLost && <Alert className="border-destructive/60 bg-destructive/5"><ShieldAlert /><AlertTitle>{message(locale, "screen.keyLifecycleView.2cbe77901416")}</AlertTitle><AlertDescription>{message(locale, "screen.keyLifecycleView.706e7170603c", { value0: latestLost.generation })}</AlertDescription></Alert>}

    {!latestLost && <section className="surface-card">
      <div className="flex items-start gap-3"><span className="form-icon"><Smartphone /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.7c5d4b2d81e0")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.48c2e2097233")}</p></div></div>
      <div className="mt-5 grid gap-4 md:grid-cols-[1fr_auto]"><div><Label htmlFor="key-device-label">{message(locale, "screen.keyLifecycleView.ac3a9af52712")}</Label><Input id="key-device-label" value={deviceLabel} maxLength={80} placeholder={message(locale, "screen.keyLifecycleView.8aa640edf80c")} onChange={(event) => setDeviceLabel(event.target.value)} /></div><Button className="self-end" type="button" disabled={Boolean(busy) || local.unavailable || !deviceLabel.trim()} onClick={() => void registerDevice()}>{busy === "register" ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{message(locale, "screen.keyLifecycleView.642595aceb80")}</Button></div>
      {local.devices.length > 0 && <div className="mt-5 grid gap-3 sm:grid-cols-2">{local.devices.map((device) => { const serverDevice = state.devices.find(({ deviceId }) => deviceId === device.deviceId); return <div key={device.deviceId} className="rounded-xl border bg-muted/25 p-4"><div className="flex items-center justify-between gap-2"><strong>{device.label}</strong><Badge variant="outline">{serverDevice ? statusLabel(locale, serverDevice.status) : message(locale, "screen.keyLifecycleView.ba4d37d9a102")}</Badge></div><p className="mt-2 break-all font-mono text-[11px] text-muted-foreground" aria-label={message(locale, "screen.keyLifecycleView.10a510f47534")}>{formatFingerprint(device.fingerprint)}</p></div>; })}</div>}
    </section>}

    {!state.currentGeneration && !latestLost && canManage && <section className="surface-card border-primary/30">
      <div className="flex items-start gap-3"><span className="form-icon"><KeyRound /></span><div><p className="eyebrow">{message(locale, "screen.keyLifecycleView.a5f97522f2b3")}</p><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.ca14dc21544b")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.70bc24909dc4")}</p></div></div>
      {!bootstrapDeviceAvailable ? <p className="mt-5 text-sm text-amber-700 dark:text-amber-300">{message(locale, "screen.keyLifecycleView.f3b97200bad4")}</p> : <div className="mt-5 space-y-4"><div className="grid gap-4 md:grid-cols-2"><div><Label htmlFor="bootstrap-passphrase">{message(locale, "screen.keyLifecycleView.ad6b02a89f69")}</Label><Input id="bootstrap-passphrase" type="password" autoComplete="new-password" value={bootstrapPassphrase} onChange={(event) => setBootstrapPassphrase(event.target.value)} /></div><div><Label htmlFor="bootstrap-confirm">{message(locale, "screen.keyLifecycleView.38663b47aac6")}</Label><Input id="bootstrap-confirm" type="password" autoComplete="new-password" value={bootstrapConfirm} onChange={(event) => setBootstrapConfirm(event.target.value)} /></div></div><Button type="button" variant="outline" disabled={Boolean(busy) || bootstrapPassphrase.length < 16 || bootstrapPassphrase !== bootstrapConfirm} onClick={() => void prepareBootstrap()}>{busy === "prepare-bootstrap" ? <LoaderCircle className="animate-spin" /> : <ArchiveRestore />}{message(locale, "screen.keyLifecycleView.c7e7bce1e8ee")}</Button>{bootstrapDraft && <div className="rounded-xl border border-primary/30 bg-primary/5 p-4"><p className="font-medium">{message(locale, "screen.keyLifecycleView.dfc676d853fa")}</p><div className="mt-3 flex flex-wrap gap-2"><Button type="button" variant="outline" onClick={() => { downloadBackup(session.tenant.slug, 1, bootstrapDraft.backup); setBootstrapDownloaded(true); }}><Download />{message(locale, "screen.keyLifecycleView.9f15479f540e")}</Button><Button type="button" disabled={!bootstrapDownloaded || Boolean(busy)} onClick={() => void initializeBootstrap()}>{busy === "initialize" ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{message(locale, "screen.keyLifecycleView.31a9b3427cef")}</Button></div>{!bootstrapDownloaded && <p className="mt-2 text-xs text-muted-foreground">{message(locale, "screen.keyLifecycleView.1c6805acafa8")}</p>}</div>}</div>}
    </section>}

    {state.currentGeneration && <>
      <section className="surface-card"><div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between"><div><p className="eyebrow">{message(locale, "screen.keyLifecycleView.6746ee90890d")}</p><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.944ae9faa259", { value0: state.currentGeneration.generation })}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.2f2f5ec1f574", { value0: state.currentGeneration.activeGrantCount, value1: friendlyDate(locale, session.tenant.timezone, state.currentGeneration.createdAt) })}</p></div>{vault.keyId === state.currentGeneration.tenantKeyId && vault.tenantId === session.tenant.id ? <Badge className="border-emerald-700 bg-emerald-700 text-white"><CheckCircle2 />{message(locale, "screen.keyLifecycleView.e3e56c91d6cc")}</Badge> : <Badge variant="outline"><LockKeyhole />{message(locale, "screen.keyLifecycleView.dffda04112f9")}</Badge>}</div><div className="mt-5 flex flex-wrap gap-2">{ownActivePairs.filter(({ grant }) => grant.tenantKeyId === state.currentGeneration?.tenantKeyId).map(({ grant, device }) => <Button key={grant.grantId} type="button" variant="outline" disabled={Boolean(busy)} onClick={() => void unlockGrant(grant, device)}>{busy === `unlock-${grant.grantId}` ? <LoaderCircle className="animate-spin" /> : <Fingerprint />}{message(locale, "screen.keyLifecycleView.190813b8a653", { value0: device.label })}</Button>)}{vault.keyId === state.currentGeneration.tenantKeyId && vault.tenantId === session.tenant.id && <Button type="button" variant="ghost" onClick={vault.lock}><LockKeyhole />{message(locale, "screen.keyLifecycleView.9806d1c22255")}</Button>}</div></section>

      {canManage && pendingDevices.length > 0 && <section className="surface-card"><div className="flex items-start gap-3"><span className="form-icon"><UserCheck /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.bb489427b9cb")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.fe2c71b7a40d")}</p></div></div><div className="mt-5 grid gap-3">{pendingDevices.map((device) => <div key={device.deviceId} className="rounded-xl border p-4"><div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div><strong>{device.label}</strong><p className="text-xs text-muted-foreground">{message(locale, "screen.keyLifecycleView.d544eec0d239")}: {device.identityId}</p><p className="mt-2 break-all font-mono text-[11px]">{formatFingerprint(device.wrappingKeyFingerprint)}</p></div><Button type="button" variant={approvalDeviceId === device.deviceId ? "default" : "outline"} onClick={() => { setApprovalDeviceId(device.deviceId); setApprovalCode(""); }}>{message(locale, "screen.keyLifecycleView.82badd6fb03b")}</Button></div>{approvalDeviceId === device.deviceId && <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]"><div><Label htmlFor={`approve-${device.deviceId}`}>{message(locale, "screen.keyLifecycleView.19b8a92922e0", { value0: fingerprintConfirmation(device.wrappingKeyFingerprint) })}</Label><Input id={`approve-${device.deviceId}`} value={approvalCode} autoComplete="off" onChange={(event) => setApprovalCode(event.target.value.toUpperCase())} /></div><Button className="self-end" type="button" disabled={Boolean(busy) || approvalCode !== fingerprintConfirmation(device.wrappingKeyFingerprint) || vault.keyId !== state.currentGeneration?.tenantKeyId} onClick={() => void approveDevice(device)}>{busy === "approve" ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{message(locale, "screen.keyLifecycleView.39f980d0fb93")}</Button></div>}</div>)}</div></section>}

      {canManage && historicalTargets.length > 0 && <section className="surface-card" data-testid="historical-key-coverage">
        <div className="flex items-start gap-3">
          <span className="form-icon"><ArchiveRestore /></span>
          <div>
            <h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.06ca2c993f40")}</h3>
            <p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.12ea7d44b1c3")}</p>
          </div>
        </div>
        <div className="mt-5 grid gap-3">
          {historicalTargets.map(({ device, coveredTenantKeyIds }) => {
            const transient = historicalResult?.targetDeviceId === device.deviceId ? historicalResult : undefined;
            const isCovered = (tenantKeyId: string) => coveredTenantKeyIds.includes(tenantKeyId)
              || transient?.generations.some((generation) =>
                generation.tenantKeyId === tenantKeyId && generation.status !== "unavailable") === true;
            const covered = retiredGenerations.filter((generation) => isCovered(generation.tenantKeyId)).length;
            const complete = covered === retiredGenerations.length;
            return <div key={device.deviceId} className="rounded-xl border p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <strong>{device.label}</strong>
                  <p className="text-xs text-muted-foreground">{message(locale, "screen.keyLifecycleView.d544eec0d239")}: {device.identityId}</p>
                  <p className="text-xs text-muted-foreground">{message(locale, "screen.keyLifecycleView.1f90cb2dc745", { value0: covered, value1: retiredGenerations.length })}</p>
                  <p className="mt-2 break-all font-mono text-[11px]">{formatFingerprint(device.wrappingKeyFingerprint)}</p>
                </div>
                {!complete && <Button type="button" variant={approvalDeviceId === device.deviceId ? "default" : "outline"} onClick={() => { setApprovalDeviceId(device.deviceId); setApprovalCode(""); }}>
                  <ArchiveRestore />{message(locale, "screen.keyLifecycleView.3e3ac840dd36")}
                </Button>}
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {retiredGenerations.map((generation) => <Badge key={generation.tenantKeyId} className={isCovered(generation.tenantKeyId) ? "border-emerald-700 bg-emerald-700 text-white" : undefined} variant="outline">
                  {message(locale, "screen.keyLifecycleView.944ae9faa259", { value0: generation.generation })} · {message(locale, isCovered(generation.tenantKeyId) ? "screen.keyLifecycleView.5f5f0d6e2ed4" : "screen.keyLifecycleView.6d1a8a51c5c7")}
                </Badge>)}
              </div>
              {!complete && approvalDeviceId === device.deviceId && <div className="mt-4 grid gap-3 border-t pt-4 md:grid-cols-[1fr_auto]">
                <div>
                  <Label htmlFor={`history-${device.deviceId}`}>{message(locale, "screen.keyLifecycleView.490cbc744d31", { value0: fingerprintConfirmation(device.wrappingKeyFingerprint) })}</Label>
                  <Input id={`history-${device.deviceId}`} value={approvalCode} autoComplete="off" onChange={(event) => setApprovalCode(event.target.value.toUpperCase())} />
                </div>
                <Button className="self-end" type="button" disabled={Boolean(busy) || local.unavailable || approvalCode !== fingerprintConfirmation(device.wrappingKeyFingerprint)} onClick={() => void completeHistoricalAccess(device)}>
                  {busy === `history-${device.deviceId}` ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />}{message(locale, "screen.keyLifecycleView.3e3ac840dd36")}
                </Button>
              </div>}
            </div>;
          })}
        </div>
      </section>}

      {canManage && <section className="surface-card"><div className="flex items-start gap-3"><span className="form-icon"><Trash2 /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.aa71baabb254")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.fb838c936ffb")}</p></div></div><div className="mt-5 grid gap-3">{activeGrants.map((grant) => { const device = state.devices.find(({ deviceId }) => deviceId === grant.deviceId); return <div key={grant.grantId} className="rounded-xl border p-4"><div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div><strong>{device?.label ?? message(locale, "screen.keyLifecycleView.847450f6d823")}</strong><p className="text-xs text-muted-foreground">{grant.identityId} · {statusLabel(locale, grant.grantKind)}</p></div><Button type="button" variant="outline" onClick={() => { setRevokeGrantId(grant.grantId); setRevokeCode(""); setRevokeReasonCode(""); setConfirmLastGrant(false); }}><Trash2 />{message(locale, "screen.keyLifecycleView.dd1d879556c8")}</Button></div>{revokeGrantId === grant.grantId && device && <div className="mt-4 space-y-3 border-t pt-4"><div className="grid gap-3 md:grid-cols-2"><div><Label htmlFor={`revoke-code-${grant.grantId}`}>{message(locale, "screen.keyLifecycleView.1ec42eb3589c", { value0: fingerprintConfirmation(device.wrappingKeyFingerprint) })}</Label><Input id={`revoke-code-${grant.grantId}`} value={revokeCode} autoComplete="off" onChange={(event) => setRevokeCode(event.target.value.toUpperCase())} /></div><div><Label htmlFor={`revoke-reason-${grant.grantId}`}>{message(locale, "screen.keyLifecycleView.523b0405721e")}</Label><select id={`revoke-reason-${grant.grantId}`} value={revokeReasonCode} onChange={(event) => setRevokeReasonCode(event.target.value)} required><option value="">{message(locale, "screen.keyLifecycleView.30360a3bdaf2")}</option>{revokeReasonCodes.map((reasonCode) => <option key={reasonCode} value={reasonCode}>{reasonCodeLabel(locale, reasonCode)}</option>)}</select></div></div>{activeGrants.length === 1 && <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="checkbox" checked={confirmLastGrant} onChange={(event) => setConfirmLastGrant(event.target.checked)} /><span>{message(locale, "screen.keyLifecycleView.d2b2dac7eaf0")}</span></label>}<Button type="button" variant="destructive" disabled={Boolean(busy) || revokeCode !== fingerprintConfirmation(device.wrappingKeyFingerprint) || !revokeReasonCode || (activeGrants.length === 1 && !confirmLastGrant)} onClick={() => void revokeGrant(grant)}>{busy === "revoke" ? <LoaderCircle className="animate-spin" /> : <Trash2 />}{message(locale, "screen.keyLifecycleView.f29c4d2048ad")}</Button></div>}</div>; })}</div></section>}

      {canManage && <section className="surface-card"><div className="flex items-start gap-3"><span className="form-icon"><RotateCcw /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.bf921124a2a2")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.38af247eeded")}</p></div></div><div className="mt-5 space-y-4"><div><Label htmlFor="rotation-reason">{message(locale, "screen.keyLifecycleView.523b0405721e")}</Label><select id="rotation-reason" value={rotationReasonCode} onChange={(event) => setRotationReasonCode(event.target.value)} required><option value="">{message(locale, "screen.keyLifecycleView.30360a3bdaf2")}</option>{rotationReasonCodes.map((reasonCode) => <option key={reasonCode} value={reasonCode}>{reasonCodeLabel(locale, reasonCode)}</option>)}</select></div><div className="grid gap-4 md:grid-cols-2"><div><Label htmlFor="rotation-passphrase">{message(locale, "screen.keyLifecycleView.6d14cae374e0")}</Label><Input id="rotation-passphrase" type="password" autoComplete="new-password" value={rotationPassphrase} onChange={(event) => setRotationPassphrase(event.target.value)} /></div><div><Label htmlFor="rotation-confirm">{message(locale, "screen.keyLifecycleView.38663b47aac6")}</Label><Input id="rotation-confirm" type="password" autoComplete="new-password" value={rotationConfirm} onChange={(event) => setRotationConfirm(event.target.value)} /></div></div><Button type="button" variant="outline" disabled={Boolean(busy) || vault.keyId !== state.currentGeneration?.tenantKeyId || !rotationReasonCode || rotationPassphrase.length < 16 || rotationPassphrase !== rotationConfirm} onClick={() => void prepareRotation()}>{busy === "prepare-rotation" ? <LoaderCircle className="animate-spin" /> : <RotateCcw />}{message(locale, "screen.keyLifecycleView.bd8b1879871d")}</Button>{rotationDraft && <div className="rounded-xl border border-primary/30 bg-primary/5 p-4"><p>{message(locale, "screen.keyLifecycleView.601ca705c2ca")}</p><div className="mt-3 flex flex-wrap gap-2"><Button type="button" variant="outline" onClick={() => { downloadBackup(session.tenant.slug, rotationDraft.request.expectedGeneration + 1, rotationDraft.backup); setRotationDownloaded(true); }}><Download />{message(locale, "screen.keyLifecycleView.b1523b78a3f9")}</Button><Button type="button" disabled={!rotationDownloaded || Boolean(busy)} onClick={() => void commitRotation()}>{busy === "rotate" ? <LoaderCircle className="animate-spin" /> : <RotateCcw />}{message(locale, "screen.keyLifecycleView.4773f15de254")}</Button></div></div>}</div></section>}

      {canManage && <section className="surface-card"><div className="flex items-start gap-3"><span className="form-icon"><ArchiveRestore /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.10ae0361229a")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.4ab7223f37cf")}</p></div></div><div className="mt-5 grid gap-4 md:grid-cols-2"><div><Label htmlFor="recovery-file">{message(locale, "screen.keyLifecycleView.f5dfc8eddb67")}</Label><Input ref={recoveryInput} id="recovery-file" type="file" accept="application/json,.json" onChange={(event) => setRecoveryFile(event.target.files?.[0])} /></div><div><Label htmlFor="recovery-passphrase">{message(locale, "screen.keyLifecycleView.b13d98ffc80d")}</Label><Input id="recovery-passphrase" type="password" autoComplete="off" value={recoveryPassphrase} onChange={(event) => setRecoveryPassphrase(event.target.value)} /></div></div>{!pendingRecoveryDeviceAvailable && <p className="mt-3 text-sm text-amber-700 dark:text-amber-300">{message(locale, "screen.keyLifecycleView.049dc88635f0")}</p>}<Button className="mt-4" type="button" variant="outline" disabled={Boolean(busy) || !recoveryFile || recoveryPassphrase.length < 16 || !pendingRecoveryDeviceAvailable} onClick={() => void recoverFromBackup()}>{busy === "recover" ? <LoaderCircle className="animate-spin" /> : <ArchiveRestore />}{message(locale, "screen.keyLifecycleView.550223cfa650")}</Button></section>}

      {canManage && state.currentGeneration.activeGrantCount === 0 && <section className="surface-card border-destructive/50 bg-destructive/5"><div className="flex items-start gap-3"><span className="form-icon"><ShieldAlert /></span><div><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.b464ee70cb20")}</h3><p className="text-sm text-muted-foreground">{message(locale, "screen.keyLifecycleView.8c1681944aac")}</p></div></div><div className="mt-5 space-y-4"><div><Label htmlFor="loss-reason">{message(locale, "screen.keyLifecycleView.523b0405721e")}</Label><select id="loss-reason" value={lossReasonCode} onChange={(event) => setLossReasonCode(event.target.value)} required><option value="">{message(locale, "screen.keyLifecycleView.30360a3bdaf2")}</option>{lossReasonCodes.map((reasonCode) => <option key={reasonCode} value={reasonCode}>{reasonCodeLabel(locale, reasonCode)}</option>)}</select></div><div><Label htmlFor="loss-confirmation">{message(locale, "screen.keyLifecycleView.5673eb8a06dd", { value0: lossPhrase })}</Label><Input id="loss-confirmation" value={lossConfirmation} autoComplete="off" onChange={(event) => setLossConfirmation(event.target.value)} /></div><Button type="button" variant="destructive" disabled={Boolean(busy) || !lossReasonCode || lossConfirmation !== lossPhrase} onClick={() => void declarePermanentLoss()}>{busy === "declare-loss" ? <LoaderCircle className="animate-spin" /> : <ShieldAlert />}{message(locale, "screen.keyLifecycleView.c62247fce2f7")}</Button></div></section>}
    </>}

    {state.generations.length > 0 && <section className="surface-card"><h3 className="text-lg font-semibold">{message(locale, "screen.keyLifecycleView.94a244ad1b7d")}</h3><div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{state.generations.map((generation) => <div key={generation.tenantKeyId} className="rounded-xl border p-4"><div className="flex items-center justify-between gap-2"><strong>{message(locale, "screen.keyLifecycleView.944ae9faa259", { value0: generation.generation })}</strong><Badge variant="outline">{statusLabel(locale, generation.status)}</Badge></div><p className="mt-2 text-xs text-muted-foreground">{friendlyDate(locale, session.tenant.timezone, generation.createdAt)}</p><p className="mt-2 break-all font-mono text-[10px]" aria-label={message(locale, "screen.keyLifecycleView.01f6f2ff51d6")}>{formatFingerprint(generation.recoveryKeyFingerprint)}</p>{state.ownGrants.filter((grant) => grant.tenantKeyId === generation.tenantKeyId).flatMap((grant) => { const device = local.devices.find(({ deviceId }) => deviceId === grant.deviceId); return device ? [<Button className="mt-3" key={grant.grantId} type="button" size="sm" variant="outline" disabled={Boolean(busy) || !canUnlockTenantGrant({ grantStatus: grant.status, grantTenantKeyId: grant.tenantKeyId, currentTenantKeyId: state.currentGeneration?.tenantKeyId, tenantId: session.tenant.id, vaultTenantId: vault.tenantId, vaultKeyId: vault.keyId })} onClick={() => void unlockGrant(grant, device)}><LockKeyhole />{message(locale, "screen.keyLifecycleView.f4286c1b891f")}</Button>] : []; })}</div>)}</div></section>}
  </div>;
}
