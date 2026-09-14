"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BALLOT_PURPOSE,
  BALLOT_SCHEMA_VERSION,
  computeBallotContentHash,
  computeTallyAggregateHash,
  createEncryptedCustodianKeyBackup,
  createTallyAggregate,
  createTallyAttestationContext,
  exportCustodianPublicKey,
  exportCustodianSigningPublicKey,
  generateCustodianKeyPair,
  generateCustodianSigningKeyPair,
  openBallotEnvelope,
  openEncryptedCustodianKeyBackup,
  signTallyAttestation,
  toCustodianPublicKey,
  toCustodianSigningPublicKey,
  verifyBallotEnvelope,
  type BallotPayload,
  type CustodianPrivateKey,
  type CustodianSigningPrivateKey,
} from "@nombramientos/e2ee";
import {
  AlertCircle,
  ArchiveRestore,
  Check,
  Download,
  Fingerprint,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  RotateCw,
  ShieldCheck,
  ShieldX,
  Upload,
  Vote,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  ApiError,
  type AuthenticatedSession,
  type CustodyPublicKey,
  type Locale,
  type RoundCustody,
  type TallyAggregate,
} from "@/lib/api";
import { message, localizedApiError, localizedName, phaseLabel } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";
import { DataError, LoadingBlock, PageTitle } from "./workspace-view";

type UnlockedKeys = {
  metadata: { tenantId: string; deviceId: string; recipientId: string; createdAt: string };
  hpke: CustodianPrivateKey;
  signing: CustodianSigningPrivateKey;
};

const copy = {
  es: {
    eyebrow: message("es", "screen.custodyView.e306e080a5b9"),
    title: message("es", "screen.custodyView.2688c5b99699"),
    description: message("es", "screen.custodyView.25adfa6fec4c"),
    ceremony: message("es", "screen.custodyView.5267fe18eb4a"),
    ceremonyHelp: message("es", "screen.custodyView.a23130ba756c"),
    passphrase: message("es", "screen.custodyView.e99f5bfd006f"),
    confirm: message("es", "screen.custodyView.38663b47aac6"),
    create: message("es", "screen.custodyView.bbf9db484922"),
    restore: message("es", "screen.custodyView.fcf7e6ca582a"),
    restoreHelp: message("es", "screen.custodyView.bc8a3ce6e092"),
    backup: message("es", "screen.custodyView.3b14181ddbcc"),
    unlock: message("es", "screen.custodyView.80019e75afea"),
    unlocked: message("es", "screen.custodyView.8130f26a7a7a"),
    keys: message("es", "screen.custodyView.f911d165e55e"),
    active: message("es", "screen.custodyView.bdb96a52baa8"),
    revoked: message("es", "screen.custodyView.f59166b506f3"),
    superseded: message("es", "screen.custodyView.79f63d2fbb7f"),
    yours: message("es", "screen.custodyView.a4bccf2858f1"),
    rotate: message("es", "screen.custodyView.a17473c9e225"),
    revoke: message("es", "screen.custodyView.dd1d879556c8"),
    choose: message("es", "screen.custodyView.0b066b65bf2c"),
    verified: message("es", "screen.custodyView.abf5f395f323"),
    freeze: message("es", "screen.custodyView.8e7e0630d7b4"),
    noVote: message("es", "screen.custodyView.427a8e7200fb"),
    noVoteHelp: message("es", "screen.custodyView.f132b6e7ce1a"),
    manifest: message("es", "screen.custodyView.7a386f478efd"),
    fixManifest: message("es", "screen.custodyView.2025268d109a"),
    count: message("es", "screen.custodyView.a9138798423e"),
    publish: message("es", "screen.custodyView.77265d476b1d"),
    waiting: message("es", "screen.custodyView.b2b339f78319"),
    disputed: message("es", "screen.custodyView.e10a616a1810"),
    published: message("es", "screen.custodyView.fb0a0ace25ee"),
    received: message("es", "screen.custodyView.b872f2607904"),
    abstentions: message("es", "screen.custodyView.995af184934e"),
    nonAbstaining: message("es", "screen.custodyView.c8e4c50ce282"),
    decision: message("es", "screen.custodyView.7288e0404863"),
    noPermission: message("es", "screen.custodyView.ab1d0673e242"), safeStop: message("es", "screen.custodyView.5dec4252f5f2"), roundLoadFailed: message("es", "screen.custodyView.808d935d7cbb"), custodyLoadFailed: message("es", "screen.custodyView.34c1ca4b59c5"), manifestLoadFailed: message("es", "screen.custodyView.7b8a78108094"), publishedLoadFailed: message("es", "screen.custodyView.7a389b48fbb5"), ceremonyEyebrow: message("es", "screen.custodyView.dfce079aa722"), registryEyebrow: message("es", "screen.custodyView.ce303e37e028"), reconcileEyebrow: message("es", "screen.custodyView.51487a84793d"), selectKey: message("es", "screen.custodyView.70ec613fb0ff"), frozenCustodians: message("es", "screen.custodyView.d11f494c0521"), version: message("es", "screen.custodyView.2a0a3b41eba1"), localVerified: message("es", "screen.custodyView.261ca4123d96"), publishedLabel: message("es", "screen.custodyView.dded955bc471"), genericError: message("es", "screen.custodyView.d9c618be2a45"),
  },
  en: {
    eyebrow: message("en", "screen.custodyView.e306e080a5b9"), title: message("en", "screen.custodyView.2688c5b99699"), description: message("en", "screen.custodyView.25adfa6fec4c"),
    ceremony: message("en", "screen.custodyView.5267fe18eb4a"), ceremonyHelp: message("en", "screen.custodyView.a23130ba756c"), passphrase: message("en", "screen.custodyView.e99f5bfd006f"), confirm: message("en", "screen.custodyView.38663b47aac6"), create: message("en", "screen.custodyView.bbf9db484922"),
    restore: message("en", "screen.custodyView.fcf7e6ca582a"), restoreHelp: message("en", "screen.custodyView.bc8a3ce6e092"), backup: message("en", "screen.custodyView.3b14181ddbcc"), unlock: message("en", "screen.custodyView.80019e75afea"), unlocked: message("en", "screen.custodyView.8130f26a7a7a"),
    keys: message("en", "screen.custodyView.f911d165e55e"), active: message("en", "screen.custodyView.bdb96a52baa8"), revoked: message("en", "screen.custodyView.f59166b506f3"), superseded: message("en", "screen.custodyView.79f63d2fbb7f"), yours: message("en", "screen.custodyView.a4bccf2858f1"), rotate: message("en", "screen.custodyView.a17473c9e225"), revoke: message("en", "screen.custodyView.dd1d879556c8"),
    choose: message("en", "screen.custodyView.0b066b65bf2c"), verified: message("en", "screen.custodyView.abf5f395f323"), freeze: message("en", "screen.custodyView.8e7e0630d7b4"),
    noVote: message("en", "screen.custodyView.427a8e7200fb"), noVoteHelp: message("en", "screen.custodyView.f132b6e7ce1a"), manifest: message("en", "screen.custodyView.7a386f478efd"), fixManifest: message("en", "screen.custodyView.2025268d109a"), count: message("en", "screen.custodyView.a9138798423e"), publish: message("en", "screen.custodyView.77265d476b1d"), waiting: message("en", "screen.custodyView.b2b339f78319"), disputed: message("en", "screen.custodyView.e10a616a1810"), published: message("en", "screen.custodyView.fb0a0ace25ee"), received: message("en", "screen.custodyView.b872f2607904"), abstentions: message("en", "screen.custodyView.995af184934e"), nonAbstaining: message("en", "screen.custodyView.c8e4c50ce282"), decision: message("en", "screen.custodyView.7288e0404863"), noPermission: message("en", "screen.custodyView.ab1d0673e242"), safeStop: message("en", "screen.custodyView.5dec4252f5f2"), roundLoadFailed: message("en", "screen.custodyView.808d935d7cbb"), custodyLoadFailed: message("en", "screen.custodyView.34c1ca4b59c5"), manifestLoadFailed: message("en", "screen.custodyView.7b8a78108094"), publishedLoadFailed: message("en", "screen.custodyView.7a389b48fbb5"), ceremonyEyebrow: message("en", "screen.custodyView.dfce079aa722"), registryEyebrow: message("en", "screen.custodyView.ce303e37e028"), reconcileEyebrow: message("en", "screen.custodyView.51487a84793d"), selectKey: message("en", "screen.custodyView.70ec613fb0ff"), frozenCustodians: message("en", "screen.custodyView.d11f494c0521"), version: message("en", "screen.custodyView.2a0a3b41eba1"), localVerified: message("en", "screen.custodyView.261ca4123d96"), publishedLabel: message("en", "screen.custodyView.dded955bc471"), genericError: message("en", "screen.custodyView.d9c618be2a45"),
  },
  fr: {
    eyebrow: message("fr", "screen.custodyView.e306e080a5b9"), title: message("fr", "screen.custodyView.2688c5b99699"), description: message("fr", "screen.custodyView.25adfa6fec4c"),
    ceremony: message("fr", "screen.custodyView.5267fe18eb4a"), ceremonyHelp: message("fr", "screen.custodyView.a23130ba756c"), passphrase: message("fr", "screen.custodyView.e99f5bfd006f"), confirm: message("fr", "screen.custodyView.38663b47aac6"), create: message("fr", "screen.custodyView.bbf9db484922"),
    restore: message("fr", "screen.custodyView.fcf7e6ca582a"), restoreHelp: message("fr", "screen.custodyView.bc8a3ce6e092"), backup: message("fr", "screen.custodyView.3b14181ddbcc"), unlock: message("fr", "screen.custodyView.80019e75afea"), unlocked: message("fr", "screen.custodyView.8130f26a7a7a"),
    keys: message("fr", "screen.custodyView.f911d165e55e"), active: message("fr", "screen.custodyView.bdb96a52baa8"), revoked: message("fr", "screen.custodyView.f59166b506f3"), superseded: message("fr", "screen.custodyView.79f63d2fbb7f"), yours: message("fr", "screen.custodyView.a4bccf2858f1"), rotate: message("fr", "screen.custodyView.a17473c9e225"), revoke: message("fr", "screen.custodyView.dd1d879556c8"),
    choose: message("fr", "screen.custodyView.0b066b65bf2c"), verified: message("fr", "screen.custodyView.abf5f395f323"), freeze: message("fr", "screen.custodyView.8e7e0630d7b4"),
    noVote: message("fr", "screen.custodyView.427a8e7200fb"), noVoteHelp: message("fr", "screen.custodyView.f132b6e7ce1a"), manifest: message("fr", "screen.custodyView.7a386f478efd"), fixManifest: message("fr", "screen.custodyView.2025268d109a"), count: message("fr", "screen.custodyView.a9138798423e"), publish: message("fr", "screen.custodyView.77265d476b1d"), waiting: message("fr", "screen.custodyView.b2b339f78319"), disputed: message("fr", "screen.custodyView.e10a616a1810"), published: message("fr", "screen.custodyView.fb0a0ace25ee"), received: message("fr", "screen.custodyView.b872f2607904"), abstentions: message("fr", "screen.custodyView.995af184934e"), nonAbstaining: message("fr", "screen.custodyView.c8e4c50ce282"), decision: message("fr", "screen.custodyView.7288e0404863"), noPermission: message("fr", "screen.custodyView.ab1d0673e242"), safeStop: message("fr", "screen.custodyView.5dec4252f5f2"), roundLoadFailed: message("fr", "screen.custodyView.808d935d7cbb"), custodyLoadFailed: message("fr", "screen.custodyView.34c1ca4b59c5"), manifestLoadFailed: message("fr", "screen.custodyView.7b8a78108094"), publishedLoadFailed: message("fr", "screen.custodyView.7a389b48fbb5"), ceremonyEyebrow: message("fr", "screen.custodyView.dfce079aa722"), registryEyebrow: message("fr", "screen.custodyView.ce303e37e028"), reconcileEyebrow: message("fr", "screen.custodyView.51487a84793d"), selectKey: message("fr", "screen.custodyView.70ec613fb0ff"), frozenCustodians: message("fr", "screen.custodyView.d11f494c0521"), version: message("fr", "screen.custodyView.2a0a3b41eba1"), localVerified: message("fr", "screen.custodyView.261ca4123d96"), publishedLabel: message("fr", "screen.custodyView.dded955bc471"), genericError: message("fr", "screen.custodyView.d9c618be2a45"),
  },
} as const;

type Labels = { [Key in keyof typeof copy.es]: string };
type CustodyRevokeReasonCode = "DEVICE_RETIRED" | "DEVICE_REPLACED" | "SECURITY_RESPONSE" | "VERIFIED_KEY_LOSS";

const custodyRevokeReasonCodes = [
  "DEVICE_RETIRED",
  "DEVICE_REPLACED",
  "SECURITY_RESPONSE",
  "VERIFIED_KEY_LOSS",
] as const satisfies readonly CustodyRevokeReasonCode[];

function custodyRevokeReasonLabel(locale: Locale, reasonCode: CustodyRevokeReasonCode): string {
  const keys: Record<CustodyRevokeReasonCode, Parameters<typeof message>[1]> = {
    DEVICE_RETIRED: "custody.revokeReason.deviceRetired",
    DEVICE_REPLACED: "custody.revokeReason.deviceReplaced",
    SECURITY_RESPONSE: "custody.revokeReason.securityResponse",
    VERIFIED_KEY_LOSS: "custody.revokeReason.verifiedKeyLoss",
  };
  return message(locale, keys[reasonCode]);
}

const decisionStatusCopy: Record<Locale, Record<string, string>> = {
  es: { SELECTED: message("es", "screen.custodyView.590e5eaad5e2"), PARTIAL_SELECTION: message("es", "screen.custodyView.f608e2e04f38"), TIEBREAK_REQUIRED: message("es", "screen.custodyView.5e261568d787"), NO_SELECTION: message("es", "screen.custodyView.1539434f3232") },
  en: { SELECTED: message("en", "screen.custodyView.590e5eaad5e2"), PARTIAL_SELECTION: message("en", "screen.custodyView.f608e2e04f38"), TIEBREAK_REQUIRED: message("en", "screen.custodyView.5e261568d787"), NO_SELECTION: message("en", "screen.custodyView.1539434f3232") },
  fr: { SELECTED: message("fr", "screen.custodyView.590e5eaad5e2"), PARTIAL_SELECTION: message("fr", "screen.custodyView.f608e2e04f38"), TIEBREAK_REQUIRED: message("fr", "screen.custodyView.5e261568d787"), NO_SELECTION: message("fr", "screen.custodyView.1539434f3232") },
};

const manifestStateCopy: Record<Locale, Record<string, string>> = {
  es: { awaiting_attestations: message("es", "screen.custodyView.9bca6e35aef3"), publishable: message("es", "screen.custodyView.79d33cbed4b3"), disputed: message("es", "screen.custodyView.88f028f77f31"), published: message("es", "screen.custodyView.dded955bc471") },
  en: { awaiting_attestations: message("en", "screen.custodyView.9bca6e35aef3"), publishable: message("en", "screen.custodyView.79d33cbed4b3"), disputed: message("en", "screen.custodyView.88f028f77f31"), published: message("en", "screen.custodyView.dded955bc471") },
  fr: { awaiting_attestations: message("fr", "screen.custodyView.9bca6e35aef3"), publishable: message("fr", "screen.custodyView.79d33cbed4b3"), disputed: message("fr", "screen.custodyView.88f028f77f31"), published: message("fr", "screen.custodyView.dded955bc471") },
};

function downloadBackup(value: unknown, tenantSlug: string, deviceId: string) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `custody-backup-${tenantSlug}-${deviceId}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

async function optionalNotFound<T>(work: () => Promise<T>): Promise<T | null> {
  try { return await work(); }
  catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

function statusLabel(key: CustodyPublicKey, t: Labels) {
  return key.status === "active" ? t.active : key.status === "revoked" ? t.revoked : t.superseded;
}

function errorMessage(error: unknown, locale: Locale, labels: Labels): string {
  return error instanceof ApiError ? localizedApiError(error, locale) : labels.genericError;
}

export function CustodyView({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const t: Labels = copy[locale];
  const client = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [revokeReasonCode, setRevokeReasonCode] = useState<CustodyRevokeReasonCode>("DEVICE_RETIRED");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [backupFile, setBackupFile] = useState<File>();
  const [unlocked, setUnlocked] = useState<UnlockedKeys>();
  const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
  const [fingerprintsVerified, setFingerprintsVerified] = useState(false);
  const [localAggregate, setLocalAggregate] = useState<TallyAggregate>();

  useEffect(() => {
    if (!unlocked) return;
    let timer: number | undefined;
    const lock = () => {
      setUnlocked(undefined);
      setLocalAggregate(undefined);
    };
    const reset = () => {
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(lock, 10 * 60_000);
    };
    const visibility = () => {
      if (document.visibilityState === "hidden") lock();
      else reset();
    };
    const events: Array<keyof WindowEventMap> = ["pointerdown", "keydown", "touchstart"];
    events.forEach((event) => window.addEventListener(event, reset, { passive: true }));
    document.addEventListener("visibilitychange", visibility);
    reset();
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      events.forEach((event) => window.removeEventListener(event, reset));
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [unlocked]);

  const mayCustody = session.permissions.includes("tally.custody");
  const mayRecount = mayCustody && session.permissions.includes("tally.recount");
  const mayPublish = mayRecount && session.permissions.includes("aggregate.publish");
  const keysQuery = useQuery({ queryKey: ["custody-keys", session.tenant.id], queryFn: api.custodyKeys, enabled: mayCustody });
  const roundQuery = useQuery({
    queryKey: ["active-round", session.tenant.id],
    queryFn: () => optionalNotFound(api.activeRound),
    retry: false,
  });
  const round = roundQuery.data ?? null;
  const roundId = round?.round.id;
  const custodyQuery = useQuery({
    queryKey: ["round-custody", session.tenant.id, roundId],
    queryFn: () => optionalNotFound(() => api.roundCustody(roundId!)),
    enabled: Boolean(roundId && mayCustody),
    retry: false,
  });
  const custody = custodyQuery.data ?? null;
  const manifestQuery = useQuery({
    queryKey: ["tally-manifest", session.tenant.id, roundId],
    queryFn: () => optionalNotFound(() => api.tallyManifest(roundId!)),
    enabled: Boolean(roundId && mayRecount && ["VOTACION_CERRADA", "ESCRUTINIO", "RESULTADO_INTERNO"].includes(round!.round.phase)),
    retry: false,
  });
  const manifest = manifestQuery.data ?? null;
  const publishedQuery = useQuery({
    queryKey: ["published-aggregate", session.tenant.id, roundId],
    queryFn: () => optionalNotFound(() => api.publishedAggregate(roundId!)),
    enabled: Boolean(roundId && session.permissions.includes("aggregate.read") && round?.round.phase === "RESULTADO_INTERNO"),
    retry: false,
  });
  const published = publishedQuery.data ?? null;

  const activeKeys = useMemo(() => (keysQuery.data ?? []).filter((key) => key.status === "active"), [keysQuery.data]);
  const distinctSelectedIdentities = new Set(activeKeys.filter((key) => selectedKeys.includes(key.keyId)).map((key) => key.custodianIdentityId)).size;

  async function prepareAndRegister(existing?: CustodyPublicKey) {
    if (passphrase.length < 16 || passphrase !== confirmation) throw new Error("La contraseña debe tener al menos 16 caracteres y coincidir.");
    const deviceId = existing?.deviceId ?? crypto.randomUUID();
    const recipientId = existing?.recipientId ?? `${session.user.id}:${deviceId}`;
    const [hpke, signing] = await Promise.all([
      generateCustodianKeyPair(recipientId),
      generateCustodianSigningKeyPair(),
    ]);
    const [hpkePublic, signingPublic, backup] = await Promise.all([
      exportCustodianPublicKey(toCustodianPublicKey(hpke)),
      exportCustodianSigningPublicKey(toCustodianSigningPublicKey(signing)),
      createEncryptedCustodianKeyBackup({
        tenantId: session.tenant.id,
        deviceId,
        recipientId,
        passphrase,
        hpke,
        signing,
      }),
    ]);
    await api.registerCustodyKey({
      deviceId,
      recipientId,
      expectedVersion: existing?.version ?? 0,
      suite: hpkePublic.suite,
      hpkePublicKey: hpkePublic.publicKey,
      hpkeFingerprint: hpkePublic.fingerprint,
      signingAlgorithm: signingPublic.algorithm,
      signingPublicKeySpki: signingPublic.publicKeySpki,
      signingFingerprint: signingPublic.fingerprint,
    });
    setUnlocked({ metadata: { tenantId: session.tenant.id, deviceId, recipientId, createdAt: backup.createdAt }, hpke, signing });
    downloadBackup(backup, session.tenant.slug, deviceId);
    setPassphrase("");
    setConfirmation("");
    await client.invalidateQueries({ queryKey: ["custody-keys", session.tenant.id] });
  }

  const registerMutation = useMutation({ mutationFn: () => prepareAndRegister() });
  const rotateMutation = useMutation({ mutationFn: (key: CustodyPublicKey) => prepareAndRegister(key) });
  const unlockMutation = useMutation({
    mutationFn: async () => {
      if (!backupFile) throw new Error("Selecciona una copia cifrada.");
      if (backupFile.size > 256 * 1024) throw new Error("La copia excede el límite permitido.");
      const parsed = JSON.parse(await backupFile.text()) as unknown;
      const keys = await openEncryptedCustodianKeyBackup(parsed, passphrase);
      if (keys.metadata.tenantId !== session.tenant.id) throw new Error("La copia pertenece a otra iglesia.");
      const registered = activeKeys.some((key) => key.deviceId === keys.metadata.deviceId
        && key.recipientId === keys.metadata.recipientId
        && key.hpkeFingerprint === keys.hpke.fingerprint
        && key.signingFingerprint === keys.signing.fingerprint);
      if (!registered) throw new Error("La copia no corresponde a una clave pública activa de este tenant.");
      setUnlocked(keys);
      setPassphrase("");
      setConfirmation("");
      setBackupFile(undefined);
      if (fileRef.current) fileRef.current.value = "";
    },
  });
  const revokeMutation = useMutation({
    mutationFn: (key: CustodyPublicKey) => api.revokeCustodyKey(key.keyId, key.version, revokeReasonCode),
    onSuccess: async (_value, key) => {
      if (unlocked?.metadata.deviceId === key.deviceId) setUnlocked(undefined);
      await client.invalidateQueries({ queryKey: ["custody-keys", session.tenant.id] });
      await client.invalidateQueries({ queryKey: ["round-custody", session.tenant.id, roundId] });
    },
  });
  const freezeMutation = useMutation({
    mutationFn: () => api.freezeRoundCustody(roundId!, round!.round.version, selectedKeys),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["round-custody", session.tenant.id, roundId] });
    },
  });
  const createManifestMutation = useMutation({
    mutationFn: () => api.createTallyManifest(roundId!, round!.round.version, custody!.version),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["active-round", session.tenant.id] });
      await client.invalidateQueries({ queryKey: ["tally-manifest", session.tenant.id, roundId] });
    },
  });
  const attestMutation = useMutation({
    mutationFn: async () => {
      if (!round || !manifest || !unlocked) throw new Error("Faltan la ronda, el manifiesto o la clave privada desbloqueada.");
      if (manifest.custodian.recipientId !== unlocked.metadata.recipientId
        || manifest.custodian.deviceId !== unlocked.metadata.deviceId
        || manifest.custodian.hpkeFingerprint !== unlocked.hpke.fingerprint
        || manifest.custodian.signingFingerprint !== unlocked.signing.fingerprint) {
        throw new Error("La copia desbloqueada no corresponde al custodio congelado para esta ronda.");
      }
      const candidateIds = round.candidates.filter((candidate) => candidate.eligible).map((candidate) => candidate.id);
      const rules = { candidateIds, minSelections: 1, maxSelections: round.round.maxSelections, allowAbstention: true } as const;
      const ballots: BallotPayload[] = [];
      for (const entry of manifest.entries) {
        const verified = await verifyBallotEnvelope(entry.envelope);
        if (verified.envelopeHash !== entry.envelopeHash || await computeBallotContentHash(verified) !== entry.contentHash) {
          throw new Error("Una boleta no coincide con las huellas del manifiesto.");
        }
        if (verified.aad.tenantId !== session.tenant.id
          || verified.aad.cycleId !== round.round.cycleId
          || verified.aad.roundId !== round.round.id
          || verified.aad.candidateSetHash !== round.round.candidateSetHash
          || verified.aad.rulesHash !== round.round.rulesHash
          || verified.aad.purpose !== BALLOT_PURPOSE
          || verified.aad.schemaVersion !== BALLOT_SCHEMA_VERSION) {
          throw new Error("Una boleta no pertenece exactamente al contexto congelado.");
        }
        ballots.push(await openBallotEnvelope({ envelope: verified, recipient: unlocked.hpke, expectedAad: verified.aad, rules }));
      }
      const aggregate = createTallyAggregate({
        ...rules,
        vacancies: round.round.vacancies,
        rule: manifest.manifest.decisionRule,
        ballots,
      });
      const aggregateHash = await computeTallyAggregateHash(aggregate);
      const context = createTallyAttestationContext({
        tenantId: session.tenant.id,
        roundId: round.round.id,
        manifestId: manifest.manifest.manifestId,
        manifestHash: manifest.manifest.manifestHash,
        aggregateHash,
      });
      const signed = await signTallyAttestation(unlocked.signing, context);
      const result = await api.attestTallyManifest(round.round.id, manifest.manifest.version, aggregate, signed.signature);
      setLocalAggregate(aggregate);
      return result;
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["tally-manifest", session.tenant.id, roundId] });
    },
  });
  const publishMutation = useMutation({
    mutationFn: () => api.publishTallyAggregate(roundId!, round!.round.version, manifest!.manifest.version),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["active-round", session.tenant.id] }),
        client.invalidateQueries({ queryKey: ["tally-manifest", session.tenant.id, roundId] }),
        client.invalidateQueries({ queryKey: ["published-aggregate", session.tenant.id, roundId] }),
        client.invalidateQueries({ queryKey: ["dashboard"] }),
      ]);
    },
  });

  const operationError = registerMutation.error ?? rotateMutation.error ?? unlockMutation.error ?? revokeMutation.error
    ?? freezeMutation.error ?? createManifestMutation.error ?? attestMutation.error ?? publishMutation.error;
  const result = publishMutation.data ?? published;
  const tally = result?.aggregate ?? localAggregate;
  const loading = keysQuery.isLoading;

  return <>
    <PageTitle eyebrow={t.eyebrow} title={t.title} description={t.description} action={<Badge variant="outline"><LockKeyhole /> HPKE · Ed25519</Badge>} />
    {!mayCustody && <Alert><ShieldX /><AlertTitle>{t.noPermission}</AlertTitle><AlertDescription>tally.custody</AlertDescription></Alert>}
    {operationError && <Alert variant="destructive"><AlertCircle /><AlertTitle>{t.safeStop}</AlertTitle><AlertDescription>{errorMessage(operationError, locale, t)}</AlertDescription></Alert>}
    <div className="custody-layout">
      {mayCustody && <section className="surface-card custody-ceremony">
        <div className="card-heading"><div><p className="eyebrow">{t.ceremonyEyebrow}</p><h2>{t.ceremony}</h2></div><span className="form-icon"><KeyRound /></span></div>
        <p>{t.ceremonyHelp}</p>
        <div className="form-grid two-col">
          <div><Label htmlFor="custody-passphrase">{t.passphrase}</Label><Input id="custody-passphrase" type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} minLength={16} /></div>
          <div><Label htmlFor="custody-confirm">{t.confirm}</Label><Input id="custody-confirm" type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} minLength={16} /></div>
        </div>
        <Button onClick={() => registerMutation.mutate()} disabled={registerMutation.isPending || passphrase.length < 16 || passphrase !== confirmation}>
          {registerMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Download />} {t.create}
        </Button>
        <div className="custody-divider" />
        <h3>{t.restore}</h3><p>{t.restoreHelp}</p>
        <div className="form-grid two-col">
          <div><Label htmlFor="custody-backup">{t.backup}</Label><Input ref={fileRef} id="custody-backup" type="file" accept="application/json,.json" onChange={(event) => setBackupFile(event.target.files?.[0])} /></div>
          <div className="align-end"><Button variant="outline" onClick={() => unlockMutation.mutate()} disabled={!backupFile || passphrase.length < 16 || unlockMutation.isPending}>{unlockMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Upload />} {t.unlock}</Button></div>
        </div>
        {unlocked && <Alert className="success-alert"><ShieldCheck /><AlertTitle>{t.unlocked}</AlertTitle><AlertDescription>{unlocked.metadata.recipientId}<br /><code>{unlocked.hpke.fingerprint}</code></AlertDescription></Alert>}
      </section>}

      {mayCustody && <section className="surface-card custody-registry">
        <div className="card-heading"><div><p className="eyebrow">{t.registryEyebrow}</p><h2>{t.keys}</h2></div><Badge variant="outline">{activeKeys.length}</Badge></div>
        <label className="mb-4 grid max-w-sm gap-1 text-sm font-medium">{message(locale, "screen.custodyView.e084bbfcd603")}<select className="h-10 rounded-md border bg-white px-3 text-sm" value={revokeReasonCode} onChange={(event) => setRevokeReasonCode(event.target.value as CustodyRevokeReasonCode)}>{custodyRevokeReasonCodes.map((reasonCode) => <option key={reasonCode} value={reasonCode}>{custodyRevokeReasonLabel(locale, reasonCode)}</option>)}</select></label>
        {loading ? <LoadingBlock locale={locale} /> : keysQuery.error ? <DataError locale={locale} /> : <div className="custody-key-list">{(keysQuery.data ?? []).map((key) => {
          const own = key.custodianIdentityId === session.user.id;
          const selected = selectedKeys.includes(key.keyId);
          return <article key={key.keyId} className={key.status === "active" ? "" : "muted"}>
            <Checkbox aria-label={`${t.selectKey} ${key.recipientId}`} checked={selected} disabled={key.status !== "active" || Boolean(custody)} onCheckedChange={(checked) => setSelectedKeys((current) => checked ? [...current, key.keyId] : current.filter((id) => id !== key.keyId))} />
            <span className="metric-icon cyan"><Fingerprint /></span>
            <div><strong>{key.recipientId}</strong><small>{key.hpkeFingerprint}</small><small>{key.signingFingerprint}</small></div>
            <div className="custody-key-actions"><Badge variant={key.status === "active" ? "default" : "outline"}>{statusLabel(key, t)}{own ? ` · ${t.yours}` : ""}</Badge>{own && key.status === "active" && <><Button size="sm" variant="outline" onClick={() => rotateMutation.mutate(key)} disabled={passphrase.length < 16 || passphrase !== confirmation || rotateMutation.isPending}><RotateCw /> {t.rotate}</Button><Button size="sm" variant="outline" onClick={() => revokeMutation.mutate(key)} disabled={revokeMutation.isPending}><ShieldX /> {t.revoke}</Button></>}</div>
          </article>;
        })}</div>}
      </section>}
    </div>

    <section className="surface-card custody-round">
      <div className="card-heading"><div><p className="eyebrow">{t.reconcileEyebrow}</p><h2>{round ? localizedName(round.round.officeNames, locale, round.round.officeName) : t.noVote}</h2></div>{round && <Badge className="phase-badge">{phaseLabel(locale, round.round.phase)}</Badge>}</div>
      {roundQuery.isLoading ? <LoadingBlock locale={locale} /> : roundQuery.isError ? <DataError locale={locale} title={t.roundLoadFailed} /> : !round ? <Alert><Vote /><AlertTitle>{t.noVote}</AlertTitle><AlertDescription>{t.noVoteHelp}</AlertDescription></Alert> : <>
        {custodyQuery.isLoading && <LoadingBlock locale={locale} />}
        {custodyQuery.isError && <DataError locale={locale} title={t.custodyLoadFailed} />}
        {!custody && !custodyQuery.isLoading && !custodyQuery.isError && mayCustody && <div className="custody-freeze">
          <p>{t.choose}</p>
          <label><Checkbox checked={fingerprintsVerified} onCheckedChange={(value) => setFingerprintsVerified(value === true)} /> <span>{t.verified}</span></label>
          <Button onClick={() => freezeMutation.mutate()} disabled={freezeMutation.isPending || distinctSelectedIdentities < 2 || !fingerprintsVerified || !["LISTA_CONFIRMADA", "VOTACION_ABIERTA"].includes(round.round.phase)}>{freezeMutation.isPending ? <LoaderCircle className="animate-spin" /> : <LockKeyhole />} {t.freeze}</Button>
        </div>}
        {custody && <CustodySummary custody={custody} locale={locale} labels={t} timeZone={session.tenant.timezone} />}
        {custody && manifestQuery.isLoading && <LoadingBlock locale={locale} />}
        {custody && manifestQuery.isError && <DataError locale={locale} title={t.manifestLoadFailed} />}
        {custody && !manifest && !manifestQuery.isLoading && !manifestQuery.isError && mayRecount && ["VOTACION_CERRADA", "ESCRUTINIO"].includes(round.round.phase) && <Button onClick={() => createManifestMutation.mutate()} disabled={createManifestMutation.isPending}>{createManifestMutation.isPending ? <LoaderCircle className="animate-spin" /> : <ArchiveRestore />} {t.fixManifest}</Button>}
        {manifest && <div className="manifest-panel">
          <div><h3>{t.manifest}</h3><p><code>{manifest.manifest.manifestHash}</code></p><p>{manifest.manifest.entryCount} {t.received.toLocaleLowerCase()} · v{manifest.manifest.version}</p></div>
          <Badge variant={manifest.manifest.state === "disputed" ? "destructive" : "outline"}>{manifestStateCopy[locale][manifest.manifest.state] ?? manifest.manifest.state}</Badge>
          {manifest.manifest.state === "disputed" && <Alert variant="destructive"><ShieldX /><AlertTitle>{t.disputed}</AlertTitle></Alert>}
          {manifest.manifest.state === "awaiting_attestations" && <p>{t.waiting}</p>}
          {mayRecount && manifest.manifest.state !== "disputed" && manifest.manifest.state !== "published" && <Button onClick={() => attestMutation.mutate()} disabled={!unlocked || attestMutation.isPending}>{attestMutation.isPending ? <LoaderCircle className="animate-spin" /> : <ShieldCheck />} {t.count}</Button>}
          {manifest.manifest.state === "publishable" && mayPublish && <Button onClick={() => publishMutation.mutate()} disabled={publishMutation.isPending}>{publishMutation.isPending ? <LoaderCircle className="animate-spin" /> : <Vote />} {t.publish}</Button>}
        </div>}
        {publishedQuery.isError && <DataError locale={locale} title={t.publishedLoadFailed} />}
        {tally && !publishedQuery.isError && <AggregateSummary aggregate={tally} published={Boolean(result)} labels={t} locale={locale} />}
      </>}
    </section>
  </>;
}

function CustodySummary({ custody, locale, labels, timeZone }: { custody: RoundCustody; locale: Locale; labels: Labels; timeZone: string }) {
  return <div className="custody-snapshot"><div><strong>{custody.custodians.length} {labels.frozenCustodians}</strong><small>{labels.version} {custody.version} · {formatInTenantTimeZone(custody.frozenAt, locale, timeZone, { dateStyle: "medium", timeStyle: "short" })}</small></div>{custody.custodians.map((key) => <code key={key.keyId}>{key.recipientId} · {key.hpkeFingerprint.slice(0, 24)}…</code>)}</div>;
}

function AggregateSummary({ aggregate, published, labels, locale }: { aggregate: TallyAggregate; published: boolean; labels: Labels; locale: Locale }) {
  return <article className="aggregate-card">
    <div className="card-heading"><div><p className="eyebrow">{published ? labels.published : labels.localVerified}</p><h3>{labels.decision}: {decisionStatusCopy[locale][aggregate.decision.status] ?? aggregate.decision.status}</h3></div>{published && <Badge><Check /> {labels.publishedLabel}</Badge>}</div>
    <div className="aggregate-metrics"><div><span>{labels.received}</span><strong>{aggregate.receivedBallots}</strong></div><div><span>{labels.nonAbstaining}</span><strong>{aggregate.nonAbstainingBallots}</strong></div><div><span>{labels.abstentions}</span><strong>{aggregate.abstentions}</strong></div></div>
    <div className="aggregate-list">{aggregate.candidates.map((candidate) => <div key={candidate.candidateId}><code>{candidate.candidateId}</code><strong>{candidate.votes}</strong></div>)}</div>
  </article>;
}
