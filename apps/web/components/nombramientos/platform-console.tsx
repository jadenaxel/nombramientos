"use client";

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, ArchiveRestore, Ban, Building2, Check, Copy, Database, Download, FileKey2, LoaderCircle, MailPlus, Plus, RefreshCw, ServerCog, ShieldCheck, TimerReset, Undo2 } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, ApiError, type Locale } from "@/lib/api";
import { message, localizedApiError } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";
import { InitialAdminRecoveryConsole } from "./initial-admin-recovery-console";

const copy = {
  es: { eyebrow: message("es", "screen.platformConsole.2d13cee68c2f"), title: message("es", "screen.platformConsole.770c5f70f04c"), description: message("es", "screen.platformConsole.7f2bedd4fc5b"), boundary: message("es", "screen.platformConsole.e496ca519de1"), boundaryBody: message("es", "screen.platformConsole.ec7749370b0c"), newTenant: message("es", "screen.platformConsole.79ec5ddba8e4"), name: message("es", "screen.platformConsole.19c1f3652481"), slug: message("es", "screen.platformConsole.2a1deb4ebac2"), kind: message("es", "screen.platformConsole.1656c049b119"), real: message("es", "screen.platformConsole.906608f896fe"), demo: message("es", "screen.platformConsole.59f5eb014e96"), timezone: message("es", "screen.platformConsole.1f470c29ba5f"), locale: message("es", "screen.platformConsole.28d05ccf3a42"), queue: message("es", "screen.platformConsole.cdf938a12814"), tenants: message("es", "screen.platformConsole.f7563f4e5757"), suspend: message("es", "screen.platformConsole.b0ba1fbda2e2"), reason: message("es", "screen.platformConsole.ca3bbc4fdee1"), cancel: message("es", "screen.platformConsole.18e29ea869c8"), confirm: message("es", "screen.platformConsole.07a389482d2c"), saved: message("es", "screen.platformConsole.9dd3d54cfa88"), failed: message("es", "screen.platformConsole.5ab5f1fae558"), loadFailed: message("es", "screen.platformConsole.6bb1af92a7a3"), retry: message("es", "screen.platformConsole.fe0bfb5b9dec"), attempt: message("es", "screen.platformConsole.ed85afb744fe"), requested: message("es", "screen.platformConsole.6f79baec0013"), queued: message("es", "screen.platformConsole.49b402e4bdc5"), running: message("es", "screen.platformConsole.8e003ba24bd1"), completed: message("es", "screen.platformConsole.47342d67a92a"), active: message("es", "screen.platformConsole.bdb96a52baa8"), provisioning: message("es", "screen.platformConsole.3e5b495ffbad"), suspended: message("es", "screen.platformConsole.4f0b500849dc"), decommissionPending: message("es", "screen.platformConsole.e540f18949a4"), failedState: message("es", "screen.platformConsole.d0a6fbabc0c0") },
  en: { eyebrow: message("en", "screen.platformConsole.2d13cee68c2f"), title: message("en", "screen.platformConsole.770c5f70f04c"), description: message("en", "screen.platformConsole.7f2bedd4fc5b"), boundary: message("en", "screen.platformConsole.e496ca519de1"), boundaryBody: message("en", "screen.platformConsole.ec7749370b0c"), newTenant: message("en", "screen.platformConsole.79ec5ddba8e4"), name: message("en", "screen.platformConsole.19c1f3652481"), slug: message("en", "screen.platformConsole.2a1deb4ebac2"), kind: message("en", "screen.platformConsole.1656c049b119"), real: message("en", "screen.platformConsole.906608f896fe"), demo: message("en", "screen.platformConsole.59f5eb014e96"), timezone: message("en", "screen.platformConsole.1f470c29ba5f"), locale: message("en", "screen.platformConsole.28d05ccf3a42"), queue: message("en", "screen.platformConsole.cdf938a12814"), tenants: message("en", "screen.platformConsole.f7563f4e5757"), suspend: message("en", "screen.platformConsole.b0ba1fbda2e2"), reason: message("en", "screen.platformConsole.ca3bbc4fdee1"), cancel: message("en", "screen.platformConsole.18e29ea869c8"), confirm: message("en", "screen.platformConsole.07a389482d2c"), saved: message("en", "screen.platformConsole.9dd3d54cfa88"), failed: message("en", "screen.platformConsole.5ab5f1fae558"), loadFailed: message("en", "screen.platformConsole.6bb1af92a7a3"), retry: message("en", "screen.platformConsole.fe0bfb5b9dec"), attempt: message("en", "screen.platformConsole.ed85afb744fe"), requested: message("en", "screen.platformConsole.6f79baec0013"), queued: message("en", "screen.platformConsole.49b402e4bdc5"), running: message("en", "screen.platformConsole.8e003ba24bd1"), completed: message("en", "screen.platformConsole.47342d67a92a"), active: message("en", "screen.platformConsole.bdb96a52baa8"), provisioning: message("en", "screen.platformConsole.3e5b495ffbad"), suspended: message("en", "screen.platformConsole.4f0b500849dc"), decommissionPending: message("en", "screen.platformConsole.e540f18949a4"), failedState: message("en", "screen.platformConsole.d0a6fbabc0c0") },
  fr: { eyebrow: message("fr", "screen.platformConsole.2d13cee68c2f"), title: message("fr", "screen.platformConsole.770c5f70f04c"), description: message("fr", "screen.platformConsole.7f2bedd4fc5b"), boundary: message("fr", "screen.platformConsole.e496ca519de1"), boundaryBody: message("fr", "screen.platformConsole.ec7749370b0c"), newTenant: message("fr", "screen.platformConsole.79ec5ddba8e4"), name: message("fr", "screen.platformConsole.19c1f3652481"), slug: message("fr", "screen.platformConsole.2a1deb4ebac2"), kind: message("fr", "screen.platformConsole.1656c049b119"), real: message("fr", "screen.platformConsole.906608f896fe"), demo: message("fr", "screen.platformConsole.59f5eb014e96"), timezone: message("fr", "screen.platformConsole.1f470c29ba5f"), locale: message("fr", "screen.platformConsole.28d05ccf3a42"), queue: message("fr", "screen.platformConsole.cdf938a12814"), tenants: message("fr", "screen.platformConsole.f7563f4e5757"), suspend: message("fr", "screen.platformConsole.b0ba1fbda2e2"), reason: message("fr", "screen.platformConsole.ca3bbc4fdee1"), cancel: message("fr", "screen.platformConsole.18e29ea869c8"), confirm: message("fr", "screen.platformConsole.07a389482d2c"), saved: message("fr", "screen.platformConsole.9dd3d54cfa88"), failed: message("fr", "screen.platformConsole.5ab5f1fae558"), loadFailed: message("fr", "screen.platformConsole.6bb1af92a7a3"), retry: message("fr", "screen.platformConsole.fe0bfb5b9dec"), attempt: message("fr", "screen.platformConsole.ed85afb744fe"), requested: message("fr", "screen.platformConsole.6f79baec0013"), queued: message("fr", "screen.platformConsole.49b402e4bdc5"), running: message("fr", "screen.platformConsole.8e003ba24bd1"), completed: message("fr", "screen.platformConsole.47342d67a92a"), active: message("fr", "screen.platformConsole.bdb96a52baa8"), provisioning: message("fr", "screen.platformConsole.3e5b495ffbad"), suspended: message("fr", "screen.platformConsole.4f0b500849dc"), decommissionPending: message("fr", "screen.platformConsole.e540f18949a4"), failedState: message("fr", "screen.platformConsole.d0a6fbabc0c0") },
} as const;

const workerCopy = {
  es: { title: message("es", "screen.platformConsole.9fe0a601dcde"), healthy: message("es", "screen.platformConsole.9a36703428be"), unavailable: message("es", "screen.platformConsole.4d6140b354ec"), heartbeat: message("es", "screen.platformConsole.35c9a9ec3538"), processed: message("es", "screen.platformConsole.a94069852d00") },
  en: { title: message("en", "screen.platformConsole.9fe0a601dcde"), healthy: message("en", "screen.platformConsole.9a36703428be"), unavailable: message("en", "screen.platformConsole.4d6140b354ec"), heartbeat: message("en", "screen.platformConsole.35c9a9ec3538"), processed: message("en", "screen.platformConsole.a94069852d00") },
  fr: { title: message("fr", "screen.platformConsole.9fe0a601dcde"), healthy: message("fr", "screen.platformConsole.9a36703428be"), unavailable: message("fr", "screen.platformConsole.4d6140b354ec"), heartbeat: message("fr", "screen.platformConsole.35c9a9ec3538"), processed: message("fr", "screen.platformConsole.a94069852d00") },
} as const;

const activationCopy = {
  es: { mode: message("es", "screen.platformConsole.ada6198b0690"), invite: message("es", "screen.platformConsole.444bacbd3d58"), pending: message("es", "screen.platformConsole.60dcd6faecc6"), email: message("es", "screen.platformConsole.9ee9c73827ac"), expiry: message("es", "screen.platformConsole.30d60832098a"), hours: message("es", "screen.platformConsole.db98a775be8f"), tokenTitle: message("es", "screen.platformConsole.bebd0c6de1a5"), tokenBody: message("es", "screen.platformConsole.b48946bcc364"), copy: message("es", "screen.platformConsole.d79e243e7572"), copied: message("es", "screen.platformConsole.c33d056f393f"), copyFailed: message("es", "screen.platformConsole.3692caf83ed5"), open: message("es", "screen.platformConsole.1586643c4817"), activate: message("es", "screen.platformConsole.20600738778e"), awaiting: message("es", "screen.platformConsole.062dbef2b4fe"), invitationPending: message("es", "screen.platformConsole.82bf3bdc50b1"), adminActive: message("es", "screen.platformConsole.0f556577810a") },
  en: { mode: message("en", "screen.platformConsole.ada6198b0690"), invite: message("en", "screen.platformConsole.444bacbd3d58"), pending: message("en", "screen.platformConsole.60dcd6faecc6"), email: message("en", "screen.platformConsole.9ee9c73827ac"), expiry: message("en", "screen.platformConsole.30d60832098a"), hours: message("en", "screen.platformConsole.db98a775be8f"), tokenTitle: message("en", "screen.platformConsole.bebd0c6de1a5"), tokenBody: message("en", "screen.platformConsole.b48946bcc364"), copy: message("en", "screen.platformConsole.d79e243e7572"), copied: message("en", "screen.platformConsole.c33d056f393f"), copyFailed: message("en", "screen.platformConsole.3692caf83ed5"), open: message("en", "screen.platformConsole.1586643c4817"), activate: message("en", "screen.platformConsole.20600738778e"), awaiting: message("en", "screen.platformConsole.062dbef2b4fe"), invitationPending: message("en", "screen.platformConsole.82bf3bdc50b1"), adminActive: message("en", "screen.platformConsole.0f556577810a") },
  fr: { mode: message("fr", "screen.platformConsole.ada6198b0690"), invite: message("fr", "screen.platformConsole.444bacbd3d58"), pending: message("fr", "screen.platformConsole.60dcd6faecc6"), email: message("fr", "screen.platformConsole.9ee9c73827ac"), expiry: message("fr", "screen.platformConsole.30d60832098a"), hours: message("fr", "screen.platformConsole.db98a775be8f"), tokenTitle: message("fr", "screen.platformConsole.bebd0c6de1a5"), tokenBody: message("fr", "screen.platformConsole.b48946bcc364"), copy: message("fr", "screen.platformConsole.d79e243e7572"), copied: message("fr", "screen.platformConsole.c33d056f393f"), copyFailed: message("fr", "screen.platformConsole.3692caf83ed5"), open: message("fr", "screen.platformConsole.1586643c4817"), activate: message("fr", "screen.platformConsole.20600738778e"), awaiting: message("fr", "screen.platformConsole.062dbef2b4fe"), invitationPending: message("fr", "screen.platformConsole.82bf3bdc50b1"), adminActive: message("fr", "screen.platformConsole.0f556577810a") },
} as const;

const suspensionCopy = {
  es: { securityReview: message("es", "screen.platformConsole.d1e0e70b688b"), operationalHold: message("es", "screen.platformConsole.918728f82a96"), institutionRequest: message("es", "screen.platformConsole.9f492f7b10d6"), complianceReview: message("es", "screen.platformConsole.0ed584afc92c") },
  en: { securityReview: message("en", "screen.platformConsole.d1e0e70b688b"), operationalHold: message("en", "screen.platformConsole.918728f82a96"), institutionRequest: message("en", "screen.platformConsole.9f492f7b10d6"), complianceReview: message("en", "screen.platformConsole.0ed584afc92c") },
  fr: { securityReview: message("fr", "screen.platformConsole.d1e0e70b688b"), operationalHold: message("fr", "screen.platformConsole.918728f82a96"), institutionRequest: message("fr", "screen.platformConsole.9f492f7b10d6"), complianceReview: message("fr", "screen.platformConsole.0ed584afc92c") },
} as const;

const reactivationCopy = {
  es: { open: message("es", "screen.platformConsole.39202ffa37b7"), title: message("es", "screen.platformConsole.172705dacc3f"), reason: message("es", "screen.platformConsole.9a8d467e5f10"), security: message("es", "screen.platformConsole.8b64537fd1f6"), operational: message("es", "screen.platformConsole.57ab3c37d3fd"), institution: message("es", "screen.platformConsole.f3392141418b"), compliance: message("es", "screen.platformConsole.818b2c0ad069"), confirm: message("es", "screen.platformConsole.26e17a71ca03"), loginRequired: message("es", "screen.platformConsole.eda5a7be86de") },
  en: { open: message("en", "screen.platformConsole.39202ffa37b7"), title: message("en", "screen.platformConsole.172705dacc3f"), reason: message("en", "screen.platformConsole.9a8d467e5f10"), security: message("en", "screen.platformConsole.8b64537fd1f6"), operational: message("en", "screen.platformConsole.57ab3c37d3fd"), institution: message("en", "screen.platformConsole.f3392141418b"), compliance: message("en", "screen.platformConsole.818b2c0ad069"), confirm: message("en", "screen.platformConsole.26e17a71ca03"), loginRequired: message("en", "screen.platformConsole.eda5a7be86de") },
  fr: { open: message("fr", "screen.platformConsole.39202ffa37b7"), title: message("fr", "screen.platformConsole.172705dacc3f"), reason: message("fr", "screen.platformConsole.9a8d467e5f10"), security: message("fr", "screen.platformConsole.8b64537fd1f6"), operational: message("fr", "screen.platformConsole.57ab3c37d3fd"), institution: message("fr", "screen.platformConsole.f3392141418b"), compliance: message("fr", "screen.platformConsole.818b2c0ad069"), confirm: message("fr", "screen.platformConsole.26e17a71ca03"), loginRequired: message("fr", "screen.platformConsole.eda5a7be86de") },
} as const;

const lifecycleCopy = {
  es: { title: message("es", "screen.platformConsole.be30df8b7913"), export: message("es", "screen.platformConsole.5b625132452b"), exportQueued: message("es", "screen.platformConsole.82cb43d6590b"), exportReady: message("es", "screen.platformConsole.da3892bd411a"), exportRunning: message("es", "screen.platformConsole.3570d58fd1ca"), exportFailed: message("es", "screen.platformConsole.cc1c2e010811"), download: message("es", "screen.platformConsole.04be1b030cae"), manifest: message("es", "screen.platformConsole.c64eb9a9504e"), recovery: message("es", "screen.platformConsole.5a548dd965db"), custody: message("es", "screen.platformConsole.20716a798b10"), schedule: message("es", "screen.platformConsole.53062d3c3be3"), scheduleTitle: message("es", "screen.platformConsole.c6b6add373cb"), retention: message("es", "screen.platformConsole.f9ee739c5b1e"), days: message("es", "screen.platformConsole.a22b86dd70c8"), reason: message("es", "screen.platformConsole.c8a81af9b3d9"), institutionRequest: message("es", "screen.platformConsole.9f492f7b10d6"), duplicateTenant: message("es", "screen.platformConsole.12dc5ad00475"), serviceEnded: message("es", "screen.platformConsole.61471b429020"), legalRetention: message("es", "screen.platformConsole.3ea7d987628c"), confirmSchedule: message("es", "screen.platformConsole.338553690c7b"), pending: message("es", "screen.platformConsole.e540f18949a4"), until: message("es", "screen.platformConsole.e38e84d90e05"), cancelDecommission: message("es", "screen.platformConsole.9674a9f588a7"), reversible: message("es", "screen.platformConsole.01ca9c32848c"), checksum: message("es", "screen.platformConsole.433d2d323804"), currentBlocked: message("es", "screen.platformConsole.529b75fa912a"), authorization: message("es", "screen.platformConsole.7e5c6306e372") },
  en: { title: message("en", "screen.platformConsole.be30df8b7913"), export: message("en", "screen.platformConsole.5b625132452b"), exportQueued: message("en", "screen.platformConsole.82cb43d6590b"), exportReady: message("en", "screen.platformConsole.da3892bd411a"), exportRunning: message("en", "screen.platformConsole.3570d58fd1ca"), exportFailed: message("en", "screen.platformConsole.cc1c2e010811"), download: message("en", "screen.platformConsole.04be1b030cae"), manifest: message("en", "screen.platformConsole.c64eb9a9504e"), recovery: message("en", "screen.platformConsole.5a548dd965db"), custody: message("en", "screen.platformConsole.20716a798b10"), schedule: message("en", "screen.platformConsole.53062d3c3be3"), scheduleTitle: message("en", "screen.platformConsole.c6b6add373cb"), retention: message("en", "screen.platformConsole.f9ee739c5b1e"), days: message("en", "screen.platformConsole.a22b86dd70c8"), reason: message("en", "screen.platformConsole.c8a81af9b3d9"), institutionRequest: message("en", "screen.platformConsole.9f492f7b10d6"), duplicateTenant: message("en", "screen.platformConsole.12dc5ad00475"), serviceEnded: message("en", "screen.platformConsole.61471b429020"), legalRetention: message("en", "screen.platformConsole.3ea7d987628c"), confirmSchedule: message("en", "screen.platformConsole.338553690c7b"), pending: message("en", "screen.platformConsole.e540f18949a4"), until: message("en", "screen.platformConsole.e38e84d90e05"), cancelDecommission: message("en", "screen.platformConsole.9674a9f588a7"), reversible: message("en", "screen.platformConsole.01ca9c32848c"), checksum: message("en", "screen.platformConsole.433d2d323804"), currentBlocked: message("en", "screen.platformConsole.529b75fa912a"), authorization: message("en", "screen.platformConsole.7e5c6306e372") },
  fr: { title: message("fr", "screen.platformConsole.be30df8b7913"), export: message("fr", "screen.platformConsole.5b625132452b"), exportQueued: message("fr", "screen.platformConsole.82cb43d6590b"), exportReady: message("fr", "screen.platformConsole.da3892bd411a"), exportRunning: message("fr", "screen.platformConsole.3570d58fd1ca"), exportFailed: message("fr", "screen.platformConsole.cc1c2e010811"), download: message("fr", "screen.platformConsole.04be1b030cae"), manifest: message("fr", "screen.platformConsole.c64eb9a9504e"), recovery: message("fr", "screen.platformConsole.5a548dd965db"), custody: message("fr", "screen.platformConsole.20716a798b10"), schedule: message("fr", "screen.platformConsole.53062d3c3be3"), scheduleTitle: message("fr", "screen.platformConsole.c6b6add373cb"), retention: message("fr", "screen.platformConsole.f9ee739c5b1e"), days: message("fr", "screen.platformConsole.a22b86dd70c8"), reason: message("fr", "screen.platformConsole.c8a81af9b3d9"), institutionRequest: message("fr", "screen.platformConsole.9f492f7b10d6"), duplicateTenant: message("fr", "screen.platformConsole.12dc5ad00475"), serviceEnded: message("fr", "screen.platformConsole.61471b429020"), legalRetention: message("fr", "screen.platformConsole.3ea7d987628c"), confirmSchedule: message("fr", "screen.platformConsole.338553690c7b"), pending: message("fr", "screen.platformConsole.e540f18949a4"), until: message("fr", "screen.platformConsole.e38e84d90e05"), cancelDecommission: message("fr", "screen.platformConsole.9674a9f588a7"), reversible: message("fr", "screen.platformConsole.01ca9c32848c"), checksum: message("fr", "screen.platformConsole.433d2d323804"), currentBlocked: message("fr", "screen.platformConsole.529b75fa912a"), authorization: message("fr", "screen.platformConsole.7e5c6306e372") },
} as const;

export function PlatformConsole({ locale, permissions, currentIdentityId }: { locale: Locale; permissions: readonly string[]; currentIdentityId: string }) {
  const labels = copy[locale];
  const workerLabels = workerCopy[locale];
  const activationLabels = activationCopy[locale];
  const suspensionLabels = suspensionCopy[locale];
  const reactivationLabels = reactivationCopy[locale];
  const lifecycleLabels = lifecycleCopy[locale];
  const canProvision = permissions.includes("platform.tenant.provision");
  const canManageInitialAdmin = permissions.includes("platform.security.manage");
  const canSuspend = permissions.includes("platform.tenant.suspend");
  const canReactivate = permissions.includes("platform.tenant.reactivate");
  const canExport = permissions.includes("platform.tenant.export.request");
  const canDownloadExport = permissions.includes("platform.tenant.export.download");
  const canScheduleDecommission = permissions.includes("platform.tenant.decommission.schedule");
  const canCancelDecommission = permissions.includes("platform.tenant.decommission.cancel");
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ["platform-tenants"], queryFn: api.platformTenants, refetchInterval: 5_000 });
  const [tenantId, setTenantId] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [slug, setSlug] = useState("");
  const [kind, setKind] = useState<"demo" | "real">("real");
  const [timezone, setTimezone] = useState("America/Santo_Domingo");
  const [tenantLocale, setTenantLocale] = useState<Locale>("es");
  const [initialAdminMode, setInitialAdminMode] = useState<"invitation" | "pending">(canManageInitialAdmin ? "invitation" : "pending");
  const [initialAdminEmail, setInitialAdminEmail] = useState("");
  const [initialAdminExpiry, setInitialAdminExpiry] = useState(72);
  const [oneTime, setOneTime] = useState<{ token: string; email: string; expiresAt: string }>();
  const [activating, setActivating] = useState<string>();
  const [activationEmail, setActivationEmail] = useState("");
  const [activationExpiry, setActivationExpiry] = useState(72);
  const [suspending, setSuspending] = useState<string>();
  const [reason, setReason] = useState<"security_review" | "operational_hold" | "institution_request" | "compliance_review">("operational_hold");
  const [reactivating, setReactivating] = useState<string>();
  const [reactivationReason, setReactivationReason] = useState<"security_review_completed" | "operational_hold_resolved" | "institution_request_resumed" | "compliance_review_completed">("operational_hold_resolved");
  const [decommissioning, setDecommissioning] = useState<string>();
  const [retentionDays, setRetentionDays] = useState(90);
  const [decommissionReason, setDecommissionReason] = useState<"institution_request" | "duplicate_tenant" | "service_ended" | "legal_retention">("institution_request");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string }>();
  const [copiedToken, setCopiedToken] = useState(false);
  const [clipboardError, setClipboardError] = useState<string>();

  useEffect(() => {
    const purge = () => {
      setOneTime(undefined);
      setCopiedToken(false);
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
      setCopiedToken(false);
      setClipboardError(undefined);
    }, Number.isFinite(remaining) ? Math.max(0, Math.min(remaining, 2_147_483_647)) : 0);
    return () => window.clearTimeout(timer);
  }, [oneTime]);

  async function copyOneTimeToken() {
    if (!oneTime) return;
    setClipboardError(undefined);
    try {
      const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname);
      const invitationOrigin = loopback ? `${window.location.protocol}//localhost:3000` : window.location.origin;
      const invitationUrl = new URL(`/${locale}/auth/invitation`, invitationOrigin).toString();
      await navigator.clipboard.writeText(`${invitationUrl}\n${oneTime.token}`);
      setCopiedToken(true);
      window.setTimeout(() => setCopiedToken(false), 1_500);
    } catch {
      setCopiedToken(false);
      setClipboardError(activationLabels.copyFailed);
    }
  }

  function showOneTimeToken(token: string, email: string, expiresAt: string) {
    setCopiedToken(false);
    setClipboardError(undefined);
    setOneTime({ token, email, expiresAt });
  }

  async function run<T>(action: () => Promise<T>, after?: (result: T) => void) {
    setBusy(true); setNotice(undefined);
    try {
      const result = await action(); after?.(result);
      await queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setNotice({ tone: "success", text: labels.saved });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof ApiError ? localizedApiError(error, locale) : labels.failed });
    } finally { setBusy(false); }
  }

  async function downloadTenantExport(tenant: NonNullable<typeof query.data>["items"][number]) {
    const current = tenant.latestExport;
    if (!current?.publicManifest || current.state !== "ready") return;
    setBusy(true); setNotice(undefined);
    let authorization: { authorizationId: string; revision: number } | undefined;
    try {
      authorization = await api.authorizeTenantExportDownload(tenant.id, current.id);
      const artifact = await api.downloadTenantExport(tenant.id, current.id, authorization.authorizationId);
      triggerDownload(artifact.blob, artifact.filename);
      triggerDownload(
        new Blob([`${JSON.stringify(current.publicManifest, null, 2)}\n`], { type: "application/json" }),
        `tenant-export-${tenant.slug}-${current.publicManifest.backupId}.manifest.json`,
      );
      setNotice({ tone: "success", text: labels.saved });
    } catch (error) {
      if (authorization) {
        await api.revokeTenantExportDownload(authorization.authorizationId, authorization.revision).catch(() => undefined);
      }
      setNotice({ tone: "error", text: error instanceof ApiError ? localizedApiError(error, locale) : labels.failed });
    } finally { setBusy(false); }
  }

  return <div className="platform-console">
    <div className="platform-heading"><div><p className="eyebrow">{labels.eyebrow}</p><h1>{labels.title}</h1><p>{labels.description}</p></div><span><ServerCog /></span></div>
    <Alert className="platform-boundary"><ShieldCheck /><AlertTitle>{labels.boundary}</AlertTitle><AlertDescription>{labels.boundaryBody}</AlertDescription></Alert>
    {query.isError && <Alert variant="destructive"><AlertTriangle /><AlertTitle>{labels.loadFailed}</AlertTitle><AlertDescription><Button type="button" variant="outline" size="sm" onClick={() => void query.refetch()}><RefreshCw /> {labels.retry}</Button></AlertDescription></Alert>}
    {query.isLoading && <div className="platform-loading" role="status"><LoaderCircle className="animate-spin" /></div>}
    {query.data && <section className="surface-card platform-worker-status" aria-live="polite">
      <div><span className={query.data?.worker.healthy ? "worker-pulse healthy" : "worker-pulse"}><Activity /></span><div><p className="eyebrow">QUEUE + WORKER</p><h2>{workerLabels.title}</h2></div></div>
      <div><Badge variant={query.data?.worker.healthy ? "default" : "destructive"}>{query.data?.worker.healthy ? workerLabels.healthy : (query.data?.worker.status ?? workerLabels.unavailable)}</Badge><small>{query.data?.worker.heartbeatAt ? `${workerLabels.heartbeat}: ${formatInTenantTimeZone(query.data.worker.heartbeatAt, locale, "UTC", { dateStyle: "medium", timeStyle: "short" })} · UTC` : workerLabels.unavailable}</small><small>{query.data?.worker.processedCount ?? 0} {workerLabels.processed}</small>{query.data?.worker.lastErrorCode && <code>{query.data.worker.lastErrorCode}</code>}</div>
    </section>}
    {oneTime && <Alert className="one-time-token" role="status"><ShieldCheck /><AlertTitle>{activationLabels.tokenTitle}</AlertTitle><AlertDescription><p>{activationLabels.tokenBody}</p><small>{oneTime.email} · {formatInTenantTimeZone(oneTime.expiresAt, locale, "UTC", { dateStyle: "medium", timeStyle: "short" })} · UTC</small><div className="token-copy"><code>{oneTime.token}</code><Button type="button" variant="outline" onClick={() => void copyOneTimeToken()}>{copiedToken ? <Check /> : <Copy />} {copiedToken ? activationLabels.copied : activationLabels.copy}</Button></div>{clipboardError && <p role="alert" className="text-sm text-destructive">{clipboardError}</p>}</AlertDescription></Alert>}
    {notice && <Alert className={notice.tone === "error" ? "access-notice-error" : "success-alert"} role="status"><Activity /><AlertTitle>{notice.tone === "success" ? labels.saved : labels.failed}</AlertTitle><AlertDescription>{notice.text}</AlertDescription></Alert>}
    <InitialAdminRecoveryConsole locale={locale} permissions={permissions} currentIdentityId={currentIdentityId} />
    <div className="platform-grid">
      {canProvision && <section className="surface-card platform-provision">
        <div className="card-heading"><div><p className="eyebrow">QUEUE + WORKER</p><h2>{labels.newTenant}</h2></div><span className="form-icon"><Plus /></span></div>
        <form onSubmit={(event) => { event.preventDefault(); void run(
          () => api.queueTenantProvisioning({ tenantId: tenantId || crypto.randomUUID(), displayName, slug, kind, timezone, locale: tenantLocale, initialAdmin: initialAdminMode === "pending" ? { mode: "pending" } : { mode: "invitation", email: initialAdminEmail, expiresInHours: initialAdminExpiry } }),
          (result) => { if (result.initialAdmin.mode === "invitation" && result.initialAdmin.acceptanceToken && result.initialAdmin.expiresAt) showOneTimeToken(result.initialAdmin.acceptanceToken, initialAdminEmail, result.initialAdmin.expiresAt); setTenantId(""); setDisplayName(""); setSlug(""); setInitialAdminEmail(""); },
        ); }}>
          <div><Label htmlFor="platform-display-name">{labels.name}</Label><Input id="platform-display-name" value={displayName} onChange={(event) => { setDisplayName(event.target.value); if (!slug) setSlug(slugify(event.target.value)); }} minLength={2} maxLength={160} required /></div>
          <div><Label htmlFor="platform-slug">{labels.slug}</Label><Input id="platform-slug" value={slug} onChange={(event) => setSlug(event.target.value.toLowerCase())} pattern="[a-z0-9][a-z0-9-]{1,61}[a-z0-9]" required /></div>
          <div className="platform-form-pair"><label><span>{labels.kind}</span><select value={kind} onChange={(event) => setKind(event.target.value as "demo" | "real")}><option value="real">{labels.real}</option><option value="demo">{labels.demo}</option></select></label><label><span>{labels.locale}</span><select value={tenantLocale} onChange={(event) => setTenantLocale(event.target.value as Locale)}><option value="es">ES</option><option value="en">EN</option><option value="fr">FR</option></select></label></div>
          <div><Label htmlFor="platform-timezone">{labels.timezone}</Label><Input id="platform-timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} pattern="[A-Za-z_+\-]+(?:/[A-Za-z0-9_+\-]+)+" required /></div>
          <div className="platform-form-pair"><label><span>{activationLabels.mode}</span><select value={initialAdminMode} onChange={(event) => setInitialAdminMode(event.target.value as "invitation" | "pending")}><option value="pending">{activationLabels.pending}</option>{canManageInitialAdmin && <option value="invitation">{activationLabels.invite}</option>}</select></label>{initialAdminMode === "invitation" && <label><span>{activationLabels.expiry}</span><select value={initialAdminExpiry} onChange={(event) => setInitialAdminExpiry(Number(event.target.value))}>{[12,24,48,72,168].map((hours) => <option key={hours} value={hours}>{hours} {activationLabels.hours}</option>)}</select></label>}</div>
          {initialAdminMode === "invitation" && <div><Label htmlFor="platform-initial-admin">{activationLabels.email}</Label><Input id="platform-initial-admin" type="email" autoComplete="off" value={initialAdminEmail} onChange={(event) => setInitialAdminEmail(event.target.value)} maxLength={320} required /></div>}
          <Button disabled={busy} type="submit">{busy ? <LoaderCircle className="animate-spin" /> : <Database />} {labels.queue}</Button>
        </form>
      </section>}

      <section className="surface-card platform-tenants">
        <div className="card-heading"><div><p className="eyebrow">POSTGRESQL</p><h2>{labels.tenants}</h2></div><Badge variant="outline">{query.data?.items.length ?? 0}</Badge></div>
        {query.isLoading ? <div className="platform-loading" role="status"><LoaderCircle className="animate-spin" /></div> : query.isError ? <p role="alert">{labels.loadFailed}</p> : <div className="platform-tenant-list">{query.data?.items.map((tenant) => <article key={tenant.id}>
          <span className={`platform-status ${tenant.status}`}><Building2 /></span>
          <div><strong>{tenant.displayName}</strong><code>{tenant.slug}</code><small>{tenant.timezone} · {tenant.locale.toUpperCase()}</small></div>
          <div className="platform-tenant-state"><Badge variant={tenant.status === "active" ? "default" : "outline"}>{statusLabel(labels, tenant.status)}</Badge><small>{provisioningStateLabel(labels, tenant.provisioningState ?? tenant.status)} · {labels.attempt} {tenant.provisioningAttempts}</small>{tenant.lastErrorCode && <code>{tenant.lastErrorCode}</code>}</div>
          <div className="platform-activation-state"><Badge variant={tenant.activationState === "admin_active" || tenant.activationState === "active" ? "default" : "outline"}>{activationLabel(activationLabels, tenant.activationState)}</Badge></div>
          {tenant.activationState === "pending_activation" && canManageInitialAdmin && <Button variant="outline" size="sm" disabled={busy} onClick={() => { setActivating(tenant.id); setActivationEmail(""); }}><MailPlus /> {activationLabels.activate}</Button>}
          {tenant.status === "active" && canSuspend && <Button variant="outline" size="sm" disabled={busy} onClick={() => { setSuspending(tenant.id); setReason("operational_hold"); }}><Ban /> {labels.suspend}</Button>}
          {tenant.status === "suspended" && canReactivate && <Button variant="outline" size="sm" disabled={busy} onClick={() => { setReactivating(tenant.id); setReactivationReason("operational_hold_resolved"); }}><Undo2 /> {reactivationLabels.open}</Button>}
          {suspending === tenant.id && <form className="platform-suspend-form" onSubmit={(event) => { event.preventDefault(); void run(
            () => api.suspendPlatformTenant(tenant.id, tenant.version, reason),
            () => { setSuspending(undefined); setReason("operational_hold"); },
          ); }}><Label htmlFor={`suspend-${tenant.id}`}>{labels.reason}</Label><select id={`suspend-${tenant.id}`} value={reason} onChange={(event) => setReason(event.target.value as typeof reason)}><option value="security_review">{suspensionLabels.securityReview}</option><option value="operational_hold">{suspensionLabels.operationalHold}</option><option value="institution_request">{suspensionLabels.institutionRequest}</option><option value="compliance_review">{suspensionLabels.complianceReview}</option></select><div className="button-row"><Button type="submit" variant="destructive" disabled={busy}><Ban /> {labels.confirm}</Button><Button type="button" variant="outline" onClick={() => setSuspending(undefined)}>{labels.cancel}</Button></div></form>}
          {reactivating === tenant.id && <form className="platform-suspend-form platform-reactivation-form" onSubmit={(event) => { event.preventDefault(); void run(
            () => api.reactivatePlatformTenant(tenant.id, tenant.version, reactivationReason),
            () => { setReactivating(undefined); setReactivationReason("operational_hold_resolved"); },
          ); }}><div><strong>{reactivationLabels.title}</strong><small>{reactivationLabels.loginRequired}</small></div><Label htmlFor={`reactivate-${tenant.id}`}>{reactivationLabels.reason}</Label><select id={`reactivate-${tenant.id}`} value={reactivationReason} onChange={(event) => setReactivationReason(event.target.value as typeof reactivationReason)}><option value="security_review_completed">{reactivationLabels.security}</option><option value="operational_hold_resolved">{reactivationLabels.operational}</option><option value="institution_request_resumed">{reactivationLabels.institution}</option><option value="compliance_review_completed">{reactivationLabels.compliance}</option></select><div className="button-row"><Button type="submit" disabled={busy}><Undo2 /> {reactivationLabels.confirm}</Button><Button type="button" variant="outline" onClick={() => setReactivating(undefined)}>{labels.cancel}</Button></div></form>}
          {activating === tenant.id && <form className="platform-suspend-form platform-activation-form" onSubmit={(event) => { event.preventDefault(); void run(
            () => api.activatePlatformTenantAdmin(tenant.id, { expectedVersion: tenant.version, email: activationEmail, expiresInHours: activationExpiry }),
            (result) => { if (result.acceptanceToken && result.expiresAt) showOneTimeToken(result.acceptanceToken, activationEmail, result.expiresAt); setActivating(undefined); setActivationEmail(""); },
          ); }}><Label htmlFor={`activate-${tenant.id}`}>{activationLabels.email}</Label><Input id={`activate-${tenant.id}`} type="email" autoComplete="off" value={activationEmail} onChange={(event) => setActivationEmail(event.target.value)} maxLength={320} required /><label><span>{activationLabels.expiry}</span><select value={activationExpiry} onChange={(event) => setActivationExpiry(Number(event.target.value))}>{[12,24,48,72,168].map((hours) => <option key={hours} value={hours}>{hours} {activationLabels.hours}</option>)}</select></label><div className="button-row"><Button type="submit" disabled={busy}><MailPlus /> {activationLabels.activate}</Button><Button type="button" variant="outline" onClick={() => setActivating(undefined)}>{labels.cancel}</Button></div></form>}
          <section className="platform-lifecycle" aria-label={lifecycleLabels.title}>
            <div className="platform-lifecycle-heading"><span><ArchiveRestore /></span><div><strong>{lifecycleLabels.title}</strong><small>{lifecycleLabels.authorization}</small></div></div>
            <div className="platform-lifecycle-actions">
              {canExport && (tenant.status === "active" || tenant.status === "suspended") && <Button type="button" size="sm" variant="outline" disabled={busy || tenant.latestExport?.state === "queued" || tenant.latestExport?.state === "running"} onClick={() => void run(() => api.requestTenantExport(tenant.id, tenant.version))}><FileKey2 /> {lifecycleLabels.export}</Button>}
              {tenant.latestExport?.state === "ready" && canDownloadExport && <Button type="button" size="sm" disabled={busy} onClick={() => void downloadTenantExport(tenant)}><Download /> {lifecycleLabels.download}</Button>}
              {tenant.latestExport?.state === "ready" && tenant.latestExport.publicManifest && <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => triggerDownload(new Blob([`${JSON.stringify(tenant.latestExport!.publicManifest, null, 2)}\n`], { type: "application/json" }), `tenant-export-${tenant.slug}-${tenant.latestExport!.publicManifest!.backupId}.manifest.json`)}><ShieldCheck /> {lifecycleLabels.manifest}</Button>}
              {canScheduleDecommission && !tenant.decommission && (tenant.status === "active" || tenant.status === "suspended") && <Button type="button" size="sm" variant="destructive" disabled={busy || tenant.latestExport?.state !== "ready" || tenant.latestExport.tenantVersion !== tenant.version} title={tenant.latestExport?.state !== "ready" || tenant.latestExport.tenantVersion !== tenant.version ? lifecycleLabels.currentBlocked : undefined} onClick={() => setDecommissioning(tenant.id)}><TimerReset /> {lifecycleLabels.schedule}</Button>}
            </div>
            {tenant.latestExport && <div className={`platform-export-state state-${tenant.latestExport.state}`} role="status">
              <Badge variant={tenant.latestExport.state === "ready" ? "default" : tenant.latestExport.state === "failed" ? "destructive" : "outline"}>{exportStateLabel(lifecycleLabels, tenant.latestExport.state)}</Badge>
              <small>{tenant.latestExport.state === "ready" && tenant.latestExport.recoveryPointAt ? `${lifecycleLabels.recovery}: ${formatInTenantTimeZone(tenant.latestExport.recoveryPointAt, locale, "UTC", { dateStyle: "medium", timeStyle: "short" })} · UTC` : `${labels.attempt} ${tenant.latestExport.attemptCount}`}</small>
              {tenant.latestExport.encryptedBytes && <small>{formatBytes(tenant.latestExport.encryptedBytes, locale)}</small>}
              {tenant.latestExport.ciphertextSha256 && <code title={tenant.latestExport.ciphertextSha256}>{lifecycleLabels.checksum}: {tenant.latestExport.ciphertextSha256.slice(0, 24)}…</code>}
              {tenant.latestExport.lastErrorCode && <code>{tenant.latestExport.lastErrorCode}</code>}
              {tenant.latestExport.state === "ready" && <small><FileKey2 /> {lifecycleLabels.custody}</small>}
            </div>}
            {tenant.decommission?.state === "scheduled" && <Alert className="platform-decommission-notice"><TimerReset /><AlertTitle>{lifecycleLabels.pending}</AlertTitle><AlertDescription><p>{lifecycleLabels.until}: {formatInTenantTimeZone(tenant.decommission.retentionUntil, locale, "UTC", { dateStyle: "long", timeStyle: "short" })} · UTC</p><p>{lifecycleLabels.reversible}</p>{canCancelDecommission && new Date(tenant.decommission.retentionUntil).getTime() > query.dataUpdatedAt && <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void run(() => api.cancelTenantDecommission(tenant.id, tenant.decommission!.id, tenant.version))}><Undo2 /> {lifecycleLabels.cancelDecommission}</Button>}</AlertDescription></Alert>}
            {decommissioning === tenant.id && tenant.latestExport?.state === "ready" && <form className="platform-decommission-form" onSubmit={(event) => { event.preventDefault(); void run(
              () => api.scheduleTenantDecommission(tenant.id, { expectedVersion: tenant.version, exportJobId: tenant.latestExport!.id, retentionDays, reasonCode: decommissionReason }),
              () => setDecommissioning(undefined),
            ); }}>
              <div><strong>{lifecycleLabels.scheduleTitle}</strong><small>{lifecycleLabels.reversible}</small></div>
              <label><span>{lifecycleLabels.retention}</span><select value={retentionDays} onChange={(event) => setRetentionDays(Number(event.target.value))}>{[30, 90, 180, 365, 730].map((days) => <option key={days} value={days}>{days} {lifecycleLabels.days}</option>)}</select></label>
              <label><span>{lifecycleLabels.reason}</span><select value={decommissionReason} onChange={(event) => setDecommissionReason(event.target.value as typeof decommissionReason)}><option value="institution_request">{lifecycleLabels.institutionRequest}</option><option value="duplicate_tenant">{lifecycleLabels.duplicateTenant}</option><option value="service_ended">{lifecycleLabels.serviceEnded}</option><option value="legal_retention">{lifecycleLabels.legalRetention}</option></select></label>
              <div className="button-row"><Button type="submit" variant="destructive" disabled={busy}><TimerReset /> {lifecycleLabels.confirmSchedule}</Button><Button type="button" variant="outline" onClick={() => setDecommissioning(undefined)}>{labels.cancel}</Button></div>
            </form>}
          </section>
        </article>)}</div>}
      </section>
    </div>
  </div>;
}

function activationLabel(labels: (typeof activationCopy)[Locale], state: string): string {
  if (state === "pending_activation") return labels.awaiting;
  if (state === "invitation_pending") return labels.invitationPending;
  if (state === "admin_active") return labels.adminActive;
  return labels.adminActive;
}

function slugify(value: string): string {
  return value.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 63);
}

function statusLabel(labels: (typeof copy)[Locale], status: string): string {
  if (status === "active") return labels.active;
  if (status === "suspended") return labels.suspended;
  if (status === "decommission_pending") return labels.decommissionPending;
  if (status === "failed") return labels.failedState;
  return labels.provisioning;
}

function provisioningStateLabel(labels: (typeof copy)[Locale], state: string): string {
  if (state === "requested") return labels.requested;
  if (state === "queued") return labels.queued;
  if (state === "claimed" || state === "processing" || state === "running") return labels.running;
  if (state === "completed") return labels.completed;
  return statusLabel(labels, state);
}

function exportStateLabel(labels: (typeof lifecycleCopy)[Locale], state: "queued" | "running" | "ready" | "failed"): string {
  if (state === "ready") return labels.exportReady;
  if (state === "failed") return labels.exportFailed;
  if (state === "running") return labels.exportRunning;
  return labels.exportQueued;
}

function formatBytes(bytes: number, locale: Locale): string {
  return new Intl.NumberFormat(locale, { style: "unit", unit: "megabyte", maximumFractionDigits: 2 }).format(bytes / 1_048_576);
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
