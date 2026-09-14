"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { Building2, LoaderCircle, Sparkles } from "lucide-react";

import { useVault } from "@/app/providers";
import { api, ApiError, setCsrfToken, type AuthenticatedSession, type Locale } from "@/lib/api";
import { message, localizedApiError } from "@/lib/product-i18n";
import { appLandingPath } from "@/lib/app-navigation";

const text = {
  es: { active: message("es", "screen.tenantSwitcher.acdb3f83aac1"), change: message("es", "screen.tenantSwitcher.27b31c9e346f"), failed: message("es", "screen.tenantSwitcher.682230e7d7eb") },
  en: { active: message("en", "screen.tenantSwitcher.acdb3f83aac1"), change: message("en", "screen.tenantSwitcher.27b31c9e346f"), failed: message("en", "screen.tenantSwitcher.682230e7d7eb") },
  fr: { active: message("fr", "screen.tenantSwitcher.acdb3f83aac1"), change: message("fr", "screen.tenantSwitcher.27b31c9e346f"), failed: message("fr", "screen.tenantSwitcher.682230e7d7eb") },
} as const;

export function TenantSwitcher({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const labels = text[locale];
  const vault = useVault();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const query = useQuery({
    queryKey: ["tenant-memberships", session.user.id],
    queryFn: api.memberships,
    staleTime: 30_000,
  });
  const memberships = (query.data?.items ?? []).filter((item) =>
    item.membershipStatus === "active" && item.tenantStatus === "active");

  async function switchTenant(tenantId: string) {
    if (!tenantId || tenantId === session.tenant.id || busy) return;
    setBusy(true);
    setError(undefined);
    try {
      const switchedSession = await api.switchTenant(tenantId);
      // The server has already atomically revoked the old session and issued
      // new cookies. Destroy every browser-held tenant context before the new
      // session is observed, then reload the application from a clean graph.
      vault.lock();
      setCsrfToken(undefined);
      queryClient.clear();
      router.replace(appLandingPath(locale, switchedSession.permissions));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof ApiError ? localizedApiError(caught, locale) : labels.failed);
      setBusy(false);
    }
  }

  return <div className="tenant-switcher">
    <span className="tenant-icon"><Building2 size={18} /></span>
    <span className="min-w-0 tenant-switcher-copy"><small>{labels.active}</small><strong className="truncate">{session.tenant.name}</strong></span>
    {session.tenant.kind === "demo" && <Sparkles size={15} className="tenant-demo-spark" />}
    {memberships.length > 1 && <label className="tenant-select-label">
      <span className="sr-only">{labels.change}</span>
      {busy && <LoaderCircle className="animate-spin" aria-hidden="true" />}
      <select
        aria-label={labels.change}
        value={session.tenant.id}
        disabled={busy}
        onChange={(event) => void switchTenant(event.target.value)}
      >
        {memberships.map((membership) => <option key={membership.tenantId} value={membership.tenantId}>
          {membership.displayName}
        </option>)}
      </select>
    </label>}
    {error && <small className="tenant-switch-error" role="alert">{error}</small>}
  </div>;
}
