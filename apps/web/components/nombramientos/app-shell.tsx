"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, BookOpenText, Building2, ChevronDown, ClipboardCheck, Clock3, FileBarChart, LayoutDashboard, LoaderCircle,
  KeyRound, LockKeyhole, LogOut, MailPlus, Menu, Network, Rocket, ServerCog, Settings2, ShieldCheck, Sparkles, Users, Vote,
} from "lucide-react";

import { useVault } from "@/app/providers";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { api, ApiError, type AuthenticatedSession, type Locale, setCsrfToken } from "@/lib/api";
import { FEDERATED_RESUME_PATH_KEY, SESSION_INVALID_EVENT } from "@/lib/gestionchurch-session";
import { sessionTimeRemaining } from "@/lib/session-clock";
import { useDeviceSessionReadiness } from "@/lib/device-session-readiness";
import {
  appLandingPath,
  canAccessAppSection,
  sectionRequiresContentKey,
  tenantNavigationGroups,
  type TenantNavigationGroupId,
  type TenantNavigationSection,
} from "@/lib/app-navigation";
import { localizedApiError, message } from "@/lib/product-i18n";
import { WorkspaceView } from "./workspace-view";
import { SecurityCenter } from "./security-center";
import { TenantSwitcher } from "./tenant-switcher";
import { TenantKeyUnlockPanel } from "./key-lifecycle-view";
import { DeviceSessionBoundary } from "./device-session-boundary";

const navLabels = {
  es: { overview: message("es", "screen.appShell.1cfd7c935051"), workflow: message("es", "screen.appShell.6d43b278b5c9"), session: message("es", "screen.appShell.81faa0bbff77"), members: message("es", "screen.appShell.500cd8288ddc"), catalog: message("es", "screen.appShell.feefa3551507"), committee: message("es", "screen.appShell.5abcb28f2788"), organization: message("es", "screen.appShell.76c653b54d72"), reports: message("es", "screen.appShell.ac093224fa25"), access: message("es", "screen.appShell.99e7b34e8f97"), custody: message("es", "screen.appShell.d35779d4b9a1"), history: message("es", "screen.appShell.c562bc35964d"), library: message("es", "nav.library"), settings: message("es", "screen.appShell.d04e192af18e"), results: message("es", "screen.appShell.678c0efa75eb"), platform: message("es", "screen.appShell.ff1186c8119b") },
  en: { overview: message("en", "screen.appShell.1cfd7c935051"), workflow: message("en", "screen.appShell.6d43b278b5c9"), session: message("en", "screen.appShell.81faa0bbff77"), members: message("en", "screen.appShell.500cd8288ddc"), catalog: message("en", "screen.appShell.feefa3551507"), committee: message("en", "screen.appShell.5abcb28f2788"), organization: message("en", "screen.appShell.76c653b54d72"), reports: message("en", "screen.appShell.ac093224fa25"), access: message("en", "screen.appShell.99e7b34e8f97"), custody: message("en", "screen.appShell.d35779d4b9a1"), history: message("en", "screen.appShell.c562bc35964d"), library: message("en", "nav.library"), settings: message("en", "screen.appShell.d04e192af18e"), results: message("en", "screen.appShell.678c0efa75eb"), platform: message("en", "screen.appShell.ff1186c8119b") },
  fr: { overview: message("fr", "screen.appShell.1cfd7c935051"), workflow: message("fr", "screen.appShell.6d43b278b5c9"), session: message("fr", "screen.appShell.81faa0bbff77"), members: message("fr", "screen.appShell.500cd8288ddc"), catalog: message("fr", "screen.appShell.feefa3551507"), committee: message("fr", "screen.appShell.5abcb28f2788"), organization: message("fr", "screen.appShell.76c653b54d72"), reports: message("fr", "screen.appShell.ac093224fa25"), access: message("fr", "screen.appShell.99e7b34e8f97"), custody: message("fr", "screen.appShell.d35779d4b9a1"), history: message("fr", "screen.appShell.c562bc35964d"), library: message("fr", "nav.library"), settings: message("fr", "screen.appShell.d04e192af18e"), results: message("fr", "screen.appShell.678c0efa75eb"), platform: message("fr", "screen.appShell.ff1186c8119b") },
};

const navIcons: Record<TenantNavigationSection, typeof LayoutDashboard> = {
  overview: LayoutDashboard,
  workflow: ClipboardCheck,
  session: Vote,
  results: FileBarChart,
  members: Users,
  catalog: Building2,
  committee: ShieldCheck,
  organization: Network,
  reports: FileBarChart,
  history: Clock3,
  library: BookOpenText,
  access: MailPlus,
  custody: KeyRound,
  settings: Settings2,
};

const navGroupMessageKeys: Record<TenantNavigationGroupId, "shell.navGroupHome" | "shell.navGroupCycle" | "shell.navGroupOrganization" | "shell.navGroupInsights" | "shell.navGroupAdministration"> = {
  home: "shell.navGroupHome",
  cycle: "shell.navGroupCycle",
  organization: "shell.navGroupOrganization",
  insights: "shell.navGroupInsights",
  administration: "shell.navGroupAdministration",
};
const gestionChurchManaged = Boolean(process.env.NEXT_PUBLIC_GESTIONCHURCH_URL);

function returnToIdentityProvider(locale: Locale, router: { replace: (href: string) => void }) {
  const gestionChurchUrl = process.env.NEXT_PUBLIC_GESTIONCHURCH_URL;
  if (gestionChurchUrl) {
    window.location.assign(new URL("/nominations", gestionChurchUrl).toString());
    return;
  }
  router.replace(`/${locale}/auth/sign-in`);
}

function LoadingScreen({ locale }: { locale: Locale }) {
  return <main className="grid min-h-screen place-items-center bg-background"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-primary" /><p className="mt-3 text-sm text-muted-foreground">{message(locale, "shell.validatingSession")}</p></div></main>;
}

function SessionTopbar({ children }: { children: ReactNode }) {
  const headerRef = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    const header = headerRef.current;
    if (!header) return;
    const root = document.documentElement;
    const property = "--session-header-scroll-offset";
    const previous = root.style.getPropertyValue(property);
    const priority = root.style.getPropertyPriority(property);
    const measure = () => {
      const height = header.getBoundingClientRect().height;
      if (Number.isFinite(height) && height > 0) root.style.setProperty(property, `${Math.ceil(height) + 12}px`);
    };
    // Measure synchronously after mounting, then follow translated labels,
    // viewport changes and text zoom without guessing a fixed header height.
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(header);
    return () => {
      observer.disconnect();
      if (previous) root.style.setProperty(property, previous, priority);
      else root.style.removeProperty(property);
    };
  }, []);
  return <header ref={headerRef} className="topbar session-topbar">{children}</header>;
}

function ServiceError({ error, locale }: { error: unknown; locale: Locale }) {
  const requestId = error instanceof ApiError ? error.requestId : undefined;
  return <main className="grid min-h-screen place-items-center bg-background p-5"><Alert className="max-w-lg"><ShieldCheck /><AlertTitle>{message(locale, "shell.localUnavailable")}</AlertTitle><AlertDescription><p>{message(locale, "shell.localUnavailableHelp")}</p>{requestId && <p>{message(locale, "audit.correlationId", { id: requestId })}</p>}</AlertDescription></Alert></main>;
}

function UnlockPanel({ session, locale }: { session: AuthenticatedSession; locale: Locale }) {
  const vault = useVault();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [passwordError, setPasswordError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const validationSummaryRef = useRef<HTMLDivElement>(null);
  if (session.tenant.kind === "real") return <TenantKeyUnlockPanel session={session} locale={locale} />;
  const keyGrant = session.keyGrant;
  if (!keyGrant) return <Alert><LockKeyhole /><AlertTitle>{message(locale, "shell.keyGrantPending")}</AlertTitle><AlertDescription>{message(locale, "shell.keyGrantPendingHelp")}</AlertDescription></Alert>;

  async function submitUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!password) {
      setPassword("");
      setPasswordError(`${message(locale, "auth.password")}: ${message(locale, "a11y.requiredField")}`);
      setError(undefined);
      requestAnimationFrame(() => validationSummaryRef.current?.focus());
      return;
    }
    const submittedPassword = password;
    setPassword("");
    setPasswordError(undefined);
    setBusy(true);
    setError(undefined);
    try {
      await vault.unlock(submittedPassword, keyGrant!, session.tenant.id);
    } catch (caught) {
      setPassword("");
      setError(localizedApiError(caught, locale, "shell.unlockError"));
    } finally {
      setBusy(false);
    }
  }

  return <section className="unlock-card"><span className="form-icon"><LockKeyhole /></span><div><p className="eyebrow">{message(locale, "shell.deviceKey")}</p><h2>{message(locale, "shell.unlockTitle", { tenant: session.tenant.name })}</h2><p>{message(locale, "shell.unlockHelp")}</p></div><form onSubmit={submitUnlock} noValidate><Label htmlFor="unlock-password">{message(locale, "auth.password")}</Label><Input id="unlock-password" type="password" autoComplete="current-password" value={password} onChange={(event) => { setPassword(event.target.value); setPasswordError(undefined); setError(undefined); }} required aria-invalid={passwordError ? true : undefined} aria-describedby={passwordError ? "unlock-password-error" : undefined} />{passwordError && <p id="unlock-password-error" className="form-error">{passwordError}</p>}{passwordError && <Alert id="unlock-validation-summary" ref={validationSummaryRef} variant="destructive" tabIndex={-1} aria-labelledby="unlock-validation-summary-title"><ShieldCheck /><AlertTitle id="unlock-validation-summary-title">{message(locale, "a11y.errorSummary", { count: 1 })}</AlertTitle><AlertDescription><a href="#unlock-password">{passwordError}</a></AlertDescription></Alert>}{error && <p role="alert" className="text-sm text-destructive">{error}</p>}<Button disabled={busy} type="submit">{busy && <LoaderCircle className="animate-spin" />} {message(locale, "shell.unlock")}</Button></form></section>;
}

function PlatformIsolationBoundary({ platformMode, children, locale }: { platformMode: boolean; children: ReactNode; locale: Locale }) {
  const queryClient = useQueryClient();
  const vault = useVault();
  const [ready, setReady] = useState(!platformMode);
  const lockVault = vault.lock;

  useEffect(() => {
    // A normal tenant mount may carry the content key unlocked by LoginForm.
    // The keyed boundary remounts when entering the global plane, so isolation
    // work is required only for that direction; tenant switching has its own
    // post-rotation purge in TenantSwitcher.
    if (!platformMode) {
      return;
    }
    let cancelled = false;
    async function isolateContext() {
      lockVault();
      await queryClient.cancelQueries();
      queryClient.removeQueries({
        predicate: (query) => query.queryKey[0] !== "session"
          && query.queryKey[0] !== "platform-tenants",
      });
      if (!cancelled) setReady(true);
    }
    void isolateContext();
    return () => { cancelled = true; };
  }, [lockVault, platformMode, queryClient]);

  if (!ready) {
    return <div className="loading-block" role="status"><span className="loading-line w-32" /><span className="loading-line h-9 w-72" /><span className="sr-only">{message(locale, "shell.isolating")}</span></div>;
  }
  return children;
}

export function AppShell({ locale, section }: { locale: Locale; section: string }) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const vault = useVault();
  const lockVault = vault.lock;
  const vaultTenantId = vault.tenantId;
  const sessionRecoveryStarted = useRef(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const mobileMenuOpenerRef = useRef<HTMLButtonElement | null>(null);
  const sessionQuery = useQuery({
    queryKey: ["session"],
    queryFn: api.session,
    retry: false,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
  const labels = navLabels[locale];
  const session = sessionQuery.data;
  const recoveryRestricted = session?.security.recoveryRestricted === true || session?.security.assurance === "recovery_limited";
  const platformAuthorized = Boolean(session?.permissions.includes("platform.operation.read"));
  const platformMode = section === "platform" && platformAuthorized;
  const deviceReadiness = useDeviceSessionReadiness(session, platformMode);
  const redirectPath = session && !recoveryRestricted && (section === "landing" || !canAccessAppSection(section, session.permissions))
    ? appLandingPath(locale, session.permissions)
    : undefined;

  const recoverSession = useCallback(() => {
    if (sessionRecoveryStarted.current) return;
    sessionRecoveryStarted.current = true;
    if (gestionChurchManaged && window.location.pathname.startsWith(`/${locale}/app/`)) {
      window.sessionStorage.setItem(FEDERATED_RESUME_PATH_KEY, window.location.pathname);
    }
    lockVault();
    setCsrfToken(undefined);
    void queryClient.cancelQueries();
    queryClient.clear();
    returnToIdentityProvider(locale, router);
  }, [locale, lockVault, queryClient, router]);

  useEffect(() => {
    window.addEventListener(SESSION_INVALID_EVENT, recoverSession);
    return () => window.removeEventListener(SESSION_INVALID_EVENT, recoverSession);
  }, [recoverSession]);

  useEffect(() => {
    if (sessionQuery.error) lockVault();
    if (sessionQuery.error instanceof ApiError && sessionQuery.error.status === 401) {
      recoverSession();
    }
  }, [lockVault, recoverSession, sessionQuery.error]);

  useEffect(() => {
    // CSRF and proof context belong to the authenticated session, not this
    // route component. Ordinary navigation must not clear a still-valid
    // signer while the next route reuses its exact-session readiness cache.
    // Explicit logout, expiry, revocation and tenant switching clear them.
    setCsrfToken(session?.csrfToken);
  }, [session?.csrfToken]);

  useEffect(() => {
    if (!session) return;
    const remaining = sessionTimeRemaining(session);
    const expireClientSession = () => {
      lockVault();
      setCsrfToken(undefined);
      queryClient.clear();
      returnToIdentityProvider(locale, router);
    };
    if (!Number.isFinite(remaining) || remaining <= 0) { expireClientSession(); return; }
    const timer = window.setTimeout(expireClientSession, remaining);
    return () => window.clearTimeout(timer);
  }, [locale, lockVault, queryClient, router, session]);

  useEffect(() => {
    if (session && vaultTenantId && vaultTenantId !== session.tenant.id) {
      lockVault(); queryClient.clear();
    }
  }, [lockVault, queryClient, session, vaultTenantId]);

  useEffect(() => {
    if (redirectPath) router.replace(redirectPath);
  }, [redirectPath, router]);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      document.querySelectorAll<HTMLElement>(".sidebar-navigation .nav-item-active").forEach((activeItem) => {
        activeItem.scrollIntoView({ block: "nearest", inline: "nearest" });
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [mobileOpen, section, session?.tenant.id]);

  if (sessionQuery.isLoading) return <LoadingScreen locale={locale} />;
  if (!session) return <ServiceError error={sessionQuery.error} locale={locale} />;
  if (redirectPath) return <LoadingScreen locale={locale} />;

  async function signOut() {
    try { await api.logout(); }
    finally {
      vault.lock(); setCsrfToken(undefined); queryClient.clear();
      returnToIdentityProvider(locale, router);
    }
  }

  if (!gestionChurchManaged && (session.security.enrollmentOnly || recoveryRestricted)) {
    return <main className="min-h-screen bg-background text-foreground" id="main-content" tabIndex={-1}>
      <header className="topbar"><div className="brand-lockup !p-0"><span className="brand-mark" aria-hidden="true">N</span><span><strong className="!text-slate-900">Nombramientos</strong><small className="!text-slate-600">{session.tenant.name}</small></span></div><Button className="ml-auto" variant="outline" onClick={() => void signOut()}><LogOut /> {message(locale, "auth.signOut")}</Button></header>
      <div className="page-wrap"><SecurityCenter locale={locale} session={session} requiredGate /></div>
    </main>;
  }

  const navigation = (
    <>
      <div className="brand-lockup"><span className="brand-mark" aria-hidden="true">N</span><span><strong>Nombramientos</strong><small>{platformMode ? labels.platform : message(locale, "shell.workspace")}</small></span></div>
      {platformMode ? <>
        <div className="platform-mode-card"><ServerCog /><span><small>{message(locale, "shell.controlPlane")}</small><strong>{labels.platform}</strong></span></div>
        <nav aria-label={labels.platform} className="mt-6 space-y-1"><Link onClick={() => setMobileOpen(false)} href={`/${locale}/app/platform`} aria-current="page" className="nav-item nav-item-active"><ServerCog size={18} /><span>{labels.platform}</span></Link></nav>
        <div className="mt-auto space-y-2"><Link href={appLandingPath(locale, session.permissions, true)} className="nav-item"><Building2 size={18} /> {session.tenant.name}</Link><div className="security-note"><ShieldCheck size={17} /><span><strong>{message(locale, "shell.noContentAccess")}</strong><small>{message(locale, "shell.healthOnly")}</small></span></div></div>
      </> : <>
        <TenantSwitcher locale={locale} session={session} deviceReady={deviceReadiness.workspaceReady} />
        <nav aria-label={message(locale, "shell.primaryNavigation")} className="sidebar-navigation">
          {tenantNavigationGroups.map((group) => {
            const visibleSections = group.sections.filter((id) => canAccessAppSection(id, session.permissions));
            if (visibleSections.length === 0) return null;
            const groupLabel = message(locale, navGroupMessageKeys[group.id]);
            const groupActive = visibleSections.includes(section as TenantNavigationSection);
            return <div key={group.id} role="group" aria-label={groupLabel} className={groupActive ? "nav-group nav-group-active" : "nav-group"}>
              <p className="nav-group-label">{groupLabel}</p>
              <div className="nav-group-items">
                {visibleSections.map((id) => {
                  const Icon = navIcons[id];
                  return <Link onClick={() => setMobileOpen(false)} key={id} href={`/${locale}/app/${id}`} aria-current={section === id ? "page" : undefined} className={section === id ? "nav-item nav-item-active" : "nav-item"}><Icon size={18} strokeWidth={1.8} /><span>{labels[id]}</span></Link>;
                })}
              </div>
            </div>;
          })}
        </nav>
        <div className="sidebar-footer">{platformAuthorized && <Link href={`/${locale}/app/platform`} className="global-console-link"><ServerCog size={18} /><span><small>{message(locale, "shell.controlPlane")}</small><strong>{labels.platform}</strong></span></Link>}<div className="security-note"><ShieldCheck size={17} /><span><strong>{message(locale, "shell.protectedContext")}</strong><small>{message(locale, "shell.isolatedByChurch")}</small></span></div></div>
      </>}
    </>
  );
  // GestionChurch already authenticated and authorized this actor. Let authorized
  // cycle managers create/select a period before asking for local cryptographic
  // custody; private committee/session actions still enforce the vault themselves.
  const managedSectionCanStartWithoutContentKey = gestionChurchManaged
    && (section === "overview" || section === "organization" || section === "workflow");
  const requiresContentKey = sectionRequiresContentKey(section)
    && !managedSectionCanStartWithoutContentKey;
  return <main className="min-h-screen bg-background text-foreground" id="main-content" tabIndex={-1}>
    <div className="app-grid min-h-screen">
      <aside className="sidebar-shell hidden lg:flex lg:flex-col">{navigation}</aside>
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}><SheetContent side="left" className="mobile-sheet" aria-describedby={undefined} onCloseAutoFocus={(event) => { event.preventDefault(); mobileMenuOpenerRef.current?.focus(); }}><SheetTitle className="sr-only">{message(locale, "shell.primaryNavigation")}</SheetTitle>{navigation}</SheetContent></Sheet>
      <section className="min-w-0 pb-20 lg:pb-0">
        <SessionTopbar><Button aria-label={message(locale, "a11y.openMenu")} variant="ghost" size="icon" className="lg:hidden" onClick={(event) => { mobileMenuOpenerRef.current = event.currentTarget; setMobileOpen(true); }}><Menu size={20} /></Button><div className="topbar-compact-brand lg:hidden"><strong className="block text-sm">Nombramientos</strong><span className="text-xs text-muted-foreground" title={platformMode ? labels.platform : session.tenant.name}>{platformMode ? labels.platform : session.tenant.name}</span></div><div className="topbar-actions ml-auto flex items-center gap-2">{!platformMode && session.permissions.includes("cycle.manage") && <Button asChild size="sm" className="px-2.5 shadow-sm sm:px-3"><Link href={`/${locale}/app/workflow`} aria-label={message(locale, "workflow.quickStart.start")}><Rocket /><span className="hidden sm:inline">{message(locale, "workflow.quickStart.start")}</span></Link></Button>}{gestionChurchManaged && <Button asChild variant="outline" size="sm" className="px-2.5 sm:px-3"><a href={new URL("/dashboard", process.env.NEXT_PUBLIC_GESTIONCHURCH_URL).toString()} aria-label={message(locale, "shell.returnToGestionChurch")}><ArrowLeft /><span className="hidden sm:inline">{message(locale, "shell.returnToGestionChurch")}</span></a></Button>}{platformMode ? <Badge className="platform-badge" variant="outline"><ServerCog size={13} /> {labels.platform}</Badge> : session.tenant.kind === "demo" && <Badge className="demo-badge" variant="outline"><Sparkles size={13} />{message(locale, "app.demoBadge")}</Badge>}<DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" className="profile-trigger" aria-label={session.user.displayName + " · " + session.user.email}><span className="avatar-button">{session.user.displayName.split(/\s+/).map((part) => part[0]).slice(0,2).join("")}</span><span className="hidden text-left md:block"><strong>{session.user.displayName}</strong><small>{session.user.email}</small></span><ChevronDown size={15} /></Button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem asChild><Link href={`/${locale}/app/settings`}><Settings2 /> {labels.settings}</Link></DropdownMenuItem><DropdownMenuItem onClick={async () => { try { await api.logout(); } finally { vault.lock(); setCsrfToken(undefined); queryClient.clear(); returnToIdentityProvider(locale, router); } }}><LogOut /> {message(locale, "auth.signOut")}</DropdownMenuItem></DropdownMenuContent></DropdownMenu></div></SessionTopbar>
        <div className="page-wrap"><PlatformIsolationBoundary key={platformMode ? "platform" : "tenant"} platformMode={platformMode} locale={locale}><DeviceSessionBoundary key={`${session.tenant.id}:${session.user.id}:${session.sessionId}`} session={session} locale={locale} platformMode={platformMode}>{section === "settings" && !gestionChurchManaged ? <div className="space-y-7"><SecurityCenter locale={locale} session={session} /><WorkspaceView locale={locale} section={section} session={session} /></div> : (!vault.key || vault.tenantId !== session.tenant.id) && requiresContentKey ? <UnlockPanel session={session} locale={locale} /> : <WorkspaceView locale={locale} section={section} session={session} />}</DeviceSessionBoundary></PlatformIsolationBoundary></div>
      </section>
      {!platformMode && <nav className="mobile-nav lg:hidden" aria-label={message(locale, "shell.mobileNavigation")}>{(["overview","session","results"] as const).filter((id)=>canAccessAppSection(id,session.permissions)).map((id) => { const Icon = id === "session" ? Vote : id === "overview" ? LayoutDashboard : FileBarChart; return <Link key={id} href={`/${locale}/app/${id}`} aria-current={section===id?"page":undefined}><Icon /><span>{labels[id]}</span></Link>; })}<button onClick={(event) => { mobileMenuOpenerRef.current = event.currentTarget; setMobileOpen(true); }}><Menu /><span>{message(locale, "common.more")}</span></button></nav>}
    </div>
  </main>;
}
