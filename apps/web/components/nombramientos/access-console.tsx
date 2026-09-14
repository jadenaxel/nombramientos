"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, LoaderCircle, LockKeyhole, Plus, RefreshCw, Save, ShieldCheck, UserMinus, UserPlus, Users } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  api,
  ApiError,
  type AccessPermission,
  type AuthenticatedSession,
  type Locale,
} from "@/lib/api";
import { message, localizedApiError, permissionDescription } from "@/lib/product-i18n";
import { InvitationsView } from "./invitations-view";

type RoleDraft = {
  name: Record<Locale, string>;
  permissionCodes: string[];
  delegablePermissionCodes: string[];
};

const copy = {
  es: {
    eyebrow: message("es", "screen.accessConsole.0964f9bddf6f"), title: message("es", "screen.accessConsole.aa015d20258a"),
    description: message("es", "screen.accessConsole.aec571575395"),
    create: message("es", "screen.accessConsole.b1ad52b01485"), code: message("es", "screen.accessConsole.e7b054fe74c5"), names: message("es", "screen.accessConsole.91b3e1760e7e"), permissions: message("es", "screen.accessConsole.a5ac415bdd83"),
    delegate: message("es", "screen.accessConsole.b95081ac1817"), save: message("es", "screen.accessConsole.0b0078ea0c81"), createAction: message("es", "screen.accessConsole.7d9f6168ef03"), roles: message("es", "screen.accessConsole.2b7d2d588af7"),
    system: message("es", "screen.accessConsole.0f0a83b1c289"), local: message("es", "screen.accessConsole.fc6ee689e4b2"), edit: message("es", "screen.accessConsole.b38c34b81dc9"), cancel: message("es", "screen.accessConsole.18e29ea869c8"), bindings: message("es", "screen.accessConsole.56f53f5780cb"),
    grant: message("es", "screen.accessConsole.206df1aab8ce"), identity: message("es", "screen.accessConsole.45dbf9372d61"), role: message("es", "screen.accessConsole.2f7980a7df73"), revoke: message("es", "screen.accessConsole.dd1d879556c8"), noBindings: message("es", "screen.accessConsole.e67f5a926e67"),
    protected: message("es", "screen.accessConsole.71bac93233e4"), protectedBody: message("es", "screen.accessConsole.6bf6130b04a8"),
    saved: message("es", "screen.accessConsole.ee59cb7189e8"), failed: message("es", "screen.accessConsole.77013335f901"), loading: message("es", "screen.accessConsole.8b30262bd08d"), loadFailed: message("es", "screen.accessConsole.b75e2bb9103b"), retry: message("es", "screen.accessConsole.fe0bfb5b9dec"),
  },
  en: {
    eyebrow: message("en", "screen.accessConsole.0964f9bddf6f"), title: message("en", "screen.accessConsole.aa015d20258a"),
    description: message("en", "screen.accessConsole.aec571575395"),
    create: message("en", "screen.accessConsole.b1ad52b01485"), code: message("en", "screen.accessConsole.e7b054fe74c5"), names: message("en", "screen.accessConsole.91b3e1760e7e"), permissions: message("en", "screen.accessConsole.a5ac415bdd83"),
    delegate: message("en", "screen.accessConsole.b95081ac1817"), save: message("en", "screen.accessConsole.0b0078ea0c81"), createAction: message("en", "screen.accessConsole.7d9f6168ef03"), roles: message("en", "screen.accessConsole.2b7d2d588af7"),
    system: message("en", "screen.accessConsole.0f0a83b1c289"), local: message("en", "screen.accessConsole.fc6ee689e4b2"), edit: message("en", "screen.accessConsole.b38c34b81dc9"), cancel: message("en", "screen.accessConsole.18e29ea869c8"), bindings: message("en", "screen.accessConsole.56f53f5780cb"),
    grant: message("en", "screen.accessConsole.206df1aab8ce"), identity: message("en", "screen.accessConsole.45dbf9372d61"), role: message("en", "screen.accessConsole.2f7980a7df73"), revoke: message("en", "screen.accessConsole.dd1d879556c8"), noBindings: message("en", "screen.accessConsole.e67f5a926e67"),
    protected: message("en", "screen.accessConsole.71bac93233e4"), protectedBody: message("en", "screen.accessConsole.6bf6130b04a8"),
    saved: message("en", "screen.accessConsole.ee59cb7189e8"), failed: message("en", "screen.accessConsole.77013335f901"), loading: message("en", "screen.accessConsole.8b30262bd08d"), loadFailed: message("en", "screen.accessConsole.b75e2bb9103b"), retry: message("en", "screen.accessConsole.fe0bfb5b9dec"),
  },
  fr: {
    eyebrow: message("fr", "screen.accessConsole.0964f9bddf6f"), title: message("fr", "screen.accessConsole.aa015d20258a"),
    description: message("fr", "screen.accessConsole.aec571575395"),
    create: message("fr", "screen.accessConsole.b1ad52b01485"), code: message("fr", "screen.accessConsole.e7b054fe74c5"), names: message("fr", "screen.accessConsole.91b3e1760e7e"), permissions: message("fr", "screen.accessConsole.a5ac415bdd83"),
    delegate: message("fr", "screen.accessConsole.b95081ac1817"), save: message("fr", "screen.accessConsole.0b0078ea0c81"), createAction: message("fr", "screen.accessConsole.7d9f6168ef03"), roles: message("fr", "screen.accessConsole.2b7d2d588af7"),
    system: message("fr", "screen.accessConsole.0f0a83b1c289"), local: message("fr", "screen.accessConsole.fc6ee689e4b2"), edit: message("fr", "screen.accessConsole.b38c34b81dc9"), cancel: message("fr", "screen.accessConsole.18e29ea869c8"), bindings: message("fr", "screen.accessConsole.56f53f5780cb"),
    grant: message("fr", "screen.accessConsole.206df1aab8ce"), identity: message("fr", "screen.accessConsole.45dbf9372d61"), role: message("fr", "screen.accessConsole.2f7980a7df73"), revoke: message("fr", "screen.accessConsole.dd1d879556c8"), noBindings: message("fr", "screen.accessConsole.e67f5a926e67"),
    protected: message("fr", "screen.accessConsole.71bac93233e4"), protectedBody: message("fr", "screen.accessConsole.6bf6130b04a8"),
    saved: message("fr", "screen.accessConsole.ee59cb7189e8"), failed: message("fr", "screen.accessConsole.77013335f901"), loading: message("fr", "screen.accessConsole.8b30262bd08d"), loadFailed: message("fr", "screen.accessConsole.b75e2bb9103b"), retry: message("fr", "screen.accessConsole.fe0bfb5b9dec"),
  },
} as const;

const emptyNames: Record<Locale, string> = { es: message("es", "screen.accessConsole.799c55d702ef"), en: message("en", "screen.accessConsole.799c55d702ef"), fr: message("fr", "screen.accessConsole.799c55d702ef") };

export function AccessConsole({ locale, session }: { locale: Locale; session: AuthenticatedSession }) {
  const labels = copy[locale];
  const queryClient = useQueryClient();
  const permissionQuery = useQuery({ queryKey: ["access-permissions", session.tenant.id], queryFn: api.accessPermissions });
  const roleQuery = useQuery({ queryKey: ["access-roles", session.tenant.id], queryFn: api.accessRoles });
  const bindingQuery = useQuery({ queryKey: ["access-bindings", session.tenant.id], queryFn: api.accessBindings });
  const [createCode, setCreateCode] = useState("");
  const [createDraft, setCreateDraft] = useState<RoleDraft>({ name: { ...emptyNames }, permissionCodes: [], delegablePermissionCodes: [] });
  const [editingId, setEditingId] = useState<string>();
  const [editDraft, setEditDraft] = useState<RoleDraft>();
  const [targetIdentityId, setTargetIdentityId] = useState("");
  const [grantRoleId, setGrantRoleId] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string }>();
  const permissions = useMemo(() => permissionQuery.data?.items ?? [], [permissionQuery.data?.items]);
  const roles = useMemo(() => roleQuery.data?.items ?? [], [roleQuery.data?.items]);
  const delegable = useMemo(() => new Set(permissions.filter((item) => item.delegable).map((item) => item.code)), [permissions]);
  const grantableRoles = useMemo(
    () => roles.filter((role) => role.permissions.length > 0 && role.permissions.every((item) => delegable.has(item.code))),
    [delegable, roles],
  );

  async function refresh() {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["access-permissions", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["access-roles", session.tenant.id] }),
      queryClient.invalidateQueries({ queryKey: ["access-bindings", session.tenant.id] }),
    ]);
  }

  async function mutate(action: () => Promise<unknown>, after?: () => void) {
    setBusy(true); setNotice(undefined);
    try {
      await action();
      after?.();
      await refresh();
      setNotice({ tone: "success", text: labels.saved });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof ApiError ? localizedApiError(error, locale) : labels.failed });
    } finally { setBusy(false); }
  }

  const heading = <>
    <div className="page-title access-title"><div><p className="eyebrow">{labels.eyebrow}</p><h1>{labels.title}</h1><p>{labels.description}</p></div><Badge><ShieldCheck /> MFA</Badge></div>
    <Alert className="access-assurance"><LockKeyhole /><AlertTitle>{labels.protected}</AlertTitle><AlertDescription>{labels.protectedBody}</AlertDescription></Alert>
  </>;
  const accessLoading = permissionQuery.isLoading || roleQuery.isLoading || bindingQuery.isLoading;
  const accessError = permissionQuery.isError || roleQuery.isError || bindingQuery.isError;
  if (accessLoading || accessError) return <div className="access-console-stack">
    <InvitationsView locale={locale} session={session} />
    {heading}
    {accessLoading ? <div className="loading-block" role="status"><LoaderCircle className="animate-spin" /><span>{labels.loading}</span></div> : <Alert variant="destructive"><AlertTriangle /><AlertTitle>{labels.loadFailed}</AlertTitle><AlertDescription><Button type="button" variant="outline" size="sm" onClick={() => void Promise.all([permissionQuery.refetch(), roleQuery.refetch(), bindingQuery.refetch()])}><RefreshCw /> {labels.retry}</Button></AlertDescription></Alert>}
  </div>;

  return <div className="access-console-stack">
    <InvitationsView locale={locale} session={session} />
    {heading}
    {notice && <Alert className={notice.tone === "error" ? "access-notice-error" : "success-alert"} role="status"><KeyRound /><AlertTitle>{notice.tone === "success" ? labels.saved : labels.failed}</AlertTitle><AlertDescription>{notice.text}</AlertDescription></Alert>}

    <div className="access-admin-grid">
      <section className="surface-card access-role-builder">
        <div className="card-heading"><div><p className="eyebrow">LOCAL</p><h2>{labels.create}</h2></div><span className="form-icon"><Plus /></span></div>
        <form onSubmit={(event) => { event.preventDefault(); void mutate(
          () => api.createAccessRole({ id: crypto.randomUUID(), code: createCode.trim().toUpperCase(), ...createDraft }),
          () => { setCreateCode(""); setCreateDraft({ name: { ...emptyNames }, permissionCodes: [], delegablePermissionCodes: [] }); },
        ); }}>
          <div className="access-form-grid">
            <div><Label htmlFor="access-role-code">{labels.code}</Label><Input id="access-role-code" value={createCode} onChange={(event) => setCreateCode(event.target.value.toUpperCase())} placeholder="LOCAL_COORDINACION" pattern="LOCAL_[A-Z0-9_]{3,54}" required /></div>
            <LocalizedNameFields prefix="create-role" value={createDraft.name} onChange={(name) => setCreateDraft((current) => ({ ...current, name }))} />
          </div>
          <PermissionMatrix locale={locale} labels={labels} permissions={permissions} draft={createDraft} onChange={setCreateDraft} />
          <Button disabled={busy || createDraft.permissionCodes.length === 0} type="submit"><Plus /> {labels.createAction}</Button>
        </form>
      </section>

      <section className="surface-card access-role-list">
        <div className="card-heading"><div><p className="eyebrow">RBAC</p><h2>{labels.roles}</h2></div><Badge variant="outline">{roles.length}</Badge></div>
        <div className="role-catalog-list">{roles.map((role) => <article key={role.id} className={editingId === role.id ? "selected" : ""}>
          <div><strong>{role.name[locale]}</strong><code>{role.code}</code></div><Badge variant={role.system ? "secondary" : "outline"}>{role.system ? labels.system : labels.local}</Badge>
          <small>{role.permissions.map((item) => item.code).join(" · ")}</small>
          {!role.system && <Button type="button" size="sm" variant="outline" onClick={() => {
            setEditingId(role.id);
            setEditDraft({
              name: { ...role.name },
              permissionCodes: role.permissions.map((item) => item.code),
              delegablePermissionCodes: role.permissions.filter((item) => item.delegable).map((item) => item.code),
            });
          }}>{labels.edit}</Button>}
        </article>)}</div>
      </section>
    </div>

    {editingId && editDraft && (() => {
      const role = roles.find((item) => item.id === editingId)!;
      return <section className="surface-card access-role-editor">
        <div className="card-heading"><div><p className="eyebrow">{role.code}</p><h2>{labels.edit}: {role.name[locale]}</h2></div><Badge>v{role.version}</Badge></div>
        <form onSubmit={(event) => { event.preventDefault(); void mutate(
          () => api.updateAccessRole(role.id, { expectedVersion: role.version, ...editDraft }),
          () => setEditingId(undefined),
        ); }}>
          <LocalizedNameFields prefix="edit-role" value={editDraft.name} onChange={(name) => setEditDraft((current) => current ? { ...current, name } : current)} />
          <PermissionMatrix locale={locale} labels={labels} permissions={permissions} draft={editDraft} onChange={setEditDraft} />
          <div className="button-row"><Button disabled={busy || editDraft.permissionCodes.length === 0} type="submit"><Save /> {labels.save}</Button><Button type="button" variant="outline" onClick={() => setEditingId(undefined)}>{labels.cancel}</Button></div>
        </form>
      </section>;
    })()}

    <section className="surface-card access-bindings">
      <div className="card-heading"><div><p className="eyebrow">{labels.grant}</p><h2>{labels.bindings}</h2></div><span className="form-icon"><Users /></span></div>
      <form className="binding-grant-form" onSubmit={(event) => { event.preventDefault(); void mutate(
        () => api.grantAccessBinding(targetIdentityId, grantRoleId),
        () => { setTargetIdentityId(""); setGrantRoleId(""); },
      ); }}>
        <label><span>{labels.identity}</span><select value={targetIdentityId} onChange={(event) => setTargetIdentityId(event.target.value)} required><option value="">—</option>{(bindingQuery.data?.identities ?? []).filter((identity) => identity.identityId !== session.user.id && identity.membershipStatus === "active").map((identity) => <option key={identity.identityId} value={identity.identityId}>{identity.displayName} · {identity.email}</option>)}</select></label>
        <label><span>{labels.role}</span><select value={grantRoleId} onChange={(event) => setGrantRoleId(event.target.value)} required><option value="">—</option>{grantableRoles.map((role) => <option key={role.id} value={role.id}>{role.name[locale]} · {role.code}</option>)}</select></label>
        <Button disabled={busy} type="submit"><UserPlus /> {labels.grant}</Button>
      </form>
      {(bindingQuery.data?.items.length ?? 0) === 0 ? <p className="access-empty">{labels.noBindings}</p> : <div className="binding-list">{bindingQuery.data?.items.map((binding) => {
        const role = roles.find((item) => item.id === binding.roleId);
        const canRevoke = Boolean(role && grantableRoles.some((item) => item.id === role.id) && binding.identityId !== session.user.id);
        return <article key={`${binding.identityId}:${binding.roleId}`}><span className="metric-icon cyan"><ShieldCheck /></span><div><strong>{binding.identity?.displayName ?? binding.identityId}</strong><small>{binding.identity?.email ?? ""}</small></div><div><code>{binding.roleCode}</code><small>v{binding.version}</small></div><Button disabled={busy || !canRevoke} variant="outline" size="sm" onClick={() => void mutate(() => api.revokeAccessBinding(binding.identityId, binding.roleId, binding.version))}><UserMinus /> {labels.revoke}</Button></article>;
      })}</div>}
    </section>
  </div>;
}

function LocalizedNameFields({ prefix, value, onChange }: {
  prefix: string;
  value: Record<Locale, string>;
  onChange: (value: Record<Locale, string>) => void;
}) {
  return <div className="localized-name-fields">{(["es", "en", "fr"] as const).map((language) => <div key={language}><Label htmlFor={`${prefix}-${language}`}>{language.toUpperCase()}</Label><Input id={`${prefix}-${language}`} value={value[language]} onChange={(event) => onChange({ ...value, [language]: event.target.value })} minLength={2} maxLength={120} required /></div>)}</div>;
}

function PermissionMatrix({ locale, labels, permissions, draft, onChange }: {
  locale: Locale;
  labels: (typeof copy)[Locale];
  permissions: readonly AccessPermission[];
  draft: RoleDraft;
  onChange: (draft: RoleDraft) => void;
}) {
  const available = permissions.filter((permission) => permission.delegable);
  function togglePermission(code: string, enabled: boolean) {
    const permissionCodes = enabled ? [...draft.permissionCodes, code] : draft.permissionCodes.filter((item) => item !== code);
    const delegablePermissionCodes = enabled ? draft.delegablePermissionCodes : draft.delegablePermissionCodes.filter((item) => item !== code);
    onChange({ ...draft, permissionCodes, delegablePermissionCodes });
  }
  return <fieldset className="permission-matrix"><legend>{labels.permissions}</legend>{available.map((permission) => {
    const selected = draft.permissionCodes.includes(permission.code);
    const delegated = draft.delegablePermissionCodes.includes(permission.code);
    return <div key={permission.code}><label><input type="checkbox" checked={selected} onChange={(event) => togglePermission(permission.code, event.target.checked)} /><span><strong>{permission.code}</strong><small>{permissionDescription(locale, permission)}</small></span></label><label className="delegation-check"><input type="checkbox" checked={delegated} disabled={!selected} onChange={(event) => onChange({ ...draft, delegablePermissionCodes: event.target.checked ? [...draft.delegablePermissionCodes, permission.code] : draft.delegablePermissionCodes.filter((item) => item !== permission.code) })} /> {labels.delegate}</label></div>;
  })}</fieldset>;
}
