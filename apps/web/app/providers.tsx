"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import type { KeyGrant } from "@/lib/api";
import { unlockTenantKey } from "@/lib/crypto-client";
import { TenantCryptoKeyring } from "@/lib/tenant-keyring";
import { AccessibilityPreferencesProvider } from "@/components/nombramientos/accessibility-preferences";
import { PwaRegistration } from "@/components/nombramientos/pwa-registration";

type VaultValue = {
  key?: CryptoKey;
  keyId?: string;
  tenantId?: string;
  keyringRevision: number;
  unlock: (password: string, grant: KeyGrant, tenantId: string) => Promise<void>;
  unlockRaw: (tenantKey: Uint8Array<ArrayBuffer>, keyId: string, tenantId: string) => Promise<void>;
  rememberRaw: (tenantKey: Uint8Array<ArrayBuffer>, keyId: string, tenantId: string) => Promise<void>;
  keyFor: (keyId: string, tenantId: string) => CryptoKey | undefined;
  withRawKey: <T>(tenantId: string, work: (tenantKey: Uint8Array<ArrayBuffer>) => Promise<T>) => Promise<T>;
  lock: () => void;
};

const VaultContext = createContext<VaultValue | undefined>(undefined);
const VAULT_IDLE_TIMEOUT_MS = 10 * 60 * 1_000;

export function useVault() {
  const value = useContext(VaultContext);
  if (!value) throw new Error("VaultProvider is missing");
  return value;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { staleTime: 10_000, retry: 1, refetchOnWindowFocus: false } },
  }));
  const [key, setKey] = useState<CryptoKey>();
  const [keyId, setKeyId] = useState<string>();
  const [tenantId, setTenantId] = useState<string>();
  const [keyringRevision, setKeyringRevision] = useState(0);
  const rawKeyRef = useRef<Uint8Array<ArrayBuffer> | undefined>(undefined);
  const keyringRef = useRef(new TenantCryptoKeyring());
  const lock = useCallback(() => {
    rawKeyRef.current?.fill(0);
    rawKeyRef.current = undefined;
    keyringRef.current.clear();
    setKey(undefined);
    setKeyId(undefined);
    setTenantId(undefined);
    setKeyringRevision((current) => current + 1);
  }, []);

  useEffect(() => {
    if (!key) return;
    let idleTimer = window.setTimeout(lock, VAULT_IDLE_TIMEOUT_MS);
    const renewIdleTimer = () => {
      window.clearTimeout(idleTimer);
      idleTimer = window.setTimeout(lock, VAULT_IDLE_TIMEOUT_MS);
    };
    const lockWhenHidden = () => {
      if (document.visibilityState === "hidden") lock();
    };

    window.addEventListener("pointerdown", renewIdleTimer, { passive: true });
    window.addEventListener("touchstart", renewIdleTimer, { passive: true });
    window.addEventListener("keydown", renewIdleTimer);
    window.addEventListener("pagehide", lock);
    document.addEventListener("visibilitychange", lockWhenHidden);
    return () => {
      window.clearTimeout(idleTimer);
      window.removeEventListener("pointerdown", renewIdleTimer);
      window.removeEventListener("touchstart", renewIdleTimer);
      window.removeEventListener("keydown", renewIdleTimer);
      window.removeEventListener("pagehide", lock);
      document.removeEventListener("visibilitychange", lockWhenHidden);
    };
  }, [key, lock]);

  const unlockRaw = useCallback(async (tenantKey: Uint8Array<ArrayBuffer>, nextKeyId: string, nextTenantId: string) => {
    if (tenantKey.byteLength !== 32) throw new Error("INVALID_TENANT_KEY");
    const rawKey = Uint8Array.from(tenantKey);
    const cryptoKey = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    rawKeyRef.current?.fill(0);
    rawKeyRef.current = rawKey;
    keyringRef.current.rememberCurrent(nextTenantId, nextKeyId, cryptoKey);
    setKey(cryptoKey);
    setKeyId(nextKeyId);
    setTenantId(nextTenantId);
    setKeyringRevision((current) => current + 1);
  }, []);

  const rememberRaw = useCallback(async (tenantKey: Uint8Array<ArrayBuffer>, historicalKeyId: string, expectedTenantId: string) => {
    if (tenantKey.byteLength !== 32) throw new Error("INVALID_TENANT_KEY");
    const rawKey = Uint8Array.from(tenantKey);
    let cryptoKey: CryptoKey;
    try {
      cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"],
      );
    } finally {
      rawKey.fill(0);
    }
    keyringRef.current.rememberHistorical(expectedTenantId, historicalKeyId, cryptoKey);
    setKeyringRevision((current) => current + 1);
  }, []);

  const keyFor = useCallback((requestedKeyId: string, expectedTenantId: string) =>
    keyringRef.current.keyFor(expectedTenantId, requestedKeyId), []);

  const withRawKey = useCallback(async <T,>(expectedTenantId: string, work: (tenantKey: Uint8Array<ArrayBuffer>) => Promise<T>) => {
    if (!rawKeyRef.current || tenantId !== expectedTenantId) throw new Error("TENANT_KEY_LOCKED");
    const workingCopy = Uint8Array.from(rawKeyRef.current);
    try {
      return await work(workingCopy);
    } finally {
      workingCopy.fill(0);
    }
  }, [tenantId]);

  const vault = useMemo<VaultValue>(() => ({
    key,
    keyId,
    tenantId,
    keyringRevision,
    unlock: async (password, grant, nextTenantId) => {
      const tenantKey = await unlockTenantKey(password, grant, nextTenantId);
      keyringRef.current.rememberCurrent(nextTenantId, grant.tenantKeyId, tenantKey);
      setKey(tenantKey);
      setKeyId(grant.tenantKeyId);
      setTenantId(nextTenantId);
      setKeyringRevision((current) => current + 1);
    },
    unlockRaw,
    rememberRaw,
    keyFor,
    withRawKey,
    lock,
  }), [key, keyFor, keyId, keyringRevision, lock, rememberRaw, tenantId, unlockRaw, withRawKey]);

  return <AccessibilityPreferencesProvider><PwaRegistration /><QueryClientProvider client={queryClient}><VaultContext.Provider value={vault}>{children}</VaultContext.Provider></QueryClientProvider></AccessibilityPreferencesProvider>;
}
