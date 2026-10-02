"use client";

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import type { AuthenticatedSession } from "./api.ts";
import { DEVICE_SESSION_READY_EVENT, loadDeviceSessionState, resumeRecognizedDevice, type DeviceSessionState } from "./device-session-client.ts";
import { currentDeviceProofContext, currentDeviceSigner } from "./device-session-proof.ts";
import { listLocalTenantDevices } from "./key-lifecycle-client.ts";

/** Sidebar and workspace share one readiness fence; neither may send data
 * requests until this exact HTTP session resumes its immutable local signer. */
export function deviceWorkspaceReady(session: AuthenticatedSession | undefined, state: DeviceSessionState | undefined, recognized: boolean): boolean {
  const context = currentDeviceProofContext(), signer = currentDeviceSigner();
  return Boolean(session?.sessionId && recognized && context && signer && state?.binding
    && state.session.sessionId === session.sessionId && context.sessionId === session.sessionId
    && state.session.tenantId === session.tenant.id && state.session.identityId === session.user.id
    && context.tenantId === session.tenant.id && context.identityId === session.user.id
    && context.sourceSessionId === state.session.sourceSessionId
    && signer.deviceId === state.binding.deviceId && signer.fingerprint === state.binding.signingFingerprint
    && state.binding.status === "active" && state.binding.deviceStatus === "active" && state.binding.hasActiveGrant);
}

export function useDeviceSessionReadiness(session?: AuthenticatedSession, platformMode = false) {
  const query = useQuery({ queryKey: ["device-session", session?.tenant.id, session?.user.id, session?.sessionId],
    enabled: Boolean(session?.sessionId && session.tenant.kind === "real" && !platformMode
      && !session.security.enrollmentOnly && !session.security.recoveryRestricted),
    retry: false, refetchOnWindowFocus: true, refetchInterval: 30_000,
    queryFn: async () => {
      const authenticated = session!;
      const state = await loadDeviceSessionState(authenticated);
      const devices = await listLocalTenantDevices(authenticated.tenant.id, authenticated.user.id);
      const recognized = await resumeRecognizedDevice(authenticated, devices);
      return { state: recognized ?? state, devices, ready: Boolean(recognized) };
    } });
  const refetch = query.refetch;
  useEffect(() => {
    const refresh = () => { void refetch(); };
    window.addEventListener(DEVICE_SESSION_READY_EVENT, refresh);
    return () => window.removeEventListener(DEVICE_SESSION_READY_EVENT, refresh);
  }, [refetch]);
  return { ...query, workspaceReady: deviceWorkspaceReady(session, query.data?.state, Boolean(query.data?.ready)) };
}
