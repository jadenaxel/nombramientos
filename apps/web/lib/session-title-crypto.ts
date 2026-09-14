import type { Envelope } from "./api.ts";
import { decryptJson, encryptJson } from "./crypto-client.ts";

export const SESSION_TITLE_SCHEMA = "nombramientos-session-title/v1" as const;
export const AGENDA_TITLE_SCHEMA = "nombramientos-session-agenda-title/v1" as const;

export type EncryptedTitleReference = {
  readonly titleEnvelope: Envelope | null;
  readonly titleVersion: number;
  readonly legacyTitleUnavailable: boolean;
};

type SessionTitleContext = {
  readonly tenantId: string;
  readonly cycleId: string;
  readonly sessionId: string;
  readonly titleVersion: number;
};

type AgendaTitleContext = {
  readonly tenantId: string;
  readonly sessionId: string;
  readonly agendaItemId: string;
  readonly titleVersion: number;
};

export function sessionTitleAad(context: SessionTitleContext) {
  return {
    tenantId: context.tenantId,
    cycleId: context.cycleId,
    sessionId: context.sessionId,
    purpose: "session-title",
    schemaVersion: 1,
    titleVersion: requireTitleVersion(context.titleVersion),
  } as const;
}

export function agendaTitleAad(context: AgendaTitleContext) {
  return {
    tenantId: context.tenantId,
    sessionId: context.sessionId,
    agendaItemId: context.agendaItemId,
    purpose: "session-agenda-title",
    schemaVersion: 1,
    titleVersion: requireTitleVersion(context.titleVersion),
  } as const;
}

export async function sealSessionTitle(
  key: CryptoKey,
  keyId: string,
  context: SessionTitleContext,
  title: string,
) {
  return encryptJson(key, keyId, sessionTitleAad(context), {
    schema: SESSION_TITLE_SCHEMA,
    title: normalizeTitle(title, 160),
  });
}

export async function openSessionTitle(
  key: CryptoKey,
  keyId: string,
  context: SessionTitleContext,
  envelope: Envelope,
): Promise<string> {
  const plaintext = await decryptJson<unknown>(key, envelope, {
    keyId,
    aad: sessionTitleAad(context),
    exactAad: true,
  });
  return parseTitlePlaintext(plaintext, SESSION_TITLE_SCHEMA, 160);
}

export async function sealAgendaTitle(
  key: CryptoKey,
  keyId: string,
  context: AgendaTitleContext,
  title: string,
) {
  return encryptJson(key, keyId, agendaTitleAad(context), {
    schema: AGENDA_TITLE_SCHEMA,
    title: normalizeTitle(title, 240),
  });
}

export async function openAgendaTitle(
  key: CryptoKey,
  keyId: string,
  context: AgendaTitleContext,
  envelope: Envelope,
): Promise<string> {
  const plaintext = await decryptJson<unknown>(key, envelope, {
    keyId,
    aad: agendaTitleAad(context),
    exactAad: true,
  });
  return parseTitlePlaintext(plaintext, AGENDA_TITLE_SCHEMA, 240);
}

export function isLegacyTitleUnavailable(reference: EncryptedTitleReference): boolean {
  return reference.titleEnvelope === null
    && reference.titleVersion === 0
    && reference.legacyTitleUnavailable;
}

function parseTitlePlaintext(value: unknown, schema: string, maximumLength: number): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The encrypted title has an invalid structure.");
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 2 || record["schema"] !== schema || typeof record["title"] !== "string") {
    throw new Error("The encrypted title has an invalid structure.");
  }
  return normalizeTitle(record["title"], maximumLength);
}

function normalizeTitle(value: string, maximumLength: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximumLength) {
    throw new Error("The encrypted title has an invalid length.");
  }
  return normalized;
}

function requireTitleVersion(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error("The encrypted title version is invalid.");
  return value;
}
