import { en } from "./en.js";
import { es, type MessageKey } from "./es.js";
import { fr } from "./fr.js";
import type { Locale } from "./types.js";

export * from "./types.js";
export * from "./glossary.js";
export type { MessageKey } from "./es.js";

export const messages = { es, en, fr } as const;

export const getMessages = (locale: Locale): Readonly<Record<MessageKey, string>> => messages[locale];

export const getMessage = (locale: Locale, key: MessageKey): string => messages[locale][key];

export const messageKeyCount = Object.keys(es).length;
