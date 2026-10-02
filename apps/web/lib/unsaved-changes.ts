const pending = new Map<symbol, () => boolean>();

/** Holds only dirty flags and confirmation callbacks, never plaintext drafts. */
export function registerUnsavedChanges(confirmLeave: () => boolean): () => void {
  const id = Symbol("unsaved-form");
  pending.set(id, confirmLeave);
  return () => { pending.delete(id); };
}

export function confirmUnsavedNavigation(): boolean {
  for (const confirm of pending.values()) if (!confirm()) return false;
  return true;
}

export function hasUnsavedChanges(): boolean { return pending.size > 0; }

export function isLeavingDocument(href: string, currentHref: string): boolean {
  try {
    const destination = new URL(href, currentHref);
    const current = new URL(currentHref);
    return destination.origin !== current.origin || destination.pathname !== current.pathname || destination.search !== current.search;
  } catch { return false; }
}
