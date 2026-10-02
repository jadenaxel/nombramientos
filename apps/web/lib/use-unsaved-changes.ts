"use client";

import { useEffect } from "react";
import type { Locale } from "./api";
import { message } from "./product-i18n";
import { isLeavingDocument, registerUnsavedChanges } from "./unsaved-changes";

/** A warning, not persistence: confidential form values remain memory-only. */
export function useUnsavedChanges(dirty: boolean, locale: Locale): () => boolean {
  const confirmLeave = () => !dirty || window.confirm(message(locale, "common.unsavedConfirm"));
  useEffect(() => {
    if (!dirty) return;
    const confirm = () => window.confirm(message(locale, "common.unsavedConfirm"));
    const unregister = registerUnsavedChanges(confirm);
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    const navigate = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      const anchor = event.target instanceof Element ? event.target.closest<HTMLAnchorElement>("a[href]") : null;
      if (!anchor || anchor.download || (anchor.target && anchor.target !== "_self") || !isLeavingDocument(anchor.href, window.location.href)) return;
      if (!confirm()) { event.preventDefault(); event.stopImmediatePropagation(); }
    };
    window.addEventListener("beforeunload", unload);
    document.addEventListener("click", navigate, true);
    return () => {
      unregister();
      window.removeEventListener("beforeunload", unload);
      document.removeEventListener("click", navigate, true);
    };
  }, [dirty, locale]);
  return confirmLeave;
}
