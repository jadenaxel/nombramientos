"use client";

import { useEffect } from "react";
import type { Locale } from "@/lib/api";

export function LocaleSync({ locale, skipToContent }: { locale: Locale; skipToContent: string }) {
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  return <a className="skip-link" href="#main-content">{skipToContent}</a>;
}
