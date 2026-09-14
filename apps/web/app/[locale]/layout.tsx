import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { NextIntlClientProvider } from "next-intl";
import { getMessage } from "@nombramientos/i18n";
import { LocaleSync } from "@/components/nombramientos/locale-sync";
import { isLocale } from "@/lib/messages";
import { intlMessages } from "@/lib/messages";

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  if (!isLocale(locale)) return {};
  return {
    title: getMessage(locale, "app.name"),
    description: getMessage(locale, "app.tagline"),
    manifest: `/${locale}/manifest.webmanifest`,
  };
}

export default async function LocaleLayout({ children, params }: { children: React.ReactNode; params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <NextIntlClientProvider locale={locale} messages={intlMessages[locale]}>
    <LocaleSync locale={locale} skipToContent={getMessage(locale, "a11y.skipToContent")} />
    {children}
  </NextIntlClientProvider>;
}
