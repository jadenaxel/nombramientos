import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getMessage } from "@nombramientos/i18n";

import { InitialAdminOnboardingRecoveryForm } from "@/components/nombramientos/initial-admin-onboarding-recovery-form";
import { isLocale } from "@/lib/messages";

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  if (!isLocale(locale)) return {};
  return {
    title: `${getMessage(locale, "recovery.public.title")} · ${getMessage(locale, "app.name")}`,
    description: getMessage(locale, "recovery.public.description"),
    robots: { index: false, follow: false },
  };
}

export default async function InitialAdminOnboardingRecoveryPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <InitialAdminOnboardingRecoveryForm locale={locale} />;
}
