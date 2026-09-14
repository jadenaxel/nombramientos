import { notFound } from "next/navigation";
import { AppShell } from "@/components/nombramientos/app-shell";
import { isLocale } from "@/lib/messages";

const sections = new Set(["overview","workflow","session","members","catalog","committee","organization","reports","access","custody","history","settings","results","library","onboarding","platform"]);

export default async function AppSectionPage({ params }: { params: Promise<{ locale: string; section: string }> }) {
  const { locale, section } = await params;
  if (!isLocale(locale) || !sections.has(section)) notFound();
  return <AppShell locale={locale} section={section} />;
}
