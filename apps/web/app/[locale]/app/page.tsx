import { AppShell } from "@/components/nombramientos/app-shell";
import { isLocale } from "@/lib/messages";
import { redirect } from "next/navigation";

export default async function AppPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) redirect("/es/app");
  return <AppShell locale={locale} section="landing" />;
}
