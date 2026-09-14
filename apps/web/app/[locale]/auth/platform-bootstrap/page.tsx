import { notFound } from "next/navigation";
import { PlatformBootstrapForm } from "@/components/nombramientos/platform-bootstrap-form";
import { isLocale } from "@/lib/messages";

export default async function PlatformBootstrapPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <PlatformBootstrapForm locale={locale} />;
}
