import { Suspense } from "react";
import { notFound } from "next/navigation";
import { GestionChurchBridge } from "@/components/nombramientos/gestionchurch-bridge";
import { isLocale } from "@/lib/messages";

export default async function GestionChurchIntegrationPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <Suspense fallback={<main className="grid min-h-screen place-items-center bg-background"><p>Validando acceso seguro…</p></main>}>
    <GestionChurchBridge locale={locale} />
  </Suspense>;
}
