import { notFound } from "next/navigation";
import { InvitationAcceptForm } from "@/components/nombramientos/invitation-accept-form";
import { isLocale } from "@/lib/messages";

export default async function InvitationPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <InvitationAcceptForm locale={locale} />;
}
