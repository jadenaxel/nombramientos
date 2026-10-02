import { notFound, redirect } from "next/navigation";
import { LoginForm } from "@/components/nombramientos/login-form";
import { isLocale } from "@/lib/messages";

export default async function SignInPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  const gestionChurchUrl = process.env.NEXT_PUBLIC_GESTIONCHURCH_URL;
  if (gestionChurchUrl) redirect(new URL("/nominations", gestionChurchUrl).toString());
  return <LoginForm locale={locale} />;
}
