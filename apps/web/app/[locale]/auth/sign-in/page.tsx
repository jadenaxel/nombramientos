import { notFound } from "next/navigation";
import { LoginForm } from "@/components/nombramientos/login-form";
import { isLocale } from "@/lib/messages";

export default async function SignInPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale } = await params;
  if (!isLocale(locale)) notFound();
  return <LoginForm locale={locale} />;
}
