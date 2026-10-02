"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { api, ApiError, setCsrfToken, type Locale } from "@/lib/api";
import { appLandingPath, canAccessAppSection } from "@/lib/app-navigation";
import { FEDERATED_RESUME_PATH_KEY } from "@/lib/gestionchurch-session";

export function GestionChurchBridge({ locale }: { locale: Locale }) {
  const router = useRouter();
  const search = useSearchParams();
  const consumed = useRef(false);
  const launchCode = search.get("code") ?? "";
  const copy = {
    es: {
      invalid: "El acceso de un solo uso no es válido. Vuelve a abrir Nombramientos desde GestionChurch.",
      notReady: "El espacio de esta iglesia todavía se está preparando. Reinicia GestionChurch y vuelve a intentarlo.",
      expired: "El acceso venció o no pudo validarse. Vuelve a abrir el módulo desde GestionChurch.",
      module: "Un módulo de GestionChurch",
      eyebrow: "Acceso centralizado",
      promise: "Un solo ingreso, una iglesia protegida.",
      validation: "Validamos el tenant y los permisos directamente con GestionChurch.",
      failed: "Acceso no completado",
      connecting: "Conectando tu espacio",
      preparing: "Estamos preparando Nombramientos con tus roles actuales.",
      back: "Volver a GestionChurch",
      oneTime: "El código de acceso es de un solo uso y ya fue retirado de la dirección.",
    },
    en: {
      invalid: "The one-time access is invalid. Open Nominations again from GestionChurch.",
      notReady: "This church workspace is still being prepared. Restart GestionChurch and try again.",
      expired: "Access expired or could not be validated. Open the module again from GestionChurch.",
      module: "A GestionChurch module",
      eyebrow: "Centralized access",
      promise: "One sign-in, one protected church.",
      validation: "We validate the tenant and permissions directly with GestionChurch.",
      failed: "Access not completed",
      connecting: "Connecting your workspace",
      preparing: "We are preparing Nominations with your current roles.",
      back: "Return to GestionChurch",
      oneTime: "The one-time access code has already been removed from the address.",
    },
    fr: {
      invalid: "L’accès à usage unique n’est pas valide. Ouvrez de nouveau Nominations depuis GestionChurch.",
      notReady: "L’espace de cette église est encore en préparation. Redémarrez GestionChurch et réessayez.",
      expired: "L’accès a expiré ou n’a pas pu être validé. Ouvrez de nouveau le module depuis GestionChurch.",
      module: "Un module de GestionChurch",
      eyebrow: "Accès centralisé",
      promise: "Une seule connexion, une église protégée.",
      validation: "Nous validons le tenant et les autorisations directement auprès de GestionChurch.",
      failed: "Accès non finalisé",
      connecting: "Connexion à votre espace",
      preparing: "Nous préparons Nominations avec vos rôles actuels.",
      back: "Retourner à GestionChurch",
      oneTime: "Le code d’accès à usage unique a déjà été retiré de l’adresse.",
    },
  } as const;
  const labels = copy[locale];
  const invalidLaunchMessage = labels.invalid;
  const launchCodeIsValid = /^[A-Za-z0-9_-]{43}$/u.test(launchCode);
  const [error, setError] = useState(() => launchCodeIsValid ? "" : invalidLaunchMessage);

  useEffect(() => {
    if (consumed.current) return;
    consumed.current = true;
    window.history.replaceState({}, "", `/${locale}/integration/gestionchurch`);
    if (!launchCodeIsValid) return;
    void api.gestionChurchSession(launchCode).then((session) => {
      setCsrfToken(session.csrfToken);
      const resumePath = window.sessionStorage.getItem(FEDERATED_RESUME_PATH_KEY);
      window.sessionStorage.removeItem(FEDERATED_RESUME_PATH_KEY);
      const resumeSection = resumePath?.match(/^\/(es|en|fr)\/app\/([a-z-]+)$/u);
      const destination = resumePath && resumeSection?.[1] === locale && canAccessAppSection(resumeSection[2] ?? "", session.permissions)
        ? resumePath
        : appLandingPath(locale, session.permissions);
      router.replace(destination);
      router.refresh();
    }).catch((reason) => {
      setError(reason instanceof ApiError && reason.code === "NOMINATIONS_TENANT_NOT_READY"
        ? labels.notReady
        : labels.expired);
    });
  }, [labels.expired, labels.notReady, launchCode, launchCodeIsValid, locale, router]);

  const gestionChurchUrl = process.env.NEXT_PUBLIC_GESTIONCHURCH_URL ?? "http://localhost:3000";
  return <main className="login-shell">
    <section className="login-visual"><div className="brand-lockup"><span className="brand-mark">N</span><span><strong>Nombramientos</strong><small>{labels.module}</small></span></div><div className="login-promise"><span className="eyebrow">{labels.eyebrow}</span><h1>{labels.promise}</h1><p>{labels.validation}</p></div></section>
    <section className="login-panel"><div className="login-card text-center"><span className="form-icon mx-auto"><ShieldCheck /></span><h2>{error ? labels.failed : labels.connecting}</h2><p>{error || labels.preparing}</p>{!error && <LoaderCircle className="mx-auto mt-6 animate-spin text-primary" />}{error && <Button className="mt-6" onClick={() => window.location.assign(new URL("/nominations", gestionChurchUrl).toString())}><RefreshCw /> {labels.back}</Button>}<small className="mt-6 block text-muted-foreground">{labels.oneTime}</small></div></section>
  </main>;
}
