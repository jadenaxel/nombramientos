"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, CheckCircle2, LockKeyhole, RefreshCw } from "lucide-react";
import { useVault } from "@/app/providers";
import { Button, buttonVariants } from "@/components/ui/button";
import { type AuthenticatedSession, type Locale } from "@/lib/api";
import { keyLifecycleApi } from "@/lib/key-lifecycle-client";
import { message } from "@/lib/product-i18n";
import { workflowGuide } from "@/lib/workflow-guide";
import type { CycleWorkflow } from "@/lib/workflow-api";

const titles = {
  cycle: "workflow.guide.cycle", key: "workflow.guide.key", directory: "workflow.guide.directory",
  configuration: "workflow.guide.configuration", session: "workflow.guide.session", process: "workflow.guide.process",
  assignments: "workflow.guide.assignments", outputs: "workflow.guide.outputs",
} as const;
const descriptions = {
  cycle: "workflow.guide.cycleHelp", key: "workflow.guide.keyHelp", directory: "workflow.guide.directoryHelp",
  configuration: "workflow.guide.configurationHelp", session: "workflow.guide.sessionHelp", process: "workflow.guide.processHelp",
  assignments: "workflow.guide.assignmentsHelp", outputs: "workflow.guide.outputsHelp",
} as const;

export function WorkflowGuidance({ session, locale, workflow, memberTotal, onStart, onStep, retry }: {
  session: AuthenticatedSession;
  locale: Locale;
  workflow: CycleWorkflow | null | undefined;
  memberTotal?: number;
  onStart: () => void;
  onStep: (step: "configuration" | "process" | "assignments") => void;
  retry: () => void;
}) {
  const vault = useVault();
  const realTenant = session.tenant.kind === "real";
  const keyQuery = useQuery({ queryKey: ["key-lifecycle", session.tenant.id], queryFn: keyLifecycleApi.state, enabled: realTenant, retry: false });
  const keyState = keyQuery.isError || !keyQuery.data ? "unknown" : !keyQuery.data.currentGeneration
    ? keyQuery.data.generations.some((item) => item.status === "lost") ? "lost" : "uninitialized"
    : vault.key && vault.tenantId === session.tenant.id && vault.keyId === keyQuery.data.currentGeneration.tenantKeyId ? "unlocked" : "locked";
  const guide = workflowGuide({ cycle: workflow, realTenant, keyState, memberTotal });
  const next = guide.steps.find((item) => item.id === guide.next)!;
  const can = (permission: string) => session.permissions.includes(permission);
  const destination = guide.next === "key" ? "settings#tenant-key-lifecycle"
    : guide.next === "directory" && can("member.read") ? "members" : undefined;
  const step = guide.next === "session" || guide.next === "configuration" ? "configuration"
    : guide.next === "process" ? "process" : guide.next === "assignments" ? "assignments" : undefined;
  const outputDestinations = [["results", "aggregate.read"], ["organization", "organigram.read"], ["reports", "report.read"]] as const;
  return <section className="surface-card border-teal-200" aria-label={message(locale, "workflow.guide.title")} data-testid="workflow-guidance">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="space-y-2"><p className="eyebrow">{message(locale, "workflow.guide.title")}</p><h2 className="text-xl font-bold">{message(locale, titles[guide.next])}</h2>
        <p className="max-w-3xl text-sm text-muted-foreground">{message(locale, next.state === "unknown" ? "workflow.guide.unknownHelp" : next.state === "blocked" ? "workflow.guide.lostHelp" : descriptions[guide.next])}</p>
        {guide.next === "key" && realTenant && keyState === "uninitialized" && <p className="text-sm font-medium text-teal-950">{message(locale, can("recovery.activate") ? "workflow.guide.initializeHelp" : "workflow.guide.custodianHelp")}</p>}
      </div>
      {next.state === "unknown" ? <Button type="button" variant="outline" onClick={() => { retry(); void keyQuery.refetch(); }}><RefreshCw />{message(locale, "common.refresh")}</Button>
        : destination ? <Link className={buttonVariants()} href={`/${locale}/app/${destination}`}><ArrowRight size={16} />{message(locale, "workflow.guide.continue")}</Link>
          : guide.next === "cycle" ? <Button type="button" onClick={onStart}><ArrowRight />{message(locale, "workflow.quickStart.start")}</Button>
            : step ? <Button type="button" onClick={() => onStep(step)}><ArrowRight />{message(locale, "workflow.guide.continue")}</Button>
              : guide.next === "outputs" ? <div className="flex flex-wrap gap-2">{outputDestinations.filter(([, permission]) => can(permission)).map(([section]) => <Link key={section} className={buttonVariants({ variant: "outline" })} href={`/${locale}/app/${section}`}>{message(locale, section === "results" ? "workflow.guide.results" : section === "organization" ? "workflow.guide.organigram" : "workflow.guide.report")}</Link>)}</div>
                : <p className="text-sm text-muted-foreground">{message(locale, "workflow.guide.custodianHelp")}</p>}
    </div>
    <details className="mt-5 border-t pt-4"><summary className="cursor-pointer text-sm font-semibold">{message(locale, "workflow.guide.allSteps")}</summary>
      <ol className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{guide.steps.map(({ id, state }, index) => <li key={id} className="rounded-xl border p-3" aria-current={id === guide.next ? "step" : undefined}>
        <div className="flex items-center gap-2 text-sm font-semibold">{state === "complete" ? <CheckCircle2 size={17} className="text-emerald-700" /> : state === "blocked" ? <LockKeyhole size={17} /> : <span aria-hidden="true">{index + 1}.</span>}{message(locale, titles[id])}</div>
        <p className="mt-1 text-xs text-muted-foreground">{message(locale, state === "complete" ? "workflow.guide.complete" : state === "unknown" ? "workflow.guide.unknown" : state === "blocked" ? "workflow.guide.blocked" : "workflow.guide.pending")}</p>
      </li>)}</ol>
      <p className="mt-3 text-xs text-muted-foreground">{message(locale, "workflow.guide.scope")}</p>
    </details>
  </section>;
}
