"use client";

import { useId, useMemo, useState, type ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts";

import { Badge } from "@/components/ui/badge";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { DashboardData, Locale, OrganizationRecord } from "@/lib/api";
import {
  analyticsPercent,
  departmentProgressRows,
  responsibilityDistributionRows,
  roundParticipationRows,
  sessionEvolutionRows,
} from "@/lib/dashboard-analytics";
import { message, phaseLabel } from "@/lib/product-i18n";
import { formatInTenantTimeZone } from "@/lib/tenant-time";

function formatPercent(value: number | null, locale: Locale): string {
  return value === null
    ? message(locale, "screen.analyticsCharts.14a82ef6df2a")
    : `${new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(value)} %`;
}

function compactAxisLabel(value: string, maximum = 16): string {
  return value.length <= maximum ? value : `${value.slice(0, maximum - 1)}…`;
}

function sessionStatusLabel(locale: Locale, status: string): string {
  const labels: Record<string, Parameters<typeof message>[1]> = {
    scheduled: "screen.analyticsCharts.308dce0cc0b0",
    in_progress: "screen.analyticsCharts.4fa7e5d0a2fc",
    closed: "screen.analyticsCharts.823c27263108",
  };
  const value = labels[status];
  return value ? message(locale, value) : status;
}

function cyclePeriod(data: DashboardData, locale: Locale): string {
  return data.cycle ? `${data.cycle.termStart} — ${data.cycle.termEnd}` : message(locale, "screen.analyticsCharts.14a82ef6df2a");
}

function AnalyticsMeta({ locale, timeZone, period, filter, phase, denominator, version, updatedAt, permission }: {
  locale: Locale;
  timeZone: string;
  period: string;
  filter: string;
  phase: string;
  denominator: string | number | null;
  version: string;
  updatedAt: string;
  permission: string;
}) {
  const denominatorLabel = denominator === null || denominator === 0 ? message(locale, "screen.analyticsCharts.14a82ef6df2a") : denominator;
  return <dl className="mt-4 grid gap-2 rounded-2xl border border-slate-200 bg-slate-50/80 p-3 text-xs text-slate-600 sm:grid-cols-2 xl:grid-cols-3">
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.0a4ee1b91101")}</dt><dd>{period}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.cfa06c903766")}</dt><dd>{filter}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.21c749ea4cb9")}</dt><dd>{phase}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.68f9c136f1e3")}</dt><dd>{denominatorLabel}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.2a0a3b41eba1")}</dt><dd>{version}</dd></div>
    <div><dt className="font-semibold text-slate-900">{message(locale, "screen.analyticsCharts.648a889041d9")}</dt><dd>{formatInTenantTimeZone(updatedAt, locale, timeZone, { dateStyle: "short", timeStyle: "short" })}</dd></div>
    <div className="sm:col-span-2 xl:col-span-3"><dt className="sr-only">{message(locale, "screen.analyticsCharts.b3d6e46fe420")}</dt><dd><Badge variant="outline">{permission}</Badge></dd></div>
  </dl>;
}

function AnalyticsShell({ id, eyebrow, title, description, controls, children, meta }: {
  id: string;
  eyebrow: string;
  title: string;
  description: string;
  controls?: ReactNode;
  children: ReactNode;
  meta: ReactNode;
}) {
  return <section className="surface-card min-w-0 overflow-hidden" aria-labelledby={id}>
    <div className="card-heading flex-wrap items-start gap-4"><div className="min-w-0"><p className="eyebrow">{eyebrow}</p><h2 id={id}>{title}</h2><p>{description}</p></div>{controls}</div>
    {children}
    {meta}
  </section>;
}

function EmptyChartRow({ locale, columns }: { locale: Locale; columns: number }) {
  return <tr><td colSpan={columns}>{message(locale, "screen.analyticsCharts.f4adf0703bf1")}</td></tr>;
}

function participationConfig(locale: Locale): ChartConfig {
  return {
    received: { label: message(locale, "screen.analyticsCharts.c7f32e1048e3"), color: "hsl(190 84% 35%)" },
    pending: { label: message(locale, "screen.analyticsCharts.46d13efc67c6"), color: "hsl(215 20% 82%)" },
  };
}

export function RoundParticipationAnalytics({ data, locale, timeZone }: { data: DashboardData; locale: Locale; timeZone: string }) {
  const titleId = useId();
  const [kind, setKind] = useState<"all" | "proposal" | "vote">("all");
  const rows = useMemo(() => roundParticipationRows(data, locale), [data, locale]);
  const visible = kind === "all" ? rows : rows.filter((row) => row.kind === kind);
  const kindLabel = (value: "proposal" | "vote") => value === "proposal"
    ? message(locale, "screen.analyticsCharts.e3cd6351cf2b")
    : message(locale, "screen.analyticsCharts.471d33c1eccc");
  const filterLabel = kind === "all" ? message(locale, "screen.analyticsCharts.fd0ecb72979f") : kindLabel(kind);
  const chartData = visible.map((row) => ({ label: kindLabel(row.kind), received: row.received, pending: row.pending }));
  const phases = visible.length ? [...new Set(visible.map((row) => phaseLabel(locale, row.phase)))].join(" · ") : message(locale, "screen.analyticsCharts.66c1ce4a524e");
  const versions = visible.length ? visible.map((row) => `${kindLabel(row.kind)} v${row.version}`).join(" · ") : `v${data.cycle?.version ?? 0}`;
  return <AnalyticsShell id={titleId} eyebrow={message(locale, "screen.analyticsCharts.cde2d099be73")} title={message(locale, "screen.analyticsCharts.36e6a6c80806")} description={message(locale, "screen.analyticsCharts.775fea2eeead")} controls={<label className="grid shrink-0 gap-1 text-xs font-semibold text-slate-700">{message(locale, "screen.analyticsCharts.1656c049b119")}<select className="h-9 rounded-lg border bg-white px-2 font-normal" value={kind} onChange={(event) => setKind(event.target.value as typeof kind)}><option value="all">{message(locale, "screen.analyticsCharts.b5d88699e335")}</option><option value="proposal">{kindLabel("proposal")}</option><option value="vote">{kindLabel("vote")}</option></select></label>} meta={<AnalyticsMeta locale={locale} timeZone={timeZone} period={cyclePeriod(data, locale)} filter={filterLabel} phase={phases} denominator={visible.length ? message(locale, "screen.analyticsCharts.0b4ee1b91102") : null} version={versions} updatedAt={data.updatedAt} permission="aggregate.read" />}>
    <div className="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <div className="min-w-0" role="img" aria-label={message(locale, "screen.analyticsCharts.e845cacaeb74")}>
        {chartData.length ? <ChartContainer config={participationConfig(locale)} className="h-64 w-full min-w-0 aspect-auto" initialDimension={{ width: 280, height: 256 }}><BarChart accessibilityLayer data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}><CartesianGrid vertical={false} /><XAxis dataKey="label" tickLine={false} axisLine={false} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} /><ChartTooltip content={<ChartTooltipContent />} /><Bar dataKey="received" name={message(locale, "screen.analyticsCharts.c7f32e1048e3")} stackId="responses" fill="var(--color-received)" isAnimationActive={false} /><Bar dataKey="pending" name={message(locale, "screen.analyticsCharts.46d13efc67c6")} stackId="responses" fill="var(--color-pending)" radius={[6, 6, 0, 0]} isAnimationActive={false} /></BarChart></ChartContainer> : <p className="stage-disclaimer">{message(locale, "screen.analyticsCharts.b815391bfdca")}</p>}
      </div>
      <div className="responsive-table min-w-0"><table><caption className="sr-only">{message(locale, "screen.analyticsCharts.45e4372080a9")}</caption><thead><tr><th>{message(locale, "screen.analyticsCharts.ca0476bb7338")}</th><th>{message(locale, "screen.analyticsCharts.c7f32e1048e3")}</th><th>{message(locale, "screen.analyticsCharts.f7ad5a0e64cc")}</th><th>{message(locale, "screen.analyticsCharts.ea220c449bb5")}</th></tr></thead><tbody>{visible.length ? visible.map((row) => <tr key={row.roundId}><td><strong>{kindLabel(row.kind)}</strong><small className="block text-slate-500">{row.office} · {phaseLabel(locale, row.phase)} · v{row.version}</small></td><td>{row.received}</td><td>{row.required}</td><td>{formatPercent(row.percent, locale)}</td></tr>) : <EmptyChartRow locale={locale} columns={4} />}</tbody></table></div>
    </div>
  </AnalyticsShell>;
}

function departmentConfig(label: string): ChartConfig {
  return { value: { label, color: "hsl(190 84% 35%)" } };
}

export function DepartmentProgressAnalytics({ data, locale, timeZone }: { data: DashboardData; locale: Locale; timeZone: string }) {
  const titleId = useId();
  const [stage, setStage] = useState<"recommended" | "accepted" | "elected">("recommended");
  const rows = useMemo(() => departmentProgressRows(data, locale, message(locale, "screen.analyticsCharts.857b50586310")), [data, locale]);
  const stageLabel = { recommended: message(locale, "screen.analyticsCharts.ecea10d38368"), accepted: message(locale, "screen.analyticsCharts.f07e03a0fbec"), elected: message(locale, "screen.analyticsCharts.a32b6e0ecea0") }[stage];
  const chartData = rows.map((row) => ({ label: row.department, value: analyticsPercent(row[stage], row.vacanciesTotal) ?? 0 }));
  const height = Math.max(240, rows.length * 42);
  return <AnalyticsShell id={titleId} eyebrow={message(locale, "screen.analyticsCharts.0fc3877b7677")} title={message(locale, "screen.analyticsCharts.736370dd627b")} description={message(locale, "screen.analyticsCharts.dab50cba5f39")} controls={<label className="grid max-w-full shrink-0 gap-1 text-xs font-semibold text-slate-700">{message(locale, "screen.analyticsCharts.217799dd8abc")}<select className="h-9 max-w-full rounded-lg border bg-white px-2 font-normal" value={stage} onChange={(event) => setStage(event.target.value as typeof stage)}><option value="recommended">{message(locale, "screen.analyticsCharts.08460001283d")}</option><option value="accepted">{message(locale, "screen.analyticsCharts.fe489c273bae")}</option><option value="elected">{message(locale, "screen.analyticsCharts.9a730756cc00")}</option></select></label>} meta={<AnalyticsMeta locale={locale} timeZone={timeZone} period={cyclePeriod(data, locale)} filter={`${data.cycle?.name ?? message(locale, "screen.analyticsCharts.390f54c5f235")} · ${message(locale, "screen.analyticsCharts.7f4fe51aa698")}`} phase={stageLabel} denominator={rows.length ? message(locale, "screen.analyticsCharts.0c4ee1b91103") : null} version={`v${data.cycle?.version ?? 0}`} updatedAt={data.updatedAt} permission="aggregate.read" />}>
    <div className="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
      <div className="max-h-[32rem] min-w-0 overflow-y-auto" role="img" aria-label={`${message(locale, "screen.analyticsCharts.1ba19de30c78")}: ${stageLabel}`}>
        {rows.length ? <ChartContainer config={departmentConfig(stageLabel)} className="w-full min-w-0 aspect-auto" style={{ height }} initialDimension={{ width: 280, height }}><BarChart accessibilityLayer data={chartData} layout="vertical" margin={{ top: 0, right: 14, bottom: 0, left: 4 }}><CartesianGrid horizontal={false} /><XAxis type="number" domain={[0, 100]} tickFormatter={(value) => `${value}%`} tickLine={false} axisLine={false} /><YAxis type="category" dataKey="label" width={92} tickFormatter={(value) => compactAxisLabel(String(value))} tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><ChartTooltip content={<ChartTooltipContent formatter={(value) => <span className="font-mono font-medium">{Number(value).toLocaleString(locale, { maximumFractionDigits: 2 })} %</span>} />} /><Bar dataKey="value" name={stageLabel} fill="var(--color-value)" radius={[0, 6, 6, 0]} isAnimationActive={false} /></BarChart></ChartContainer> : <p className="stage-disclaimer">{message(locale, "screen.analyticsCharts.359839269d51")}</p>}
      </div>
      <div className="responsive-table min-w-0"><table><caption className="sr-only">{message(locale, "screen.analyticsCharts.05ccc59c97c0")}</caption><thead><tr><th>{message(locale, "screen.analyticsCharts.a9c1f5f4089f")}</th><th>{stageLabel}</th><th>{message(locale, "screen.analyticsCharts.91eea5daa3f0")}</th><th>{message(locale, "screen.analyticsCharts.ea220c449bb5")}</th></tr></thead><tbody>{rows.length ? rows.map((row) => { const value = row[stage]; return <tr key={row.departmentId ?? row.department}><td>{row.department}</td><td>{value}</td><td>{row.vacanciesTotal}</td><td>{formatPercent(analyticsPercent(value, row.vacanciesTotal), locale)}</td></tr>; }) : <EmptyChartRow locale={locale} columns={4} />}</tbody></table></div>
    </div>
  </AnalyticsShell>;
}

function responsibilityConfig(locale: Locale): ChartConfig {
  return { value: { label: message(locale, "screen.analyticsCharts.e71a1bf62a6c"), color: "hsl(221 68% 37%)" } };
}

function candidateVoteConfig(locale: Locale): ChartConfig {
  return { value: { label: message(locale, "screen.analyticsCharts.471d33c1eccc"), color: "hsl(221 68% 37%)" } };
}

export function ResponsibilityDistributionAnalytics({ items, data, locale, timeZone }: { items: readonly OrganizationRecord[]; data: DashboardData; locale: Locale; timeZone: string }) {
  const titleId = useId();
  const rows = useMemo(() => responsibilityDistributionRows(items, data.metrics.eligibleReference).map((row) => ({
    ...row,
    label: message(locale, ({
      zero: "screen.analyticsCharts.018d62fbb101",
      one: "screen.analyticsCharts.12f9195cc102",
      two: "screen.analyticsCharts.24e5c927f103",
      threePlus: "screen.analyticsCharts.35d13b82a104",
    } as const)[row.key]),
  })), [data.metrics.eligibleReference, items, locale]);
  const denominator = rows[0]?.denominator ?? 0;
  return <AnalyticsShell id={titleId} eyebrow={message(locale, "screen.analyticsCharts.b3f0f133b369")} title={message(locale, "screen.analyticsCharts.43c2aace70d4")} description={message(locale, "screen.analyticsCharts.cc9c5408fb13")} meta={<AnalyticsMeta locale={locale} timeZone={timeZone} period={cyclePeriod(data, locale)} filter={`${data.cycle?.name ?? message(locale, "screen.analyticsCharts.390f54c5f235")} · ${message(locale, "screen.analyticsCharts.ae57d7a4e160")}`} phase={message(locale, "screen.analyticsCharts.644b20b407ec")} denominator={denominator || null} version={`v${data.cycle?.version ?? 0}`} updatedAt={data.updatedAt} permission="organigram.read" />}>
    <div className="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <div className="min-w-0" role="img" aria-label={message(locale, "screen.analyticsCharts.0f9f71239384")}>{denominator ? <ChartContainer config={responsibilityConfig(locale)} className="h-56 w-full min-w-0 aspect-auto" initialDimension={{ width: 280, height: 224 }}><BarChart accessibilityLayer data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}><CartesianGrid vertical={false} /><XAxis dataKey="label" tickLine={false} axisLine={false} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} /><ChartTooltip content={<ChartTooltipContent />} /><Bar dataKey="value" name={message(locale, "screen.analyticsCharts.e71a1bf62a6c")} fill="var(--color-value)" radius={[6, 6, 0, 0]} isAnimationActive={false} /></BarChart></ChartContainer> : <p className="stage-disclaimer">{message(locale, "screen.analyticsCharts.cce3b700bb8b")}</p>}</div>
      <div className="responsive-table min-w-0"><table><caption className="sr-only">{message(locale, "screen.analyticsCharts.6935ce83ff58")}</caption><thead><tr><th>{message(locale, "screen.analyticsCharts.1656c049b119")}</th><th>{message(locale, "screen.analyticsCharts.e71a1bf62a6c")}</th><th>{message(locale, "screen.analyticsCharts.d3420e567325")}</th><th>{message(locale, "screen.analyticsCharts.877e05955293")}</th><th>{message(locale, "screen.analyticsCharts.4e2018ea0801")}</th></tr></thead><tbody>{rows.map((row) => <tr key={row.key}><td>{row.label}</td><td>{row.value}</td><td>{row.denominator}</td><td>{formatPercent(row.percent, locale)}</td><td>{row.linkedFunctions}</td></tr>)}</tbody></table></div>
    </div>
  </AnalyticsShell>;
}

function sessionConfig(locale: Locale): ChartConfig {
  return {
    agendaItems: { label: message(locale, "screen.analyticsCharts.a70d027e7b16"), color: "hsl(190 84% 35%)" },
    decisions: { label: message(locale, "screen.analyticsCharts.dde48235221f"), color: "hsl(42 88% 44%)" },
  };
}

export function SessionEvolutionAnalytics({ data, locale, timeZone }: { data: DashboardData; locale: Locale; timeZone: string }) {
  const titleId = useId();
  const [metric, setMetric] = useState<"both" | "agendaItems" | "decisions">("both");
  const rows = useMemo(() => sessionEvolutionRows(data), [data]);
  const chartData = rows.map((row) => ({ ...row, label: `${message(locale, "screen.analyticsCharts.bba4234f0ca5")} ${row.sequence}` }));
  const metricLabel = metric === "both" ? message(locale, "screen.analyticsCharts.4f346f1fd30d") : metric === "agendaItems" ? message(locale, "screen.analyticsCharts.a70d027e7b16") : message(locale, "screen.analyticsCharts.dde48235221f");
  const phases = rows.length ? [...new Set(rows.map((row) => sessionStatusLabel(locale, row.status)))].join(" · ") : message(locale, "screen.analyticsCharts.b6396180dfd1");
  const versions = rows.length ? rows.map((row) => `S${row.sequence} v${row.version}`).join(" · ") : `v${data.cycle?.version ?? 0}`;
  return <AnalyticsShell id={titleId} eyebrow={message(locale, "screen.analyticsCharts.658ddf2a84ec")} title={message(locale, "screen.analyticsCharts.e703b991aedc")} description={message(locale, "screen.analyticsCharts.ee103ef2035c")} controls={<label className="grid max-w-full shrink-0 gap-1 text-xs font-semibold text-slate-700">{message(locale, "screen.analyticsCharts.600dff6d6dd6")}<select className="h-9 max-w-full rounded-lg border bg-white px-2 font-normal" value={metric} onChange={(event) => setMetric(event.target.value as typeof metric)}><option value="both">{message(locale, "screen.analyticsCharts.650d99951cd9")}</option><option value="agendaItems">{message(locale, "screen.analyticsCharts.a24aa2ce489f")}</option><option value="decisions">{message(locale, "screen.analyticsCharts.dde48235221f")}</option></select></label>} meta={<AnalyticsMeta locale={locale} timeZone={timeZone} period={cyclePeriod(data, locale)} filter={`${data.cycle?.name ?? message(locale, "screen.analyticsCharts.390f54c5f235")} · ${message(locale, "screen.analyticsCharts.5bee57aa3bd8")}`} phase={phases} denominator={rows.length ? message(locale, "screen.analyticsCharts.0d4ee1b91104") : null} version={versions} updatedAt={data.updatedAt} permission="aggregate.read" />}>
    <div className="mt-5 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <div className="min-w-0" role="img" aria-label={`${message(locale, "screen.analyticsCharts.1f5f17073aa7")}: ${metricLabel}`}>
        {rows.length ? <ChartContainer config={sessionConfig(locale)} className="h-64 w-full min-w-0 aspect-auto" initialDimension={{ width: 280, height: 256 }}><LineChart accessibilityLayer data={chartData} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}><CartesianGrid vertical={false} /><XAxis dataKey="label" tickLine={false} axisLine={false} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} /><ChartTooltip content={<ChartTooltipContent />} />{metric !== "decisions" && <Line type="linear" dataKey="agendaItems" name={message(locale, "screen.analyticsCharts.a70d027e7b16")} stroke="var(--color-agendaItems)" strokeWidth={3} dot={{ r: 3 }} isAnimationActive={false} />}{metric !== "agendaItems" && <Line type="linear" dataKey="decisions" name={message(locale, "screen.analyticsCharts.dde48235221f")} stroke="var(--color-decisions)" strokeWidth={3} dot={{ r: 3 }} isAnimationActive={false} />}</LineChart></ChartContainer> : <p className="stage-disclaimer">{message(locale, "screen.analyticsCharts.9659335b1b6b")}</p>}
      </div>
      <div className="responsive-table min-w-0"><table><caption className="sr-only">{message(locale, "screen.analyticsCharts.783379bb54a6")}</caption><thead><tr><th>{message(locale, "screen.analyticsCharts.bba4234f0ca5")}</th><th>{message(locale, "screen.analyticsCharts.a24aa2ce489f")}</th><th>{message(locale, "screen.analyticsCharts.dde48235221f")}</th><th>{message(locale, "screen.analyticsCharts.e55050f49c52")}</th></tr></thead><tbody>{rows.length ? rows.map((row) => <tr key={row.sessionId}><td><strong>{row.sequence}</strong><small className="block text-slate-500">{sessionStatusLabel(locale, row.status)} · v{row.version}</small></td><td>{row.agendaItems}</td><td>{row.decisions}</td><td>{formatPercent(row.completionPercent, locale)}</td></tr>) : <EmptyChartRow locale={locale} columns={4} />}</tbody></table></div>
    </div>
  </AnalyticsShell>;
}

export function CandidateVoteAnalytics({ locale, timeZone, period, candidates, denominator, office, phase, roundVersion, publicationVersion, publishedAt }: {
  locale: Locale;
  timeZone: string;
  period: string;
  candidates: readonly { candidateId: string; label: string; votes: number }[];
  denominator: number;
  office: string;
  phase: string;
  roundVersion: number;
  publicationVersion: number;
  publishedAt: string;
}) {
  const titleId = useId();
  const chartData = candidates.map((candidate) => ({ ...candidate, value: candidate.votes }));
  const height = Math.max(240, candidates.length * 42);
  return <section className="mt-5 min-w-0 border-t border-slate-200 pt-5" aria-labelledby={titleId}><div className="card-heading"><div><p className="eyebrow">{message(locale, "screen.analyticsCharts.cc10787622de")}</p><h3 id={titleId} className="text-lg font-semibold">{message(locale, "screen.analyticsCharts.078bc6994922")}</h3><p>{message(locale, "screen.analyticsCharts.a79833ad999a")}</p></div></div><div className="mt-4 grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]"><div className="max-h-[32rem] min-w-0 overflow-y-auto" role="img" aria-label={message(locale, "screen.analyticsCharts.9d59e7814c50")}><ChartContainer config={candidateVoteConfig(locale)} className="w-full min-w-0 aspect-auto" style={{ height }} initialDimension={{ width: 280, height }}><BarChart accessibilityLayer data={chartData} layout="vertical" margin={{ top: 0, right: 14, bottom: 0, left: 4 }}><CartesianGrid horizontal={false} /><XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} /><YAxis type="category" dataKey="label" width={100} tickFormatter={(value) => compactAxisLabel(String(value))} tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><ChartTooltip content={<ChartTooltipContent />} /><Bar dataKey="value" name={message(locale, "screen.analyticsCharts.471d33c1eccc")} fill="var(--color-value)" radius={[0, 6, 6, 0]} isAnimationActive={false} /></BarChart></ChartContainer></div><div className="responsive-table min-w-0"><table><caption className="sr-only">{message(locale, "screen.analyticsCharts.2ce9694e114d")}</caption><thead><tr><th>{message(locale, "screen.analyticsCharts.f538cb19ab12")}</th><th>{message(locale, "screen.analyticsCharts.471d33c1eccc")}</th><th>{message(locale, "screen.analyticsCharts.68f9c136f1e3")}</th><th>{message(locale, "screen.analyticsCharts.5f3863488523")}</th></tr></thead><tbody>{candidates.length ? candidates.map((candidate) => <tr key={candidate.candidateId}><td>{candidate.label}</td><td>{candidate.votes}</td><td>{denominator || message(locale, "screen.analyticsCharts.14a82ef6df2a")}</td><td>{formatPercent(analyticsPercent(candidate.votes, denominator), locale)}</td></tr>) : <EmptyChartRow locale={locale} columns={4} />}</tbody></table></div></div><AnalyticsMeta locale={locale} timeZone={timeZone} period={period} filter={office} phase={phaseLabel(locale, phase)} denominator={denominator || null} version={`${message(locale, "screen.analyticsCharts.c4ce86ba5470")} v${roundVersion} · ${message(locale, "screen.analyticsCharts.ff0d8a3e8f45")} v${publicationVersion}`} updatedAt={publishedAt} permission="aggregate.read" /></section>;
}
