import { useMemo } from "react";
import { Link } from "react-router-dom";
import { Bar, CartesianGrid, ComposedChart, Legend, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, EmptyState } from "../components/ui";
import { SEVERITY_LABEL, SEVERITY_TONE } from "../components/feed/labels";
import { useIncidents, useMitigations, useSuricataAlerts, useSuricataSummary } from "../lib/defenseEngineApi";
import { useSandboxAttacksStatus } from "../lib/sandboxStatus";

const ALERT_BUCKET_S = 300;
const RECENT_INCIDENTS = 6;

const fmtTime = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

interface MetricProps {
  label: string;
  value: string;
  unit?: string;
  hint: string;
  to?: string;
  linkLabel?: string;
}

/**
 * One headline figure: a large light-weight number, its title and a short
 * explanation, with an optional link to where the detail lives. Columns are
 * separated by a hairline rule rather than boxed.
 */
function Metric({ label, value, unit, hint, to, linkLabel }: MetricProps) {
  return (
    <div className="flex min-h-[210px] flex-col border-t border-line px-0 py-6 first:border-t-0 sm:px-6 sm:first:pl-0 lg:min-h-[230px] lg:border-l lg:border-t-0 lg:first:border-l-0">
      <p className="text-4xl font-extralight leading-none tracking-tight text-ink md:text-5xl">
        {value}
        {unit && <span className="ml-1.5 text-base font-light text-ink-muted">{unit}</span>}
      </p>
      <h3 className="mt-8 text-base font-medium text-ink">{label}</h3>
      <p className="mb-5 mt-2 text-sm leading-relaxed text-ink-soft">{hint}</p>
      {to && linkLabel ? (
        <Link
          to={to}
          className="mt-auto inline-flex w-fit items-center gap-2 border-b border-accent pb-0.5 text-sm font-medium text-accent hover:text-ink"
        >
          {linkLabel} <span aria-hidden>&rarr;</span>
        </Link>
      ) : (
        <span className="mt-auto block h-[22px]" aria-hidden />
      )}
    </div>
  );
}

/**
 * Operational overview. Every figure comes from defense-engine's own
 * endpoints (incidents, Suricata summary/alerts, the mitigation log); a
 * metric the backend does not expose is labelled as such rather than
 * estimated. Threat-indicator / CVE totals live on Global Threat
 * Intelligence, service health and providers in Settings.
 */
export function Overview() {
  const { data: incidentData, isLoading: incidentsLoading, isError: incidentsError } = useIncidents(50);
  const { data: suricata, isError: suricataError } = useSuricataSummary();
  const { data: alerts } = useSuricataAlerts(200);
  const { data: actions, isLoading: actionsLoading, isError: actionsError } = useMitigations(200);
  const { data: sandbox, isLoading: sandboxLoading, isError: sandboxError } = useSandboxAttacksStatus();

  const incidents = useMemo(() => incidentData?.incidents ?? [], [incidentData]);
  const active = incidents.filter((i) => i.status === "active").length;
  const mlOnly = incidents.filter((i) => i.assessment === "ml_only" || i.assessment === "ml_only_suricata_unavailable").length;

  const latestSample = actions && actions.length > 0 ? actions[actions.length - 1] : null;
  const latestRate = latestSample?.features.request_rate;
  const latestAge = latestSample ? Math.max(0, Math.round(Date.now() / 1000 - latestSample.ts)) : null;

  const peakBlocked = useMemo(() => {
    const values = incidents.map((i) => i.mitigation.blocked_rps_peak).filter((v): v is number => v != null);
    return values.length > 0 ? Math.max(...values) : null;
  }, [incidents]);

  const trend = useMemo(() => {
    const samples = (actions ?? []).filter((a) => a.features.request_rate != null);
    if (samples.length === 0) return [];
    const start = Math.floor(samples[0].ts / ALERT_BUCKET_S) * ALERT_BUCKET_S;
    const counts = new Map<number, number>();
    for (const a of alerts ?? []) {
      if (a.ts < start) continue;
      const bucket = Math.floor(a.ts / ALERT_BUCKET_S) * ALERT_BUCKET_S;
      counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
    }
    const rows = samples.map((a) => ({
      ts: a.ts,
      time: fmtTime(a.ts),
      rate: Number(a.features.request_rate.toFixed(2)),
      limit: Number(a.new_threshold.toFixed(1)),
      alerts: undefined as number | undefined,
    }));
    // Alert counts are drawn at their own 5-minute bucket, not per sample.
    for (const [bucket, count] of counts) {
      rows.push({ ts: bucket + ALERT_BUCKET_S / 2, time: fmtTime(bucket + ALERT_BUCKET_S / 2), rate: NaN, limit: NaN, alerts: count });
    }
    return rows.sort((a, b) => a.ts - b.ts).map((r) => ({ ...r, rate: Number.isNaN(r.rate) ? undefined : r.rate, limit: Number.isNaN(r.limit) ? undefined : r.limit }));
  }, [actions, alerts]);

  const running = Object.entries(sandbox?.running ?? {});
  const dash = "--";

  return (
    <div className="flex flex-col gap-8">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <Metric
          label="Active incidents"
          value={incidentsError ? dash : incidentsLoading ? "..." : String(active)}
          hint={incidentsError ? "defense-engine unreachable" : `${incidents.length} recorded in total, ${mlOnly} flagged by ML only`}
          to="/alerts?tab=incidents"
          linkLabel="View incidents"
        />
        <Metric
          label="Monitored traffic"
          value={latestRate != null ? latestRate.toFixed(1) : actionsError ? dash : actionsLoading ? "..." : dash}
          unit={latestRate != null ? "req/s" : undefined}
          to="/sandbox"
          linkLabel="View live metrics"
          hint={
            latestRate != null && latestAge != null
              ? `Latest detector sample, ${latestAge < 90 ? `${latestAge} s` : `${Math.round(latestAge / 60)} min`} ago. HTTP traffic through the rate limiter only.`
              : "No detector sample available"
          }
        />
        <Metric
          label="Detection events"
          value={suricataError ? dash : String(suricata?.total_ingested ?? "...")}
          hint={
            suricata
              ? `Suricata alerts ingested; ${suricata.recent_alerts} in the last ${Math.round(suricata.window_seconds / 60)} min`
              : "Suricata summary unavailable"
          }
          to="/alerts?tab=suricata"
          linkLabel="View alerts"
        />
        <Metric
          label="Peak blocked rate"
          value={peakBlocked != null ? peakBlocked.toFixed(1) : dash}
          unit={peakBlocked != null ? "req/s" : undefined}
          to="/analytics?tab=mitigation"
          linkLabel="View mitigation"
          hint={
            peakBlocked != null
              ? "Highest blocked rate across recorded incidents. A total mitigated-request count is not exposed by the backend."
              : "No blocked traffic recorded. A total mitigated-request count is not exposed by the backend."
          }
        />
      </div>

      <section>
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-base font-semibold uppercase tracking-[0.1em] text-ink">Traffic and detections</h2>
          <span className="text-sm text-ink-muted">Logged detector samples and Suricata alerts per 5 min</span>
        </div>
        <div className="border border-line bg-white p-4">
          {trend.length === 0 ? (
            <EmptyState title="No detector samples yet" hint="The trend appears once defense-engine has recorded traffic samples." />
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                  <CartesianGrid stroke="#e8eaec" vertical={false} />
                  <XAxis dataKey="ts" type="number" scale="time" domain={["dataMin", "dataMax"]} tickFormatter={fmtTime} tick={{ fontSize: 13, fill: "#5f6770" }} minTickGap={40} />
                  <YAxis yAxisId="rate" tick={{ fontSize: 13, fill: "#5f6770" }} />
                  <YAxis yAxisId="alerts" orientation="right" allowDecimals={false} tick={{ fontSize: 13, fill: "#5f6770" }} />
                  <Tooltip labelFormatter={(v) => new Date(Number(v) * 1000).toLocaleString()} contentStyle={{ border: "1px solid #dcdfe2", borderRadius: 0, fontSize: 14 }} />
                  <Legend wrapperStyle={{ fontSize: 14 }} />
                  <Bar yAxisId="alerts" dataKey="alerts" name="Suricata alerts" fill="#16191c" barSize={10} />
                  <Line yAxisId="rate" type="monotone" dataKey="rate" name="Request rate (req/s)" stroke="#2f7f7a" strokeWidth={2} dot={false} connectNulls />
                  <Line yAxisId="rate" type="stepAfter" dataKey="limit" name="Rate limit (req/s)" stroke="#8a949b" strokeDasharray="4 3" dot={false} connectNulls />
                </ComposedChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
        <p className="mt-2 text-sm text-ink-muted">
          Request-rate points are recorded by the detector when it adjusts the rate limit, so gaps mean no adjustment, not zero
          traffic. The backend does not expose a continuous traffic series.
        </p>
      </section>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
        <section className="lg:col-span-2">
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-base font-semibold uppercase tracking-[0.1em] text-ink">Recent incidents</h2>
            <Link to="/alerts" className="text-sm font-medium text-accent hover:underline">
              All alerts &rarr;
            </Link>
          </div>
          <div className="border border-line bg-white">
            {incidentsError && <p className="p-4 text-sm text-ink-muted">Incident data is unavailable right now.</p>}
            {incidentsLoading && <p className="p-4 text-sm text-ink-muted">Loading...</p>}
            {!incidentsLoading && !incidentsError && incidents.length === 0 && (
              <p className="p-4 text-sm text-ink-muted">No incidents recorded. They appear when Suricata or the ML detector flag traffic.</p>
            )}
            <ul className="divide-y divide-line">
              {incidents.slice(0, RECENT_INCIDENTS).map((incident) => (
                <li key={incident.id} className="flex items-start justify-between gap-4 px-4 py-3">
                  <div className="min-w-0">
                    <Link
                      to={`/alerts/${encodeURIComponent(`incident-${incident.id}`)}`}
                      className="text-base font-medium text-ink hover:text-accent hover:underline"
                    >
                      {incident.title}
                    </Link>
                    <p className="mt-0.5 text-sm text-ink-muted">
                      {new Date(incident.start * 1000).toLocaleString()} · {incident.duration_s.toFixed(0)} s · {incident.status}
                    </p>
                  </div>
                  <Badge tone={SEVERITY_TONE[incident.severity]} className="shrink-0">
                    {SEVERITY_LABEL[incident.severity]}
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section>
          <div className="mb-3 flex items-baseline justify-between">
            <h2 className="text-base font-semibold uppercase tracking-[0.1em] text-ink">Sandbox</h2>
            <Link to="/sandbox" className="text-sm font-medium text-accent hover:underline">
              Open lab &rarr;
            </Link>
          </div>
          <Card className="p-0 md:p-0">
            {sandboxError && <p className="p-4 text-sm text-ink-muted">Sandbox control API is unreachable.</p>}
            {sandboxLoading && !sandboxError && <p className="p-4 text-sm text-ink-muted">Checking...</p>}
            {!sandboxLoading && !sandboxError && running.length === 0 && (
              <p className="p-4 text-sm text-ink-muted">No attack profiles reported.</p>
            )}
            <ul className="divide-y divide-line">
              {running.map(([attackType, isRunning]) => (
                <li key={attackType} className="flex items-center justify-between px-4 py-3 text-sm">
                  <span className="text-ink-soft">{attackType}</span>
                  <Badge tone={isRunning ? "ok" : "neutral"}>{isRunning ? "Running" : "Stopped"}</Badge>
                </li>
              ))}
            </ul>
          </Card>
        </section>
      </div>
    </div>
  );
}
