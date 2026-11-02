import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useDefenseThreshold, useMitigations } from "../../lib/defenseEngineApi";
import { useSandboxFeed } from "../../lib/sandboxApi";

const BUCKET_S = 5;
const FEED_WINDOW_S = 120;
const AXIS = { fontSize: 13, fill: "#5f6770" };
const TOOLTIP = { border: "1px solid #dcdfe2", borderRadius: 0, fontSize: 14 };
const fmtTime = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

function ChartCard({ title, note, empty, children }: { title: string; note: string; empty: boolean; children: React.ReactNode }) {
  return (
    <div className="border border-line bg-white p-4">
      <h3 className="text-[13px] font-semibold uppercase tracking-[0.12em] text-ink">{title}</h3>
      <p className="mb-2 text-sm text-ink-muted">{note}</p>
      <div className="h-44">
        {empty ? (
          <div className="flex h-full items-center justify-center text-sm text-ink-muted">No data in the current window</div>
        ) : (
          children
        )}
      </div>
    </div>
  );
}

/**
 * Three small live charts drawn from the same endpoints the rest of the page
 * uses (sandbox feed, mitigation log), in the dashboard's own theme. The
 * embedded Grafana dashboard remains available below.
 */
export function SandboxCharts() {
  const { data: feed } = useSandboxFeed(FEED_WINDOW_S, 500);
  const { data: actions } = useMitigations(60);
  const { data: threshold } = useDefenseThreshold();

  const traffic = useMemo(() => {
    const events = feed?.events ?? [];
    if (events.length === 0) return { counts: [], latency: [] };
    const last = Math.max(...events.map((e) => e.ts));
    const first = Math.floor((last - FEED_WINDOW_S) / BUCKET_S) * BUCKET_S;
    const buckets = new Map<number, { n: number; lat: number; latN: number }>();
    for (let t = first; t <= last; t += BUCKET_S) buckets.set(t, { n: 0, lat: 0, latN: 0 });
    for (const e of events) {
      const b = buckets.get(Math.floor(e.ts / BUCKET_S) * BUCKET_S);
      if (!b) continue;
      b.n += 1;
      if (e.latency_ms != null) {
        b.lat += e.latency_ms;
        b.latN += 1;
      }
    }
    const rows = [...buckets.entries()].sort((a, b) => a[0] - b[0]);
    return {
      counts: rows.map(([ts, b]) => ({ ts, events: b.n })),
      latency: rows.filter(([, b]) => b.latN > 0).map(([ts, b]) => ({ ts, ms: Math.round(b.lat / b.latN) })),
    };
  }, [feed]);

  const detector = useMemo(
    () => (actions ?? []).map((a) => ({ ts: a.ts, confidence: Number((a.confidence * 100).toFixed(1)), limit: Number(a.new_threshold.toFixed(1)) })),
    [actions],
  );

  const xAxis = <XAxis dataKey="ts" type="number" scale="time" domain={["dataMin", "dataMax"]} tickFormatter={fmtTime} tick={AXIS} minTickGap={50} />;
  const tip = <Tooltip labelFormatter={(v) => fmtTime(Number(v))} contentStyle={TOOLTIP} />;

  return (
    <section>
      <div className="mb-3 flex items-baseline justify-between">
        <h2 className="text-base font-semibold uppercase tracking-[0.12em] text-ink">Live metrics</h2>
        {threshold && (
          <span className="text-sm text-ink-muted">
            Rate limit {threshold.threshold_rps.toFixed(0)} req/s · confidence {Math.round(threshold.confidence * 100)}%
          </span>
        )}
      </div>
      <div className="grid grid-cols-1 gap-px border border-line bg-line lg:grid-cols-3">
        <ChartCard title="Attack events" note={`Recorded events per ${BUCKET_S} s`} empty={traffic.counts.length === 0}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={traffic.counts} margin={{ left: -18, right: 6, top: 4 }}>
              <CartesianGrid stroke="#e8eaec" vertical={false} />
              {xAxis}
              <YAxis tick={AXIS} allowDecimals={false} />
              {tip}
              <Area type="monotone" dataKey="events" name="Events" stroke="#2f7f7a" fill="#2f7f7a" fillOpacity={0.15} strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Response latency" note="Mean latency of recorded requests (ms)" empty={traffic.latency.length === 0}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={traffic.latency} margin={{ left: -18, right: 6, top: 4 }}>
              <CartesianGrid stroke="#e8eaec" vertical={false} />
              {xAxis}
              <YAxis tick={AXIS} />
              {tip}
              <Line type="monotone" dataKey="ms" name="Latency (ms)" stroke="#16191c" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
        <ChartCard title="Detector and rate limit" note="Classifier confidence (%) and limit (req/s) at each logged action" empty={detector.length === 0}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={detector} margin={{ left: -18, right: 6, top: 4 }}>
              <CartesianGrid stroke="#e8eaec" vertical={false} />
              {xAxis}
              <YAxis tick={AXIS} />
              {tip}
              <Line type="monotone" dataKey="confidence" name="Confidence %" stroke="#2f7f7a" strokeWidth={2} dot={false} />
              <Line type="stepAfter" dataKey="limit" name="Limit req/s" stroke="#8a949b" strokeDasharray="4 3" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </section>
  );
}
