import { Line, LineChart, Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { Card, EmptyState, StatTile } from "../components/ui";
import { useMitigations, useDefenseThreshold } from "../lib/defenseEngineApi";
import { useThreatsStats, useThreatsTimeline, useThreatsTypes } from "../lib/queries";

/**
 * Sandbox vs. global comparison (Stage G). Deliberately shows only metrics
 * the backends actually expose: `defense-engine`'s `/mitigations` gives a
 * confidence/threshold timeline and an action count, `threat-intel`'s
 * `/api/threats/{timeline,types,stats}` gives real ingestion volume. There
 * is no precision/recall/false-positive-rate computation anywhere in
 * either backend (no ground-truth labels exist to compute them from), so
 * none are shown or estimated here -- adding that would be inventing a
 * number the platform doesn't measure, which the project's no-fabrication
 * rule (PROJECT_EXECUTION_PLAN.md Safety Requirement 5) forbids.
 */
export function Analytics() {
  const { data: actions, isLoading: actionsLoading, isError: actionsError } = useMitigations(200);
  const { data: threshold, isError: thresholdError } = useDefenseThreshold();
  const { data: stats, isError: statsError } = useThreatsStats();
  const { data: timeline, isLoading: timelineLoading, isError: timelineError } = useThreatsTimeline("hour", 48);
  const { data: types, isLoading: typesLoading, isError: typesError } = useThreatsTypes();

  const mitigationChartData = (actions ?? []).map((action) => ({
    time: new Date(action.ts * 1000).toLocaleTimeString(),
    confidence: Number((action.confidence * 100).toFixed(1)),
    threshold: Number(action.new_threshold.toFixed(1)),
  }));

  const timelineChartData = (timeline ?? []).map((bucket) => ({
    time: new Date(bucket.bucket).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" }),
    count: bucket.count,
  }));

  const typesChartData = (types ?? []).slice(0, 8).map((t) => ({ type: t.threat_type, count: t.count }));

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Sandbox Lab -- defense engine</h2>
        {actionsError && thresholdError ? (
          <EmptyState
            title="Defense engine unreachable"
            hint="defense-engine:9300 did not respond. Bring up the sandbox stack to see mitigation metrics."
          />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <StatTile
                label="Mitigation actions logged"
                value={actionsError ? "--" : (actions?.length ?? (actionsLoading ? "..." : 0))}
              />
              <StatTile
                label="Current rate-limit threshold"
                value={thresholdError ? "--" : `${threshold?.threshold_rps.toFixed(1) ?? "?"} req/s`}
              />
              <StatTile
                label="Current classifier confidence"
                value={thresholdError ? "--" : `${Math.round((threshold?.confidence ?? 0) * 100)}%`}
              />
            </div>

            <Card className="mt-4">
              <h3 className="mb-2 text-xs font-medium text-slate-300">
                Classifier confidence &amp; rate-limit threshold over recent mitigation actions
              </h3>
              {actionsLoading && <p className="text-xs text-slate-500">Loading...</p>}
              {!actionsLoading && mitigationChartData.length === 0 && (
                <EmptyState
                  title="No mitigation actions yet"
                  hint="Run an attack scenario against the sandbox to generate real mitigation events."
                />
              )}
              {mitigationChartData.length > 0 && (
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={mitigationChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                      <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <Tooltip contentStyle={{ background: "#161c2c", border: "1px solid #ffffff1a", fontSize: 12 }} />
                      <Line type="monotone" dataKey="confidence" name="Confidence %" stroke="#38bdf8" dot={false} />
                      <Line type="monotone" dataKey="threshold" name="Threshold req/s" stroke="#facc15" dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
          </>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Global Threat Intelligence -- ingestion volume</h2>
        {statsError ? (
          <EmptyState title="threat-intel unreachable" hint="Could not load aggregate statistics." />
        ) : (
          <div className="grid grid-cols-1 gap-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <StatTile label="Total IOCs" value={stats?.total_iocs ?? 0} />
              <StatTile label="Total CVEs" value={stats?.total_cves ?? 0} />
              <StatTile label="Distinct countries" value={stats?.distinct_countries ?? 0} />
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <h3 className="mb-2 text-xs font-medium text-slate-300">IOCs ingested per hour (last 48h)</h3>
              {timelineLoading && <p className="text-xs text-slate-500">Loading...</p>}
              {!timelineLoading && timelineChartData.length === 0 && (
                <EmptyState title="No ingestion activity yet" />
              )}
              {timelineError && <EmptyState title="Timeline unavailable" />}
              {timelineChartData.length > 0 && (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={timelineChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                      <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <Tooltip contentStyle={{ background: "#161c2c", border: "1px solid #ffffff1a", fontSize: 12 }} />
                      <Bar dataKey="count" name="IOCs ingested" fill="#38bdf8" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>

            <Card>
              <h3 className="mb-2 text-xs font-medium text-slate-300">Top threat types (all-time)</h3>
              {typesLoading && <p className="text-xs text-slate-500">Loading...</p>}
              {!typesLoading && typesChartData.length === 0 && <EmptyState title="No threat type data yet" />}
              {typesError && <EmptyState title="Threat type data unavailable" />}
              {typesChartData.length > 0 && (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={typesChartData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" />
                      <XAxis type="number" tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <YAxis dataKey="type" type="category" width={90} tick={{ fontSize: 10, fill: "#94a3b8" }} />
                      <Tooltip contentStyle={{ background: "#161c2c", border: "1px solid #ffffff1a", fontSize: 12 }} />
                      <Bar dataKey="count" name="Count" fill="#c084fc" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
            </div>
          </div>
        )}
      </section>

      <p className="text-[11px] text-slate-500">
        Precision, recall, and false-positive-rate are not shown -- neither backend computes them (no ground-truth
        attack/legitimate labels are tracked at runtime), so they are omitted rather than estimated.
      </p>
    </div>
  );
}
