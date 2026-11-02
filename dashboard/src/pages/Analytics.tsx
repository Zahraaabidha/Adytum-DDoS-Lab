import { Line, LineChart, Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { Badge, Card, EmptyState, StatTile } from "../components/ui";
import type { DetectionNormal, DetectionTypeResult } from "../types/threat";
import {
  useMitigations,
  useDefenseThreshold,
  useDetectionEvaluation,
  useMitigationReport,
  useDefenseEngineHealth,
} from "../lib/defenseEngineApi";
import { useThreatsStats, useThreatsTimeline, useThreatsTypes } from "../lib/queries";

/**
 * Sandbox vs. global comparison (Stage G). Deliberately shows only metrics
 * the backends actually expose: `defense-engine`'s `/mitigations` gives a
 * confidence/threshold timeline and an action count, `threat-intel`'s
 * `/api/threats/{timeline,types,stats}` gives real ingestion volume.
 * Precision/recall/FPR are shown only when `defense-engine`'s `/evaluation`
 * serves a report produced by `classifier/evaluate.py` from labeled
 * recordings; with no report the section shows an empty state rather than
 * an estimate (the project's no-fabrication rule).
 */
const percent = (value: number) => `${(value * 100).toFixed(1)}%`;

/** Per-traffic-type detection results. */
function ResultTable({
  rows,
  normal,
  idle,
}: {
  rows: DetectionTypeResult[];
  normal: DetectionNormal;
  idle: DetectionNormal;
}) {
  const falseRate = (row: DetectionNormal) => percent(row.false_positives / Math.max(row.samples, 1));
  return (
    <table className="mb-4 w-full text-left text-xs text-ink-soft">
      <thead className="text-ink-muted">
        <tr>
          <th className="py-1 font-medium">Traffic type</th>
          <th className="py-1 font-medium">Samples</th>
          <th className="py-1 font-medium">Flagged</th>
          <th className="py-1 font-medium">Precision</th>
          <th className="py-1 font-medium">Recall</th>
          <th className="py-1 font-medium">F1</th>
        </tr>
      </thead>
      <tbody>
        {[
          { label: "legitimate", row: normal },
          { label: "idle (no traffic)", row: idle },
        ].map(({ label, row }) => (
          <tr key={label} className="border-t border-line">
            <td className="py-1">{label}</td>
            <td className="py-1">{row.samples}</td>
            <td className="py-1">{row.false_positives} false</td>
            <td className="py-1" colSpan={3}>
              false-positive rate {falseRate(row)}
            </td>
          </tr>
        ))}
        {rows.map((row) => (
          <tr key={row.attack_type} className="border-t border-line">
            <td className="py-1">
              {row.attack_type}
              {row.low_sample && <span className="ml-2 text-amber-600">low sample</span>}
            </td>
            <td className="py-1">{row.samples}</td>
            <td className="py-1">{row.flagged}</td>
            <td className="py-1">{percent(row.metrics.precision)}</td>
            <td className="py-1">{percent(row.metrics.recall)}</td>
            <td className="py-1">{row.metrics.f1.toFixed(3)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const SCENARIO_LABEL: Record<string, string> = {
  legit: "Legitimate alone",
  flood: "Flood alone",
  dist: "Distributed flood alone",
  floodL: "Flood + legitimate",
  distL: "Distributed flood + legitimate",
  slowL: "Slowloris + legitimate (not HTTP-blockable)",
};

export function Analytics() {
  const { data: actions, isLoading: actionsLoading, isError: actionsError } = useMitigations(200);
  const { data: threshold, isError: thresholdError } = useDefenseThreshold();
  const { data: evaluation, isLoading: evaluationLoading, isError: evaluationError } = useDetectionEvaluation();
  const { data: mitigation, isLoading: mitigationLoading } = useMitigationReport();
  const { data: engineHealth } = useDefenseEngineHealth();
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
        <h2 className="mb-3 text-sm font-semibold text-ink">Sandbox Lab -- defense engine</h2>
        {actionsError && thresholdError ? (
          <EmptyState
            title="Defense engine unreachable"
            hint="defense-engine:9300 did not respond. Bring up the sandbox stack to see mitigation metrics."
          />
        ) : (
          <>
            <Card className="mb-4">
              <p className="mb-2 text-xs font-medium text-ink-soft">Active model and mitigation policy (selected default)</p>
              {engineHealth && !engineHealth.model_loaded ? (
                <p className="text-xs text-red-600">
                  NO MODEL LOADED: detection is in pass-through mode (confidence 0) and nothing will be mitigated. Check
                  MODEL_PATH / SENTINEL_MODEL_PATH and the engine log.
                </p>
              ) : engineHealth?.model ? (
                <p className="text-xs text-ink-soft">
                  Model <span className="font-mono">{engineHealth.model.file}</span>, trained{" "}
                  {engineHealth.model.trained_at ? new Date(engineHealth.model.trained_at).toLocaleDateString() : "?"} on{" "}
                  {engineHealth.model.samples} live samples from {engineHealth.model.legit_runs.length} legitimate runs
                  {engineHealth.model.idle_windows > 0 && ` plus ${engineHealth.model.idle_windows} idle window`}; boundary
                  contamination {engineHealth.model.contamination}. Mitigation policy: {engineHealth.policy}.
                </p>
              ) : (
                <p className="text-xs text-ink-muted">Loading...</p>
              )}
              <p className="mt-2 text-[11px] text-ink-muted">
                The candidate model is the selected default; the original model.joblib is kept for rollback (set
                SENTINEL_MODEL_PATH=/app/classifier/model.joblib). Limitations: the rate limiter protects HTTP traffic only
                (UDP, TCP and Slowloris are detected, not mitigated); concurrent legitimate requests are still partly
                blocked during floods and mitigation starts only after a delay (measured in the lab comparison below);
                training used synthetic lab traffic at one load level. See the README, &quot;Model selection&quot;.
              </p>
            </Card>
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
              <h3 className="mb-2 text-xs font-medium text-ink-soft">
                Classifier confidence &amp; rate-limit threshold over recent mitigation actions
              </h3>
              {actionsLoading && <p className="text-xs text-ink-muted">Loading...</p>}
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
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#64748b" }} />
                      <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
                      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }} />
                      <Line type="monotone" dataKey="confidence" name="Confidence %" stroke="#2f7f7a" dot={false} />
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
        <h2 className="mb-1 text-sm font-semibold text-ink">
          <Badge tone="neutral">OFFLINE</Badge> Classifier evaluation on held-out runs
        </h2>
        <p className="mb-3 text-[11px] text-ink-muted">
          Live feature samples logged by the engine during labeled test runs the model was not trained on, re-scored
          with the trained model while mitigation was inert. Measures detection only; no rate limiting involved.
        </p>
        {evaluationError || !evaluation || !evaluation.available ? (
          <EmptyState
            title={evaluationLoading ? "Loading..." : "No evaluation report yet"}
            hint="Run defense/classifier/evaluate.py with --output on labeled recordings (see README) to populate this."
          />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatTile label="Precision" value={percent(evaluation.metrics.precision)} />
              <StatTile label="Recall" value={percent(evaluation.metrics.recall)} />
              <StatTile label="False-positive rate" value={percent(evaluation.metrics.false_positive_rate)} />
              <StatTile label="F1" value={evaluation.metrics.f1.toFixed(3)} />
            </div>
            <Card className="mt-4">
              <p className="mb-2 text-xs text-ink-soft">
                {evaluation.samples.normal} legitimate and {evaluation.samples.attack} attack samples, threshold{" "}
                {evaluation.metrics.threshold}. Confusion: TP {evaluation.metrics.true_positives}, FP{" "}
                {evaluation.metrics.false_positives}, TN {evaluation.metrics.true_negatives}, FN{" "}
                {evaluation.metrics.false_negatives}.
              </p>
              <ResultTable rows={evaluation.by_type} normal={evaluation.normal} idle={evaluation.idle} />
              <table className="w-full text-left text-xs text-ink-soft">
                <thead className="text-ink-muted">
                  <tr>
                    <th className="py-1 font-medium">Run</th>
                    <th className="py-1 font-medium">Traffic</th>
                    <th className="py-1 font-medium">Samples flagged</th>
                  </tr>
                </thead>
                <tbody>
                  {evaluation.runs.map((row) => (
                    <tr key={row.run} className="border-t border-line">
                      <td className="py-1">{row.run}</td>
                      <td className="py-1">{row.attack_type ?? row.label}</td>
                      <td className="py-1">
                        {row.flagged} / {row.samples}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {evaluation.excluded.length > 0 && (
                <div className="mt-3 text-xs text-ink-soft">
                  <p className="mb-1 text-ink-muted">Recordings not scored</p>
                  <ul className="list-disc pl-5">
                    {evaluation.excluded.map((row) => (
                      <li key={row.run}>
                        {row.run} ({row.events} events): {row.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p className="mt-2 text-[11px] text-ink-muted">
                Evaluated {new Date(evaluation.generated_at).toLocaleString()}. Model trained on:{" "}
                {evaluation.trained_on.join(", ") || "unknown"}; none of those runs are scored. Sample unit:{" "}
                {evaluation.sample_unit}.
              </p>
            </Card>
          </>
        )}
      </section>

      <section>
        <h2 className="mb-1 text-sm font-semibold text-ink">
          <Badge tone="neutral">NOTE</Badge> End-to-end mitigation results
        </h2>
        <p className="text-[11px] text-ink-muted">
          End-to-end mitigation results (rate limit reached, requests blocked, legitimate traffic blocked during an
          attack) are shown only in the LAB RUNS comparison below, which includes the final default (candidate model,
          guarded policy, headroom 6, fair limiter). The offline report served here was generated before that
          configuration was final, so its older &quot;live&quot; and &quot;collateral&quot; figures are deliberately not displayed.
        </p>
      </section>

      <section>
        <h2 className="mb-1 text-sm font-semibold text-ink">
          <Badge tone="warn">LAB RUNS</Badge> Rate-limit policy comparison
        </h2>
        <p className="mb-3 text-[11px] text-ink-muted">
          The same controlled scenarios replayed against each limiter and mitigation-policy configuration with the same
          model: legitimate traffic alone, single-source and six-source floods, and legitimate traffic running at the
          same time. All figures are measured from the recordings and the engine&apos;s own log.
        </p>
        {!mitigation || !mitigation.available ? (
          <EmptyState
            title={mitigationLoading ? "Loading..." : "No mitigation comparison yet"}
            hint="Run the m_<config>_<scenario> lab scenarios and classifier/mitigation_report.py --output (see README)."
          />
        ) : (
          <Card>
            <table className="w-full text-left text-xs text-ink-soft">
              <thead className="text-ink-muted">
                <tr>
                  <th className="py-1 font-medium">Scenario</th>
                  <th className="py-1 font-medium">Configuration</th>
                  <th className="py-1 font-medium">Attack blocked</th>
                  <th className="py-1 font-medium">Attack req/s (offered → admitted, steady)</th>
                  <th className="py-1 font-medium">Legitimate blocked</th>
                  <th className="py-1 font-medium">Cap (min / typical; below ½ baseline after)</th>
                  <th className="py-1 font-medium">Flagged polls</th>
                  <th className="py-1 font-medium">Recovery</th>
                </tr>
              </thead>
              <tbody>
                {mitigation.rows.map((row) => (
                  <tr key={`${row.scenario}-${row.config}`} className="border-t border-line">
                    <td className="py-1">
                      {SCENARIO_LABEL[row.scenario]}
                      {row.attack_sources > 1 && ` (${row.attack_sources} sources)`}
                      {row.start?.clean === false && (
                        <span className="ml-2 text-amber-600">unclean start (cap {row.start.cap_rps?.toFixed(0)})</span>
                      )}
                    </td>
                    <td className="py-1">{mitigation.configs[row.config]?.label ?? row.config}</td>
                    <td className="py-1">
                      {!row.attack
                        ? "--"
                        : row.attack.http && row.attack.blocked_fraction !== undefined
                          ? `${percent(row.attack.blocked_fraction)} (${row.attack.blocked}/${row.attack.requests})`
                          : "not HTTP: detected only, not blocked"}
                    </td>
                    <td className="py-1">
                      {!row.attack
                        ? "--"
                        : row.attack.http
                          ? `${row.attack.offered_rps.toFixed(0)} → ${row.attack.admitted_rps?.toFixed(0)}, ${row.attack.steady_admitted_rps?.toFixed(0)}`
                          : `${row.attack.offered_rps.toFixed(0)} events/s`}
                    </td>
                    <td className="py-1">
                      {row.legit ? `${percent(row.legit.blocked_fraction)} (${row.legit.blocked}/${row.legit.requests})` : "--"}
                    </td>
                    <td className="py-1">
                      {row.limit.min_rps == null
                        ? "--"
                        : `${row.limit.min_rps.toFixed(0)} / ${row.limit.typical_rps?.toFixed(0)}${row.limit.below_half_baseline_s == null ? "" : `; ${row.limit.below_half_baseline_s}s`}`}
                    </td>
                    <td className="py-1">
                      {row.flagged_polls} / {row.polls}
                    </td>
                    <td className="py-1">
                      {row.recovery
                        ? row.recovery.recovered
                          ? `${row.recovery.seconds}s`
                          : `not within ${row.recovery.observed_seconds}s`
                        : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-[11px] text-ink-muted">
              Generated {new Date(mitigation.generated_at).toLocaleString()}. Baseline cap {mitigation.baseline_limit_rps}{" "}
              req/s. &quot;Flagged polls&quot; are engine polls with confidence of at least 0.5; for the legitimate-only
              scenario they are false positives. Recovery is the time after an attack stopped until the cap was back
              above 90% of the baseline.
            </p>
            {mitigation.excluded_runs && mitigation.excluded_runs.length > 0 && (
              <div className="mt-2 text-[11px] text-ink-muted">
                <p>Recordings kept on disk but not counted:</p>
                <ul className="list-disc pl-5">
                  {mitigation.excluded_runs.map((row) => (
                    <li key={row.run}>
                      {row.run}: {row.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </Card>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Global Threat Intelligence -- ingestion volume</h2>
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
              <h3 className="mb-2 text-xs font-medium text-ink-soft">IOCs ingested per hour (last 48h)</h3>
              {timelineLoading && <p className="text-xs text-ink-muted">Loading...</p>}
              {!timelineLoading && timelineChartData.length === 0 && (
                <EmptyState title="No ingestion activity yet" />
              )}
              {timelineError && <EmptyState title="Timeline unavailable" />}
              {timelineChartData.length > 0 && (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={timelineChartData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#64748b" }} />
                      <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
                      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }} />
                      <Bar dataKey="count" name="IOCs ingested" fill="#2b2f33" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>

            <Card>
              <h3 className="mb-2 text-xs font-medium text-ink-soft">Top threat types (all-time)</h3>
              {typesLoading && <p className="text-xs text-ink-muted">Loading...</p>}
              {!typesLoading && typesChartData.length === 0 && <EmptyState title="No threat type data yet" />}
              {typesError && <EmptyState title="Threat type data unavailable" />}
              {typesChartData.length > 0 && (
                <div className="h-56 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={typesChartData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                      <XAxis type="number" tick={{ fontSize: 10, fill: "#64748b" }} />
                      <YAxis dataKey="type" type="category" width={90} tick={{ fontSize: 10, fill: "#64748b" }} />
                      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: 8, fontSize: 12 }} />
                      <Bar dataKey="count" name="Count" fill="#2f7f7a" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>
            </div>
          </div>
        )}
      </section>

      <p className="text-[11px] text-ink-muted">
        Detection metrics come only from labeled test runs: OFFLINE results score held-out runs with mitigation
        inert; LAB RUNS are measured from recordings of the final configuration. Nothing is estimated.
      </p>
    </div>
  );
}
