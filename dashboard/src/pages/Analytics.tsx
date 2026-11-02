import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { Line, LineChart, Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { MitigationLogTable } from "../components/sandbox/MitigationLogTable";
import { Badge, Disclosure, EmptyState, Pagination, Tabs, usePagination } from "../components/ui";
import type { DetectionNormal, DetectionTypeResult, MitigationReport } from "../types/threat";
import {
  useMitigations,
  useDefenseThreshold,
  useDetectionEvaluation,
  useMitigationReport,
  useDefenseEngineHealth,
} from "../lib/defenseEngineApi";
import { useThreatsStats, useThreatsTimeline, useThreatsTypes } from "../lib/queries";

/**
 * Sandbox vs. global comparison. Deliberately shows only metrics the backends
 * actually expose: `defense-engine`'s `/mitigations` gives a confidence/
 * threshold timeline and an action count, `threat-intel`'s
 * `/api/threats/{timeline,types,stats}` gives real ingestion volume.
 * Precision/recall/FPR are shown only when `defense-engine`'s `/evaluation`
 * serves a report produced by `classifier/evaluate.py` from labeled
 * recordings; with no report the section shows an empty state rather than
 * an estimate (the project's no-fabrication rule).
 *
 * Four tabs: headline numbers first (Overview), then the offline evaluation,
 * the lab-run mitigation results, and threat-intelligence volume. Long
 * historical tables sit in collapsed, paginated sections.
 */
const percent = (value: number) => `${(value * 100).toFixed(1)}%`;

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "detection", label: "Detection" },
  { id: "mitigation", label: "Mitigation" },
  { id: "experiments", label: "Experiments" },
] as const;
type TabId = (typeof TABS)[number]["id"];

const AXIS = { fontSize: 13, fill: "#5f6770" };
const TOOLTIP = { background: "#ffffff", border: "1px solid #dcdfe2", borderRadius: 0, fontSize: 14 };

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="bg-white p-5">
      <p className="text-[13px] font-semibold uppercase tracking-[0.12em] text-ink-muted">{label}</p>
      <p className="mt-2 text-3xl font-semibold tracking-tight text-ink">{value}</p>
      {hint && <p className="mt-1.5 text-sm text-ink-muted">{hint}</p>}
    </div>
  );
}

function MetricGrid({ children, cols = 4 }: { children: ReactNode; cols?: 3 | 4 }) {
  return (
    <div className={`grid grid-cols-2 gap-px border border-line bg-line ${cols === 4 ? "lg:grid-cols-4" : "sm:grid-cols-3"}`}>{children}</div>
  );
}

/** One connected strip of figures, the same style as the live-engine metrics. */
function MetricList({ items }: { items: [string, string][] }) {
  return (
    <MetricGrid>
      {items.map(([label, value]) => (
        <Metric key={label} label={label} value={value} />
      ))}
    </MetricGrid>
  );
}

function Panel({ title, note, large = false, children }: { title: string; note?: ReactNode; large?: boolean; children: ReactNode }) {
  return (
    <section>
      <h2 className={large ? "text-3xl font-medium tracking-tight text-ink md:text-4xl" : "text-base font-semibold uppercase tracking-[0.12em] text-ink"}>{title}</h2>
      {note && <p className={`mb-4 ${large ? "mt-3" : "mt-1"} text-sm leading-relaxed text-ink-muted`}>{note}</p>}
      <div className={note ? "" : "mt-3"}>{children}</div>
    </section>
  );
}

function TableBox({ children }: { children: ReactNode }) {
  return <div className="overflow-x-auto border border-line bg-white p-4">{children}</div>;
}

/** Per-traffic-type detection results. */
function ResultTable({ rows, normal, idle }: { rows: DetectionTypeResult[]; normal: DetectionNormal; idle: DetectionNormal }) {
  const falseRate = (row: DetectionNormal) => percent(row.false_positives / Math.max(row.samples, 1));
  return (
    <table className="w-full min-w-[520px] text-left text-base text-ink-soft">
      <thead className="text-[13px] uppercase tracking-wide text-ink-muted">
        <tr>
          <th className="py-1.5 font-medium">Traffic type</th>
          <th className="py-1.5 font-medium">Samples</th>
          <th className="py-1.5 font-medium">Flagged</th>
          <th className="py-1.5 font-medium">Precision</th>
          <th className="py-1.5 font-medium">Recall</th>
          <th className="py-1.5 font-medium">F1</th>
        </tr>
      </thead>
      <tbody>
        {[
          { label: "legitimate", row: normal },
          { label: "idle (no traffic)", row: idle },
        ].map(({ label, row }) => (
          <tr key={label} className="border-t border-line">
            <td className="py-2">{label}</td>
            <td className="py-2">{row.samples}</td>
            <td className="py-2">{row.false_positives} false</td>
            <td className="py-2" colSpan={3}>
              false-positive rate {falseRate(row)}
            </td>
          </tr>
        ))}
        {rows.map((row) => (
          <tr key={row.attack_type} className="border-t border-line">
            <td className="py-2">
              {row.attack_type}
              {row.low_sample && <span className="ml-2 text-amber-700">low sample</span>}
            </td>
            <td className="py-2">{row.samples}</td>
            <td className="py-2">{row.flagged}</td>
            <td className="py-2">{percent(row.metrics.precision)}</td>
            <td className="py-2">{percent(row.metrics.recall)}</td>
            <td className="py-2">{row.metrics.f1.toFixed(3)}</td>
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

type ReportData = Extract<MitigationReport, { available: true }>;
type MitigationRow = ReportData["rows"][number];

function MitigationTable({ rows, report, showConfig }: { rows: MitigationRow[]; report: ReportData; showConfig: boolean }) {
  return (
    <table className="w-full min-w-[980px] text-left text-sm text-ink-soft">
      <thead className="text-[13px] uppercase tracking-wide text-ink-muted">
        <tr>
          <th className="py-1.5 pr-3 font-medium">Scenario</th>
          {showConfig && <th className="py-1.5 pr-3 font-medium">Configuration</th>}
          <th className="py-1.5 pr-3 font-medium">Attack blocked</th>
          <th className="py-1.5 pr-3 font-medium">Attack req/s (offered → admitted, steady)</th>
          <th className="py-1.5 pr-3 font-medium">Legitimate blocked</th>
          <th className="py-1.5 pr-3 font-medium">Cap (min / typical; below ½ baseline after)</th>
          <th className="py-1.5 pr-3 font-medium">Flagged polls</th>
          <th className="py-1.5 font-medium">Recovery</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={`${row.scenario}-${row.config}`} className="border-t border-line align-top">
            <td className="py-2 pr-3">
              {SCENARIO_LABEL[row.scenario]}
              {row.attack_sources > 1 && ` (${row.attack_sources} sources)`}
              {row.start?.clean === false && <span className="ml-2 text-amber-700">unclean start (cap {row.start.cap_rps?.toFixed(0)})</span>}
            </td>
            {showConfig && <td className="py-2 pr-3">{report.configs[row.config]?.label ?? row.config}</td>}
            <td className="py-2 pr-3">
              {!row.attack
                ? "--"
                : row.attack.http && row.attack.blocked_fraction !== undefined
                  ? `${percent(row.attack.blocked_fraction)} (${row.attack.blocked}/${row.attack.requests})`
                  : "not HTTP: detected only, not blocked"}
            </td>
            <td className="py-2 pr-3">
              {!row.attack
                ? "--"
                : row.attack.http
                  ? `${row.attack.offered_rps.toFixed(0)} → ${row.attack.admitted_rps?.toFixed(0)}, ${row.attack.steady_admitted_rps?.toFixed(0)}`
                  : `${row.attack.offered_rps.toFixed(0)} events/s`}
            </td>
            <td className="py-2 pr-3">{row.legit ? `${percent(row.legit.blocked_fraction)} (${row.legit.blocked}/${row.legit.requests})` : "--"}</td>
            <td className="py-2 pr-3">
              {row.limit.min_rps == null
                ? "--"
                : `${row.limit.min_rps.toFixed(0)} / ${row.limit.typical_rps?.toFixed(0)}${row.limit.below_half_baseline_s == null ? "" : `; ${row.limit.below_half_baseline_s}s`}`}
            </td>
            <td className="py-2 pr-3">
              {row.flagged_polls} / {row.polls}
            </td>
            <td className="py-2">
              {row.recovery ? (row.recovery.recovered ? `${row.recovery.seconds}s` : `not within ${row.recovery.observed_seconds}s`) : "--"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HistoricalRows({ rows, report }: { rows: MitigationRow[]; report: ReportData }) {
  const paged = usePagination(rows, 10);
  return (
    <>
      <TableBox>
        <MitigationTable rows={paged.rows} report={report} showConfig />
      </TableBox>
      <Pagination current={paged.current} pageCount={paged.pageCount} total={paged.total} pageSize={paged.pageSize} onPage={paged.setPage} />
    </>
  );
}

function PagedList<T>({ items, render }: { items: T[]; render: (item: T) => ReactNode }) {
  const paged = usePagination(items, 10);
  return (
    <>
      <ul className="list-disc space-y-1 pl-5 text-base text-ink-soft">{paged.rows.map(render)}</ul>
      <Pagination current={paged.current} pageCount={paged.pageCount} total={paged.total} pageSize={paged.pageSize} onPage={paged.setPage} />
    </>
  );
}

export function Analytics() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab: TabId = TABS.some((t) => t.id === requested) ? (requested as TabId) : "overview";

  const { data: actions, isLoading: actionsLoading, isError: actionsError } = useMitigations(200);
  const { data: threshold, isError: thresholdError } = useDefenseThreshold();
  const { data: evaluation, isLoading: evaluationLoading, isError: evaluationError } = useDetectionEvaluation();
  const { data: mitigation, isLoading: mitigationLoading } = useMitigationReport();
  const { data: engineHealth } = useDefenseEngineHealth();

  const mitigationChartData = (actions ?? []).map((action) => ({
    time: new Date(action.ts * 1000).toLocaleTimeString(),
    confidence: Number((action.confidence * 100).toFixed(1)),
    threshold: Number(action.new_threshold.toFixed(1)),
  }));

  const evalReady = !evaluationError && evaluation?.available ? evaluation : null;
  const report = mitigation?.available ? mitigation : null;
  const finalConfig = report ? Object.entries(report.configs).find(([, c]) => /^final\b/i.test(c.label))?.[0] : undefined;
  const finalRows = report ? report.rows.filter((r) => (finalConfig ? r.config === finalConfig : true)) : [];

  const engineDown = actionsError && thresholdError;

  return (
    <div className="flex flex-col gap-8">
      <Tabs tabs={TABS} active={tab} onChange={(id) => setParams(id === "overview" ? {} : { tab: id })} label="Analytics sections" />

      {tab === "overview" && (
        <div className="flex flex-col gap-8">
          {engineDown ? (
            <EmptyState title="Defense engine unreachable" hint="defense-engine:9300 did not respond. Bring up the sandbox stack to see mitigation metrics." />
          ) : (
            <>
              <Panel
                large
                title="Detection results"
                note={
                  evalReady
                    ? `Offline evaluation on held-out labeled runs (${evalReady.samples.normal} legitimate, ${evalReady.samples.attack} attack samples). Full breakdown in the Detection tab.`
                    : "Offline evaluation on held-out labeled runs."
                }
              >
                {evalReady ? (
                  <MetricList
                    items={[
                      ["Precision", percent(evalReady.metrics.precision)],
                      ["Recall", percent(evalReady.metrics.recall)],
                      ["False-positive rate", percent(evalReady.metrics.false_positive_rate)],
                      ["F1", evalReady.metrics.f1.toFixed(3)],
                    ]}
                  />
                ) : (
                  <EmptyState
                    title={evaluationLoading ? "Loading..." : "No evaluation report yet"}
                    hint="Run defense/classifier/evaluate.py with --output on labeled recordings (see README) to populate this."
                  />
                )}
              </Panel>

              {engineHealth && !engineHealth.model_loaded && (
                <p className="border border-red-200 bg-white px-4 py-3 text-base text-red-700">
                  NO MODEL LOADED: detection is in pass-through mode (confidence 0) and nothing will be mitigated. Check MODEL_PATH /
                  SENTINEL_MODEL_PATH and the engine log.
                </p>
              )}

              <Panel title="Live defense engine">
                <MetricGrid cols={3}>
                  <Metric label="Mitigation actions logged" value={actionsError ? "--" : String(actions?.length ?? (actionsLoading ? "..." : 0))} />
                  <Metric label="Rate-limit threshold" value={thresholdError ? "--" : `${threshold?.threshold_rps.toFixed(1) ?? "?"} req/s`} />
                  <Metric label="Classifier confidence" value={thresholdError ? "--" : `${Math.round((threshold?.confidence ?? 0) * 100)}%`} />
                </MetricGrid>
              </Panel>

              <Panel title="Classifier confidence and rate-limit threshold" note="Over recent mitigation actions.">
                <div className="border border-line bg-white p-4">
                  {actionsLoading && <p className="text-sm text-ink-muted">Loading...</p>}
                  {!actionsLoading && mitigationChartData.length === 0 && (
                    <EmptyState title="No mitigation actions yet" hint="Run an attack scenario against the sandbox to generate real mitigation events." />
                  )}
                  {mitigationChartData.length > 0 && (
                    <div className="h-64 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={mitigationChartData}>
                          <CartesianGrid stroke="#e8eaec" vertical={false} />
                          <XAxis dataKey="time" tick={AXIS} minTickGap={40} />
                          <YAxis tick={AXIS} />
                          <Tooltip contentStyle={TOOLTIP} />
                          <Line type="monotone" dataKey="confidence" name="Confidence %" stroke="#2f7f7a" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="threshold" name="Threshold req/s" stroke="#16191c" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>
              </Panel>

              <Disclosure title="Limitations" hint="What the results do not cover">
                <p className="text-sm leading-relaxed text-ink-muted">
                  The candidate model is the selected default; the original model.joblib is kept for rollback (set
                  SENTINEL_MODEL_PATH=/app/classifier/model.joblib). Limitations: the rate limiter protects HTTP traffic only (UDP, TCP and
                  Slowloris are detected, not mitigated); concurrent legitimate requests are still partly blocked during floods and mitigation
                  starts only after a delay (measured in the lab comparison); training used synthetic lab traffic at one load level. See the
                  README, &quot;Model selection&quot;.
                </p>
              </Disclosure>

              <Disclosure title="Global Threat Intelligence ingestion volume" hint="Indicator and CVE totals, ingestion per hour and top threat types">
                <IntelSection />
              </Disclosure>
            </>
          )}
        </div>
      )}

      {tab === "detection" && (
        <div className="flex flex-col gap-6">
          <Panel
            title="Classifier evaluation on held-out runs"
            note={
              <>
                <Badge tone="neutral">OFFLINE</Badge> Live feature samples logged by the engine during labeled test runs the model was not
                trained on, re-scored with the trained model while mitigation was inert. Measures detection only; no rate limiting involved.
              </>
            }
          >
            {!evalReady ? (
              <EmptyState
                title={evaluationLoading ? "Loading..." : "No evaluation report yet"}
                hint="Run defense/classifier/evaluate.py with --output on labeled recordings (see README) to populate this."
              />
            ) : (
              <div className="flex flex-col gap-4">
                <MetricList
                    items={[
                      ["Precision", percent(evalReady.metrics.precision)],
                      ["Recall", percent(evalReady.metrics.recall)],
                      ["False-positive rate", percent(evalReady.metrics.false_positive_rate)],
                      ["F1", evalReady.metrics.f1.toFixed(3)],
                    ]}
                  />
                <p className="text-base text-ink-soft">
                  {evalReady.samples.normal} legitimate and {evalReady.samples.attack} attack samples, threshold {evalReady.metrics.threshold}.
                  Confusion: TP {evalReady.metrics.true_positives}, FP {evalReady.metrics.false_positives}, TN {evalReady.metrics.true_negatives},
                  FN {evalReady.metrics.false_negatives}.
                </p>
                <ConfusionMatrix m={evalReady.metrics} />
                <TableBox>
                  <ResultTable rows={evalReady.by_type} normal={evalReady.normal} idle={evalReady.idle} />
                </TableBox>

                <p className="text-sm text-ink-muted">
                  Evaluated {new Date(evalReady.generated_at).toLocaleString()}. Model trained on: {evalReady.trained_on.join(", ") || "unknown"};
                  none of those runs are scored. Sample unit: {evalReady.sample_unit}.
                </p>
              </div>
            )}
          </Panel>
        </div>
      )}

      {tab === "mitigation" && (
        <div className="flex flex-col gap-6">
          <Panel
            title="End-to-end mitigation results"
            note={
              <>
                <Badge tone="neutral">NOTE</Badge> End-to-end mitigation results (rate limit reached, requests blocked, legitimate traffic blocked
                during an attack, recovery) are shown only from the LAB RUNS below, which include the final default (candidate model, guarded policy,
                headroom 6, fair limiter). The offline report served with the evaluation was generated before that configuration was final, so its
                older &quot;live&quot; and &quot;collateral&quot; figures are deliberately not displayed.
              </>
            }
          >
            {!report ? (
              <EmptyState
                title={mitigationLoading ? "Loading..." : "No mitigation comparison yet"}
                hint="Run the m_<config>_<scenario> lab scenarios and classifier/mitigation_report.py --output (see README)."
              />
            ) : (
              <div className="flex flex-col gap-4">
                <div>
                  <p className="mb-2 text-[13px] font-semibold uppercase tracking-[0.12em] text-ink-muted">
                    <Badge tone="accent">LAB RUNS</Badge>{" "}
                    {finalConfig ? report.configs[finalConfig].label : "All configurations"}
                  </p>
                  <TableBox>
                    <MitigationTable rows={finalRows} report={report} showConfig={!finalConfig} />
                  </TableBox>
                </div>

                <p className="text-sm text-ink-muted">
                  The other configurations and the full comparison are in the Experiments tab.
                </p>
                <p className="text-sm leading-relaxed text-ink-muted">
                  Generated {new Date(report.generated_at).toLocaleString()}. Baseline cap {report.baseline_limit_rps} req/s. The same controlled
                  scenarios were replayed against each limiter and mitigation-policy configuration with the same model; all figures are measured
                  from the recordings and the engine&apos;s own log. &quot;Flagged polls&quot; are engine polls with confidence of at least 0.5; for
                  the legitimate-only scenario they are false positives. Recovery is the time after an attack stopped until the cap was back
                  above 90% of the baseline.
                </p>

              </div>
            )}
          </Panel>
        </div>
      )}

      {tab === "mitigation" && (
        <Disclosure title="Mitigation log" hint="Every rate-limit adjustment the defense engine has logged, newest first">
          <MitigationLogTable />
        </Disclosure>
      )}

      {tab === "experiments" && (
        <div className="flex flex-col gap-8">
          <Panel
            title="LAB RUNS comparison"
            note="The same controlled scenarios replayed against each limiter and mitigation-policy configuration with the same model. Figures are measured from the recordings and the engine's own log."
          >
            {!report ? (
              <EmptyState
                title={mitigationLoading ? "Loading..." : "No mitigation comparison yet"}
                hint="Run the m_<config>_<scenario> lab scenarios and classifier/mitigation_report.py --output (see README)."
              />
            ) : (
              <div className="flex flex-col gap-4">
                <HistoricalRows rows={report.rows} report={report} />
                <p className="text-sm text-ink-muted">
                  {report.rows.length} runs across {Object.keys(report.configs).length} configurations; generated{" "}
                  {new Date(report.generated_at).toLocaleString()}. Baseline cap {report.baseline_limit_rps} req/s.
                </p>
                {report.excluded_runs && report.excluded_runs.length > 0 && (
                  <Disclosure title={`Recordings not counted (${report.excluded_runs.length})`} hint="Kept on disk but excluded from the results">
                    <PagedList
                      items={report.excluded_runs}
                      render={(row) => (
                        <li key={row.run}>
                          {row.run}: {row.reason}
                        </li>
                      )}
                    />
                  </Disclosure>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Detailed evaluation records" note="Per-recording results behind the Detection tab.">
            {!evalReady ? (
              <EmptyState title={evaluationLoading ? "Loading..." : "No evaluation report yet"} />
            ) : (
              <div className="flex flex-col gap-4">
                <Disclosure title={`Per-run results (${evalReady.runs.length})`} hint="Samples flagged in each evaluated recording">
                  <RunsTable runs={evalReady.runs} />
                </Disclosure>
                {evalReady.excluded.length > 0 && (
                  <Disclosure title={`Recordings not scored (${evalReady.excluded.length})`} hint="Kept on disk but excluded from the metrics">
                    <PagedList
                      items={evalReady.excluded}
                      render={(row) => (
                        <li key={row.run}>
                          {row.run} ({row.events} events): {row.reason}
                        </li>
                      )}
                    />
                  </Disclosure>
                )}
              </div>
            )}
          </Panel>
        </div>
      )}

      <p className="text-sm text-ink-muted">
        Detection metrics come only from labeled test runs: OFFLINE results score held-out runs with mitigation inert; LAB RUNS are measured from
        recordings of the final configuration. Nothing is estimated.
      </p>
    </div>
  );
}


function RunsTable({ runs }: { runs: { run: string; attack_type?: string | null; label?: string; flagged: number; samples: number }[] }) {
  const paged = usePagination(runs, 10);
  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[420px] text-left text-base text-ink-soft">
          <thead className="text-[13px] uppercase tracking-wide text-ink-muted">
            <tr>
              <th className="py-1.5 font-medium">Run</th>
              <th className="py-1.5 font-medium">Traffic</th>
              <th className="py-1.5 font-medium">Samples flagged</th>
            </tr>
          </thead>
          <tbody>
            {paged.rows.map((row) => (
              <tr key={row.run} className="border-t border-line">
                <td className="py-2">{row.run}</td>
                <td className="py-2">{row.attack_type ?? row.label}</td>
                <td className="py-2">
                  {row.flagged} / {row.samples}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pagination current={paged.current} pageCount={paged.pageCount} total={paged.total} pageSize={paged.pageSize} onPage={paged.setPage} />
    </>
  );
}

function IntelSection() {
  const { data: stats, isError: statsError } = useThreatsStats();
  const { data: timeline, isLoading: timelineLoading, isError: timelineError } = useThreatsTimeline("hour", 48);
  const { data: types, isLoading: typesLoading, isError: typesError } = useThreatsTypes();

  const timelineChartData = (timeline ?? []).map((bucket) => ({
    time: new Date(bucket.bucket).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" }),
    count: bucket.count,
  }));
  const typesChartData = (types ?? []).slice(0, 8).map((t) => ({ type: t.threat_type, count: t.count }));

  return (
    <>
          {statsError ? (
            <EmptyState title="threat-intel unreachable" hint="Could not load aggregate statistics." />
          ) : (
            <div className="flex flex-col gap-6">
              <MetricGrid cols={3}>
                <Metric label="Total IOCs" value={(stats?.total_iocs ?? 0).toLocaleString()} />
                <Metric label="Total CVEs" value={(stats?.total_cves ?? 0).toLocaleString()} />
                <Metric label="Distinct countries" value={String(stats?.distinct_countries ?? 0)} />
              </MetricGrid>
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div className="border border-line bg-white p-4">
                  <h3 className="mb-2 text-[13px] font-semibold uppercase tracking-[0.12em] text-ink">IOCs ingested per hour (last 48h)</h3>
                  {timelineLoading && <p className="text-sm text-ink-muted">Loading...</p>}
                  {!timelineLoading && timelineChartData.length === 0 && <EmptyState title="No ingestion activity yet" />}
                  {timelineError && <EmptyState title="Timeline unavailable" />}
                  {timelineChartData.length > 0 && (
                    <div className="h-60 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={timelineChartData}>
                          <CartesianGrid stroke="#e8eaec" vertical={false} />
                          <XAxis dataKey="time" tick={AXIS} minTickGap={40} />
                          <YAxis tick={AXIS} />
                          <Tooltip contentStyle={TOOLTIP} />
                          <Bar dataKey="count" name="IOCs ingested" fill="#2b2f33" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>

                <div className="border border-line bg-white p-4">
                  <h3 className="mb-2 text-[13px] font-semibold uppercase tracking-[0.12em] text-ink">Top threat types (all-time)</h3>
                  {typesLoading && <p className="text-sm text-ink-muted">Loading...</p>}
                  {!typesLoading && typesChartData.length === 0 && <EmptyState title="No threat type data yet" />}
                  {typesError && <EmptyState title="Threat type data unavailable" />}
                  {typesChartData.length > 0 && (
                    <div className="h-60 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={typesChartData} layout="vertical">
                          <CartesianGrid stroke="#e8eaec" horizontal={false} />
                          <XAxis type="number" tick={AXIS} />
                          <YAxis dataKey="type" type="category" width={110} tick={AXIS} />
                          <Tooltip contentStyle={TOOLTIP} />
                          <Bar dataKey="count" name="Count" fill="#2f7f7a" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

    </>
  );
}

function ConfusionMatrix({ m }: { m: { true_positives: number; false_positives: number; true_negatives: number; false_negatives: number } }) {
  const cell = "border border-line px-6 py-8 text-center text-2xl";
  const colHead = "px-6 py-3 text-center text-sm font-medium uppercase tracking-wide text-ink-muted";
  const rowHead = "py-8 pr-6 text-center text-sm font-medium uppercase tracking-wide text-ink-muted";
  return (
    <div className="overflow-x-auto border border-line bg-white px-4 py-8 md:px-8">
      <p className="mb-6 text-center text-base font-semibold uppercase tracking-[0.12em] text-ink">Confusion matrix</p>
      <table className="mx-auto w-full max-w-2xl border-collapse text-ink-soft">
        <thead>
          <tr>
            <th className="px-6 py-3" />
            <th className={colHead}>Predicted attack</th>
            <th className={colHead}>Predicted normal</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th className={rowHead}>Actual attack</th>
            <td className={`${cell} bg-teal-50 font-semibold text-ink`}>TP {m.true_positives}</td>
            <td className={cell}>FN {m.false_negatives}</td>
          </tr>
          <tr>
            <th className={rowHead}>Actual normal</th>
            <td className={cell}>FP {m.false_positives}</td>
            <td className={`${cell} bg-teal-50 font-semibold text-ink`}>TN {m.true_negatives}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
