import { useState } from "react";
import { EmptyState, ShowMore } from "../ui";
import { useMitigations } from "../../lib/defenseEngineApi";

/**
 * Reuses the existing `useMitigations` client (`lib/defenseEngineApi.ts`,
 * built in Stage G for the Analytics page) rather than adding a second
 * `/mitigations` fetcher -- same `defense-engine:9300/mitigations` data,
 * rendered as a raw chronological log here instead of a chart.
 */
const INITIAL = 10;

export function MitigationLogTable() {
  const [shown, setShown] = useState(INITIAL);
  const { data: actions, isLoading, isError } = useMitigations(100);

  if (isError) {
    return (
      <EmptyState
        title="Mitigation log unavailable"
        hint="defense-engine:9300 did not respond."
      />
    );
  }

  const rows = [...(actions ?? [])].sort((a, b) => b.ts - a.ts);

  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold uppercase tracking-[0.12em] text-ink">Mitigation log</h2>
      {isLoading && <p className="text-xs text-ink-muted">Loading...</p>}
      {!isLoading && rows.length === 0 && (
        <EmptyState title="No mitigation actions yet" hint="Run an attack scenario to generate real mitigation events." />
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto border border-line bg-white p-4">
          <table className="w-full min-w-[560px] text-left text-xs">
            <thead className="text-ink-muted">
              <tr>
                <th className="py-1 pr-2 font-medium">Time</th>
                <th className="py-1 pr-2 font-medium">Confidence</th>
                <th className="py-1 pr-2 font-medium">Threshold</th>
                <th className="py-1 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, shown).map((action, i) => (
                <tr key={`${action.ts}-${i}`} className="border-t border-line text-ink-soft">
                  <td className="py-1 pr-2 whitespace-nowrap">{new Date(action.ts * 1000).toLocaleTimeString()}</td>
                  <td className="py-1 pr-2">{Math.round(action.confidence * 100)}%</td>
                  <td className="py-1 pr-2 whitespace-nowrap">
                    {action.old_threshold.toFixed(1)} &rarr; {action.new_threshold.toFixed(1)} req/s
                  </td>
                  <td className="py-1 text-ink-muted">{action.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ShowMore shown={shown} total={rows.length} step={20} initial={INITIAL} onChange={setShown} />
    </section>
  );
}
