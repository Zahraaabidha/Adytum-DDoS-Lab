import { Card, EmptyState } from "../ui";
import { useMitigations } from "../../lib/defenseEngineApi";

/**
 * Reuses the existing `useMitigations` client (`lib/defenseEngineApi.ts`,
 * built in Stage G for the Analytics page) rather than adding a second
 * `/mitigations` fetcher -- same `defense-engine:9300/mitigations` data,
 * rendered as a raw chronological log here instead of a chart.
 */
export function MitigationLogTable() {
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
    <Card className="flex flex-col gap-2">
      <h3 className="text-xs font-medium text-slate-300">Mitigation log</h3>
      {isLoading && <p className="text-xs text-slate-500">Loading...</p>}
      {!isLoading && rows.length === 0 && (
        <EmptyState title="No mitigation actions yet" hint="Run an attack scenario to generate real mitigation events." />
      )}
      {rows.length > 0 && (
        <div className="max-h-72 overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-panelmuted/95 text-slate-400">
              <tr>
                <th className="py-1 pr-2 font-medium">Time</th>
                <th className="py-1 pr-2 font-medium">Confidence</th>
                <th className="py-1 pr-2 font-medium">Threshold</th>
                <th className="py-1 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((action, i) => (
                <tr key={`${action.ts}-${i}`} className="border-t border-white/5 text-slate-300">
                  <td className="py-1 pr-2 whitespace-nowrap">{new Date(action.ts * 1000).toLocaleTimeString()}</td>
                  <td className="py-1 pr-2">{Math.round(action.confidence * 100)}%</td>
                  <td className="py-1 pr-2 whitespace-nowrap">
                    {action.old_threshold.toFixed(1)} &rarr; {action.new_threshold.toFixed(1)} req/s
                  </td>
                  <td className="py-1 text-slate-400">{action.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
