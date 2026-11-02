import { Card, EmptyState } from "../components/ui";
import { AttackControls } from "../components/sandbox/AttackControls";
import { GrafanaPanel } from "../components/sandbox/GrafanaPanel";
import { MitigationLogTable } from "../components/sandbox/MitigationLogTable";
import { IncidentList } from "../components/sandbox/IncidentList";
import { SuricataAlerts } from "../components/sandbox/SuricataAlerts";
import { useSandboxFeed } from "../lib/sandboxApi";

/**
 * Sandbox Lab, ported natively (Architecture Decision #4) -- calls
 * `globe/server.py`'s existing JSON API directly via the `/api/sandbox/*`
 * same-origin proxy, same as `sandboxStatus.ts` already did for Overview.
 * No Docker/container awareness exists anywhere in this file or its
 * children: attack lifecycle is two REST calls (`AttackControls`), the
 * event feed is one REST call (below), and the mitigation log reuses the
 * existing `defense-engine` client. The legacy `globe/index.html` UI at
 * :8090 is untouched and keeps working independently of this page.
 */
export function SandboxLab() {
  const { data: feed, isLoading, isError } = useSandboxFeed(60, 200);
  const events = [...(feed?.events ?? [])].reverse();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <AttackControls />
        <GrafanaPanel />
      </div>

      <Card className="flex flex-col gap-2">
        <div className="flex items-baseline justify-between">
          <h3 className="text-xs font-medium text-ink-soft">Live event feed</h3>
          {feed?.run_name && <span className="text-[11px] text-ink-muted">run: {feed.run_name}</span>}
        </div>
        {isError && (
          <EmptyState title="Feed unavailable" hint="globe:8090's /api/feed did not respond." />
        )}
        {!isError && isLoading && <p className="text-xs text-ink-muted">Loading...</p>}
        {!isError && !isLoading && events.length === 0 && (
          <EmptyState title="No recent events" hint="Start an attack scenario above to populate the live feed." />
        )}
        {events.length > 0 && (
          <div className="max-h-72 overflow-y-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-white text-ink-muted">
                <tr>
                  <th className="py-1 pr-2 font-medium">Time</th>
                  <th className="py-1 pr-2 font-medium">Attack</th>
                  <th className="py-1 pr-2 font-medium">Target</th>
                  <th className="py-1 pr-2 font-medium">Status</th>
                  <th className="py-1 font-medium">Latency</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, i) => (
                  <tr key={`${event.ts}-${i}`} className="border-t border-line text-ink-soft">
                    <td className="py-1 pr-2 whitespace-nowrap">{new Date(event.ts * 1000).toLocaleTimeString()}</td>
                    <td className="py-1 pr-2">{event.attack_type}</td>
                    <td className="py-1 pr-2">{event.target}</td>
                    <td className="py-1 pr-2">{event.status ?? "--"}</td>
                    <td className="py-1">{event.latency_ms != null ? `${event.latency_ms.toFixed(0)} ms` : "--"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <IncidentList />

      <SuricataAlerts />

      <MitigationLogTable />
    </div>
  );
}
