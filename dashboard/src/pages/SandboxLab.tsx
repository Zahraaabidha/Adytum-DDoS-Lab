import { useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState, ShowMore } from "../components/ui";
import { AttackControls } from "../components/sandbox/AttackControls";
import { SandboxCharts } from "../components/sandbox/SandboxCharts";
import { GrafanaPanel } from "../components/sandbox/GrafanaPanel";
import { useSandboxFeed } from "../lib/sandboxApi";

const FEED_INITIAL = 10;

/**
 * Sandbox Lab, ported natively (Architecture Decision #4) -- calls
 * `globe/server.py`'s existing JSON API directly via the `/api/sandbox/*`
 * same-origin proxy. No Docker/container awareness exists anywhere in this
 * file or its children: attack lifecycle is two REST calls
 * (`AttackControls`), the event feed is one REST call (below), and the
 * mitigation log reuses the existing `defense-engine` client. Lists start
 * short and expand in place; nothing scrolls inside a box.
 */
export function SandboxLab() {
  const { data: feed, isLoading, isError } = useSandboxFeed(60, 200);
  const events = [...(feed?.events ?? [])].reverse();
  const [shown, setShown] = useState(FEED_INITIAL);

  return (
    <div className="flex flex-col gap-10">
      <AttackControls />

      <SandboxCharts />

      <GrafanaPanel />

      <section>
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-base font-semibold uppercase tracking-[0.12em] text-ink">Live event feed</h2>
          {feed?.run_name && <span className="text-sm text-ink-muted">run: {feed.run_name}</span>}
        </div>
        <div className="border border-line bg-white p-4">
          {isError && <EmptyState title="Feed unavailable" hint="The sandbox control API's /api/feed did not respond." />}
          {!isError && isLoading && <p className="text-sm text-ink-muted">Loading...</p>}
          {!isError && !isLoading && events.length === 0 && (
            <EmptyState title="No recent events" hint="Start an attack scenario above to populate the live feed." />
          )}
          {events.length > 0 && (
            <>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-left text-base">
                  <thead className="border-b border-line text-[13px] uppercase tracking-wide text-ink-muted">
                    <tr>
                      <th className="py-2 pr-3 font-medium">Time</th>
                      <th className="py-2 pr-3 font-medium">Attack</th>
                      <th className="py-2 pr-3 font-medium">Target</th>
                      <th className="py-2 pr-3 font-medium">Status</th>
                      <th className="py-2 font-medium">Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {events.slice(0, shown).map((event, i) => (
                      <tr key={`${event.ts}-${i}`} className="text-ink-soft">
                        <td className="whitespace-nowrap py-2 pr-3 text-sm">{new Date(event.ts * 1000).toLocaleTimeString()}</td>
                        <td className="py-2 pr-3">{event.attack_type}</td>
                        <td className="py-2 pr-3">{event.target}</td>
                        <td className="py-2 pr-3">{event.status ?? "--"}</td>
                        <td className="py-2">{event.latency_ms != null ? `${event.latency_ms.toFixed(0)} ms` : "--"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <ShowMore shown={shown} total={events.length} step={20} initial={FEED_INITIAL} onChange={setShown} />
            </>
          )}
        </div>
      </section>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 border-t border-line pt-6 text-sm text-ink-muted">
        <span>
          Incidents and Suricata alerts are on the <Link to="/alerts" className="font-medium text-accent hover:underline">Alerts</Link> page; the mitigation log is
          under <Link to="/analytics?tab=mitigation" className="font-medium text-accent hover:underline">Analytics</Link>.
        </span>
      </div>
    </div>
  );
}
