import { Badge, EmptyState } from "../ui";
import { CorrelationPanel } from "../correlation/CorrelationPanel";
import { useGeoipStatus, useProvidersStatus, useThreatsCountries, useThreatsStats, useThreatsTypes } from "../../lib/queries";

const TOP_N = 8;

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border border-line bg-white">
      <h3 className="border-b border-line px-4 py-3 text-[13px] font-semibold uppercase tracking-[0.12em] text-ink">{title}</h3>
      {children}
    </section>
  );
}

export function DataSources() {
  const { data: providers, isLoading, isError } = useProvidersStatus();
  const { data: geoip } = useGeoipStatus();
  const { data: stats } = useThreatsStats();
  const { data: countries } = useThreatsCountries();
  const { data: types } = useThreatsTypes();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Panel title="Intelligence providers">
            {isError && <p className="p-4 text-sm text-ink-muted">Provider status is unavailable.</p>}
            {isLoading && <p className="p-4 text-sm text-ink-muted">Loading...</p>}
            {providers && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[480px] text-left text-base">
                  <thead className="border-b border-line text-[13px] uppercase tracking-wide text-ink-muted">
                    <tr>
                      <th className="px-4 py-2 font-medium">Provider</th>
                      <th className="px-4 py-2 font-medium">Provides</th>
                      <th className="px-4 py-2 font-medium">Status</th>
                      <th className="px-4 py-2 font-medium">Refresh</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {providers.map((p) => (
                      <tr key={p.name}>
                        <td className="px-4 py-2.5 text-ink">{p.name}</td>
                        <td className="px-4 py-2.5 text-sm uppercase text-ink-soft">{p.event_kind === "cve" ? "CVEs" : "Indicators"}</td>
                        <td className="px-4 py-2.5">
                          <Badge tone={p.enabled ? "ok" : "neutral"}>
                            {p.enabled ? "Enabled" : p.requires_key ? "No API key" : "Disabled"}
                          </Badge>
                        </td>
                        <td className="px-4 py-2.5 text-sm text-ink-muted">every {Math.round(p.poll_interval_seconds / 60)} min</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>

        <Panel title="Geolocation">
          <div className="space-y-2 p-4 text-base">
            <div className="flex justify-between">
              <span className="text-ink-muted">GeoIP enrichment</span>
              <Badge tone={geoip?.enrichment_available ? "ok" : "neutral"}>{geoip?.enrichment_available ? "Active" : "Unavailable"}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-ink-muted">Countries observed</span>
              <span className="text-ink">{stats?.distinct_countries ?? "--"}</span>
            </div>
            <p className="pt-2 text-sm text-ink-muted">Full GeoIP and service details are in Settings.</p>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <Panel title="Top countries">
          {(countries?.length ?? 0) === 0 ? (
            <p className="p-4 text-sm text-ink-muted">No country data yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {(countries ?? []).slice(0, TOP_N).map((c) => (
                <li key={c.country} className="flex justify-between px-4 py-2 text-base">
                  <span className="text-ink-soft">{c.country}</span>
                  <span className="text-ink-muted">{c.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        <Panel title="Top threat types">
          {(types?.length ?? 0) === 0 ? (
            <p className="p-4 text-sm text-ink-muted">No type data yet.</p>
          ) : (
            <ul className="divide-y divide-line">
              {(types ?? []).slice(0, TOP_N).map((t) => (
                <li key={t.threat_type} className="flex justify-between px-4 py-2 text-base">
                  <span className="text-ink-soft">{t.threat_type}</span>
                  <span className="text-ink-muted">{t.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {!providers && !isLoading && !isError && <EmptyState title="No data" />}
      <CorrelationPanel />
    </div>
  );
}
