import { Link } from "react-router-dom";
import { Badge, Card, StatTile, EmptyState } from "../components/ui";
import { CorrelationPanel } from "../components/correlation/CorrelationPanel";
import { SEVERITY_LABEL, SEVERITY_TONE } from "../components/feed/labels";
import { useGlobeMarkers } from "../components/globe/useGlobeMarkers";
import { useThreatsCountries, useThreatsStats, useThreatsTypes } from "../lib/queries";
import { useIncidents, useSuricataSummary } from "../lib/defenseEngineApi";
import { useSandboxAttacksStatus } from "../lib/sandboxStatus";
import { useThreatStore } from "../store/threatStore";

const TOP_N = 5;
const RECENT_INCIDENTS = 6;

/**
 * Operational overview: real security metrics first (incidents, Suricata
 * alerts, indicators), then recent incidents and the geographic picture.
 * Service health, providers and GeoIP status live in Settings.
 */
export function Overview() {
  const { data: stats, isLoading: statsLoading, isError: statsError } = useThreatsStats();
  const { data: incidents, isLoading: incidentsLoading, isError: incidentsError } = useIncidents(RECENT_INCIDENTS);
  const { data: suricata, isError: suricataError } = useSuricataSummary();
  const { data: countries, isLoading: countriesLoading } = useThreatsCountries();
  const { data: types, isLoading: typesLoading } = useThreatsTypes();
  const globeFilters = useThreatStore((state) => state.globeFilters);
  const { markers: mapMarkers, sandboxMarkers, isLoading: mapLoading } = useGlobeMarkers(globeFilters);
  const { data: sandboxStatus, isLoading: sandboxLoading, isError: sandboxError } = useSandboxAttacksStatus();

  const list = incidents?.incidents ?? [];
  const activeIncidents = list.filter((i) => i.status === "active").length;
  const dash = "--";

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile
          label="Active incidents"
          value={incidentsError ? dash : incidentsLoading ? "..." : activeIncidents}
          hint={incidentsError ? "defense-engine unreachable" : `${list.length} recent incidents`}
        />
        <StatTile
          label="Suricata alerts"
          value={suricataError ? dash : (suricata?.total_ingested ?? "...")}
          hint={
            suricata
              ? `${suricata.recent_alerts} in the last ${Math.round(suricata.window_seconds / 60)} min`
              : suricataError
                ? "defense-engine unreachable"
                : undefined
          }
        />
        <StatTile
          label="Threat indicators"
          value={statsError ? dash : (stats?.total_iocs ?? (statsLoading ? "..." : 0))}
          hint="From external feeds"
        />
        <StatTile
          label="Known CVEs"
          value={statsError ? dash : (stats?.total_cves ?? (statsLoading ? "..." : 0))}
          hint="From external feeds"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-ink">Recent incidents</h2>
            <Link to="/alerts" className="text-xs font-medium text-accent hover:underline">
              All alerts &rarr;
            </Link>
          </div>
          {incidentsError && <p className="mt-4 text-xs text-ink-muted">Incident data is unavailable right now.</p>}
          {incidentsLoading && <p className="mt-4 text-xs text-ink-muted">Loading...</p>}
          {!incidentsLoading && !incidentsError && list.length === 0 && (
            <div className="mt-3">
              <EmptyState title="No incidents recorded" hint="Incidents appear when Suricata or the ML detector flag traffic." />
            </div>
          )}
          {list.length > 0 && (
            <ul className="mt-3 divide-y divide-line">
              {list.map((incident) => (
                <li key={incident.id} className="flex items-start justify-between gap-3 py-3">
                  <div className="min-w-0">
                    <Link
                      to={`/alerts/${encodeURIComponent(`incident-${incident.id}`)}`}
                      className="text-sm font-medium text-ink hover:text-accent hover:underline"
                    >
                      {incident.title}
                    </Link>
                    <p className="mt-0.5 text-xs text-ink-muted">
                      {new Date(incident.start * 1000).toLocaleString()} · {incident.duration_s.toFixed(0)} s · {incident.status}
                    </p>
                  </div>
                  <Badge tone={SEVERITY_TONE[incident.severity]} className="shrink-0">
                    {SEVERITY_LABEL[incident.severity]}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-ink">Sandbox Lab status</h2>
          {sandboxError && <p className="mt-3 text-xs text-ink-muted">Sandbox control API is unreachable right now.</p>}
          {sandboxLoading && !sandboxError && <p className="mt-3 text-xs text-ink-muted">Checking...</p>}
          {!sandboxLoading && !sandboxError && (
            <ul className="mt-3 divide-y divide-line">
              {Object.entries(sandboxStatus?.running ?? {}).map(([attackType, running]) => (
                <li key={attackType} className="flex items-center justify-between py-2 text-xs">
                  <span className="text-ink-soft">{attackType}</span>
                  <Badge tone={running ? "ok" : "neutral"}>{running ? "Running" : "Stopped"}</Badge>
                </li>
              ))}
              {Object.keys(sandboxStatus?.running ?? {}).length === 0 && (
                <li className="py-2 text-xs text-ink-muted">No attack profiles reported.</li>
              )}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-ink">Global threat map</h2>
            <Link to="/threat-intel" className="text-xs font-medium text-accent hover:underline">
              Open globe &rarr;
            </Link>
          </div>
          {mapLoading ? (
            <p className="mt-4 text-xs text-ink-muted">Loading map data...</p>
          ) : mapMarkers.length === 0 ? (
            <div className="mt-3">
              <EmptyState
                title="No geolocated threats yet"
                hint="Indicators are plotted once GeoIP enrichment resolves a coordinate. See GeoIP status in Settings."
              />
            </div>
          ) : (
            <p className="mt-4 text-sm text-ink-soft">
              <span className="text-2xl font-semibold text-ink">{mapMarkers.length}</span> geolocated threats plotted
              {sandboxMarkers.length > 0 && <span className="text-ink-muted"> ({sandboxMarkers.length} from sandbox traffic)</span>}
            </p>
          )}
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-ink">Top countries</h2>
          {countriesLoading && <p className="text-xs text-ink-muted">Loading...</p>}
          {!countriesLoading && (countries?.length ?? 0) === 0 && (
            <p className="text-xs text-ink-muted">No country data yet (requires GeoIP enrichment).</p>
          )}
          <ul className="divide-y divide-line">
            {(countries ?? []).slice(0, TOP_N).map((c) => (
              <li key={c.country} className="flex items-center justify-between py-2 text-xs">
                <span className="text-ink-soft">{c.country}</span>
                <span className="text-ink-muted">{c.count}</span>
              </li>
            ))}
          </ul>
          <h2 className="mb-2 mt-5 text-sm font-semibold uppercase tracking-wide text-ink">Top threat types</h2>
          {typesLoading && <p className="text-xs text-ink-muted">Loading...</p>}
          {!typesLoading && (types?.length ?? 0) === 0 && <p className="text-xs text-ink-muted">No type data yet.</p>}
          <ul className="divide-y divide-line">
            {(types ?? []).slice(0, TOP_N).map((t) => (
              <li key={t.threat_type} className="flex items-center justify-between py-2 text-xs">
                <span className="text-ink-soft">{t.threat_type}</span>
                <span className="text-ink-muted">{t.count}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <CorrelationPanel />
    </div>
  );
}
