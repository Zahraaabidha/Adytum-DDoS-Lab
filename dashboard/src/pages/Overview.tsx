import { Link } from "react-router-dom";
import { Badge, Card, StatTile, EmptyState } from "../components/ui";
import { CorrelationPanel } from "../components/correlation/CorrelationPanel";
import { LiveFeedList } from "../components/feed/LiveFeedList";
import { useGlobeMarkers } from "../components/globe/useGlobeMarkers";
import { useThreatsCountries, useThreatsLive, useThreatsStats, useThreatsTypes } from "../lib/queries";
import { useSandboxAttacksStatus } from "../lib/sandboxStatus";
import { useThreatStore } from "../store/threatStore";

const RECENT_ALERTS_LIMIT = 5;
const TOP_N = 5;

/**
 * High-level operational dashboard (Stage G) -- summary widgets/KPIs and a
 * globe preview card, deliberately NOT the full Threat Feed experience
 * (search/filter/sort UI, the full live feed list) which lives on its own
 * page. Everything here is either a small real-data summary or a link
 * into the page that has the full experience.
 */
export function Overview() {
  const { data: stats, isLoading: statsLoading, isError: statsError } = useThreatsStats();
  const { data: recent, isLoading: recentLoading, isError: recentError } = useThreatsLive(RECENT_ALERTS_LIMIT);
  const { data: countries, isLoading: countriesLoading } = useThreatsCountries();
  const { data: types, isLoading: typesLoading } = useThreatsTypes();
  const globeFilters = useThreatStore((state) => state.globeFilters);
  const { markers: mapMarkers, sandboxMarkers, isLoading: mapLoading } = useGlobeMarkers(globeFilters);
  const { data: sandboxStatus, isLoading: sandboxLoading, isError: sandboxError } = useSandboxAttacksStatus();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatTile label="Total IOCs" value={statsError ? "--" : (stats?.total_iocs ?? (statsLoading ? "..." : 0))} />
        <StatTile label="Total CVEs" value={statsError ? "--" : (stats?.total_cves ?? (statsLoading ? "..." : 0))} />
        <StatTile
          label="Countries observed"
          value={statsError ? "--" : (stats?.distinct_countries ?? (statsLoading ? "..." : 0))}
        />
        <StatTile
          label="Top attack family"
          value={statsError ? "--" : (stats?.top_attack_family ?? (statsLoading ? "..." : "None yet"))}
        />
      </div>

      <CorrelationPanel />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Global Threat Map</h2>
            <Link to="/threat-intel" className="text-xs text-accent hover:underline">
              Open full 3D globe &rarr;
            </Link>
          </div>
          {mapLoading ? (
            <p className="mt-4 text-xs text-slate-500">Loading map data...</p>
          ) : mapMarkers.length === 0 ? (
            <div className="mt-2">
              <EmptyState
                title="No geolocated threats yet"
                hint="Real threat-intel indicators fill in once GeoIP enrichment resolves at least one coordinate. Sandbox attacks plot immediately -- try starting one in Sandbox Lab."
              />
            </div>
          ) : (
            <p className="mt-4 text-sm text-slate-300">
              <span className="text-2xl font-semibold text-slate-100">{mapMarkers.length}</span> geolocated threats
              plotted{" "}
              {sandboxMarkers.length > 0 && (
                <span className="text-slate-500">({sandboxMarkers.length} from active sandbox traffic)</span>
              )}
              {sandboxMarkers.length === 0 && (
                <>
                  across <span className="font-medium text-slate-100">{stats?.distinct_countries ?? "?"}</span>{" "}
                  countries.
                </>
              )}
            </p>
          )}
        </Card>

        <Card>
          <h2 className="text-sm font-semibold text-slate-100">Sandbox Lab status</h2>
          {sandboxError && (
            <p className="mt-2 text-xs text-slate-500">Sandbox control API (globe:8090) is unreachable right now.</p>
          )}
          {sandboxLoading && !sandboxError && <p className="mt-2 text-xs text-slate-500">Checking...</p>}
          {!sandboxLoading && !sandboxError && (
            <ul className="mt-3 space-y-2">
              {Object.entries(sandboxStatus?.running ?? {}).map(([attackType, running]) => (
                <li key={attackType} className="flex items-center justify-between text-xs">
                  <span className="text-slate-300">{attackType}</span>
                  <Badge tone={running ? "ok" : "neutral"}>{running ? "Running" : "Stopped"}</Badge>
                </li>
              ))}
              {Object.keys(sandboxStatus?.running ?? {}).length === 0 && (
                <li className="text-xs text-slate-500">No attack profiles reported.</li>
              )}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <h2 className="mb-2 text-sm font-semibold text-slate-100">Top countries</h2>
          {countriesLoading && <p className="text-xs text-slate-500">Loading...</p>}
          {!countriesLoading && (countries?.length ?? 0) === 0 && (
            <p className="text-xs text-slate-500">No country data yet.</p>
          )}
          <ul className="space-y-1.5">
            {(countries ?? []).slice(0, TOP_N).map((c) => (
              <li key={c.country} className="flex items-center justify-between text-xs">
                <span className="text-slate-300">{c.country}</span>
                <span className="text-slate-500">{c.count}</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <h2 className="mb-2 text-sm font-semibold text-slate-100">Top threat types</h2>
          {typesLoading && <p className="text-xs text-slate-500">Loading...</p>}
          {!typesLoading && (types?.length ?? 0) === 0 && <p className="text-xs text-slate-500">No type data yet.</p>}
          <ul className="space-y-1.5">
            {(types ?? []).slice(0, TOP_N).map((t) => (
              <li key={t.threat_type} className="flex items-center justify-between text-xs">
                <span className="text-slate-300">{t.threat_type}</span>
                <span className="text-slate-500">{t.count}</span>
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Recent alerts</h2>
            <Link to="/threat-intel" className="text-xs text-accent hover:underline">
              View all &rarr;
            </Link>
          </div>
          <div className="mt-2">
            <LiveFeedList events={recent ?? []} isLoading={recentLoading} isError={recentError} compact />
          </div>
        </Card>
      </div>
    </div>
  );
}
