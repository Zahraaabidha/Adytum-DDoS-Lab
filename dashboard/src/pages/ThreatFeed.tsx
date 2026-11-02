import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { ThreatGlobe } from "../components/globe/ThreatGlobe";
import { IndicatorFeed } from "../components/feed/IndicatorFeed";
import { DataSources } from "../components/feed/DataSources";
import { useThreatsStats } from "../lib/queries";

const TABS = [
  { id: "globe", label: "Globe" },
  { id: "feed", label: "Threat Feed" },
  { id: "sources", label: "Data Sources" },
] as const;
type TabId = (typeof TABS)[number]["id"];

function Total({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-white px-5 py-4">
      <p className="text-[13px] font-semibold uppercase tracking-[0.12em] text-ink-muted">{label}</p>
      <p className="mt-1.5 text-2xl font-semibold tracking-tight text-ink">{value}</p>
    </div>
  );
}

/**
 * Global Threat Intelligence: the geographic view, a searchable indicator
 * feed, and the data sources behind both. The active tab lives in the URL
 * (?tab=) so it survives reloads and can be linked.
 */
export function ThreatFeed() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab: TabId = TABS.some((t) => t.id === requested) ? (requested as TabId) : "globe";
  const { data: stats, isError } = useThreatsStats();
  const show = (n: number | undefined) => (isError ? "--" : n != null ? n.toLocaleString() : "...");

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-px border border-line bg-line lg:grid-cols-4">
        <Total label="Threat indicators" value={show(stats?.total_iocs)} />
        <Total label="Known CVEs" value={show(stats?.total_cves)} />
        <Total label="Countries observed" value={show(stats?.distinct_countries)} />
        <Total label="Top attack family" value={isError ? "--" : (stats?.top_attack_family ?? (stats ? "None yet" : "..."))} />
      </div>

      <div role="tablist" aria-label="Global Threat Intelligence sections" className="flex gap-6 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setParams(t.id === "globe" ? {} : { tab: t.id })}
            className={clsx(
              "-mb-px border-b-2 px-1 pb-3 pt-1 text-base font-semibold transition-colors",
              tab === t.id ? "border-accent text-ink" : "border-transparent text-ink-muted hover:text-ink",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "globe" && <ThreatGlobe />}
      {tab === "feed" && <IndicatorFeed />}
      {tab === "sources" && <DataSources />}
    </div>
  );
}
