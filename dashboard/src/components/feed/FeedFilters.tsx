import type { CountryCount, ProviderStatus, ThreatTypeCount } from "../../types/threat";

export type FeedSort = "newest" | "oldest";

export interface FeedFilterState {
  search: string;
  provider: string | null;
  threatType: string | null;
  country: string | null;
  minConfidence: number;
  sort: FeedSort;
}

interface FeedFiltersProps {
  value: FeedFilterState;
  onChange: (patch: Partial<FeedFilterState>) => void;
  providers: ProviderStatus[];
  types: ThreatTypeCount[];
  countries: CountryCount[];
}

const SELECT_CLASSES =
  " border border-line bg-white px-2 py-1.5 text-xs text-ink focus:border-accent/60 focus:outline-none";

/**
 * Search + filter/sort bar for the full Threat Feed page. Filter option
 * lists are built entirely from real backend data (`/api/providers/status`,
 * `/api/threats/types`, `/api/threats/countries`) rather than a
 * hand-maintained enum, so a new provider/type/country shows up here
 * automatically.
 *
 * Provider filtering is a known partial feature: `Ioc` rows returned by
 * `/api/threats/live`/`/search` are deduped/merged across sources and only
 * carry a `source_count` integer, not a per-row provider name (see
 * `app/common/models.py`) -- the Global Threat Intelligence backend is not
 * modified in this stage to add one. The per-provider `source` name is
 * only present on events received live over `/ws/threats` while this page
 * is open (`LiveThreatEvent.source`). So the Provider filter only matches
 * threats that have arrived live during this session; backlog threats
 * loaded from `/api/threats/live` are excluded when a specific provider is
 * selected, which the hint text below states explicitly rather than
 * silently under-filtering.
 */
export function FeedFilters({ value, onChange, providers, types, countries }: FeedFiltersProps) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={value.search}
          onChange={(e) => onChange({ search: e.target.value })}
          placeholder="Search IP, country, type..."
          className="min-w-[220px] flex-1  border border-line bg-white px-3 py-1.5 text-sm text-ink placeholder:text-ink-muted focus:border-accent/60 focus:outline-none"
        />

        <select
          className={SELECT_CLASSES}
          value={value.provider ?? ""}
          onChange={(e) => onChange({ provider: e.target.value || null })}
        >
          <option value="">All providers</option>
          {providers.map((provider) => (
            <option key={provider.name} value={provider.name}>
              {provider.name}
              {!provider.enabled ? " (disabled)" : ""}
            </option>
          ))}
        </select>

        <select
          className={SELECT_CLASSES}
          value={value.threatType ?? ""}
          onChange={(e) => onChange({ threatType: e.target.value || null })}
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t.threat_type} value={t.threat_type}>
              {t.threat_type} ({t.count})
            </option>
          ))}
        </select>

        <select
          className={SELECT_CLASSES}
          value={value.country ?? ""}
          onChange={(e) => onChange({ country: e.target.value || null })}
        >
          <option value="">All countries</option>
          {countries.map((c) => (
            <option key={c.country} value={c.country}>
              {c.country} ({c.count})
            </option>
          ))}
        </select>

        <label className="flex items-center gap-2 text-xs text-ink-muted">
          Min confidence
          <input
            type="range"
            min={0}
            max={100}
            step={5}
            value={Math.round(value.minConfidence * 100)}
            onChange={(e) => onChange({ minConfidence: Number(e.target.value) / 100 })}
            className="accent-accent"
          />
          <span className="w-9 text-right text-ink-soft">{Math.round(value.minConfidence * 100)}%</span>
        </label>

        <select
          className={SELECT_CLASSES}
          value={value.sort}
          onChange={(e) => onChange({ sort: e.target.value as FeedSort })}
        >
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
        </select>
      </div>

      {value.provider && (
        <p className="text-[11px] text-ink-muted">
          Provider filter only matches threats received live over the WebSocket during this session -- the backend's
          deduped IOC records don't carry a per-row provider name (see source_count instead).
        </p>
      )}
    </div>
  );
}
