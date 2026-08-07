import { useMemo, useState } from "react";
import { ThreatGlobe } from "../components/globe/ThreatGlobe";
import { LiveFeedList } from "../components/feed/LiveFeedList";
import { FeedFilters, type FeedFilterState } from "../components/feed/FeedFilters";
import { Card } from "../components/ui";
import { useProvidersStatus, useThreatsCountries, useThreatsLive, useThreatsTypes } from "../lib/queries";
import { useThreatStore } from "../store/threatStore";
import type { LiveThreatEvent, ThreatEvent } from "../types/threat";

const DEFAULT_FILTERS: FeedFilterState = {
  search: "",
  provider: null,
  threatType: null,
  country: null,
  minConfidence: 0,
  sort: "newest",
};

/** Fills the structural gap between `LiveThreatEvent` and `ThreatEvent` with
 * explicit nulls/defaults -- never invented values, just the fields a live
 * WS payload genuinely doesn't carry (asn, organization, category,
 * source_count, first_seen). See `LiveThreatEvent`'s doc comment. */
function liveEventToRow(event: LiveThreatEvent): ThreatEvent & { source?: string } {
  return {
    ioc: event.ioc,
    ioc_type: event.ioc_type,
    country: event.country,
    lat: event.lat,
    lon: event.lon,
    asn: null,
    organization: null,
    threat_type: event.threat_type,
    attack_family: event.attack_family,
    category: null,
    confidence_score: event.confidence_score,
    source_count: 1,
    first_seen: event.timestamp,
    last_seen: event.timestamp,
    source: event.source,
  };
}

/**
 * Full Threat Feed page (Stage G) -- Stage F's globe stays mounted
 * unchanged at the top; below it, the live feed gains the search/filter/
 * sort UI this page was always the reserved spot for (see Stage F's
 * placeholder comment, since replaced).
 */
export function ThreatFeed() {
  const [filters, setFilters] = useState<FeedFilterState>(DEFAULT_FILTERS);

  const { data: liveData, isLoading, isError } = useThreatsLive(300);
  const { data: providers } = useProvidersStatus();
  const { data: types } = useThreatsTypes();
  const { data: countries } = useThreatsCountries();
  const wsEvents = useThreatStore((state) => state.liveEvents);

  const merged = useMemo(() => {
    const base = liveData ?? [];
    const byKey = new Map<string, ThreatEvent & { source?: string }>();
    for (const event of base) byKey.set(`${event.ioc}-${event.threat_type}`, event);
    for (const event of wsEvents) {
      const key = `${event.ioc}-${event.threat_type}`;
      const existing = byKey.get(key);
      if (existing) {
        byKey.set(key, { ...existing, source: event.source });
      } else {
        byKey.set(key, liveEventToRow(event));
      }
    }
    return Array.from(byKey.values());
  }, [liveData, wsEvents]);

  const filtered = useMemo(() => {
    const search = filters.search.trim().toLowerCase();
    let rows = merged.filter((event) => {
      if (filters.threatType && event.threat_type !== filters.threatType) return false;
      if (filters.country && event.country !== filters.country) return false;
      if (event.confidence_score < filters.minConfidence) return false;
      if (filters.provider && (event as { source?: string }).source !== filters.provider) return false;
      if (search) {
        const haystack = [event.ioc, event.country, event.threat_type, event.attack_family, event.category]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      return true;
    });

    rows = [...rows].sort((a, b) => {
      const diff = new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      return filters.sort === "newest" ? diff : -diff;
    });

    return rows;
  }, [merged, filters]);

  return (
    <div className="flex flex-col gap-6">
      <ThreatGlobe />

      <Card>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Threat Feed</h2>
        <FeedFilters
          value={filters}
          onChange={(patch) => setFilters((prev) => ({ ...prev, ...patch }))}
          providers={providers ?? []}
          types={types ?? []}
          countries={countries ?? []}
        />
        <div className="mt-4">
          <LiveFeedList
            events={filtered}
            isLoading={isLoading}
            isError={isError}
            emptyHint="No IOCs match the current search/filters."
          />
        </div>
      </Card>
    </div>
  );
}
