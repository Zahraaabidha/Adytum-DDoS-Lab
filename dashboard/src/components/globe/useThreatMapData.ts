import { useQuery } from "@tanstack/react-query";
import { threatIntelApi } from "../../lib/api";
import type { ThreatEvent } from "../../types/threat";
import type { GlobeFilters } from "../../store/threatStore";

/**
 * Client-side render cap, independent of the backend's own MAP_LIMIT=2000
 * (services/threat-intel/app/api/routes_threats.py). 2000 individually
 * rendered/animated WebGL objects is more than a smooth orbit-controlled
 * scene needs; capping here (after sorting by recency) keeps the globe
 * responsive regardless of how much data the backend has ingested.
 */
export const MAX_RENDERED_MARKERS = 800;

interface ThreatMapResponse {
  events: ThreatEvent[];
}

/**
 * Fetches `/api/threats/map` (lat/lon guaranteed non-null by that
 * endpoint -- rows without geolocation are excluded server-side) filtered
 * by the globe's current filter state, and caps the result client-side
 * for render performance. Response body is typed `unknown` by the
 * generated client (routes_threats.py returns plain dicts) so it's cast
 * to `ThreatEvent[]` here, same pattern as the rest of the dashboard.
 */
export function useThreatMapData(filters: GlobeFilters) {
  return useQuery({
    queryKey: ["threats-map", filters],
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/map", {
        params: {
          query: {
            since_hours: filters.sinceHours,
            country: filters.country ?? undefined,
            threat_type: filters.threatType ?? undefined,
            min_confidence: filters.minConfidence,
          },
        },
      });
      if (error) throw error;
      const events = (data as ThreatMapResponse).events ?? [];
      const sorted = [...events].sort(
        (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
      );
      return sorted.slice(0, MAX_RENDERED_MARKERS);
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}
