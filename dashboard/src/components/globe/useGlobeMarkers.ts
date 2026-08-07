import { useMemo } from "react";
import { useSandboxFeed } from "../../lib/sandboxApi";
import { sandboxEventToThreatEvent } from "./sandboxMarkers";
import { useThreatMapData } from "./useThreatMapData";
import type { GlobeFilters } from "../../store/threatStore";

/**
 * Combines the two independent data sources the globe draws from:
 * threat-intel's GeoIP-enriched `/api/threats/map` (real external IOCs,
 * empty until GeoIP enrichment is configured) and the Sandbox Lab's own
 * `/api/sandbox/feed` (synthetic attacker locations, present the instant an
 * attack scenario starts -- see `sandboxMarkers.ts`). Neither source being
 * empty should block the other from rendering, so `hasData`/`isError` are
 * computed against the merged result, not threat-intel's status alone.
 */
export function useGlobeMarkers(filters: GlobeFilters) {
  const geoip = useThreatMapData(filters);
  const sandbox = useSandboxFeed(120, 150);

  const sandboxMarkers = useMemo(
    () => (sandbox.data?.events ?? []).map(sandboxEventToThreatEvent),
    [sandbox.data],
  );

  const markers = useMemo(
    () => [...(geoip.data ?? []), ...sandboxMarkers],
    [geoip.data, sandboxMarkers],
  );

  return {
    markers,
    sandboxMarkers,
    latestSandboxEvent: sandbox.data?.events.at(-1) ?? null,
    isLoading: geoip.isLoading && sandbox.isLoading,
    isError: geoip.isError,
    hasData: markers.length > 0,
  };
}
