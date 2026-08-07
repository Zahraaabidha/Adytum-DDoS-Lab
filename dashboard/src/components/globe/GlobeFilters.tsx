import { useQuery } from "@tanstack/react-query";
import { threatIntelApi } from "../../lib/api";
import { useThreatStore } from "../../store/threatStore";
import { Card } from "../ui";

const SINCE_HOURS_OPTIONS = [
  { label: "Last hour", value: 1 },
  { label: "Last 6 hours", value: 6 },
  { label: "Last 24 hours", value: 24 },
  { label: "Last 7 days", value: 168 },
];

/**
 * Country/type/confidence/time filters for the globe, wired to
 * useThreatStore's globeFilters slice (Stage F addition) so filter state
 * survives remounts and is available to any later page that wants it.
 * Country/type option lists come from the backend's own distinct-value
 * endpoints rather than being hardcoded, so they stay accurate as new
 * providers/geographies appear.
 */
export function GlobeFilters() {
  const filters = useThreatStore((state) => state.globeFilters);
  const setFilters = useThreatStore((state) => state.setGlobeFilters);

  const { data: countries } = useQuery({
    queryKey: ["threat-countries"],
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/countries", {});
      if (error) throw error;
      return (data as { countries?: { country: string; count: number }[] }).countries ?? [];
    },
    staleTime: 5 * 60_000,
  });

  const { data: types } = useQuery({
    queryKey: ["threat-types"],
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/types", {});
      if (error) throw error;
      return (data as { types?: { threat_type: string; count: number }[] }).types ?? [];
    },
    staleTime: 5 * 60_000,
  });

  return (
    <Card className="absolute left-4 top-4 z-10 w-64 space-y-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Globe filters</p>

      <label className="block text-xs text-slate-400">
        Time window
        <select
          className="mt-1 w-full rounded-md border border-white/10 bg-panel px-2 py-1.5 text-xs text-slate-200"
          value={filters.sinceHours}
          onChange={(e) => setFilters({ sinceHours: Number(e.target.value) })}
        >
          {SINCE_HOURS_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>

      <label className="block text-xs text-slate-400">
        Country
        <select
          className="mt-1 w-full rounded-md border border-white/10 bg-panel px-2 py-1.5 text-xs text-slate-200"
          value={filters.country ?? ""}
          onChange={(e) => setFilters({ country: e.target.value || null })}
        >
          <option value="">All countries</option>
          {(countries ?? []).map(({ country }) => (
            <option key={country} value={country}>
              {country}
            </option>
          ))}
        </select>
      </label>

      <label className="block text-xs text-slate-400">
        Threat type
        <select
          className="mt-1 w-full rounded-md border border-white/10 bg-panel px-2 py-1.5 text-xs text-slate-200"
          value={filters.threatType ?? ""}
          onChange={(e) => setFilters({ threatType: e.target.value || null })}
        >
          <option value="">All types</option>
          {(types ?? []).map(({ threat_type }) => (
            <option key={threat_type} value={threat_type}>
              {threat_type}
            </option>
          ))}
        </select>
      </label>

      <label className="block text-xs text-slate-400">
        Min confidence: {Math.round(filters.minConfidence * 100)}%
        <input
          type="range"
          min={0}
          max={1}
          step={0.05}
          value={filters.minConfidence}
          onChange={(e) => setFilters({ minConfidence: Number(e.target.value) })}
          className="mt-1 w-full accent-accent"
        />
      </label>
    </Card>
  );
}
