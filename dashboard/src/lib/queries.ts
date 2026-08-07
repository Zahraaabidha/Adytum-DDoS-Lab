import { useQuery } from "@tanstack/react-query";
import { threatIntelApi } from "./api";
import type {
  CorrelationResult,
  CountryCount,
  GeoipStatus,
  ProviderStatus,
  ThreatEvent,
  ThreatStats,
  ThreatTypeCount,
  TimelineBucket,
} from "../types/threat";

/**
 * Typed react-query wrappers around threat-intel's aggregate/list REST
 * endpoints. `routes_threats.py`'s handlers return plain dicts (not a
 * Pydantic `response_model`), so `openapi-fetch`'s generated response type
 * is `unknown` for all of these -- each hook here casts to the matching
 * hand-written shape in `types/threat.ts` (Stage E's documented extension
 * point for exactly this gap), same pattern already used by
 * `components/globe/DetailPanel.tsx`.
 */

const STALE_TIME_MS = 30_000;

export function useThreatsLive(limit = 100) {
  return useQuery({
    queryKey: ["threats-live", limit],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/live", {
        params: { query: { limit } },
      });
      if (error) throw error;
      return ((data as { events: ThreatEvent[] }).events ?? []) as ThreatEvent[];
    },
  });
}

export function useThreatsCountries() {
  return useQuery({
    queryKey: ["threats-countries"],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/countries", {});
      if (error) throw error;
      return ((data as { countries: CountryCount[] }).countries ?? []) as CountryCount[];
    },
  });
}

export function useThreatsTypes() {
  return useQuery({
    queryKey: ["threats-types"],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/types", {});
      if (error) throw error;
      return ((data as { types: ThreatTypeCount[] }).types ?? []) as ThreatTypeCount[];
    },
  });
}

export function useThreatsTimeline(bucket: "hour" | "day" = "hour", sinceHours = 48) {
  return useQuery({
    queryKey: ["threats-timeline", bucket, sinceHours],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/timeline", {
        params: { query: { bucket, since_hours: sinceHours } },
      });
      if (error) throw error;
      return ((data as { buckets: TimelineBucket[] }).buckets ?? []) as TimelineBucket[];
    },
  });
}

export function useThreatsStats() {
  return useQuery({
    queryKey: ["threats-stats"],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/stats", {});
      if (error) throw error;
      return data as ThreatStats;
    },
  });
}

/**
 * Stage I: the sandbox <-> global-threat-intel correlation heuristic.
 * Polled rather than one-shot since the underlying sandbox telemetry
 * changes continuously; `retry: 0` because an unreachable defense-engine
 * is already represented by `available: false` in the payload itself
 * (the endpoint degrades gracefully, it does not error), so retrying a
 * successful-but-unavailable response would be pointless.
 */
export function useCorrelation() {
  return useQuery({
    queryKey: ["threats-correlation"],
    staleTime: 10_000,
    refetchInterval: 15_000,
    retry: 0,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/correlation", {});
      if (error) throw error;
      return data as CorrelationResult;
    },
  });
}

export function useProvidersStatus() {
  return useQuery({
    queryKey: ["providers-status"],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/providers/status", {});
      if (error) throw error;
      return ((data as { providers: ProviderStatus[] }).providers ?? []) as ProviderStatus[];
    },
  });
}

export function useGeoipStatus() {
  return useQuery({
    queryKey: ["geoip-status"],
    staleTime: STALE_TIME_MS,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/geoip/status", {});
      if (error) throw error;
      return data as GeoipStatus;
    },
  });
}

/**
 * threat-intel's own `/health` (Stage A cross-cutting requirement),
 * reached same-origin via the `/health` proxy rule added in this stage
 * (`vite.config.ts` dev / `nginx.conf` prod) -- not part of the OpenAPI
 * schema `threatIntelApi` is generated from, so a plain `fetch` is used.
 */
export function useThreatIntelHealth() {
  return useQuery({
    queryKey: ["threat-intel-health"],
    staleTime: STALE_TIME_MS,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/health");
      if (!response.ok) throw new Error(`threat-intel /health returned ${response.status}`);
      return (await response.json()) as Record<string, unknown>;
    },
  });
}
