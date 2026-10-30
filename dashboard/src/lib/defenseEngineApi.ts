import { useQuery } from "@tanstack/react-query";
import type {
  DefenseHealth,
  DefenseThreshold,
  DetectionEvaluation,
  IncidentsResponse,
  MitigationAction,
  MitigationReport,
  SuricataAlert,
  SuricataSummary,
} from "../types/threat";

/**
 * `defense-engine` (Sandbox Lab, port 9300) is reached same-origin via the
 * `/api/defense/*` proxy rule (`vite.config.ts` dev / `nginx.conf` prod),
 * mirroring the `/api/threats/*` and `/api/sandbox/*` rules exactly, rather
 * than depending on `defense/engine.py`'s `CORSMiddleware(allow_origins=
 * ["*"])` for a direct cross-origin fetch (the original Stage G approach).
 * `defense/engine.py` itself is unchanged -- only the dashboard's own
 * proxy config and this client were touched.
 */
export function useMitigations(limit = 100) {
  return useQuery({
    queryKey: ["defense-mitigations", limit],
    staleTime: 15_000,
    refetchInterval: 15_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch(`/api/defense/mitigations?limit=${limit}`);
      if (!response.ok) throw new Error(`defense-engine /mitigations returned ${response.status}`);
      const data = (await response.json()) as { actions: MitigationAction[] };
      return data.actions ?? [];
    },
  });
}

export function useDefenseThreshold() {
  return useQuery({
    queryKey: ["defense-threshold"],
    staleTime: 10_000,
    refetchInterval: 15_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/defense/threshold");
      if (!response.ok) throw new Error(`defense-engine /threshold returned ${response.status}`);
      return (await response.json()) as DefenseThreshold;
    },
  });
}

export function useDefenseEngineHealth() {
  return useQuery({
    queryKey: ["defense-engine-health"],
    staleTime: 15_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/defense/health");
      if (!response.ok) throw new Error(`defense-engine /health returned ${response.status}`);
      return (await response.json()) as DefenseHealth;
    },
  });
}

/** Offline evaluation of the classifier on labeled recordings (`defense-engine` `/evaluation`). */
export function useDetectionEvaluation() {
  return useQuery({
    queryKey: ["defense-evaluation"],
    staleTime: 60_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/defense/evaluation");
      if (!response.ok) throw new Error(`defense-engine /evaluation returned ${response.status}`);
      return (await response.json()) as DetectionEvaluation;
    },
  });
}

/** Measured limiter/policy comparison from the controlled lab scenarios (`defense-engine` `/mitigation-report`). */
export function useMitigationReport() {
  return useQuery({
    queryKey: ["defense-mitigation-report"],
    staleTime: 60_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/defense/mitigation-report");
      if (!response.ok) throw new Error(`defense-engine /mitigation-report returned ${response.status}`);
      return (await response.json()) as MitigationReport;
    },
  });
}

/** Suricata alerts (newest first), each annotated with the ML detector's view at that time (`/suricata/alerts`). */
export function useSuricataAlerts(limit = 100) {
  return useQuery({
    queryKey: ["defense-suricata-alerts", limit],
    staleTime: 5_000,
    refetchInterval: 10_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch(`/api/defense/suricata/alerts?limit=${limit}`);
      if (!response.ok) throw new Error(`defense-engine /suricata/alerts returned ${response.status}`);
      return ((await response.json()) as { alerts: SuricataAlert[] }).alerts ?? [];
    },
  });
}

export function useSuricataSummary() {
  return useQuery({
    queryKey: ["defense-suricata-summary"],
    staleTime: 5_000,
    refetchInterval: 10_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/defense/suricata/summary");
      if (!response.ok) throw new Error(`defense-engine /suricata/summary returned ${response.status}`);
      return (await response.json()) as SuricataSummary;
    },
  });
}

/** Unified incidents: Suricata alerts + Isolation Forest + Prometheus evidence (`/incidents`). */
export function useIncidents(limit = 10) {
  return useQuery({
    queryKey: ["defense-incidents", limit],
    staleTime: 5_000,
    refetchInterval: 10_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch(`/api/defense/incidents?limit=${limit}`);
      if (!response.ok) throw new Error(`defense-engine /incidents returned ${response.status}`);
      return (await response.json()) as IncidentsResponse;
    },
  });
}
