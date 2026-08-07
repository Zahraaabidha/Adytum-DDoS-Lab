import { useQuery } from "@tanstack/react-query";
import type { DefenseThreshold, MitigationAction } from "../types/threat";

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
      return (await response.json()) as Record<string, unknown>;
    },
  });
}
