import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { SandboxFeedResponse } from "../types/threat";

/**
 * Typed client for `globe/server.py`'s attack-lifecycle and feed endpoints,
 * reached same-origin via the existing `/api/sandbox/*` proxy rule
 * (`vite.config.ts` dev / `nginx.conf` prod, both wired in Stage E) -- the
 * same pattern `defenseEngineApi.ts` uses for `/api/defense/*`. No CORS
 * change is needed: the browser only ever talks to this dashboard's own
 * origin, and the proxy forwards to `globe:8090` server-side.
 *
 * This is the full Sandbox Lab client reserved by `sandboxStatus.ts`'s
 * doc comment for Stage H -- `sandboxStatus.ts` itself is left untouched
 * (Overview still depends on its narrower `useSandboxAttacksStatus` hook,
 * which this module re-exports rather than duplicating).
 *
 * Docker/container lifecycle is entirely `globe/server.py`'s
 * responsibility (it shells out to `docker compose` over its own mounted
 * docker.sock). This client only ever calls that service's HTTP API --
 * nothing here, or anywhere else in `dashboard/`, invokes Docker directly.
 */
export { useSandboxAttacksStatus } from "./sandboxStatus";

export const ATTACK_TYPES = [
  { id: "http-flood", label: "HTTP Flood" },
  { id: "slowloris", label: "Slowloris" },
  { id: "udp-flood", label: "UDP Flood" },
  { id: "tcp-exhaustion", label: "TCP Exhaustion" },
  { id: "legit-load", label: "Legit Load (control)" },
] as const;

export function useSandboxFeed(windowSeconds = 60, limit = 200) {
  return useQuery({
    queryKey: ["sandbox-feed", windowSeconds, limit],
    staleTime: 5_000,
    refetchInterval: 5_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch(`/api/sandbox/feed?window_seconds=${windowSeconds}&limit=${limit}`);
      if (!response.ok) throw new Error(`sandbox /api/feed returned ${response.status}`);
      return (await response.json()) as SandboxFeedResponse;
    },
  });
}

export function useStartAttack() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (attackType: string) => {
      const response = await fetch(`/api/sandbox/attacks/${attackType}/start`, { method: "POST" });
      if (!response.ok) throw new Error(`start ${attackType} returned ${response.status}`);
      return (await response.json()) as { ok: boolean; attack_type: string };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sandbox-attacks-status"] });
    },
  });
}

export function useStopAttack() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (attackType: string) => {
      const response = await fetch(`/api/sandbox/attacks/${attackType}/stop`, { method: "POST" });
      if (!response.ok) throw new Error(`stop ${attackType} returned ${response.status}`);
      return (await response.json()) as { ok: boolean; attack_type: string };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sandbox-attacks-status"] });
    },
  });
}
