import { useQuery } from "@tanstack/react-query";
import type { SandboxAttacksStatus } from "../types/threat";

/**
 * Read-only client for exactly one `globe/server.py` endpoint --
 * `GET /api/attacks/status` -- reached same-origin via the existing
 * `/api/sandbox/*` proxy rule (`vite.config.ts` dev / `nginx.conf` prod,
 * both wired in Stage E). This powers Overview's sandbox status widget
 * only (per the Stage G roadmap entry in PROJECT_EXECUTION_PLAN.md).
 *
 * Deliberately narrower than `src/lib/sandboxApi.ts`, the full typed
 * client (start/stop controls, feed, etc.) reserved for Stage H's ported
 * Sandbox Lab page -- this file must not grow into that.
 */
export function useSandboxAttacksStatus() {
  return useQuery({
    queryKey: ["sandbox-attacks-status"],
    staleTime: 10_000,
    refetchInterval: 15_000,
    retry: 0,
    queryFn: async () => {
      const response = await fetch("/api/sandbox/attacks/status");
      if (!response.ok) throw new Error(`sandbox attacks/status returned ${response.status}`);
      return (await response.json()) as SandboxAttacksStatus;
    },
  });
}
