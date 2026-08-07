import { create } from "zustand";
import type { LiveThreatEvent } from "../types/threat";

const MAX_LIVE_EVENTS = 200;

export interface GlobeFilters {
  country: string | null;
  threatType: string | null;
  minConfidence: number;
  sinceHours: number;
}

const DEFAULT_GLOBE_FILTERS: GlobeFilters = {
  country: null,
  threatType: null,
  minConfidence: 0,
  sinceHours: 24,
};

interface ThreatStoreState {
  liveEvents: LiveThreatEvent[];
  connectionStatus: "connecting" | "open" | "closed";
  pushEvent: (event: LiveThreatEvent) => void;
  setConnectionStatus: (status: ThreatStoreState["connectionStatus"]) => void;
  globeFilters: GlobeFilters;
  setGlobeFilters: (patch: Partial<GlobeFilters>) => void;
}

/**
 * Client-side live-event/filter state (Vite+React scaffold, Stage E).
 * Pages built in later stages (Overview, Threat Feed, the globe) all read
 * from this single store rather than each opening their own WS
 * connection -- useThreatStream is wired once, at the app shell level.
 *
 * globeFilters/setGlobeFilters added in Stage F: GlobeFilters.tsx writes
 * here so the selected country/type/confidence/time window is available
 * to any future consumer (e.g. Stage G's Overview page) without a second
 * source of truth.
 */
export const useThreatStore = create<ThreatStoreState>((set) => ({
  liveEvents: [],
  connectionStatus: "connecting",
  pushEvent: (event) =>
    set((state) => ({
      liveEvents: [event, ...state.liveEvents].slice(0, MAX_LIVE_EVENTS),
    })),
  setConnectionStatus: (status) => set({ connectionStatus: status }),
  globeFilters: DEFAULT_GLOBE_FILTERS,
  setGlobeFilters: (patch) =>
    set((state) => ({ globeFilters: { ...state.globeFilters, ...patch } })),
}));
