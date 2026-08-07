/** Shared sizing constants so every layer (sphere, markers, arcs, pulses) agrees on scale. */
export const GLOBE_RADIUS = 2;
export const MARKER_RADIUS = 0.014;

/**
 * Cap on concurrently-animated live pulse rings (new WS events), independent
 * of the static marker cap in useThreatMapData. Keeps continuous per-frame
 * animation work bounded even during a burst of live ingestion events.
 */
export const MAX_LIVE_PULSES = 40;
export const PULSE_LIFETIME_MS = 4000;
