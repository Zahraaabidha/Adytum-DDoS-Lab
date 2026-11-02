import { useMemo, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { useThreatStore } from "../../store/threatStore";
import { MAX_RENDERED_MARKERS } from "./useThreatMapData";
import { useGlobeMarkers } from "./useGlobeMarkers";
import { sandboxEventToLiveThreatEvent } from "./sandboxMarkers";
import { GlobeBase } from "./GlobeBase";
import { MarkerLayer } from "./MarkerLayer";
import { LivePulseLayer } from "./LivePulseLayer";
import { ArcLayer } from "./ArcLayer";
import { Tooltip } from "./Tooltip";
import { GlobeFilters } from "./GlobeFilters";
import { DetailPanel } from "./DetailPanel";
import { EmptyState } from "../ui";
import type { ThreatEvent } from "../../types/threat";

/**
 * The Global Threat Intelligence 3D globe (Stage F). Primarily visualizes
 * the geographic distribution of ingested threats as static instanced
 * markers plus live arrival pulses; arcs are drawn only for events that
 * carry real destination coordinates (see ArcLayer.tsx), which never
 * happens with the current schema -- there is no fixed/fabricated
 * destination point anywhere in this component.
 *
 * Performance safeguards: markers are rendered as a single InstancedMesh
 * (one draw call regardless of count, static matrices written once rather
 * than per frame), the dataset is capped client-side at
 * MAX_RENDERED_MARKERS on top of the backend's own cap, live pulses are
 * capped (MAX_LIVE_PULSES) and self-expiring so a burst of ingestion can't
 * grow the animated object count without bound, and `dpr` is capped so
 * high-DPI displays don't force an oversized framebuffer. `frameloop`
 * stays at its default ("always") because live pulses animate
 * continuously via useFrame -- "demand" mode would freeze that animation
 * between OrbitControls interactions.
 */
export function ThreatGlobe() {
  const filters = useThreatStore((state) => state.globeFilters);
  const liveEvents = useThreatStore((state) => state.liveEvents);
  const { markers, latestSandboxEvent, isLoading, isError, hasData } = useGlobeMarkers(filters);
  const [hovered, setHovered] = useState<ThreatEvent | null>(null);
  const [selected, setSelected] = useState<ThreatEvent | null>(null);

  // Sandbox events don't arrive over `/ws/threats` (that socket is
  // threat-intel-only), so LivePulseLayer never sees them via `liveEvents`.
  // Splicing the most recent sandbox event in front gives sandbox attacks
  // the same animated arrival pulse real IOC ingestion gets.
  const mergedLiveEvents = useMemo(
    () => (latestSandboxEvent ? [sandboxEventToLiveThreatEvent(latestSandboxEvent), ...liveEvents] : liveEvents),
    [liveEvents, latestSandboxEvent],
  );

  return (
    <div className="relative h-[calc(100vh-12rem)] min-h-[480px] w-full overflow-hidden  border border-line bg-gradient-to-b from-white to-slate-100 ">
      <GlobeFilters />

      {/*
        `isError` only reflects threat-intel's /api/threats/map -- sandbox
        markers are a separate, independent source (useGlobeMarkers.ts), so
        a threat-intel outage no longer blanks out sandbox activity that's
        already rendering.
      */}
      {isError && !hasData && (
        <div className="absolute inset-0 flex items-center justify-center">
          <EmptyState
            title="Unable to load threat map"
            hint="threat-intel's /api/threats/map endpoint is unreachable. Check the service status and retry."
          />
        </div>
      )}

      {!isLoading && !hasData && !isError && (
        <div className="absolute inset-0 flex items-center justify-center">
          <EmptyState
            title="No geolocated threats yet"
            hint="Real threat-intel indicators appear here once ingestion has run and GeoIP enrichment has resolved at least one coordinate. Sandbox attack traffic appears immediately -- start a scenario on the Sandbox Lab page to see it here."
          />
        </div>
      )}

      {hasData && (
        <Canvas
          dpr={[1, 1.5]}
          camera={{ position: [0, 0, 5.2], fov: 45 }}
          gl={{ antialias: true, powerPreference: "high-performance" }}
        >
          <ambientLight intensity={1.6} />
          <directionalLight position={[5, 3, 5]} intensity={1.2} />
          <GlobeBase />
          <MarkerLayer events={markers} onHover={setHovered} onSelect={setSelected} />
          <LivePulseLayer liveEvents={mergedLiveEvents} />
          <ArcLayer events={markers} />
          <Tooltip event={hovered} />
          <OrbitControls
            enablePan={false}
            minDistance={3}
            maxDistance={9}
            rotateSpeed={0.4}
            enableDamping
            dampingFactor={0.08}
          />
        </Canvas>
      )}

      {!hasData && isLoading && (
        <div className="absolute inset-0 flex items-center justify-center text-xs text-ink-muted">
          Loading threat map...
        </div>
      )}

      {hasData && (
        <div className="absolute bottom-3 right-3 z-10 text-[10px] text-ink-muted">
          {markers.length} of up to {MAX_RENDERED_MARKERS}+ rendered
        </div>
      )}

      <DetailPanel event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
