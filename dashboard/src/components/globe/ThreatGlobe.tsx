import { useMemo, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { useThreatStore } from "../../store/threatStore";
import { MAX_RENDERED_MARKERS } from "./useThreatMapData";
import { useGlobeMarkers } from "./useGlobeMarkers";
import { sandboxEventToLiveThreatEvent } from "./sandboxMarkers";
import { GlobeBase } from "./GlobeBase";
import { EXTERNAL_MARKER_COLOR, SANDBOX_MARKER_COLOR } from "./colorScale";
import { MarkerLayer } from "./MarkerLayer";
import { LivePulseLayer } from "./LivePulseLayer";
import { ArcLayer } from "./ArcLayer";
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
  const sandboxCount = useMemo(() => markers.filter((m) => m.ioc_type === "sandbox").length, [markers]);
  // Rotation pauses while the pointer is over the globe so markers stay put and can be hovered and clicked.
  const [pointerInside, setPointerInside] = useState(false);
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
    <div
      className="relative h-[calc(100vh-20rem)] min-h-[560px] w-full overflow-hidden border border-line bg-white"
      onPointerEnter={() => setPointerInside(true)}
      onPointerLeave={() => setPointerInside(false)}
    >
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
          <OrbitControls
            enablePan={false}
            minDistance={3}
            maxDistance={10}
            rotateSpeed={0.4}
            enableDamping
            autoRotate={!pointerInside && !hovered && !selected}
            autoRotateSpeed={0.35}
            dampingFactor={0.08}
          />
        </Canvas>
      )}

      {!hasData && isLoading && (
        <div className="absolute inset-0 flex items-center justify-center text-sm text-ink-muted">
          Loading threat map...
        </div>
      )}

      {hasData && (
        <div className="absolute bottom-4 left-4 z-10 border border-line bg-white/95 px-4 py-3 text-sm text-ink-soft">
          <p className="mb-2 text-[13px] font-semibold uppercase tracking-wide text-ink-muted">Markers</p>
          <p className="flex items-center gap-2">
            <span className="h-2.5 w-2.5" style={{ backgroundColor: EXTERNAL_MARKER_COLOR }} aria-hidden />
            External threat indicators ({markers.length - sandboxCount})
          </p>
          <p className="mt-1 flex items-center gap-2">
            <span className="h-2.5 w-2.5" style={{ backgroundColor: SANDBOX_MARKER_COLOR }} aria-hidden />
            Attacks observed in the sandbox ({sandboxCount})
          </p>
          <p className="mt-2 text-[13px] text-ink-muted">
            GeoIP coordinates only. Showing up to {MAX_RENDERED_MARKERS}. Drag to rotate, scroll to zoom.
          </p>
        </div>
      )}

      <DetailPanel event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
