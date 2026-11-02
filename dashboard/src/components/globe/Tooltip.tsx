import { Html } from "@react-three/drei";
import { latLonToVector3 } from "./geo";
import { markerColor } from "./colorScale";
import { GLOBE_RADIUS } from "./constants";
import type { ThreatEvent } from "../../types/threat";

interface TooltipProps {
  event: ThreatEvent | null;
}

/**
 * Hover-only summary (country/ip/threat_type/confidence/source/timestamp)
 * rendered via drei's <Html>, which projects a 3D position into the DOM so
 * the tooltip tracks the globe as it rotates. Only mounted while something
 * is hovered -- no per-frame cost when idle.
 */
export function Tooltip({ event }: TooltipProps) {
  if (!event || event.lat == null || event.lon == null) return null;
  const position = latLonToVector3(event.lat, event.lon, GLOBE_RADIUS + 0.05);
  const color = markerColor(event);

  return (
    <Html position={position} center distanceFactor={6} zIndexRange={[100, 0]} pointerEvents="none">
      <div className="w-52 -translate-y-full  border border-line bg-white/95 p-2.5 text-xs  backdrop-blur">
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 " style={{ backgroundColor: color }} />
          <span className="font-medium text-ink">{event.ioc}</span>
        </div>
        <dl className="mt-1.5 space-y-0.5 text-ink-muted">
          <div className="flex justify-between gap-2">
            <dt>Country</dt>
            <dd className="text-ink-soft">{event.country ?? "Unknown"}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt>Type</dt>
            <dd className="text-ink-soft">{event.threat_type}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt>Confidence</dt>
            <dd className="text-ink-soft">{Math.round(event.confidence_score * 100)}%</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt>Source count</dt>
            <dd className="text-ink-soft">{event.source_count}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt>Last seen</dt>
            <dd className="text-ink-soft">{new Date(event.last_seen).toLocaleString()}</dd>
          </div>
        </dl>
      </div>
    </Html>
  );
}
