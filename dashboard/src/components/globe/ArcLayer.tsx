import { useMemo } from "react";
import { QuadraticBezierCurve3 } from "three";
import { Line } from "@react-three/drei";
import { latLonToVector3 } from "./geo";
import { threatTypeColor } from "./colorScale";
import { GLOBE_RADIUS } from "./constants";
import type { ThreatEvent } from "../../types/threat";

/**
 * Optional destination coordinates. `ThreatEvent` (types/threat.ts) mirrors
 * `_ioc_to_dict()` in routes_threats.py exactly and currently has no
 * destination field -- the Global Threat Intelligence schema records
 * where a threat was *observed*, not a source/destination pair. These
 * fields are declared here, additively and optionally, as the extension
 * point a future backend/schema change could populate; until then no
 * event will ever satisfy the guard below, which is intentional per the
 * "no hardcoded destination marker" requirement: an arc is only ever
 * drawn when real destination data exists on the event itself.
 */
interface ThreatEventWithDestination extends ThreatEvent {
  dest_lat?: number | null;
  dest_lon?: number | null;
}

interface ArcLayerProps {
  events: ThreatEvent[];
}

const MAX_ARCS = 200;

/**
 * Renders source -> destination arcs, but only for events that actually
 * carry destination coordinates. As of Stage F this is structurally never
 * true (see the comment above), so this layer renders nothing rather than
 * arcing every threat toward a fabricated fixed point -- the globe's
 * primary visualization is the geographic distribution of threats
 * (MarkerLayer/LivePulseLayer), not a fixed-destination attack map.
 */
export function ArcLayer({ events }: ArcLayerProps) {
  const arcs = useMemo(() => {
    const withDestination = events.filter(
      (event): event is ThreatEventWithDestination =>
        event.lat != null &&
        event.lon != null &&
        (event as ThreatEventWithDestination).dest_lat != null &&
        (event as ThreatEventWithDestination).dest_lon != null,
    );
    return withDestination.slice(0, MAX_ARCS).map((event) => {
      const start = latLonToVector3(event.lat as number, event.lon as number, GLOBE_RADIUS);
      const end = latLonToVector3(
        event.dest_lat as number,
        event.dest_lon as number,
        GLOBE_RADIUS,
      );
      const mid = start.clone().add(end).multiplyScalar(0.5);
      const liftFactor = 1 + start.distanceTo(end) / (GLOBE_RADIUS * 4);
      mid.multiplyScalar(liftFactor);
      const curve = new QuadraticBezierCurve3(start, mid, end);
      return {
        key: `${event.ioc}-${event.last_seen}`,
        points: curve.getPoints(32),
        color: threatTypeColor(event.threat_type),
      };
    });
  }, [events]);

  if (arcs.length === 0) return null;

  return (
    <>
      {arcs.map((arc) => (
        <Line key={arc.key} points={arc.points} color={arc.color} lineWidth={1} transparent opacity={0.5} />
      ))}
    </>
  );
}
