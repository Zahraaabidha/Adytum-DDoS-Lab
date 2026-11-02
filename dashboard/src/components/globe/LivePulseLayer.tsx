import { useEffect, useRef, useState } from "react";
import { useFrame } from "@react-three/fiber";
import type { Mesh } from "three";
import { latLonToVector3 } from "./geo";
import { markerColor } from "./colorScale";
import { GLOBE_RADIUS, MAX_LIVE_PULSES, PULSE_LIFETIME_MS } from "./constants";
import type { LiveThreatEvent } from "../../types/threat";

interface Pulse {
  key: string;
  lat: number;
  lon: number;
  color: string;
  spawnedAt: number;
}

interface LivePulseLayerProps {
  liveEvents: LiveThreatEvent[];
}

/**
 * Stage G bug fix: this used to key on a `last_seen` field that never
 * exists on the real WS payload (see `LiveThreatEvent`'s doc comment in
 * types/threat.ts) -- every event for the same IOC collapsed to the same
 * `"${ioc}-undefined"` key, so a given IOC only ever pulsed once for the
 * lifetime of the page. `timestamp` is the field the payload actually has.
 */
function pulseKey(event: LiveThreatEvent): string {
  return `${event.ioc}-${event.timestamp}`;
}

/**
 * Animated arrival pulses for newly ingested threats streamed over
 * `/ws/threats` (Stage E's useThreatStream, already wired at the app-shell
 * level into useThreatStore.liveEvents). This is the "animated markers"
 * requirement's live half -- distinct from MarkerLayer's static instanced
 * dots, which represent the standing geographic distribution.
 *
 * Bounded by MAX_LIVE_PULSES so a burst of ingestion (e.g. a provider
 * dumping hundreds of IOCs at once) can't spawn unbounded animated
 * objects: oldest pulses are dropped first, and every pulse self-expires
 * after PULSE_LIFETIME_MS regardless.
 */
export function LivePulseLayer({ liveEvents }: LivePulseLayerProps) {
  const [pulses, setPulses] = useState<Pulse[]>([]);
  const seenKeys = useRef<Set<string>>(new Set());

  useEffect(() => {
    const newest = liveEvents[0];
    if (!newest || newest.lat == null || newest.lon == null) return;
    const key = pulseKey(newest);
    if (seenKeys.current.has(key)) return;
    seenKeys.current.add(key);

    setPulses((prev) => {
      const next: Pulse[] = [
        {
          key,
          lat: newest.lat as number,
          lon: newest.lon as number,
          color: markerColor(newest),
          spawnedAt: performance.now(),
        },
        ...prev,
      ].slice(0, MAX_LIVE_PULSES);
      return next;
    });

    const timer = setTimeout(() => {
      setPulses((prev) => prev.filter((pulse) => pulse.key !== key));
      seenKeys.current.delete(key);
    }, PULSE_LIFETIME_MS);
    return () => clearTimeout(timer);
    // Only re-run when the newest live event changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveEvents[0]]);

  if (pulses.length === 0) return null;

  return (
    <>
      {pulses.map((pulse) => (
        <PulseRing key={pulse.key} pulse={pulse} />
      ))}
    </>
  );
}

function PulseRing({ pulse }: { pulse: Pulse }) {
  const ringRef = useRef<Mesh>(null);
  const position = latLonToVector3(pulse.lat, pulse.lon, GLOBE_RADIUS + 0.002);

  useFrame(() => {
    const mesh = ringRef.current;
    if (!mesh) return;
    const age = (performance.now() - pulse.spawnedAt) / PULSE_LIFETIME_MS;
    const progress = Math.min(age, 1);
    const scale = 1 + progress * 6;
    mesh.scale.setScalar(scale);
    const material = mesh.material as import("three").MeshBasicMaterial;
    material.opacity = Math.max(0, 1 - progress) * 0.8;
  });

  return (
    <mesh ref={ringRef} position={position} lookAt={[0, 0, 0]}>
      <ringGeometry args={[0.012, 0.02, 24]} />
      <meshBasicMaterial color={pulse.color} transparent opacity={0.8} toneMapped={false} />
    </mesh>
  );
}
