import { useEffect, useMemo, useRef } from "react";
import { InstancedMesh, Object3D } from "three";
import type { ThreeEvent } from "@react-three/fiber";
import { latLonToVector3 } from "./geo";
import { markerColorObject } from "./colorScale";
import { GLOBE_RADIUS, MARKER_RADIUS } from "./constants";
import type { ThreatEvent as ThreatEventType } from "../../types/threat";

interface MarkerLayerProps {
  events: ThreatEventType[];
  onHover: (event: ThreatEventType | null) => void;
  onSelect: (event: ThreatEventType) => void;
}

const dummy = new Object3D();

/**
 * The globe's primary content: one InstancedMesh draw call for every
 * geolocated threat, regardless of count (capped upstream by
 * useThreatMapData). Instancing is the performance safeguard here -- a
 * regular <mesh> per marker would mean hundreds of separate draw calls and
 * scene-graph nodes; this is one geometry/material pair with per-instance
 * transform + color, and no per-frame work at all (matrices are written
 * once when `events` changes, not in a render loop).
 */
export function MarkerLayer({ events, onHover, onSelect }: MarkerLayerProps) {
  const meshRef = useRef<InstancedMesh>(null);
  const geolocated = useMemo(
    () => events.filter((event) => event.lat != null && event.lon != null),
    [events],
  );

  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    geolocated.forEach((event, i) => {
      const position = latLonToVector3(event.lat as number, event.lon as number, GLOBE_RADIUS);
      dummy.position.copy(position);
      const scale = 0.9 + Math.min(event.confidence_score, 1) * 0.6;
      dummy.scale.setScalar(scale);
      dummy.lookAt(0, 0, 0);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
      mesh.setColorAt(i, markerColorObject(event));
    });
    mesh.count = geolocated.length;
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  }, [geolocated]);

  if (geolocated.length === 0) return null;

  return (
    <instancedMesh
      ref={meshRef}
      args={[undefined, undefined, geolocated.length]}
      onPointerOver={(event: ThreeEvent<PointerEvent>) => {
        event.stopPropagation();
        if (event.instanceId != null && geolocated[event.instanceId]) {
          document.body.style.cursor = "pointer";
          onHover(geolocated[event.instanceId]);
        }
      }}
      onPointerOut={(event: ThreeEvent<PointerEvent>) => {
        event.stopPropagation();
        document.body.style.cursor = "auto";
        onHover(null);
      }}
      onClick={(event: ThreeEvent<MouseEvent>) => {
        event.stopPropagation();
        if (event.instanceId != null && geolocated[event.instanceId]) {
          onSelect(geolocated[event.instanceId]);
        }
      }}
    >
      <sphereGeometry args={[MARKER_RADIUS, 8, 8]} />
      <meshBasicMaterial toneMapped={false} />
    </instancedMesh>
  );
}
