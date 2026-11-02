import { useEffect, useMemo, useRef } from "react";
import { DoubleSide, InstancedMesh, Object3D } from "three";
import type { ThreeEvent } from "@react-three/fiber";
import { latLonToVector3 } from "./geo";
import { markerColorObject } from "./colorScale";
import { MARKER_BASE_RADIUS, MARKER_RADIUS } from "./constants";
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
  const haloRef = useRef<InstancedMesh>(null);
  const ringRef = useRef<InstancedMesh>(null);
  const geolocated = useMemo(
    () => events.filter((event) => event.lat != null && event.lon != null),
    [events],
  );

  useEffect(() => {
    const mesh = meshRef.current;
    const halo = haloRef.current;
    const ring = ringRef.current;
    if (!mesh) return;
    geolocated.forEach((event, i) => {
      const position = latLonToVector3(event.lat as number, event.lon as number, MARKER_BASE_RADIUS);
      dummy.position.copy(position);
      const scale = 0.85 + Math.min(event.confidence_score, 1) * 0.45;
      // Flattened along the radial axis: a low dome that sits on the surface.
      dummy.scale.set(scale, scale, scale * 0.45);
      dummy.lookAt(0, 0, 0);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
      mesh.setColorAt(i, markerColorObject(event));
      if (halo) {
        dummy.scale.set(scale, scale, scale * 0.45);
        dummy.updateMatrix();
        halo.setMatrixAt(i, dummy.matrix);
        halo.setColorAt(i, markerColorObject(event));
      }
      if (ring) {
        // White outline just above the surface so overlapping dots stay distinct.
        dummy.position.copy(latLonToVector3(event.lat as number, event.lon as number, MARKER_BASE_RADIUS + 0.004));
        dummy.updateMatrix();
        ring.setMatrixAt(i, dummy.matrix);
      }
    });
    mesh.count = geolocated.length;
    mesh.instanceMatrix.needsUpdate = true;
    // Raycasting uses the bounding sphere; it must be rebuilt from the real instance positions
    // or hover/click would test against the empty (all-at-origin) initial state.
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
    if (ring) {
      ring.count = geolocated.length;
      ring.instanceMatrix.needsUpdate = true;
    }
    if (halo) {
      halo.count = geolocated.length;
      halo.instanceMatrix.needsUpdate = true;
      // Raycasting uses the bounding sphere; rebuild it from the real instance positions.
      halo.computeBoundingSphere();
      if (halo.instanceColor) halo.instanceColor.needsUpdate = true;
    }
  }, [geolocated]);

  if (geolocated.length === 0) return null;

  return (
    <>
      {/* Translucent halo: also the (larger) hover/click target for each real marker. */}
      <instancedMesh
        ref={haloRef}
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
        <sphereGeometry args={[MARKER_RADIUS * 2.1, 12, 12]} />
        <meshBasicMaterial transparent opacity={0.16} depthWrite={false} toneMapped={false} />
      </instancedMesh>
      <instancedMesh ref={ringRef} args={[undefined, undefined, geolocated.length]} raycast={() => null}>
        <ringGeometry args={[MARKER_RADIUS * 0.95, MARKER_RADIUS * 1.45, 24]} />
        <meshBasicMaterial color="#ffffff" side={DoubleSide} toneMapped={false} />
      </instancedMesh>
      <instancedMesh ref={meshRef} args={[undefined, undefined, geolocated.length]} raycast={() => null}>
        <sphereGeometry args={[MARKER_RADIUS, 12, 12]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
    </>
  );
}
