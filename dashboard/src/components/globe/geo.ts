import { Vector3 } from "three";

/**
 * Converts geographic coordinates to a position on a sphere of the given
 * radius, centered at the origin. Standard equirectangular-to-sphere
 * mapping shared by every layer that needs to place something on the
 * globe (markers, pulses, arcs).
 */
export function latLonToVector3(lat: number, lon: number, radius: number): Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}
