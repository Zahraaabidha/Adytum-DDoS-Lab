import { useEffect, useMemo, useState } from "react";
import { Color } from "three";
import ThreeGlobe from "three-globe";
import { GLOBE_RADIUS } from "./constants";

// three-globe's native radius; scaled down so it matches GLOBE_RADIUS, which
// every marker/pulse/arc layer positions against via latLonToVector3.
const THREE_GLOBE_RADIUS = 100;

interface CountryCollection {
  features: object[];
}

/**
 * Light, elegant hex-dot Earth built on three-globe (the same engine the
 * Aceternity 3D Globe component wraps). Only the base sphere lives here --
 * threat markers, pulses and arcs remain separate layers fed exclusively by
 * real GeoIP/sandbox coordinates, so this component never plots anything.
 * Country outlines load from /countries.geojson (bundled in /public); if the
 * fetch fails the plain sphere + atmosphere still render.
 */
export function GlobeBase() {
  const [countries, setCountries] = useState<object[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/countries.geojson")
      .then((response) => (response.ok ? (response.json() as Promise<CountryCollection>) : null))
      .then((data) => {
        if (!cancelled && data) setCountries(data.features);
      })
      .catch(() => {
        /* decorative only -- sphere renders without land hexes */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const globe = useMemo(() => {
    const instance = new ThreeGlobe({ animateIn: false })
      .showAtmosphere(true)
      .atmosphereColor("#5fa8a2")
      .atmosphereAltitude(0.24);
    const material = instance.globeMaterial() as unknown as {
      color: Color;
      emissive: Color;
      emissiveIntensity: number;
      shininess: number;
    };
    material.color = new Color("#e6edee");
    material.emissive = new Color("#dfe8e9");
    material.emissiveIntensity = 0.6;
    material.shininess = 0.4;
    instance.scale.setScalar(GLOBE_RADIUS / THREE_GLOBE_RADIUS);
    // Align three-globe's longitude origin (+z) with latLonToVector3's (+x).
    instance.rotation.y = Math.PI / 2;
    return instance;
  }, []);

  useEffect(() => {
    if (!countries) return;
    globe
      .polygonsTransitionDuration(0)
      .polygonsData(countries)
      .polygonCapColor(() => "rgba(120, 160, 156, 0.55)")
      .polygonSideColor(() => "rgba(0, 0, 0, 0)")
      .polygonStrokeColor(() => "#f7fafa")
      .polygonAltitude(0.012);
  }, [globe, countries]);

  useEffect(
    () => () => {
      globe.clear?.();
    },
    [globe],
  );

  return <primitive object={globe} />;
}
