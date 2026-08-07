import { CanvasTexture, RepeatWrapping } from "three";

/**
 * Generates the globe's surface texture entirely in-code on an offscreen
 * canvas, rather than shipping/fetching a satellite-imagery texture file.
 * This keeps the globe asset bundled with the app (no runtime CDN request,
 * no binary image to source/license) and matches the SOC-dashboard "data
 * globe" aesthetic (dark sphere + lat/lon graticule) rather than a
 * photographic Earth. Called once and memoized by the caller -- this does
 * real canvas work and shouldn't run per-render.
 */
export function generateEarthTexture(): CanvasTexture {
  const width = 1024;
  const height = 512;
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("2D canvas context unavailable -- cannot generate globe texture");
  }

  // Ocean base: vertical gradient matching the dashboard's dark theme.
  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, "#0b3d55");
  gradient.addColorStop(0.5, "#0f1420");
  gradient.addColorStop(1, "#0b3d55");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, width, height);

  // Latitude/longitude graticule.
  ctx.strokeStyle = "rgba(56, 189, 248, 0.18)";
  ctx.lineWidth = 1;
  const lonStep = width / 24; // every 15 degrees
  for (let x = 0; x <= width; x += lonStep) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  const latStep = height / 12; // every 15 degrees
  for (let y = 0; y <= height; y += latStep) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  // Equator + prime meridian slightly brighter for orientation.
  ctx.strokeStyle = "rgba(56, 189, 248, 0.35)";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(0, height / 2);
  ctx.lineTo(width, height / 2);
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(width / 2, 0);
  ctx.lineTo(width / 2, height);
  ctx.stroke();

  // Sparse deterministic dot noise for surface texture, avoiding a flat fill.
  let seed = 42;
  const nextRandom = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return (seed % 10000) / 10000;
  };
  ctx.fillStyle = "rgba(148, 163, 184, 0.10)";
  for (let i = 0; i < 2200; i++) {
    const x = nextRandom() * width;
    const y = nextRandom() * height;
    ctx.fillRect(x, y, 1.2, 1.2);
  }

  const texture = new CanvasTexture(canvas);
  texture.wrapS = RepeatWrapping;
  texture.needsUpdate = true;
  return texture;
}
