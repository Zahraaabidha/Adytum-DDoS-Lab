import { Color } from "three";

/**
 * Deterministic threat_type -> color mapping. Known categories get a
 * hand-picked color that matches the dashboard's Tailwind palette
 * (tailwind.config.ts); anything unrecognized still gets a stable color
 * (hashed into the fallback palette) rather than a default gray, so a new
 * provider/threat_type value never silently blends into the background.
 */
const KNOWN_THREAT_COLORS: Record<string, string> = {
  malware: "#f87171", // danger
  botnet: "#facc15", // warn
  c2: "#c084fc",
  phishing: "#fb923c",
  spam: "#a3a3a3",
  scanning: "#38bdf8", // accent
  exploit: "#f472b6",
  vulnerable: "#facc15",
  ddos: "#f87171",
};

const FALLBACK_PALETTE = ["#4ade80", "#38bdf8", "#c084fc", "#fb923c", "#facc15"];

function hashString(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash << 5) - hash + value.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

export function threatTypeColor(threatType: string): string {
  const normalized = threatType.toLowerCase();
  if (KNOWN_THREAT_COLORS[normalized]) return KNOWN_THREAT_COLORS[normalized];
  return FALLBACK_PALETTE[hashString(normalized) % FALLBACK_PALETTE.length];
}

const colorCache = new Map<string, Color>();

/** Same mapping as `threatTypeColor`, cached as a reusable THREE.Color instance. */
export function threatTypeColorObject(threatType: string): Color {
  const key = threatType.toLowerCase();
  let color = colorCache.get(key);
  if (!color) {
    color = new Color(threatTypeColor(threatType));
    colorCache.set(key, color);
  }
  return color;
}
