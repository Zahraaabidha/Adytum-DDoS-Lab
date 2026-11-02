import { Color } from "three";

/**
 * Deterministic threat_type -> color mapping. Known categories get a
 * hand-picked color that matches the dashboard's Tailwind palette
 * (tailwind.config.ts); anything unrecognized still gets a stable color
 * (hashed into the fallback palette) rather than a default gray, so a new
 * provider/threat_type value never silently blends into the background.
 */
const KNOWN_THREAT_COLORS: Record<string, string> = {
  malware: "#b42318", // danger
  botnet: "#b7791f", // warn
  c2: "#2b2f33",
  phishing: "#c2410c",
  spam: "#9aa0a6",
  scanning: "#2f7f7a", // accent
  exploit: "#5f6b73",
  vulnerable: "#b7791f",
  ddos: "#b42318",
};

const FALLBACK_PALETTE = ["#2f7f7a", "#2b2f33", "#8a949b", "#b7791f", "#5f6b73"];

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
