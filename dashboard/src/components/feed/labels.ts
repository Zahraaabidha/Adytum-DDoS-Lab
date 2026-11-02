import type { BadgeTone } from "../ui";


const CATEGORY_LABELS: Record<string, string> = {
  botnet: "Botnet activity",
  c2: "New C2 server",
  malware: "Malware indicator",
  phishing: "Phishing indicator",
  spam: "Spam source",
  scanning: "Scanning activity",
  exploit: "Exploit activity",
  vulnerable: "Vulnerable host reported",
  ddos: "DDoS-related indicator",
};

function titleCase(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((word) => word[0]!.toUpperCase() + word.slice(1))
    .join(" ");
}

export function humanLabel(event: { category: string | null; attack_family: string | null; threat_type: string }): string {
  const key = (event.category ?? event.attack_family ?? event.threat_type).toLowerCase();
  if (CATEGORY_LABELS[key]) return CATEGORY_LABELS[key];
  return `New ${titleCase(event.threat_type)} indicator`;
}

export type SeverityLevel = "high" | "medium" | "low" | "unclassified";

/**
 * Severity is only ever taken from a source that actually states one
 * (Suricata's rule priority, the defense-engine incident rule). Threat-intel
 * indicators carry no severity field -- `confidence_score` measures how sure
 * the feeds are that an indicator is malicious, not how severe it is -- so
 * those are Unclassified rather than being bucketed from confidence.
 */
export const SEVERITY_TONE: Record<SeverityLevel, BadgeTone> = {
  high: "danger",
  medium: "warn",
  low: "neutral",
  unclassified: "neutral",
};

export const SEVERITY_LABEL: Record<SeverityLevel, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  unclassified: "Unclassified",
};
