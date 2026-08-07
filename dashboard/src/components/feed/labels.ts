import type { BadgeTone } from "../ui";

/**
 * category/attack_family/threat_type -> human-readable label, per the
 * Stage G roadmap entry in PROJECT_EXECUTION_PLAN.md ("New malicious IP
 * detected", "Botnet activity", "New C2 server"). Falls back to a
 * title-cased threat_type rather than a raw provider-specific string --
 * never invents a category that isn't present in the real data.
 */
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

export type SeverityLevel = "critical" | "high" | "medium" | "low";

/**
 * Confidence-derived severity bucket -- `confidence_score` is the only
 * real, non-fabricated signal `Ioc` carries for "how bad is this," so
 * severity is a direct, documented mapping of that field rather than an
 * invented metric. Thresholds chosen to split the observed 0-1 confidence
 * range into four roughly actionable bands; adjust here (one place) if
 * real ingested data shows this skews too high/low.
 */
export function severityFromConfidence(confidenceScore: number): SeverityLevel {
  if (confidenceScore >= 0.8) return "critical";
  if (confidenceScore >= 0.6) return "high";
  if (confidenceScore >= 0.4) return "medium";
  return "low";
}

export const SEVERITY_TONE: Record<SeverityLevel, BadgeTone> = {
  critical: "danger",
  high: "warn",
  medium: "accent",
  low: "neutral",
};

export const SEVERITY_LABEL: Record<SeverityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
