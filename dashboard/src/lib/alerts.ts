import { useMemo } from "react";
import { useIncidents, useSuricataAlerts } from "./defenseEngineApi";
import { useThreatsLive } from "./queries";
import { humanLabel, type SeverityLevel } from "../components/feed/labels";
import type { Incident, SuricataAlert, ThreatEvent } from "../types/threat";

/**
 * The Alerts page merges three different things the backend reports. They
 * are kept distinct on purpose:
 *  - "alert"    : one Suricata IDS signature hit (individual detection)
 *  - "incident" : a correlated incident (Suricata + ML + metrics agree)
 *  - "anomaly"  : an incident the ML detector raised with no Suricata alert
 *  - "intel"    : a threat-intelligence indicator (no severity is published)
 */
export type AlertKind = "alert" | "incident" | "anomaly" | "intel";

export const KIND_LABEL: Record<AlertKind, string> = {
  alert: "Alert",
  incident: "Incident",
  anomaly: "ML anomaly",
  intel: "Threat intel",
};

export const KIND_HELP: Record<AlertKind, string> = {
  alert: "A single Suricata signature match.",
  incident: "Correlated from several detectors over a time window.",
  anomaly: "Flagged only by the Isolation Forest model; no Suricata alert and no known attack type.",
  intel: "An indicator reported by external threat feeds; the feeds do not publish a severity.",
};

export interface UnifiedAlert {
  id: string;
  kind: AlertKind;
  title: string;
  /** Epoch milliseconds. */
  time: number;
  severity: SeverityLevel;
  /** Where it came from, e.g. "Suricata / ingress". */
  source: string;
  ip: string | null;
  summary: string;
  suricata?: SuricataAlert;
  incident?: Incident;
  intel?: ThreatEvent;
}

const SEVERITY_RANK: Record<SeverityLevel, number> = { high: 0, medium: 1, low: 2, unclassified: 3 };
export const severityRank = (s: SeverityLevel) => SEVERITY_RANK[s];

function suricataToAlert(a: SuricataAlert): UnifiedAlert {
  const sev = a.severity_label;
  return {
    id: `alert-${a.flow_id ?? Math.round(a.ts * 1000)}-${a.signature_id ?? 0}`,
    kind: "alert",
    title: a.signature.replace("SENTINEL LAB: ", ""),
    time: a.ts * 1000,
    severity: sev === "high" || sev === "medium" || sev === "low" ? sev : "unclassified",
    source: `Suricata / ${a.sensor}`,
    ip: a.src_ip,
    summary: `${a.src_ip} to ${a.dest_ip}${a.dest_port != null ? `:${a.dest_port}` : ""} (${a.protocol})`,
    suricata: a,
  };
}

function incidentToAlert(i: Incident): UnifiedAlert {
  const mlOnly = i.assessment === "ml_only" || i.assessment === "ml_only_suricata_unavailable";
  const sev = i.severity;
  return {
    id: `incident-${i.id}`,
    kind: mlOnly ? "anomaly" : "incident",
    title: i.title,
    time: i.start * 1000,
    severity: sev === "high" || sev === "medium" || sev === "low" ? sev : "unclassified",
    source: mlOnly ? "Isolation Forest" : "Defense engine",
    ip: i.detectors.suricata.sources[0]?.ip ?? null,
    summary: i.evidence[0] ?? `${i.status} for ${i.duration_s.toFixed(0)} s`,
    incident: i,
  };
}

function intelToAlert(e: ThreatEvent): UnifiedAlert {
  return {
    id: `intel-${e.ioc_type}-${e.ioc}-${e.threat_type}`,
    kind: "intel",
    title: humanLabel(e),
    time: new Date(e.last_seen).getTime(),
    severity: "unclassified",
    source: `Threat feed / ${e.category ?? e.threat_type}`,
    ip: e.ioc_type === "ip" ? e.ioc : null,
    summary: `${e.ioc}${e.country ? ` · ${e.country}` : ""} · ${Math.round(e.confidence_score * 100)}% feed confidence`,
    intel: e,
  };
}

export function useUnifiedAlerts() {
  const suricata = useSuricataAlerts(200);
  const incidents = useIncidents(50);
  const intel = useThreatsLive(200);

  const alerts = useMemo(() => {
    const rows: UnifiedAlert[] = [
      ...(suricata.data ?? []).map(suricataToAlert),
      ...(incidents.data?.incidents ?? []).map(incidentToAlert),
      ...(intel.data ?? []).map(intelToAlert),
    ];
    return rows;
  }, [suricata.data, incidents.data, intel.data]);

  return {
    alerts,
    isLoading: suricata.isLoading || incidents.isLoading || intel.isLoading,
    failedSources: [
      suricata.isError && "Suricata alerts",
      incidents.isError && "Incidents",
      intel.isError && "Threat intelligence",
    ].filter(Boolean) as string[],
    allFailed: suricata.isError && incidents.isError && intel.isError,
  };
}

/** Incident whose time window covers an alert and that names its signature (time-window match only). */
export function relatedIncident(alert: UnifiedAlert, all: UnifiedAlert[]): Incident | null {
  if (!alert.suricata) return null;
  const s = alert.suricata;
  for (const row of all) {
    const i = row.incident;
    if (!i) continue;
    const inWindow = s.ts >= i.start - 10 && s.ts <= i.end + 10;
    if (inWindow && i.detectors.suricata.signatures.includes(s.signature)) return i;
  }
  return null;
}

export function isPrivateIp(ip: string): boolean {
  if (ip.includes(":")) return /^(fc|fd|fe80|::1)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}
