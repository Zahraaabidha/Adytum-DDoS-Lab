import { Badge, Card, EmptyState } from "../ui";
import type { BadgeTone } from "../ui/Badge";
import { useIncidents } from "../../lib/defenseEngineApi";
import type { Incident } from "../../types/threat";

const SEVERITY_TONE: Record<Incident["severity"], BadgeTone> = { high: "danger", medium: "warn", low: "neutral" };

const ASSESSMENT_LABEL: Record<string, string> = {
  corroborated: "Suricata and ML agree",
  suricata_only: "Suricata only: ML did not flag",
  suricata_ml_unavailable: "Suricata only: no ML data",
  ml_only: "ML only: no Suricata alert",
  ml_only_suricata_unavailable: "ML only: no Suricata data",
};

const STATE_TONE: Record<string, BadgeTone> = {
  flagged: "danger",
  elevated: "warn",
  not_flagged: "ok",
  not_elevated: "ok",
  no_data: "neutral",
  no_baseline: "neutral",
  not_applicable: "neutral",
};

function StateChip({ label, state }: { label: string; state: string }) {
  return (
    <Badge tone={STATE_TONE[state] ?? "neutral"}>
      {label}: {state.replace(/_/g, " ")}
    </Badge>
  );
}

function IncidentRow({ incident }: { incident: Incident }) {
  const { suricata, ml } = incident.detectors;
  const mitigation = incident.mitigation;
  return (
    <div className="flex flex-col gap-2  border border-line p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={SEVERITY_TONE[incident.severity]}>{incident.severity}</Badge>
        <span className="text-sm font-medium text-ink">{incident.title}</span>
        <Badge tone={incident.status === "active" ? "warn" : "neutral"}>{incident.status}</Badge>
        {incident.source === "stored" && <Badge tone="neutral">stored</Badge>}
        <span className="text-[11px] text-ink-muted">
          {new Date(incident.start * 1000).toLocaleTimeString()} - {new Date(incident.end * 1000).toLocaleTimeString()} (
          {incident.duration_s}s)
        </span>
      </div>
      <p className="text-xs text-ink-soft">{ASSESSMENT_LABEL[incident.assessment] ?? incident.assessment}</p>
      <div className="flex flex-wrap gap-1">
        <StateChip label="Suricata" state={suricata.state} />
        <StateChip label="Isolation Forest" state={ml.state} />
        <StateChip label="Metric" state={incident.metrics.state} />
      </div>
      <p className="text-[11px] text-ink-muted">
        Mitigation:{" "}
        {mitigation.applicable === false
          ? "not applicable (the rate limiter protects HTTP only)"
          : mitigation.applicable === null
            ? "unknown attack type"
            : mitigation.cap_lowered === null
              ? "no engine samples in this period"
              : mitigation.cap_lowered
                ? `rate limit lowered to ${mitigation.min_cap_rps?.toFixed(0)} req/s (baseline ${mitigation.baseline_cap_rps.toFixed(0)})`
                : "rate limit not lowered"}
        {mitigation.cap_lowered && mitigation.lowered_before_start && " (already lowered before this incident began, likely left over from an earlier one)"}
        {mitigation.states_seen.length > 0 && ` · policy state: ${mitigation.states_seen.join(", ")}`}
      </p>
      <details className="text-[11px] text-ink-muted">
        <summary className="cursor-pointer text-ink-soft">Evidence and caveats</summary>
        <ul className="mt-1 list-disc pl-5">
          {incident.evidence.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <ul className="mt-1 list-disc pl-5 text-ink-muted">
          {incident.caveats.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

/**
 * Unified incidents from `defense-engine`'s `/incidents`: Suricata alerts, Isolation Forest detections and the
 * type-specific Prometheus metric combined, with which sources agreed and the existing mitigation status. The raw
 * Suricata table and the mitigation log below stay as the detail views; this card does not repeat them.
 */
export function IncidentList() {
  const { data, isLoading, isError } = useIncidents(10);

  if (isError) {
    return <EmptyState title="Incidents unavailable" hint="defense-engine:9300 did not respond." />;
  }
  const incidents = data?.incidents ?? [];

  return (
    <Card className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-1">
        <h3 className="text-xs font-medium text-ink-soft">
          <Badge tone="accent">INCIDENTS</Badge> Unified detection
        </h3>
        <span className="text-[11px] text-ink-muted">advisory only: a Suricata alert never triggers mitigation</span>
      </div>
      {isLoading && <p className="text-xs text-ink-muted">Loading...</p>}
      {!isLoading && incidents.length === 0 && (
        <EmptyState title="No incidents" hint="Run an attack scenario: Suricata alerts and ML detections are grouped here." />
      )}
      {data && !data.inputs.persistence.enabled && (
        <p className="text-xs text-amber-600">
          Persistence is off ({data.inputs.persistence.error ?? "state store not opened"}): incidents and detector history
          will be lost when the engine restarts.
        </p>
      )}
      {data && !data.inputs.ml_model_loaded && (
        <p className="text-xs text-red-600">No model loaded: ML detections are unavailable, not calm.</p>
      )}
      <div className="flex max-h-[32rem] flex-col gap-2 overflow-y-auto">
        {incidents.map((incident) => (
          <IncidentRow key={incident.id} incident={incident} />
        ))}
      </div>
      <p className="text-[11px] text-ink-muted">
        Signals are matched by attack type and a +/-20 s time window, not by flow, so agreement means they coincided, not
        that one proves the other. The Isolation Forest scores anomaly, not attack type, and needs 3 consecutive flagged
        polls to count. A missing signal is shown as &quot;no data&quot;, never as calm.
        {data?.inputs.persistence.enabled &&
          ` Finished incidents are stored (${data.inputs.persistence.incidents ?? 0} kept, ${data.inputs.persistence.polls ?? 0} detector polls) and survive an engine restart; the gap while the engine was down stays no data.`}
      </p>
    </Card>
  );
}
