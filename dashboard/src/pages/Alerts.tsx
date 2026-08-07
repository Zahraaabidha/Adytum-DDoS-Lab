import { useMemo, useState } from "react";
import { Badge, Card, EmptyState } from "../components/ui";
import { humanLabel, severityFromConfidence, SEVERITY_LABEL, SEVERITY_TONE, type SeverityLevel } from "../components/feed/labels";
import { useThreatsLive } from "../lib/queries";
import { threatTypeColor } from "../components/globe/colorScale";

const SEVERITY_ORDER: SeverityLevel[] = ["critical", "high", "medium", "low"];

/**
 * Alerts page (Stage G) -- there is no dedicated "alerts" table/endpoint
 * in threat-intel; alerts here are high-confidence IOCs from
 * `/api/threats/live`, with severity derived from the real
 * `confidence_score` field (see `severityFromConfidence` in
 * `components/feed/labels.ts`) rather than a fabricated risk score.
 */
export function Alerts() {
  const { data, isLoading, isError } = useThreatsLive(200);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | "all">("all");

  const alerts = useMemo(() => {
    const rows = (data ?? []).map((event) => ({ event, severity: severityFromConfidence(event.confidence_score) }));
    rows.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
    return severityFilter === "all" ? rows : rows.filter((row) => row.severity === severityFilter);
  }, [data, severityFilter]);

  const counts = useMemo(() => {
    const base: Record<SeverityLevel, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const event of data ?? []) base[severityFromConfidence(event.confidence_score)]++;
    return base;
  }, [data]);

  if (isError) {
    return (
      <EmptyState
        title="Unable to load alerts"
        hint="threat-intel's /api/threats/live endpoint is unreachable. Check the service status and retry."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setSeverityFilter("all")}
          className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
            severityFilter === "all" ? "bg-accent/15 text-accent" : "bg-white/5 text-slate-400 hover:text-slate-200"
          }`}
        >
          All ({(data ?? []).length})
        </button>
        {SEVERITY_ORDER.map((level) => (
          <button
            key={level}
            onClick={() => setSeverityFilter(level)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
              severityFilter === level ? "bg-accent/15 text-accent" : "bg-white/5 text-slate-400 hover:text-slate-200"
            }`}
          >
            {SEVERITY_LABEL[level]} ({counts[level]})
          </button>
        ))}
      </div>

      {isLoading && <p className="text-xs text-slate-500">Loading...</p>}

      {!isLoading && alerts.length === 0 && (
        <EmptyState title="No alerts" hint="No IOCs match the selected severity yet." />
      )}

      <div className="flex flex-col gap-2">
        {alerts.map(({ event, severity }) => (
          <Card key={`${event.ioc}-${event.threat_type}`} className="border-l-4" style={{ borderLeftColor: threatTypeColor(event.threat_type) }}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-slate-100">{humanLabel(event)}</p>
                <p className="mt-0.5 truncate text-xs text-slate-400">
                  {event.ioc}
                  {event.country ? ` · ${event.country}` : ""} · {Math.round(event.confidence_score * 100)}% confidence
                </p>
              </div>
              <Badge tone={SEVERITY_TONE[severity]} className="shrink-0">
                {SEVERITY_LABEL[severity]}
              </Badge>
            </div>
            <p className="mt-2 text-[11px] text-slate-500">
              Last seen {new Date(event.last_seen).toLocaleString()} · {event.source_count} source
              {event.source_count === 1 ? "" : "s"}
            </p>
          </Card>
        ))}
      </div>
    </div>
  );
}
