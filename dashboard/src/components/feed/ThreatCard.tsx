import { Badge, Card } from "../ui";
import { threatTypeColor } from "../globe/colorScale";
import { humanLabel } from "./labels";
import type { ThreatEvent } from "../../types/threat";

interface ThreatCardProps {
  event: ThreatEvent;
  compact?: boolean;
}

/**
 * One row of the live feed (Overview's "recent alerts" widget and the full
 * Threat Feed page both render lists of these) -- built on Stage E's
 * `Card`/`Badge` primitives, per requirement to reuse shared UI components.
 */
export function ThreatCard({ event, compact = false }: ThreatCardProps) {
  const color = threatTypeColor(event.threat_type);

  return (
    <Card className={compact ? "p-3" : undefined}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className="inline-block h-2 w-2 shrink-0 "
              style={{ backgroundColor: color }}
              aria-hidden
            />
            <p className="truncate text-sm font-medium text-ink">{humanLabel(event)}</p>
          </div>
          <p className="mt-0.5 truncate text-xs text-ink-muted">
            {event.ioc}
            {event.country ? ` · ${event.country}` : ""}
          </p>
        </div>
        <Badge tone="neutral" className="shrink-0">
          Unclassified
        </Badge>
      </div>

      {!compact && (
        <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-ink-muted sm:grid-cols-4">
          <div>
            <dt className="text-ink-muted">Type</dt>
            <dd className="text-ink-soft">{event.threat_type}</dd>
          </div>
          <div>
            <dt className="text-ink-muted">Confidence</dt>
            <dd className="text-ink-soft">{Math.round(event.confidence_score * 100)}%</dd>
          </div>
          <div>
            <dt className="text-ink-muted">Sources</dt>
            <dd className="text-ink-soft">{event.source_count}</dd>
          </div>
          <div>
            <dt className="text-ink-muted">Last seen</dt>
            <dd className="text-ink-soft">{new Date(event.last_seen).toLocaleString()}</dd>
          </div>
        </dl>
      )}
    </Card>
  );
}
