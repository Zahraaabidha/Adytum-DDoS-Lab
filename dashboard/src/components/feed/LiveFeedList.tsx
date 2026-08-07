import { EmptyState } from "../ui";
import { ThreatCard } from "./ThreatCard";
import type { ThreatEvent } from "../../types/threat";

interface LiveFeedListProps {
  events: ThreatEvent[];
  isLoading: boolean;
  isError: boolean;
  compact?: boolean;
  emptyHint?: string;
}

/**
 * Shared loading/empty/error/list rendering for any page that shows a
 * feed of `ThreatEvent`s (Overview's recent-alerts widget, the full
 * Threat Feed page). Never fabricates rows -- an empty or errored fetch
 * always renders `EmptyState`, matching Stage F's own precedent.
 */
export function LiveFeedList({ events, isLoading, isError, compact = false, emptyHint }: LiveFeedListProps) {
  if (isError) {
    return (
      <EmptyState
        title="Unable to load threats"
        hint="threat-intel's /api/threats endpoints are unreachable. Check the service status and retry."
      />
    );
  }

  if (isLoading) {
    return <p className="text-xs text-slate-500">Loading...</p>;
  }

  if (events.length === 0) {
    return <EmptyState title="No threats found" hint={emptyHint ?? "No IOCs match the current filters yet."} />;
  }

  return (
    <div className="flex flex-col gap-2">
      {events.map((event) => (
        <ThreatCard key={`${event.ioc}-${event.threat_type}`} event={event} compact={compact} />
      ))}
    </div>
  );
}
