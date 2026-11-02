import { Card } from "./Card";

interface StatTileProps {
  label: string;
  value: string | number;
  hint?: string;
}

/**
 * Shared KPI tile -- Overview/Analytics pages compose several of these
 * rather than each hand-rolling stat markup.
 */
export function StatTile({ label, value, hint }: StatTileProps) {
  return (
    <Card className="relative flex flex-col gap-1 overflow-hidden">
      <span className="absolute inset-x-0 top-0 h-0.5 bg-accent" />
      <span className="text-xs font-medium uppercase tracking-wide text-ink-muted">{label}</span>
      <span className="truncate text-2xl font-semibold text-ink">{value}</span>
      {hint && <span className="text-xs text-ink-muted">{hint}</span>}
    </Card>
  );
}
