import { Card } from "./Card";

interface StatTileProps {
  label: string;
  value: string | number;
  hint?: string;
}

/**
 * Shared KPI tile -- Overview/Analytics pages (Stage G) compose several
 * of these rather than each hand-rolling stat markup.
 */
export function StatTile({ label, value, hint }: StatTileProps) {
  return (
    <Card className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
      <span className="text-2xl font-semibold text-slate-100">{value}</span>
      {hint && <span className="text-xs text-slate-500">{hint}</span>}
    </Card>
  );
}
