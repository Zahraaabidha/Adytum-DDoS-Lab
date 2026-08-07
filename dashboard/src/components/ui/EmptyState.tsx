interface EmptyStateProps {
  title: string;
  hint?: string;
}

/**
 * Used by every placeholder page in Stage E, and later by any page whose
 * data source is disabled/unavailable (e.g. Settings showing GeoIP
 * unavailable, per Stage G's verification requirement that such states
 * stay visible rather than silently absent).
 */
export function EmptyState({ title, hint }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 rounded-xl border border-dashed border-white/10 p-12 text-center">
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  );
}
