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
    <div className="flex flex-col items-center justify-center gap-1  border border-dashed border-line bg-white p-12 text-center">
      <p className="text-base font-medium text-ink-soft">{title}</p>
      {hint && <p className="text-sm text-ink-muted">{hint}</p>}
    </div>
  );
}
