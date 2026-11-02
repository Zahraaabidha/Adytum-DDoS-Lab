interface ShowMoreProps {
  shown: number;
  total: number;
  step: number;
  onChange: (shown: number) => void;
  initial: number;
}

/** "Show more / Show less" control for lists that start short instead of scrolling inside a box. */
export function ShowMore({ shown, total, step, initial, onChange }: ShowMoreProps) {
  if (total <= initial) return null;
  return (
    <div className="mt-3 flex items-center gap-4 text-sm">
      <span className="text-ink-muted">
        Showing {Math.min(shown, total)} of {total}
      </span>
      {shown < total && (
        <button className="font-medium text-accent hover:underline" onClick={() => onChange(Math.min(total, shown + step))}>
          Show {Math.min(step, total - shown)} more
        </button>
      )}
      {shown > initial && (
        <button className="font-medium text-ink-muted hover:underline" onClick={() => onChange(initial)}>
          Show less
        </button>
      )}
    </div>
  );
}
