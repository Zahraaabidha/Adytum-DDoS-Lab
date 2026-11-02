interface PaginationProps {
  current: number;
  pageCount: number;
  total: number;
  pageSize: number;
  onPage: (page: number) => void;
}

export function Pagination({ current, pageCount, total, pageSize, onPage }: PaginationProps) {
  if (total <= pageSize) return null;
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-ink-muted">
      <span>
        {current * pageSize + 1}-{Math.min((current + 1) * pageSize, total)} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button className="border border-line bg-white px-3 py-1.5 text-ink disabled:opacity-40" disabled={current === 0} onClick={() => onPage(current - 1)}>
          Previous
        </button>
        <span>
          Page {current + 1} / {pageCount}
        </span>
        <button className="border border-line bg-white px-3 py-1.5 text-ink disabled:opacity-40" disabled={current >= pageCount - 1} onClick={() => onPage(current + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
