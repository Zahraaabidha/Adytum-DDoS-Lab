import { useState } from "react";

/** Client-side paging for a list; returns the visible slice plus controls. */
export function usePagination<T>(items: T[], pageSize: number) {
  const [page, setPage] = useState(0);
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(page, pageCount - 1);
  return { rows: items.slice(current * pageSize, (current + 1) * pageSize), current, pageCount, total: items.length, pageSize, setPage };
}
