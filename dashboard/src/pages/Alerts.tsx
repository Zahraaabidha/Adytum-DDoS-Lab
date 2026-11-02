import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import clsx from "clsx";
import { Badge, EmptyState } from "../components/ui";
import { SEVERITY_LABEL, SEVERITY_TONE, type SeverityLevel } from "../components/feed/labels";
import {
  KIND_HELP,
  KIND_LABEL,
  severityRank,
  useUnifiedAlerts,
  type AlertKind,
  type UnifiedAlert,
} from "../lib/alerts";

const PAGE_SIZE = 25;
const SEVERITIES: SeverityLevel[] = ["high", "medium", "low", "unclassified"];
const KINDS: AlertKind[] = ["alert", "incident", "anomaly", "intel"];
type SortKey = "newest" | "oldest" | "severity";

const selectClass = "border border-line bg-white px-3 py-2 text-xs text-ink";

export function Alerts() {
  const { alerts, isLoading, failedSources, allFailed } = useUnifiedAlerts();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<SeverityLevel | "all">("all");
  const [kind, setKind] = useState<AlertKind | "all">("all");
  const [source, setSource] = useState("all");
  const [sort, setSort] = useState<SortKey>("newest");
  const [page, setPage] = useState(0);

  const sources = useMemo(() => [...new Set(alerts.map((a) => a.source))].sort(), [alerts]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = alerts.filter(
      (a) =>
        (severity === "all" || a.severity === severity) &&
        (kind === "all" || a.kind === kind) &&
        (source === "all" || a.source === source) &&
        (!q || `${a.title} ${a.summary} ${a.source} ${a.ip ?? ""} ${a.id}`.toLowerCase().includes(q)),
    );
    rows.sort((a, b) =>
      sort === "oldest"
        ? a.time - b.time
        : sort === "severity"
          ? severityRank(a.severity) - severityRank(b.severity) || b.time - a.time
          : b.time - a.time,
    );
    return rows;
  }, [alerts, query, severity, kind, source, sort]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pageCount - 1);
  const rows = filtered.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE);

  const counts = useMemo(() => {
    const c: Record<AlertKind, number> = { alert: 0, incident: 0, anomaly: 0, intel: 0 };
    for (const a of alerts) c[a.kind]++;
    return c;
  }, [alerts]);

  // Any filter change returns to the first page.
  const onFilter = <T,>(setter: (value: T) => void) => (value: T) => {
    setter(value);
    setPage(0);
  };

  if (allFailed) {
    return (
      <EmptyState
        title="Unable to load alerts"
        hint="Neither defense-engine nor threat-intel responded. Check the service status in Settings and retry."
      />
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-px border border-line bg-line md:grid-cols-4">
        {KINDS.map((k) => (
          <button
            key={k}
            onClick={() => onFilter(setKind)(kind === k ? "all" : k)}
            className={clsx(
              "border-b-2 bg-white p-4 text-left transition-colors hover:bg-slate-50",
              kind === k ? "border-accent" : "border-transparent",
            )}
            title={KIND_HELP[k]}
          >
            <span className="block text-[11px] font-medium uppercase tracking-wide text-ink-muted">{KIND_LABEL[k]}</span>
            <span className="mt-1 block text-2xl font-semibold text-ink">{counts[k]}</span>
            <span className="mt-1 block text-[11px] leading-snug text-ink-muted">{KIND_HELP[k]}</span>
          </button>
        ))}
      </div>

      {failedSources.length > 0 && (
        <p className="border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          Some sources did not respond and are missing from this list: {failedSources.join(", ")}.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          value={query}
          onChange={(e) => onFilter(setQuery)(e.target.value)}
          placeholder="Search title, IP, signature, source"
          className="min-w-[220px] flex-1 border border-line bg-white px-3 py-2 text-sm placeholder:text-ink-muted"
          aria-label="Search alerts"
        />
        <select
          className={selectClass}
          value={severity}
          onChange={(e) => onFilter(setSeverity)(e.target.value as SeverityLevel | "all")}
          aria-label="Severity"
        >
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={kind}
          onChange={(e) => onFilter(setKind)(e.target.value as AlertKind | "all")}
          aria-label="Type"
        >
          <option value="all">All types</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <select className={selectClass} value={source} onChange={(e) => onFilter(setSource)(e.target.value)} aria-label="Source">
          <option value="all">All sources</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select className={selectClass} value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label="Sort">
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
          <option value="severity">Severity</option>
        </select>
      </div>

      {isLoading && <p className="text-xs text-ink-muted">Loading...</p>}
      {!isLoading && filtered.length === 0 && (
        <EmptyState title="No alerts match" hint="Adjust the search or filters. Severity is only shown when the source reports one." />
      )}

      {filtered.length > 0 && (
        <div className="overflow-x-auto border border-line bg-white">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-line bg-slate-50 text-[11px] uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="px-4 py-2.5 font-medium">Time</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Severity</th>
                <th className="px-4 py-2.5 font-medium">Alert</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((a) => (
                <AlertRow key={a.id} alert={a} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > 0 && (
        <div className="flex items-center justify-between text-xs text-ink-muted">
          <span>
            {current * PAGE_SIZE + 1}-{Math.min((current + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
          </span>
          <div className="flex items-center gap-2">
            <button
              className="border border-line bg-white px-3 py-1.5 text-ink disabled:opacity-40"
              disabled={current === 0}
              onClick={() => setPage(current - 1)}
            >
              Previous
            </button>
            <span>
              Page {current + 1} / {pageCount}
            </span>
            <button
              className="border border-line bg-white px-3 py-1.5 text-ink disabled:opacity-40"
              disabled={current >= pageCount - 1}
              onClick={() => setPage(current + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert }: { alert: UnifiedAlert }) {
  const to = `/alerts/${encodeURIComponent(alert.id)}`;
  return (
    <tr className="align-top transition-colors hover:bg-slate-50">
      <td className="whitespace-nowrap px-4 py-3 text-xs text-ink-muted">{new Date(alert.time).toLocaleString()}</td>
      <td className="px-4 py-3">
        <Badge tone={alert.kind === "intel" ? "neutral" : "accent"}>{KIND_LABEL[alert.kind]}</Badge>
      </td>
      <td className="px-4 py-3">
        <Badge tone={SEVERITY_TONE[alert.severity]}>{SEVERITY_LABEL[alert.severity]}</Badge>
      </td>
      <td className="px-4 py-3">
        <Link to={to} className="font-medium text-ink hover:text-accent hover:underline">
          {alert.title}
        </Link>
        <p className="mt-0.5 text-xs text-ink-muted">{alert.summary}</p>
      </td>
      <td className="px-4 py-3 text-xs text-ink-soft">{alert.source}</td>
    </tr>
  );
}
