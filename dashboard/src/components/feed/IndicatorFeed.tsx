import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Badge, EmptyState } from "../ui";
import { threatIntelApi } from "../../lib/api";
import { useProvidersStatus, useThreatsLive } from "../../lib/queries";
import { humanLabel } from "./labels";
import type { ThreatEvent } from "../../types/threat";

const PAGE_SIZE = 25;
/** `/api/threats/live` caps at 500 rows; the backend has no offset/pagination yet. */
const FEED_WINDOW = 500;
const UNATTRIBUTED = "Unattributed";

type SortKey = "newest" | "oldest" | "confidence";

const selectClass = "border border-line bg-white px-3 py-2 text-sm text-ink";

/**
 * Indicators carry no provider field. The `category` string begins with the
 * provider name for the feeds that set it (e.g. `abuseipdb_blacklist`), so
 * that prefix is used when it matches a known provider; anything else is
 * reported as Unattributed rather than guessed.
 */
function providerOf(event: ThreatEvent, providers: string[]): string {
  const category = (event.category ?? "").toLowerCase();
  return providers.find((name) => category.startsWith(name)) ?? UNATTRIBUTED;
}

interface Row {
  event: ThreatEvent;
  provider: string;
  key: string;
}

export function IndicatorFeed() {
  const { data, isLoading, isError } = useThreatsLive(FEED_WINDOW);
  const { data: providerStatus } = useProvidersStatus();
  const providerNames = useMemo(() => (providerStatus ?? []).map((p) => p.name), [providerStatus]);

  const [query, setQuery] = useState("");
  const [provider, setProvider] = useState("all");
  const [type, setType] = useState("all");
  const [country, setCountry] = useState("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [sort, setSort] = useState<SortKey>("newest");
  const [page, setPage] = useState(0);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const rows: Row[] = useMemo(
    () =>
      (data ?? []).map((event) => ({
        event,
        provider: providerOf(event, providerNames),
        key: `${event.ioc_type}|${event.ioc}|${event.threat_type}`,
      })),
    [data, providerNames],
  );

  const options = useMemo(() => {
    const uniq = (values: (string | null)[]) => [...new Set(values.filter((v): v is string => !!v))].sort();
    return {
      providers: uniq(rows.map((r) => r.provider)),
      types: uniq(rows.map((r) => r.event.ioc_type)),
      countries: uniq(rows.map((r) => r.event.country)),
    };
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const out = rows.filter(
      ({ event, provider: p }) =>
        (provider === "all" || p === provider) &&
        (type === "all" || event.ioc_type === type) &&
        (country === "all" || event.country === country) &&
        event.confidence_score >= minConfidence &&
        (!q ||
          [event.ioc, event.country, event.threat_type, event.attack_family, event.category, event.organization, event.asn]
            .filter((v) => v != null)
            .join(" ")
            .toLowerCase()
            .includes(q)),
    );
    out.sort((a, b) =>
      sort === "confidence"
        ? b.event.confidence_score - a.event.confidence_score
        : sort === "oldest"
          ? new Date(a.event.last_seen).getTime() - new Date(b.event.last_seen).getTime()
          : new Date(b.event.last_seen).getTime() - new Date(a.event.last_seen).getTime(),
    );
    return out;
  }, [rows, query, provider, type, country, minConfidence, sort]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pageCount - 1);
  const visible = filtered.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE);
  const selected = rows.find((r) => r.key === selectedKey) ?? null;

  const onFilter =
    <T,>(setter: (value: T) => void) =>
    (value: T) => {
      setter(value);
      setPage(0);
    };

  if (isError) {
    return <EmptyState title="Unable to load indicators" hint="threat-intel's /api/threats/live endpoint is unreachable." />;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          value={query}
          onChange={(e) => onFilter(setQuery)(e.target.value)}
          placeholder="Search IP, country, type, ASN, organisation"
          className="min-w-[220px] flex-1 border border-line bg-white px-3 py-2 text-base placeholder:text-ink-muted"
          aria-label="Search indicators"
        />
        <select className={selectClass} value={provider} onChange={(e) => onFilter(setProvider)(e.target.value)} aria-label="Provider">
          <option value="all">All providers</option>
          {options.providers.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <select className={selectClass} value={type} onChange={(e) => onFilter(setType)(e.target.value)} aria-label="Indicator type">
          <option value="all">All indicator types</option>
          {options.types.map((t) => (
            <option key={t} value={t}>
              {t.toUpperCase()}
            </option>
          ))}
        </select>
        <select className={selectClass} value={country} onChange={(e) => onFilter(setCountry)(e.target.value)} aria-label="Country">
          <option value="all">All countries</option>
          {options.countries.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          className={selectClass}
          value={minConfidence}
          onChange={(e) => onFilter(setMinConfidence)(Number(e.target.value))}
          aria-label="Minimum confidence"
        >
          {[0, 0.25, 0.5, 0.75, 0.9].map((v) => (
            <option key={v} value={v}>
              {v === 0 ? "Any confidence" : `Confidence ${Math.round(v * 100)}%+`}
            </option>
          ))}
        </select>
        <select className={selectClass} value={sort} onChange={(e) => setSort(e.target.value as SortKey)} aria-label="Sort">
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
          <option value="confidence">Highest confidence</option>
        </select>
      </div>

      <p className="text-sm text-ink-muted">
        Showing the {Math.min(FEED_WINDOW, rows.length)} most recently updated indicators. Providers are inferred from each
        indicator&apos;s category where it names one; the API does not return a provider field.
      </p>

      {isLoading && <p className="text-sm text-ink-muted">Loading...</p>}
      {!isLoading && filtered.length === 0 && <EmptyState title="No indicators match" hint="Adjust the search or filters." />}

      {filtered.length > 0 && (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_340px]">
          <div className="min-w-0">
            <div className="overflow-x-auto border border-line bg-white">
              <table className="w-full min-w-[640px] text-left text-base">
                <thead className="border-b border-line bg-white text-[13px] uppercase tracking-wide text-ink-muted">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">Indicator</th>
                    <th className="px-4 py-2.5 font-medium">Type</th>
                    <th className="px-4 py-2.5 font-medium">Country</th>
                    <th className="px-4 py-2.5 font-medium">Confidence</th>
                    <th className="px-4 py-2.5 font-medium">Provider</th>
                    <th className="px-4 py-2.5 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {visible.map(({ event, provider: p, key }) => (
                    <tr
                      key={key}
                      onClick={() => setSelectedKey(key)}
                      className={clsx("cursor-pointer transition-colors hover:bg-slate-50", key === selectedKey && "bg-teal-50")}
                    >
                      <td className="px-4 py-2.5 font-mono text-sm text-ink">
                        <button className="text-left hover:text-accent" onClick={() => setSelectedKey(key)}>
                          {event.ioc}
                        </button>
                      </td>
                      <td className="px-4 py-2.5 text-sm uppercase text-ink-soft">{event.ioc_type}</td>
                      <td className="px-4 py-2.5 text-sm text-ink-soft">{event.country ?? "Unknown"}</td>
                      <td className="px-4 py-2.5 text-sm text-ink-soft">{Math.round(event.confidence_score * 100)}%</td>
                      <td className="px-4 py-2.5 text-sm text-ink-soft">{p}</td>
                      <td className="whitespace-nowrap px-4 py-2.5 text-sm text-ink-muted">{new Date(event.last_seen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-3 flex items-center justify-between text-sm text-ink-muted">
              <span>
                {current * PAGE_SIZE + 1}-{Math.min((current + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-2">
                <button className="border border-line bg-white px-3 py-1.5 text-ink disabled:opacity-40" disabled={current === 0} onClick={() => setPage(current - 1)}>
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
          </div>

          <IndicatorDetail row={selected} />
        </div>
      )}
    </div>
  );
}

function IndicatorDetail({ row }: { row: Row | null }) {
  const event = row?.event;
  const isIp = event?.ioc_type === "ip";
  const { data: sightings, isLoading } = useQuery({
    queryKey: ["indicator-sightings", event?.ioc],
    enabled: !!event && isIp,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/search", { params: { query: { ip: event?.ioc, limit: 25 } } });
      if (error) throw error;
      return ((data as { results: ThreatEvent[] }).results ?? []) as ThreatEvent[];
    },
  });

  if (!row || !event) {
    return (
      <aside className="border border-dashed border-line bg-white p-5 text-base text-ink-muted lg:sticky lg:top-24 lg:self-start">
        Select an indicator to see its details.
      </aside>
    );
  }

  const fields: [string, string][] = [
    ["Type", event.ioc_type.toUpperCase()],
    ["Provider", row.provider],
    ["Category", event.category ?? "Not provided"],
    ["Threat type", event.threat_type],
    ["Attack family", event.attack_family ?? "Not provided"],
    ["Confidence", `${Math.round(event.confidence_score * 100)}%`],
    ["Reporting sources", String(event.source_count)],
    ["Country", event.country ?? "Unknown"],
    ["ASN", event.asn != null ? `AS${event.asn}` : "Unknown"],
    ["Organisation", event.organization ?? "Unknown"],
    ["Coordinates", event.lat != null && event.lon != null ? `${event.lat.toFixed(2)}, ${event.lon.toFixed(2)}` : "Not geolocated"],
    ["First seen", new Date(event.first_seen).toLocaleString()],
    ["Last seen", new Date(event.last_seen).toLocaleString()],
  ];

  return (
    <aside className="border border-line bg-white p-5 lg:sticky lg:top-24 lg:self-start">
      <Badge tone="neutral">{humanLabel(event)}</Badge>
      <p className="mt-3 break-all font-mono text-base font-semibold text-ink">{event.ioc}</p>
      <dl className="mt-4">
        {fields.map(([label, value]) => (
          <div key={label} className="flex justify-between gap-3 border-b border-line py-2 text-sm last:border-b-0">
            <dt className="shrink-0 text-ink-muted">{label}</dt>
            <dd className="min-w-0 break-words text-right text-ink">{value}</dd>
          </div>
        ))}
      </dl>
      {isIp && (
        <div className="mt-4">
          <p className="text-[13px] font-semibold uppercase tracking-wide text-ink-muted">Other records for this IP</p>
          {isLoading && <p className="mt-1 text-sm text-ink-muted">Loading...</p>}
          {!isLoading && (sightings?.length ?? 0) <= 1 && <p className="mt-1 text-sm text-ink-muted">No additional records.</p>}
          <ul className="mt-1 space-y-1 text-sm text-ink-soft">
            {(sightings ?? [])
              .filter((s) => s.threat_type !== event.threat_type)
              .map((s) => (
                <li key={`${s.threat_type}-${s.last_seen}`}>
                  {s.threat_type} · {new Date(s.last_seen).toLocaleDateString()}
                </li>
              ))}
          </ul>
        </div>
      )}
    </aside>
  );
}
