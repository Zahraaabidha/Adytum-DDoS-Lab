import { AnimatePresence, motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { threatIntelApi } from "../../lib/api";
import { Badge, Card } from "../ui";
import { threatTypeColor } from "./colorScale";
import type { ThreatEvent } from "../../types/threat";

interface DetailPanelProps {
  event: ThreatEvent | null;
  onClose: () => void;
}

interface ThreatSearchResponse {
  results: ThreatEvent[];
}

/**
 * Click-to-open slide-in panel calling `/api/threats/search?ip=` for the
 * selected marker, per Stage F's spec. Rendered as a normal DOM overlay
 * (outside the Canvas) so it composes with the rest of the dashboard's
 * Tailwind/framer-motion conventions rather than living inside WebGL.
 */
export function DetailPanel({ event, onClose }: DetailPanelProps) {
  const enabled = event?.ioc_type === "ip" && !!event.ioc;
  const { data, isLoading } = useQuery({
    queryKey: ["threat-search", event?.ioc],
    enabled,
    queryFn: async () => {
      const { data, error } = await threatIntelApi.GET("/api/threats/search", {
        params: { query: { ip: event?.ioc, limit: 25 } },
      });
      if (error) throw error;
      return ((data as ThreatSearchResponse).results ?? []) as ThreatEvent[];
    },
  });

  return (
    <AnimatePresence>
      {event && (
        <motion.div
          initial={{ x: 360, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 360, opacity: 0 }}
          transition={{ type: "tween", duration: 0.2 }}
          className="absolute right-4 top-4 bottom-4 z-10 w-80 overflow-y-auto"
        >
          <Card className="h-full">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-sm font-semibold text-slate-100">{event.ioc}</p>
                <Badge className="mt-1" style={{ backgroundColor: `${threatTypeColor(event.threat_type)}26`, color: threatTypeColor(event.threat_type) }}>
                  {event.threat_type}
                </Badge>
              </div>
              <button
                onClick={onClose}
                className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-white/5 hover:text-slate-200"
                aria-label="Close detail panel"
              >
                Close
              </button>
            </div>

            <dl className="mt-4 space-y-2 text-xs">
              <Row label="Country" value={event.country ?? "Unknown"} />
              <Row label="ASN" value={event.asn != null ? String(event.asn) : "Unknown"} />
              <Row label="Organization" value={event.organization ?? "Unknown"} />
              <Row label="Category" value={event.category ?? "Unclassified"} />
              <Row label="Confidence" value={`${Math.round(event.confidence_score * 100)}%`} />
              <Row label="Source count" value={String(event.source_count)} />
              <Row label="First seen" value={new Date(event.first_seen).toLocaleString()} />
              <Row label="Last seen" value={new Date(event.last_seen).toLocaleString()} />
            </dl>

            <div className="mt-4 border-t border-white/10 pt-3">
              <p className="text-xs font-medium text-slate-300">Related sightings</p>
              {!enabled && (
                <p className="mt-1 text-xs text-slate-500">Search is only available for IP indicators.</p>
              )}
              {enabled && isLoading && <p className="mt-1 text-xs text-slate-500">Loading...</p>}
              {enabled && !isLoading && (data?.length ?? 0) === 0 && (
                <p className="mt-1 text-xs text-slate-500">No additional sightings found.</p>
              )}
              {enabled && (data?.length ?? 0) > 0 && (
                <ul className="mt-1 space-y-1.5">
                  {data!.map((result) => (
                    <li key={`${result.ioc}-${result.threat_type}-${result.last_seen}`} className="text-xs text-slate-400">
                      <span className="text-slate-200">{result.threat_type}</span>
                      {" · "}
                      {new Date(result.last_seen).toLocaleDateString()}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-right text-slate-300">{value}</dd>
    </div>
  );
}
