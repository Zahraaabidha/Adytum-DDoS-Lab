import { Badge, Card, EmptyState, StatTile } from "../ui";
import type { BadgeTone } from "../ui/Badge";
import { useSuricataAlerts, useSuricataSummary } from "../../lib/defenseEngineApi";

const SEVERITY_TONE: Record<string, BadgeTone> = { high: "danger", medium: "warn", low: "neutral" };

/**
 * Suricata IDS alerts from `defense-engine`'s `/suricata/*` endpoints (EVE JSON read from the shared
 * volume). Advisory only: an alert never changes the rate limit. The "ML" column shows what the
 * classifier saw within 10 s of the alert (peak confidence, and the Prometheus-derived request rate).
 */
export function SuricataAlerts() {
  const { data: alerts, isLoading, isError } = useSuricataAlerts(100);
  const { data: summary } = useSuricataSummary();

  if (isError) {
    return <EmptyState title="Suricata alerts unavailable" hint="defense-engine:9300 did not respond." />;
  }

  const rows = alerts ?? [];

  return (
    <Card className="flex flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-1">
        <h3 className="text-xs font-medium text-ink-soft">
          <Badge tone="accent">SURICATA</Badge> IDS alerts
        </h3>
        <span className="text-[11px] text-ink-muted">advisory only: alerts never trigger mitigation</span>
      </div>

      {summary && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatTile label="Alerts ingested" value={summary.total_ingested} />
          <StatTile label={`Last ${Math.round(summary.window_seconds / 60)} min`} value={summary.recent_alerts} />
          <StatTile label="ML also flagged" value={summary.ml_flagged_alerts} />
          <StatTile label="ML did not flag" value={summary.ml_not_flagged_alerts} />
        </div>
      )}

      {summary && summary.signatures.length > 0 && (
        <p className="text-[11px] text-ink-muted">
          {summary.signatures.map((s) => `${s.signature.replace("SENTINEL LAB: ", "")} x${s.count}`).join(" | ")}
        </p>
      )}

      {isLoading && <p className="text-xs text-ink-muted">Loading...</p>}
      {!isLoading && rows.length === 0 && (
        <EmptyState
          title="No Suricata alerts yet"
          hint={
            summary && !summary.eve_file_present
              ? "eve.json not found: is the suricata service running?"
              : "Run an HTTP flood or Slowloris scenario to generate alerts."
          }
        />
      )}
      {rows.length > 0 && (
        <div className="max-h-72 overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-white text-ink-muted">
              <tr>
                <th className="py-1 pr-2 font-medium">Time</th>
                <th className="py-1 pr-2 font-medium">Severity</th>
                <th className="py-1 pr-2 font-medium">Signature</th>
                <th className="py-1 pr-2 font-medium">Source</th>
                <th className="py-1 pr-2 font-medium">Destination</th>
                <th className="py-1 pr-2 font-medium">Proto</th>
                <th className="py-1 pr-2 font-medium">Seen on</th>
                <th className="py-1 font-medium">ML (confidence, req/s)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((alert, i) => (
                <tr key={`${alert.ts}-${alert.signature_id}-${i}`} className="border-t border-line text-ink-soft">
                  <td className="py-1 pr-2 whitespace-nowrap">{new Date(alert.ts * 1000).toLocaleTimeString()}</td>
                  <td className="py-1 pr-2">
                    <Badge tone={SEVERITY_TONE[alert.severity_label] ?? "neutral"}>{alert.severity_label}</Badge>
                  </td>
                  <td className="py-1 pr-2">{alert.signature.replace("SENTINEL LAB: ", "")}</td>
                  <td className="py-1 pr-2 font-mono">{alert.src_ip}</td>
                  <td className="py-1 pr-2 font-mono">
                    {alert.dest_ip}
                    {alert.dest_port != null && `:${alert.dest_port}`}
                  </td>
                  <td className="py-1 pr-2">{alert.protocol}</td>
                  <td className="py-1 pr-2 whitespace-nowrap" title={alert.hop_alerts > 0 ? `${alert.hop_alerts} duplicate sighting(s) merged` : undefined}>
                    {alert.sensor} {alert.interfaces.join(" + ")}
                  </td>
                  <td className="py-1 whitespace-nowrap">
                    {!alert.ml.ml_available || alert.ml.confidence == null
                      ? "no sample"
                      : `${alert.ml.ml_flagged ? "flagged" : "not flagged"} (${(alert.ml.confidence * 100).toFixed(0)}%, ${(alert.ml.request_rate ?? 0).toFixed(1)})`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-[11px] text-ink-muted">
        Sensors: <span className="font-mono">ingress</span> watches the rate-limiter (HTTP flood);{" "}
        <span className="font-mono">web</span>, <span className="font-mono">udp</span> and{" "}
        <span className="font-mono">tcp</span> are passive taps inside one replica of each target (Slowloris, UDP flood, TCP
        exhaustion), so they see only a share of that traffic. The rate-limiter forwarding a request is merged into the
        client&apos;s alert (shown as two interfaces), not listed twice.
      </p>
    </Card>
  );
}
