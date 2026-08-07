import { Badge, Card, EmptyState } from "../components/ui";
import { useGeoipStatus, useProvidersStatus, useThreatIntelHealth } from "../lib/queries";
import { useDefenseEngineHealth } from "../lib/defenseEngineApi";
import { useThreatStore } from "../store/threatStore";

const WS_TONE: Record<string, "ok" | "warn" | "danger"> = {
  open: "ok",
  connecting: "warn",
  closed: "danger",
};

/**
 * Operational status page (Stage G) -- every section here reads a real
 * transparency endpoint the backend already exposes; nothing is inferred
 * or invented. Disabled/unavailable states are shown explicitly (per this
 * stage's own verification requirement) rather than silently omitted.
 */
export function Settings() {
  const { data: providers, isLoading: providersLoading, isError: providersError } = useProvidersStatus();
  const { data: geoip, isLoading: geoipLoading, isError: geoipError } = useGeoipStatus();
  const { data: threatIntelHealth, isError: threatIntelHealthError } = useThreatIntelHealth();
  const { data: defenseHealth, isError: defenseHealthError } = useDefenseEngineHealth();
  const connectionStatus = useThreatStore((state) => state.connectionStatus);

  return (
    <div className="flex flex-col gap-6">
      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Service health</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">threat-intel</span>
              <Badge tone={threatIntelHealthError ? "danger" : "ok"}>
                {threatIntelHealthError ? "Unreachable" : "Healthy"}
              </Badge>
            </div>
            {threatIntelHealth && (
              <pre className="mt-2 overflow-x-auto text-[10px] text-slate-500">
                {JSON.stringify(threatIntelHealth, null, 2)}
              </pre>
            )}
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">defense-engine</span>
              <Badge tone={defenseHealthError ? "danger" : "ok"}>
                {defenseHealthError ? "Unreachable" : "Healthy"}
              </Badge>
            </div>
            {defenseHealth && (
              <pre className="mt-2 overflow-x-auto text-[10px] text-slate-500">
                {JSON.stringify(defenseHealth, null, 2)}
              </pre>
            )}
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">Live WebSocket (/ws/threats)</span>
              <Badge tone={WS_TONE[connectionStatus]}>{connectionStatus}</Badge>
            </div>
            <p className="mt-2 text-[10px] text-slate-500">
              Reflects this browser tab's own connection to threat-intel's live event stream.
            </p>
          </Card>
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">Ingestion providers</h2>
        {providersError && <EmptyState title="Provider status unavailable" hint="/api/providers/status did not respond." />}
        {providersLoading && !providersError && <p className="text-xs text-slate-500">Loading...</p>}
        {!providersLoading && !providersError && (
          <div className="overflow-x-auto rounded-xl border border-white/10">
            <table className="min-w-full text-left text-xs">
              <thead className="bg-white/5 text-slate-400">
                <tr>
                  <th className="px-3 py-2 font-medium">Provider</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Requires key</th>
                  <th className="px-3 py-2 font-medium">Poll interval</th>
                  <th className="px-3 py-2 font-medium">Event kind</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {(providers ?? []).map((provider) => (
                  <tr key={provider.name}>
                    <td className="px-3 py-2 text-slate-200">{provider.name}</td>
                    <td className="px-3 py-2">
                      <Badge tone={provider.enabled ? "ok" : "neutral"}>
                        {provider.enabled ? "Enabled" : provider.requires_key ? "Disabled (missing API key)" : "Disabled"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-slate-400">{provider.requires_key ? "Yes" : "No"}</td>
                    <td className="px-3 py-2 text-slate-400">{provider.poll_interval_seconds}s</td>
                    <td className="px-3 py-2 text-slate-400">{provider.event_kind}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-slate-100">GeoIP enrichment</h2>
        {geoipError && <EmptyState title="GeoIP status unavailable" hint="/api/geoip/status did not respond." />}
        {geoipLoading && !geoipError && <p className="text-xs text-slate-500">Loading...</p>}
        {!geoipLoading && !geoipError && geoip && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <StatusItem label="License key configured" ok={geoip.license_key_configured} />
            <StatusItem label="City DB present" ok={geoip.city_db_present} />
            <StatusItem label="ASN DB present" ok={geoip.asn_db_present} />
            <StatusItem label="Enrichment available" ok={geoip.enrichment_available} />
            <StatusItem label="Fallback API enabled" ok={geoip.fallback_api_enabled} />
          </div>
        )}
        {!geoipLoading && !geoipError && geoip && !geoip.enrichment_available && (
          <p className="mt-3 text-[11px] text-slate-500">
            GeoIP enrichment is unavailable (no license key and/or database present) -- the 3D globe and map endpoint
            will show no geolocated threats until a MaxMind license key is supplied. This is expected in this
            environment, not an error.
          </p>
        )}
      </section>
    </div>
  );
}

function StatusItem({ label, ok }: { label: string; ok: boolean }) {
  return (
    <Card className="flex flex-col gap-1 p-3">
      <span className="text-[11px] text-slate-400">{label}</span>
      <Badge tone={ok ? "ok" : "neutral"} className="w-fit">
        {ok ? "Yes" : "No"}
      </Badge>
    </Card>
  );
}
