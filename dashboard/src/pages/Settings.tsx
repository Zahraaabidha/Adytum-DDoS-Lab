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
        <h2 className="mb-3 text-base font-semibold text-ink">Service health</h2>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-sm text-ink-muted">threat-intel</span>
              <Badge tone={threatIntelHealthError ? "danger" : "ok"}>
                {threatIntelHealthError ? "Unreachable" : "Healthy"}
              </Badge>
            </div>
            {threatIntelHealth && (
              <p className="mt-2 text-sm text-ink-muted">Service reports status: {String((threatIntelHealth as { status?: unknown }).status ?? "ok")}.</p>
            )}
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-sm text-ink-muted">defense-engine</span>
              <Badge tone={defenseHealthError ? "danger" : "ok"}>
                {defenseHealthError ? "Unreachable" : "Healthy"}
              </Badge>
            </div>
            {defenseHealth && (
              <dl className="mt-2 space-y-1 text-sm text-ink-muted">
                <div className="flex justify-between"><dt>ML model</dt><dd className="text-ink">{defenseHealth.model_loaded ? "Loaded" : "Not loaded"}</dd></div>
                <div className="flex justify-between"><dt>Mitigation policy</dt><dd className="text-ink">{defenseHealth.policy}</dd></div>
              </dl>
            )}
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-sm text-ink-muted">Live WebSocket (/ws/threats)</span>
              <Badge tone={WS_TONE[connectionStatus]}>{connectionStatus}</Badge>
            </div>
            <p className="mt-2 text-xs text-ink-muted">
              Reflects this browser tab's own connection to threat-intel's live event stream.
            </p>
          </Card>
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-base font-semibold text-ink">Ingestion providers</h2>
        {providersError && <EmptyState title="Provider status unavailable" hint="/api/providers/status did not respond." />}
        {providersLoading && !providersError && <p className="text-sm text-ink-muted">Loading...</p>}
        {!providersLoading && !providersError && (
          <div className="overflow-x-auto  border border-line">
            <table className="min-w-full text-left text-sm">
              <thead className="bg-white text-ink-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Provider</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Requires key</th>
                  <th className="px-3 py-2 font-medium">Poll interval</th>
                  <th className="px-3 py-2 font-medium">Event kind</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {(providers ?? []).map((provider) => (
                  <tr key={provider.name}>
                    <td className="px-3 py-2 text-ink">{provider.name}</td>
                    <td className="px-3 py-2">
                      <Badge tone={provider.enabled ? "ok" : "neutral"}>
                        {provider.enabled ? "Enabled" : provider.requires_key ? "Disabled (missing API key)" : "Disabled"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-ink-muted">{provider.requires_key ? "Yes" : "No"}</td>
                    <td className="px-3 py-2 text-ink-muted">{provider.poll_interval_seconds}s</td>
                    <td className="px-3 py-2 text-ink-muted">{provider.event_kind}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-base font-semibold text-ink">GeoIP enrichment</h2>
        {geoipError && <EmptyState title="GeoIP status unavailable" hint="/api/geoip/status did not respond." />}
        {geoipLoading && !geoipError && <p className="text-sm text-ink-muted">Loading...</p>}
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
          <p className="mt-3 text-[13px] text-ink-muted">
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
      <span className="text-[13px] text-ink-muted">{label}</span>
      <Badge tone={ok ? "ok" : "neutral"} className="w-fit">
        {ok ? "Yes" : "No"}
      </Badge>
    </Card>
  );
}
