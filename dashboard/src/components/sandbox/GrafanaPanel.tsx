import { Card } from "../ui";

/**
 * Embeds the existing "SENTINEL LAB - Overview" Grafana dashboard
 * (`observability/grafana/provisioning/dashboards/json/sentinel-overview.json`,
 * uid `sentinel-overview`) via the same-origin `/grafana/*` proxy rule
 * (`nginx.conf`; added to `vite.config.ts` for dev-mode parity in this
 * stage). Embedding was already enabled for this exact purpose in
 * `docker-compose.yml`'s `grafana` service (`GF_SECURITY_ALLOW_EMBEDDING`,
 * `GF_AUTH_ANONYMOUS_ENABLED`, `GF_SECURITY_COOKIE_SAMESITE: "disabled"`)
 * before this stage existed -- this is the one deliberate, approved iframe
 * in the Sandbox Lab page, distinct from the "port, don't iframe" rule that
 * applies to the attack controls/feed/mitigation log themselves.
 */
export function GrafanaPanel() {
  return (
    <Card className="flex flex-col gap-2">
      <h3 className="text-xs font-medium text-slate-300">Live metrics (Grafana)</h3>
      <div className="h-[420px] w-full overflow-hidden rounded-lg border border-white/10">
        <iframe
          title="SENTINEL LAB - Overview"
          src="/grafana/d/sentinel-overview/sentinel-lab-overview?orgId=1&refresh=5s&kiosk=tv&theme=dark"
          className="h-full w-full border-0"
        />
      </div>
    </Card>
  );
}
