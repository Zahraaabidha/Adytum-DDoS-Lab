import { Disclosure } from "../ui";

/**
 * Embeds the existing Grafana overview dashboard
 * (`observability/grafana/provisioning/dashboards/json/sentinel-overview.json`,
 * uid `sentinel-overview`) via the same-origin `/grafana/*` proxy rule
 * (`nginx.conf`; `vite.config.ts` for dev). Embedding was already enabled for
 * this exact purpose in `docker-compose.yml`'s `grafana` service. The iframe
 * is only mounted once the section is opened, so it costs nothing while
 * collapsed.
 */
export function GrafanaPanel() {
  return (
    <Disclosure title="Grafana dashboard" hint="The full metrics dashboard from the observability stack">
      <div className="h-[560px] w-full overflow-hidden border border-line">
        <iframe
          title="Adytum - Overview"
          src="/grafana/d/sentinel-overview/sentinel-lab-overview?orgId=1&refresh=5s&kiosk=tv&theme=light"
          className="h-full w-full border-0"
        />
      </div>
    </Disclosure>
  );
}
