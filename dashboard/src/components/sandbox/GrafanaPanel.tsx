const DASHBOARD_PATH = "/grafana/d/sentinel-overview/sentinel-lab-overview?orgId=1&refresh=5s&theme=light";

/**
 * The existing Grafana overview dashboard
 * (`observability/grafana/provisioning/dashboards/json/sentinel-overview.json`,
 * uid `sentinel-overview`), embedded through the same-origin `/grafana/*`
 * proxy rule (`nginx.conf`; `vite.config.ts` for dev). Embedding is enabled
 * on the `grafana` service in `docker-compose.yml`. Kiosk mode hides
 * Grafana's own navigation so only the charts are shown; the link opens the
 * full dashboard in a separate tab.
 */
export function GrafanaPanel() {
  return (
    <section>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold uppercase tracking-[0.12em] text-ink">Grafana dashboard</h2>
        <a
          href={DASHBOARD_PATH}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 border border-line bg-white px-4 py-2 text-sm font-semibold text-ink transition-colors hover:border-accent hover:text-accent"
        >
          Open Grafana dashboard
          <span aria-hidden>&nearr;</span>
        </a>
      </div>
      <div className="h-[80vh] min-h-[560px] max-h-[820px] w-full overflow-hidden border border-line bg-white">
        <iframe title="Adytum - Overview" src={`${DASHBOARD_PATH}&kiosk`} loading="lazy" className="h-full w-full border-0" />
      </div>
    </section>
  );
}
