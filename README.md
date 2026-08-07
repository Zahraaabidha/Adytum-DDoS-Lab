# SENTINEL LAB

SENTINEL LAB is a self-contained DDoS attack-simulation and detection
platform. **It is an isolated research/learning environment, not a tool for
attacking anything outside itself.**

## Why this is safe

The attacker containers in this lab are physically incapable of sending
traffic to any host outside the lab's own Docker network. This is enforced
at the infrastructure level, not by application code that could be bypassed:

- `docker-compose.yml` defines `attacker_net` and `target_net` with
  [`internal: true`](https://docs.docker.com/engine/network/#internal). This
  tells the Docker daemon to omit the network from NAT/masquerade rules and
  to give it no default route to any external interface. A container attached
  only to internal networks has **no kernel-level route to the internet** —
  there is no application-layer check to bypass because there is no path to
  bypass it with.
- [`tests/test_network_isolation.sh`](tests/test_network_isolation.sh) proves
  this empirically: it starts a container on the same networks the real
  attacker containers use, confirms it CAN reach an internal target, and
  confirms it CANNOT reach a raw external IP over HTTPS, resolve any public
  DNS name, or even ping out. This test is step 1 of the CI pipeline
  ([.github/workflows/ci.yml](.github/workflows/ci.yml)) and must pass before
  any other stage runs.
- The equivalent guarantee for the Kubernetes deployment path is a
  default-deny egress `NetworkPolicy` scoped to `role: attacker` pods — see
  [infra/k8s/00-namespace-and-networkpolicy.yaml](infra/k8s/00-namespace-and-networkpolicy.yaml)
  and its own verification Job,
  [infra/k8s/verify-isolation-job.yaml](infra/k8s/verify-isolation-job.yaml).
- The synthetic "attacker identity" (fake IP + fake geolocation, see
  [attackers/common/identity.py](attackers/common/identity.py)) used for the
  globe visualization is a display label only. It never touches real routing,
  real IP spoofing, or a real geolocation lookup — attack traffic always
  originates from the attacker container's real internal Docker IP address on
  the isolated networks above.

## Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │              public_net (bridge)             │
                          │   Grafana :3000   Prometheus UI :9090        │
                          │   Globe dashboard :8090                      │
                          └───────────────┬───────────────────────────────┘
                                          │ (dashboards only, no attack traffic)
 ┌────────────────────┐    ┌─────────────┴──────────────────────────────┐
 │  attacker_net       │    │              target_net (internal: true)   │
 │  (internal: true)   │    │                                             │
 │                     │    │  lb (nginx) ──▶ web x3 replicas             │
 │  attacker-http-flood│    │                                             │
 │  attacker-slowloris │◀──▶│  rate-limiter (adaptive) ──▶ lb             │
 │  attacker-udp-flood │    │                                             │
 │  attacker-tcp-exh.  │◀──▶│  tcp-service x2   dns-udp x2                │
 │  legit-load         │    │                                             │
 │                     │    │  prometheus ◀── scrapes all of the above    │
 │  (NO route out of   │    │  defense-engine (classifier + mitigation)   │
 │   these two networks)   │  suricata (flow/alert telemetry)             │
 └─────────────────────┘    └─────────────────────────────────────────────┘
```

- **targets/** — FastAPI web app, TCP echo service, DNS-like UDP service.
  Each is scaled to 2-3 replicas and exports Prometheus metrics
  (request rate, latency, error rate, connection count). `targets/lb`
  is an nginx load balancer in front of the web replicas; the TCP/UDP
  targets are load-balanced via Docker's embedded round-robin DNS.
- **attackers/** — one module per attack pattern (`http_flood.py`,
  `slowloris.py`, `udp_flood.py`, `tcp_exhaustion.py`), a legitimate
  load-test mode (`legit_load.py`, used to measure false positives), and
  record/replay (`common/recorder.py`, `replay.py`) for repeatable
  benchmarking.
- **defense/** — `engine.py` polls Prometheus, extracts request-rate /
  connection-duration / packet-timing features
  (`classifier/features.py`), scores them with a trained IsolationForest
  (`classifier/train.py`), and adaptively adjusts a rate-limit threshold
  enforced by `rate_limiter/proxy.py`. Every mitigation action is logged
  with its triggering feature values (`defense/mitigation_log.jsonl`).
  `suricata/` and `wazuh/` provide flow-level telemetry and alert
  correlation (see `defense/wazuh/README.md`).
- **observability/** — Prometheus scrape config + Grafana dashboards
  (requests/sec, latency percentiles, active connections, classifier
  confidence, mitigation timeline).
- **globe/** — a globe.gl/Three.js dashboard rendering the synthetic
  attacker geolocations as arcs. Clearly labeled on-screen as synthetic,
  lab-only data.
- **reports/** — post-run benchmark report generator (attack type, peak
  req/s, detection latency, false-positive rate, degradation metrics),
  exported as HTML (PDF if `weasyprint` is installed).
- **infra/** — Kubernetes manifests (primary IaC target) and a minimal
  Terraform wrapper; **.github/workflows/ci.yml** lints, unit-tests the
  classifier, and runs an end-to-end smoke test.

## Module 2: Global Threat Intelligence (in progress)

SENTINEL LAB is being extended with a second, completely separate module:
a read-only Global Threat Intelligence service that ingests real public
threat feeds (ThreatFox, CISA KEV, Spamhaus DROP, Emerging Threats Open,
NVD CVE, and key-gated AbuseIPDB/AlienVault OTX), normalizes them into a
common schema, and serves them over REST/WebSocket for a new SOC-style
dashboard. It is being built incrementally, one stage at a time; this
section will grow with each stage.

**Safety**: this service only downloads public feeds over HTTPS. It is
never attached to `attacker_net` or `target_net`, has no code path that
sends network traffic other than those feed downloads, and cannot start,
stop, or influence anything in the Sandbox Lab module.

- **services/threat-intel/** — FastAPI service (`app/main.py`), organized
  as `app/common/` (DB models, normalized `ThreatEvent`/`CveEvent` schema,
  dedup/confidence-scoring logic), `app/provider/` (one connector module
  per feed, registered via `@register_provider` — see
  `app/provider/base.py` for the interface; adding a provider means adding
  one file plus one import line in `app/provider/__init__.py`), and
  `app/api/` (REST/WebSocket routes, added in a later stage).
- Currently implemented:
  - **Stage A**: service skeleton, PostgreSQL schema (`iocs`,
    `ioc_sightings`, `cves`), the provider registry mechanism, a
    `/health` endpoint, structured logging, environment-variable
    configuration, and graceful startup/shutdown.
  - **Stage B**: seven provider connectors — five enabled by default with
    no API key (ThreatFox, CISA KEV, Spamhaus DROP, Emerging Threats
    Open, NVD CVE) and two that require a free key and self-disable
    cleanly when it's absent (AbuseIPDB via `ABUSEIPDB_API_KEY`,
    AlienVault OTX via `OTX_API_KEY`). Each connector catches its own
    request/parsing errors and returns an empty list rather than raising,
    so one feed being down or rate-limited never affects the others. See
    `services/threat-intel/tests/test_providers.py`.
  - **Stage C**: an APScheduler-driven ingestion loop that polls each
    enabled provider on its own interval, persists normalized events
    (IOCs → `iocs`/`ioc_sightings`, CVEs → `cves`), and publishes IOC
    events to a Redis pub/sub channel. REST API:
    `GET /api/threats/{live,map,countries,types,timeline,search,stats}`
    (aggregate endpoints Redis-cached 30-60s) and `GET /api/providers/status`.
    `WebSocket /ws/threats` streams newly ingested IOC events live. See
    `services/threat-intel/app/ingest.py`, `app/api/routes_threats.py`,
    `app/api/routes_ws.py`.
  - **Stage C.5**: geolocation enrichment, kept as its own subsystem
    (`app/enrich.py`, `app/common/geoip.py`, `app/common/geo_cache.py`,
    `app/geoip_updater.py`) rather than embedded in the ingestion loop --
    `ingest.py` calls `enrich_ioc()` once per persisted IOC and that's the
    entire integration surface. Local MaxMind GeoLite2 (City + ASN) is the
    primary source; a periodic updater downloads/refreshes both databases
    when `MAXMIND_LICENSE_KEY` is set and self-disables (clear log
    message, no download attempted) when it isn't -- independently of
    `GeoIpEnricher` itself also self-disabling when no `.mmdb` file is
    present. Results are cached in Redis by IP address (30-day TTL,
    including negative results for unresolvable addresses) so the same IP
    is never looked up twice, even across different `Ioc` rows. A public
    API fallback (`app/geo_fallback.py`, ip-api.com) exists for future
    interactive single-IP lookups but is off by default
    (`GEOIP_FALLBACK_API_ENABLED=false`) and is never called from bulk
    ingestion. Status: `GET /api/geoip/status`.
  - **Stage D**: wired into `docker-compose.yml` on its own isolated
    `threatintel_net` (bridge, non-internal — needed for outbound HTTPS to
    public feed hosts and MaxMind). `threat-intel-db` (Postgres) and
    `threat-intel-redis` (Redis) live only on `threatintel_net`;
    `threat-intel` itself sits on `[threatintel_net, public_net]` and is
    never attached to `attacker_net` or `target_net`. Bring the whole
    service up with:
    ```bash
    docker compose up -d --build threat-intel-db threat-intel-redis threat-intel
    ```
    Then reach it at `http://localhost:9400` (`/health`,
    `/api/threats/*`, `/api/providers/status`, `/api/geoip/status`,
    `/ws/threats`). Postgres data and downloaded GeoIP `.mmdb` files
    persist in named volumes (`threat-intel-db-data`, `threat-intel-geoip`)
    across restarts.
  - **Stage E**: `dashboard/` — a Vite + React + TypeScript + Tailwind SPA
    shell (no real page content yet; that arrives in Stages F-H). Sidebar
    routes: Overview, Global Threat Intelligence, Sandbox Lab, Analytics,
    Alerts, Settings, all placeholders for now. `src/generated/` holds
    frontend types generated from threat-intel's OpenAPI spec via
    `npm run gen:threat-intel` (never hand-duplicate a backend model that
    OpenAPI already describes); `src/types/threat.ts` covers the one
    response shape the generator can't reach, since `routes_threats.py`
    returns plain dicts rather than a `response_model`. `src/components/
    ui/` is a shared primitive library (`Card`, `Badge`, `StatTile`,
    `Button`, `EmptyState`) that later stages build pages on top of. Bring
    it up with:
    ```bash
    docker compose up -d --build dashboard
    ```
    Then reach it at `http://localhost:8080`. In dev mode
    (`npm run dev` inside `dashboard/`, or the `dashboard-dev` launch
    config), Vite proxies `/api/threats/*`, `/api/providers/*`,
    `/api/geoip/*`, `/ws/*` to `threat-intel:9400` and `/api/sandbox/*` to
    `globe:8090`; in production this is done by nginx (`dashboard/
    nginx.conf`), which also proxies `/grafana/*` to `grafana:3000`.
  - **Stage F**: the "Global Threat Intelligence" sidebar page
    (`/threat-intel`) now renders a `react-three-fiber` 3D globe
    (`src/components/globe/`) visualizing the geographic distribution of
    `threat-intel`'s ingested IOCs — static instanced markers for the
    standing dataset plus short-lived animated pulses for events arriving
    live over the existing WebSocket stream. There is no fixed/hardcoded
    destination point anywhere in this feature: `ArcLayer.tsx` only draws
    a source→destination arc for events carrying real destination
    coordinates, which the current schema never populates, so the globe's
    primary (and currently only) visualization is the markers/pulses. The
    surface texture is generated procedurally on an offscreen canvas at
    runtime (`earthTexture.ts`) rather than bundling or fetching a
    satellite-imagery file, so the globe has no runtime CDN dependency.
    When `/api/threats/map` returns no geolocated results (e.g. this dev
    environment, which has no `MAXMIND_LICENSE_KEY` configured) the page
    shows the shared `EmptyState` component instead of an empty or broken
    canvas. Rendering is capped for large datasets: markers are drawn as
    a single `InstancedMesh` (one draw call regardless of count), capped
    client-side at 800 on top of the backend's own 2,000-row cap, and
    live pulses are capped at 40 concurrent with a 4-second self-expiry.
    Hover shows a tooltip (country/ip/threat_type/confidence/source/
    timestamp); click opens a slide-in detail panel backed by
    `/api/threats/search`; `GlobeFilters` (country/type/confidence/time
    window) are wired into `threatStore`'s new `globeFilters` slice.
  - **Stage G**: the remaining five sidebar pages now render real data.
    **Overview** is a high-level operational summary (KPI tiles, a compact
    globe-preview card linking to the full 3D globe, sandbox status,
    top countries/types, recent alerts) — deliberately not a duplicate of
    the full Threat Feed experience. **Threat Feed** keeps Stage F's globe
    unchanged and adds search plus filter-by-provider/threat-type/
    confidence/country and sort-by-newest/oldest underneath it (provider
    filtering only matches threats seen live over the WebSocket during the
    current session, since deduped `Ioc` rows don't carry a per-row
    provider name — the UI states this explicitly). **Analytics** shows
    only metrics either backend actually computes: `defense-engine`'s
    mitigation-action confidence/threshold timeline, and `threat-intel`'s
    ingestion volume/threat-type breakdown — no precision/recall/
    false-positive-rate, since neither backend tracks ground-truth labels
    to compute them from. **Alerts** buckets IOCs into
    critical/high/medium/low severity derived from the real
    `confidence_score` field, each with a distinct color. **Settings**
    adds threat-intel/defense-engine `/health` checks and live WebSocket
    connection status alongside the existing provider/GeoIP status views.
    Shared `src/components/feed/{ThreatCard,LiveFeedList,FeedFilters,
    labels}.tsx` and `src/lib/{queries,sandboxStatus,defenseEngineApi}.ts`
    were added; no `services/threat-intel/app/` file and no Sandbox Lab
    file were touched. Building this stage surfaced and fixed three real
    bugs in already-completed Stage E/F code (the live WebSocket payload
    was mistyped, `LivePulseLayer`'s pulse key read a field that doesn't
    exist on that payload so a given IOC only ever pulsed once per page
    load, and `threatStore.connectionStatus` was never actually wired up)
    plus one missing dependency (`react-is`, an undeclared `recharts` peer)
    — see `PROJECT_EXECUTION_PLAN.md`'s Stage G entry for full detail.
  - **Stage H**: the "Sandbox Lab" sidebar page (`/sandbox`) is now the
    real, natively-ported control page for the Sandbox Lab module — attack
    start/stop controls (`AttackControls.tsx`), a live event feed table, an
    embedded Grafana panel, and a mitigation log table
    (`MitigationLogTable.tsx`, reusing Stage G's `useMitigations`), all
    talking to `globe/server.py` and `defense-engine:9300` exclusively
    through the existing same-origin `/api/sandbox/*` and `/api/defense/*`
    proxy rules from Stage E/G. **No CORS change was made to
    `globe/server.py`** — the proxy already made every request same-origin,
    so the CORS addition originally anticipated in the execution plan
    turned out to be unnecessary and was skipped. No file in `dashboard/`
    ever calls Docker directly; attack lifecycle management remains
    entirely `globe/server.py`'s responsibility, reached only over HTTP.
    The Grafana panel (`GrafanaPanel.tsx`) is the one deliberate iframe in
    this stage, embedding the existing "SENTINEL LAB - Overview" dashboard
    (already configured for anonymous/embedded access in
    `docker-compose.yml`) — everything else on the page is ported UI, not
    iframed. See `PROJECT_EXECUTION_PLAN.md`'s Stage H entry for full
    verification detail.

## Setup

Requires Docker Desktop (or Docker Engine + Compose v2).

```bash
git clone <this repo>
cd ddos-attack

# Step 1 (mandatory): verify isolation before anything else
bash tests/test_network_isolation.sh

# Step 2: bring up targets + observability
docker compose up -d --build web lb tcp-service dns-udp prometheus grafana

# Grafana: http://localhost:3000  (anonymous viewer access enabled)
# Prometheus: http://localhost:9090
```

## Running attack scenarios

Each attack module is a Compose profile, so it's never started by accident:

```bash
# Record a legitimate-load control run first (needed to train the classifier)
docker compose --profile legit-load run --rm legit-load

# Train the classifier on that recording, then restart the engine to load it
docker compose run --rm --entrypoint python defense-engine classifier/train.py --legit-runs legit_load_control_run
docker compose restart defense-engine

# Bring up the defense engine + adaptive rate limiter
docker compose up -d --build defense-engine rate-limiter

# Now run an attack
docker compose --profile attack-http-flood run --rm attacker-http-flood
docker compose --profile attack-slowloris run --rm attacker-slowloris
docker compose --profile attack-udp-flood run --rm attacker-udp-flood
docker compose --profile attack-tcp-exhaustion run --rm attacker-tcp-exhaustion

# Replay a recorded run later for a repeatable benchmark
docker compose run --rm attacker-http-flood python replay.py http_flood_run
```

Generate a benchmark report after any run (only needs `jinja2` locally,
or run it via a throwaway container built from `reports/Dockerfile`):

```bash
pip install jinja2
python reports/generate_report.py http_flood_run
python reports/generate_report.py legit_load_control_run --control
```

## Reading the dashboards

- **Grafana → SENTINEL LAB - Overview**: requests/sec per target, latency
  p95, active connections (HTTP/TCP), UDP packets/sec, classifier attack
  confidence (0-1), and the mitigation-action timeline (rate-limit threshold
  over time + actions/min).
- **Globe dashboard** (`http://localhost:8090`): each arc is one simulated
  attacker session, colored red for attack traffic and blue for legitimate
  load, converging on the lab's symbolic target marker. The synthetic-data
  banner is always shown on-screen. It reads only
  `attackers/recordings/*.jsonl` — never real network traffic.
- **`/mitigations` on the defense engine** (`http://localhost:9300/mitigations`):
  the raw log of every adaptive rate-limit change with the classifier
  confidence and feature values that triggered it.

## Kubernetes deployment

`infra/k8s/` contains the full manifest set. Apply the namespace +
NetworkPolicy first and confirm the isolation Job passes:

```bash
kubectl apply -f infra/k8s/00-namespace-and-networkpolicy.yaml
kubectl apply -f infra/k8s/verify-isolation-job.yaml
kubectl wait --for=condition=complete job/verify-isolation -n sentinel-lab --timeout=60s
kubectl logs job/verify-isolation -n sentinel-lab   # expect "PASS: external host unreachable"

kubectl apply -f infra/k8s/10-targets.yaml
```
