<p align="center"><img src="logo/download__1_-removebg-preview.png" alt="Adytum" width="120"></p>

# Adytum

Adytum is a self-contained DDoS simulation, detection and threat-intelligence platform for security research and learning. It runs entirely in Docker: simulated attacks hit an isolated target network, an ML detector and Suricata flag them, an adaptive rate limiter mitigates HTTP floods, and a dashboard shows the results next to live public threat-intelligence data.

> **Safety:** the attacker and target networks are Docker `internal` networks. Attack traffic cannot reach external hosts. Do not publish the lab's ports beyond your own machine.

## What it does

| Area | Details |
|---|---|
| Attack simulation | HTTP flood, Slowloris, UDP flood, TCP exhaustion, plus a legitimate-load control |
| Detection | Isolation Forest anomaly detector on live traffic features; four Suricata sensors with calibrated rules |
| Mitigation | Adaptive per-source-fair rate limiter. **HTTP only**: UDP, TCP and Slowloris are detected, not mitigated |
| Incidents | Suricata alerts, ML detections and Prometheus metrics correlated into incidents (advisory only) |
| Threat intelligence | Public feeds normalised into PostgreSQL, served over REST and WebSocket, geolocated with MaxMind GeoLite2 |
| Dashboard | React app: Overview, Global Threat Intelligence (3D globe, feed, sources), Sandbox Lab, Analytics, Alerts, Settings |
| Observability | Prometheus and Grafana |

## Architecture

```text
attacker_net (internal)          target_net (internal)                  public_net
 attacker-* containers  ──►  rate-limiter ──► lb ──► web x3      Grafana, globe API, dashboard,
                                  │            tcp-service x2    threat-intel, defense-engine
                                  │            dns-udp x2
                     defense-engine (ML + mitigation policy)
                     Suricata: ingress + 3 target taps
                     Prometheus

threatintel_net: threat-intel ── PostgreSQL ── Redis   (outbound HTTPS for feeds)
```

`defense-engine` is the single read-only link between the lab and threat intelligence (the correlation endpoint reads its `/metrics`).

## Requirements

Docker Desktop, or Docker Engine with Compose v2. For dashboard development: Node.js 22+. For backend tests: Python 3.12 (as in CI).

## Quick start

```bash
cd sentinel-x
docker compose -p ddos-attack up -d --build
```

Use the same `-p ddos-attack` project name every time. Without it Compose names the project after the folder and creates a second, duplicate set of images, networks and volumes.

| Service | URL |
|---|---|
| Dashboard | http://localhost:8080 |
| Threat-intel API | http://localhost:9400 |
| Defense engine | http://localhost:9300 |
| Sandbox control API (globe) | http://localhost:8090 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |

Every port is bound to `127.0.0.1` (`SENTINEL_BIND` overrides this). The `globe` service mounts the Docker socket and its attack-control API is unauthenticated, so never expose port 8090. Grafana allows anonymous viewing and its admin password defaults to a lab value; set `GRAFANA_ADMIN_PASSWORD` to change it.

### Configuration (`.env`)

Create `sentinel-x/.env` next to `docker-compose.yml`. It is git-ignored; never commit it.

```text
ABUSEIPDB_API_KEY=
OTX_API_KEY=
MAXMIND_LICENSE_KEY=
```

All three are optional. Providers without a key disable themselves. After editing `.env`, recreate the service: `docker compose -p ddos-attack up -d threat-intel`.

### GeoIP

Place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in `data/geoip/` (bind-mounted into `threat-intel`; git-ignored). With a `MAXMIND_LICENSE_KEY` the service also refreshes them daily. Only valid public IPs are looked up; private, reserved and unresolvable addresses stay without a location, and no coordinates are ever invented. `GET /api/geoip/status` reports what is actually loaded.

## Running a simulation

Attacks can be started and stopped from **Sandbox Lab**, or from the command line:

```bash
docker compose -p ddos-attack --profile legit-load run --rm legit-load
docker compose -p ddos-attack --profile attack-http-flood run --rm attacker-http-flood
docker compose -p ddos-attack --profile attack-slowloris run --rm attacker-slowloris
docker compose -p ddos-attack --profile attack-udp-flood run --rm attacker-udp-flood
docker compose -p ddos-attack --profile attack-tcp-exhaustion run --rm attacker-tcp-exhaustion
```

Recordings are stored in the `attacker-recordings` volume and can be replayed for repeatable benchmarking.

### Detector and mitigation defaults

| Setting | Default | Override |
|---|---|---|
| Model | `defense/classifier/model.candidate.joblib` | `SENTINEL_MODEL_PATH` |
| Mitigation policy | `guarded` | `MITIGATION_POLICY=linear` |
| Protective-cap headroom | `6` | `MITIGATION_HEADROOM` |
| Rate limiter | `fair` | `LIMITER_MODE=global` |

The original `model.joblib` is kept for rollback. If no model file is found the engine runs in pass-through mode (nothing mitigated) and says so on the Analytics page. To train a new model, set `MODEL_PATH=` to a new file name first, because `train.py` writes `model.joblib` by default.

Measured results (precision, recall, false-positive rate, confusion matrix, and the lab-run comparison of limiter and policy configurations) are on the **Analytics** page. The full method, tables and caveats are in [docs/RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md).

## Dashboard

| Page | Contents |
|---|---|
| Overview | Active incidents, monitored traffic, detection events, peak blocked rate, trend chart, recent incidents, sandbox status |
| Global Threat Intelligence | Interactive 3D globe (GeoIP markers only), searchable indicator feed, data sources |
| Sandbox Lab | Attack controls, live metrics, event feed, embedded Grafana dashboard |
| Analytics | Detection metrics, mitigation results, lab-run experiments |
| Alerts | Suricata alerts, correlated incidents, ML anomalies and threat-intel indicators with severity, filters and detail pages |
| Settings | Service health, providers, GeoIP status |

Severity is shown only where a source reports one (Suricata, incident rules); everything else is "Unclassified".

Development (hot reload against the running backends):

```bash
cd dashboard
npm ci --legacy-peer-deps
npm run dev
```

## Threat-intelligence API

`GET /health`, `GET /api/threats/{live,map,countries,types,timeline,search,stats,correlation}`, `GET /api/providers/status`, `GET /api/geoip/status`, `WS /ws/threats`. Correlation is a heuristic similarity score with a permanent disclaimer; it is not attribution.

| Provider | Key |
|---|---|
| ThreatFox, CISA KEV, Spamhaus DROP, Emerging Threats, NVD CVE | none |
| AbuseIPDB, AlienVault OTX | `ABUSEIPDB_API_KEY`, `OTX_API_KEY` |

Schema changes use Alembic (`services/threat-intel/migrations`), applied automatically at startup.

## Project layout

```text
attackers/              attack and legitimate-load generators
targets/                web, load balancer, TCP and UDP target services
defense/                detector, mitigation policy, rate limiter, Suricata rules
observability/          Prometheus and Grafana configuration
services/threat-intel/  threat-intelligence service
dashboard/              React + TypeScript dashboard (Vite, Tailwind, Recharts, Three.js)
globe/                  sandbox control API and event feed
reports/                benchmark report generation
infra/                  Kubernetes and Terraform (unverified)
tests/                  isolation, detector, policy and limiter tests
docs/                   research notes
logo/                   brand images
```

## Tests

```bash
# Detector, policy, limiter, incidents (repository root)
pip install -r tests/requirements.txt -r defense/requirements.txt
pytest tests

# Threat-intel service
cd services/threat-intel && pip install -r requirements-dev.txt
mypy --ignore-missing-imports app && pytest

# Dashboard
cd dashboard && npm run typecheck && npm run lint && npm run build

# Network isolation
bash tests/test_network_isolation.sh
```

GitHub Actions runs all of the above plus `ruff`.

## Data you should keep

Never run `docker compose down -v` or `docker system prune --volumes` on this project. They delete the `attacker-recordings` (research recordings), `defense-state` (incident history), `suricata-logs` and `threat-intel-db-data` volumes.

## Known limitations

* The rate limiter protects HTTP only. A detection of another attack still lowers the HTTP cap, which is not protection.
* Mitigation starts about 20-29 s after a flood begins, and roughly half of a flood still gets through. Concurrent legitimate clients lose 1.3% (single-source flood) to 6.7% (six-source flood) of requests.
* All training and test traffic is synthetic lab traffic at one load level, with one run per scenario. The detector flags about 8% of legitimate samples offline.
* Suricata alerts are advisory and never change the rate limit. The three target taps each see one replica.
* The threat-intel feed view shows the 500 most recently updated indicators; the API has no pagination or per-indicator provider field yet.
* Wazuh rules are a configuration stub (no manager is deployed). `infra/k8s` and `infra/terraform` are unverified; Docker Compose is the supported way to run the lab.
