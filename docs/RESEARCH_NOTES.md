# SENTINEL LAB

SENTINEL LAB is a self-contained DDoS attack-simulation, detection, and threat-intelligence platform built for security research and learning.

> **Safety:** The attack environment is isolated and designed to prevent traffic from reaching external hosts.

## Overview

* **DDoS Simulation** — HTTP flood, Slowloris, UDP flood, and TCP exhaustion
* **Detection & Defense** — IsolationForest anomaly detection for all four attack types; adaptive rate limiting that mitigates **HTTP traffic only** (UDP flood, TCP exhaustion and Slowloris are detected, not mitigated)
* **Observability** — Prometheus and Grafana monitoring
* **Threat Intelligence** — Public threat-feed ingestion with REST/WebSocket APIs
* **3D Visualization** — Globe-based visualization of synthetic attacker locations
* **Benchmarking** — Record/replay and automated reports
* **Correlation** — Heuristic comparison of live sandbox traffic with recent threat-intel volume (not attribution)
* **Kubernetes** — Deployment manifests with network-isolation policies (not yet verified on a live cluster)

## Architecture

```text
Attackers
   │
   ▼
Isolated Target Network
   │
   ├── Web / TCP / UDP Services
   ├── Rate Limiter (HTTP only)
   ├── Defense Engine
   └── Suricata (passive IDS; EVE alerts are ingested by defense-engine and shown in the dashboard, advisory only)
            │
            ▼
     Prometheus + Grafana

Threat Intelligence
   │
   ├── Public Threat Feeds
   ├── PostgreSQL
   ├── Redis
   └── REST / WebSocket API
            │
            ▼
      React Dashboard
```

The attacker and target networks are isolated at the infrastructure level using Docker internal networks and Kubernetes network policies.

### Networks

| Network | Type | Members |
|---|---|---|
| `attacker_net` | internal | attacker containers, `rate-limiter` |
| `target_net` | internal | targets, Prometheus, Suricata, `defense-engine` |
| `public_net` | bridge | Grafana, `globe`, `dashboard`, `threat-intel`, `defense-engine` and Prometheus (dual-homed) |
| `threatintel_net` | bridge | `threat-intel`, its Postgres and Redis (needs outbound HTTPS for feeds) |

`defense-engine` is the one read-only seam between the sandbox and threat intelligence: the correlation engine reads its `/metrics`.

## Project Structure

```text
attackers/              DDoS simulation modules
targets/                Web, TCP, and UDP target services
defense/                Detection and adaptive HTTP rate limiting
observability/          Prometheus and Grafana configuration
services/threat-intel/  Threat intelligence service
dashboard/              React + TypeScript dashboard
globe/                  3D attacker visualization
reports/                Benchmark report generation
infra/                  Kubernetes and Terraform configuration
tests/                  Isolation and project tests
```

## Tech Stack

**Backend:** Python, FastAPI
**Frontend:** React, TypeScript, Tailwind CSS
**Security:** IsolationForest, Suricata
**Data:** PostgreSQL, Redis
**Monitoring:** Prometheus, Grafana
**Infrastructure:** Docker, Kubernetes, Terraform
**Visualization:** Three.js / React Three Fiber

## Setup

Requires **Docker Desktop** or **Docker Engine with Compose v2**.

```bash
git clone <repository-url>
cd ddos-based-attacks   # or the folder you cloned into

# Verify network isolation
bash tests/test_network_isolation.sh

# Start targets and monitoring
docker compose up -d --build web lb tcp-service dns-udp prometheus grafana
```

* Grafana: `http://localhost:3000`
* Prometheus: `http://localhost:9090`

**Security:** every published port is bound to `127.0.0.1` by default (`SENTINEL_BIND` overrides it). The `globe` service mounts the Docker socket (root-equivalent on the host) and its attack-control API is unauthenticated, so never publish port 8090 beyond the local machine. Grafana allows anonymous Viewer access and its admin password defaults to a lab value; set `GRAFANA_ADMIN_PASSWORD` to change it. The threat-intel database password in `docker-compose.yml` is a lab default.

## Running a Simulation

First, create a legitimate control run and train the classifier:

```bash
docker compose --profile legit-load run --rm legit-load

docker compose run --rm --entrypoint python \
  defense-engine classifier/train.py \
  --legit-runs legit_load_control_run

docker compose restart defense-engine
docker compose up -d --build defense-engine rate-limiter
```

Run an isolated attack scenario:

```bash
docker compose --profile attack-http-flood run --rm attacker-http-flood
docker compose --profile attack-slowloris run --rm attacker-slowloris
docker compose --profile attack-udp-flood run --rm attacker-udp-flood
docker compose --profile attack-tcp-exhaustion run --rm attacker-tcp-exhaustion
```

Recorded runs can be replayed for repeatable benchmarking.

### Model selection

**Selected default model: `defense/classifier/model.candidate.joblib`** -- an IsolationForest trained on 135 live feature samples from six varied legitimate-load runs plus one 150 s idle window (boundary contamination 0.005, with a range guard taken from the training minimum and maximum). Its offline report is `evaluation.candidate.json`. The original `model.joblib` and `evaluation.json` are untouched and kept as the rollback; so are the other models and reports from earlier iterations (`model.baseline-range-guard.joblib` and `evaluation.baseline-range-guard.json` are byte-identical copies of the originals). Nothing was retrained for this selection.

Defaults, all set in `docker-compose.yml` and mirrored in the code (a test fails if they drift apart):

| Setting | Default | Override |
|---|---|---|
| Model | `/app/classifier/model.candidate.joblib` | `SENTINEL_MODEL_PATH` |
| Offline report served at `/evaluation` | `/app/classifier/evaluation.candidate.json` | `SENTINEL_EVALUATION_PATH` |
| Mitigation policy | `guarded` | `MITIGATION_POLICY=linear` |
| Protective-cap headroom | `6` | `MITIGATION_HEADROOM` |
| Rate limiter | `fair` | `LIMITER_MODE=global` |

Rollback to the original model is one variable:

```bash
SENTINEL_MODEL_PATH=/app/classifier/model.joblib SENTINEL_EVALUATION_PATH=/app/classifier/evaluation.json \
  docker compose up -d --force-recreate defense-engine
```

Verified behavior: after a clean `docker compose down` and `up` with no overrides the engine logs `Loaded classifier model from /app/classifier/model.candidate.joblib (... 135 samples from 6 legitimate run(s))` and `Mitigation policy: guarded`, and `GET /health` reports the model file, its training summary and the policy. With the rollback variable it loads the original (73 samples); returning to the default restores the candidate. If the model file is missing the engine runs in pass-through mode (confidence 0, nothing mitigated) with a warning, `model_loaded: false` in `/health`, and a red banner on the Analytics page; it does not stop. Model files are git-ignored by default; `.gitignore` makes an exception for the selected model, the original and their reports, but they must still be added to the repository, and a clone without them runs in pass-through mode. **Train new models with `MODEL_PATH=` set to a new file name**, because `train.py` writes `model.joblib` by default.

Why the candidate: the two models were compared on identical scenarios, the original in the plain Docker configuration and the candidate with only the model path changed (guarded policy as it was then, estimator v2, headroom 2). The original flags a third of diverse legitimate load as anomalous, and the policy sets its protective cap from the peak of *unflagged* load, so the cap landed low and a legitimate client lost 42.6% of its requests under a six-source flood; the candidate lost 7.1% and recovered about twice as fast.

| Scenario (measured earlier: guarded policy, estimator v2, headroom 2) | original `model.joblib` | candidate model |
|---|---|---|
| Legitimate alone: blocked / lowest cap | 0 of 873 / 500 | 0 of 830 / 500 |
| Flood alone: admitted req/s, blocked | 28, 94.4% | 39, 94.9% |
| Six-source flood alone: admitted req/s, blocked | 29, 95.5% | 69, 90.1% |
| Flood + legitimate: legitimate blocked | 1.6% | 2.8% |
| Six-source flood + legitimate: legitimate blocked | 42.6% | 7.1% |
| Cap back above 90% of baseline (slowest of the four attack scenarios) | 141 s | 66 s |

### Rate limiting

> **Scope: HTTP only.** The rate limiter sits in front of the HTTP targets and rejects requests with `429`. UDP flood, TCP exhaustion and Slowloris traffic goes straight to `dns-udp`, `tcp-service` and `web:8000` and never passes through it. Those attacks are **detected** (and logged), but nothing in this project **mitigates** them, and no separate defense for them has been built or tested. When one is detected the engine still lowers the HTTP cap, which does not stop the attack and can throttle legitimate HTTP clients (measured below, *Slowloris + legitimate*). Do not read a lowered cap during those attacks as protection.

`rate-limiter` fronts the HTTP targets and enforces a requests-per-second cap that `defense-engine` lowers as its attack confidence rises. Two admission policies (`defense/rate_limiter/limiter.py`, selected with `LIMITER_MODE`) enforce the same cap and never admit more than it allows:

* `fair` (default) -- max-min fairness per source address. Each source seen in the previous second is guaranteed an equal share of the cap; capacity is held back for what each source asked for last second (up to its share), and a source over its share may only use the rest. A light legitimate client keeps its requests during a flood, and a distributed flood is still held to the global cap, with no single address above a fair share.
* `global` -- first come, first served: a flood fills the cap early in each second and later requests from everyone else are rejected. Kept for comparison.

The source is the TCP peer address; `X-Forwarded-For` is deliberately ignored. Per-source fairness has limits: an attacker with many addresses holds many shares (the cap still holds), many legitimate users behind one address share one, and a client that suddenly needs more than it used last second gets the extra only from unreserved capacity until the next second.

### Mitigation policy

`defense-engine` turns detector confidence into the rate limit that `rate-limiter` enforces. `MITIGATION_POLICY` selects how:

* `guarded` (default, `defense/mitigation.py`) -- a small state machine. In the normal state the cap stays at the baseline however the confidence wanders below 0.5. Three consecutive flagged polls (15 s) start mitigation, so an isolated false positive changes nothing. The cap then steps down by at most 60% per poll toward a protective cap of `MITIGATION_HEADROOM` (default 6) times the recent peak of normal load over the last 5 minutes, never below `MITIGATION_MIN_CAP` (default 20). Normal load is learned only from polls that stayed calm: a calm poll counts after four further calm polls, and any flagged or ambiguous poll discards the polls still waiting, because an attack ramps up over a poll or two before its confidence crosses the threshold. Mitigation ends only after four calm polls in a row (confidence below 0.45 *and* the limiter rejecting under 2 req/s): the detector sees the already limited traffic, so confidence falls once the limit works, and the rejection rate is what shows the attack is still on. After that the cap climbs back at most 1.5x per poll. Other tunable: `MITIGATION_FALLBACK_CAP`.
* `linear` -- the original mapping, a straight line from confidence to cap. It has no memory, keeps the cap lowered for ordinary traffic (270-300 req/s with the candidate model at idle and under legitimate load), and only throttles a ~105 req/s flood once confidence passes 0.80.

**Final default, measured.** Same scenarios for every column: legitimate traffic alone (about 9 req/s of requests, 20 simulated users), a single-source flood, a six-source flood, legitimate traffic running at the same time as each, and Slowloris with legitimate traffic. The last column is plain `docker compose` with no overrides (candidate model, guarded policy, headroom 6, fair limiter); the two linear columns were measured earlier with the candidate model. Scenario recordings are named `m_<config>_<scenario>`; `classifier/mitigation_report.py` measures them from the recordings and the engine's feature log, and the **Analytics** page shows the result under *LAB RUNS*.

| Scenario (measured) | global + linear | fair + linear | **final default**: fair + guarded |
|---|---|---|---|
| Legitimate alone: blocked / lowest cap | 0 of 862 / cap 298 | 0 of 871 / cap 270 | 0 of 844 / cap 500 |
| Flood alone: admitted req/s (2nd half) / blocked | 120 / 0.0% | 117 / 0.0% | 64 / 91.4% |
| Six-source flood alone | 111 / 0.0% | 118 / 4.7% | 64 / 90.3% |
| Flood + legitimate: admitted flood req/s; legitimate blocked | 115; legitimate 0.2% | 116; legitimate 0.0% | 53; legitimate 1.3% |
| Six-source flood + legitimate | 108; legitimate 0.0% | 115; legitimate 0.2% | 57; legitimate 6.7% |
| Slowloris + legitimate (not blockable by the HTTP limiter) | not run | not run | legitimate 0.0%, cap 64 |
| Cap back above 90% of baseline: flood alone | not within 98 s | not within 97 s | 71 s |
| ... six-source flood alone | not within 97 s | not within 97 s | 56 s |
| ... flood + legitimate | not within 48 s | not within 48 s | 57 s |
| ... six-source flood + legitimate | not within 91 s | 52 s | 63 s |

Reading it:

* Both linear configurations leave floods almost entirely unthrottled (the cap never fell below 104-141 req/s while floods ran at 105-120), so their low legitimate blocking comes from not blocking anything; they also never return the cap to the baseline.
* The final default never throttles legitimate traffic that runs alone, cuts the flood load that gets through from about 115 req/s to 53-64 req/s, rejects 90-92% of flood requests (inflated, because rejected attackers retry at once: offered rates reached 860-1,000 req/s; the admitted rate is the meaningful figure), and costs concurrent legitimate clients 1.3% (single-source flood) and 6.7% (six-source flood). Suppression is moderate, not strong: roughly half of the flood still reaches the targets.
* Slowloris is detected but **not mitigated**: the rate limiter cannot affect it. The engine still lowered the HTTP cap (to 64 req/s) while it ran; here that did not block the legitimate client (about 5 req/s), but a legitimate client above the lowered cap would have been throttled for no protective benefit.
* The protective cap scales with legitimate load (6x its recent peak, about 11 req/s here, giving 64-70 req/s). A flood below that level is not constrained, and a site whose legitimate peak is already near the flood's rate gets no protection from this policy.

**How the default was reached.** The first run of the promoted configuration failed its acceptance criteria (flood load admitted 94-97 req/s, a cap of 105 req/s): the first two polls of the attack ramp still had low confidence and were learned as normal load, which lifted the cap to the flood's own rate. Replaying 45 real flood onsets through the policy showed this would have set a cap of 90 req/s or more in 12 of 45, and in none after the fix (calm polls count only after confirmation, above). The fixed policy at headroom 2 protected well but cost a legitimate client 36.8% of its requests under a six-source flood, so a sweep of headroom 2, 4 and 6 was declared before it ran, with these criteria: legitimate traffic alone never blocked and the cap at 500; floods at least 85% rejected with at most 70 req/s admitted; concurrent legitimate blocking at most 10%; the cap back above 90% of the baseline within 90 s; every scenario starting with a clean cap. The smallest headroom meeting all of them was chosen:

| Headroom (protective cap = headroom x recent normal peak) | flood + legitimate: flood req/s admitted, legitimate blocked | six-source flood + legitimate: flood req/s admitted, legitimate blocked, recovery | cap | meets every criterion |
|---|---|---|---|---|
| 2 | 15, 4.8% | 21, 36.8%, 126 s | 22 | no |
| 4 | 33, 1.5% | 40, 21.9%, 57 s | 44 | no |
| 6 (chosen) | 60, 2.2% | 64, 5.3%, 56 s | 70 | yes |

The headroom-6 row comes from the sweep run; the final-default run (table above) is the same configuration measured a second time and differs slightly (53 and 57 req/s admitted instead of 60 and 64, legitimate blocked 1.3% and 6.7% instead of 2.2% and 5.3%), which gives a rough idea of run-to-run variation. Every cell is otherwise a single run.

**Mitigation delay.** From the start of a flood, the engine's cap first fell below half the baseline after 20-22 s and the first request was rejected after 26-29 s in the final-default runs (every scenario started with the cap at the baseline, and none rejected a request before the engine lowered the cap). The delay is the sum of the 15 s Prometheus rate windows the features use, three consecutive flagged polls (15 s) and the bounded cap steps. Replaying the engine's real logged vectors (about 2 h of non-attack traffic, 16 floods) through the policy showed it cannot be shortened safely: two flagged polls instead of three roughly doubles false mitigation entries on legitimate and idle time (candidate model 1.5 to 3.0 per hour, original model 3.5 to 5.0), one poll is far worse (about 16 and 12 per hour), and a faster cap ramp saves only about 2 s. The defaults were left unchanged.

**Measurement validity.** Earlier iterations showed first rejections within 0.3-1 s of a flood starting. Two causes were found: a scenario that began while the cap was still lowered by the previous one, and, with the cap at its baseline of 500 req/s, the first seconds of a flood against a cold target briefly exceeding 500 req/s (rejected attackers then retry instantly). The report records the engine's state and cap when each scenario starts (`clean_start`) and how many requests were rejected before the cap was lowered, and the runs wait for full recovery between scenarios. All rows of the final-default run have a clean start and no pre-engagement rejections.

### Suricata alerts

Four passive Suricata sensors write EVE JSON to the `suricata-logs` volume:

| Sensor | Where it sits | File | Rule (threshold per source, per 10 s) |
|---|---|---|---|
| `ingress` (`suricata`) | the rate-limiter's network namespace (both interfaces) | `eve.json` | HTTP flood: more than 400 `GET` requests to :8080 |
| `web` (`suricata-web`) | the namespace of one `web` replica (of three) | `eve-web.json` | Slowloris: more than 25 tiny (1-60 byte) payloads on established connections to :8000 |
| `udp` (`suricata-udp`) | the namespace of one `dns-udp` replica (of two) | `eve-udp.json` | UDP flood: more than 1000 packets to :5300 |
| `tcp` (`suricata-tcp`) | the namespace of one `tcp-service` replica (of two) | `eve-tcp.json` | TCP exhaustion: more than 80 SYNs to :9000 |

The three taps only *join* an existing internal namespace: no new network, route or port, and the traffic paths, target metrics and ML features are unchanged. Each sees one replica, so a share of the traffic; the thresholds are per replica.

**Thresholds are measured, not guessed.** `defense/suricata/calibrate.py` and `calibrate.rules` (which alerts on every matching packet) drive labelled legitimate traffic and the real attackers at the taps and report, per source, the most matches in any 10 s window. Two repetitions each, maximum per window:

| Signal | Legitimate | Attack | Threshold |
|---|---|---|---|
| UDP packets at one `dns-udp` replica | 67-70 (10 pps), 264-266 (50 pps), 158-168 (10 pps + 200-packet burst) | 4145-4612 | 1000 |
| TCP SYNs at one `tcp-service` replica | 13-18 (2 conn/s), 53-59 (10 conn/s), 59-66 (10 conn/s + 40-connection burst) | 103-108 | 80 |
| Slowloris: SYNs at one `web` replica | 47-55 (10 users), 253-302 (45 users) | 29-37 | not usable: legitimate load looks bigger |
| Slowloris: tiny payloads at one `web` replica | 0 (10 users, 45 users, HTTP flood) | 102-114 | 25 |
| GET requests at the ingress | 132-146 (10 users), 785-877 (45 users) | 1089-1159 | 400 |

Each threshold is the geometric mean of the largest legitimate and smallest attack value (Slowloris: a quarter of the weakest attack, since legitimate is 0). Caveats: the margin for TCP exhaustion is thin (legitimate maximum 66, attack minimum 103, about 1.3x), so a single source opening more than about 10 connections per second looks like the attack; legitimate HTTP from one source above about 40 req/s (the 45-user profile) cannot be told from the flood by rate and alerts; the legitimate UDP/TCP traffic is a synthetic generator from one source address; and there are only two repetitions per scenario. The previous ingress rules (200 packets per 10 s, and a SYN-count Slowloris rule) alerted on ordinary legitimate load and were replaced. To recalibrate, run the taps with `calibrate.rules` mounted in place of their rules, drive the traffic (`calibrate.py traffic udp|tcp`, `legit-load`, the attackers) and run `calibrate.py analyze` on the EVE files.

`defense-engine` mounts the volume **read-only**, tails every `eve*.json` incrementally (`defense/suricata_alerts.py`), and normalizes each alert: signature and id, severity (Suricata 1/2/3 -> high/medium/low), source and destination address and port, protocol, timestamp, sensor and capture interfaces. It serves them at `GET /suricata/alerts` (`limit`, `min_severity`, `signature_id`) and `GET /suricata/summary`, exports `defense_suricata_alerts_total{signature_id,severity}` to Prometheus, and the dashboard shows them on **Sandbox Lab**.

* **Deduplication.** The ingress sensor can see one request twice: arriving from the client, and again as the rate-limiter forwards it to the load balancer. With the calibrated HTTP rule (port 8080 only) the forwarded leg no longer alerts, so merging is now a safeguard rather than an everyday path. The second sighting (source = the rate-limiter, resolved by DNS name `rate-limiter`, `SURICATA_PROXY_HOSTS`) is merged into the client's alert when it has the same signature within 15 s, in either order. The alert keeps both capture interfaces and the merged sighting. If the client-side twin never arrives the sighting is promoted to an alert after 15 s. If the rate-limiter cannot be resolved nothing is merged. Docker does not fix which of `eth0`/`eth1` faces the attacker, so the role comes from the address, never the interface name.
* **Restart safety.** The read position (file inode and offset) is saved to `defense/suricata_state.json` (git-ignored). After an engine restart, ingestion resumes there: alerts written while it was down are counted once, alerts already counted are not replayed into the Prometheus counter. Alerts that pre-date the first start fill the history but are not counted. Without a state file nothing is replayed; with a rotated file (new inode) ingestion restarts from the top.
* **Bounds.** At most 1,000 alerts and 6 hours are kept in memory, at most 200 signature counters and 200 unmatched sightings, lines over 64 kB are dropped, flow/stats records are skipped before parsing, and one poll reads at most 8 MB (it catches up on the next poll).
* **EVE log rotation and retention.** Every Suricata container runs `defense/suricata/rotate-eve.sh` next to Suricata: it renames the sensor's file to `<file>.<timestamp>` (Suricata keeps writing to the same inode), sends Suricata `SIGHUP` so it opens a fresh file, and deletes all but the newest 6 rotated files. It rotates hourly or at 50 MB, whichever is first (`SURICATA_ROTATE_SECONDS`, `SURICATA_ROTATE_BYTES`, `SURICATA_KEEP_ROTATED`), so a sensor holds at most about 7 files. The engine reads each file through one open handle, so it notices a rotation by the inode, finishes the renamed file from its saved offset, then reads the new file from the top: nothing written between its last read and the rotation is lost, and nothing is read twice. It does the same if the rotation happened while it was down, and it also catches up through several rotations. Rotated files (`eve.json.<timestamp>`) never match the active-file pattern `eve*.json`. If retention removed a file before the engine read it, the engine logs a warning and those alerts are lost. The `.sh` file must keep Unix line endings (`.gitattributes` enforces it).

Each alert is annotated with the highest classifier confidence and the Prometheus-derived request rate within 10 s of it, so you can see whether the ML detector agreed. **This is advisory only:** a Suricata alert never changes the rate limit, the model or the mitigation policy.

### Unified incidents

`GET /incidents` on `defense-engine` (`defense/incidents.py`) combines what the existing components reported into one record per incident. It is read-only and advisory: it changes nothing about the rate limit, the model, the Suricata rules or the mitigation policy. The dashboard shows the records on **Sandbox Lab** above the raw Suricata table, which stays as the detail view.

* **Grouping.** Suricata alerts (already deduplicated across interfaces) are grouped by attack type, taken from the signature id (1000001 HTTP flood, 1000002 Slowloris, 1000003 UDP flood, 1000004 TCP exhaustion), into bursts: alerts of one type less than 60 s apart are one incident, with every source address and sensor listed. Isolation Forest episodes that no Suricata incident explains become separate "anomalous traffic" incidents.
* **Two detectors, one kind of evidence.** Suricata and the Isolation Forest are the detectors; the Prometheus series for the attack type (`target_http_requests_total` rate, `target_http_established_sockets`, `target_udp_packets_total` rate, `target_tcp_active_connections`, fetched with `query_range`) is evidence. The record states each detector as `flagged`, `not_flagged` or `no_data`, and the metric as `elevated`, `not_elevated`, `no_baseline`, `no_data` or `not_applicable` (peak against the median of the 90 s ending 30 s before the first alert; elevated means at least 3x the baseline and a minimum absolute rise: 20 req/s, 20 sockets, 100 packets/s, 50 connections).
* **Agreement.** `corroborated` means both detectors flagged the same period (alert times padded by 20 s); `suricata_only`, `ml_only` and the `..._unavailable` variants say which one flagged and whether the other disagreed or had no data. The Isolation Forest needs 3 consecutive flagged polls (the guarded policy's own `enter_polls`) because a single flagged poll happens by chance on ordinary traffic. A missing signal is `no_data`, never calm; with no model loaded the ML side is `no_data`, not zero.
* **Severity** is a plain rule, not a score: `high` when both detectors flagged, `medium` when one did and the type's metric rose, otherwise `low`. No confidence is invented.
* **Mitigation status** is reported from the engine's own samples: whether the cap was lowered below the baseline, the lowest cap, the policy states seen. For Slowloris, UDP flood and TCP exhaustion it says mitigation is not applicable (the limiter protects HTTP only) and that a lowered cap is not protection.
* **Caveats are part of the record.** Matching is by attack type and time window, not by flow, so agreement means the signals coincided, not that one proves the other; the Isolation Forest scores anomaly, not attack type, so it cannot confirm which attack Suricata named; for HTTP flood the Suricata rule, the ML request-rate feature and the metric all measure request rate, so they are not independent and legitimate load from one source above about 40 req/s looks the same; a lone TCP-exhaustion alert sits close to busy legitimate traffic.
* **Persistence.** Detector history and incidents survive an engine restart (`defense/state_store.py`). See *Persistence and retention* below.

#### Persistence and retention

Before this, a restart lost the in-memory detector history (the ML and mitigation evidence), the `/mitigations` list, and every incident, which is derived. The engine now keeps one SQLite file (`/data/state.db`, the named volume `defense-state`; `SENTINEL_STATE_DB`). PostgreSQL was not used on purpose: the engine sits on `target_net` and `public_net`, and the threat-intel database lives on a network that never touches the lab, so using it would have meant bridging them. SQLite is in the Python standard library: no new service.

| Stored | What | Retention |
|---|---|---|
| `detector_polls` | one row per 5 s poll: confidence, rate-limit cap, policy state, blocked rate, the six live features, and the model file that scored it | 24 h and at most 20,000 rows |
| `incidents` | the full unified incident record (detectors, metric, mitigation, evidence, caveats) | 7 days and at most 500 |
| `incident_alerts` | the Suricata alerts that support an incident | with their incident; at most 500 per incident |

* **Restore on start.** The last 6 hours of polls scored by the *current* model go back into memory (polls from another model, such as after the `SENTINEL_MODEL_PATH` rollback, are not restored: their confidences mean something else). The `/mitigations` list is restored from the engine's own `mitigation_log.jsonl`. The gap while the engine was down stays a gap: no poll is invented, so an incident inside it keeps `no_data` for the detector.
* **Recording.** A background task records incidents every 15 s, whether or not the dashboard is open, so a crash mid-incident loses at most 15 s of updates. An open incident (`source: live`) is updated in place; 2 minutes after it closes it is **frozen** (`source: stored`) and served exactly as recorded, never recomputed, so evidence that has since left the EVE files (rotation, the 2 MB startup backfill) or the in-memory history cannot be lost or rewritten.
* **No duplicates.** An incident is matched by attack type and time overlap, not by an id built from its first alert, so regrouping the same alerts after a restart updates the stored incident instead of creating a second one. Supporting alerts are keyed by time, signature, source, sensor and interface, so replaying them is a no-op. A detector episode with no Suricata alert is not recorded as a separate "ML only" incident if a stored Suricata-based incident covers the period (the restart test found exactly this bug), and an open ML-only record is dropped if Suricata alerts later cover it.
* **Never worse, never invented.** If a recomputed open incident rests on fewer real signals than the stored one (typically because history was missing after a restart), the stored record is kept and the new alerts are still added as evidence. Missing signals are stored as `no_data`. Whether an incident is `active` or `closed` is recomputed when read.
* **Failure is not fatal.** If the file cannot be opened the engine runs in memory only and says so (`/incidents` reports `persistence.enabled: false`, and the card shows a warning). A damaged file is renamed `state.db.corrupt-<time>` and a fresh one started. `GET /incidents/{id}` returns one stored incident with its supporting alerts.

##### Guarded policy across a restart

The guarded policy used to restart at the baseline cap with nothing learned. Measured with an HTTP flood running: the rate limiter kept its lowered cap while the engine was down, then the restarted engine served the 500 req/s baseline and the limiter was fully open for about 11-14 s until the guard had seen three flagged polls again; and with the learned legitimate peak gone, the protective cap fell back to the fixed 50 req/s instead of 6x that peak, which would throttle legitimate traffic peaking above about 8 req/s. So the policy's cap, state and learned normal load are saved every poll (one row, `policy_state`) and restored at startup (`defense/policy_state.py`), under these rules so a stale setting can never restrict legitimate traffic:

* Used only if it was saved under the same settings (baseline, minimum cap, headroom, fallback cap, poll interval, memory length) **and the same model**; otherwise it is discarded.
* The cap and the mitigating/normal state come back only if the snapshot is at most 120 s old. Older than that, the cap starts at the baseline (the attack may be over) and only the learned normal load is kept.
* The learned normal load is kept only while the policy would have remembered it anyway (5 minutes): each remembered poll is dropped once its age plus the downtime exceeds that. Nothing older is used; a snapshot from the future or a malformed one is discarded.
* The decision counters restart at zero: a restored policy leaves mitigation only after four fresh calm polls with nothing rejected, and the cap then climbs back by the normal recovery factor, so a restored cap outlives an attack by the usual recovery time at most. `update()` and every threshold are unchanged. `/health` reports `policy_restore` (mode, reason, age).

Limits: only the two layers above plus this policy snapshot are persisted. The policy still cannot protect the seconds the engine is down, and the limiter holds its last cap during that time (existing behaviour, unchanged); if the engine stays down longer than 120 s with an attack still running, it restarts at the baseline and re-detects as before. Prometheus evidence for an incident is fetched while it is open and frozen with it; if Prometheus was down at that time it is stored as `no_data`, not refetched later. Deleting the `defense-state` volume (`docker compose down -v`) deletes the history.

### Detection pipeline

The classifier is trained and evaluated on the **same live features the defense engine scores in production**. Both read the engine's feature log: every 5 seconds `defense-engine` computes six features from Prometheus (`classifier/live_features.py`: request rate, p95 latency, inter-arrival time, error rate, active connections, and ESTABLISHED TCP sockets on the web port) and appends the vector, its confidence and the rate limit it set to `defense/feature_log.jsonl` (git-ignored).

`established_connections` comes from `target_http_established_sockets`, a gauge the web target reads from `/proc/net/tcp` and Prometheus already scrapes. Unlike the request metrics it sees Slowloris's half-open connections, which never reach the application.

The recordings in the Docker volume `ddos-attack_attacker-recordings` (one `*.jsonl` plus a `*.meta.json` with the run's real start and end time per run) say *when* each kind of traffic ran; a logged sample takes the label of the run whose time span contains it. The first 15 s and last 20 s around a run are not labeled (Prometheus rate windows still contain the previous state); samples outside every run are labeled idle. A recording's label comes from its own events (`legitimate_load` is normal, anything else is an attack), and a recording is **excluded, with the reason printed**, if it is empty, mixed-label, mostly unparseable, an HTTP run the target never answered, or has no feature-log samples (for example, recorded before the feature log existed). Nothing is deleted or skipped silently.

Record legitimate runs with the engine running, train on some of them, then evaluate on everything else. The evaluator never scores the runs the model was trained on:

```bash
docker compose run --rm --entrypoint python \
  defense-engine classifier/train.py --legit-runs <legit_run> [<legit_run> ...]

docker compose run --rm --entrypoint python \
  defense-engine classifier/evaluate.py --output classifier/evaluation.json
```

Legitimate traffic for training should vary: `legit-load` accepts `CONCURRENCY`, `THINK_SCALE` (below 1 means busier users), `PATHS` (weighted, e.g. `/:6,/work:3,/health:1`; `/work` does CPU work) and `KEEPALIVE=false` (a new connection per request), and the default command adds a flash-crowd burst. `classifier/audit.py` prints exactly which recordings and how many live feature samples a model was trained on, confirms its feature names match the live engine's, and shows each feature's spread in the training data (a feature that is constant there cannot be used by the forest). In this topology the legitimate clients' connections end at the rate limiter, so `active_connections`, `error_rate` and `established_connections` stay constant however the load varies.

Training stores each feature's min/max. At scoring time a value beyond the training maximum is scored by how far past the range it is, because an IsolationForest alone cannot split a feature that was constant in training and does not extrapolate beyond the range it saw.

The report has two separately labeled sections, both shown on the dashboard's **Analytics** page via `defense-engine`'s `/evaluation`:

* **Offline evaluation** -- samples logged while mitigation was inert (`MIN_RATE_LIMIT` at the baseline), re-scored with the trained model. Per traffic type: precision, recall, F1, false-positive rate and sample counts, with types under 10 samples flagged as low-sample. Detection only.
* **Live end-to-end** -- samples logged with mitigation active and a model loaded, using the engine's own confidence: the lowest rate limit it set and, for HTTP runs, how many requests were actually answered 429, including legitimate ones.

`train.py --contamination` sets the decision boundary (default 0.05) and `--idle-windows START:END` adds recorded no-traffic periods as normal; both are stored in the model. Write experiments to separate files with `MODEL_PATH=` and `--output` so earlier models and reports stay as baselines.

Use `--runs <run> ...` to restrict the evaluation and `--threshold` to change the attack cut-off (default 0.5). Without a report Analytics shows an empty state, never an estimate. Older recordings made before the feature log existed stay in the volume and are listed as not scored.

## Threat Intelligence

`services/threat-intel` is a separate FastAPI service (port `9400`) that ingests public feeds, normalizes them into one event schema, deduplicates and scores them, and stores them in PostgreSQL (Redis for caching and WebSocket fan-out).

| Provider | Key needed | Default poll |
|---|---|---|
| ThreatFox | no | 5 min |
| CISA KEV | no | 1 h |
| Spamhaus DROP | no | 1 h |
| Emerging Threats Open | no | 15 min |
| NVD CVE | no | 15 min |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 15 min |
| AlienVault OTX | `OTX_API_KEY` | 10 min |

Key-gated providers disable themselves when their key is empty. Geolocation uses MaxMind GeoLite2 when `MAXMIND_LICENSE_KEY` is set.

**API**

* `GET /health`
* `GET /api/threats/{live,map,countries,types,timeline,search,stats}`
* `GET /api/threats/correlation`
* `GET /api/providers/status`, `GET /api/geoip/status`
* `WS /ws/threats`

**Correlation.** `/api/threats/correlation` compares five live sandbox features from `defense-engine` with the number of recent high-confidence IOCs. It returns a heuristic similarity percentage and always carries a disclaimer: it is **not attribution** and never names an actor, campaign, or indicator. If `defense-engine` is unreachable it returns `available: false` rather than an error.

**Configuration** (environment variables, see `services/threat-intel/app/settings.py`): `DATABASE_URL`, `REDIS_URL`, `DASHBOARD_ORIGINS`, `*_POLL_SECONDS`, `CONFIDENCE_WINDOW_HOURS`, `DEFENSE_ENGINE_METRICS_URL`, `CORRELATION_MIN_CONFIDENCE`, `CORRELATION_WINDOW_HOURS`, `GEOIP_DB_DIR`.

**Database migrations.** The schema is managed with Alembic (`services/threat-intel/migrations`) and applied automatically at startup. Databases created before Alembic was added are stamped at the baseline revision without being altered. To change the schema, edit `app/common/models.py`, then:

```bash
cd services/threat-intel
alembic revision --autogenerate -m "describe the change"   # review the generated file
alembic upgrade head
```

```bash
docker compose up -d --build threat-intel
curl http://localhost:9400/health
```

## Dashboard

The React dashboard provides:

* Global Threat Intelligence
* 3D threat visualization
* Threat feed and filtering
* Analytics
* Alerts
* Sandbox Lab controls
* Service health monitoring

Start the dashboard with:

```bash
docker compose up -d --build dashboard
```

Dashboard: `http://localhost:8080`

## Kubernetes

Kubernetes manifests are provided under `infra/k8s/`, including network-isolation policies and verification jobs.

```bash
kubectl apply -f infra/k8s/00-namespace-and-networkpolicy.yaml
kubectl apply -f infra/k8s/verify-isolation-job.yaml

kubectl wait --for=condition=complete job/verify-isolation \
  -n sentinel-lab --timeout=60s
```

## Tests and CI

```bash
# Classifier and detection-metric tests
pip install -r tests/requirements.txt -r defense/requirements.txt
pytest tests

# Threat-intel backend (database, Redis and defense-engine are mocked;
# migration tests also run when MIGRATION_TEST_DATABASE_URL points at a
# throwaway Postgres whose database name contains "test" -- they reset its schema)
cd services/threat-intel && pip install -r requirements-dev.txt
mypy --ignore-missing-imports app && pytest

# Dashboard
cd dashboard && npm ci --legacy-peer-deps
npm run typecheck && npm run lint && npm run build
```

GitHub Actions runs all of the above, plus `ruff` and the network-isolation smoke test.

## Known limitations

* Rate limiting, measured in the lab with the cap held fixed at 40 req/s (below the ~105 req/s flood) and no classifier: the `global` policy blocked 97-100% of a legitimate client's requests during a flood, the `fair` policy 10-15% for a light client (about 3 req/s) and 8% for a moderate one (about 15 req/s) under a single-source flood. Both admitted at most the cap and blocked about the same share of attacker traffic (about 98%). Under a 6-address flood a moderate legitimate client (above its fair share of about 5.7 req/s) still lost 46% under `fair` (99% under `global`): per-source fairness cannot protect a client that needs more than its share when the attacker holds many addresses. UDP, TCP-exhaustion and Slowloris traffic does not pass through the rate limiter at all, so only the (lowered) cap, not the attack, is affected.
* Limitations of the selected default (measured above): 20-29 s pass from the start of a flood until the first request is rejected, so the start of every attack is unmitigated; only about half of a flood is suppressed (53-64 req/s still admitted against about 115 unmitigated); concurrent legitimate clients lose 1.3% under a single-source and 6.7% under a six-source flood, and would lose more if their demand grew relative to the cap; the protective cap is 6x the recent peak of normal load, so floods below that level, or sites whose legitimate peak is close to the flood's rate, are not constrained; the candidate model flags about 8% of legitimate samples in its offline evaluation; and only one legitimate load level (about 9 req/s, 20 users) and one run per scenario were tested, with no variance estimate beyond one repeated configuration.
* **The rate limiter protects HTTP traffic only.** UDP flood, TCP exhaustion and Slowloris are detected but not mitigated: they do not pass through the limiter, and no separate defense for them exists or has been tested. A detection of one of them still lowers the HTTP cap.
* How much load counts as "legitimate" is a policy choice the data cannot settle: a legitimate run at 56 req/s (training coverage up to that) made the lab's ~67 req/s floods indistinguishable by request rate (HTTP flood recall fell to 64%). The shipped candidate is trained on legitimate load up to about 32 req/s, so legitimate peaks above that (45 users, about 35 req/s) are partly flagged. The range guard scores anything above the training maximum as anomalous.
* In this topology legitimate clients' connections end at the rate limiter, so `active_connections`, `error_rate` and `established_connections` are constant in all legitimate training data whatever the load. The forest cannot use them; only the range guard does.
* Candidate results come from small samples (a few dozen overlapping 5-second samples per type; UDP and TCP exhaustion are low-sample) and two design choices (excluding the 56 req/s run, contamination 0.005 chosen by leave-one-run-out on the training runs) were made after seeing earlier evaluation results, so they were checked on runs recorded afterwards.
* All training and test traffic is synthetic lab traffic generated by `attackers/` inside the isolated network. It is not real-world traffic and does not come from any third party, Cloudflare included. Aggregated public threat data such as Cloudflare Radar could be considered for the threat-intelligence module as context, but it is not suitable as raw training data for this classifier.
* Suricata alerts are advisory: they are displayed and correlated with the ML detector, and never change the rate limit (see *Suricata alerts*). The taps see one replica each (a third of `web`, half of `dns-udp` and `tcp-service`), the thresholds rest on two calibration runs per scenario, and the TCP-exhaustion margin is thin (see *Suricata alerts*).
* Wazuh rules and decoders exist under `defense/wazuh/` as a configuration stub; no Wazuh manager is deployed.
* `infra/k8s` and `infra/terraform` are unverified; Docker Compose is the supported way to run the lab.

---

**Built with Python, React, TypeScript, Docker, Kubernetes, and security-focused observability tools.**
