# SENTINEL LAB — Project Execution Plan

**This is the single source of truth for this project.** It exists so any
future Claude session (or any other AI assistant, or a new human
contributor) can pick up development without access to the conversation
history that produced this codebase.

> **Rule for future contributors: always read this file (`PROJECT_EXECUTION_PLAN.md`) in full before implementing anything.**
> If anything in this document conflicts with what you find in the actual
> code, the code is the current ground truth for *what exists*, but this
> document is the ground truth for *why it exists that way and what must
> not change without explicit human approval*. If you find a conflict,
> stop and ask rather than silently resolving it either direction.

---

# Project Overview

## Purpose

SENTINEL LAB is being transformed from a single-purpose DDoS
attack-simulation/detection sandbox into a two-module **Cyber Threat
Intelligence & DDoS Defense Platform**, portfolio-grade and resembling a
professional Security Operations Center (SOC) product.

The two modules:

1. **Sandbox Lab** (pre-existing, must never be weakened) — an isolated
   Docker environment that simulates DDoS attacks (HTTP flood, UDP flood,
   Slowloris, TCP exhaustion) against synthetic targets, detects them with
   a trained ML classifier, and adaptively rate-limits them. Physically
   incapable of sending traffic outside its own Docker networks.
2. **Global Threat Intelligence** (new) — a read-only service that
   ingests real public threat-intel feeds (ThreatFox, CISA KEV, Spamhaus
   DROP, Emerging Threats Open, NVD CVE, AbuseIPDB, AlienVault OTX),
   normalizes/deduplicates/scores them, geolocates them, and serves them
   over REST/WebSocket to a new SOC-style dashboard with a 3D threat globe.

The two modules are **completely separate but integrated**: separate
Docker networks, separate codebases, separate failure domains — but
presented as one unified dashboard, and connected by one deliberate,
narrow integration seam (the correlation engine in Stage I, which reads
sandbox telemetry over a network they both happen to share, without ever
joining the sandbox's isolated internal networks).

## High-level architecture

```
                    ┌───────────────────────────────────────────────┐
                    │            public_net (bridge)                 │
                    │  Grafana :3000   Prometheus :9090  Globe :8090 │
                    │  dashboard (new React SPA) :8080                │
                    │  threat-intel :9400  (also on threatintel_net)  │
                    └───────────────┬─────────────────────────────────┘
 ┌────────────────────┐   ┌─────────┴──────────────────────┐  ┌──────────────────┐
 │  attacker_net       │   │      target_net (internal)     │  │  threatintel_net  │
 │  (internal: true)   │   │  lb → web x3, tcp-service,      │  │  (bridge)         │
 │  attacker-* profiles│◀─▶│  dns-udp, defense-engine,       │  │  threat-intel-db  │
 │  (NO route out)     │   │  rate-limiter, prometheus,      │  │  threat-intel-    │
 │                     │   │  suricata                        │  │  redis            │
 └─────────────────────┘   └──────────────────────────────────┘  └──────────────────┘
```

`threat-intel` (and its DB/Redis) is the ONLY new thing attached to
`threatintel_net`; it also sits on `public_net` (shared with the
dashboard and, deliberately, with `defense-engine` — see Stage I). It is
**never** attached to `attacker_net` or `target_net`.

## Major modules and how they interact

| Logical module | Physical location | Role |
|---|---|---|
| Sandbox Lab | `attackers/`, `defense/`, `targets/`, `globe/`, `observability/`, `infra/`, `tests/` (all pre-existing, unmodified except one CORS addition in Stage H) | Attack simulation, ML detection, adaptive rate limiting, metrics |
| Global Threat Intelligence | `services/threat-intel/` (new) | Public feed ingestion, normalization, dedup, geolocation, REST/WS API |
| Dashboard | `dashboard/` (new, not yet built — Stage E+) | Unified SOC UI: 3D globe, sandbox controls, analytics |
| Integration seam | `app/api/routes_correlation.py` (Stage I, not yet built) | Compares sandbox telemetry to global threat data — read-only, no attribution |

`globe/server.py` (pre-existing FastAPI app on port 8090) keeps running
unmodified as the sandbox's control API — it shells out to `docker
compose` (via a mounted `docker.sock`) to start/stop the profile-gated
`attacker-*` containers. The new dashboard becomes a second client of
this same API rather than replacing it; the legacy `globe/index.html` UI
keeps working throughout every stage.

---

# Architecture Decisions

These are the decisions that were explicitly discussed and approved.
**None of these should be changed without explicit human approval** — if
a future stage seems to require changing one of these, stop and ask
rather than redesigning silently.

## 1. Docker network isolation (pre-existing, must never weaken)

- `attacker_net` and `target_net` are `internal: true` — no NAT/route to
  the internet at the kernel level, not an application-layer check.
- `public_net` is a normal bridge network for dashboards only; nothing on
  it can originate attack traffic.
- `tests/test_network_isolation.sh` is the empirical proof of this and
  is step 1 of CI. **It must keep passing, unmodified, after every
  stage.**
- The new `threatintel_net` (bridge, non-internal) is a *third* isolated
  network, used only by `threat-intel`/`threat-intel-db`/
  `threat-intel-redis`. It is separate from, and has no bridge to,
  `attacker_net`/`target_net`. `threat-intel` also sits on `public_net`
  for dashboard/API access and the Stage I correlation read, but is
  **never** added to `attacker_net` or `target_net`.

## 2. Threat Intelligence service architecture

- New top-level directory `services/threat-intel/`, NOT a rewrite/move of
  any existing sandbox code.
- Internal structure: `app/common/` (DB models, normalized schema,
  dedup/confidence logic, caching), `app/provider/` (one connector module
  per feed, self-registering), `app/api/` (REST/WS routes). This
  satisfies the user's requested `common/provider/api` split without
  forcing a repo-root rewrite of working sandbox code.
- FastAPI + PostgreSQL (async SQLAlchemy + asyncpg) + Redis (caching +
  pub/sub for live events) + APScheduler (per-provider independent poll
  intervals).
- **No Alembic.** The rest of the repo has zero migration tooling
  (`defense/classifier` just loads a joblib file); schema is created via
  `Base.metadata.create_all()` on startup. This only *creates missing
  tables*, it does **not** `ALTER` existing ones — a real consequence:
  if you add a column to an ORM model in a later stage, you must also
  manually `ALTER TABLE` any already-populated persistent database, or
  document that a fresh volume is required. This was an accepted
  tradeoff for a schema still under active development; revisit if the
  schema stabilizes and a real deployment needs safe migrations.
- Read-only posture: the service only ever makes outbound HTTPS requests
  to download public feeds (or the MaxMind GeoLite2 database). It never
  writes to the sandbox, never sends attack traffic, and has no code path
  that could.

## 3. Sandbox architecture (pre-existing, preserve exactly)

- Everything under `attackers/`, `defense/`, `targets/`, `globe/`,
  `observability/`, `infra/`, `reports/`, `tests/` is considered
  **production-stable** and must not be rewritten.
- The only two approved surgical edits to this code, across the entire
  project:
  1. Stage H (not yet done): add `CORSMiddleware` to `globe/server.py`,
     origins from a new `DASHBOARD_ORIGIN` env var — mirrors the pattern
     already used in `defense/engine.py`. This is the ONLY functional
     change to this file.
  2. UI-only improvements are permitted per the original request ("Nothing
     here should change except UI improvements") but no backend/attack
     logic changes.
- The legacy `globe/index.html`/`app.js` UI must keep working, unmodified,
  through every stage — it is not replaced, just supplemented by the new
  dashboard which becomes a second client of `globe/server.py`'s JSON API.

## 4. React SOC dashboard architecture (Stage E+, not yet built)

- New top-level `dashboard/` directory: Vite + React + TypeScript +
  Tailwind + Framer Motion, built as a static SPA, served by nginx in
  production (multi-stage Docker build).
- State: `zustand` for client-side live-event/filter state,
  `@tanstack/react-query` for server-state/REST caching.
- Charts: `recharts`.
- Routing/sidebar: Overview, Global Threat Intelligence, Sandbox Lab,
  Analytics, Alerts, Settings (exact sidebar structure specified by the
  original request).
- The Sandbox Lab page is **ported natively** into the React app — it
  calls `globe/server.py`'s existing JSON endpoints directly
  (`/api/feed`, `/api/attacks/status`, `/api/attacks/{type}/start|stop`),
  NOT iframed. This was an explicit choice over iframing, made to keep
  visual consistency with the new SOC dashboard while leaving all
  Docker/attack orchestration logic in `globe/server.py` untouched.
- Dev-mode Vite proxy and prod-mode nginx reverse proxy both route
  `/api/threats/*` → `threat-intel:9400`, `/api/sandbox/*` →
  `globe:8090`, `/ws` → `threat-intel:9400`'s WebSocket, `/grafana/*` →
  `grafana:3000` — keeping the browser same-origin in production so CORS
  is only strictly needed for the Vite dev server.

## 5. GeoLite2 enrichment architecture (Stage C.5 — IMPLEMENTED)

Formally evaluated three options (local MaxMind GeoLite2 DB, public
geolocation APIs, hybrid) against licensing, update frequency,
performance, privacy, Docker deployment, offline capability, and future
scalability. **Decision: local MaxMind GeoLite2 (City + ASN databases) is
the primary and default enrichment path. A public API is an optional,
off-by-default fallback reserved for future interactive single-IP
lookups only — never for bulk ingestion.**

Rationale (do not re-litigate without a strong new reason):
- Local `.mmdb` lookups are in-memory, microsecond-scale, and handle the
  volumes this service actually produces (1,600+ CVEs, 1,600+ Spamhaus
  networks, 600+ ET IPs observed in a single real ingestion cycle) with
  zero rate-limit risk.
- Public geolocation APIs' free tiers (e.g. 45 req/min) cannot sustain
  that volume without paid tiers or hours of delay.
- Local lookups keep the service's external-communication footprint at
  "periodic bulk download of a public dataset," matching the same shape
  as every provider connector — not a new kind of live third-party
  dependency in the hot ingestion path.
- Zero per-lookup network traffic to a third party is also the better
  privacy posture: it doesn't continuously leak every observed malicious
  IP to an external service.

Implementation as built:
- `app/common/geoip.py` — `GeoIpEnricher`, lazily loads
  `GeoLite2-City.mmdb` (required) and `GeoLite2-ASN.mmdb` (optional — if
  absent, country/city/lat/lon still work, only asn/organization stay
  empty). Self-disables per-database, never raises. Never geolocates
  private/loopback/link-local/reserved/multicast addresses (no fabricated
  data).
- `app/geoip_updater.py` — its own `AsyncIOScheduler`, entirely separate
  from the provider ingestion scheduler (this is infrastructure the
  enrichment subsystem depends on, not a threat-intel provider). Downloads
  both editions from MaxMind's direct-download URL, extracts the `.mmdb`
  from the tar.gz, writes to a `.tmp` file and atomically renames into
  place (a cancelled download can never leave a truncated database). Runs
  daily by default (`GEOIP_UPDATE_POLL_SECONDS=86400`); MaxMind itself
  republishes GeoLite2 twice weekly. Self-disables cleanly (logs once,
  attempts no download) when `MAXMIND_LICENSE_KEY` is unset.
- `app/common/geo_cache.py` — Redis, keyed by IP address, 30-day TTL,
  caches negative results too (so a permanently-unresolvable address
  isn't retried against the local DB either). This exists *in addition
  to* `iocs.geo_enriched_at` because the same IP can appear across
  multiple `Ioc` rows (dedup key is `(ioc, threat_type)`, so one IP
  flagged by two different feeds under two different threat types is two
  separate rows) — the cache means the second row is a cache hit, not a
  second lookup.
- `app/enrich.py` — the standalone enrichment pass, deliberately its own
  module rather than folded into `dedup.merge_or_insert`, per explicit
  instruction to keep this subsystem independently testable/verifiable.
  `app/ingest.py` calls `enrich_ioc(session, ioc)` exactly once, right
  after `merge_or_insert` — that one call is the entire integration
  surface.
- `app/geo_fallback.py` — built and self-disabling
  (`GEOIP_FALLBACK_API_ENABLED`, default `false`, uses ip-api.com) but
  **not yet wired into any endpoint**. Deciding exactly where an
  "interactive single-IP lookup" should trigger it is a UX/dashboard-stage
  decision, deliberately left open rather than guessed at. A future stage
  should wire this into a specific on-demand lookup path (e.g.
  `/api/threats/search` when local DB has no entry AND the flag is on),
  not into the bulk ingestion loop.
- Schema: `iocs.city`, `iocs.geo_source` (`'geolite2'` | `'fallback_api'`
  | `NULL`), `iocs.geo_enriched_at` (`NULL` until an enrichment attempt
  was made — set even on a negative/no-data result, so nothing is retried
  every cycle forever).
- `GET /api/geoip/status` — transparency endpoint reporting
  `license_key_configured`, `city_db_present`, `asn_db_present`,
  `enrichment_available`, `fallback_api_enabled`.

## 6. Provider plugin architecture (Stage B — IMPLEMENTED)

- `app/provider/base.py` defines the `ThreatProvider` ABC + a module-level
  `PROVIDER_REGISTRY: list[type[ThreatProvider]]` + a `@register_provider`
  decorator that appends to it.
- Adding a new provider = one new file (subclassing `ThreatProvider`,
  decorated with `@register_provider`) + one import line in
  `app/provider/__init__.py`. That import list is the single place that
  has to change to add or remove a provider.
- Each provider declares `name`, `requires_key`, `poll_interval_seconds`,
  `event_kind` (`"ioc"` or `"cve"` — CVE-keyed feeds like CISA KEV/NVD
  persist to a separate `cves` table since they have no IP/coordinates),
  and implements `async fetch(client, settings) -> list[ThreatEvent] |
  list[CveEvent]`.
- **Fault isolation is enforced at the connector level, not just by the
  scheduler**: every connector catches its own request/parsing errors
  internally and returns `[]` rather than raising — this was verified by
  a real ThreatFox DNS-resolution failure in this environment which
  degraded to 0 events without affecting any other provider, both in unit
  tests and live in Docker. The ingestion scheduler (`app/ingest.py`) adds
  a second, belt-and-suspenders layer on top (catches around the whole
  fetch+persist cycle) in case a bug ever appears outside a connector's
  own try/except.
- Key-gated providers (`AbuseIPDB`, `OTX`) self-disable via
  `is_enabled(settings)` returning `bool(settings.<KEY>)` — checked both
  at startup (so the scheduler never even schedules a disabled provider)
  and defensively inside `fetch()` itself (so calling it directly, e.g.
  by mistake or in a test, is still a safe no-op).
- Seven providers currently implemented: `threatfox`, `cisa_kev`,
  `spamhaus_drop`, `emerging_threats`, `nvd_cve` (all enabled by default,
  no key required), `abuseipdb`, `otx` (both require a free key via
  `ABUSEIPDB_API_KEY`/`OTX_API_KEY`, disabled otherwise).

## 7. Redis / WebSocket design (Stage C — IMPLEMENTED)

- Redis serves two purposes, kept in one thin wrapper
  (`app/common/cache.py`): JSON key/value caching with TTLs (30-60s) for
  expensive aggregate REST queries, and pub/sub as the live-event
  fan-out backbone.
- `app/ingest.py` publishes every newly persisted IOC event to the
  `threats:live` Redis channel. `app/api/routes_ws.py`'s
  `WebSocket /ws/threats` handler subscribes to that channel and forwards
  each message verbatim. This decouples the WS layer from the scheduler
  entirely — chosen specifically so that if this service is ever scaled
  to multiple uvicorn workers, every worker's WS clients still see every
  event, because Redis (not in-process state) is the fan-out point.
- Confirmed working live: published a message directly to the Redis
  channel and observed a connected WS client receive the exact JSON
  payload.

## 8. Safety constraints (apply to every stage, non-negotiable)

- No attack traffic may ever leave the Docker sandbox's isolated
  networks. `threat-intel` is read-only and may only download public
  threat feeds (and the MaxMind database) over HTTPS.
- `threat-intel` must never be attached to `attacker_net` or
  `target_net`.
- No feature in the Global Threat Intelligence module may transmit attack
  packets anywhere, including to the sandbox.
- No fabricated/synthetic threat data: if a provider is unreachable or a
  geolocation lookup finds nothing, the correct behavior is an empty
  result — never a placeholder or invented value. (Verified repeatedly:
  ThreatFox/OTX degrade to 0 events; unresolvable IPs degrade to `None`
  geo fields; the correlation engine, when built, must express
  observation, not attribution.)
- The Stage I correlation engine, when built, must never claim
  attribution — only observable feature similarity, via a fixed
  observation-string template that never interpolates a specific
  identity/actor.

## 9. Deployment assumptions

- Docker Desktop / Docker Engine + Compose v2, same as the existing
  sandbox.
- `threat-intel` needs outbound HTTPS to: `threatfox-api.abuse.ch`,
  `www.cisa.gov`, `www.spamhaus.org`, `rules.emergingthreats.net`,
  `services.nvd.nist.gov`, `api.abuseipdb.com` (if keyed),
  `otx.alienvault.com` (if keyed), `download.maxmind.com` (if
  `MAXMIND_LICENSE_KEY` set). In a sandboxed dev environment, some of
  these hosts may be DNS-blocked (observed for `threatfox-api.abuse.ch`
  and `otx.alienvault.com` in this project's development environment) —
  this must degrade gracefully (see fault-isolation above), not be
  treated as a code bug, if reproduced elsewhere.
- No live `MAXMIND_LICENSE_KEY` was available during development; Stage
  C.5's tests and demonstrations used real MaxMind-format `.mmdb` test
  fixtures built with the `mmdb_writer` package
  (`services/threat-intel/tests/fixtures/`), not the real GeoLite2
  database. A real key should be supplied via `MAXMIND_LICENSE_KEY` in
  any real deployment; everything is built to "just work" once it is.

---

# Execution Rules

These rules were established explicitly and have been followed for every
stage so far. **Continue following them for every subsequent stage.**

1. **One stage at a time.** Implement exactly one lettered/numbered stage
   per work session. Do not start the next stage until the current one is
   explicitly approved.
2. **A stage is not "done" until it**: builds successfully, passes lint
   (`ruff check`), passes type-checking (`mypy --ignore-missing-imports`),
   starts correctly in Docker, exposes its expected endpoints/behavior,
   and introduces no breaking change to existing functionality.
3. **Verify in Docker, not just locally.** Build the actual image, run it
   against throwaway Postgres/Redis containers (or the real stack once
   Stage D wires `docker-compose.yml`), and exercise the real endpoints —
   don't rely on unit tests alone to claim a stage works.
4. **After every stage, stop and report**: what was implemented, every
   file added, every file modified (and *why* — each modification to a
   previously-completed stage's files must be justified as either a
   necessary bug fix or an explicitly-approved extension), manual
   verification steps, Docker commands to reproduce them, and any
   assumptions made. Then wait for explicit approval before continuing.
5. **Never rewrite a completed stage's working code** unless a real bug
   is found in it (see below) or the user explicitly approves an
   extension (e.g. adding `upsert_cve` to `dedup.py` in Stage C was an
   *addition*, not a rewrite of `merge_or_insert`).
6. **When a real bug is found during verification of a later stage**,
   fix it, but explain the root cause and keep the fix minimal and
   targeted. Example precedent: Stage C's shutdown handling had a real
   bug (APScheduler's `AsyncIOExecutor.shutdown()` unconditionally
   cancels in-flight job futures regardless of its `wait` argument) found
   by deliberately testing shutdown-during-ingestion, not by code review
   alone — the fix was to track in-flight tasks and `pause()` the
   scheduler before waiting for them, rather than calling `shutdown()`
   first. Read `services/threat-intel/app/ingest.py`'s `stop_scheduler`
   docstring for the full account before touching scheduler
   shutdown/lifecycle logic again.
7. **Backwards compatibility.** Anything already working must keep
   working after a new stage — re-run all previous stages' tests every
   time, don't just test the new stage in isolation.
8. **Update `README.md` in the same stage that introduces a new
   module/service or user-visible capability.** Don't let documentation
   drift behind the code.
9. **Cross-cutting requirements for every new backend service** (applies
   to `threat-intel` and to anything added later):
   - `GET /health` endpoint.
   - Structured logging via `app/logging_config.py`'s
     `configure_logging()`/`get_logger()` pattern (stdlib `logging`,
     consistent formatter, level from `settings.LOG_LEVEL`).
   - All configuration via environment variables through
     `app/settings.py`'s `Settings`/`get_settings()` — no hardcoded
     secrets/URLs anywhere else.
   - Graceful startup/shutdown via FastAPI's `lifespan` context manager:
     cleanly open/close the DB engine, Redis connection, and any
     scheduler. See the Stage C bug-fix precedent above before assuming
     "just call `.shutdown()`" is graceful for APScheduler.
   - A Docker `HEALTHCHECK` in the service's `Dockerfile` hitting
     `/health` (using Python's stdlib `urllib`, since the `python:*-slim`
     base images don't include `curl`).
   - Every connector/plugin unit is independently testable and must
     catch its own errors — one failing must never crash the service or
     block another. A missing API key/credential disables only that one
     unit, never the whole service.
   - No fabricated data, ever, in any subsystem.
10. **No secrets in the repo.** `services/threat-intel/.env` is
    gitignored; document required env vars in `README.md` /
    `docs/threat-intel.md` (Stage J) instead of committing example
    values with real-looking keys.
11. **If anything looks architecturally inconsistent once real code is in
    front of you, ask before silently redesigning it.** This has already
    happened once productively: the original plan said connectors return
    only `ThreatEvent`, but Stage A's schema already anticipated a
    separate `cves` table — Stage B's implementation surfaced that gap
    and `ThreatProvider`'s interface was extended (additively) to support
    `CveEvent` too, rather than forcing CVE data into the IP-shaped
    schema.

---

# Stage Roadmap

Stages A through C.5 are **implemented and approved**. Stages D through J
are **planned but not yet built** — the descriptions below are the
approved design to implement, not a description of existing code.

## Stage A — Threat-intel backend skeleton, DB schema, provider registry
**Status: ✅ Complete**

- **Objective**: stand up the `services/threat-intel/` FastAPI service
  skeleton with the normalized data model and the provider plugin
  interface, before any real connector exists.
- **Deliverables**: `Dockerfile`, `requirements.txt`, `app/settings.py`,
  `app/logging_config.py`, `app/common/schema.py` (`ThreatEvent`,
  `CveEvent` Pydantic models), `app/common/db.py` (async engine/session,
  `init_db`/`dispose_engine`), `app/common/models.py` (`Ioc`,
  `IocSighting`, `Cve` ORM tables), `app/common/dedup.py`
  (`merge_or_insert`), `app/provider/base.py` (`ThreatProvider` ABC +
  registry), `app/main.py` (health check, lifespan-managed
  startup/shutdown, CORS).
- **Verification requirements**: `ruff`/`mypy` clean; Docker build
  succeeds; container starts against throwaway Postgres/Redis; `/health`
  returns 200; all three tables (`iocs`, `ioc_sightings`, `cves`) actually
  created (confirmed via `psql \dt` — this caught a real bug where the
  ORM models module was never imported, so `Base.metadata` was empty);
  clean shutdown with no errors.
- **Completion criteria**: met and approved.

## Stage B — Provider connectors
**Status: ✅ Complete**

- **Objective**: implement all seven provider connectors behind the
  Stage A registry interface.
- **Deliverables**: `app/provider/{threatfox,cisa_kev,spamhaus_drop,
  emerging_threats,nvd_cve,abuseipdb,otx}.py`, `app/provider/http.py`
  (shared retrying HTTP client), `app/provider/__init__.py` updated to
  import all seven.
- **Verification requirements**: 15 unit tests (mocked HTTP via
  `respx`), including a dedicated fault-isolation test proving one
  provider's total failure doesn't affect the others; live smoke test
  against real public feeds (not mocks) confirming real data volumes;
  Docker verification of both the disabled-by-default and
  enabled-with-key log states for the two key-gated providers.
- **Completion criteria**: met and approved. Real live results at
  approval time: CISA KEV 1,638 CVEs, Spamhaus DROP 1,677 networks,
  Emerging Threats 666 IPs, NVD CVE 100 CVEs successfully fetched and
  normalized; ThreatFox/OTX degraded gracefully to 0 events due to a
  DNS-resolution restriction in the dev sandbox (not a code defect).

## Stage C — REST + WebSocket API, Redis caching, ingestion scheduler
**Status: ✅ Complete**

- **Objective**: actually call the Stage B connectors on a schedule,
  persist their output, and expose it over REST + WebSocket.
- **Deliverables**: `app/common/cache.py`, `app/ingest.py`
  (`AsyncIOScheduler`-driven per-provider polling, `start_scheduler`/
  `stop_scheduler`), `app/api/routes_threats.py` (`/api/threats/{live,
  map,countries,types,timeline,search,stats}`), `app/api/
  routes_providers.py` (`/api/providers/status`), `app/api/routes_ws.py`
  (`WebSocket /ws/threats`), `app/common/dedup.py` extended with
  `upsert_cve` (additive), `app/main.py` updated to mount routers and
  manage the scheduler's lifecycle.
- **Verification requirements**: full live pipeline test in Docker
  (real ingestion → real persistence → all REST endpoints → Redis cache
  hit confirmed → WebSocket delivery confirmed via a manually published
  Redis message); graceful-shutdown-during-ingestion specifically tested
  (not just graceful shutdown while idle) — this is what surfaced the
  APScheduler shutdown bug described in Execution Rule 6.
- **Completion criteria**: met and approved, including the shutdown bug
  fix (tracked in-flight tasks + `pause()`-then-wait-then-`shutdown()`,
  documented in `app/ingest.py`'s `stop_scheduler` docstring).

## Stage C.5 — Geolocation enrichment
**Status: ✅ Complete**

- **Objective**: enrich IOCs with country/city/lat/lon/ASN/organization
  using local MaxMind GeoLite2, as its own independently-testable
  subsystem, per the approved design in Architecture Decision #5 above.
- **Deliverables**: `app/common/geoip.py`, `app/common/geo_cache.py`,
  `app/enrich.py`, `app/geoip_updater.py`, `app/geo_fallback.py`,
  `app/api/routes_geoip.py`; `Ioc` model extended with `city`,
  `geo_source`, `geo_enriched_at` (additive); `ingest.py` extended with
  exactly one call to `enrich_ioc`.
- **Verification requirements**: 13 new unit tests, including against
  real MaxMind-format `.mmdb` test fixtures (not mocks of `geoip2`
  internals); live demonstration of enriching genuine ingested IOC rows;
  live demonstration that a second `Ioc` row sharing an IP is a cache hit
  (mocked `lookup()`, confirmed `call_count == 0`); demonstrated behavior
  with no database present, and separately with no license key present;
  re-verified all of Stage A/B/C's functionality and graceful shutdown
  still work unchanged (28/28 tests passing total).
- **Completion criteria**: met and approved.

## Stage D — docker-compose wiring
**Status: ✅ Complete**

- **Objective**: wire `threat-intel`, its Postgres, and its Redis into
  `docker-compose.yml` so the whole service can be brought up with
  `docker compose up`, on the correct (isolated) networks.
- **Expected deliverables** (see the approved design captured in the plan
  file the team has been working from — reproduced here):
  1. New network `threatintel_net: { driver: bridge }`.
  2. New services `threat-intel-db` (`postgres:16-alpine`) and
     `threat-intel-redis` (`redis:7-alpine`), both on `[threatintel_net]`
     only.
  3. New service `threat-intel` (`build: ./services/threat-intel`) on
     `[threatintel_net, public_net]`, port `9400`, env `DATABASE_URL`,
     `REDIS_URL`, `ABUSEIPDB_API_KEY: ${ABUSEIPDB_API_KEY:-}`,
     `OTX_API_KEY: ${OTX_API_KEY:-}`, `MAXMIND_LICENSE_KEY:
     ${MAXMIND_LICENSE_KEY:-}`. Add a comment block mirroring the
     existing top-of-file isolation note, explicitly stating this service
     is never attached to `attacker_net`/`target_net`.
  4. A named volume for `threat-intel-db`'s data and one for the GeoIP
     `.mmdb` files (`GEOIP_DB_DIR`, so they survive container restarts
     and don't need re-downloading every time).
  5. `dashboard` service is NOT part of Stage D (that's Stage E) — Stage D
     is backend-only wiring.
- **Verification requirements**: `docker compose up -d --build
  threat-intel-db threat-intel-redis threat-intel` brings the full
  service up cleanly (not throwaway test containers — the real compose
  stack); all REST endpoints reachable at `http://localhost:9400`;
  `docker inspect threat-intel` confirms `attacker_net`/`target_net` are
  absent from its network list; `bash tests/test_network_isolation.sh`
  still passes unchanged; existing sandbox services (`web`, `lb`,
  `defense-engine`, etc.) still start and behave exactly as before this
  change (no shared resource conflicts, e.g. port collisions).
- **Completion criteria**: full stack (`threat-intel` + its DB/Redis)
  runs via `docker compose up`, isolation verified, existing sandbox
  services unaffected.

## Stage E — React dashboard scaffold
**Status: ✅ Complete**

- **Objective**: stand up the `dashboard/` Vite+React+TypeScript+
  Tailwind+Framer Motion SPA shell — routing, sidebar, typed API client,
  WebSocket hook, state store — with no real page content yet.
- **Expected deliverables**: `dashboard/package.json` (react,
  react-dom, react-router-dom, typescript, vite, tailwindcss,
  framer-motion, three, @react-three/fiber, @react-three/drei, zustand,
  @tanstack/react-query, recharts, clsx), `vite.config.ts` (dev proxy to
  `threat-intel:9400` and `globe:8090`), `tailwind.config.ts`,
  `Dockerfile` (multi-stage: node build → nginx serving `dist/`, with
  `nginx.conf` reverse-proxying `/api/threats/*`, `/ws`,
  `/api/sandbox/*`, `/grafana/*`), `src/main.tsx`, `src/App.tsx`,
  `src/layout/{Sidebar,AppShell}.tsx` (routes: Overview, Global Threat
  Intelligence, Sandbox Lab, Analytics, Alerts, Settings),
  `src/routes/index.tsx`, `src/lib/api.ts`, `src/lib/ws.ts`
  (`useThreatStream` hook with reconnect/backoff), `src/types/threat.ts`
  (TS mirror of `ThreatEvent`, ideally generated from
  `threat-intel`'s `/openapi.json` via `openapi-typescript` for strong
  typing per the original requirements), `src/store/threatStore.ts`.
- **Verification requirements**: `npm run build` and a TypeScript
  typecheck pass cleanly; `docker compose up --build dashboard` serves a
  page at `http://localhost:8080` with working sidebar navigation between
  placeholder pages; dev-mode Vite proxy confirmed working against a live
  `threat-intel` instance.
- **Completion criteria**: an empty-but-navigable SOC shell is live,
  correctly proxying to the backend, before any page gets real content.

## Stage F — 3D globe
**Status: ✅ Complete**

- **Objective**: replace the sandbox's amCharts/globe.gl visualization
  concept with a modern react-three-fiber WebGL globe for the Global
  Threat Intelligence data (the Sandbox Lab's own visualization stays in
  `globe/server.py`'s existing UI per Architecture Decision #3/#4).
- **Expected deliverables**: `src/components/globe/ThreatGlobe.tsx`
  (`@react-three/fiber` Canvas, textured sphere, `OrbitControls` from
  drei), `ArcLayer.tsx` (animated arcs from `(lat,lon)` to a fixed
  destination marker, colored by threat type), `colorScale.ts`,
  `Tooltip.tsx` (hover: country/ip/threat_type/confidence/source/
  timestamp), `DetailPanel.tsx` (click → slide-in panel, calls
  `/api/threats/search?ip=`), `GlobeFilters.tsx` (country/type/
  confidence/feed/time, wired to the zustand store). New events arriving
  via `useThreatStream` mount transient fading-in arcs, auto-removed
  after a few seconds.
- **Verification requirements**: globe renders real data from
  `/api/threats/map` (requires Stage C.5 enrichment to have actually
  populated some coordinates — verify with real or test-fixture-enriched
  data); hover/click/filter interactions manually verified in a browser;
  live WS-driven arc animation manually verified by triggering a real or
  simulated ingestion event while the page is open.
- **Completion criteria**: an interactive, real-data-driven 3D globe,
  not a static/mock demo.
- **As built — deviations from the plan above, all explicitly requested
  by the user before implementation**:
  - **No fixed destination marker.** `ArcLayer.tsx` was NOT built around
    a hardcoded destination point. `ThreatEvent` (mirroring
    `_ioc_to_dict()`) has no destination field, so arcs only render for
    an (optional, additive, currently-never-populated)
    `dest_lat`/`dest_lon` pair a future schema change could add — as of
    this stage `ArcLayer` always renders nothing. The globe's primary
    visualization is `MarkerLayer.tsx` (static, instanced, one draw call,
    geographic distribution of all currently-loaded threats) plus
    `LivePulseLayer.tsx` (animated arrival pulses for new WS events,
    capped and self-expiring) — not arcs.
  - **No CDN texture.** `earthTexture.ts` generates the globe's surface
    entirely on an offscreen `<canvas>` at runtime (dark gradient +
    lat/lon graticule, no photographic Earth imagery) rather than
    bundling or fetching a satellite-imagery texture file, since no such
    asset exists anywhere in the repo and none should be fetched from a
    runtime CDN.
  - **EmptyState instead of a broken globe.** `ThreatGlobe.tsx` checks
    `/api/threats/map`'s result before mounting the `Canvas` at all —
    zero results (or a fetch error) renders the existing `EmptyState`
    component, matching Stage G's own precedent for surfacing
    disabled/unavailable states rather than a blank or errored canvas.
    Verified live: this environment has no `MAXMIND_LICENSE_KEY`
    configured (see Architecture Decision #5), so every one of the
    2,342 real IOCs ingested during verification had `lat`/`lon` both
    `NULL` and `/api/threats/map` legitimately returned zero events —
    the EmptyState path was exercised against real data, not a
    contrived case.
  - **Performance safeguards**: `useThreatMapData.ts` caps rendered
    markers client-side at `MAX_RENDERED_MARKERS = 800` (sorted by
    recency) on top of the backend's own `MAP_LIMIT = 2000`;
    `MarkerLayer.tsx` renders every marker as a single `InstancedMesh`
    draw call with per-instance matrices written once (not per frame);
    `LivePulseLayer.tsx` caps concurrent animated pulses at
    `MAX_LIVE_PULSES = 40` with a `PULSE_LIFETIME_MS = 4000` self-expiry
    so a burst of ingestion can't grow the animated object count without
    bound; `Canvas` caps `dpr` at `[1, 1.5]`.
  - **Store extension**: `threatStore.ts` gained an additive
    `globeFilters`/`setGlobeFilters` slice (country/threatType/
    minConfidence/sinceHours) for `GlobeFilters.tsx` to read/write, per
    Stage F's own spec ("wired to the zustand store"). No existing field
    was changed.
  - **Mounting decision (judgment call, not in the original plan
    text)**: Stage E's placeholder comment in `ThreatFeed.tsx` reserved
    that file for Stage G ("must not import anything from the globe
    extension point"). Stage F's own completion criteria require "an
    interactive, real-data-driven 3D globe" — which needs to be mounted
    somewhere to be verified as real, not a demo. Resolved by minimally
    replacing the Stage E placeholder with `<ThreatGlobe />` and nothing
    else — no live feed list, `ThreatCard`, or search UI, which remain
    Stage G's "full page + search" deliverable untouched.
  - **`/api/threats/countries` and `/api/threats/types` return
    `{country, count}` / `{threat_type, count}` objects, not bare
    strings** (confirmed by reading `routes_threats.py` directly, not
    assumed from the plan text) — `GlobeFilters.tsx` destructures
    accordingly.
  - **Bug found and fixed during Docker/browser verification, then
    reverted as unverified**: the `Canvas` element was observed stuck at
    the browser's bare-HTML-element default size (300x150) on initial
    mount in the Docker/Browser-pane verification environment, separate
    from the screenshot tool itself timing out on every page (including
    pages with no WebGL at all) in the same session — evidence this was
    a render-loop/tab-visibility throttling artifact of that specific
    preview surface, not an application defect (confirmed: a
    `useFrame`-driven bounded retry never ran either, meaning the whole
    `requestAnimationFrame` loop was paused, not just `ResizeObserver`).
    Two speculative fixes (`preserveDrawingBuffer: true`, a
    `CanvasSizeGuard` component) were tried, neither resolved it, and
    both were removed rather than shipped as unverified complexity.
    `ThreatGlobe.tsx` uses `@react-three/fiber`'s standard `Canvas`
    sizing with no custom workaround. A real browser tab (not this
    embedded automation surface) does not exhibit this throttling.
  - Verification was completed via DOM inspection, network-request
    inspection, and direct backend queries rather than pixel screenshots,
    because of the above tool limitation — see this stage's completion
    report for the exact steps and evidence.

## Stage G — Overview / Threat Feed / Analytics / Alerts / Settings pages
**Status: ✅ Complete**

- **Objective**: build out the remaining dashboard pages with real data
  (five of the six sidebar pages -- Sandbox Lab itself is Stage H).
- **Deliverables**: `src/pages/Overview.tsx` (KPI stat tiles, a compact
  "globe preview" summary card linking into the full 3D globe rather than
  a second embedded canvas, sandbox status widget polling
  `globe/server.py`'s `/api/attacks/status` via the existing
  `/api/sandbox/*` proxy, top countries/types, recent alerts -- explicitly
  NOT the full Threat Feed search/filter experience), `src/pages/
  ThreatFeed.tsx` (Stage F's globe unchanged on top; full search + filter
  by provider/threat type/confidence/country + sort newest/oldest below
  it), `src/pages/Analytics.tsx` (sandbox mitigation confidence/threshold
  timeline from `defense-engine:9300/mitigations` + `threat-intel`
  ingestion timeline/types/stats -- deliberately omits precision/recall/
  false-positive-rate since neither backend computes them), `src/pages/
  Alerts.tsx` (confidence-derived severity levels with color-coded
  badges), `src/pages/Settings.tsx` (service health for threat-intel +
  defense-engine, live WebSocket connection status, provider status table,
  GeoIP status), `src/components/feed/{ThreatCard,LiveFeedList,
  FeedFilters,labels}.tsx`, `src/lib/{queries,sandboxStatus,
  defenseEngineApi}.ts`.
- **As built -- deviations/decisions made during implementation**:
  - **Provider filter is a documented partial feature.** `Ioc` rows
    returned by `/api/threats/live`/`/search` are deduped/merged across
    sources (`source_count` is an integer, not a provider name -- see
    `app/common/models.py`), and the Global Threat Intelligence backend is
    not modified in this stage to add one. Only `LiveThreatEvent` (the
    live WebSocket payload) carries a `source` field, so the Provider
    filter on Threat Feed only matches threats that arrived live during
    the current session; the UI states this explicitly rather than
    silently under-filtering backlog data.
  - **Search is client-side substring matching** across the already-loaded
    dataset (ioc/country/threat_type/attack_family/category), not a new
    backend query -- `/api/threats/search` only supports exact
    ip/asn/country matches, which doesn't fit a free-text search box, and
    the backend is not modified in this stage.
  - **Three real bugs found and fixed in already-completed Stage E/F code**
    while wiring this stage's live-feed merging (Execution Rule 6):
    1. `useThreatStream`/`threatStore.liveEvents` were typed as
       `ThreatEvent[]` but the real WS payload (`_ioc_live_payload()` in
       `app/ingest.py`) is a different, narrower shape -- introduced the
       correct `LiveThreatEvent` type (`src/types/threat.ts`) instead.
    2. `LivePulseLayer.tsx`'s `pulseKey()` read a `last_seen` field that
       never exists on that payload, so every live pulse for the same IOC
       collapsed to the same `"${ioc}-undefined"` key and a given IOC only
       ever animated once for the page's lifetime -- fixed to key on the
       payload's real `timestamp` field.
    3. `threatStore.connectionStatus`/`setConnectionStatus` were scaffolded
       in Stage E but `useThreatStream` never actually called back into
       them, so the status stayed stuck at "connecting" forever -- added
       an optional `onStatusChange` callback to `useThreatStream`, wired
       from `AppShell.tsx`. No earlier stage's page displayed this value
       on screen, which is why it went unnoticed until Settings needed it.
  - **`react-is` was a missing, undeclared dependency.** `recharts@3.9.2`
    peer-depends on it; nothing else in the tree provides it, and no
    earlier stage's code imported from `recharts` (Stage E only listed it
    in `package.json`; Stage F used `@react-three/fiber` directly), so the
    gap was invisible until Analytics became the first real consumer.
    Fixed by adding `react-is` to `dashboard/package.json` (`npm install
    --legacy-peer-deps`, matching this environment's existing
    `typescript`-version peer conflict between `openapi-typescript` and
    the installed compiler, unrelated to this stage).
  - **Added a `/health` proxy rule** for threat-intel to `vite.config.ts`
    (dev) and `nginx.conf` (prod) -- additive, dashboard-owned config,
    mirrors the existing `/api/threats`, `/api/providers`, etc. rules
    exactly; not a threat-intel backend change.
  - **Post-approval follow-up**: `defense-engine` was initially called
    directly cross-origin (relying on its existing
    `CORSMiddleware(allow_origins=["*"])`), per this stage's original spec
    wording ("pulls defense-engine:9300/mitigations directly, already
    CORS-open"). After approval, moved this behind a same-origin
    `/api/defense/*` proxy rule (`vite.config.ts` dev / `nginx.conf` prod,
    stripping the prefix before forwarding to `defense-engine:9300`) so
    all three backends (`threat-intel`, `globe`, `defense-engine`) are now
    reached the same way, for consistency and so the dashboard no longer
    depends on that CORS config. `defense/engine.py` itself was not
    touched -- `dashboard/src/lib/defenseEngineApi.ts` now fetches
    `/api/defense/{mitigations,threshold,health}` instead of constructing
    a cross-host URL. `dashboard` and `defense-engine` already share
    `public_net` in `docker-compose.yml`, so no compose change was needed.
- **Verification performed**: `npm run typecheck`/`build`/`lint` clean;
  `docker compose build dashboard` succeeds; full stack brought up
  (`threat-intel`+db+redis, `defense-engine`, `rate-limiter`, `lb`,
  targets, `globe`, `dashboard`) and every page manually verified in a
  browser against live, real backend data (2,342 real IOCs, 1,747 real
  CVEs, real `/mitigations` history); Settings confirmed showing
  AbuseIPDB/OTX as disabled (missing key) and GeoIP as unavailable (no
  license key/db) exactly as required; WebSocket status confirmed
  reaching "open" after the bug fix; `bash tests/test_network_isolation.sh`
  still passes; `docker inspect` confirms `threat-intel` is still only on
  `public_net`/`threatintel_net`; the legacy `globe/index.html` UI at
  `:8090` verified still working, console-clean, completely unmodified.
- **Completion criteria**: met and approved -- all five pages fully
  functional against real data, no fabricated metrics anywhere.

## Stage H — Sandbox Lab page (ported, not iframed)
**Status: ✅ Complete**

- **Objective**: give the Sandbox Lab a native page inside the new
  dashboard, per Architecture Decision #4, without touching sandbox logic
  beyond one CORS addition.
- **Expected deliverables**: `src/lib/sandboxApi.ts` (typed client for
  `globe/server.py`'s existing endpoints), `src/pages/SandboxLab.tsx`
  (attack start/stop controls, live feed table, embedded Grafana panel
  via iframe — embedding is already enabled in `docker-compose.yml`'s
  `grafana` service env vars — and a mitigation log table reading
  `defense-engine:9300/mitigations`), `src/components/sandbox/
  {AttackControls,GrafanaPanel,MitigationLogTable}.tsx`.
- **The one approved existing-file edit**: add `CORSMiddleware` to
  `globe/server.py`, right after `app = FastAPI(...)`, origins from a new
  `DASHBOARD_ORIGIN` env var (default covering both the Vite dev server
  and the production dashboard port), mirroring the exact pattern already
  used in `defense/engine.py`. This must be the ONLY change to this file.
- **Verification requirements**: starting/stopping a real attack from the
  new dashboard page actually starts/stops the corresponding
  `attacker-*` Docker container (`docker compose ps` reflects it);
  Grafana iframe renders; mitigation log populates live during a running
  attack; the legacy `globe/index.html` UI at `:8090` still works
  completely unmodified after this change.
- **Completion criteria**: Sandbox Lab is fully controllable from the new
  dashboard, legacy UI unaffected.
- **As built — deviation from the plan above, explicitly directed by the
  user before implementation**:
  - **The CORS edit was skipped entirely — `globe/server.py` was not
    touched.** The user's approval for this stage explicitly said not to
    add `CORSMiddleware` unless verification proved it was required. The
    Sandbox Lab page only ever calls `globe/server.py` through the
    existing same-origin `/api/sandbox/*` proxy (`vite.config.ts` dev /
    `nginx.conf` prod, both wired in Stage E) — the same pattern
    `sandboxStatus.ts` already used in Stage G for the Overview status
    widget. Because the browser only ever talks to its own origin and the
    proxy forwards server-side, no cross-origin request is ever made, so
    CORS was never required. Verified live: every `/api/sandbox/*` call
    (`GET attacks/status`, `GET feed`, `POST attacks/{type}/start`,
    `POST attacks/{type}/stop`) returned `200 OK` with zero CORS errors in
    the browser console. `globe/server.py`'s `git diff` is empty after
    this stage.
  - `src/lib/sandboxApi.ts` re-exports the existing
    `useSandboxAttacksStatus` hook from `sandboxStatus.ts` (Stage G)
    rather than duplicating a second `/api/attacks/status` fetcher/query
    key — both the Overview widget and the new Sandbox Lab page now share
    one hook and one react-query cache entry for that endpoint.
    `sandboxStatus.ts` itself was not modified.
  - `MitigationLogTable.tsx` reuses `useMitigations` from
    `defenseEngineApi.ts` (Stage G) rather than adding a second
    `/mitigations` fetcher — same data, rendered as a chronological table
    instead of Analytics' chart.
  - `vite.config.ts` gained one additive dev-mode proxy rule (`/grafana`
    → `localhost:3000`), mirroring `nginx.conf`'s existing `/grafana/`
    rule, so the Grafana iframe works identically in `npm run dev` and in
    the production nginx build. No prod config (`nginx.conf`,
    `docker-compose.yml`) needed changes — the `/grafana/` proxy rule and
    Grafana's embedding/anonymous-access env vars already existed.
  - **No Docker/container awareness was introduced anywhere in
    `dashboard/`.** `AttackControls.tsx` and `sandboxApi.ts` only issue
    plain `fetch()` calls to `/api/sandbox/attacks/{type}/{start,stop}`;
    all container lifecycle logic remains exclusively in
    `globe/server.py`'s existing `docker compose` subprocess calls, which
    were not modified.
  - **Verified live in Docker** (`docker compose up -d --build web lb
    tcp-service dns-udp prometheus grafana threat-intel-db
    threat-intel-redis threat-intel defense-engine rate-limiter globe
    dashboard`): clicked "Start" on Slowloris in the new dashboard page —
    `docker compose ps` showed `ddos-attack-attacker-slowloris-1` actually
    `Up`; the page's status badge flipped to "running"; clicked "Stop" —
    `docker compose ps -a` showed the same container `Exited (137)` and
    the badge flipped back to "idle". Grafana panel iframe loaded real
    assets (200 OK on the dashboard JSON, CSS, and icon requests). Live
    event feed and mitigation log both rendered real data from
    `globe:8090` and `defense-engine:9300` respectively. The legacy
    `globe/index.html` UI at `:8090` was reloaded and confirmed fully
    functional, console-clean, completely unmodified (attack controls,
    live feed, classifier confidence, mitigation log, and Grafana links
    all present exactly as before). `bash tests/test_network_isolation.sh`
    passed both before and after this stage's changes. `docker inspect
    ddos-attack-threat-intel-1` confirmed its network attachments are
    still exactly `[public_net, threatintel_net]` — unaffected by this
    stage, as expected since no `services/threat-intel/` or
    `docker-compose.yml` file was touched.
  - `npm run typecheck` / `npm run build` / `npm run lint` (oxlint) all
    clean.

## Stage I — AI correlation engine
**Status: ⬜ Not started**

- **Objective**: build the one deliberate integration seam between the
  two modules — comparing sandbox attack telemetry to global threat
  indicators, expressed as observable similarity only, never attribution.
- **Expected deliverables**: `services/threat-intel/app/correlation/
  engine.py` — pure heuristic (NOT ML training, NOT attribution),
  comparing current sandbox feature values (request_rate,
  avg_connection_duration, inter_arrival_std, error_rate,
  active_connections — the same fields `defense/classifier/features.py`
  already computes) against recent high-confidence IOCs, producing
  `{correlation_percentage, observation, matched_features}` via a FIXED
  observation-string template that never interpolates a specific
  IP/actor into a claim of attribution. `app/api/routes_correlation.py`:
  `GET /api/threats/correlation`, reading `defense-engine` telemetry over
  `public_net` (the network they already share — this is the deliberate,
  narrow, isolation-preserving integration point; `threat-intel` must
  NOT be added to `target_net` to make this call).
  `src/components/correlation/CorrelationPanel.tsx` on the dashboard,
  always rendering a "heuristic similarity only, not attribution"
  disclaimer alongside the percentage.
- **Verification requirements**: trigger a real sandbox attack, confirm
  `/api/threats/correlation` returns a percentage and an observation
  string containing no specific attributed identity — only
  feature-similarity language; confirm `threat-intel`'s network
  attachments are unchanged (still no `target_net`) after this stage.
- **Completion criteria**: correlation is observable and demonstrable,
  the no-attribution constraint is structurally enforced (not just a
  convention), isolation is provably unaffected.

## Stage J — Docs and CI
**Status: ⬜ Not started**

- **Objective**: finalize documentation and CI coverage for the whole
  platform.
- **Expected deliverables**: `README.md` gets a "Module 2: Global Threat
  Intelligence" section (already partially present, extend it) plus a
  "Logical vs Physical Architecture" table (see the Project Overview
  table above — put a version of it in the README too) and an extension
  of the existing "Why this is safe" section covering `threat-intel`'s
  read-only-outbound-HTTPS posture and exact network attachment. New
  `docs/threat-intel.md`: provider list, schema, confidence formula,
  correlation disclaimer, all env vars. `.github/workflows/ci.yml`
  extended: add `services/threat-intel` to the `ruff` lint target list
  (and `mypy`, and `pytest services/threat-intel/tests`); add an
  independent `dashboard` CI job (`npm ci && npm run build && npm run
  typecheck`) that doesn't block or get blocked by the existing Python
  jobs.
- **Verification requirements**: CI green on a clean branch/PR; a fresh
  clone + the documented setup steps actually bring up the full stack
  successfully, following only the README (dogfood the docs).
- **Completion criteria**: a new contributor (human or AI) could set up
  and understand the full platform from `README.md` +
  `docs/threat-intel.md` + this file alone.

---

# Current Project State

✅ **Stage A Complete** — threat-intel backend skeleton, DB schema, provider registry
✅ **Stage B Complete** — 7 provider connectors (5 no-key, 2 key-gated)
✅ **Stage C Complete** — REST + WebSocket API, Redis caching, ingestion scheduler
✅ **Stage C.5 Complete** — GeoLite2 geolocation enrichment
✅ **Stage D Complete** — docker-compose wiring for `threat-intel`,
`threat-intel-db`, `threat-intel-redis` on the new `threatintel_net`.
✅ **Stage E Complete** — `dashboard/` Vite+React+TypeScript+Tailwind SPA
shell (routing, sidebar, typed API client, WS hook, zustand store, shared
`components/ui/` primitives), wired into `docker-compose.yml` as the
`dashboard` service on `public_net`.
✅ **Stage F Complete** — `dashboard/src/components/globe/` — a
react-three-fiber 3D globe visualizing the geographic distribution of
`threat-intel`'s ingested IOCs as instanced markers plus live arrival
pulses, with a procedurally-generated (no CDN, no bundled binary asset)
surface texture, an `EmptyState` fallback when no geolocated data exists,
and client-side rendering caps for large datasets. Mounted at
`/threat-intel` (`src/pages/ThreatFeed.tsx`), replacing the Stage E
placeholder. See the Stage F entry above ("As built") for the full list
of deviations/decisions made during implementation.

✅ **Stage G Complete** — `dashboard/src/pages/{Overview,ThreatFeed,
Analytics,Alerts,Settings}.tsx` now render real data (Sandbox Lab page
itself is still Stage H's placeholder). New `src/components/feed/`
(ThreatCard, LiveFeedList, FeedFilters, labels) and `src/lib/{queries,
sandboxStatus,defenseEngineApi}.ts`. Fixed three real bugs surfaced while
building this stage in already-completed Stage E/F code (WS payload
mistyped as `ThreatEvent` instead of the real `LiveThreatEvent` shape,
`LivePulseLayer`'s pulse key reading a nonexistent field, and
`connectionStatus` never actually being wired up) plus one missing
dependency (`react-is`, a `recharts` peer nothing else in the tree
provided) -- see the Stage G entry above for full detail. No
`services/threat-intel/app/` file and no Sandbox Lab file were touched.

✅ **Stage H Complete** — `dashboard/src/pages/SandboxLab.tsx` is now the
real, native, ported Sandbox Lab page: `AttackControls` (start/stop each
attack scenario), a live event feed table, an embedded Grafana panel
(iframe — the one approved iframe in this stage), and `MitigationLogTable`
(reusing Stage G's `useMitigations`). New `src/lib/sandboxApi.ts` and
`src/components/sandbox/{AttackControls,GrafanaPanel,
MitigationLogTable}.tsx`. **The approved CORS edit to `globe/server.py`
was not made** — the user's Stage H approval explicitly directed skipping
it unless verification proved it necessary, and the existing same-origin
`/api/sandbox/*` proxy (Stage E) fully satisfied every request with no
CORS error, so `globe/server.py` is untouched. See the Stage H entry above
("As built") for full verification detail.

⬜ **Stage I is the next stage to implement** — AI correlation engine.

⬜ Stage J is planned (see Stage Roadmap above) but not started.

The Sandbox Lab module (`attackers/`, `defense/`, `targets/`, `globe/`,
`observability/`, `infra/`, `tests/`) has still not been modified in any
stage — Stage H's originally-anticipated CORS edit turned out not to be
necessary and was not made — and remains fully functional exactly as it
was before this project began. Stage D touched only `docker-compose.yml`
(additive), plus this file and `README.md`. Stage E added the new
`dashboard/` directory and one additive `docker-compose.yml` service, plus
this file and `README.md` -- no Sandbox Lab or threat-intel backend file
was touched. Stage H touched only `dashboard/` files, plus this file and
`README.md` -- no Sandbox Lab or threat-intel backend file was touched.

`services/threat-intel/` is now wired into `docker-compose.yml`: bring up
the full service with
`docker compose up -d --build threat-intel-db threat-intel-redis threat-intel`.
It runs on the new `threatintel_net` (bridge, non-internal) plus
`public_net`; it is never attached to `attacker_net` or `target_net`
(verified via `docker inspect` after Stage D — see the Stage D completion
report for the exact command and output).

---

# Important Files

## Sandbox Lab (pre-existing — do not rewrite)
| Path | Purpose |
|---|---|
| `docker-compose.yml` | Defines all networks/services for both modules; Stage D will extend this additively |
| `attackers/` | Attack simulation modules (`http_flood.py`, `slowloris.py`, `udp_flood.py`, `tcp_exhaustion.py`), `legit_load.py` control traffic, record/replay tooling |
| `defense/` | `engine.py` (ML detection + adaptive rate-limit engine, port 9300), `classifier/` (IsolationForest training/features), `rate_limiter/` (enforcement proxy), `suricata/`, `wazuh/` |
| `targets/` | Synthetic target services (web, tcp_service, dns_udp, lb) with Prometheus metrics |
| `globe/` | `server.py` — the sandbox's existing FastAPI control/visualization API (port 8090); becomes a second dashboard's backend in Stage H, otherwise untouched |
| `observability/` | Prometheus scrape config + Grafana dashboards |
| `infra/` | Kubernetes manifests + Terraform wrapper |
| `tests/test_network_isolation.sh` | THE empirical proof of network isolation; must pass unchanged after every stage |
| `reports/` | Post-run benchmark report generator |

## Global Threat Intelligence (new — `services/threat-intel/`)
| Path | Purpose |
|---|---|
| `app/main.py` | FastAPI app, lifespan-managed startup/shutdown, router mounting, CORS |
| `app/settings.py` | ALL configuration, via env vars, one place |
| `app/logging_config.py` | Structured logging setup |
| `app/common/schema.py` | `ThreatEvent`/`CveEvent` — the canonical normalized shapes every connector targets |
| `app/common/models.py` | SQLAlchemy ORM: `Ioc`, `IocSighting`, `Cve` |
| `app/common/db.py` | Async engine/session lifecycle |
| `app/common/dedup.py` | `merge_or_insert` (IOC dedup/confidence scoring), `upsert_cve` |
| `app/common/cache.py` | Redis JSON cache + pub/sub wrapper |
| `app/common/geoip.py` | `GeoIpEnricher` — local MaxMind lookups |
| `app/common/geo_cache.py` | Redis cache of geo lookup results, by IP |
| `app/provider/base.py` | `ThreatProvider` ABC + `PROVIDER_REGISTRY` — the plugin interface |
| `app/provider/{threatfox,cisa_kev,spamhaus_drop,emerging_threats,nvd_cve,abuseipdb,otx}.py` | The 7 connectors |
| `app/provider/http.py` | Shared retrying HTTP client |
| `app/provider/__init__.py` | THE file to touch to add/remove a provider |
| `app/ingest.py` | The ingestion scheduler — polls providers, persists, enriches, publishes live events |
| `app/enrich.py` | The standalone geolocation enrichment pass |
| `app/geoip_updater.py` | Periodic GeoLite2 database downloader (own scheduler) |
| `app/geo_fallback.py` | Optional, off-by-default, NOT YET WIRED public geolocation API fallback |
| `app/api/routes_threats.py` | `/api/threats/*` REST endpoints |
| `app/api/routes_providers.py` | `/api/providers/status` |
| `app/api/routes_geoip.py` | `/api/geoip/status` |
| `app/api/routes_ws.py` | `WebSocket /ws/threats` |
| `tests/` | 28 passing unit tests; `tests/fixtures/*.mmdb` are real (test-scale) MaxMind-format databases, committed to the repo, needed for `test_geoip.py` |
| `requirements.txt` / `requirements-dev.txt` | Runtime deps / +test+lint+typecheck deps |
| `Dockerfile` | Includes a `HEALTHCHECK` hitting `/health` via Python stdlib (no `curl` in the base image) |

## Not yet created
| Path | Arrives in |
|---|---|
| `dashboard/` | Stage E |
| `services/threat-intel/app/correlation/` | Stage I |
| `docs/threat-intel.md` | Stage J |

---

# Safety Requirements

These are the concrete, checkable guarantees that must hold after every
single stage, forever:

1. **`bash tests/test_network_isolation.sh` passes.** This is not
   optional and not stage-specific — run it after every stage that
   touches `docker-compose.yml` or any networking config, even stages
   that seem unrelated to the sandbox.
2. **`docker inspect <threat-intel container>` never lists `attacker_net`
   or `target_net`** among its networks. Check this explicitly after
   Stage D and after any future change to `docker-compose.yml`.
3. **No code in `services/threat-intel/` or `dashboard/` ever shells out
   to `docker`, writes to a Docker socket, or otherwise controls
   container lifecycle.** That capability is exclusive to
   `globe/server.py` (an existing, already-audited, already-scoped-down
   piece of the Sandbox Lab), which the new dashboard calls as a client
   but never reimplements or bypasses.
4. **No provider connector, geolocation lookup, or any other Global
   Threat Intelligence code path ever sends traffic anywhere other than:
   the specific public feed/API host it's documented to call, or the
   `threat-intel-db`/`threat-intel-redis` containers.** If a future
   connector or feature seems to need to reach anything else, stop and
   ask before implementing it.
5. **No fabricated/synthetic data anywhere in the Global Threat
   Intelligence module.** An empty result is always the correct
   fallback when real data isn't available — this has been true for
   provider outages, missing API keys, missing GeoIP databases, and
   unresolvable addresses, and must remain true for anything built later
   (e.g. the Stage I correlation engine must never invent a match).
6. **The Stage I correlation engine (when built) must structurally
   prevent attribution claims** — via a fixed template, not a
   convention that could be forgotten. Review this specifically before
   marking Stage I complete.
7. **The legacy `globe/index.html` UI at port 8090 must keep working,
   completely unmodified in its own behavior, through every remaining
   stage** — it is the fallback/proof that the Sandbox Lab was never
   touched beyond the one approved CORS edit.

---

# Future Contributors Guide

**Always read `PROJECT_EXECUTION_PLAN.md` before implementing anything.**

If you are a future Claude session (or any other AI assistant) picking up
this project without access to the conversation that built it so far:

1. Read this entire document first. It is the source of truth for *why*
   the code is shaped the way it is, not just *what* exists.
2. Check the **Current Project State** section above to see which stage
   is next. Do not skip ahead — implement exactly one stage, verify it in
   Docker (not just with unit tests), then stop and report before
   continuing, per the **Execution Rules** section.
3. Before modifying any file inside `services/threat-intel/app/` that
   belongs to an already-completed stage, re-read that stage's entry in
   the **Stage Roadmap** and the relevant **Architecture Decision** above.
   If your planned change isn't a bug fix or an explicitly-approved
   extension, don't make it — ask first.
4. Before modifying anything under `attackers/`, `defense/`, `targets/`,
   `globe/`, `observability/`, `infra/`, or `tests/` (the Sandbox Lab),
   stop and confirm this is one of the two explicitly-approved edits
   (Stage H's CORS addition, or a UI-only improvement) — this code is
   considered production-stable and off-limits otherwise.
5. Read the **Safety Requirements** section and verify every one of them
   still holds after your change, not just the specific thing you were
   asked to build.
6. When you finish a stage, update the **Current Project State** section
   of this document (mark the stage complete, update "next stage"), and
   update `README.md` per Execution Rule 8 — don't let this document or
   the README drift out of sync with reality.
7. If you discover that an earlier stage has a bug, follow the precedent
   set by the Stage C shutdown bug: investigate the root cause properly
   (don't just paper over the symptom), fix it minimally, document what
   you found and why the fix works in the code itself (see
   `app/ingest.py`'s `stop_scheduler` docstring for the standard of
   documentation expected), and report it clearly when you report the
   stage you were actually working on.
8. If the user's instructions for a new stage seem to contradict an
   **Architecture Decision** recorded in this document, do not silently
   follow the new instruction over the old decision — surface the
   conflict and ask, since architecture decisions in this document were
   explicitly marked as requiring approval to change.
