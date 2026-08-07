/**
 * threat-intel's REST routes (app/api/routes_threats.py) return plain
 * dicts rather than a Pydantic response_model, so this shape does not
 * appear in /openapi.json and openapi-typescript cannot generate it --
 * confirmed against a live /api/threats/live response during Stage E.
 * Path/query params for these same endpoints ARE generated (see
 * src/generated/threat-intel.ts); this file only covers the response
 * body shape that generator gap leaves uncovered. Mirrors
 * `_ioc_to_dict()` in routes_threats.py exactly -- update both together
 * if that shape changes.
 */
export interface ThreatEvent {
  ioc: string;
  ioc_type: string;
  country: string | null;
  lat: number | null;
  lon: number | null;
  asn: number | null;
  organization: string | null;
  threat_type: string;
  attack_family: string | null;
  category: string | null;
  confidence_score: number;
  source_count: number;
  first_seen: string;
  last_seen: string;
}

/**
 * Mirrors app/common/models.py's `Cve` ORM table. No dedicated
 * /api/threats/cves list endpoint exists yet (only a count via /stats),
 * so this type has no consumer in Stage E -- kept here as the agreed
 * extension point for whichever future stage adds that endpoint, so it
 * doesn't get invented ad hoc later.
 */
export interface CveEvent {
  cve_id: string;
  description: string | null;
  severity: string | null;
  published: string | null;
  source: string;
  vendor_project: string | null;
  product: string | null;
  first_seen: string;
  last_seen: string;
}

/**
 * Mirrors `_ioc_live_payload()` in `app/ingest.py` exactly -- the shape
 * actually published to the `threats:live` Redis channel and forwarded
 * verbatim by `WebSocket /ws/threats`. This is a narrower, differently-shaped
 * snapshot than `ThreatEvent` (no asn/organization/category/source_count/
 * first_seen; has `city`/`source`/`timestamp` instead of `last_seen`).
 *
 * Stage G bug fix: `useThreatStream`/`threatStore.liveEvents` previously
 * cast live WS messages to `ThreatEvent`, which doesn't match this real
 * payload shape -- `LivePulseLayer.tsx`'s `pulseKey()` read a `last_seen`
 * field that never exists on the wire, so every live event for the same
 * IOC produced the same `"${ioc}-undefined"` key and only ever pulsed once
 * per IOC for the lifetime of the page. Fixed by introducing this correct
 * type and keying pulses on `timestamp` instead.
 */
export interface LiveThreatEvent {
  ioc: string;
  ioc_type: string;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  threat_type: string;
  attack_family: string | null;
  confidence_score: number;
  source: string;
  timestamp: string;
}

/** `{country, count}` rows from `GET /api/threats/countries`. */
export interface CountryCount {
  country: string;
  count: number;
}

/** `{threat_type, count}` rows from `GET /api/threats/types`. */
export interface ThreatTypeCount {
  threat_type: string;
  count: number;
}

/** `{bucket, count}` rows from `GET /api/threats/timeline`. */
export interface TimelineBucket {
  bucket: string;
  count: number;
}

/** Shape of `GET /api/threats/stats`. */
export interface ThreatStats {
  total_iocs: number;
  total_cves: number;
  distinct_countries: number;
  top_attack_family: string | null;
}

/** One entry of `GET /api/providers/status`'s `providers` array. */
export interface ProviderStatus {
  name: string;
  requires_key: boolean;
  enabled: boolean;
  poll_interval_seconds: number;
  event_kind: "ioc" | "cve";
}

/** Shape of `GET /api/geoip/status`. */
export interface GeoipStatus {
  license_key_configured: boolean;
  city_db_present: boolean;
  asn_db_present: boolean;
  enrichment_available: boolean;
  fallback_api_enabled: boolean;
}

/** Shape of `defense-engine`'s `GET /mitigations`. */
export interface MitigationAction {
  ts: number;
  confidence: number;
  features: Record<string, number>;
  old_threshold: number;
  new_threshold: number;
  reason: string;
}

/** Shape of `defense-engine`'s `GET /threshold`. */
export interface DefenseThreshold {
  threshold_rps: number;
  confidence: number;
}

/** Shape of `globe/server.py`'s `GET /api/attacks/status` (proxied via `/api/sandbox/attacks/status`). */
export interface SandboxAttacksStatus {
  running: Record<string, boolean>;
}

/**
 * One line of an `attackers/recordings/*.jsonl` file, mirroring
 * `attackers/common/recorder.py`'s `SimEvent` dataclass exactly. Served by
 * `globe/server.py`'s `GET /api/feed` (proxied via `/api/sandbox/feed`).
 * `fake_ip`/`city`/`lat`/`lon` are the synthetic attacker identity used for
 * the legacy globe visualization only -- never a real network address.
 */
export interface SandboxFeedEvent {
  ts: number;
  attack_type: string;
  target: string;
  fake_ip: string;
  city: string;
  lat: number;
  lon: number;
  status: number | null;
  latency_ms: number | null;
  extra: Record<string, unknown>;
}

/** Shape of `GET /api/feed` (proxied via `/api/sandbox/feed`). */
export interface SandboxFeedResponse {
  run_name: string | null;
  events: SandboxFeedEvent[];
}

/**
 * Shape of `GET /api/threats/correlation` (Stage I) -- mirrors
 * `app/correlation/engine.py`'s `CorrelationResult` exactly. `disclaimer`
 * is a fixed string and must always be rendered alongside the score;
 * `observation` never contains an IP, country, actor, malware family, or
 * campaign name -- only a percentage, a count, and this module's own
 * feature names (see `matched_features`).
 */
export interface CorrelationResult {
  available: boolean;
  correlation_percentage: number | null;
  observation: string;
  matched_features: string[];
  disclaimer: string;
  compared_ioc_count: number;
  generated_at: string;
}
