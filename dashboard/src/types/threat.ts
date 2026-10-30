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

/** Shape of `defense-engine`'s `GET /health`: which model is active and which mitigation policy is in force. */
export interface DefenseHealth {
  status: string;
  model_loaded: boolean;
  model: {
    file: string;
    trained_at: string | null;
    samples: number | null;
    legit_runs: string[];
    idle_windows: number;
    contamination: number | null;
  } | null;
  policy: string;
}

/** Shape of `defense-engine`'s `GET /threshold`. */
export interface DefenseThreshold {
  threshold_rps: number;
  confidence: number;
}

export interface DetectionMetrics {
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  false_positive_rate: number;
  f1: number;
  accuracy: number;
  threshold: number;
}

export interface DetectionTypeResult {
  attack_type: string;
  runs: number;
  samples: number;
  flagged: number;
  low_sample: boolean;
  metrics: DetectionMetrics;
  /** Live results only: how far the rate limit dropped and, for HTTP runs, how many requests were answered 429. */
  mitigation?: { min_threshold_rps: number | null; requests?: number; blocked?: number; blocked_fraction?: number };
}

export interface DetectionRunRow {
  run: string;
  attack_type?: string;
  label: "normal" | "attack";
  samples: number;
  flagged: number;
}

/** Samples scored for normal traffic; `mitigation` is present for live results. */
export interface DetectionNormal {
  samples: number;
  false_positives: number;
  mitigation?: { min_threshold_rps: number | null; requests?: number; blocked?: number; blocked_fraction?: number };
}

/**
 * Shape of `defense-engine`'s `GET /evaluation` (the report written by `classifier/evaluate.py`).
 * The top level is the OFFLINE evaluation (held-out runs, logged live features re-scored with the trained
 * model, mitigation inert). `live` is the END-TO-END result from runs with mitigation active, using the
 * engine's own logged confidence and rate limit.
 */
export type DetectionEvaluation =
  | { available: false }
  | {
      available: true;
      generated_at: string;
      trained_on: string[];
      sample_unit: string;
      samples: { normal: number; attack: number };
      metrics: DetectionMetrics;
      normal: DetectionNormal;
      idle: DetectionNormal;
      by_type: DetectionTypeResult[];
      runs: DetectionRunRow[];
      excluded: { run: string; events: number; reason: string }[];
      /** Legitimate requests answered 429 while an attack was running at the same time (from the recordings). */
      collateral?: {
        legit_run: string;
        attack_type: string;
        attack_runs: number;
        overlap_seconds: number;
        requests: number;
        blocked: number;
        blocked_fraction: number;
      }[];
      live?: {
        samples: { normal: number; attack: number };
        metrics: DetectionMetrics;
        normal: DetectionNormal;
        idle: DetectionNormal;
        by_type: DetectionTypeResult[];
        runs: DetectionRunRow[];
      };
    };

/** Shape of `defense-engine`'s `GET /mitigation-report` (written by `classifier/mitigation_report.py`). */
export type MitigationReport =
  | { available: false }
  | {
      available: true;
      generated_at: string;
      baseline_limit_rps: number;
      configs: Record<string, { limiter: string; policy: string; label: string }>;
      excluded_runs?: { run: string; reason: string }[];
      rows: {
        config: string;
        scenario: "legit" | "flood" | "dist" | "floodL" | "distL" | "slowL";
        attack_sources: number;
        seconds: number;
        /** Engine state when the scenario began; `clean` is false if the cap was still lowered by the previous one. */
        start?: { cap_rps: number | null; state: string | null; clean: boolean | null };
        /** `http: false` (Slowloris, TCP, UDP): the HTTP rate limiter cannot block it, so nothing is measured as blocked. */
        attack?: {
          http: boolean;
          requests: number;
          offered_rps: number;
          blocked?: number;
          blocked_fraction?: number;
          admitted_rps?: number;
          steady_admitted_rps?: number;
          first_block_s?: number | null;
          blocked_before_engagement?: number;
        };
        legit?: { requests: number; blocked: number; blocked_fraction: number; admitted_rps: number; steady_admitted_rps: number };
        limit: { min_rps: number | null; typical_rps: number | null; below_half_baseline_s: number | null };
        polls: number;
        flagged_polls: number;
        mitigating_polls: number;
        recovery?: { recovered: boolean; seconds: number | null; observed_seconds: number };
      }[];
    };

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

/** Detector context attached to a Suricata alert by `defense-engine` (`/suricata/alerts`). */
export interface SuricataMlContext {
  ml_available: boolean;
  /** The highest-confidence detector poll within 10 s was >= 0.5; null when no poll was recorded then. */
  ml_flagged: boolean | null;
  confidence: number | null;
  /** Request rate (req/s) from the Prometheus-derived feature at that time. */
  request_rate: number | null;
  threshold_rps: number | null;
  policy_state: string | null;
}

export interface SuricataAlert {
  ts: number;
  timestamp: string;
  signature_id: number | null;
  signature: string;
  category: string | null;
  severity: number;
  severity_label: "high" | "medium" | "low";
  action: string | null;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  protocol: string;
  app_proto: string | null;
  /** Capture interface of the primary sighting. */
  in_iface: string | null;
  /** Every interface that saw this event (deduplicated sightings are merged, not listed twice). */
  interfaces: string[];
  /** How many extra sightings (the rate-limiter forwarding the same request) were merged into this alert. */
  hop_alerts: number;
  /** Which Suricata sensor wrote it: ingress (rate-limiter), udp or tcp (target taps). */
  sensor: string;
  ml: SuricataMlContext;
}

export interface SuricataSummary {
  eve_path: string;
  eve_file_present: boolean;
  eve_files: string[];
  merged_duplicate_sightings: number;
  total_ingested: number;
  skipped_lines: number;
  window_seconds: number;
  recent_alerts: number;
  ml_flagged_alerts: number;
  ml_not_flagged_alerts: number;
  no_ml_sample_alerts: number;
  signatures: { signature_id: number | null; signature: string; severity_label: string; count: number }[];
}

/** Unified incident from `defense-engine` `/incidents` (Suricata + Isolation Forest + Prometheus evidence). */
export interface Incident {
  id: string;
  attack_type: "http_flood" | "slowloris" | "udp_flood" | "tcp_exhaustion" | null;
  title: string;
  status: "active" | "closed";
  start: number;
  end: number;
  duration_s: number;
  severity: "high" | "medium" | "low";
  assessment:
    | "corroborated"
    | "suricata_only"
    | "suricata_ml_unavailable"
    | "ml_only"
    | "ml_only_suricata_unavailable";
  detectors: {
    suricata: {
      state: "flagged" | "not_flagged" | "no_data";
      alerts: number;
      sightings: number;
      signatures: string[];
      sensors: string[];
      interfaces: string[];
      sources: { ip: string; alerts: number }[];
    };
    ml: {
      state: "flagged" | "not_flagged" | "no_data";
      polls: number;
      flagged_polls: number;
      longest_run: number;
      peak_confidence: number | null;
    };
  };
  metrics: {
    state: "elevated" | "not_elevated" | "no_baseline" | "no_data" | "not_applicable";
    metric: string | null;
    unit?: string;
    baseline?: number | null;
    peak?: number;
    ratio?: number | null;
  };
  mitigation: {
    applicable: boolean | null;
    policy: string;
    baseline_cap_rps: number;
    current_cap_rps: number;
    samples: number;
    min_cap_rps: number | null;
    cap_lowered: boolean | null;
    lowered_before_start: boolean | null;
    states_seen: string[];
    blocked_rps_peak: number | null;
    note?: string;
  };
  evidence: string[];
  caveats: string[];
}

export interface IncidentsResponse {
  generated_at: number;
  incidents: Incident[];
  inputs: { suricata_files: number; ml_model_loaded: boolean; ml_polls: number; ml_window_seconds: number };
}
