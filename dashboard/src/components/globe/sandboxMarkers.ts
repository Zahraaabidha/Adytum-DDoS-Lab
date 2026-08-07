import type { LiveThreatEvent, SandboxFeedEvent, ThreatEvent } from "../../types/threat";

/**
 * Stage I follow-up fix: the globe was wired exclusively to
 * `/api/threats/map` (threat-intel's GeoIP-enriched IOCs), so it stayed
 * empty whenever GeoIP enrichment wasn't configured -- which is the default
 * state (no MAXMIND_LICENSE_KEY). Sandbox attack events already carry a
 * synthetic lat/lon (`attackers/common/identity.py`'s `random_fake_identity`,
 * recorded per-event by `attackers/common/recorder.py`, served by
 * `globe/server.py`'s `GET /api/feed`) -- this maps that existing data into
 * the same shapes `MarkerLayer`/`LivePulseLayer` already consume, so a
 * sandbox attack starting produces globe activity immediately, independent
 * of GeoIP. `ioc_type: "sandbox"` keeps these markers out of
 * `DetailPanel`'s IOC-search path (that search is for real threat-intel
 * indicators only).
 */
export function sandboxEventToThreatEvent(event: SandboxFeedEvent): ThreatEvent {
  const timestamp = new Date(event.ts * 1000).toISOString();
  return {
    ioc: event.fake_ip,
    ioc_type: "sandbox",
    country: event.city,
    lat: event.lat,
    lon: event.lon,
    asn: null,
    organization: null,
    threat_type: event.attack_type,
    attack_family: event.attack_type,
    category: "sandbox_simulation",
    confidence_score: 1,
    source_count: 1,
    first_seen: timestamp,
    last_seen: timestamp,
  };
}

export function sandboxEventToLiveThreatEvent(event: SandboxFeedEvent): LiveThreatEvent {
  return {
    ioc: event.fake_ip,
    ioc_type: "sandbox",
    country: event.city,
    city: event.city,
    lat: event.lat,
    lon: event.lon,
    threat_type: event.attack_type,
    attack_family: event.attack_type,
    confidence_score: 1,
    source: "sandbox",
    timestamp: new Date(event.ts * 1000).toISOString(),
  };
}
