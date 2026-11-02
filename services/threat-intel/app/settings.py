"""Central environment-variable configuration for the threat-intel service.

Every other module reads config through `get_settings()` instead of calling
`os.environ` directly. Doing it here in one place is what lets provider
connectors (Stage B) self-disable cleanly when a required API key is
missing: a connector only has to check one settings field, and this module
is the only place that knows how that field was sourced (env var, default,
future secrets-manager, etc).
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Core infra ---
    DATABASE_URL: str = "postgresql+asyncpg://threat_intel:threat_intel_dev_only@threat-intel-db:5432/threat_intel"
    REDIS_URL: str = "redis://threat-intel-redis:6379/0"
    LOG_LEVEL: str = "INFO"

    # --- Key-gated provider credentials. Empty string == connector disabled. ---
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # --- Dashboard CORS origins (comma-separated) ---
    DASHBOARD_ORIGINS: str = "http://localhost:5173,http://localhost:8080"

    # --- Per-provider poll intervals (seconds). Individually overridable so
    # a slow/rate-limited provider (e.g. NVD) doesn't force every provider
    # onto the same cadence. ---
    THREATFOX_POLL_SECONDS: int = 300
    CISA_KEV_POLL_SECONDS: int = 3600
    SPAMHAUS_DROP_POLL_SECONDS: int = 3600
    EMERGING_THREATS_POLL_SECONDS: int = 900
    NVD_CVE_POLL_SECONDS: int = 900
    ABUSEIPDB_POLL_SECONDS: int = 900
    OTX_POLL_SECONDS: int = 600

    # --- Dedup / confidence scoring ---
    CONFIDENCE_WINDOW_HOURS: int = 24

    # --- Stage I: sandbox <-> global-threat-intel correlation (heuristic
    # only -- see app/correlation/engine.py). `defense-engine` is on the
    # sandbox side of the project but is reached read-only, over the
    # `public_net` the two modules already share; this is the one approved
    DEFENSE_ENGINE_METRICS_URL: str = "http://defense-engine:9300/metrics"
    CORRELATION_MIN_CONFIDENCE: float = 0.7
    CORRELATION_WINDOW_HOURS: int = 24

    # --- Geolocation enrichment (Stage C.5). Empty MAXMIND_LICENSE_KEY ==
    # updater self-disables and enrichment stays a no-op, same pattern as
    # ABUSEIPDB_API_KEY/OTX_API_KEY above. ---
    MAXMIND_LICENSE_KEY: str = ""
    GEOIP_DB_DIR: str = "/app/data/geoip"
    GEOIP_UPDATE_POLL_SECONDS: int = 86400  # daily refresh check (MaxMind publishes GeoLite2 twice/week)
    GEOIP_CACHE_TTL_SECONDS: int = 30 * 24 * 3600  # 30 days -- IP geolocation rarely changes
    # Public fallback API used ONLY for interactive single-IP lookups, never
    # bulk ingestion. Off by default -- see the approved Stage C.5 design.
    GEOIP_FALLBACK_API_ENABLED: bool = False

    @property
    def dashboard_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.DASHBOARD_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
