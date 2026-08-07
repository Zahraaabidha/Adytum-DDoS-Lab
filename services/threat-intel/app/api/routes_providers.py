"""Provider transparency endpoint.

Surfaces exactly what `main.py`'s startup log already reports (enabled vs
disabled-for-missing-key) as JSON, so the dashboard's Settings page
(a later stage) can show e.g. "AbuseIPDB: disabled, missing API key"
without scraping logs.
"""
from fastapi import APIRouter

from app.provider.base import PROVIDER_REGISTRY
from app.settings import get_settings

router = APIRouter(prefix="/api/providers", tags=["providers"])


@router.get("/status")
async def providers_status():
    settings = get_settings()
    providers = []
    for provider_cls in PROVIDER_REGISTRY:
        provider = provider_cls()
        providers.append(
            {
                "name": provider.name,
                "requires_key": provider.requires_key,
                "enabled": provider.is_enabled(settings),
                "poll_interval_seconds": provider.poll_interval_seconds,
                "event_kind": provider.event_kind,
            }
        )
    return {"providers": providers}
