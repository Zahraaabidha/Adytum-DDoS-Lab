"""Stage I: `GET /api/threats/correlation` -- the one deliberate, narrow
integration seam between the Global Threat Intelligence module and the
Sandbox Lab. `threat-intel` reads `defense-engine`'s existing `/metrics`
over `public_net`, the network the two already share; this endpoint adds
no new network attachment, and `threat-intel` is not added to
`target_net` to serve it (see `app/correlation/engine.py` and
PROJECT_EXECUTION_PLAN.md Stage I).
"""
import httpx
from fastapi import APIRouter

from app.common.db import session_scope
from app.correlation.engine import compute_correlation
from app.settings import get_settings

router = APIRouter(prefix="/api/threats", tags=["correlation"])


@router.get("/correlation")
async def correlation():
    settings = get_settings()
    async with httpx.AsyncClient() as client, session_scope() as session:
        result = await compute_correlation(session, client, settings)
    return {
        "available": result.available,
        "correlation_percentage": result.correlation_percentage,
        "observation": result.observation,
        "matched_features": result.matched_features,
        "disclaimer": result.disclaimer,
        "compared_ioc_count": result.compared_ioc_count,
        "generated_at": result.generated_at,
    }
