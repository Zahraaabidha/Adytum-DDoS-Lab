"""WebSocket endpoint streaming newly ingested IOC events.

Subscribes to the Redis pub/sub channel the ingestion loop publishes to
(`app.ingest.LIVE_CHANNEL`) rather than holding any direct reference to the
scheduler -- if this service ever runs multiple uvicorn workers, every
worker's WS clients still see every event, because Redis (not in-process
state) is the fan-out point.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.common.cache import get_redis
from app.ingest import LIVE_CHANNEL
from app.logging_config import get_logger

log = get_logger("threat-intel.ws")

router = APIRouter()


@router.websocket("/ws/threats")
async def threats_ws(websocket: WebSocket):
    await websocket.accept()
    pubsub = get_redis().pubsub()
    await pubsub.subscribe(LIVE_CHANNEL)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            await websocket.send_text(message["data"])
    except WebSocketDisconnect:
        log.debug("WebSocket client disconnected")
    finally:
        await pubsub.unsubscribe(LIVE_CHANNEL)
        await pubsub.aclose()
