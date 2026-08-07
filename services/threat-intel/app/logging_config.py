"""Structured logging setup, shared by every module in this service.

Mirrors the logging style already used in `defense/engine.py`
(`logging.basicConfig` with a timestamp/level/message format) so log output
looks consistent across SENTINEL LAB's services, but centralized here so
Stage B's per-provider connectors all get the same formatter without each
one configuring logging itself.
"""
import logging

from app.settings import get_settings


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
