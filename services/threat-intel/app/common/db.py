"""Async SQLAlchemy engine/session plumbing.

One module-level engine, created lazily on first use so importing this
module (e.g. for its `Base`) never opens a connection by itself. The
FastAPI lifespan handler in `app.main` owns disposing the engine on
shutdown, which is what gives the service graceful shutdown for its DB
connection pool.
"""
import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.settings import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().DATABASE_URL, pool_pre_ping=True)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    factory = get_session_factory()
    async with factory() as session:
        yield session


SERVICE_DIR = Path(__file__).resolve().parents[2]  # holds alembic.ini and migrations/
BASELINE_REVISION = "0001"
BASELINE_TABLES = {"iocs", "ioc_sightings", "cves"}


def alembic_config(url: str | None = None) -> Config:
    config = Config(str(SERVICE_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(SERVICE_DIR / "migrations"))
    config.attributes["configure_logger"] = False  # keep the service's own logging setup
    if url:
        config.attributes["url"] = url
    return config


async def init_db(url: str | None = None) -> None:
    """Brings the schema up to date by running Alembic migrations.

    A database created by the earlier `create_all()` startup already matches
    the baseline migration, so it is stamped as being at the baseline instead
    of having its tables created again; nothing existing is altered or
    dropped. Anything else (empty database, or already under Alembic) is
    simply upgraded to head. Alembic runs in a worker thread because its
    async env.py starts its own event loop.
    """
    engine = get_engine() if url is None else create_async_engine(url, pool_pre_ping=True)
    try:
        async with engine.connect() as conn:
            existing = await conn.run_sync(lambda sync_conn: set(inspect(sync_conn).get_table_names()))
    finally:
        if url is not None:
            await engine.dispose()

    config = alembic_config(url)
    if "alembic_version" not in existing and BASELINE_TABLES <= existing:
        await asyncio.to_thread(command.stamp, config, BASELINE_REVISION)
    await asyncio.to_thread(command.upgrade, config, "head")


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
