"""Async SQLAlchemy engine/session plumbing.

One module-level engine, created lazily on first use so importing this
module (e.g. for its `Base`) never opens a connection by itself. The
FastAPI lifespan handler in `app.main` owns disposing the engine on
shutdown, which is what gives the service graceful shutdown for its DB
connection pool.
"""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

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


async def init_db() -> None:
    """Creates tables if they don't exist yet.

    The rest of the repo has no migration tooling (see `defense/classifier`,
    which just loads a joblib file), so this service matches that lightweight
    style instead of introducing Alembic for a schema that has exactly one
    version so far. If/when the schema needs versioned migrations, Alembic
    can be layered on top of these same models without changing them.
    """
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
