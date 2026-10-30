"""Alembic migration tests against a real Postgres.

Skipped unless MIGRATION_TEST_DATABASE_URL is set (CI provides a Postgres
service). The tests reset the `public` schema of that database, so they refuse
to run unless the database name contains "test".
"""
import os

import pytest
import pytest_asyncio
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app.common import models  # noqa: F401  -- registers ORM tables on Base.metadata
from app.common.db import BASELINE_REVISION, BASELINE_TABLES, Base, init_db

URL = os.environ.get("MIGRATION_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.skipif(not URL, reason="MIGRATION_TEST_DATABASE_URL not set"),
    pytest.mark.asyncio,
]


@pytest_asyncio.fixture
async def engine():
    assert "test" in (make_url(URL).database or ""), "refusing to reset a database whose name lacks 'test'"
    eng = create_async_engine(URL)
    async with eng.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    yield eng
    await eng.dispose()


async def _tables(engine) -> set[str]:
    async with engine.connect() as conn:
        return await conn.run_sync(lambda c: set(inspect(c).get_table_names()))


async def _version(engine) -> str:
    async with engine.connect() as conn:
        return (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()


async def test_empty_database_is_migrated_to_models(engine):
    await init_db(URL)
    assert BASELINE_TABLES <= await _tables(engine)
    assert await _version(engine) == BASELINE_REVISION

    # The migrations must produce exactly the schema the ORM models describe.
    async with engine.connect() as conn:
        diff = await conn.run_sync(lambda c: compare_metadata(MigrationContext.configure(c), Base.metadata))
    assert diff == []


async def test_existing_create_all_database_is_stamped_without_data_loss(engine):
    async with engine.begin() as conn:  # what the service did before Alembic
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text(
            "INSERT INTO iocs (ioc, ioc_type, threat_type, confidence_score, first_seen, last_seen, source_count) "
            "VALUES ('203.0.113.7', 'ip', 'scanner', 0.9, now(), now(), 1)"
        ))
    await init_db(URL)
    assert await _version(engine) == BASELINE_REVISION
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT ioc FROM iocs"))).scalar_one() == "203.0.113.7"


async def test_init_db_is_idempotent(engine):
    await init_db(URL)
    await init_db(URL)
    assert await _version(engine) == BASELINE_REVISION
