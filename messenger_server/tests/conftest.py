import os
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.db.session import Base, get_db
from app.db import models
from app.main import app


TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

@pytest_asyncio.fixture(scope="function")
async def test_engine():
    engine = create_async_engine(TEST_DATABASE_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine

    await engine.dispose()
    if os.path.exists("./test.db"):
        os.remove("./test.db")

@pytest_asyncio.fixture(scope="function")
async def test_session_factory(test_engine):
    return async_sessionmaker(test_engine, expire_on_commit=False)

@pytest_asyncio.fixture(scope="function")
async def db_session(test_session_factory):
    async with test_session_factory() as session:
        yield session

@pytest_asyncio.fixture(scope="function")
async def client(test_session_factory):
    async def override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
