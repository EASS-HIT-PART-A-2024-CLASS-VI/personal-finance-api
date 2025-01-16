# conftest.py

import asyncio
import pytest
import warnings
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture(scope="session")
def event_loop():
    # Create a new event loop for the session to avoid "Event loop is closed" errors.
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def anyio_backend():
    return 'asyncio'


@pytest_asyncio.fixture(scope="function")
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(base_url="http://testserver", transport=transport) as client:
        yield client


@pytest.fixture(autouse=True)
def ignore_warnings():
    warnings.filterwarnings("ignore")
