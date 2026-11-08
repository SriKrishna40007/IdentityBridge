import asyncio

import pytest

from identitybridge.config.settings import get_settings
from identitybridge.main import create_app


@pytest.mark.anyio
async def test_jit_worker_stays_disabled_by_default(monkeypatch):
    settings = get_settings().model_copy(update={"jit_worker_enabled": False})

    started = False

    async def unexpected_worker(application):
        nonlocal started
        started = True

    monkeypatch.setattr(
        "identitybridge.main.run_jit_expiry_worker",
        unexpected_worker,
    )

    application = create_app(settings)

    async with application.router.lifespan_context(application):
        await asyncio.sleep(0)

    assert started is False


@pytest.mark.anyio
async def test_enabled_jit_worker_starts_and_stops_cleanly(monkeypatch):
    settings = get_settings().model_copy(update={"jit_worker_enabled": True})

    started = asyncio.Event()
    stopped = asyncio.Event()

    async def fake_worker(application):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(
        "identitybridge.main.run_jit_expiry_worker",
        fake_worker,
    )

    application = create_app(settings)

    async with application.router.lifespan_context(application):
        await asyncio.wait_for(started.wait(), timeout=2)
        assert not stopped.is_set()

    assert stopped.is_set()
