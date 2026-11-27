import time
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from cryptography.fernet import Fernet

from pauza.db.models import Check, CheckStatus, InputType
from pauza.queue import EXPIRED_COUNT_KEY, QUEUE_KEY, UpdateCipher, UpdateQueue, WorkerQueue
from pauza.worker import Worker

from .conftest import text_update


async def test_retry_then_drop(redis):
    cipher = UpdateCipher(Fernet.generate_key().decode(), 900)
    q = UpdateQueue(redis, 3600, cipher)
    w = WorkerQueue(redis, "w1", cipher)
    await q.enqueue_once(text_update("x"))
    job = await w.reserve(0.1)
    assert await w.retry(job, max_attempts=2) is True
    job = await w.reserve(0.1)
    assert job.attempts == 1
    assert await w.retry(job, max_attempts=2) is False
    assert await redis.llen(QUEUE_KEY) == 0 and await redis.llen(w.processing_key) == 0


async def test_dead_worker_jobs_requeued(redis):
    cipher = UpdateCipher(Fernet.generate_key().decode(), 900)
    q = UpdateQueue(redis, 3600, cipher)
    dead = WorkerQueue(redis, "dead", cipher)
    alive = WorkerQueue(redis, "alive", cipher)
    await dead.register()
    await q.enqueue_once(text_update("x"))
    assert await dead.reserve(0.1) is not None
    await redis.delete("pauza:worker:hb:dead")  # heartbeat истёк
    await alive.register()
    assert await alive.reap_dead_workers() == 1
    job = await alive.reserve(0.1)
    assert job is not None and job.attempts == 1


async def test_graceful_unregister_returns_jobs(redis):
    cipher = UpdateCipher(Fernet.generate_key().decode(), 900)
    q = UpdateQueue(redis, 3600, cipher)
    w = WorkerQueue(redis, "w", cipher)
    await w.register()
    await q.enqueue_once(text_update("x"))
    await w.reserve(0.1)
    await w.unregister()
    assert await redis.llen(QUEUE_KEY) == 1


async def test_expired_temp_data_is_dropped(redis):
    key = Fernet.generate_key().decode()
    q = UpdateQueue(redis, 3600, UpdateCipher(key, 900))
    await q.enqueue_once(text_update("x"))
    w = WorkerQueue(redis, "w", UpdateCipher(key, 1))
    # Fernet проверяет TTL по метке времени токена
    import pauza.queue as pq

    real = pq.Fernet.decrypt

    def later(self, token, ttl=None):
        return pq.Fernet.decrypt_at_time(self, token, ttl, int(time.time()) + 3600)

    pq.Fernet.decrypt = later
    try:
        assert await w.reserve(0.1) is None
    finally:
        pq.Fernet.decrypt = real
    assert int(await redis.get(EXPIRED_COUNT_KEY)) == 1
    assert await redis.llen(w.processing_key) == 0


async def test_infra_error_requeues(container, monkeypatch):
    async def broken(update, enqueued_at):
        raise ConnectionError("db down")

    monkeypatch.setattr(container.handler, "handle", broken)
    await container.queue.enqueue_once(text_update("x"))
    worker = Worker(container, "w")
    job = await worker.queue.reserve(0.1)
    await worker.process(job)
    assert await container.redis.llen(QUEUE_KEY) == 1


async def test_maintenance_expires_and_purges(container):
    now = datetime.now(UTC)
    async with container.db.session() as s:
        s.add(Check(telegram_update_id=1, input_type=InputType.TEXT, status=CheckStatus.PROCESSING, created_at=now - timedelta(hours=1), expires_at=now + timedelta(days=1)))
        s.add(Check(telegram_update_id=2, input_type=InputType.TEXT, status=CheckStatus.COMPLETED, created_at=now - timedelta(days=400), expires_at=now - timedelta(days=1)))
    await Worker(container, "w").maintenance()
    async with container.db.session() as s:
        rows = list((await s.execute(sa.select(Check))).scalars())
    assert len(rows) == 1 and rows[0].status == CheckStatus.FAILED and rows[0].error_code == "EXPIRED"
