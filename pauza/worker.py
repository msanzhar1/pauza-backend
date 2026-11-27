"""Фоновый воркер: забирает Update из очереди, обрабатывает, подтверждает.

Graceful shutdown: по SIGTERM/SIGINT воркер перестаёт брать новые задания,
дорабатывает текущее и возвращает незавершённые в очередь.
"""

from __future__ import annotations

import asyncio
import signal
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa

from pauza import metrics
from pauza.config import get_settings
from pauza.container import Container, build_container
from pauza.db.models import Check, CheckStatus, User
from pauza.integrations.ocr import cleanup_temp_dir
from pauza.logs import configure_logging, get_logger, new_correlation_id, pseudonymize
from pauza.queue import Job, WorkerQueue

log = get_logger(__name__)

MAINTENANCE_INTERVAL = 60.0


class Worker:
    def __init__(self, container: Container, worker_id: str | None = None) -> None:
        self.c = container
        self.worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.queue = WorkerQueue(container.redis, self.worker_id, container.cipher)
        self._stop = asyncio.Event()
        self._last_maintenance = 0.0

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        await self.queue.register()
        log.info("worker started", extra={"component": "worker", "worker_id": self.worker_id})
        try:
            while not self._stop.is_set():
                await self.queue.heartbeat()
                await self._maybe_maintenance()
                job = await self.queue.reserve(timeout=2.0)
                if job is None:
                    continue
                await self.process(job)
        finally:
            await self.queue.unregister()
            log.info("worker stopped", extra={"component": "worker", "worker_id": self.worker_id})

    async def process(self, job: Job) -> None:
        new_correlation_id()
        started = time.monotonic()
        metrics.LATENCY.labels("queue_wait").observe(max(0.0, time.time() - job.enqueued_at))
        try:
            status = await self.c.handler.handle(job.update, job.enqueued_at)
        except Exception:
            # Ошибка инфраструктуры (БД/Redis): повторяем ограниченное число раз.
            requeued = await self.queue.retry(job, self.c.settings.job_max_attempts)
            log.exception(
                "job failed",
                extra={"component": "worker", "error_code": "INTERNAL_ERROR", "update_ref": pseudonymize(job.update_id), "attempt": job.attempts + 1, "status": "requeued" if requeued else "dropped"},
            )
            return
        await self.queue.ack(job)
        log.info("job done", extra={"component": "worker", "update_ref": pseudonymize(job.update_id), "status": status, "duration_ms": int((time.monotonic() - started) * 1000)})

    async def _maybe_maintenance(self) -> None:
        now = time.monotonic()
        if now - self._last_maintenance < MAINTENANCE_INTERVAL:
            return
        self._last_maintenance = now
        try:
            await self.maintenance()
        except Exception:
            log.exception("maintenance failed", extra={"component": "worker", "error_code": "INTERNAL_ERROR"})

    async def maintenance(self) -> None:
        s = self.c.settings
        moved = await self.queue.reap_dead_workers()
        if moved:
            log.warning("requeued jobs of dead workers", extra={"component": "worker", "count": moved})
        removed = cleanup_temp_dir(s.temp_dir, s.temp_data_ttl_seconds)
        if removed:
            log.warning("removed stale temp files", extra={"component": "worker", "count": removed})
        metrics.QUEUE_DEPTH.set(await self.c.queue.depth())
        now = datetime.now(UTC)
        async with self.c.db.session() as session:
            # Зависшие проверки (воркер упал) помечаем как FAILED.
            await session.execute(
                sa.update(Check)
                .where(Check.status.in_([CheckStatus.RECEIVED, CheckStatus.PROCESSING]), Check.created_at < now - timedelta(seconds=s.temp_data_ttl_seconds))
                .values(status=CheckStatus.FAILED, error_code="EXPIRED", completed_at=now)
            )
            # Срок хранения метаданных проверок.
            await session.execute(sa.delete(Check).where(Check.expires_at < now))
            if s.user_inactivity_days:
                await session.execute(sa.delete(User).where(User.last_active_at < now - timedelta(days=s.user_inactivity_days)))


async def main() -> None:
    settings = get_settings()
    configure_logging(settings.app_log_level, settings.id_hash_key.get_secret_value())
    from prometheus_client import start_http_server

    start_http_server(settings.metrics_port)
    container = build_container(settings)
    worker = Worker(container)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.stop)
    try:
        await worker.run()
    finally:
        await container.aclose()


if __name__ == "__main__":
    asyncio.run(main())
