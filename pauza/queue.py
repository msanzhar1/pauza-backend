"""Надёжная очередь Update на Redis.

- Приём: Lua-скрипт атомарно ставит idempotency key (TTL 48 ч) и кладёт Update
  в очередь. Повторный update_id не создаёт новое задание.
- Обработка: BLMOVE в персональный processing-список воркера; после обработки
  задание удаляется (ack). Если воркер умер (heartbeat истёк), reaper
  возвращает его задания в очередь с увеличенным счётчиком попыток.

Тело Update в очереди зашифровано (Fernet, AES-128-CBC + HMAC) и имеет TTL
TEMP_DATA_TTL_SECONDS (≤ 15 минут): просроченные задания расшифровать нельзя,
они отбрасываются. Так Redis выступает «зашифрованным временным хранилищем»
из раздела 11.2 ТЗ, а снимки Redis не содержат открытого текста сообщений.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from redis.asyncio import Redis

QUEUE_KEY = "pauza:queue:updates"
PROCESSING_PREFIX = "pauza:processing:"
WORKERS_KEY = "pauza:workers"
HEARTBEAT_PREFIX = "pauza:worker:hb:"
IDEMPOTENCY_PREFIX = "pauza:idem:update:"
DEAD_LETTER_COUNT_KEY = "pauza:queue:dead_count"

_ENQUEUE_LUA = """
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then
  redis.call('LPUSH', KEYS[2], ARGV[2])
  return 1
end
return 0
"""


EXPIRED_COUNT_KEY = "pauza:queue:expired_count"


@dataclass(slots=True)
class Job:
    raw: str
    token: str  # зашифрованный Update
    update: dict[str, Any]
    attempts: int
    enqueued_at: float

    def __repr__(self) -> str:
        return f"Job(attempts={self.attempts})"

    @property
    def update_id(self) -> int:
        return int(self.update["update_id"])


def _encode(token: str, attempts: int = 0, enqueued_at: float | None = None) -> str:
    return json.dumps(
        {"u": token, "a": attempts, "t": enqueued_at or time.time(), "n": uuid.uuid4().hex[:8]},
        separators=(",", ":"),
    )


class UpdateCipher:
    def __init__(self, key: str, ttl_seconds: int) -> None:
        self._fernet = Fernet(key)
        self.ttl = ttl_seconds

    def encrypt(self, update: dict[str, Any]) -> str:
        return self._fernet.encrypt(json.dumps(update, ensure_ascii=False, separators=(",", ":")).encode()).decode()

    def decrypt(self, token: str) -> dict[str, Any]:
        """InvalidToken — подделка или истёк TTL временных данных."""
        return json.loads(self._fernet.decrypt(token.encode(), ttl=self.ttl))


class UpdateQueue:
    def __init__(self, redis: Redis, idempotency_ttl: int, cipher: UpdateCipher) -> None:
        self.redis = redis
        self.idempotency_ttl = idempotency_ttl
        self.cipher = cipher
        self._enqueue = redis.register_script(_ENQUEUE_LUA)

    async def enqueue_once(self, update: dict[str, Any]) -> bool:
        """True — поставлено в очередь, False — дубликат update_id."""
        key = f"{IDEMPOTENCY_PREFIX}{int(update['update_id'])}"
        payload = _encode(self.cipher.encrypt(update))
        result = await self._enqueue(keys=[key, QUEUE_KEY], args=[self.idempotency_ttl, payload])
        return bool(result)

    async def depth(self) -> int:
        return int(await self.redis.llen(QUEUE_KEY))


class WorkerQueue:
    def __init__(self, redis: Redis, worker_id: str, cipher: UpdateCipher, heartbeat_ttl: int = 30) -> None:
        self.redis = redis
        self.cipher = cipher
        self.worker_id = worker_id
        self.processing_key = f"{PROCESSING_PREFIX}{worker_id}"
        self.heartbeat_ttl = heartbeat_ttl

    async def register(self) -> None:
        await self.redis.sadd(WORKERS_KEY, self.worker_id)
        await self.heartbeat()

    async def unregister(self) -> None:
        # Незавершённые задания возвращаем в очередь (graceful shutdown).
        await self._requeue_list(self.processing_key, bump=False)
        await self.redis.srem(WORKERS_KEY, self.worker_id)
        await self.redis.delete(f"{HEARTBEAT_PREFIX}{self.worker_id}")

    async def heartbeat(self) -> None:
        await self.redis.set(f"{HEARTBEAT_PREFIX}{self.worker_id}", "1", ex=self.heartbeat_ttl)

    async def reserve(self, timeout: float = 5.0) -> Job | None:
        raw = await self.redis.blmove(QUEUE_KEY, self.processing_key, timeout, "RIGHT", "LEFT")
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        try:
            data = json.loads(raw)
            token = data["u"]
            update = self.cipher.decrypt(token)
            return Job(raw=raw, token=token, update=update, attempts=int(data.get("a", 0)), enqueued_at=float(data.get("t", time.time())))
        except InvalidToken:
            # Истёк TTL временных данных (или подделка): содержимое больше не обрабатываем.
            await self.redis.lrem(self.processing_key, 1, raw)
            await self.redis.incr(EXPIRED_COUNT_KEY)
            return None
        except (ValueError, KeyError, TypeError):
            await self.redis.lrem(self.processing_key, 1, raw)
            return None

    async def ack(self, job: Job) -> None:
        await self.redis.lrem(self.processing_key, 1, job.raw)

    async def retry(self, job: Job, max_attempts: int) -> bool:
        """Вернуть задание в очередь. False — попытки исчерпаны (задание удалено)."""
        pipe = self.redis.pipeline(transaction=True)
        pipe.lrem(self.processing_key, 1, job.raw)
        if job.attempts + 1 < max_attempts:
            pipe.lpush(QUEUE_KEY, _encode(job.token, job.attempts + 1, job.enqueued_at))
            await pipe.execute()
            return True
        pipe.incr(DEAD_LETTER_COUNT_KEY)
        await pipe.execute()
        return False

    async def reap_dead_workers(self) -> int:
        moved = 0
        for wid in await self.redis.smembers(WORKERS_KEY):
            wid = wid.decode() if isinstance(wid, bytes) else wid
            if wid == self.worker_id:
                continue
            if not await self.redis.exists(f"{HEARTBEAT_PREFIX}{wid}"):
                moved += await self._requeue_list(f"{PROCESSING_PREFIX}{wid}", bump=True)
                await self.redis.srem(WORKERS_KEY, wid)
        return moved

    async def _requeue_list(self, key: str, bump: bool) -> int:
        moved = 0
        while True:
            raw = await self.redis.rpop(key)
            if raw is None:
                return moved
            raw = raw.decode() if isinstance(raw, bytes) else raw
            try:
                data = json.loads(raw)
                payload = _encode(data["u"], int(data.get("a", 0)) + (1 if bump else 0), float(data.get("t", time.time())))
            except (ValueError, KeyError, TypeError):
                continue
            await self.redis.rpush(QUEUE_KEY, payload)
            moved += 1
