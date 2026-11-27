"""Rate limit, временные состояния диалога и подписанные callback-кнопки."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass
from enum import Enum

from redis.asyncio import Redis

RATE_PREFIX = "pauza:rl:"
STATE_PREFIX = "pauza:state:"


def user_hash(id_hash_key: str, telegram_user_id: int) -> str:
    """Keyed hash Telegram ID: используется вместо сырого ID в БД и ключах Redis."""
    return hmac.new(id_hash_key.encode(), str(telegram_user_id).encode(), hashlib.sha256).hexdigest()


# --- Rate limit -------------------------------------------------------------

_RATE_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return n
"""


@dataclass(slots=True)
class RateLimit:
    name: str
    window_seconds: int
    max_hits: int


class RateLimiter:
    """Фиксированные окна в Redis. Ключи содержат только keyed hash пользователя."""

    def __init__(self, redis: Redis, limits: list[RateLimit]) -> None:
        self.redis = redis
        self.limits = limits
        self._script = redis.register_script(_RATE_LUA)

    async def hit(self, subject: str) -> bool:
        """Учесть попытку. False — лимит превышен."""
        now = int(time.time())
        allowed = True
        for lim in self.limits:
            bucket = now // lim.window_seconds
            key = f"{RATE_PREFIX}{lim.name}:{subject}:{bucket}"
            n = int(await self._script(keys=[key], args=[lim.window_seconds + 5]))
            if n > lim.max_hits:
                allowed = False
        return allowed

    async def forget(self, subject: str) -> None:
        async for key in self.redis.scan_iter(match=f"{RATE_PREFIX}*:{subject}:*"):
            await self.redis.delete(key)


# --- Состояния диалога ------------------------------------------------------


class DialogState(str, Enum):
    NEW = "NEW"
    AWAITING_INPUT = "AWAITING_INPUT"
    READY = "READY"


class StateStore:
    def __init__(self, redis: Redis, ttl_seconds: int) -> None:
        self.redis = redis
        self.ttl = ttl_seconds

    async def get(self, subject: str) -> DialogState | None:
        raw = await self.redis.get(f"{STATE_PREFIX}{subject}")
        if raw is None:
            return None
        raw = raw.decode() if isinstance(raw, bytes) else raw
        try:
            return DialogState(raw)
        except ValueError:
            return None

    async def set(self, subject: str, state: DialogState) -> None:
        await self.redis.set(f"{STATE_PREFIX}{subject}", state.value, ex=self.ttl)

    async def clear(self, subject: str) -> None:
        await self.redis.delete(f"{STATE_PREFIX}{subject}")


# --- Подписанные callback payload ------------------------------------------
# Формат (≤ 64 байт, лимит Telegram): <action>.<arg>.<exp base36>.<sig 16>
# Подпись HMAC-SHA256 покрывает action, arg, exp и hash пользователя, поэтому
# кнопку нельзя использовать от имени другого пользователя или после срока.


class CallbackError(Exception):
    pass


ALLOWED_ACTIONS = frozenset({"fh", "fi", "fn", "hn", "rg", "st", "dl", "dk"})
# fh/fi/fn — обратная связь HELPFUL/INCORRECT/NEED_HELP (arg = check id)
# hn — «Я уже ответил или заплатил»; rg — выбор региона (arg = код или "-")
# st — открыть настройки; dl — запрос удаления; dk — подтверждение удаления


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode_check_id(check_id: uuid.UUID) -> str:
    return _b64(check_id.bytes)


def decode_check_id(arg: str) -> uuid.UUID:
    return uuid.UUID(bytes=_unb64(arg))


class CallbackSigner:
    def __init__(self, key: str, ttl_seconds: int) -> None:
        self.key = key.encode()
        self.ttl = ttl_seconds

    def _sig(self, action: str, arg: str, exp: str, subject: str) -> str:
        msg = f"{action}|{arg}|{exp}|{subject}".encode()
        return _b64(hmac.new(self.key, msg, hashlib.sha256).digest()[:12])

    def sign(self, action: str, arg: str, subject: str, now: float | None = None) -> str:
        if action not in ALLOWED_ACTIONS or "." in arg:
            raise ValueError("bad callback")
        exp = _base36(int((now or time.time()) + self.ttl))
        payload = f"{action}.{arg}.{exp}.{self._sig(action, arg, exp, subject)}"
        if len(payload.encode()) > 64:
            raise ValueError("callback too long")
        return payload

    def verify(self, data: str, subject: str, now: float | None = None) -> tuple[str, str]:
        parts = (data or "").split(".")
        if len(parts) != 4:
            raise CallbackError("format")
        action, arg, exp, sig = parts
        if action not in ALLOWED_ACTIONS:
            raise CallbackError("action")
        if not hmac.compare_digest(sig, self._sig(action, arg, exp, subject)):
            raise CallbackError("signature")
        try:
            if int(exp, 36) < (now or time.time()):
                raise CallbackError("expired")
        except ValueError:
            raise CallbackError("format") from None
        return action, arg


def _base36(n: int) -> str:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = chars[r] + out
    return out or "0"
