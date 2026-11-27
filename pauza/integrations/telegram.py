"""Клиент Telegram Bot API с повторами (раздел 8.1, 14).

- exponential backoff + jitter, уважение `retry_after` (429);
- конфигурируемые число попыток и максимальный возраст сообщения;
- токен бота не попадает в логи (логгер httpx отключён, URL не логируется).
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from pauza.logs import get_logger

log = get_logger(__name__)


class TelegramError(Exception):
    def __init__(self, code: str, http_status: int | None = None, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.retryable = retryable


@dataclass(slots=True)
class TelegramMessage:
    text: str  # HTML, пользовательские данные уже экранированы
    keyboard: list[list[dict[str, str]]] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class TelegramClient:
    def __init__(
        self,
        token: str,
        api_base: str = "https://api.telegram.org",
        timeout: float = 10.0,
        max_attempts: int = 5,
        max_message_age: float = 300.0,
        http: httpx.AsyncClient | None = None,
        sleep=asyncio.sleep,
    ) -> None:
        self._token = token
        self._base = f"{api_base.rstrip('/')}/bot{token}"
        self._file_base = f"{api_base.rstrip('/')}/file/bot{token}"
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self.max_attempts = max_attempts
        self.max_message_age = max_message_age
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    async def call(self, method: str, payload: dict[str, Any], created_at: float | None = None) -> dict[str, Any]:
        created_at = created_at or time.monotonic()
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._http.post(f"{self._base}/{method}", json=payload)
            except httpx.HTTPError:
                err = TelegramError("TELEGRAM_SEND_FAILED", None, retryable=True)
                retry_after = None
            else:
                data = _json(resp)
                if resp.status_code == 200 and data.get("ok"):
                    return data.get("result", {})
                retry_after = (data.get("parameters") or {}).get("retry_after")
                retryable = resp.status_code == 429 or resp.status_code >= 500
                err = TelegramError("TELEGRAM_SEND_FAILED", resp.status_code, retryable=retryable)
            if not err.retryable or attempt >= self.max_attempts:
                log.warning("telegram call failed", extra={"component": "telegram", "method": method, "http_status": err.http_status, "attempt": attempt, "error_code": err.code})
                raise err
            delay = float(retry_after) if retry_after else min(30.0, 0.5 * 2 ** (attempt - 1)) * (0.5 + random.random())
            if time.monotonic() + delay - created_at > self.max_message_age:
                log.warning("telegram message too old to retry", extra={"component": "telegram", "method": method, "attempt": attempt, "error_code": err.code})
                raise err
            log.info("telegram retry", extra={"component": "telegram", "method": method, "attempt": attempt, "retry_after": retry_after, "http_status": err.http_status})
            await self._sleep(delay)

    async def send_message(self, chat_id: int, message: TelegramMessage) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": message.text,
            "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": True},
            **message.extra,
        }
        if message.keyboard:
            payload["reply_markup"] = {"inline_keyboard": message.keyboard}
        return await self.call("sendMessage", payload)

    async def answer_callback(self, callback_query_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text[:200]
        try:
            await self.call("answerCallbackQuery", payload)
        except TelegramError:
            pass  # не критично: истёкший callback

    async def get_file_path(self, file_id: str) -> tuple[str, int | None]:
        result = await self.call("getFile", {"file_id": file_id})
        path = result.get("file_path")
        if not path:
            raise TelegramError("TELEGRAM_FILE_UNAVAILABLE")
        return path, result.get("file_size")

    async def download_file(self, file_path: str, max_bytes: int) -> bytes:
        """Скачать файл через Telegram file API с жёстким лимитом размера."""
        buf = bytearray()
        try:
            async with self._http.stream("GET", f"{self._file_base}/{file_path}") as resp:
                if resp.status_code != 200:
                    raise TelegramError("TELEGRAM_FILE_UNAVAILABLE", resp.status_code)
                declared = resp.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise TelegramError("INPUT_TOO_LARGE")
                async for chunk in resp.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise TelegramError("INPUT_TOO_LARGE")
        except httpx.HTTPError:
            raise TelegramError("TELEGRAM_FILE_UNAVAILABLE") from None
        return bytes(buf)

    async def set_webhook(self, url: str, secret_token: str) -> dict[str, Any]:
        return await self.call(
            "setWebhook",
            {
                "url": url,
                "secret_token": secret_token,
                "allowed_updates": ["message", "callback_query", "my_chat_member"],
                "drop_pending_updates": False,
                "max_connections": 40,
            },
        )

    async def set_my_commands(self, commands: list[tuple[str, str]]) -> None:
        await self.call("setMyCommands", {"commands": [{"command": c, "description": d} for c, d in commands]})


def _json(resp: httpx.Response) -> dict[str, Any]:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}
