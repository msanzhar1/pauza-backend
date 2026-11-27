"""Структурированные JSON-логи без пользовательского содержимого.

Правило: в логи попадают только технические поля из белого списка
(компонент, код ошибки, длительность, псевдонимизированные идентификаторы).
Текст, URL, OCR-результат, file_path и callback payload никогда не логируются.
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import logging
import sys
import time
import uuid

correlation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)

# Поля, которые разрешено передавать в extra. Всё остальное отбрасывается.
ALLOWED_FIELDS = frozenset(
    {
        "component",
        "event",
        "error_code",
        "duration_ms",
        "update_ref",
        "check_id",
        "input_type",
        "risk_level",
        "status",
        "attempt",
        "retry_after",
        "http_status",
        "method",
        "queue_depth",
        "count",
        "indicator_codes",
        "provider",
        "worker_id",
    }
)

_PSEUDO_SALT = uuid.uuid4().hex  # заменяется ключом из настроек в configure_logging


def pseudonymize(value: object) -> str:
    """Короткий псевдоним идентификатора для логов (update_id и т.п.).

    Ключ общий для API и воркера, поэтому одно и то же Update можно проследить
    между процессами, но нельзя восстановить исходный ID.
    """
    return hmac.new(_PSEUDO_SALT.encode(), f"log:{value}".encode(), hashlib.sha256).hexdigest()[:12]


def new_correlation_id() -> str:
    cid = uuid.uuid4().hex[:16]
    correlation_id_var.set(cid)
    return cid


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            # Сообщение — всегда константная строка из кода, не пользовательские данные.
            "msg": record.msg if isinstance(record.msg, str) else "event",
        }
        cid = correlation_id_var.get()
        if cid:
            payload["correlation_id"] = cid
        for key in ALLOWED_FIELDS:
            if key in record.__dict__:
                payload[key] = record.__dict__[key]
        if record.exc_info and record.exc_info[0] is not None:
            # Только тип исключения: сообщение исключения может содержать данные.
            payload["exc_type"] = record.exc_info[0].__name__
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO", pseudonym_key: str | None = None) -> None:
    global _PSEUDO_SALT
    if pseudonym_key:
        _PSEUDO_SALT = pseudonym_key
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Логи сторонних библиотек могут содержать URL с токеном бота (httpx) или тела запросов.
    for noisy in ("httpx", "httpcore", "uvicorn.access", "asyncio", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
