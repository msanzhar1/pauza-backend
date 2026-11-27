"""Webhook API (раздел 12). Публичные endpoint-ы: только Telegram webhook и health."""

from __future__ import annotations

import hmac
import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from redis.asyncio import Redis

from pauza import metrics
from pauza.config import Settings, get_settings
from pauza.db.session import Database, engine_from_settings
from pauza.logs import configure_logging, get_logger, new_correlation_id, pseudonymize
from pauza.queue import UpdateCipher, UpdateQueue

log = get_logger(__name__)

ALLOWED_UPDATE_KEYS = {"message", "callback_query", "my_chat_member"}
_IP_RL_LUA = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 65) end
return n
"""


def create_app(settings: Settings | None = None, redis: Redis | None = None, db: Database | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging(settings.app_log_level, settings.id_hash_key.get_secret_value())
        app.state.redis = redis or Redis.from_url(settings.redis_url)
        app.state.db = db or Database(engine_from_settings(settings))
        cipher = UpdateCipher(settings.queue_encryption_key.get_secret_value(), settings.temp_data_ttl_seconds)
        app.state.queue = UpdateQueue(app.state.redis, settings.idempotency_ttl_seconds, cipher)
        app.state.ip_rl = app.state.redis.register_script(_IP_RL_LUA)
        yield
        if redis is None:
            await app.state.redis.aclose()
        if db is None:
            await app.state.db.engine.dispose()

    app = FastAPI(title="pauza-backend", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    secret = settings.telegram_webhook_secret.get_secret_value().encode()

    @app.post("/webhooks/telegram")
    async def telegram_webhook(request: Request) -> Response:
        started = time.monotonic()
        new_correlation_id()
        try:
            return await _webhook(request)
        finally:
            metrics.LATENCY.labels("webhook").observe(time.monotonic() - started)

    async def _webhook(request: Request) -> Response:
        header = request.headers.get("x-telegram-bot-api-secret-token", "").encode()
        if not hmac.compare_digest(header, secret):
            metrics.UPDATES.labels("unknown", "unauthorized").inc()
            log.warning("webhook rejected", extra={"component": "webhook", "error_code": "INVALID_UPDATE", "http_status": 401})
            return Response(status_code=401)

        # Лимит на сетевой адрес (защита от флуда при утечке секрета).
        ip = request.client.host if request.client else "unknown"
        try:
            bucket = int(time.time() // 60)
            n = await request.app.state.ip_rl(keys=[f"pauza:rl:ip:{pseudonymize(ip)}:{bucket}"], args=[])
        except Exception:
            log.error("redis unavailable", extra={"component": "webhook", "error_code": "INTERNAL_ERROR"})
            return Response(status_code=503)
        if int(n) > settings.webhook_ip_rate_limit_per_minute:
            metrics.RATE_LIMITED.labels("webhook_ip").inc()
            return Response(status_code=429)

        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > settings.max_webhook_body_bytes):
            return _invalid("too_large", 413)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > settings.max_webhook_body_bytes:
                return _invalid("too_large", 413)
        if "application/json" not in request.headers.get("content-type", ""):
            return _invalid("content_type", 415)
        try:
            update = json.loads(body)
        except ValueError:
            return _invalid("json", 400)
        if not isinstance(update, dict) or not isinstance(update.get("update_id"), int) or update["update_id"] < 0:
            return _invalid("schema", 400)

        kind = next((k for k in ALLOWED_UPDATE_KEYS if k in update), None)
        if kind is None or not isinstance(update[kind], dict):
            metrics.UPDATES.labels("other", "ignored").inc()
            return Response(status_code=200)  # неподдерживаемые типы не обрабатываем

        try:
            accepted = await request.app.state.queue.enqueue_once({"update_id": update["update_id"], kind: update[kind]})
        except Exception:
            # Очередь недоступна: 5xx, чтобы Telegram повторил доставку.
            metrics.UPDATES.labels(kind, "enqueue_failed").inc()
            log.error("enqueue failed", extra={"component": "webhook", "error_code": "INTERNAL_ERROR", "update_ref": pseudonymize(update["update_id"])})
            return Response(status_code=503)
        metrics.UPDATES.labels(kind, "accepted" if accepted else "duplicate").inc()
        if not accepted:
            metrics.DUPLICATE_UPDATES.inc()
        log.info("update accepted" if accepted else "duplicate update", extra={"component": "webhook", "update_ref": pseudonymize(update["update_id"]), "event": kind})
        return Response(status_code=200)

    def _invalid(reason: str, status: int) -> Response:
        metrics.UPDATES.labels("unknown", "invalid").inc()
        log.warning("invalid update", extra={"component": "webhook", "error_code": "INVALID_UPDATE", "event": reason, "http_status": status})
        return Response(status_code=status)

    @app.get("/health/live")
    async def live() -> Response:
        return Response(status_code=200)

    @app.get("/health/ready")
    async def ready(request: Request) -> Response:
        try:
            redis_ok = bool(await request.app.state.redis.ping())
        except Exception:
            redis_ok = False
        db_ok = await request.app.state.db.ping()
        return Response(status_code=200 if redis_ok and db_ok else 503)

    return app


def app_factory() -> FastAPI:  # uvicorn --factory pauza.api:app_factory
    from prometheus_client import start_http_server

    settings = get_settings()
    start_http_server(settings.metrics_port)
    return create_app(settings)
