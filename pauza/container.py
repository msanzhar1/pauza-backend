"""Сборка зависимостей из настроек."""

from __future__ import annotations

from dataclasses import dataclass

from redis.asyncio import Redis

from pauza.analysis.rules import RuleEngine
from pauza.analysis.service import Analyzer
from pauza.analysis.urls import OfficialDomains, UrlAnalyzer
from pauza.bot import BotHandler
from pauza.config import ConfigError, Settings
from pauza.db.session import Database, engine_from_settings
from pauza.integrations.llm import LLMExplainer
from pauza.integrations.ocr import build_ocr
from pauza.integrations.reputation import UrlReputationProvider
from pauza.integrations.telegram import TelegramClient
from pauza.queue import UpdateCipher, UpdateQueue
from pauza.userstate import CallbackSigner, RateLimit, RateLimiter, StateStore


@dataclass
class Container:
    settings: Settings
    redis: Redis
    db: Database
    telegram: TelegramClient
    handler: BotHandler
    queue: UpdateQueue
    cipher: UpdateCipher

    async def aclose(self) -> None:
        await self.telegram.aclose()
        await self.redis.aclose()
        await self.db.engine.dispose()


def build_reputation(settings: Settings) -> UrlReputationProvider | None:
    if not settings.url_reputation_enabled:
        return None
    # Конкретный провайдер выбирается решением раздела 21 п.5; до этого — только явная ошибка.
    raise ConfigError(f"URL reputation provider '{settings.url_reputation_provider}' не реализован")


def build_llm(settings: Settings) -> LLMExplainer | None:
    if not settings.llm_enabled:
        return None
    raise ConfigError(f"LLM provider '{settings.llm_provider}' не реализован; оставьте LLM_ENABLED=false")


def build_analyzer(settings: Settings) -> Analyzer:
    return Analyzer(
        UrlAnalyzer(OfficialDomains.load(settings.official_domains_file), settings.max_urls_per_check),
        RuleEngine(),
        settings.max_text_length,
        reputation=build_reputation(settings),
        llm=build_llm(settings),
        components=settings.analysis_components,
    )


def build_cipher(settings: Settings) -> UpdateCipher:
    return UpdateCipher(settings.queue_encryption_key.get_secret_value(), settings.temp_data_ttl_seconds)


def build_rate_limiter(settings: Settings, redis: Redis) -> RateLimiter:
    return RateLimiter(
        redis,
        [
            RateLimit("short", settings.rate_limit_window_seconds, settings.rate_limit_max_checks),
            RateLimit("day", 86400, settings.rate_limit_daily_max_checks),
        ],
    )


def build_container(settings: Settings, redis: Redis | None = None, db: Database | None = None, telegram: TelegramClient | None = None) -> Container:
    redis = redis or Redis.from_url(settings.redis_url)
    db = db or Database(engine_from_settings(settings))
    telegram = telegram or TelegramClient(
        settings.telegram_bot_token.get_secret_value(),
        settings.telegram_api_base,
        timeout=settings.telegram_timeout_seconds,
        max_attempts=settings.telegram_max_attempts,
        max_message_age=settings.telegram_max_message_age_seconds,
    )
    handler = BotHandler(
        settings=settings,
        db=db,
        telegram=telegram,
        analyzer=build_analyzer(settings),
        ocr=build_ocr(settings.ocr_provider, settings.ocr_languages, settings.temp_dir),
        rate_limiter=build_rate_limiter(settings, redis),
        states=StateStore(redis, settings.dialog_state_ttl_seconds),
        signer=CallbackSigner(settings.callback_signing_key.get_secret_value(), settings.callback_ttl_seconds),
        redis=redis,
    )
    cipher = build_cipher(settings)
    return Container(settings, redis, db, telegram, handler, UpdateQueue(redis, settings.idempotency_ttl_seconds, cipher), cipher)
