"""Конфигурация приложения из переменных окружения.

Запуск завершается ошибкой, если обязательные параметры не заданы или в
production оставлены небезопасные значения по умолчанию (раздел 16 ТЗ).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

UNSAFE_SECRET_MARKERS = ("change-me", "changeme", "example", "dev-")
MIN_SECRET_LENGTH = 32


class ConfigError(RuntimeError):
    """Неверная или небезопасная конфигурация."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: Literal["development", "test", "production"] = "development"
    app_log_level: str = "INFO"
    public_base_url: str = "http://localhost:8000"

    telegram_bot_token: SecretStr
    telegram_webhook_secret: SecretStr
    telegram_api_base: str = "https://api.telegram.org"
    # Ключ для keyed hash Telegram ID (в БД сырой ID не хранится) и подписи callback.
    id_hash_key: SecretStr
    callback_signing_key: SecretStr
    # Fernet-ключ для шифрования Update в очереди (временное хранилище, TTL = TEMP_DATA_TTL_SECONDS).
    queue_encryption_key: SecretStr

    database_url: str
    redis_url: str

    # Лимиты входа (раздел 7.1)
    max_text_length: int = 10_000
    max_image_bytes: int = 10 * 1024 * 1024
    max_image_pixels: int = 20_000_000
    max_urls_per_check: int = 10
    max_webhook_body_bytes: int = 1024 * 1024

    # Rate limit: короткое окно и сутки на пользователя, отдельно на сетевой адрес webhook
    rate_limit_window_seconds: int = 600
    rate_limit_max_checks: int = 10
    rate_limit_daily_max_checks: int = 50
    webhook_ip_rate_limit_per_minute: int = 3000

    # TTL (раздел 11.6)
    temp_data_ttl_seconds: int = Field(default=900, le=900)
    idempotency_ttl_seconds: int = 48 * 3600
    dialog_state_ttl_seconds: int = Field(default=1800, le=1800)
    callback_ttl_seconds: int = 24 * 3600
    check_retention_days: int = 365
    user_inactivity_days: int | None = None  # решение раздела 21 п.4 ещё не принято
    temp_dir: str = "/tmp/pauza"

    # Таймауты и повторы
    analysis_timeout_seconds: float = 10.0
    ocr_timeout_seconds: float = 15.0
    telegram_timeout_seconds: float = 10.0
    telegram_max_attempts: int = 5
    telegram_max_message_age_seconds: int = 300
    job_max_attempts: int = 3

    # Провайдеры
    ocr_provider: Literal["tesseract", "disabled"] = "tesseract"
    ocr_api_key: SecretStr | None = None
    ocr_languages: str = "rus+eng"
    llm_enabled: bool = False
    llm_provider: str | None = None
    llm_api_key: SecretStr | None = None
    llm_timeout_seconds: float = 5.0
    url_reputation_enabled: bool = False
    url_reputation_provider: str | None = None
    url_reputation_api_key: SecretStr | None = None

    default_locale: str = "ru"
    default_region_code: str | None = None
    consent_version: str = "2026-11-draft"
    official_domains_file: str = "config/official_domains.json"

    metrics_port: int = 9100

    @model_validator(mode="after")
    def _check_safety(self) -> Settings:
        if self.llm_enabled and not self.llm_provider:
            raise ConfigError("LLM_ENABLED=true требует LLM_PROVIDER")
        if self.url_reputation_enabled and not self.url_reputation_provider:
            raise ConfigError("URL_REPUTATION_ENABLED=true требует URL_REPUTATION_PROVIDER")
        try:
            from cryptography.fernet import Fernet

            Fernet(self.queue_encryption_key.get_secret_value())
        except Exception:
            raise ConfigError("QUEUE_ENCRYPTION_KEY: нужен ключ Fernet (см. README)") from None
        if self.app_env == "production":
            secrets = {
                "TELEGRAM_WEBHOOK_SECRET": self.telegram_webhook_secret,
                "ID_HASH_KEY": self.id_hash_key,
                "CALLBACK_SIGNING_KEY": self.callback_signing_key,
            }
            for name, value in secrets.items():
                raw = value.get_secret_value()
                if len(raw) < MIN_SECRET_LENGTH or any(m in raw.lower() for m in UNSAFE_SECRET_MARKERS):
                    raise ConfigError(f"{name}: небезопасное значение для production")
            if not self.public_base_url.startswith("https://"):
                raise ConfigError("PUBLIC_BASE_URL в production должен быть https://")
        return self

    @property
    def analysis_components(self) -> str:
        parts = [f"ocr={self.ocr_provider}"]
        parts.append(f"llm={self.llm_provider if self.llm_enabled else 'off'}")
        parts.append(f"rep={self.url_reputation_provider if self.url_reputation_enabled else 'off'}")
        return ",".join(parts)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        return Settings()  # type: ignore[call-arg]
    except ConfigError:
        raise
    except Exception as exc:  # pydantic ValidationError: не печатаем значения
        raise ConfigError(f"Ошибка конфигурации: {exc.__class__.__name__}: {_safe_errors(exc)}") from None


def _safe_errors(exc: Exception) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        return "; ".join(f"{'.'.join(map(str, e['loc'])) or '?'}: {e['type']}" for e in errors())
    return "invalid"
