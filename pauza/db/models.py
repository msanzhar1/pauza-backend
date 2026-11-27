"""Модель данных (раздел 11 ТЗ).

В таблицах нет полей для исходного текста, URL, OCR-текста, file_id или имени
файла. Telegram ID хранится только как keyed hash (HMAC-SHA256): для отправки
ответа используется chat_id из самого Update, поэтому сырой ID не нужен.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JsonType = sa.JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class InputType(str, enum.Enum):
    TEXT = "TEXT"
    URL = "URL"
    IMAGE = "IMAGE"
    UNSUPPORTED = "UNSUPPORTED"


class CheckStatus(str, enum.Enum):
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class RiskLevel(str, enum.Enum):
    HIGH = "HIGH"
    ELEVATED = "ELEVATED"
    NO_CLEAR_SIGNAL = "NO_CLEAR_SIGNAL"


class FeedbackType(str, enum.Enum):
    HELPFUL = "HELPFUL"
    INCORRECT = "INCORRECT"
    NEED_HELP = "NEED_HELP"


class ResourceType(str, enum.Enum):
    BANK_GUIDANCE = "BANK_GUIDANCE"
    POLICE_REPORT = "POLICE_REPORT"
    CONSUMER_PROTECTION = "CONSUMER_PROTECTION"
    CYBER_REPORT = "CYBER_REPORT"
    EMERGENCY = "EMERGENCY"


def _enum(e: type[enum.Enum], name: str) -> sa.Enum:
    return sa.Enum(e, name=name, values_callable=lambda x: [m.value for m in x])


def _now() -> datetime:
    from datetime import UTC

    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    # HMAC-SHA256(ID_HASH_KEY, telegram_user_id), hex. Сырой ID не хранится.
    telegram_user_hash: Mapped[str] = mapped_column(sa.String(64), unique=True, nullable=False)
    locale: Mapped[str] = mapped_column(sa.String(8), nullable=False, default="ru")
    region_code: Mapped[str | None] = mapped_column(sa.String(8))
    consent_version: Mapped[str | None] = mapped_column(sa.String(32))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)
    last_active_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, sa.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    telegram_update_id: Mapped[int] = mapped_column(sa.BigInteger, unique=True, nullable=False)
    input_type: Mapped[InputType] = mapped_column(_enum(InputType, "input_type"), nullable=False)
    status: Mapped[CheckStatus] = mapped_column(_enum(CheckStatus, "check_status"), nullable=False)
    risk_level: Mapped[RiskLevel | None] = mapped_column(_enum(RiskLevel, "risk_level"))
    indicator_codes: Mapped[list[str] | None] = mapped_column(JsonType)
    error_code: Mapped[str | None] = mapped_column(sa.String(32))
    analysis_version: Mapped[str | None] = mapped_column(sa.String(128))
    duration_ms: Mapped[int | None] = mapped_column(sa.Integer)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, index=True)


class Feedback(Base):
    __tablename__ = "feedback"
    __table_args__ = (sa.UniqueConstraint("check_id", "feedback_type", name="uq_feedback_check_type"),)

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    check_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid, sa.ForeignKey("checks.id", ondelete="SET NULL"), index=True)
    feedback_type: Mapped[FeedbackType] = mapped_column(_enum(FeedbackType, "feedback_type"), nullable=False)
    risk_level: Mapped[RiskLevel | None] = mapped_column(_enum(RiskLevel, "risk_level"))
    analysis_version: Mapped[str | None] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)


class RegionResource(Base):
    __tablename__ = "region_resources"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    region_code: Mapped[str] = mapped_column(sa.String(8), nullable=False, index=True)
    resource_type: Mapped[ResourceType] = mapped_column(_enum(ResourceType, "resource_type"), nullable=False)
    display_name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    official_url: Mapped[str | None] = mapped_column(sa.Text)
    official_phone: Mapped[str | None] = mapped_column(sa.String(40))
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    source_url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    verified_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)


class RuleVersion(Base):
    """Журнал версий набора правил. Образцы сообщений сюда не пишутся."""

    __tablename__ = "rule_versions"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    version: Mapped[str] = mapped_column(sa.String(32), unique=True, nullable=False)
    published_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)
    description: Mapped[str] = mapped_column(sa.Text, nullable=False)
    author: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    rules_digest: Mapped[str] = mapped_column(sa.String(64), nullable=False)


class AuditEvent(Base):
    """Аудит изменений правил и справочника регионов."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(sa.Uuid, primary_key=True, default=uuid.uuid4)
    action: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    entity: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    entity_ref: Mapped[str | None] = mapped_column(sa.String(64))
    author: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    details: Mapped[dict | None] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False, default=_now)
