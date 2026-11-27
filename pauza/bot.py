"""Обработка Update в воркере: команды, проверки, callback-кнопки.

Оригинальное содержимое (текст, URL, изображение, OCR-текст) существует только
в локальных переменных этой обработки. В БД пишутся только метаданные проверки.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError

from pauza import messages as M
from pauza import metrics
from pauza.analysis.service import AnalysisResult, Analyzer
from pauza.analysis.urls import extract_urls
from pauza.config import Settings
from pauza.db.models import Check, CheckStatus, Feedback, FeedbackType, InputType, RiskLevel, User
from pauza.db.session import Database
from pauza.integrations.ocr import ALLOWED_MIME, ImageRejected, OCRProvider, OCRUnavailable, validate_image
from pauza.integrations.telegram import TelegramClient, TelegramError, TelegramMessage
from pauza.logs import get_logger, pseudonymize
from pauza.regions import available_regions, region_name, resources_for
from pauza.userstate import (
    CallbackError,
    CallbackSigner,
    DialogState,
    RateLimiter,
    StateStore,
    decode_check_id,
    encode_check_id,
    user_hash,
)

log = get_logger(__name__)

COMMANDS = [
    ("start", "Начало и настройка"),
    ("check", "Проверить сообщение, ссылку или скриншот"),
    ("help_now", "Я уже ответил или заплатил"),
    ("settings", "Регион"),
    ("help", "Возможности и приватность"),
    ("delete_me", "Удалить мои данные"),
]
FEEDBACK_ACTIONS = {"fh": FeedbackType.HELPFUL, "fi": FeedbackType.INCORRECT, "fn": FeedbackType.NEED_HELP}


class ProcessingError(Exception):
    def __init__(self, code: str, reason: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason or code


@dataclass(slots=True)
class Ctx:
    update_id: int
    chat_id: int
    subject: str  # keyed hash Telegram user ID
    enqueued_at: float


class BotHandler:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        telegram: TelegramClient,
        analyzer: Analyzer,
        ocr: OCRProvider,
        rate_limiter: RateLimiter,
        states: StateStore,
        signer: CallbackSigner,
        redis,
    ) -> None:
        self.s = settings
        self.db = db
        self.tg = telegram
        self.analyzer = analyzer
        self.ocr = ocr
        self.rate = rate_limiter
        self.states = states
        self.signer = signer
        self.redis = redis

    # ------------------------------------------------------------------ entry
    async def handle(self, update: dict[str, Any], enqueued_at: float) -> str:
        """Возвращает статус для логов: Accepted | Ignored | Rejected."""
        update_id = int(update["update_id"])
        if "callback_query" in update:
            return await self._handle_callback(update_id, update["callback_query"], enqueued_at)
        msg = update.get("message")
        if not isinstance(msg, dict):
            return "Ignored"  # my_chat_member и прочие типы
        chat = msg.get("chat") or {}
        sender = msg.get("from") or {}
        if not chat.get("id") or not sender.get("id") or sender.get("is_bot"):
            return "Ignored"
        if chat.get("type") != "private":
            return await self._handle_group(chat["id"])
        ctx = Ctx(update_id, int(chat["id"]), user_hash(self.s.id_hash_key.get_secret_value(), int(sender["id"])), enqueued_at)
        text = msg.get("text")
        if isinstance(text, str) and text.startswith("/"):
            await self._handle_command(ctx, text)
            return "Accepted"
        await self._handle_content(ctx, msg)
        return "Accepted"

    async def _handle_group(self, chat_id: int) -> str:
        # Не обрабатываем содержимое групп; инструкция — не чаще раза в 10 минут на чат.
        key = f"pauza:grp:{pseudonymize(chat_id)}"
        if await self.redis.set(key, "1", nx=True, ex=600):
            await self._send(chat_id, TelegramMessage(M.e(M.ERRORS["GROUP_CHAT"])))
        return "Rejected"

    # --------------------------------------------------------------- commands
    async def _handle_command(self, ctx: Ctx, text: str) -> None:
        command = text.split()[0][1:].split("@")[0].lower()
        user = await self._get_or_create_user(ctx.subject)
        if command == "start":
            await self._set_consent(user.id)
            await self.states.set(ctx.subject, DialogState.READY)
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.START), keyboard=await self._start_keyboard(ctx.subject)))
        elif command == "help":
            await self._send(ctx.chat_id, TelegramMessage(M.HELP))
        elif command == "check":
            await self.states.set(ctx.subject, DialogState.AWAITING_INPUT)
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.CHECK_PROMPT)))
        elif command == "help_now":
            await self._send_help_now(ctx, user.region_code)
        elif command == "settings":
            await self._send_settings(ctx, user)
        elif command == "delete_me":
            kb = [[{"text": "Да, удалить", "callback_data": self.signer.sign("dk", "-", ctx.subject)}]]
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.DELETE_CONFIRM), keyboard=kb))
        else:
            await self._send(ctx.chat_id, TelegramMessage(M.HELP))

    async def _start_keyboard(self, subject: str) -> list[list[dict[str, str]]]:
        return [
            [{"text": "🆘 Я уже ответил или заплатил", "callback_data": self.signer.sign("hn", "-", subject)}],
            [{"text": "⚙️ Выбрать регион", "callback_data": self.signer.sign("st", "-", subject)}],
        ]

    async def _send_settings(self, ctx: Ctx, user: User) -> None:
        async with self.db.session() as s:
            regions = await available_regions(s)
        current = region_name(user.region_code) or "не выбран"
        lines = [
            "<b>Настройки</b>",
            "Язык: русский (другие языки пока недоступны).",
            f"Регион: {M.e(current)}.",
        ]
        if not regions:
            lines.append(M.e("Проверенные региональные контакты пока не добавлены. Я покажу универсальные рекомендации."))
        kb = [[{"text": region_name(code) or code, "callback_data": self.signer.sign("rg", code, ctx.subject)}] for code in regions[:20]]
        if user.region_code:
            kb.append([{"text": "Сбросить регион", "callback_data": self.signer.sign("rg", "-", ctx.subject)}])
        await self._send(ctx.chat_id, TelegramMessage("\n".join(lines), keyboard=kb or None))

    async def _send_help_now(self, ctx: Ctx, region_code: str | None) -> None:
        async with self.db.session() as s:
            resources = await resources_for(s, region_code)
        await self._send(ctx.chat_id, TelegramMessage(M.compose_help_now(region_name(region_code), resources)))

    # ---------------------------------------------------------------- content
    async def _handle_content(self, ctx: Ctx, msg: dict[str, Any]) -> None:
        input_type, raw_text, image_meta = self._classify(msg)
        user = await self._get_or_create_user(ctx.subject)
        state = await self.states.get(ctx.subject)
        if user.consent_version is None:
            # Пользователь не видел уведомление о данных: показываем его перед первой проверкой.
            await self._set_consent(user.id)
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.START)))
        if state == DialogState.AWAITING_INPUT:
            await self.states.set(ctx.subject, DialogState.READY)

        if input_type == InputType.UNSUPPORTED:
            metrics.CHECK_ERRORS.labels("UNSUPPORTED_INPUT").inc()
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.ERRORS["UNSUPPORTED_INPUT"])))
            return

        if not await self.rate.hit(ctx.subject):
            metrics.RATE_LIMITED.labels("user").inc()
            log.info("rate limited", extra={"component": "bot", "error_code": "RATE_LIMITED"})
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.ERRORS["RATE_LIMITED"])))
            return

        check = await self._claim_check(ctx.update_id, user.id, input_type)
        if check is None:
            metrics.DUPLICATE_UPDATES.inc()
            return  # уже обработано ранее (повторная доставка)

        if time.time() - ctx.enqueued_at > self.s.temp_data_ttl_seconds:
            await self._finish(check.id, CheckStatus.EXPIRED, error_code="EXPIRED")
            return

        started = time.monotonic()
        notes: list[str] = []
        try:
            if input_type == InputType.IMAGE:
                if msg.get("media_group_id"):
                    first = await self.redis.set(f"pauza:mg:{pseudonymize(msg['media_group_id'])}", "1", nx=True, ex=120)
                    if not first:
                        await self._finish(check.id, CheckStatus.FAILED, error_code="UNSUPPORTED_INPUT")
                        return
                    notes.append(M.ERRORS["MULTIPLE_IMAGES"])
                ocr_text, confident = await self._ocr(image_meta)
                if not confident:
                    notes.append(M.ERRORS["OCR_LOW_CONFIDENCE"])
                raw_text = "\n".join(t for t in (raw_text, ocr_text) if t)
                if not raw_text.strip():
                    raise ProcessingError("OCR_FAILED")
            elif len(raw_text) > self.s.max_text_length:
                raise ProcessingError("INPUT_TOO_LARGE", "INPUT_TOO_LARGE_TEXT")

            result = await asyncio.wait_for(self.analyzer.analyze_text(raw_text), timeout=self.s.analysis_timeout_seconds)
            raw_text = ""  # исходный текст больше не нужен
        except TimeoutError:
            await self._fail(ctx, check.id, "ANALYSIS_TIMEOUT", "ANALYSIS_TIMEOUT")
            return
        except ProcessingError as exc:
            await self._fail(ctx, check.id, exc.code, exc.reason)
            return
        except ImageRejected as exc:
            await self._fail(ctx, check.id, exc.code, exc.reason)
            return
        except Exception:
            log.exception("check failed", extra={"component": "bot", "error_code": "INTERNAL_ERROR", "check_id": str(check.id)})
            await self._fail(ctx, check.id, "INTERNAL_ERROR", "INTERNAL_ERROR")
            return
        finally:
            raw_text = ""
            image_meta = None

        duration_ms = int((time.monotonic() - started) * 1000)
        metrics.LATENCY.labels(f"analysis_{input_type.value.lower()}").observe(duration_ms / 1000)
        keyboard = self._result_keyboard(ctx.subject, check.id)
        sent = await self._send(ctx.chat_id, M.compose_result(result, keyboard, notes))
        await self._finish(
            check.id,
            CheckStatus.COMPLETED,
            result=result,
            duration_ms=duration_ms,
            error_code=None if sent else "TELEGRAM_SEND_FAILED",
        )
        metrics.CHECKS.labels(input_type.value, result.risk_level.value).inc()
        log.info(
            "check completed",
            extra={"component": "bot", "check_id": str(check.id), "input_type": input_type.value, "risk_level": result.risk_level.value, "indicator_codes": result.all_indicator_codes, "duration_ms": duration_ms},
        )

    def _classify(self, msg: dict[str, Any]) -> tuple[InputType, str, dict | None]:
        caption = msg.get("caption") or ""
        photos = msg.get("photo")
        if isinstance(photos, list) and photos:
            return InputType.IMAGE, caption, {"kind": "photo", "sizes": photos}
        doc = msg.get("document")
        if isinstance(doc, dict):
            if doc.get("mime_type") in ALLOWED_MIME:
                return InputType.IMAGE, caption, {"kind": "document", "file": doc}
            return InputType.UNSUPPORTED, "", None
        text = msg.get("text")
        if isinstance(text, str) and text.strip():
            return self._text_type(text), text, None
        if caption.strip() and not any(k in msg for k in ("sticker", "voice", "video", "video_note", "audio", "animation")):
            return self._text_type(caption), caption, None
        return InputType.UNSUPPORTED, "", None

    @staticmethod
    def _text_type(text: str) -> InputType:
        urls = extract_urls(text)
        if urls:
            rest = text
            for u in urls:
                rest = rest.replace(u, " ")
            if len(rest.strip()) < 5:
                return InputType.URL
        return InputType.TEXT

    async def _ocr(self, meta: dict | None) -> tuple[str, bool]:
        assert meta is not None
        if meta["kind"] == "photo":
            # Берём самый большой вариант, который укладывается в лимит по метаданным.
            sizes = sorted(meta["sizes"], key=lambda p: (p.get("width", 0) * p.get("height", 0)))
            fitting = [p for p in sizes if (p.get("file_size") or 0) <= self.s.max_image_bytes and p.get("width", 0) * p.get("height", 0) <= self.s.max_image_pixels]
            if not fitting:
                raise ImageRejected("INPUT_TOO_LARGE", "image_too_large")
            file_id = fitting[-1]["file_id"]
        else:
            file = meta["file"]
            if (file.get("file_size") or 0) > self.s.max_image_bytes:
                raise ImageRejected("INPUT_TOO_LARGE", "image_too_large")
            file_id = file["file_id"]

        started = time.monotonic()
        try:
            file_path, declared = await self.tg.get_file_path(file_id)
            if declared and declared > self.s.max_image_bytes:
                raise ImageRejected("INPUT_TOO_LARGE", "image_too_large")
            data = await self.tg.download_file(file_path, self.s.max_image_bytes)
        except TelegramError as exc:
            if exc.code == "INPUT_TOO_LARGE":
                raise ImageRejected("INPUT_TOO_LARGE", "image_too_large") from None
            raise ProcessingError("OCR_FAILED") from None
        try:
            image = await asyncio.to_thread(validate_image, data, self.s.max_image_bytes, self.s.max_image_pixels)
        finally:
            data = b""
        try:
            result = await asyncio.wait_for(self.ocr.extract_text(image), timeout=self.s.ocr_timeout_seconds)
        except (OCRUnavailable, TimeoutError):
            metrics.PROVIDER_ERRORS.labels("ocr").inc()
            raise ProcessingError("OCR_FAILED") from None
        finally:
            image.close()
            metrics.LATENCY.labels("ocr").observe(time.monotonic() - started)
        return result.text, result.confident

    async def _fail(self, ctx: Ctx, check_id: uuid.UUID, code: str, reason: str) -> None:
        metrics.CHECK_ERRORS.labels(code).inc()
        log.info("check not completed", extra={"component": "bot", "check_id": str(check_id), "error_code": code})
        template = M.ERRORS.get(reason) or M.ERRORS.get(code) or M.ERRORS["INTERNAL_ERROR"]
        text = template.format(limit=self.s.max_text_length) if "{limit}" in template else template
        await self._send(ctx.chat_id, TelegramMessage(M.e(text)))
        await self._finish(check_id, CheckStatus.FAILED, error_code=code)

    def _result_keyboard(self, subject: str, check_id: uuid.UUID) -> list[list[dict[str, str]]]:
        arg = encode_check_id(check_id)
        return [
            [{"text": "🆘 Я уже ответил или заплатил", "callback_data": self.signer.sign("hn", "-", subject)}],
            [
                {"text": "👍 Полезно", "callback_data": self.signer.sign("fh", arg, subject)},
                {"text": "🤔 Кажется, ошибка", "callback_data": self.signer.sign("fi", arg, subject)},
            ],
            [{"text": "🙋 Нужна помощь", "callback_data": self.signer.sign("fn", arg, subject)}],
        ]

    # -------------------------------------------------------------- callbacks
    async def _handle_callback(self, update_id: int, cq: dict[str, Any], enqueued_at: float) -> str:
        cq_id = cq.get("id")
        sender = cq.get("from") or {}
        message = cq.get("message") or {}
        chat = message.get("chat") or {}
        if not cq_id or not sender.get("id"):
            return "Ignored"
        # Кнопки работают только в личном чате самого пользователя.
        if chat.get("type") != "private" or chat.get("id") != sender.get("id"):
            await self.tg.answer_callback(cq_id, M.CALLBACK_EXPIRED)
            return "Rejected"
        subject = user_hash(self.s.id_hash_key.get_secret_value(), int(sender["id"]))
        try:
            action, arg = self.signer.verify(cq.get("data") or "", subject)
        except CallbackError:
            await self.tg.answer_callback(cq_id, M.CALLBACK_EXPIRED)
            return "Rejected"
        ctx = Ctx(update_id, int(chat["id"]), subject, enqueued_at)

        if action in FEEDBACK_ACTIONS:
            await self._record_feedback(subject, arg, FEEDBACK_ACTIONS[action])
            await self.tg.answer_callback(cq_id, M.FEEDBACK_THANKS)
            if action == "fn":
                user = await self._get_or_create_user(subject)
                await self._send_help_now(ctx, user.region_code)
        elif action == "hn":
            await self.tg.answer_callback(cq_id)
            user = await self._get_or_create_user(subject)
            await self._send_help_now(ctx, user.region_code)
        elif action == "st":
            await self.tg.answer_callback(cq_id)
            await self._send_settings(ctx, await self._get_or_create_user(subject))
        elif action == "rg":
            await self._set_region(ctx, cq_id, arg)
        elif action == "dk":
            await self.tg.answer_callback(cq_id)
            deleted = await self.delete_user(subject)
            await self._send(ctx.chat_id, TelegramMessage(M.e(M.DELETE_DONE if deleted else M.DELETE_NOTHING)))
        else:
            await self.tg.answer_callback(cq_id)
        return "Accepted"

    async def _set_region(self, ctx: Ctx, cq_id: str, code: str) -> None:
        async with self.db.session() as s:
            allowed = await available_regions(s)
            new_code = None if code == "-" else code
            if new_code is not None and new_code not in allowed:
                await self.tg.answer_callback(cq_id, M.CALLBACK_EXPIRED)
                return
            await s.execute(sa.update(User).where(User.telegram_user_hash == ctx.subject).values(region_code=new_code, updated_at=datetime.now(UTC)))
        await self.tg.answer_callback(cq_id, "Регион сохранён" if new_code else "Регион сброшен")
        name = region_name(new_code) or "не выбран"
        await self._send(ctx.chat_id, TelegramMessage(f"Регион: {M.e(name)}."))

    async def _record_feedback(self, subject: str, arg: str, ftype: FeedbackType) -> None:
        try:
            check_id = decode_check_id(arg)
        except (ValueError, TypeError):
            return
        async with self.db.session() as s:
            row = (
                await s.execute(
                    sa.select(Check.id, Check.risk_level, Check.analysis_version)
                    .join(User, User.id == Check.user_id)
                    .where(Check.id == check_id, User.telegram_user_hash == subject)
                )
            ).first()
            if row is None:
                return
            exists = await s.scalar(sa.select(sa.func.count()).select_from(Feedback).where(Feedback.check_id == check_id, Feedback.feedback_type == ftype))
            if exists:
                return
            s.add(Feedback(check_id=check_id, feedback_type=ftype, risk_level=row.risk_level, analysis_version=row.analysis_version))
        metrics.FEEDBACK.labels(ftype.value).inc()

    # ------------------------------------------------------------------- data
    async def _get_or_create_user(self, subject: str) -> User:
        async with self.db.session() as s:
            user = await s.scalar(sa.select(User).where(User.telegram_user_hash == subject))
            now = datetime.now(UTC)
            if user is None:
                user = User(telegram_user_hash=subject, locale=self.s.default_locale, region_code=self.s.default_region_code)
                s.add(user)
                try:
                    await s.flush()
                except IntegrityError:
                    await s.rollback()
                    user = await s.scalar(sa.select(User).where(User.telegram_user_hash == subject))
                    assert user is not None
            else:
                user.last_active_at = now
            return user

    async def _set_consent(self, user_id: uuid.UUID) -> None:
        async with self.db.session() as s:
            await s.execute(sa.update(User).where(User.id == user_id).values(consent_version=self.s.consent_version, updated_at=datetime.now(UTC)))

    async def _claim_check(self, update_id: int, user_id: uuid.UUID, input_type: InputType) -> Check | None:
        """Идемпотентное создание записи проверки по update_id."""
        now = datetime.now(UTC)
        async with self.db.session() as s:
            existing = await s.scalar(sa.select(Check).where(Check.telegram_update_id == update_id))
            if existing is not None:
                if existing.status in (CheckStatus.COMPLETED, CheckStatus.FAILED, CheckStatus.EXPIRED):
                    return None
                existing.status = CheckStatus.PROCESSING
                return existing
            check = Check(
                user_id=user_id,
                telegram_update_id=update_id,
                input_type=input_type,
                status=CheckStatus.RECEIVED,
                created_at=now,
                expires_at=now + timedelta(days=self.s.check_retention_days),
                analysis_version=self.analyzer.version,
            )
            s.add(check)
            try:
                await s.flush()
            except IntegrityError:
                await s.rollback()
                return None
            check.status = CheckStatus.PROCESSING
            return check

    async def _finish(
        self,
        check_id: uuid.UUID,
        status: CheckStatus,
        result: AnalysisResult | None = None,
        duration_ms: int | None = None,
        error_code: str | None = None,
    ) -> None:
        values: dict[str, Any] = {"status": status, "completed_at": datetime.now(UTC), "error_code": error_code}
        if result is not None:
            values.update(
                risk_level=result.risk_level,
                indicator_codes=result.all_indicator_codes,  # только короткие коды
                analysis_version=result.analysis_version,
            )
        if duration_ms is not None:
            values["duration_ms"] = duration_ms
        async with self.db.session() as s:
            await s.execute(sa.update(Check).where(Check.id == check_id).values(**values))

    async def delete_user(self, subject: str) -> bool:
        """/delete_me: удалить настройки, связь с Telegram ID, состояния и события пользователя."""
        async with self.db.session() as s:
            user = await s.scalar(sa.select(User).where(User.telegram_user_hash == subject))
            if user is not None:
                check_ids = sa.select(Check.id).where(Check.user_id == user.id)
                await s.execute(sa.delete(Feedback).where(Feedback.check_id.in_(check_ids)))
                await s.execute(sa.delete(Check).where(Check.user_id == user.id))
                await s.execute(sa.delete(User).where(User.id == user.id))
        await self.states.clear(subject)
        await self.rate.forget(subject)
        return user is not None

    # --------------------------------------------------------------- transport
    async def _send(self, chat_id: int, message: TelegramMessage) -> bool:
        started = time.monotonic()
        try:
            await self.tg.send_message(chat_id, message)
            return True
        except TelegramError:
            metrics.TELEGRAM_SEND_FAILED.inc()
            log.warning("message not delivered", extra={"component": "bot", "error_code": "TELEGRAM_SEND_FAILED"})
            return False
        finally:
            metrics.LATENCY.labels("send").observe(time.monotonic() - started)


__all__ = ["BotHandler", "COMMANDS", "RiskLevel"]
