import asyncio
import json
import logging
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa

from pauza.db.models import Check, CheckStatus, Feedback, RegionResource, ResourceType, RiskLevel, User
from pauza.logs import JsonFormatter
from pauza.userstate import DialogState, user_hash
from pauza.worker import Worker

from .conftest import USER_ID, FakeOCR, callback_update, photo_update, png_bytes, text_update

SCAM = "Здравствуйте, служба безопасности банка. Продиктуйте код из СМС, иначе счёт заблокируют https://telegrarn.org/x?id=SECRETQUERY"


async def run(container, update) -> None:
    """Пройти полный путь: очередь → воркер → обработчик."""
    assert await container.queue.enqueue_once(update)
    worker = Worker(container, "test-worker")
    job = await worker.queue.reserve(timeout=0.1)
    assert job is not None
    await worker.process(job)


async def checks(container) -> list[Check]:
    async with container.db.session() as s:
        return list((await s.execute(sa.select(Check))).scalars())


def subject(container):
    return user_hash(container.settings.id_hash_key.get_secret_value(), USER_ID)


# --- Команды -------------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["/start", "/help", "/check", "/help_now", "/settings", "/delete_me", "/unknown", "/start@pauza_bot"])
async def test_commands_reply(container, telegram, cmd):
    await run(container, text_update(cmd))
    assert telegram.sent, cmd
    assert await checks(container) == []  # команды не создают проверок


async def test_check_command_sets_awaiting_state(container):
    await run(container, text_update("/check"))
    assert await container.handler.states.get(subject(container)) == DialogState.AWAITING_INPUT
    await run(container, text_update("Привет"))
    assert await container.handler.states.get(subject(container)) == DialogState.READY
    assert await container.redis.ttl(f"pauza:state:{subject(container)}") <= 1800


async def test_start_stores_consent_and_no_raw_id(container):
    await run(container, text_update("/start"))
    async with container.db.session() as s:
        user = await s.scalar(sa.select(User))
    assert user.consent_version == container.settings.consent_version
    assert str(USER_ID) not in user.telegram_user_hash


# --- Проверка текста и URL --------------------------------------------------------

async def test_scam_text_high_and_nothing_stored(container, telegram):
    await run(container, text_update("/start"))
    telegram.sent.clear()
    await run(container, text_update(SCAM))
    text = telegram.texts[-1]
    assert "Высокий риск" in text and "Просят одноразовый код" in text
    assert "telegrarn[.]org" in text and "SECRETQUERY" not in text
    kb = telegram.sent[-1][1].keyboard
    assert any("Я уже ответил" in b["text"] for row in kb for b in row)
    [check] = await checks(container)
    assert check.status == CheckStatus.COMPLETED and check.risk_level == RiskLevel.HIGH
    assert "OTP_REQUEST" in check.indicator_codes
    # В таблице checks нет исходного содержимого
    dump = json.dumps({c.name: str(getattr(check, c.key)) for c in Check.__table__.columns}, ensure_ascii=False)
    assert "Продиктуйте" not in dump and "telegrarn" not in dump


async def test_first_content_shows_privacy_notice(container, telegram):
    await run(container, text_update("Привет, как дела?"))
    assert "не сохраняю" in telegram.texts[0]
    assert "Явных признаков не найдено" in telegram.texts[1]
    assert "не значит, что сообщение безопасно" in telegram.texts[1]


async def test_url_only_input_type(container):
    await run(container, text_update("https://bit.ly/abc"))
    [check] = await checks(container)
    assert check.input_type.value == "URL"


async def test_text_too_long(container, telegram):
    container.settings.max_text_length = 50
    await run(container, text_update("а" * 51))
    assert "слишком длинное" in telegram.texts[-1]
    [check] = await checks(container)
    assert check.status == CheckStatus.FAILED and check.error_code == "INPUT_TOO_LARGE"


async def test_redelivered_update_processed_once(container, telegram):
    upd = text_update(SCAM, update_id=424242)
    await run(container, upd)
    n = len(telegram.sent)
    # Idempotency key в Redis истёк, а Telegram прислал Update снова
    await container.redis.flushall()
    await run(container, upd)
    assert len(telegram.sent) == n
    assert len(await checks(container)) == 1


async def test_rate_limit_blocks_checks_not_commands(container, telegram):
    container.settings.rate_limit_max_checks = 2
    container.handler.rate.limits[0].max_hits = 2
    for _ in range(3):
        await run(container, text_update("обычный текст"))
    assert "Слишком много проверок" in telegram.texts[-1]
    await run(container, text_update("/help"))
    assert "Что я умею" in telegram.texts[-1]


async def test_unsupported_input(container, telegram):
    upd = text_update("x")
    del upd["message"]["text"]
    upd["message"]["voice"] = {"file_id": "v"}
    await run(container, upd)
    assert "только текст, ссылки и скриншоты" in telegram.texts[-1]


async def test_group_chat_not_processed(container, telegram):
    await run(container, text_update(SCAM, chat_type="group"))
    await run(container, text_update(SCAM, chat_type="group"))
    assert len(telegram.sent) == 1 and "личных сообщениях" in telegram.texts[0]
    assert await checks(container) == []


async def test_analysis_timeout_never_returns_no_clear_signal(container, telegram):
    async def slow(text):
        await asyncio.sleep(1)

    container.handler.analyzer.analyze_text = slow
    container.settings.analysis_timeout_seconds = 0.01
    await run(container, text_update("текст"))
    assert "не завершилась" in telegram.texts[-1]
    assert all("Явных признаков" not in t for t in telegram.texts)
    [check] = await checks(container)
    assert check.error_code == "ANALYSIS_TIMEOUT" and check.risk_level is None


async def test_internal_error_safe_message(container, telegram):
    async def boom(text):
        raise RuntimeError("Продиктуйте код")  # текст исключения не должен утечь

    container.handler.analyzer.analyze_text = boom
    await run(container, text_update("текст"))
    assert "Что-то пошло не так" in telegram.texts[-1]


async def test_send_failure_recorded(container, telegram):
    telegram.fail_send = True
    await run(container, text_update(SCAM))
    [check] = await checks(container)
    assert check.status == CheckStatus.COMPLETED and check.error_code == "TELEGRAM_SEND_FAILED"


# --- Изображения ------------------------------------------------------------------

async def test_image_ocr_flow(container, telegram):
    telegram.files["F1"] = png_bytes()
    container.handler.ocr = FakeOCR("Сообщите код из смс оператору")
    await run(container, photo_update("F1"))
    assert "Высокий риск" in telegram.texts[-1]
    [check] = await checks(container)
    assert check.input_type.value == "IMAGE"


async def test_image_low_confidence_note(container, telegram):
    telegram.files["F1"] = png_bytes()
    container.handler.ocr = FakeOCR("какой-то текст", confident=False)
    await run(container, photo_update("F1"))
    assert "распознан неуверенно" in telegram.texts[-1]


async def test_ocr_failure_asks_for_text(container, telegram):
    telegram.files["F1"] = png_bytes()
    container.handler.ocr = FakeOCR(fail=True)
    await run(container, photo_update("F1"))
    assert "вставьте текст вручную" in telegram.texts[-1]
    assert all("Явных признаков" not in t for t in telegram.texts)


async def test_unsupported_image_rejected(container, telegram):
    telegram.files["F1"] = b"GIF89a" + b"\x00" * 50
    await run(container, photo_update("F1"))
    assert "формат не поддерживается" in telegram.texts[-1]
    assert container.handler.ocr.calls == 0


async def test_too_large_image_rejected_by_metadata(container, telegram):
    upd = photo_update("F1")
    for p in upd["message"]["photo"]:
        p["file_size"] = container.settings.max_image_bytes + 1
    await run(container, upd)
    assert "слишком большое" in telegram.texts[-1]


async def test_document_heic_unsupported(container, telegram):
    upd = text_update("x")
    del upd["message"]["text"]
    upd["message"]["document"] = {"file_id": "D", "mime_type": "image/heic", "file_size": 100}
    await run(container, upd)
    assert "только текст, ссылки и скриншоты" in telegram.texts[-1]


async def test_media_group_only_first_image(container, telegram):
    telegram.files["A"] = png_bytes()
    telegram.files["B"] = png_bytes()
    container.handler.ocr = FakeOCR("обычный текст на картинке")
    await run(container, photo_update("A", media_group_id="g1"))
    await run(container, photo_update("B", media_group_id="g1"))
    assert container.handler.ocr.calls == 1
    assert "по одному изображению" in telegram.texts[-1]


# --- Кнопки -----------------------------------------------------------------------

async def _scam_check(container, telegram):
    await run(container, text_update(SCAM))
    return telegram.sent[-1][1].keyboard


def _button(kb, label):
    return next(b["callback_data"] for row in kb for b in row if label in b["text"])


async def test_feedback_recorded_once(container, telegram):
    kb = await _scam_check(container, telegram)
    data = _button(kb, "Полезно")
    await run(container, callback_update(data))
    await run(container, callback_update(data))
    async with container.db.session() as s:
        rows = list((await s.execute(sa.select(Feedback))).scalars())
    assert len(rows) == 1 and rows[0].feedback_type.value == "HELPFUL" and rows[0].risk_level == RiskLevel.HIGH
    assert ("cq1", "Спасибо за отзыв!") in telegram.callbacks


async def test_need_help_button_sends_help_now(container, telegram):
    kb = await _scam_check(container, telegram)
    await run(container, callback_update(_button(kb, "Нужна помощь")))
    assert "Что сделать прямо сейчас" in telegram.texts[-1]


async def test_callback_from_other_user_rejected(container, telegram):
    kb = await _scam_check(container, telegram)
    await run(container, callback_update(_button(kb, "Полезно"), user_id=999))
    assert telegram.callbacks[-1][1] == "Кнопка устарела. Пришлите материал ещё раз."
    async with container.db.session() as s:
        assert (await s.scalar(sa.select(sa.func.count()).select_from(Feedback))) == 0


async def test_callback_in_foreign_chat_rejected(container, telegram):
    kb = await _scam_check(container, telegram)
    n = len(telegram.sent)
    await run(container, callback_update(_button(kb, "Я уже ответил"), chat_id=-100))
    assert len(telegram.sent) == n


# --- Регионы и help_now ----------------------------------------------------------

async def _add_region(container):
    async with container.db.session() as s:
        s.add(RegionResource(region_code="KZ", resource_type=ResourceType.POLICE_REPORT, display_name="Тестовая служба",
                             official_phone="102", description="Тестовое описание", source_url="https://source.example",
                             verified_at=datetime.now(UTC), active=True))


async def test_help_now_universal_without_region(container, telegram):
    await run(container, text_update("/help_now"))
    assert "нет проверенного списка" in telegram.texts[-1]
    assert "Не присылайте их сюда" in telegram.texts[-1]


async def test_region_selection_and_contacts(container, telegram):
    await _add_region(container)
    await run(container, text_update("/settings"))
    kb = telegram.sent[-1][1].keyboard
    await run(container, callback_update(_button(kb, "Казахстан")))
    assert "Регион: Казахстан" in telegram.texts[-1]
    await run(container, text_update("/help_now"))
    assert "Тестовая служба" in telegram.texts[-1] and "102" in telegram.texts[-1]


async def test_region_not_in_directory_rejected(container, telegram):
    data = container.handler.signer.sign("rg", "XX", subject(container))
    await run(container, text_update("/start"))
    await run(container, callback_update(data))
    async with container.db.session() as s:
        assert (await s.scalar(sa.select(User.region_code))) is None


# --- /delete_me ------------------------------------------------------------------

async def test_delete_me_removes_user_data(container, telegram):
    kb = await _scam_check(container, telegram)
    await run(container, callback_update(_button(kb, "Полезно")))
    await run(container, text_update("/check"))
    await run(container, text_update("/delete_me"))
    confirm = telegram.sent[-1][1].keyboard[0][0]["callback_data"]
    await run(container, callback_update(confirm))
    assert "удалены" in telegram.texts[-1]
    async with container.db.session() as s:
        for model in (User, Check, Feedback):
            assert (await s.scalar(sa.select(sa.func.count()).select_from(model))) == 0
    keys = [k.decode() async for k in container.redis.scan_iter(match="*")]
    assert not [k for k in keys if subject(container) in k]


# --- Логи без содержимого --------------------------------------------------------

async def test_logs_contain_no_user_content(container, telegram, caplog):
    caplog.set_level(logging.DEBUG)
    telegram.files["F1"] = png_bytes()
    container.handler.ocr = FakeOCR("OCRSECRETTEXT продиктуйте код")
    await run(container, text_update(SCAM))
    await run(container, photo_update("F1", caption="CAPTIONSECRET"))

    async def boom(text):
        raise RuntimeError("EXCEPTIONSECRET " + text)

    container.handler.analyzer.analyze_text = boom
    await run(container, text_update("BOOMSECRET"))
    fmt = JsonFormatter()
    output = "\n".join(fmt.format(r) for r in caplog.records)
    assert output, "логи должны писаться"
    for secret in ("Продиктуйте", "telegrarn", "SECRETQUERY", "OCRSECRETTEXT", "CAPTIONSECRET", "EXCEPTIONSECRET", "BOOMSECRET", str(USER_ID), "secret_username", "123:TEST", "photos/F1"):
        assert secret not in output, secret


async def test_metrics_contain_no_user_content(container, telegram):
    from prometheus_client import REGISTRY, generate_latest

    await run(container, text_update(SCAM))
    out = generate_latest(REGISTRY).decode()
    assert "pauza_checks_total" in out
    for secret in ("telegrarn", str(USER_ID), "Продиктуйте"):
        assert secret not in out
