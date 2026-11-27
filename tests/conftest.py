from __future__ import annotations

import io
import os
from typing import Any

import fakeredis
import pytest
from cryptography.fernet import Fernet
from PIL import Image

from pauza.config import Settings
from pauza.container import build_container
from pauza.db.models import Base
from pauza.db.session import Database, make_engine
from pauza.integrations.ocr import OCRResult
from pauza.integrations.telegram import TelegramMessage

QUEUE_KEY = Fernet.generate_key().decode()


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = dict(
        app_env="test",
        telegram_bot_token="123:TEST",
        telegram_webhook_secret="test-webhook-secret",
        id_hash_key="test-id-hash-key",
        callback_signing_key="test-callback-key",
        queue_encryption_key=QUEUE_KEY,
        database_url="sqlite+aiosqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        temp_dir="/tmp/pauza-test",
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
async def redis():
    r = fakeredis.FakeAsyncRedis()
    yield r
    await r.flushall()
    await r.aclose()


@pytest.fixture
async def db():
    url = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    engine = make_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    database = Database(engine)
    yield database
    await engine.dispose()


class FakeTelegram:
    """Mock Telegram API: запоминает отправленное, отдаёт «файлы» из словаря."""

    def __init__(self) -> None:
        self.sent: list[tuple[int, TelegramMessage]] = []
        self.callbacks: list[tuple[str, str | None]] = []
        self.files: dict[str, bytes] = {}
        self.fail_send = False

    async def send_message(self, chat_id: int, message: TelegramMessage) -> dict:
        from pauza.integrations.telegram import TelegramError

        if self.fail_send:
            raise TelegramError("TELEGRAM_SEND_FAILED", 500)
        self.sent.append((chat_id, message))
        return {}

    async def answer_callback(self, callback_query_id: str, text: str | None = None) -> None:
        self.callbacks.append((callback_query_id, text))

    async def get_file_path(self, file_id: str) -> tuple[str, int | None]:
        return f"photos/{file_id}.jpg", len(self.files.get(file_id, b""))

    async def download_file(self, file_path: str, max_bytes: int) -> bytes:
        file_id = file_path.split("/")[-1].rsplit(".", 1)[0]
        return self.files[file_id]

    async def aclose(self) -> None:
        pass

    @property
    def texts(self) -> list[str]:
        return [m.text for _, m in self.sent]


class FakeOCR:
    name = "fake"

    def __init__(self, text: str = "", confident: bool = True, fail: bool = False) -> None:
        self.text = text
        self.confident = confident
        self.fail = fail
        self.calls = 0

    async def extract_text(self, image, options=None) -> OCRResult:
        from pauza.integrations.ocr import OCRUnavailable

        self.calls += 1
        if self.fail:
            raise OCRUnavailable("down")
        return OCRResult(self.text, self.confident, 90.0)


@pytest.fixture
def telegram() -> FakeTelegram:
    return FakeTelegram()


@pytest.fixture
async def container(settings, redis, db, telegram):
    c = build_container(settings, redis=redis, db=db, telegram=telegram)  # type: ignore[arg-type]
    c.handler.ocr = FakeOCR()
    yield c


def png_bytes(size: tuple[int, int] = (200, 100), fmt: str = "PNG") -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, "white").save(buf, format=fmt)
    return buf.getvalue()


USER_ID = 555000111
_counter = iter(range(1000, 10**6))


def text_update(text: str, user_id: int = USER_ID, chat_type: str = "private", update_id: int | None = None) -> dict:
    return {
        "update_id": update_id if update_id is not None else next(_counter),
        "message": {
            "message_id": 1,
            "date": 0,
            "chat": {"id": user_id if chat_type == "private" else -100500, "type": chat_type},
            "from": {"id": user_id, "is_bot": False, "first_name": "Тест", "username": "secret_username"},
            "text": text,
        },
    }


def photo_update(file_id: str = "F1", caption: str | None = None, user_id: int = USER_ID, **extra) -> dict:
    msg = {
        "message_id": 2,
        "date": 0,
        "chat": {"id": user_id, "type": "private"},
        "from": {"id": user_id, "is_bot": False, "first_name": "Тест"},
        "photo": [
            {"file_id": file_id + "s", "file_unique_id": "u1", "width": 90, "height": 45, "file_size": 1000},
            {"file_id": file_id, "file_unique_id": "u2", "width": 200, "height": 100, "file_size": 5000},
        ],
        **extra,
    }
    if caption:
        msg["caption"] = caption
    return {"update_id": next(_counter), "message": msg}


def callback_update(data: str, user_id: int = USER_ID, chat_id: int | None = None) -> dict:
    return {
        "update_id": next(_counter),
        "callback_query": {
            "id": "cq1",
            "from": {"id": user_id, "is_bot": False, "first_name": "Тест"},
            "message": {"message_id": 3, "chat": {"id": chat_id if chat_id is not None else user_id, "type": "private"}},
            "data": data,
        },
    }
