import json

import httpx
import pytest

from pauza.api import create_app
from pauza.queue import QUEUE_KEY

from .conftest import text_update

SECRET = "test-webhook-secret"


@pytest.fixture
async def client(settings, redis, db):
    app = create_app(settings, redis=redis, db=db)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.app = app
            yield c


def post(client, body, secret=SECRET, **headers):
    h = {"content-type": "application/json", **headers}
    if secret is not None:
        h["x-telegram-bot-api-secret-token"] = secret
    data = body if isinstance(body, (bytes, str)) else json.dumps(body)
    return client.post("/webhooks/telegram", content=data, headers=h)


async def test_valid_secret_enqueues(client, redis):
    r = await post(client, text_update("привет"))
    assert r.status_code == 200
    assert await redis.llen(QUEUE_KEY) == 1


@pytest.mark.parametrize("secret", [None, "", "wrong"])
async def test_missing_or_wrong_secret(client, redis, secret):
    r = await post(client, text_update("привет"), secret=secret)
    assert r.status_code == 401
    assert await redis.llen(QUEUE_KEY) == 0


async def test_duplicate_update_id_not_enqueued_twice(client, redis):
    upd = text_update("привет", update_id=777)
    assert (await post(client, upd)).status_code == 200
    assert (await post(client, upd)).status_code == 200
    assert await redis.llen(QUEUE_KEY) == 1


async def test_queue_payload_is_encrypted(client, redis):
    await post(client, text_update("Продиктуйте код из смс"))
    raw = (await redis.lindex(QUEUE_KEY, 0)).decode()
    assert "Продиктуйте" not in raw and "555000111" not in raw


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ("not json", 400),
        ({"no_update_id": 1}, 400),
        ({"update_id": "1"}, 400),
        ([1, 2], 400),
    ],
)
async def test_invalid_schema(client, body, status):
    assert (await post(client, body)).status_code == status


async def test_body_too_large(client, settings):
    big = json.dumps({"update_id": 1, "message": {"text": "a" * (settings.max_webhook_body_bytes + 1)}})
    assert (await post(client, big)).status_code == 413


async def test_unsupported_update_types_ignored(client, redis):
    r = await post(client, {"update_id": 5, "edited_message": {"text": "x"}})
    assert r.status_code == 200 and await redis.llen(QUEUE_KEY) == 0


async def test_queue_unavailable_returns_5xx(client):
    class Broken:
        async def enqueue_once(self, update):
            raise ConnectionError("redis down")

    client.app.state.queue = Broken()
    assert (await post(client, text_update("x"))).status_code == 503


async def test_ip_rate_limit(client, settings):
    settings.webhook_ip_rate_limit_per_minute = 2
    codes = [(await post(client, text_update("x"))).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


async def test_health(client):
    assert (await client.get("/health/live")).status_code == 200
    r = await client.get("/health/ready")
    assert r.status_code == 200 and r.content == b""


async def test_no_docs_exposed(client):
    for path in ("/docs", "/openapi.json", "/redoc"):
        assert (await client.get(path)).status_code == 404
