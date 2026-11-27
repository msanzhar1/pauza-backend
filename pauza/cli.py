"""Административные команды (не публикуются в интернет).

    python -m pauza.cli set-webhook
    python -m pauza.cli publish-ruleset --author "ФИО" --description "что изменилось"
    python -m pauza.cli import-regions config/regions.json --author "ФИО"
    python -m pauza.cli validate-regions config/regions.json
    python -m pauza.cli gen-keys
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
from pathlib import Path

import sqlalchemy as sa


def _settings():
    from pauza.config import get_settings

    return get_settings()


async def set_webhook() -> None:
    from pauza.bot import COMMANDS
    from pauza.integrations.telegram import TelegramClient

    s = _settings()
    tg = TelegramClient(s.telegram_bot_token.get_secret_value(), s.telegram_api_base)
    try:
        url = s.public_base_url.rstrip("/") + "/webhooks/telegram"
        await tg.set_webhook(url, s.telegram_webhook_secret.get_secret_value())
        await tg.set_my_commands(COMMANDS)
        print("webhook установлен, команды обновлены")
    finally:
        await tg.aclose()


async def publish_ruleset(author: str, description: str) -> None:
    from pauza.analysis.rules import RULESET_VERSION, ruleset_digest
    from pauza.db.models import AuditEvent, RuleVersion
    from pauza.db.session import Database, make_engine

    db = Database(make_engine(_settings().database_url))
    digest = ruleset_digest()
    try:
        async with db.session() as s:
            existing = await s.scalar(sa.select(RuleVersion).where(RuleVersion.version == RULESET_VERSION))
            if existing is not None:
                if existing.rules_digest != digest:
                    sys.exit(f"Версия {RULESET_VERSION} уже опубликована с другим содержимым. Увеличьте RULESET_VERSION.")
                print(f"Версия {RULESET_VERSION} уже опубликована")
                return
            s.add(RuleVersion(version=RULESET_VERSION, description=description, author=author, rules_digest=digest))
            s.add(AuditEvent(action="publish", entity="rule_versions", entity_ref=RULESET_VERSION, author=author, details={"digest": digest}))
        print(f"Опубликована версия правил {RULESET_VERSION}")
    finally:
        await db.engine.dispose()


async def import_regions_cmd(path: str, author: str) -> None:
    from pauza.db.session import Database, make_engine
    from pauza.regions import import_regions

    db = Database(make_engine(_settings().database_url))
    try:
        async with db.session() as s:
            n = await import_regions(s, path, author)
        print(f"Импортировано записей: {n}")
    finally:
        await db.engine.dispose()


def validate_regions(path: str) -> None:
    from pauza.regions import validate_entries

    entries = validate_entries(json.loads(Path(path).read_text(encoding="utf-8")))
    print(f"OK: {len(entries)} записей")


def gen_keys() -> None:
    from cryptography.fernet import Fernet

    print(f"TELEGRAM_WEBHOOK_SECRET={secrets.token_urlsafe(48)[:64]}")
    print(f"ID_HASH_KEY={secrets.token_urlsafe(48)}")
    print(f"CALLBACK_SIGNING_KEY={secrets.token_urlsafe(48)}")
    print(f"QUEUE_ENCRYPTION_KEY={Fernet.generate_key().decode()}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pauza")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-webhook")
    p = sub.add_parser("publish-ruleset")
    p.add_argument("--author", required=True)
    p.add_argument("--description", required=True)
    p = sub.add_parser("import-regions")
    p.add_argument("path")
    p.add_argument("--author", required=True)
    p = sub.add_parser("validate-regions")
    p.add_argument("path")
    sub.add_parser("gen-keys")
    args = parser.parse_args(argv)

    if args.cmd == "set-webhook":
        asyncio.run(set_webhook())
    elif args.cmd == "publish-ruleset":
        asyncio.run(publish_ruleset(args.author, args.description))
    elif args.cmd == "import-regions":
        asyncio.run(import_regions_cmd(args.path, args.author))
    elif args.cmd == "validate-regions":
        validate_regions(args.path)
    elif args.cmd == "gen-keys":
        gen_keys()


if __name__ == "__main__":
    main()
