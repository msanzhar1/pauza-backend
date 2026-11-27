"""Региональный справочник официальных каналов помощи (раздел 11.4).

Контакты показываются пользователю только если у записи заполнены источник
(source_url) и дата ручной проверки (verified_at). Справочник по умолчанию
пуст: решение о первом рынке (раздел 21 п.1) ещё не принято, и бот не
придумывает телефоны и ссылки.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from pauza.db.models import AuditEvent, RegionResource, ResourceType

# Названия регионов для меню. Код без названия показывается как есть.
REGION_NAMES = {
    "RU": "Россия", "KZ": "Казахстан", "BY": "Беларусь", "UZ": "Узбекистан", "KG": "Кыргызстан",
    "AM": "Армения", "GE": "Грузия", "AZ": "Азербайджан", "TJ": "Таджикистан", "MD": "Молдова",
}

_REGION_RE = re.compile(r"^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$")
_PHONE_RE = re.compile(r"^\+?[0-9 ()-]{2,20}$")


class RegionImportError(ValueError):
    pass


def region_name(code: str | None) -> str | None:
    if not code:
        return None
    return REGION_NAMES.get(code, code)


async def available_regions(session: AsyncSession) -> list[str]:
    rows = await session.execute(
        sa.select(RegionResource.region_code).where(RegionResource.active.is_(True)).distinct().order_by(RegionResource.region_code)
    )
    return [r[0] for r in rows]


async def resources_for(session: AsyncSession, region_code: str | None) -> list[RegionResource]:
    if not region_code:
        return []
    rows = await session.execute(
        sa.select(RegionResource)
        .where(
            RegionResource.region_code == region_code,
            RegionResource.active.is_(True),
            RegionResource.source_url.is_not(None),
            RegionResource.source_url != "",
            RegionResource.verified_at.is_not(None),
        )
        .order_by(RegionResource.resource_type)
    )
    return list(rows.scalars())


def validate_entries(data: object) -> list[dict]:
    """Проверка файла справочника перед импортом."""
    if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
        raise RegionImportError("ожидается объект {\"resources\": [...]}")
    out = []
    for i, item in enumerate(data["resources"]):
        where = f"resources[{i}]"
        if not isinstance(item, dict):
            raise RegionImportError(f"{where}: ожидается объект")
        code = str(item.get("region_code", "")).upper()
        if not _REGION_RE.match(code):
            raise RegionImportError(f"{where}.region_code: неверный код региона")
        try:
            rtype = ResourceType(item.get("resource_type"))
        except ValueError:
            raise RegionImportError(f"{where}.resource_type: неизвестный тип") from None
        for req in ("display_name", "description", "source_url", "verified_at"):
            if not item.get(req):
                raise RegionImportError(f"{where}.{req}: обязательное поле")
        if not str(item["source_url"]).startswith("https://"):
            raise RegionImportError(f"{where}.source_url: нужен https-источник")
        url = item.get("official_url")
        if url and not str(url).startswith("https://"):
            raise RegionImportError(f"{where}.official_url: нужен https")
        phone = item.get("official_phone")
        if phone and not _PHONE_RE.match(str(phone)):
            raise RegionImportError(f"{where}.official_phone: неверный формат")
        if not url and not phone:
            raise RegionImportError(f"{where}: нужен official_url или official_phone")
        try:
            verified = datetime.fromisoformat(str(item["verified_at"]))
        except ValueError:
            raise RegionImportError(f"{where}.verified_at: ожидается ISO-дата") from None
        if verified.tzinfo is None:
            verified = verified.replace(tzinfo=UTC)
        out.append(
            {
                "region_code": code,
                "resource_type": rtype,
                "display_name": str(item["display_name"])[:200],
                "official_url": url,
                "official_phone": phone,
                "description": str(item["description"]),
                "source_url": str(item["source_url"]),
                "verified_at": verified,
                "active": bool(item.get("active", True)),
            }
        )
    return out


async def import_regions(session: AsyncSession, path: str | Path, author: str, replace_regions: bool = True) -> int:
    entries = validate_entries(json.loads(Path(path).read_text(encoding="utf-8")))
    codes = sorted({e["region_code"] for e in entries})
    if replace_regions and codes:
        await session.execute(sa.delete(RegionResource).where(RegionResource.region_code.in_(codes)))
    for entry in entries:
        session.add(RegionResource(**entry))
    session.add(
        AuditEvent(action="import", entity="region_resources", entity_ref=",".join(codes)[:64], author=author, details={"count": len(entries), "regions": codes})
    )
    return len(entries)
