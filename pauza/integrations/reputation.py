"""Интерфейс репутационных списков URL (раздел 8.4).

В MVP реальный провайдер не подключён (решение раздела 21 п.5 не принято).
Провайдеру разрешено передавать только хосты, никогда текст переписки.
"""

from __future__ import annotations

from typing import Protocol


class UrlReputationProvider(Protocol):
    name: str
    data_version: str
    timeout: float

    async def check_hosts(self, hosts: list[str]) -> set[str]:
        """Вернуть подмножество хостов, которые числятся в списках угроз."""
        ...


class StaticBlocklistProvider:
    """Локальный список из файла: без сетевых запросов. Пригоден для тестов и ручных списков."""

    name = "static"

    def __init__(self, hosts: set[str], data_version: str, timeout: float = 1.0) -> None:
        self.hosts = {h.lower() for h in hosts}
        self.data_version = data_version
        self.timeout = timeout

    async def check_hosts(self, hosts: list[str]) -> set[str]:
        return {h for h in hosts if h.lower() in self.hosts}
