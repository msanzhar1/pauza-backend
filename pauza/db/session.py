from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

if TYPE_CHECKING:
    from pauza.config import Settings


def engine_kwargs(database_url: str, pool_size: int = 5, max_overflow: int = 5, pool_mode: str = "session") -> dict[str, Any]:
    """Параметры движка.

    pool_mode="transaction" — для пулера в режиме транзакций (например, Supabase, порт 6543):
    он не поддерживает prepared statements, а пул соединений держит сам пулер.
    """
    # Логирование SQL выключено: параметры запросов могут содержать служебные данные.
    kwargs: dict[str, Any] = {"echo": False, "pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        return kwargs
    if pool_mode == "transaction":
        kwargs["poolclass"] = NullPool
        kwargs["connect_args"] = {"statement_cache_size": 0, "prepared_statement_cache_size": 0}
    else:
        kwargs.update(pool_size=pool_size, max_overflow=max_overflow, pool_recycle=1800)
    return kwargs


def make_engine(database_url: str, pool_size: int = 5, max_overflow: int = 5, pool_mode: str = "session") -> AsyncEngine:
    return create_async_engine(database_url, **engine_kwargs(database_url, pool_size, max_overflow, pool_mode))


def engine_from_settings(settings: Settings) -> AsyncEngine:
    return make_engine(settings.database_url, settings.database_pool_size, settings.database_max_overflow, settings.database_pool_mode)


class Database:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self._factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._factory() as s:
            try:
                yield s
                await s.commit()
            except BaseException:
                await s.rollback()
                raise

    async def ping(self) -> bool:
        from sqlalchemy import text

        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
