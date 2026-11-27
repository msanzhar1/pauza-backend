"""Закрыть таблицы от внешних API (Supabase Data API / PostgREST)

Приложение ходит в БД напрямую под ролью-владельцем, поэтому RLS без политик
его не ограничивает, но запрещает чтение и запись ролям anon/authenticated,
если у проекта включён Data API. На обычном PostgreSQL этих ролей нет, и
миграция только включает RLS.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-27
"""
from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("users", "checks", "feedback", "region_resources", "rule_versions", "audit_events", "alembic_version")
API_ROLES = ("anon", "authenticated")


def upgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    for role in API_ROLES:
        op.execute(
            f"""
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                REVOKE ALL ON {", ".join(TABLES)} FROM {role};
              END IF;
            END
            $$;
            """
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
