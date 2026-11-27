# Журнал изменений правил

Каждое изменение `pauza/analysis/rules.py` должно поднимать `RULESET_VERSION` и добавлять запись сюда. После деплоя версия публикуется в БД командой `python -m pauza.cli publish-ruleset` (таблицы `rule_versions`, `audit_events`). Образцы реальных сообщений сюда не записываются.

## 1.0.0 — 2026-11-27

Первый набор правил MVP: `OTP_REQUEST`, `CREDENTIAL_REQUEST`, `REMOTE_ACCESS`, `URGENT_PAYMENT`, `PRIZE_OR_REFUND_FEE`, `SUSPICIOUS_DOMAIN`, `SECRET_KEEPING`, `PAYMENT_IRREVERSIBLE`, `INVESTMENT_GUARANTEE`, `IMPERSONATION_CLAIM`, контекстный `TIME_PRESSURE`, пять комбинаций-эскалаций. Проверено на синтетическом наборе `tests/data/synthetic_messages.json` (40 примеров).
