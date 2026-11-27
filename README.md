# pauza-backend

Backend Telegram-бота «Пауза». Бот принимает текст, ссылку или скриншот, ищет признаки мошенничества и отвечает уровнем риска (`HIGH`, `ELEVATED`, `NO_CLEAR_SIGNAL`), причинами и безопасными шагами. Реализация MVP по ТЗ v1.0.

Бот — информационный помощник. Он не гарантирует обнаружение всех схем и никогда не называет сообщение «безопасным».

## Архитектура

Одна кодовая база, два процесса: **API** и **worker**.

```
Telegram ──HTTPS──▶ API (FastAPI) ──Lua: idempotency key + LPUSH──▶ Redis (очередь, зашифровано, TTL 15 мин)
                     │ секрет, схема, размер,                          │
                     │ лимит по IP                                     ▼
                     ▼                                      Worker ── BLMOVE ── обработка ── sendMessage ──▶ Telegram
                /health/*                                     │
                                                              ├─ Analysis: normalize → URL analyzer → RuleEngine → шаблоны
                                                              ├─ OCR (локальный Tesseract)
                                                              ├─ PostgreSQL: users, checks, feedback, region_resources, rule_versions, audit_events
                                                              └─ Redis: rate limit, состояния диалога (TTL 30 мин)
```

| Модуль | Назначение |
|---|---|
| `pauza/api.py` | `POST /webhooks/telegram`, `GET /health/live`, `GET /health/ready` |
| `pauza/queue.py` | Надёжная очередь: идемпотентность по `update_id`, processing-списки, возврат заданий упавших воркеров |
| `pauza/worker.py` | Цикл воркера, graceful shutdown, периодическая очистка |
| `pauza/bot.py` | Команды, проверки, callback-кнопки, `/delete_me` |
| `pauza/analysis/` | `normalize.py`, `urls.py` (UrlAnalyzer), `rules.py` (RuleEngine), `service.py` (сборка результата) |
| `pauza/messages.py` | Шаблоны ответов (ResponseComposer), экранирование HTML |
| `pauza/integrations/` | `telegram.py` (retry, `retry_after`), `ocr.py` (OCRProvider), `llm.py` (выключен), `reputation.py` (интерфейс) |
| `pauza/regions.py` | Справочник официальных контактов, импорт с проверкой |
| `pauza/cli.py` | Webhook, публикация версии правил, импорт регионов, генерация ключей |

Внутренние контракты из раздела 10 ТЗ: `BotHandler.handle(update) -> Accepted | Ignored | Rejected`, `normalize()`, `UrlAnalyzer.analyze()`, `RuleEngine.evaluate()`, `OCRProvider.extract_text()`, `compose_result()`, `TelegramClient.send_message()`.

## Приватность: что хранится и где

| Данные | Где | Срок |
|---|---|---|
| Текст, URL, изображение, OCR-текст | Только память воркера; Update в очереди Redis **зашифрован** (Fernet) | До ответа, максимум `TEMP_DATA_TTL_SECONDS` (≤ 15 мин): просроченный токен не расшифровывается и отбрасывается |
| Временный файл для OCR | `TEMP_DIR`, случайное имя, права 700 | Удаляется в `finally`; cleaner удаляет остатки старше TTL |
| Telegram ID | Не хранится. В БД и Redis только `HMAC-SHA256(ID_HASH_KEY, id)` | Ответы отправляются по `chat_id` из самого Update |
| Настройки (регион, версия согласия) | `users` | До `/delete_me` или срока неактивности (`USER_INACTIVITY_DAYS`) |
| Метаданные проверки (тип, уровень, коды индикаторов, длительность) | `checks` | `CHECK_RETENTION_DAYS` (по умолчанию 365) |
| Idempotency key | Redis `pauza:idem:update:<id>` | 48 часов |
| Состояние диалога | Redis | 30 минут |

Логи — JSON только с полями из белого списка (`pauza/logs.py`); сообщения исключений не логируются, только тип. `update_id` и прочие идентификаторы псевдонимизируются. Метрики Prometheus не содержат пользовательских меток. Автотесты проверяют, что текст, URL, OCR-текст, подпись, Telegram ID, username и токен не попадают в логи, метрики и таблицу `checks`.

Ссылки из сообщений **никогда не открываются**: анализ только по строке адреса (схема, IP, punycode/смешение алфавитов, сокращатели, `user@host`, похожесть на официальные домены из `config/official_domains.json`). Тест `test_url_analysis_makes_no_network_requests` это проверяет.

## Переменные окружения

Полный список с комментариями — в [`.env.example`](.env.example). Ключевые:

| Переменная | Описание |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Токен бота |
| `TELEGRAM_WEBHOOK_SECRET` | `secret_token` webhook, проверяется постоянным сравнением |
| `ID_HASH_KEY` | Ключ keyed hash для Telegram ID и псевдонимов в логах. **Смена ключа отвяжет всех пользователей от их настроек** |
| `CALLBACK_SIGNING_KEY` | Подпись inline-кнопок (HMAC, срок действия, привязка к пользователю) |
| `QUEUE_ENCRYPTION_KEY` | Fernet-ключ шифрования очереди |
| `DATABASE_URL`, `REDIS_URL` | `postgresql+asyncpg://...`, `redis://...` |
| `MAX_TEXT_LENGTH`, `MAX_IMAGE_BYTES`, `MAX_IMAGE_PIXELS`, `MAX_URLS_PER_CHECK` | Лимиты входа |
| `RATE_LIMIT_WINDOW_SECONDS`, `RATE_LIMIT_MAX_CHECKS`, `RATE_LIMIT_DAILY_MAX_CHECKS` | Лимит проверок на пользователя (по умолчанию 10 за 10 минут и 50 в сутки). Команды не лимитируются |
| `WEBHOOK_IP_RATE_LIMIT_PER_MINUTE` | Лимит запросов к webhook с одного адреса |
| `OCR_PROVIDER` | `tesseract` (локально) или `disabled` |
| `LLM_ENABLED` | `false`. Включение требует реализации провайдера (см. «Открытые решения») |
| `URL_REPUTATION_ENABLED` | `false`. Аналогично |

Сгенерировать ключи: `python -m pauza.cli gen-keys`.

При `APP_ENV=production` запуск падает с ошибкой конфигурации, если секреты короче 32 символов или похожи на заглушки, либо `PUBLIC_BASE_URL` не `https://`.

## Локальный запуск

```bash
cp .env.example .env
python -m pip install -e ".[dev]"
python -m pauza.cli gen-keys           # вставьте выведенные ключи в .env
# впишите TELEGRAM_BOT_TOKEN и PUBLIC_BASE_URL

docker compose up --build              # postgres, redis, migrate, api (:8000), worker
```

Без Docker: поднимите PostgreSQL и Redis, затем

```bash
alembic upgrade head
uvicorn pauza.api:app_factory --factory --port 8000 --no-access-log
python -m pauza.worker
```

Для приёма webhook локально нужен публичный HTTPS-адрес (например, туннель) в `PUBLIC_BASE_URL`.

## Миграции

Alembic, async-драйвер. URL берётся из `DATABASE_URL`.

```bash
alembic upgrade head        # отдельным шагом деплоя, до выката новых api/worker
alembic revision --autogenerate -m "..."   # новая миграция
alembic check               # модели и миграции совпадают (выполняется в CI)
```

Несовместимые изменения схемы — через expand/contract: сначала добавить новое и выкатить код, который понимает обе схемы, затем удалить старое отдельной миграцией.

## Настройка webhook

```bash
python -m pauza.cli set-webhook
```

Команда идемпотентна: устанавливает `PUBLIC_BASE_URL/webhooks/telegram`, `secret_token`, `allowed_updates = [message, callback_query, my_chat_member]` и список команд бота. Повторяйте её при каждом деплое.

## Правила и регионы

- Каталог индикаторов и уровни: [`docs/INDICATORS.md`](docs/INDICATORS.md).
- Правила — код в `pauza/analysis/rules.py`, версия `RULESET_VERSION`. При изменении: поднять версию, записать в [`docs/RULES_CHANGELOG.md`](docs/RULES_CHANGELOG.md), после деплоя выполнить
  `python -m pauza.cli publish-ruleset --author "Имя" --description "Что изменилось"` (пишет `rule_versions` и `audit_events`). Каждая проверка хранит `analysis_version`.
- Справочник регионов пуст по умолчанию. Формат — `config/regions.example.json` (значения вымышлены). Каждая запись требует https-источник и дату ручной проверки, иначе импорт отклоняется:
  ```bash
  python -m pauza.cli validate-regions config/regions.json
  python -m pauza.cli import-regions config/regions.json --author "Имя"
  ```
  Пока справочника нет, `/help_now` даёт только универсальные шаги без телефонов и ссылок.

## Тесты

```bash
pytest -q                                     # SQLite + fakeredis, ~3 с
TEST_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/pauza_test pytest -q   # на PostgreSQL
ruff check .
```

Что покрыто: нормализация и извлечение URL; каждое правило на позитивных и негативных примерах (синтетический набор `tests/data/synthetic_messages.json`); приоритет `HIGH`; запрет понижения риска LLM и prompt injection; экранирование ответа; подписи callback; валидация изображений (формат по содержимому, HEIC, анимация, битые файлы, лимиты); webhook-секрет (валидный, отсутствующий, неверный), повторный `update_id`, недоступная очередь → 5xx; retry и `retry_after` Telegram; полный путь очередь → воркер → ответ; таймаут анализа не даёт `NO_CLEAR_SIGNAL`; сбой OCR; `/delete_me`; отсутствие содержимого в логах и метриках; отсутствие сетевых запросов к URL; реальный Tesseract (пропускается, если не установлен).

Нагрузочные тесты (20 Update/с, всплеск 100 Update/с) в репозиторий не входят: их нужно прогнать на стенде, близком к production.

## Развёртывание (production)

1. Образ один (`Dockerfile`); процессы: `api` (команда по умолчанию), `worker` (`python -m pauza.worker`), миграции (`alembic upgrade head`) отдельным шагом.
2. HTTPS-ingress перед `api`; наружу публикуется только `/webhooks/telegram` и при необходимости `/health/*`. Порт метрик `9100` — только во внутреннюю сеть.
3. PostgreSQL с шифрованием диска и резервными копиями; регулярно проверяйте восстановление. Redis без RDB/AOF (`--save "" --appendonly no`): в нём только зашифрованная очередь и короткоживущие ключи.
4. Секреты — из secret manager, не из файлов в репозитории.
5. Воркеры масштабируются горизонтально. `stop_grace_period` ≥ 30 с: по SIGTERM воркер дорабатывает текущее задание и возвращает остальные в очередь.
6. После деплоя: `python -m pauza.cli set-webhook`, при изменении правил — `publish-ruleset`.
7. Зависимости: Dependabot и `pip-audit` в CI.

Метрики (`pauza_*`): число Update по типу и результату, проверки по типу входа и уровню риска, латентность этапов (`webhook`, `queue_wait`, `ocr`, `analysis_*`, `send`), ошибки провайдеров, rate limit, повторные доставки, обратная связь, глубина очереди. Рекомендуемые алерты и действия — в [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Внешние поставщики и передаваемые данные

| Поставщик | Статус | Что получает |
|---|---|---|
| Telegram Bot API | Используется | Ответы бота; бот скачивает файлы пользователя через file API |
| OCR | Локальный Tesseract | Ничего не уходит наружу |
| LLM | Выключен, провайдер не реализован | Если включат: фрагмент текста до 2000 символов и коды правил, без Telegram ID, имени, телефона и настроек |
| Репутация URL | Выключена, провайдер не реализован | Если включат: только хосты, без текста сообщения |

## Открытые решения (раздел 21 ТЗ)

До их утверждения код работает на безопасных значениях по умолчанию.

1. **Первый рынок и региональные контакты** — справочник пуст, контакты не выдумываются.
2. **OCR** — локальный Tesseract (`rus+eng`).
3. **LLM** — выключен (`LLM_ENABLED=false`); есть адаптер со строгой схемой и защитой от понижения риска, но без конкретного провайдера.
4. **Срок неактивности** — `USER_INACTIVITY_DAYS` пуст (не удаляем по неактивности).
5. **Источник репутации доменов** — только интерфейс `UrlReputationProvider`.
6. **Юридические тексты** — в боте краткое уведомление о данных, версия `CONSENT_VERSION=2026-11-draft`; нужен утверждённый текст.
7. **Нагрузка и лимиты провайдеров** — лимиты из ТЗ, настраиваются через env.

## Известные ограничения

- Правила работают на регулярных выражениях для русского и частично английского; новые схемы и перефразирования могут быть пропущены. Метрики качества не измерены: до ручной разметки набора бот нельзя позиционировать как гарантированно обнаруживающий мошенничество.
- Анализ ссылок статический: без репутационного провайдера новый фишинговый домен без явной маскировки не будет распознан.
- Список официальных доменов (`config/official_domains.json`) минимальный и не привязан к рынку.
- Интерфейс только на русском.
- В группах бот не работает: отвечает инструкцией перейти в личный чат (не чаще раза в 10 минут на чат).
- Из альбома проверяется только первое изображение.
- Update, пролежавший в очереди дольше `TEMP_DATA_TTL_SECONDS`, отбрасывается без ответа (содержимое уже нельзя расшифровать).
- Docker-образ не собирался в среде разработки этого PR (нет доступа к apt-зеркалам); CI собирает и тестирует код без Docker.
