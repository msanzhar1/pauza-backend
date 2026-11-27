# Развёртывание: Supabase + Railway

Пошаговая инструкция для первого production-запуска. Supabase даёт только PostgreSQL. API, воркер и Redis живут на Railway.

```
Telegram ──HTTPS──▶ Railway: api ──▶ Railway: Redis (очередь) ──▶ Railway: worker ──▶ Telegram
                          │                                            │
                          └──────────────▶ Supabase: PostgreSQL ◀──────┘
```

Что понадобится: аккаунты Supabase, Railway и GitHub (репозиторий `msanzhar1/pauza-backend`), токен бота от @BotFather, Python 3.12 локально (только чтобы сгенерировать ключи).

Регионы: выберите европейский регион и в Supabase, и в Railway, чтобы база и приложение были рядом. Серверы Telegram для webhook тоже в Европе.

---

## 1. Supabase: база данных

1. Создайте проект. Сохраните пароль базы в менеджере паролей: он понадобится в строке подключения.
2. Откройте **Connect** вверху страницы проекта и выберите **Session pooler**. Скопируйте строку вида
   ```
   postgresql://postgres.<PROJECT-REF>:[YOUR-PASSWORD]@aws-<N>-<REGION>.pooler.supabase.com:5432/postgres
   ```
   Хост копируйте из диалога, не собирайте вручную.
3. Превратите её в `DATABASE_URL` для приложения: замените схему на `postgresql+asyncpg://`, подставьте пароль и добавьте `?ssl=require`:
   ```
   postgresql+asyncpg://postgres.<PROJECT-REF>:<ПАРОЛЬ>@aws-<N>-<REGION>.pooler.supabase.com:5432/postgres?ssl=require
   ```
   Если в пароле есть `@`, `:`, `/`, `?`, `#` или `%`, закодируйте их (`@` → `%40` и т.д.) или смените пароль на буквенно-цифровой.

**Почему Session pooler.** Прямое подключение (`db.<ref>.supabase.co`) работает только по IPv6, если не покупать IPv4-надстройку. Пулер доступен по IPv4 на всех планах. В режиме сессий (порт `5432`) работают prepared statements и миграции, поэтому код менять не нужно.

**Режим транзакций (порт `6543`)** нужен только если упрётесь в лимит подключений. Тогда в `DATABASE_URL` укажите порт `6543` и добавьте переменную `DATABASE_POOL_MODE=transaction`: приложение отключит prepared statements и свой пул. Миграции всё равно запускайте через Session pooler.

4. **Настройки безопасности в Supabase:**
   - *Database → Settings → SSL*: включите **Enforce SSL**, чтобы база отклоняла подключения без шифрования.
   - *Integrations → Data API*: бот не использует Data API, его можно выключить (**Enable Data API** → off). Миграция `0002` в любом случае включает RLS на всех таблицах и отзывает права у ролей `anon` и `authenticated`, поэтому через публичный API таблицы не читаются, даже если Data API включён.
   - *Database → Backups*: проверьте, какие резервные копии даёт ваш план, и сделайте одно тестовое восстановление до запуска.
5. **Лимит подключений.** Каждый процесс держит до `DATABASE_POOL_SIZE + DATABASE_MAX_OVERFLOW` соединений (по умолчанию 5 + 5 = 10). Считайте так:
   `(реплики api + реплики worker) × 10 + 1 (миграции)` ≤ лимит клиентов пулера на вашем плане (смотрите в *Database → Settings → Connection pooling*). Для старта (1 api + 1 worker) это 21. Если лимит меньше, уменьшите `DATABASE_POOL_SIZE` и `DATABASE_MAX_OVERFLOW`.

Таблицы создавать вручную не нужно: их создаст шаг миграций при первом деплое.

---

## 2. Секреты

Локально, в клоне репозитория:

```bash
python -m pip install cryptography
python -c "import secrets; from cryptography.fernet import Fernet; print('TELEGRAM_WEBHOOK_SECRET='+secrets.token_urlsafe(48)[:64]); print('ID_HASH_KEY='+secrets.token_urlsafe(48)); print('CALLBACK_SIGNING_KEY='+secrets.token_urlsafe(48)); print('QUEUE_ENCRYPTION_KEY='+Fernet.generate_key().decode())"
```

(Если проект установлен целиком, то же делает `python -m pauza.cli gen-keys`.)

Сохраните значения в менеджере паролей. Отдельно запомните про `ID_HASH_KEY`: если его потерять или сменить, все пользователи потеряют свои настройки. Никуда не коммитьте эти значения.

---

## 3. Railway: проект и Redis

1. **New Project → Deploy from GitHub repo** → `msanzhar1/pauza-backend`, ветка `main`. Railway найдёт `Dockerfile` и соберёт образ вместе с Tesseract (`rus`, `eng`). Это первый сервис, назовите его `api`.
2. В том же проекте: **New → Database → Redis**. Сервис будет называться `Redis`.
3. Добавьте второй сервис из того же репозитория (**New → GitHub Repo** → тот же репозиторий), назовите его `worker`.

Файлы `railway.json`/`railway.toml` в репозиторий не добавлены: Railway отключает этот способ конфигурации с 1 декабря 2026 года. Всё ниже настраивается в интерфейсе.

### 3.1. Общие переменные

В **Project Settings → Shared Variables** добавьте (и подключите к обоим сервисам `api` и `worker`):

| Переменная | Значение |
|---|---|
| `APP_ENV` | `production` |
| `APP_LOG_LEVEL` | `INFO` |
| `TELEGRAM_BOT_TOKEN` | токен от @BotFather |
| `TELEGRAM_WEBHOOK_SECRET` | из шага 2 |
| `ID_HASH_KEY` | из шага 2 |
| `CALLBACK_SIGNING_KEY` | из шага 2 |
| `QUEUE_ENCRYPTION_KEY` | из шага 2 |
| `DATABASE_URL` | строка из шага 1.3 |
| `REDIS_URL` | `${{Redis.REDIS_URL}}` (ссылка на переменную сервиса Redis, внутренняя сеть) |
| `DEFAULT_REGION_CODE` | `KG` |
| `PUBLIC_BASE_URL` | заполните в шаге 3.2 |

Остальные параметры (лимиты, таймауты) можно не задавать: значения по умолчанию соответствуют ТЗ. Полный список — в `.env.example`. `LLM_ENABLED` и `URL_REPUTATION_ENABLED` оставьте выключенными.

При `APP_ENV=production` приложение не стартует, если секреты короче 32 символов или `PUBLIC_BASE_URL` не начинается с `https://`. Это защита от случайного запуска с тестовыми значениями.

### 3.2. Сервис `api`

*Settings:*
- **Networking → Generate Domain**. Получите адрес вида `https://<name>.up.railway.app` и запишите его в общую переменную `PUBLIC_BASE_URL`.
- **Deploy → Pre-deploy Command**:
  ```
  /bin/sh -c "alembic upgrade head && python -m pauza.cli publish-ruleset --author deploy --description 'см. docs/RULES_CHANGELOG.md' && python -m pauza.cli set-webhook"
  ```
  Команда выполняется перед каждым деплоем с переменными сервиса: применяет миграции, записывает версию правил в журнал аудита и заново регистрирует webhook. Если она падает, деплой не выкатывается, а старая версия продолжает работать.
- **Deploy → Healthcheck Path**: `/health/ready` (отвечает 200, только когда доступны и БД, и Redis).
- **Variables** (только для `api`): `FORWARDED_ALLOW_IPS=*`, чтобы uvicorn брал адрес клиента из заголовка прокси Railway.

Порт задавать не нужно: образ слушает `$PORT`, который подставляет Railway.

### 3.3. Сервис `worker`

*Settings:*
- **Deploy → Custom Start Command**: `python -m pauza.worker`
- Домен **не** генерируйте: воркеру не нужен вход из интернета.
- Pre-deploy и healthcheck не нужны.
- **Draining** (время между SIGTERM и SIGKILL): 30 секунд, чтобы воркер успел закончить текущую проверку и вернуть остальное в очередь.
- **Replicas**: для старта 1. При росте очереди добавляйте реплики; учитывайте лимит подключений из шага 1.5.

---

## 4. Первый запуск и проверка

1. Нажмите **Deploy** для `api`, затем для `worker`. В логах `api` должны появиться строки о миграциях `0001` и `0002`, `Опубликована версия правил 1.0.0` и `webhook установлен, команды обновлены`.
2. Откройте `https://<домен>/health/ready`: ответ 200.
3. Проверьте webhook в браузере: `https://api.telegram.org/bot<TOKEN>/getWebhookInfo`. Поле `url` должно указывать на `https://<домен>/webhooks/telegram`, `last_error_message` должно отсутствовать.
4. Напишите боту `/start`, затем перешлите тестовое сообщение вроде «Продиктуйте код из СМС». Должен прийти ответ «Высокий риск».
5. В логах `worker` найдите `check completed`. Текста сообщения в логах быть не должно, только коды индикаторов.

---

## 5. Справочник контактов Кыргызстана

Черновик лежит в `config/regions/KG.draft.json`. После ручной проверки каждого контакта:

1. Скопируйте его в `config/regions/KG.json`, у каждой записи проставьте `verified_at` (дата проверки) и `active: true`, при необходимости поправьте `source_url`.
2. Проверьте файл локально: `python -m pauza.cli validate-regions config/regions/KG.json`.
3. Закоммитьте файл, дождитесь деплоя и импортируйте его в базу из контейнера `api`:
   ```bash
   railway ssh --service api
   python -m pauza.cli import-regions config/regions/KG.json --author "Ваше имя"
   ```
   Импорт заменяет все записи региона и пишет событие в `audit_events`.

---

## 6. Обновления

- Каждый push в `main` запускает новый деплой обоих сервисов. Pre-deploy применяет миграции до выката кода, поэтому изменения схемы делайте по схеме expand/contract (см. README).
- Если менялись правила, сначала поднимите `RULESET_VERSION` и добавьте запись в `docs/RULES_CHANGELOG.md`. Иначе `publish-ruleset` остановит деплой с ошибкой «версия уже опубликована с другим содержимым».
- Смена секретов описана в `docs/RUNBOOK.md`, раздел «Подозрение на утечку секретов».

---

## 7. Частые проблемы

| Симптом | Причина и что делать |
|---|---|
| Pre-deploy падает на `alembic upgrade head` | Неверный `DATABASE_URL`: проверьте `postgresql+asyncpg://`, пользователя `postgres.<ref>`, порт `5432`, закодированный пароль и `?ssl=require` |
| `too many clients` / `max clients reached` | Превышен лимит пулера: уменьшите `DATABASE_POOL_SIZE`/`DATABASE_MAX_OVERFLOW` или число реплик (шаг 1.5) |
| `prepared statement ... does not exist` | Подключение идёт через порт `6543` без `DATABASE_POOL_MODE=transaction`. Используйте `5432` или добавьте переменную |
| Healthcheck не проходит | `/health/ready` возвращает 503, если недоступны БД или Redis. Проверьте `REDIS_URL=${{Redis.REDIS_URL}}` и `DATABASE_URL` |
| Приложение падает при старте с `ConfigError` | Не задана обязательная переменная, слабый секрет или `PUBLIC_BASE_URL` без `https://`. В сообщении указано имя переменной (без значения) |
| `getWebhookInfo` показывает `401 Unauthorized` | `TELEGRAM_WEBHOOK_SECRET` в Railway не совпадает с зарегистрированным. Сделайте повторный деплой `api` (pre-deploy снова вызовет `set-webhook`) |
| Скриншоты не распознаются (`OCR_FAILED`) | Проверьте в контейнере `tesseract --list-langs`: должны быть `rus` и `eng` |

Порт метрик `9100` наружу не публикуется. Для начала хватает встроенных графиков Railway (CPU, память) и логов. Подключение Prometheus и алертов из `docs/RUNBOOK.md` — следующий шаг.
