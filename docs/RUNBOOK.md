# Runbook

Общий принцип: при любом сбое пользователь получает нейтральное сообщение и никогда не получает ложное «явных признаков не найдено». Логи — JSON без содержимого; ищите по `correlation_id`, `update_ref`, `error_code`, `component`.

## Рекомендуемые алерты

| Алерт | Условие (стартовые пороги) |
|---|---|
| Webhook 5xx | `pauza_updates_total{result="enqueue_failed"}` > 0 за 5 мин |
| Растёт очередь | `pauza_queue_depth` > 500 или растёт 10 мин подряд |
| Массовые ошибки Telegram | `rate(pauza_telegram_send_failed_total[5m])` > 1/мин |
| БД/Redis недоступны | `/health/ready` ≠ 200 дольше 1 мин |
| OCR сбоит | `rate(pauza_provider_errors_total{provider="ocr"}[5m])` растёт или `pauza_check_errors_total{error_code="OCR_FAILED"}` > 20% проверок изображений |
| Таймауты анализа | `pauza_check_errors_total{error_code="ANALYSIS_TIMEOUT"}` > 0 |
| Диск / временные файлы | заполнение диска > 80%; в логах `removed stale temp files` |

## Telegram API недоступен

Симптомы: `telegram call failed`, рост `pauza_telegram_send_failed_total`.
1. Проверить статус Telegram и сетевой доступ к `api.telegram.org` с воркеров.
2. Клиент сам повторяет с backoff и учитывает `retry_after`; ответ старше `TELEGRAM_MAX_MESSAGE_AGE_SECONDS` не досылается (запись проверки получает `error_code=TELEGRAM_SEND_FAILED`).
3. Если входящие webhook не приходят: `python -m pauza.cli set-webhook`, затем `getWebhookInfo` вручную.

## Очередь (Redis) недоступна

Симптомы: webhook отвечает 503, `/health/ready` = 503.
1. Telegram сам повторяет доставку при 5xx — данные не теряются, пока Redis восстанавливается (Telegram хранит Update до 24 часов).
2. Восстановить Redis. Персистентность не нужна: idempotency keys потеряются, но повторная проверка того же Update блокируется уникальным `checks.telegram_update_id` в БД (команды в этом случае могут получить ответ повторно).
3. Задания в очереди старше `TEMP_DATA_TTL_SECONDS` будут отброшены (счётчик `pauza:queue:expired_count`).

## Очередь растёт

1. Проверить, живы ли воркеры (логи `worker started`, ключи `pauza:worker:hb:*`).
2. Масштабировать воркеры. Задания упавших воркеров возвращаются в очередь автоматически (reaper раз в минуту).
3. Если узкое место — OCR: увеличить число воркеров или временно `OCR_PROVIDER=disabled` (пользователи получат просьбу вставить текст).

## БД недоступна

Симптомы: `job failed` с `INTERNAL_ERROR`, `/health/ready` = 503.
1. Задания возвращаются в очередь до `JOB_MAX_ATTEMPTS` раз, затем отбрасываются (счётчик `pauza:queue:dead_count`).
2. Восстановить БД. Миграции не запускать до восстановления.

## OCR не работает

Симптомы: `OCR_FAILED`, рост `pauza_provider_errors_total{provider="ocr"}`.
1. Проверить, что в образе есть `tesseract` и языки `rus`, `eng` (`tesseract --list-langs`).
2. Проверить свободное место и права на `TEMP_DIR`.
3. Пользователи в это время получают просьбу вставить текст вручную — базовый бот работает.

## Внешние провайдеры (LLM, репутация URL)

В MVP выключены. Если включены и сбоят: бот продолжает работать по правилам и шаблонам. Отключить без простоя: `LLM_ENABLED=false` / `URL_REPUTATION_ENABLED=false` и перезапуск воркеров.

## Подозрение на утечку секретов

- `TELEGRAM_BOT_TOKEN`: перевыпустить у @BotFather, обновить секрет, `set-webhook`.
- `TELEGRAM_WEBHOOK_SECRET`: сменить, перезапустить API, `set-webhook`.
- `CALLBACK_SIGNING_KEY`: сменить; старые кнопки перестанут работать (пользователь увидит «Кнопка устарела»).
- `QUEUE_ENCRYPTION_KEY`: сменить при пустой очереди; задания, зашифрованные старым ключом, будут отброшены.
- `ID_HASH_KEY`: смена отвязывает всех пользователей от настроек. Менять только при компрометации.

## Запрос на удаление данных

Пользователь делает это сам через `/delete_me`. Удаляются строка `users`, все его `checks` и `feedback`, состояния и счётчики rate limit в Redis. Остаются только агрегированные метрики Prometheus без идентификаторов.
