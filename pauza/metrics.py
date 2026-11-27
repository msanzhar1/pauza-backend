"""Prometheus-метрики. Метки — только низкокардинальные технические значения,
никаких идентификаторов пользователей и содержимого."""

from prometheus_client import Counter, Gauge, Histogram

UPDATES = Counter("pauza_updates_total", "Telegram updates received by webhook", ["kind", "result"])
CHECKS = Counter("pauza_checks_total", "Completed checks", ["input_type", "risk_level"])
CHECK_ERRORS = Counter("pauza_check_errors_total", "Check errors by code", ["error_code"])
RATE_LIMITED = Counter("pauza_rate_limited_total", "Rate limit events", ["scope"])
FEEDBACK = Counter("pauza_feedback_total", "Feedback button presses", ["feedback_type"])
PROVIDER_ERRORS = Counter("pauza_provider_errors_total", "External provider errors", ["provider"])
TELEGRAM_SEND_FAILED = Counter("pauza_telegram_send_failed_total", "Messages not delivered after retries")
DUPLICATE_UPDATES = Counter("pauza_duplicate_updates_total", "Redelivered updates ignored")

LATENCY = Histogram(
    "pauza_stage_seconds",
    "Latency by stage",
    ["stage"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 15, 20, 30, 60),
)
QUEUE_DEPTH = Gauge("pauza_queue_depth", "Updates waiting in queue")
