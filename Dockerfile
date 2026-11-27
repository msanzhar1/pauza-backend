FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# Локальный OCR: изображения не покидают сервер.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-rus tesseract-ocr-eng \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 pauza
WORKDIR /app

COPY pyproject.toml ./
COPY pauza ./pauza
RUN pip install .

COPY alembic.ini ./
COPY migrations ./migrations
COPY config ./config

# Временные файлы OCR — вне web root, только для пользователя приложения.
RUN mkdir -p /tmp/pauza && chown pauza:pauza /tmp/pauza && chmod 700 /tmp/pauza
USER pauza

EXPOSE 8000 9100
# Процесс выбирается командой: api | worker | migrate (см. docker-compose.yml)
CMD ["uvicorn", "pauza.api:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
