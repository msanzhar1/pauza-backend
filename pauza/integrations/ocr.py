"""Проверка изображений и OCR (разделы 5.3, 8.2).

Изображение проверяется по сигнатуре содержимого, декодируется с лимитом
пикселей, анимированные и HEIC отклоняются. OCR по умолчанию локальный
(Tesseract): изображение не покидает сервер.
"""

from __future__ import annotations

import asyncio
import io
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from PIL import Image, ImageOps, UnidentifiedImageError

from pauza.logs import get_logger

log = get_logger(__name__)

ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp"}
OCR_MAX_SIDE = 3000  # масштабирование перед OCR


class ImageRejected(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(code)
        self.code = code  # UNSUPPORTED_INPUT | INPUT_TOO_LARGE
        self.reason = reason  # ключ шаблона ответа


def sniff_mime(data: bytes) -> str | None:
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftyphevc", b"ftypavif"):
        return "image/heic"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    return None


def validate_image(data: bytes, max_bytes: int, max_pixels: int) -> Image.Image:
    if len(data) > max_bytes:
        raise ImageRejected("INPUT_TOO_LARGE", "image_too_large")
    mime = sniff_mime(data)
    if mime not in ALLOWED_MIME:
        raise ImageRejected("UNSUPPORTED_INPUT", "image_format")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            width, height = probe.size
            if width * height > max_pixels:
                raise ImageRejected("INPUT_TOO_LARGE", "image_too_many_pixels")
            if getattr(probe, "is_animated", False) or getattr(probe, "n_frames", 1) > 1:
                raise ImageRejected("UNSUPPORTED_INPUT", "image_animated")
            probe.verify()
        # verify() делает объект непригодным — открываем заново и декодируем.
        img = Image.open(io.BytesIO(data))
        img.load()
    except ImageRejected:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, Image.DecompressionBombError):
        raise ImageRejected("UNSUPPORTED_INPUT", "image_corrupted") from None
    img = ImageOps.exif_transpose(img)
    if max(img.size) > OCR_MAX_SIDE:
        img.thumbnail((OCR_MAX_SIDE, OCR_MAX_SIDE))
    return img.convert("L")


@dataclass(slots=True)
class OCRResult:
    text: str
    confident: bool
    mean_confidence: float | None = None

    def __repr__(self) -> str:
        return f"OCRResult(len={len(self.text)}, confident={self.confident})"


class OCRProvider(Protocol):
    name: str

    async def extract_text(self, image: Image.Image, options: dict | None = None) -> OCRResult: ...


class OCRUnavailable(Exception):
    pass


class DisabledOCR:
    name = "disabled"

    async def extract_text(self, image: Image.Image, options: dict | None = None) -> OCRResult:
        raise OCRUnavailable("ocr disabled")


class TesseractOCR:
    """Локальный OCR. Временный файл со случайным именем удаляется в finally."""

    name = "tesseract"

    def __init__(self, languages: str, temp_dir: str, min_confidence: float = 55.0, min_chars: int = 8) -> None:
        self.languages = languages
        self.temp_dir = Path(temp_dir)
        self.min_confidence = min_confidence
        self.min_chars = min_chars

    async def extract_text(self, image: Image.Image, options: dict | None = None) -> OCRResult:
        return await asyncio.to_thread(self._run, image)

    def _run(self, image: Image.Image) -> OCRResult:
        import pytesseract

        self.temp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.temp_dir / f"{secrets.token_hex(16)}.png"
        try:
            image.save(path, format="PNG")
            with Image.open(path) as img:
                data = pytesseract.image_to_data(img, lang=self.languages, output_type=pytesseract.Output.DICT)
        except pytesseract.TesseractNotFoundError:
            raise OCRUnavailable("tesseract not installed") from None
        except pytesseract.TesseractError:
            raise OCRUnavailable("tesseract error") from None
        finally:
            path.unlink(missing_ok=True)
        words, confs = [], []
        for word, conf in zip(data.get("text", []), data.get("conf", []), strict=False):
            try:
                c = float(conf)
            except (TypeError, ValueError):
                continue
            if word and word.strip() and c >= 0:
                words.append(word.strip())
                confs.append(c)
        text = " ".join(words)
        mean = sum(confs) / len(confs) if confs else None
        confident = bool(mean is not None and mean >= self.min_confidence and len(text) >= self.min_chars)
        return OCRResult(text=text, confident=confident, mean_confidence=mean)


def cleanup_temp_dir(temp_dir: str, max_age_seconds: int) -> int:
    """Периодический cleaner: удалить временные файлы старше TTL (на случай аварий)."""
    removed = 0
    root = Path(temp_dir)
    if not root.exists():
        return 0
    now = time.time()
    for p in root.iterdir():
        try:
            if p.is_file() and now - p.stat().st_mtime > max_age_seconds:
                p.unlink(missing_ok=True)
                removed += 1
        except OSError:
            continue
    return removed


def build_ocr(provider: str, languages: str, temp_dir: str) -> OCRProvider:
    if provider == "tesseract":
        return TesseractOCR(languages, temp_dir)
    return DisabledOCR()


__all__ = [
    "ALLOWED_MIME", "DisabledOCR", "ImageRejected", "OCRProvider", "OCRResult", "OCRUnavailable",
    "TesseractOCR", "build_ocr", "cleanup_temp_dir", "sniff_mime", "validate_image",
]
