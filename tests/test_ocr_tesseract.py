"""Интеграционный тест локального OCR. Пропускается, если Tesseract не установлен."""

import glob
import shutil

import pytest
from PIL import Image, ImageDraw, ImageFont

from pauza.integrations.ocr import TesseractOCR, validate_image

FONTS = glob.glob("/usr/share/fonts/**/DejaVuSans.ttf", recursive=True) + glob.glob("/usr/share/fonts/**/LiberationSans-Regular.ttf", recursive=True)
pytestmark = pytest.mark.skipif(not shutil.which("tesseract") or not FONTS, reason="tesseract или шрифт не установлены")


async def test_tesseract_reads_russian_and_cleans_temp(tmp_path):
    import io

    img = Image.new("RGB", (1000, 140), "white")
    ImageDraw.Draw(img).text((20, 40), "Продиктуйте код из СМС", fill="black", font=ImageFont.truetype(FONTS[0], 48))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    ocr = TesseractOCR("rus+eng", str(tmp_path))
    result = await ocr.extract_text(validate_image(buf.getvalue(), 10_000_000, 20_000_000))
    assert "код" in result.text.lower()
    assert result.confident
    assert list(tmp_path.iterdir()) == []  # временный файл удалён
