"""Нормализация входного текста (InputNormalizer).

`NormalizedInput` живёт только в памяти воркера: не логируется и не сохраняется.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Невидимые символы, которыми прячут ключевые слова: «к​од».
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍⁠﻿­᠎⁡⁢⁣⁤"), None
)

# Латинские буквы, похожие на кириллические. Применяется только к копии текста
# для сопоставления правил («кoд» с латинской «o» → «код»).
_LATIN_TO_CYR = str.maketrans(
    {
        "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у",
        "k": "к", "m": "м", "t": "т", "h": "н", "b": "в", "3": "з",
    }
)
_WORD_RE = re.compile(r"\w+", re.UNICODE)
_CYR_RE = re.compile(r"[а-яё]")
_WS_RE = re.compile(r"\s+")


@dataclass(slots=True)
class NormalizedInput:
    original_length: int
    text: str  # NFKC, без невидимых символов, свёрнутые пробелы, исходный регистр
    match_text: str  # нижний регистр, ё→е, латинские двойники в кириллических словах заменены
    truncated: bool = False
    extra: dict[str, object] = field(default_factory=dict)

    def __repr__(self) -> str:  # защита от случайного логирования содержимого
        return f"NormalizedInput(len={len(self.text)}, truncated={self.truncated})"


def _fix_mixed_word(word: str) -> str:
    # Заменяем латинские двойники, только если в слове уже есть кириллица,
    # чтобы не портить URL и английский текст.
    if _CYR_RE.search(word) and re.search(r"[a-z3]", word):
        return word.translate(_LATIN_TO_CYR)
    return word


def normalize(raw: str, max_length: int) -> NormalizedInput:
    original_length = len(raw)
    text = unicodedata.normalize("NFKC", raw).translate(_INVISIBLE)
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")
    text = _WS_RE.sub(" ", text).strip()
    truncated = len(text) > max_length
    if truncated:
        text = text[:max_length]
    lowered = text.lower().replace("ё", "е")
    match_text = _WORD_RE.sub(lambda m: _fix_mixed_word(m.group(0)), lowered)
    return NormalizedInput(original_length=original_length, text=text, match_text=match_text, truncated=truncated)
