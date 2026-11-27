"""Извлечение и статический анализ URL (UrlAnalyzer).

Никаких сетевых запросов: URL не открывается, DNS не резолвится. Это
требование раздела 5.2 ТЗ (защита от SSRF и загрузки вредоносного контента).
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# Распространённые TLD для поиска «голых» доменов без схемы (example.ru).
_COMMON_TLDS = (
    "ru|su|рф|com|net|org|info|biz|io|me|app|xyz|top|online|site|shop|store|club|live|pro|link|click|"
    "kz|by|uz|kg|tj|am|az|ge|ua|md|de|uk|us|eu|co|cc|tk|ml|ga|cf|gq|pw|ws|tv|icu|vip|win|bid|"
    "best|support|help|services|digital|today|world|space|website|fun|cyou|buzz|rest|sbs|cfd|"
    "gov|edu|int|travel|money|bank|finance|cash|tech|ly|gl|gd|to|im|la"
)
_SCHEME_URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?|ftp)://[^\s<>\"'«»]+")
_WWW_RE = re.compile(r"(?i)\bwww\.[^\s<>\"'«»]+")
_BARE_RE = re.compile(
    rf"(?i)(?<![@\w.-])(?:[\w-]{{1,63}}\.)+(?:{_COMMON_TLDS})(?![\w-])(?:[/?#][^\s<>\"'«»]*)?"
)
_TRAILING_PUNCT = ".,;:!?)]}'\"»…"

SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
        "clck.ru", "vk.cc", "u.to", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "qps.ru", "bit.do",
        "lnkd.in", "t.ly", "v.gd", "surl.li", "goo.su", "inlnk.ru",
    }
)
SUSPICIOUS_TLDS = frozenset(
    {"xyz", "top", "click", "icu", "tk", "ml", "ga", "cf", "gq", "pw", "cyou", "buzz", "rest", "sbs", "cfd", "win", "bid", "vip"}
)
# Двухуровневые публичные суффиксы, после которых регистрируемый домен — 3 метки.
_SECOND_LEVEL_SUFFIXES = frozenset(
    {"co.uk", "org.uk", "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "com.kz", "org.kz",
     "com.ua", "co.jp", "com.au", "com.br", "com.tr", "com.cn", "gov.ru", "edu.ru"}
)


@dataclass(slots=True)
class UrlFinding:
    display: str  # безопасное отображение: только хост, «обезвреженный» и укороченный
    host: str
    signals: list[str] = field(default_factory=list)  # коды признаков
    strong: bool = False


@dataclass(slots=True)
class UrlFindings:
    items: list[UrlFinding] = field(default_factory=list)
    total_found: int = 0
    truncated: bool = False
    reputation_checked: bool = False

    @property
    def suspicious(self) -> list[UrlFinding]:
        return [f for f in self.items if f.signals]

    @property
    def any_strong(self) -> bool:
        return any(f.strong for f in self.items)


STRONG_SIGNALS = frozenset(
    {"IP_HOST", "USERINFO_MASKING", "LOOKALIKE_OFFICIAL", "MIXED_SCRIPT", "BRAND_IN_UNOFFICIAL", "REPUTATION_LISTED"}
)


def extract_urls(text: str) -> list[str]:
    found: list[tuple[int, str]] = []
    taken: list[tuple[int, int]] = []

    def _add(m: re.Match[str]) -> None:
        start, end = m.span()
        if any(s <= start < e for s, e in taken):
            return
        value = m.group(0).rstrip(_TRAILING_PUNCT)
        if not value:
            return
        taken.append((start, start + len(value)))
        found.append((start, value))

    for regex in (_SCHEME_URL_RE, _WWW_RE, _BARE_RE):
        for m in regex.finditer(text):
            _add(m)
    found.sort()
    seen: set[str] = set()
    result = []
    for _, url in found:
        key = url.lower()
        if key not in seen:
            seen.add(key)
            result.append(url)
    return result


def registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def defang(host: str) -> str:
    """example.com → example[.]com, чтобы Telegram не сделал ссылку кликабельной."""
    return host.replace(".", "[.]")


def _levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONFUSABLE_DIGITS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def _scripts(s: str) -> set[str]:
    result = set()
    for ch in s:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            result.add(name.split(" ")[0])
    return result


class OfficialDomains:
    """Настраиваемый список официальных доменов для поиска похожих (lookalike)."""

    def __init__(self, domains: dict[str, list[str]] | None = None) -> None:
        # brand -> список официальных регистрируемых доменов
        self.brands: dict[str, list[str]] = {k.lower(): [d.lower() for d in v] for k, v in (domains or {}).items()}
        self.all_domains = {d for v in self.brands.values() for d in v}

    @classmethod
    def load(cls, path: str | Path) -> OfficialDomains:
        p = Path(path)
        if not p.exists():
            return cls({})
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(data.get("brands", {}))


class UrlAnalyzer:
    def __init__(self, official: OfficialDomains, max_urls: int = 10) -> None:
        self.official = official
        self.max_urls = max_urls

    def analyze(self, urls: list[str]) -> UrlFindings:
        findings = UrlFindings(total_found=len(urls), truncated=len(urls) > self.max_urls)
        for raw in urls[: self.max_urls]:
            findings.items.append(self._analyze_one(raw))
        return findings

    def _analyze_one(self, raw: str) -> UrlFinding:
        signals: list[str] = []
        value = raw.strip()
        lowered = value.lower()
        if lowered.startswith(("hxxp://", "hxxps://")):
            value = "http" + value[4:]
        if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", value):
            value = "http://" + value
            scheme_given = False
        else:
            scheme_given = True
        try:
            parts = urlsplit(value)
            host = (parts.hostname or "").rstrip(".")
            port = parts.port
        except ValueError:
            return UrlFinding(display="[некорректная ссылка]", host="", signals=["MALFORMED"], strong=True)

        if parts.username is not None or "@" in (parts.netloc or ""):
            signals.append("USERINFO_MASKING")
        if scheme_given and parts.scheme == "http":
            signals.append("NO_TLS")
        if port not in (None, 80, 443):
            signals.append("NONSTANDARD_PORT")

        ascii_host = host
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            pass
        if not is_ip and re.fullmatch(r"\d+", host or ""):
            is_ip = True  # десятичная запись IP: http://3232235777
        if is_ip:
            signals.append("IP_HOST")
        else:
            try:
                ascii_host = host.encode("idna").decode("ascii") if host else host
            except UnicodeError:
                ascii_host = host
            unicode_host = host
            if "xn--" in ascii_host:
                try:
                    unicode_host = ascii_host.encode("ascii").decode("idna")
                except UnicodeError:
                    unicode_host = host
            if "xn--" in ascii_host or any(ord(c) > 127 for c in host):
                labels = [lbl for lbl in unicode_host.split(".") if lbl]
                # Смешение алфавитов внутри одной метки — типичная маскировка (раураl.com).
                if any(len(_scripts(lbl)) > 1 for lbl in labels):
                    signals.append("MIXED_SCRIPT")
                elif not unicode_host.endswith(("рф", "рус", "москва", "дети", "онлайн", "сайт", "орг", "қаз", "бел", "укр")):
                    signals.append("PUNYCODE")
            reg = registrable_domain(ascii_host)
            if reg in SHORTENERS or ascii_host in SHORTENERS:
                signals.append("SHORTENER")
            tld = ascii_host.rsplit(".", 1)[-1] if "." in ascii_host else ""
            if tld in SUSPICIOUS_TLDS:
                signals.append("SUSPICIOUS_TLD")
            if ascii_host.count(".") >= 4 or len(ascii_host) > 60:
                signals.append("DEEP_SUBDOMAINS")
            signals.extend(self._official_checks(ascii_host, reg))

        display_host = host or "?"
        display = defang(display_host if len(display_host) <= 60 else "…" + display_host[-57:])
        strong = any(s in STRONG_SIGNALS for s in signals)
        # Без схемы и с одним NO_TLS не считаем подозрительным.
        return UrlFinding(display=display, host=ascii_host, signals=signals, strong=strong)

    def _official_checks(self, host: str, reg: str) -> list[str]:
        if not self.official.brands or reg in self.official.all_domains:
            return []
        out: list[str] = []
        reg_label = reg.split(".")[0]
        reg_norm = reg_label.translate(_CONFUSABLE_DIGITS)
        for brand, domains in self.official.brands.items():
            for official in domains:
                off_label = official.split(".")[0]
                if len(off_label) >= 4 and (
                    _levenshtein(reg_label, off_label) <= (1 if len(off_label) < 7 else 2)
                    or reg_norm == off_label
                ):
                    out.append("LOOKALIKE_OFFICIAL")
                    return out
            # Бренд в поддомене или в составном домене: brand-support.xyz, brand.secure-login.com
            if len(brand) >= 4 and re.search(rf"(?:^|[.-]){re.escape(brand)}(?:$|[.-])", host):
                out.append("BRAND_IN_UNOFFICIAL")
                return out
        return out
