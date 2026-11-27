import httpx
import pytest
import respx

from pauza.analysis.normalize import normalize
from pauza.analysis.urls import OfficialDomains, UrlAnalyzer, defang, extract_urls, registrable_domain

official = OfficialDomains({"telegram": ["telegram.org"], "paypal": ["paypal.com"]})
analyzer = UrlAnalyzer(official, max_urls=10)


def signals(url: str) -> list[str]:
    return analyzer.analyze([url]).items[0].signals


def test_normalize_strips_invisible_and_homoglyphs():
    n = normalize("Сообщите к​oд", 100)
    assert n.match_text == "сообщите код"
    assert n.text == "Сообщите koд".replace("k", "к")


def test_normalize_keeps_latin_words():
    n = normalize("Send CODE now", 100)
    assert n.match_text == "send code now"


def test_normalize_truncates():
    n = normalize("а" * 50, 10)
    assert n.truncated and len(n.text) == 10


def test_normalize_repr_hides_content():
    assert "секрет" not in repr(normalize("секрет", 100))


def test_extract_urls_variants():
    text = "см. https://a.example.com/x?y=1, www.test.ru и просто bank-help.xyz. И ещё t.me/name"
    assert extract_urls(text) == ["https://a.example.com/x?y=1", "www.test.ru", "bank-help.xyz", "t.me/name"]


def test_extract_urls_ignores_abbreviations():
    assert extract_urls("т.е. и т.д., e.g. это") == []


def test_extract_urls_dedup():
    assert extract_urls("bit.ly/a bit.ly/a") == ["bit.ly/a"]


def test_url_limit():
    found = analyzer.analyze([f"site{i}.ru" for i in range(15)])
    assert len(found.items) == 10 and found.truncated and found.total_found == 15


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://192.168.0.1/login", "IP_HOST"),
        ("http://3232235521/", "IP_HOST"),
        ("https://telegram.org@evil.example/", "USERINFO_MASKING"),
        ("https://telegrarn.org", "LOOKALIKE_OFFICIAL"),
        ("https://paypa1.com", "LOOKALIKE_OFFICIAL"),
        ("https://xn--pypal-4ve.com", "MIXED_SCRIPT"),
        ("https://раураl.com", "MIXED_SCRIPT"),
        ("https://telegram-support.top", "BRAND_IN_UNOFFICIAL"),
        ("https://bit.ly/abc", "SHORTENER"),
        ("https://a.b.c.d.e.example.com", "DEEP_SUBDOMAINS"),
        ("https://example.com:8443/x", "NONSTANDARD_PORT"),
    ],
)
def test_url_signals(url, expected):
    assert expected in signals(url)


def test_official_domain_is_clean():
    assert signals("https://telegram.org/blog") == []
    assert signals("https://core.telegram.org") == []


def test_cyrillic_tld_not_flagged():
    assert "PUNYCODE" not in signals("https://пример.рф")


def test_display_is_defanged_and_short():
    item = analyzer.analyze(["https://" + "a" * 80 + ".com/path?token=secret"]).items[0]
    assert "[.]" in item.display and "token" not in item.display and len(item.display) <= 70


def test_registrable_domain():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("login.example.com") == "example.com"
    assert defang("a.b") == "a[.]b"


@respx.mock(assert_all_mocked=True)
async def test_url_analysis_makes_no_network_requests():
    """SSRF: анализ URL не делает HTTP-запросов (любой запрос упал бы в respx)."""
    from pauza.analysis.rules import RuleEngine
    from pauza.analysis.service import Analyzer

    a = Analyzer(analyzer, RuleEngine(), 10_000)
    await a.analyze_text("http://169.254.169.254/latest/meta-data http://localhost:6379 https://evil.example")
    assert respx.calls.call_count == 0
    with pytest.raises(respx.models.AllMockedAssertionError):
        async with httpx.AsyncClient() as c:  # контроль: сеть действительно перехвачена
            await c.get("http://169.254.169.254/")
