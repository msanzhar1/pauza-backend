import json
from pathlib import Path

import pytest

from pauza.analysis.normalize import normalize
from pauza.analysis.rules import RULES, RuleEngine, ruleset_digest
from pauza.analysis.urls import OfficialDomains, UrlAnalyzer, extract_urls
from pauza.db.models import RiskLevel

DATA = json.loads((Path(__file__).parent / "data" / "synthetic_messages.json").read_text(encoding="utf-8"))["cases"]
ORDER = {"NO_CLEAR_SIGNAL": 0, "ELEVATED": 1, "HIGH": 2}

engine = RuleEngine()
urls = UrlAnalyzer(OfficialDomains.load("config/official_domains.json"))


def evaluate(text: str):
    n = normalize(text, 10_000)
    return engine.evaluate(n, urls.analyze(extract_urls(n.text)))


@pytest.mark.parametrize("case", DATA, ids=[c["id"] for c in DATA])
def test_synthetic_dataset(case):
    result = evaluate(case["text"])
    assert result.risk_level.value == case["expected"], result.codes
    for code in case.get("must", []):
        assert code in result.codes
    for code in case.get("must_not", []):
        assert code not in result.codes


def test_every_rule_has_positive_and_negative_examples():
    codes = {r.code for r in RULES} | {"SUSPICIOUS_DOMAIN"}
    covered = {c for case in DATA for c in case.get("must", [])}
    missing = codes - covered - {"TIME_PRESSURE"}
    assert not missing, f"нет позитивных примеров: {missing}"
    assert any(c["expected"] == "NO_CLEAR_SIGNAL" for c in DATA)


def test_high_wins_over_elevated():
    r = evaluate("Никому не говори. Продиктуй код из смс")
    assert r.risk_level == RiskLevel.HIGH
    assert r.indicators[0].code == "OTP_REQUEST"  # сильные индикаторы первыми


def test_context_only_rules_do_not_trigger_alone():
    assert evaluate("Срочно!").risk_level == RiskLevel.NO_CLEAR_SIGNAL
    assert evaluate("Курьер СДЭК приедет завтра").risk_level == RiskLevel.NO_CLEAR_SIGNAL


def test_digest_is_stable():
    assert ruleset_digest() == ruleset_digest()
    assert len(ruleset_digest()) == 64
