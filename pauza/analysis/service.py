"""Анализ: нормализация → URL → правила → (опционально репутация и LLM) → результат.

Структура результата соответствует разделу 7.2 ТЗ.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from pauza.analysis.normalize import NormalizedInput, normalize
from pauza.analysis.rules import RULESET_VERSION, RuleEngine, RuleResult
from pauza.analysis.urls import UrlAnalyzer, UrlFindings, extract_urls
from pauza.db.models import RiskLevel
from pauza.integrations.llm import LLMExplainer, merge_with_rules
from pauza.integrations.reputation import UrlReputationProvider
from pauza.logs import get_logger

log = get_logger(__name__)

SUMMARY = {
    RiskLevel.HIGH: "Обнаружены сильные признаки мошенничества. Ничего не переводите и не сообщайте, пока не проверите информацию сами.",
    RiskLevel.ELEVATED: "Есть подозрительные признаки. Прежде чем что-то делать, проверьте информацию через официальный канал.",
    RiskLevel.NO_CLEAR_SIGNAL: "Известных признаков мошенничества не найдено. Это не значит, что сообщение безопасно: бот видит не все схемы.",
}

ACTIONS = {
    RiskLevel.HIGH: [
        "Не переводите деньги и не сообщайте коды, пароли и данные карты.",
        "Свяжитесь с организацией сами: по номеру с её официального сайта или с обратной стороны карты.",
    ],
    RiskLevel.ELEVATED: [
        "Не спешите и не переходите по ссылкам из сообщения.",
        "Проверьте информацию, позвонив в организацию по номеру, который нашли сами.",
    ],
    RiskLevel.NO_CLEAR_SIGNAL: [
        "Если вас просят о деньгах или данных, всё равно проверьте отправителя через официальный канал.",
    ],
}
URL_ACTION = "Не открывайте ссылки из сообщения. Наберите адрес сайта вручную или используйте официальное приложение."

DISCLAIMER = "Оценка автоматическая и может ошибаться. Бот не подтверждает подлинность отправителя или сайта."


@dataclass(slots=True)
class IndicatorOut:
    code: str
    label: str
    explanation: str


@dataclass(slots=True)
class AnalysisResult:
    risk_level: RiskLevel
    summary: str
    indicators: list[IndicatorOut]
    recommended_actions: list[str]
    detected_urls: list[str]
    disclaimer: str
    analysis_version: str
    urls_truncated: bool = False
    input_truncated: bool = False
    all_indicator_codes: list[str] = field(default_factory=list)


class Analyzer:
    def __init__(
        self,
        url_analyzer: UrlAnalyzer,
        rule_engine: RuleEngine,
        max_text_length: int,
        reputation: UrlReputationProvider | None = None,
        llm: LLMExplainer | None = None,
        components: str = "",
    ) -> None:
        self.url_analyzer = url_analyzer
        self.rule_engine = rule_engine
        self.max_text_length = max_text_length
        self.reputation = reputation
        self.llm = llm
        self.components = components

    @property
    def version(self) -> str:
        return f"rules={RULESET_VERSION};{self.components}" if self.components else f"rules={RULESET_VERSION}"

    async def analyze_text(self, raw_text: str) -> AnalysisResult:
        normalized = normalize(raw_text, self.max_text_length)
        urls = extract_urls(normalized.text)
        findings = self.url_analyzer.analyze(urls)
        if self.reputation is not None and findings.items:
            await self._apply_reputation(findings)
        rule_result = self.rule_engine.evaluate(normalized, findings)
        result = self._build(rule_result, findings, normalized)
        if self.llm is not None:
            result = await self._apply_llm(result, normalized)
        return result

    async def _apply_reputation(self, findings: UrlFindings) -> None:
        assert self.reputation is not None
        try:
            # Провайдеру передаются только хосты, без текста сообщения.
            hosts = [f.host for f in findings.items if f.host]
            listed = await asyncio.wait_for(self.reputation.check_hosts(hosts), timeout=self.reputation.timeout)
            for f in findings.items:
                if f.host in listed:
                    f.signals.append("REPUTATION_LISTED")
                    f.strong = True
            findings.reputation_checked = True
        except Exception as exc:  # сбой провайдера не блокирует базовую проверку
            log.warning("reputation provider failed", extra={"component": "reputation", "error_code": "PROVIDER_UNAVAILABLE", "provider": type(exc).__name__})

    async def _apply_llm(self, result: AnalysisResult, normalized: NormalizedInput) -> AnalysisResult:
        assert self.llm is not None
        try:
            suggestion = await asyncio.wait_for(
                self.llm.explain(normalized.text[:2000], [i.code for i in result.indicators]),
                timeout=self.llm.timeout,
            )
        except Exception as exc:
            log.warning("llm failed", extra={"component": "llm", "error_code": "PROVIDER_UNAVAILABLE", "provider": type(exc).__name__})
            return result
        return merge_with_rules(result, suggestion)

    def _build(self, rr: RuleResult, findings: UrlFindings, normalized: NormalizedInput) -> AnalysisResult:
        indicators = [IndicatorOut(i.code, i.label, i.explanation) for i in rr.indicators[:3]]
        actions = list(ACTIONS[rr.risk_level])
        if findings.items and rr.risk_level != RiskLevel.NO_CLEAR_SIGNAL:
            actions = [actions[0], URL_ACTION]
        detected = []
        for f in findings.items:
            detected.append(f.display)
        return AnalysisResult(
            risk_level=rr.risk_level,
            summary=SUMMARY[rr.risk_level][:300],
            indicators=indicators,
            recommended_actions=actions[:2],
            detected_urls=detected,
            disclaimer=DISCLAIMER,
            analysis_version=self.version,
            urls_truncated=findings.truncated,
            input_truncated=normalized.truncated,
            all_indicator_codes=rr.codes,
        )
