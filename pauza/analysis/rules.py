"""Версионируемый набор правил (RuleEngine).

Изменение любого правила требует:
1. увеличить RULESET_VERSION;
2. добавить запись в docs/RULES_CHANGELOG.md;
3. опубликовать версию в БД: `python -m pauza.cli publish-ruleset --author ... --description ...`
   (пишется в rule_versions и audit_events).

Уровень риска определяется только правилами. Необязательный LLM-слой не может
понизить его (см. pauza.integrations.llm.merge_with_rules).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from pauza.analysis.normalize import NormalizedInput
from pauza.analysis.urls import UrlFindings
from pauza.db.models import RiskLevel

RULESET_VERSION = "1.0.0"

_SEVERITY_ORDER = {RiskLevel.HIGH: 2, RiskLevel.ELEVATED: 1, RiskLevel.NO_CLEAR_SIGNAL: 0}


def max_level(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda lv: _SEVERITY_ORDER[lv])


@dataclass(frozen=True, slots=True)
class Rule:
    code: str
    severity: RiskLevel
    label: str
    explanation: str
    patterns: tuple[str, ...]
    # Фразы, при которых совпадение рядом (±window символов) не засчитывается:
    # например, легитимное «никому не сообщайте код».
    suppressors: tuple[str, ...] = ()
    # Дополнительно должно найтись хотя бы одно из этих выражений в тексте.
    requires_any: tuple[str, ...] = ()
    # Индикатор учитывается, только если найден ещё какой-то индикатор.
    context_only: bool = False
    priority: int = 50
    window: int = 60

    def compiled(self) -> _CompiledRule:
        return _CompiledRule(
            self,
            tuple(re.compile(p) for p in self.patterns),
            tuple(re.compile(p) for p in self.suppressors),
            tuple(re.compile(p) for p in self.requires_any),
        )


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    rule: Rule
    patterns: tuple[re.Pattern[str], ...]
    suppressors: tuple[re.Pattern[str], ...]
    requires_any: tuple[re.Pattern[str], ...]

    def matches(self, text: str) -> bool:
        if self.requires_any and not any(r.search(text) for r in self.requires_any):
            return False
        for pattern in self.patterns:
            for m in pattern.finditer(text):
                lo = max(0, m.start() - self.rule.window)
                hi = min(len(text), m.end() + self.rule.window)
                ctx = text[lo:hi]
                if not any(s.search(ctx) for s in self.suppressors):
                    return True
        return False


# --- Общие фрагменты (текст уже в нижнем регистре, ё → е) ------------------
_GAP = r"[^.!?\n]{0,40}?"  # до 40 символов в пределах предложения
_ASK_VERB = (
    r"(?:сообщ|назов|назва|продикт|диктуй|скаж|сказа|отправ|пришл|присла|перешл|пересла|скин|напиш|написа|"
    r"подскаж|подсказа|зачита|озвуч|продублир|дай|дайте|нужен|нужно|send|tell|share|give|read)\w*"
)
_CODE_WORD = r"(?:\bкод\w*|\bцифр\w*|\bsms\b|\bсмс\b|\bone[- ]time\b|\botp\b|\bcode\b)"
# Легитимные предупреждения: «никому не сообщайте код», «банк никогда не просит пароль».
_NEVER_SHARE = (
    r"(?:никому\s+не|никогда\s+не|\bне)\s+(?:сообща|говор|переда|называ|назов|диктуй|диктов|пересыла|показыва|"
    r"просим|просят|просит|запрашива|спрашива|требу|звон)\w*[^.!?\n]{0,60}?"
    r"(?:\bкод|парол|данн|cvv|cvc|\bпин|seed|сид|реквизит|карт)|"
    r"(?:do\s+not|don't|never)\s+(?:share|tell|give|ask)"
)
_PAY_VERB = (
    r"(?:перевед\w*|перевест\w*|перевод\w*|переведи\w*|оплат\w*|заплат\w*|перечисл\w*|внес\w*|внест\w*|"
    r"пополн\w*|отправ\w*\s+(?:деньги|средства|сумму)|скин\w*\s+(?:деньги|\d+)|закин\w*|положи\w*\s+на|"
    r"\bpay\b|\bsend\s+money\b|\bwire\b|\btransfer\b)"
)
_URGENCY = (
    r"(?:\bсрочн\w*|немедленн\w*|сейчас\s+же|прямо\s+сейчас|как\s+можно\s+скорее|в\s+течени[ея]\s+\d*\s*(?:минут|час)\w*|"
    r"сегодня\s+до|до\s+конца\s+дня|последн\w+\s+(?:день|шанс|предупреждени)|иначе\s+(?:\w+\s+){0,3}(?:заблок|спиш|арест|штраф|потеря)|"
    r"будет\s+заблокир\w*|заблокирую?т|аннулир\w*|осталось\s+\d+\s+(?:минут|час)|\burgent\w*|\bimmediately\b|\basap\b)"
)
_SAFE_ACCOUNT = r"(?:безопасн\w*|защищенн\w*|резервн\w*|специальн\w*|страхов\w*)\s+(?:сч[её]т|ячейк)\w*"

RULES: tuple[Rule, ...] = (
    Rule(
        code="OTP_REQUEST",
        severity=RiskLevel.HIGH,
        label="Просят одноразовый код",
        explanation="В сообщении просят сообщить код из СМС или приложения. Такой код подтверждает операцию от вашего имени, и настоящие банки и службы его не спрашивают.",
        patterns=(
            rf"{_ASK_VERB}{_GAP}{_CODE_WORD}",
            rf"{_CODE_WORD}{_GAP}\b{_ASK_VERB}",
            r"какой\s+(?:вам\s+|тебе\s+)?(?:пришел\s+)?код|(?:пришел|пришел\s+ли)\s+(?:ли\s+)?(?:вам\s+|тебе\s+)?код",
        ),
        suppressors=(_NEVER_SHARE, r"\bпромокод\w*|штрих-?код|почтов\w+\s+индекс|код\s+товара|qr-?код|исходн\w+\s+код"),
        priority=100,
        window=50,
    ),
    Rule(
        code="CREDENTIAL_REQUEST",
        severity=RiskLevel.HIGH,
        label="Просят пароль или секретные данные",
        explanation="Просят пароль, PIN, CVV, seed-фразу или секретный ключ. Эти данные дают полный доступ к деньгам и аккаунтам.",
        patterns=(
            rf"(?:{_ASK_VERB}|введ\w*|укаж\w*|вставь\w*|подтверд\w*){_GAP}(?:\bпарол\w*|\bpin\b|\bпин\b|пин-код\w*|\bcvv2?\b|\bcvc2?\b|"
            r"три\s+цифры\s+на\s+обороте|код\s+на\s+обороте|срок\s+действия\s+карты|данные\s+(?:вашей\s+)?карты|"
            r"seed|сид-?фраз\w*|секретн\w+\s+(?:фраз|ключ|слов)\w*|мнемоническ\w*|приватн\w+\s+ключ\w*|private\s+key|recovery\s+phrase|password)",
        ),
        suppressors=(_NEVER_SHARE, r"придумайте\s+(?:новый\s+)?пароль|смените\s+пароль|забыли\s+пароль"),
        priority=95,
        window=50,
    ),
    Rule(
        code="REMOTE_ACCESS",
        severity=RiskLevel.HIGH,
        label="Просят дать доступ к устройству",
        explanation="Предлагают установить программу удалённого доступа или показать экран. Так посторонний может управлять телефоном и банковским приложением.",
        patterns=(
            r"any\s?desk|team\s?viewer|rust\s?desk|ammyy|энидеск|анидеск|тимвьюер|quick\s?support|airdroid|supremo|"
            r"удаленн\w+\s+(?:доступ|помощ|управлени)\w*|демонстраци\w+\s+экрана|(?:включите|включи|покажите|покажи)\s+(?:\w+\s+)?экран|"
            r"screen\s?shar\w*|\.apk\b|файл\s+apk|apk-файл",
        ),
        suppressors=(r"никогда\s+не\s+(?:просим|попросим|предлагаем)",),
        priority=90,
    ),
    Rule(
        code="URGENT_PAYMENT",
        severity=RiskLevel.HIGH,
        label="Срочно требуют перевести деньги",
        explanation="Требуют быстро перевести или оплатить деньги. Спешка мешает проверить информацию, это частый приём обмана.",
        patterns=(
            rf"{_PAY_VERB}[^\n]{{0,120}}?{_URGENCY}",
            rf"{_URGENCY}[^\n]{{0,120}}?{_PAY_VERB}",
            _SAFE_ACCOUNT,
        ),
        priority=85,
        window=0,
    ),
    Rule(
        code="PRIZE_OR_REFUND_FEE",
        severity=RiskLevel.HIGH,
        label="Просят оплату, чтобы получить выигрыш или возврат",
        explanation="Чтобы получить приз, компенсацию или возврат, просят сначала заплатить комиссию, налог или сбор. Это типичная схема предоплаты.",
        patterns=(
            r"(?:комисси|пошлин|налог|взнос|сбор|страховк|оплат\w*\s+(?:доставк|оформлени|услуг))\w*",
        ),
        requires_any=(
            r"выигр\w*|\bприз\w*|розыгрыш\w*|лотере\w*|компенсаци\w*|возврат\w*|выплат\w*|наследств\w*|вознагражден\w*|"
            r"\bподар\w*|\bpriz\w*|refund|lottery|you\s+(?:have\s+)?won",
        ),
        suppressors=(r"без\s+комисси|комиссия\s+(?:не\s+взимается|0|отсутствует)",),
        priority=80,
        window=30,
    ),
    Rule(
        code="SECRET_KEEPING",
        severity=RiskLevel.ELEVATED,
        label="Просят сохранить всё в тайне",
        explanation="Просят никому не рассказывать или не обращаться в банк и к близким. Так обычно пытаются не дать вам проверить ситуацию.",
        patterns=(
            r"никому\s+не\s+(?:говори|рассказыва|сообща|пиши)\w*",
            r"не\s+(?:говори|рассказыва|сообща|звони|обращай|ходи)\w*\s+(?:об\s+этом\s+)?(?:\w+\s+)?(?:родн|родственник|близк|никому|банк|в\s+банк|сотрудник|муж|жен|дет|мам|пап|полици)\w*",
            r"(?:секретн|конфиденциальн)\w+\s+(?:операци|информаци|проверк|расследовани)\w*|тайн\w+\s+следстви\w*|"
            r"неразглашени\w*|не\s+(?:кладите|клади)\s+трубку|не\s+прерывай\w*\s+(?:разговор|звонок)|don'?t\s+tell\s+anyone",
        ),
        suppressors=(r"никому\s+не\s+\w+\s+(?:\w+\s+){0,3}(?:код|пароль|данные|cvv|пин|реквизит)",),
        priority=70,
        window=40,
    ),
    Rule(
        code="PAYMENT_IRREVERSIBLE",
        severity=RiskLevel.ELEVATED,
        label="Необычный способ оплаты",
        explanation="Просят заплатить криптовалютой, подарочными картами или иным способом, который трудно отменить или оспорить.",
        patterns=(
            r"криптовалют\w*|биткоин\w*|bitcoin|\bbtc\b|\busdt\b|tether|ethereum|\bcrypto\w*|подарочн\w+\s+карт\w*|gift\s?cards?|"
            r"itunes|steam\s+карт\w*|карт\w*\s+(?:google\s+play|steam|app\s?store)|western\s+union|золот\w+\s+корон\w*|"
            r"через\s+(?:терминал|банкомат)|передайте\s+(?:\w+\s+)?(?:наличные|деньги)\s+курьер\w*|курьер\w*\s+(?:наличн|деньг)\w*",
        ),
        requires_any=(_PAY_VERB, r"купи\w*|приобрет\w*|\bbuy\b|кошел\w*|wallet"),
        priority=60,
    ),
    Rule(
        code="INVESTMENT_GUARANTEE",
        severity=RiskLevel.ELEVATED,
        label="Обещают гарантированную доходность",
        explanation="Обещают гарантированный или очень высокий доход без риска. Настоящие инвестиции не дают таких гарантий.",
        patterns=(
            r"гарантированн\w+\s+(?:доход|прибыл|доходност|выплат)\w*|без\s+(?:всякого\s+)?риска|безрисков\w*|"
            r"\d+\s?%\s+(?:в|за)\s+(?:день|сутки|неделю)|доход\w*\s+от\s+\d+\s?%|удво\w+|утро\w+\s+(?:деньги|вложени|сумм)|"
            r"пассивн\w+\s+доход\w*|guaranteed\s+(?:return|profit|income)|risk[- ]free",
        ),
        suppressors=(r"не\s+гарантиру\w*|не\s+является\s+гарантией|риск\s+потери",),
        priority=55,
    ),
    Rule(
        code="IMPERSONATION_CLAIM",
        severity=RiskLevel.ELEVATED,
        label="Представляются банком, госорганом или близким",
        explanation="Отправитель называет себя сотрудником банка, госоргана, службы или близким человеком. Само сообщение этого не подтверждает.",
        patterns=(
            r"служб\w+\s+безопасности|сотрудник\w*\s+(?:\w+\s+)?банка|(?:я|мы)\s+из\s+банка|центральн\w+\s+банк\w*|центробанк\w*|\bцб\s+рф|"
            r"\bфсб\b|\bмвд\b|следовател\w*|прокуратур\w*|финансов\w+\s+мониторинг\w*|росфинмониторинг\w*|"
            r"(?:мама|папа|сын|дочь|это\s+я)[,!.]?\s+(?:это\s+я|у\s+меня\s+новый\s+номер)|у\s+меня\s+новый\s+номер|(?:это\s+)?мой\s+новый\s+номер|"
            r"попал\w*\s+в\s+(?:беду|дтп|аварию|полицию|больниц)",
        ),
        # «Никому не сообщайте код, даже сотрудникам банка» — легитимное предупреждение.
        suppressors=(_NEVER_SHARE, r"даже\s+сотрудник"),
        priority=50,
    ),
    Rule(
        code="IMPERSONATION_CLAIM",
        severity=RiskLevel.ELEVATED,
        label="Представляются банком, госорганом или близким",
        explanation="Отправитель называет себя сотрудником банка, госоргана, службы или близким человеком. Само сообщение этого не подтверждает.",
        # Упоминания организаций сами по себе обычны, поэтому учитываются только вместе с другими признаками.
        patterns=(
            r"ваш\s+банк|из\s+банка|госуслуг\w*|налогов\w+|\bфнс\b|пенсионн\w+\s+фонд\w*|социальн\w+\s+фонд\w*|\bсфр\b|\bмфц\b|"
            r"служб\w+\s+(?:доставки|поддержки)|техподдержк\w*|курьер\w*|почт\w+\s+россии|\bсдэк\b|\bcdek\b|wildberries|\bozon\b|\bавито\b|\bavito\b|"
            r"оператор\w*\s+(?:связи|сотов)|support\s+team|your\s+bank",
        ),
        context_only=True,
        priority=49,
    ),
    Rule(
        code="TIME_PRESSURE",
        severity=RiskLevel.ELEVATED,
        label="Давят сроками",
        explanation="Сообщение торопит и пугает последствиями. Спокойно проверьте информацию через официальный канал, прежде чем что-то делать.",
        patterns=(_URGENCY,),
        context_only=True,
        priority=40,
    ),
)

# Комбинации, которые повышают уровень до HIGH.
ESCALATIONS: tuple[frozenset[str], ...] = (
    frozenset({"SUSPICIOUS_DOMAIN_STRONG", "IMPERSONATION_CLAIM"}),
    frozenset({"PAYMENT_IRREVERSIBLE", "IMPERSONATION_CLAIM"}),
    frozenset({"PAYMENT_IRREVERSIBLE", "TIME_PRESSURE"}),
    frozenset({"PAYMENT_IRREVERSIBLE", "INVESTMENT_GUARANTEE"}),
    frozenset({"SECRET_KEEPING", "IMPERSONATION_CLAIM"}),
)

SUSPICIOUS_DOMAIN = Rule(
    code="SUSPICIOUS_DOMAIN",
    severity=RiskLevel.ELEVATED,
    label="Подозрительная ссылка",
    explanation="Адрес ссылки выглядит необычно: похож на известный сайт, скрывает настоящий адрес, ведёт на IP-адрес или через сокращатель. Не переходите по ней.",
    patterns=(),
    priority=75,
)

# Признаки ссылки, которых достаточно, чтобы показать SUSPICIOUS_DOMAIN.
URL_SIGNALS_FOR_INDICATOR = frozenset(
    {"IP_HOST", "USERINFO_MASKING", "LOOKALIKE_OFFICIAL", "MIXED_SCRIPT", "BRAND_IN_UNOFFICIAL", "PUNYCODE",
     "SHORTENER", "SUSPICIOUS_TLD", "NONSTANDARD_PORT", "MALFORMED", "REPUTATION_LISTED", "DEEP_SUBDOMAINS"}
)


@dataclass(slots=True)
class Indicator:
    code: str
    label: str
    explanation: str
    severity: RiskLevel
    priority: int


@dataclass(slots=True)
class RuleResult:
    risk_level: RiskLevel
    indicators: list[Indicator] = field(default_factory=list)
    ruleset_version: str = RULESET_VERSION

    @property
    def codes(self) -> list[str]:
        return [i.code for i in self.indicators]


def ruleset_digest() -> str:
    h = hashlib.sha256(RULESET_VERSION.encode())
    for rule in (*RULES, SUSPICIOUS_DOMAIN):
        h.update(repr((rule.code, rule.severity.value, rule.patterns, rule.suppressors, rule.requires_any, rule.context_only)).encode())
    for esc in ESCALATIONS:
        h.update(",".join(sorted(esc)).encode())
    return h.hexdigest()


class RuleEngine:
    def __init__(self) -> None:
        self._compiled = [r.compiled() for r in RULES]

    def evaluate(self, normalized: NormalizedInput, url_findings: UrlFindings) -> RuleResult:
        text = normalized.match_text
        found: dict[str, Indicator] = {}
        context_only: dict[str, Indicator] = {}

        for cr in self._compiled:
            rule = cr.rule
            if rule.code in found or not cr.matches(text):
                continue
            ind = Indicator(rule.code, rule.label, rule.explanation, rule.severity, rule.priority)
            (context_only if rule.context_only else found)[rule.code] = ind

        url_hit = [f for f in url_findings.items if set(f.signals) & URL_SIGNALS_FOR_INDICATOR]
        if url_hit:
            r = SUSPICIOUS_DOMAIN
            found["SUSPICIOUS_DOMAIN"] = Indicator(r.code, r.label, r.explanation, r.severity, r.priority)

        if found:
            for code, ind in context_only.items():
                found.setdefault(code, ind)

        level = RiskLevel.NO_CLEAR_SIGNAL
        for ind in found.values():
            level = max_level(level, ind.severity)

        combo = set(found)
        if url_findings.any_strong:
            combo.add("SUSPICIOUS_DOMAIN_STRONG")
        if any(esc <= combo for esc in ESCALATIONS):
            level = RiskLevel.HIGH

        indicators = sorted(found.values(), key=lambda i: (-_SEVERITY_ORDER[i.severity], -i.priority))
        return RuleResult(risk_level=level, indicators=indicators)
