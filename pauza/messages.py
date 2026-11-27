"""Шаблоны сообщений бота (ResponseComposer). Все пользовательские данные
экранируются через html.escape; ссылки показываются «обезвреженными»."""

from __future__ import annotations

from html import escape

from pauza.analysis.service import AnalysisResult
from pauza.db.models import RegionResource, ResourceType, RiskLevel
from pauza.integrations.telegram import TelegramMessage

LEVEL_TITLE = {
    RiskLevel.HIGH: "🔴 Высокий риск",
    RiskLevel.ELEVATED: "🟠 Есть подозрительные признаки",
    RiskLevel.NO_CLEAR_SIGNAL: "⚪️ Явных признаков не найдено",
}

PRIVACY_NOTE = (
    "🔒 Я не сохраняю текст, ссылки и картинки, которые вы присылаете: они удаляются сразу после проверки. "
    "Храню только настройки (регион) и обезличенную статистику. Удалить всё: /delete_me."
)

START = (
    "Здравствуйте! Я «Пауза» — помогаю заметить признаки мошенничества.\n\n"
    "Перешлите мне подозрительное сообщение, пришлите ссылку или скриншот, и я покажу, что в нём настораживает.\n\n"
    "Важно: я информационный помощник. Я не могу гарантировать, что сообщение безопасно, "
    "и не подтверждаю, кто его отправил. Если сомневаетесь, свяжитесь с организацией по официальному номеру.\n\n"
    f"{PRIVACY_NOTE}"
)

HELP = (
    "<b>Что я умею</b>\n"
    "• Проверяю текст, ссылки и скриншоты на признаки мошенничества.\n"
    "• /check — прислать материал на проверку.\n"
    "• /help_now — если вы уже ответили, перевели деньги или сообщили код.\n"
    "• /settings — регион.\n"
    "• /delete_me — удалить ваши данные.\n\n"
    "Ссылки я не открываю, только анализирую их адрес.\n\n"
    f"{PRIVACY_NOTE}"
)

CHECK_PROMPT = "Пришлите текст сообщения, ссылку или один скриншот. Можно просто переслать сообщение."

HELP_NOW_UNIVERSAL = [
    "Позвоните в свой банк по номеру на обратной стороне карты или из официального приложения. Попросите заблокировать карту и остановить или оспорить операцию.",
    "Если сообщили пароль или код от аккаунта, смените пароль и завершите все чужие сеансы в настройках аккаунта.",
    "Не отвечайте мошенникам и не устанавливайте программы, которые они предлагают. Если установили, удалите их.",
    "Сохраните переписку и детали операции: они понадобятся банку и полиции.",
    "Обратитесь в полицию с заявлением.",
]
HELP_NOW_NEVER = (
    "Никто, включая меня, не должен просить у вас номер карты, CVV, пароль, код из СМС или seed-фразу. "
    "Не присылайте их сюда."
)

RESOURCE_TITLES = {
    ResourceType.BANK_GUIDANCE: "Банк",
    ResourceType.POLICE_REPORT: "Полиция",
    ResourceType.CONSUMER_PROTECTION: "Защита прав потребителей",
    ResourceType.CYBER_REPORT: "Киберпреступления",
    ResourceType.EMERGENCY: "Экстренные службы",
}

ERRORS = {
    "RATE_LIMITED": "Слишком много проверок подряд. Пожалуйста, попробуйте немного позже.",
    "INPUT_TOO_LARGE_TEXT": "Сообщение слишком длинное. Пришлите, пожалуйста, самый важный фрагмент (до {limit} символов).",
    "image_too_large": "Изображение слишком большое. Пришлите скриншот поменьше или вставьте текст вручную.",
    "image_too_many_pixels": "Разрешение изображения слишком большое. Обрежьте скриншот или вставьте текст вручную.",
    "image_format": "Этот формат не поддерживается. Пришлите скриншот в JPEG, PNG или WEBP либо вставьте текст.",
    "image_animated": "Анимированные изображения не поддерживаются. Пришлите обычный скриншот или вставьте текст.",
    "image_corrupted": "Не получилось открыть изображение. Попробуйте другой скриншот или вставьте текст.",
    "UNSUPPORTED_INPUT": "Я пока умею проверять только текст, ссылки и скриншоты. Перешлите сообщение или пришлите скриншот.",
    "OCR_FAILED": "Не получилось прочитать текст на изображении. Пожалуйста, вставьте текст вручную.",
    "OCR_LOW_CONFIDENCE": "Текст на изображении распознан неуверенно, поэтому результат может быть неполным. Надёжнее вставить текст вручную.",
    "ANALYSIS_TIMEOUT": "Проверка не завершилась вовремя. Пожалуйста, попробуйте ещё раз чуть позже. Пока не переводите деньги и не сообщайте данные.",
    "INTERNAL_ERROR": "Что-то пошло не так, и проверка не завершилась. Попробуйте ещё раз позже. Пока не переводите деньги и не сообщайте данные.",
    "GROUP_CHAT": "Я работаю только в личных сообщениях, чтобы не показывать ваши данные другим. Напишите мне в личный чат.",
    "MULTIPLE_IMAGES": "Пожалуйста, присылайте по одному изображению за раз. Я проверил первое.",
}

DELETE_CONFIRM = "Удалить ваши настройки и все связанные с вами записи? Это нельзя отменить."
DELETE_DONE = "Готово. Ваши настройки и связанные записи удалены. Обезличенная статистика без привязки к вам сохраняется."
DELETE_NOTHING = "У меня нет сохранённых данных о вас."
FEEDBACK_THANKS = "Спасибо за отзыв!"
CALLBACK_EXPIRED = "Кнопка устарела. Пришлите материал ещё раз."


def e(s: str) -> str:
    return escape(s, quote=False)


def compose_result(result: AnalysisResult, keyboard: list[list[dict[str, str]]], notes: list[str] | None = None) -> TelegramMessage:
    lines = [f"<b>{LEVEL_TITLE[result.risk_level]}</b>", "", e(result.summary)]
    if result.indicators:
        lines += ["", "<b>Что настораживает:</b>"]
        for ind in result.indicators:
            lines.append(f"• <b>{e(ind.label)}.</b> {e(ind.explanation)}")
    if result.detected_urls:
        shown = ", ".join(f"<code>{e(u)}</code>" for u in result.detected_urls[:5])
        more = f" и ещё {len(result.detected_urls) - 5}" if len(result.detected_urls) > 5 else ""
        lines += ["", f"<b>Ссылки в сообщении:</b> {shown}{more}"]
    if result.urls_truncated:
        lines.append(e("Ссылок очень много, я проверил только первые 10."))
    if result.input_truncated:
        lines.append(e("Текст длинный, я проверил только его начало."))
    lines += ["", "<b>Что сделать:</b>"]
    for action in result.recommended_actions:
        lines.append(f"• {e(action)}")
    for note in notes or []:
        lines += ["", f"<i>{e(note)}</i>"]
    lines += ["", f"<i>{e(result.disclaimer)}</i>"]
    return TelegramMessage(text="\n".join(lines), keyboard=keyboard)


def compose_help_now(region_name: str | None, resources: list[RegionResource]) -> str:
    lines = ["<b>Что сделать прямо сейчас</b>", ""]
    for i, step in enumerate(HELP_NOW_UNIVERSAL, 1):
        lines.append(f"{i}. {e(step)}")
    if resources:
        lines += ["", f"<b>Официальные контакты ({e(region_name or '')}):</b>"]
        for r in resources:
            parts = [f"<b>{e(RESOURCE_TITLES[r.resource_type])}:</b> {e(r.display_name)}"]
            if r.official_phone:
                parts.append(f"тел. {e(r.official_phone)}")
            if r.official_url:
                parts.append(e(r.official_url))
            lines.append("• " + ", ".join(parts))
            if r.description:
                lines.append(f"  {e(r.description)}")
        lines.append("<i>Контакты взяты из официальных источников и проверены вручную; перед звонком сверьте номер с сайтом организации.</i>")
    else:
        lines += [
            "",
            e("Для вашего региона у меня пока нет проверенного списка контактов. "
              "Найдите номер банка на карте или в официальном приложении, а номер полиции — на официальном сайте."),
        ]
    lines += ["", f"⚠️ {e(HELP_NOW_NEVER)}"]
    return "\n".join(lines)
