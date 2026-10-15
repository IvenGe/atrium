"""What an agent's settings add to the system prompt of its model calls (hub/llm gateway): the additional instructions
an administrator appended to a core agent's built-in ones, the reply language of chat agents and when they escalate.
The fixed parts stay where the agents put them (a custom agent's safety text, the task prompts of the Patch Agent)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..models import AgentConfig

if TYPE_CHECKING:
    from . import LLM

LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[a-z0-9]{2,8}){0,3}$", re.IGNORECASE)  # a BCP 47 tag ("nl", "fr-BE", "pt-BR")
LANGUAGES = {
    "en": "English", "nl": "Dutch", "fr": "French", "de": "German", "es": "Spanish", "it": "Italian",
    "pt": "Portuguese", "pl": "Polish", "sv": "Swedish", "da": "Danish", "nb": "Norwegian", "no": "Norwegian",
    "fi": "Finnish", "cs": "Czech", "sk": "Slovak", "hu": "Hungarian", "ro": "Romanian", "el": "Greek",
    "tr": "Turkish", "uk": "Ukrainian", "ru": "Russian", "ja": "Japanese", "ko": "Korean", "zh": "Chinese",
    "ar": "Arabic", "he": "Hebrew", "hi": "Hindi", "lb": "Luxembourgish", "ca": "Catalan", "et": "Estonian",
    "lv": "Latvian", "lt": "Lithuanian", "sl": "Slovenian", "hr": "Croatian", "bg": "Bulgarian", "ga": "Irish",
}


def check_language(code: str, where: str = "Language") -> str:
    """"" (the default), "auto" or a BCP 47 tag; ValueError otherwise."""
    code = (code or "").strip()
    if code in ("", "auto") or LANGUAGE_RE.match(code):
        return code
    raise ValueError(f"{where}: '{code[:40]}' is not a language code (use e.g. nl, fr, de, en or fr-BE)")


def language_name(code: str) -> str:
    base, _, region = code.partition("-")
    name = LANGUAGES.get(base.lower(), f"the language with the code '{code}'")
    return f"{name} ({code})" if region and base.lower() in LANGUAGES else name


def reply_language(gw: "LLM", config: AgentConfig) -> str | None:
    """The language an agent answers in: its own setting, else the suite default; None = the person's language."""
    from .resolve import selection

    code = config.language or selection(gw).language
    return None if code in ("", "auto") else code


def escalation_block(config: AgentConfig) -> str:
    """When the agent must use its escalate tool (its escalation rules, and always when blocked or unsure)."""
    rules = [r.strip() for r in config.escalation.rules if r.strip()]
    lead = ("When one of these applies, call the escalate tool instead of deciding yourself:\n"
            + "\n".join(f"- {r}" for r in rules) + "\n") if rules else ""
    return (f"{lead}Also escalate (the escalate tool) when you are blocked or unsure whether an action is safe. A "
            "person answers through Approvals; the answer reaches you in a later turn.")


def assemble(system: str, config: AgentConfig, *, language: str | None, purpose: str, escalate: bool = False) -> str:
    """`system` + the administrator's additional instructions (append mode) + the reply language (chat only) + when
    to escalate (when the escalate tool is offered)."""
    parts = [system.rstrip()]
    extra = config.extra_instructions.strip()
    if extra and config.instructions_mode == "append":
        parts.append(f"Additional instructions from an administrator:\n{extra}")
    if language and purpose == "chat":
        parts.append(f"Answer in {language_name(language)}. Keep ids, commands, code and quoted tool output unchanged.")
    if escalate:
        parts.append(escalation_block(config))
    return "\n\n".join(p for p in parts if p)
