"""Normalização do texto antes da detecção."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

INVISIBLE = frozenset(
    [0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x3164, 0xFEFF]
    + list(range(0x200B, 0x2010))
    + list(range(0x202A, 0x202F))
    + list(range(0x2060, 0x2070))
)
# bloco Tags: espelha ASCII de forma invisível ("ASCII smuggling")
TAG_START, TAG_END = 0xE0000, 0xE007F
ZERO_WIDTH_JOINER = 0x200D

HOMOGLYPHS = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "һ": "h",
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ϲ": "c",
}  # fmt: skip


@dataclass
class Normalized:
    text: str
    index: list[int]  # posição no texto original de cada caractere de `text`
    invisible: list[int] = field(default_factory=list)  # posições de invisíveis removidos
    hidden_ascii: str = ""  # mensagem decodificada de caracteres Tag
    mixed_script_words: list[str] = field(default_factory=list)

    def span(self, start: int, end: int) -> tuple[int, int]:
        """Converte um trecho da forma normalizada para o texto original."""
        return self.index[start], self.index[end - 1] + 1


def _is_symbol(ch: str) -> bool:
    return bool(ch) and unicodedata.category(ch) in ("So", "Sk")


def _legit_invisible(text: str, i: int) -> bool:
    """ZWJ dentro de emoji composto e BOM no início do arquivo são legítimos."""
    code = ord(text[i])
    if code == 0xFEFF and i == 0:
        return True
    if code == ZERO_WIDTH_JOINER:
        before = text[i - 1] if i > 0 else ""
        after = text[i + 1] if i + 1 < len(text) else ""
        return _is_symbol(before) or _is_symbol(after)
    return False


def _script(ch: str) -> str:
    if not ch.isalpha():
        return ""
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def mixed_script_words(text: str) -> list[str]:
    """Palavras que misturam latim com cirílico ou grego: assinatura de homoglifo."""
    found = []
    for word in text.split():
        scripts = {_script(ch) for ch in word} - {""}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            found.append(word)
    return found


def fold(ch: str) -> str:
    """Forma canônica de um caractere: compatibilidade, sem acento, homoglifo trocado."""
    out = []
    for part in unicodedata.normalize("NFKD", ch):
        if unicodedata.combining(part):
            continue
        part = part.lower()
        out.append(HOMOGLYPHS.get(part, part))
    return "".join(out)


def normalize(text: str) -> Normalized:
    chars: list[str] = []
    index: list[int] = []
    invisible: list[int] = []
    hidden: list[str] = []

    for i, ch in enumerate(text):
        code = ord(ch)
        if TAG_START <= code <= TAG_END:
            invisible.append(i)
            if 0xE0020 <= code <= 0xE007E:
                hidden.append(chr(code - TAG_START))
            continue
        if code in INVISIBLE:
            if not _legit_invisible(text, i):
                invisible.append(i)
            continue
        for out in fold(ch):
            # \n fica: "System:" só é marcação de papel no começo da linha
            if out == "\r":
                continue
            if out.isspace() and out != "\n":
                if chars and chars[-1] in " \n":
                    continue
                out = " "
            chars.append(out)
            index.append(i)

    return Normalized(
        text="".join(chars),
        index=index,
        invisible=invisible,
        hidden_ascii="".join(hidden),
        mixed_script_words=mixed_script_words(
            "".join(ch for ch in text if ord(ch) not in INVISIBLE)
        ),
    )
