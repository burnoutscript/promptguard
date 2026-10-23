"""Ponto de entrada da biblioteca: `scan(texto) -> Verdict`."""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

from .normalize import HOMOGLYPHS, Normalized, mixed_script_words, normalize
from .rules import ENCODED_ID, ENCODED_NAME, SEMANTIC_RULES, SHAPE_ID, SHAPE_NAME

BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=])")
HEX_CANDIDATE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){8,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[ :]?){12,}"
)
MAX_DEPTH = 2


class Policy(str, Enum):
    """Nível de tolerância. O limiar é o risco a partir do qual o texto é bloqueado."""

    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"

    @property
    def threshold(self) -> float:
        return {"strict": 0.3, "balanced": 0.5, "permissive": 0.75}[self.value]


@dataclass(frozen=True)
class Match:
    rule_id: str
    name: str
    weight: float
    label: str
    evidence: str = ""
    span: tuple[int, int] | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "weight": self.weight,
            "label": self.label,
            "evidence": self.evidence,
        }


@dataclass
class Verdict:
    risk_score: float
    matched_rules: list[Match]
    sanitized_text: str
    policy: Policy = Policy.BALANCED
    removed: list[tuple[int, int]] = field(default_factory=list, repr=False)

    @property
    def blocked(self) -> bool:
        return self.risk_score >= self.policy.threshold

    @property
    def rule_ids(self) -> list[str]:
        return sorted({m.rule_id for m in self.matched_rules})

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "blocked": self.blocked,
            "policy": self.policy.value,
            "threshold": self.policy.threshold,
            "matched_rules": [m.to_dict() for m in self.matched_rules],
            "sanitized_text": self.sanitized_text,
        }


def _semantic_matches(text: str, norm: Normalized) -> list[Match]:
    matches = []
    for rule in SEMANTIC_RULES:
        for pattern in rule.patterns:
            for found in pattern.regex.finditer(norm.text):
                if found.end() == found.start():
                    continue
                start, end = norm.span(found.start(), found.end())
                while start < end and text[start].isspace():
                    start += 1
                matches.append(
                    Match(
                        rule.rule_id,
                        rule.name,
                        pattern.weight,
                        pattern.label,
                        _evidence(text[start:end]),
                        (start, end),
                    )
                )
    return matches


def _evidence(snippet: str, limit: int = 80) -> str:
    snippet = " ".join(snippet.split())
    return snippet if len(snippet) <= limit else snippet[: limit - 1] + "…"


def _printable_text(raw: bytes) -> str | None:
    """Devolve o texto se os bytes forem UTF-8 legível; senão None."""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(decoded) < 8:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t")
    letters = sum(1 for ch in decoded if ch.isalpha())
    if printable / len(decoded) < 0.95 or letters / len(decoded) < 0.5:
        return None
    return decoded


def _decode_base64(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        if "-" in candidate or "_" in candidate:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(raw)


def _decode_hex(candidate: str) -> str | None:
    digits = re.sub(r"\\x|[ :]", "", candidate)
    if len(digits) % 2:
        digits = digits[:-1]
    try:
        return _printable_text(bytes.fromhex(digits))
    except ValueError:
        return None


def _payload_match(kind: str, decoded: str, depth: int, span: tuple[int, int] | None) -> Match:
    inner = _analyze(decoded, depth + 1)
    hidden_attack = any(m.rule_id not in (ENCODED_ID, SHAPE_ID) for m in inner)
    if hidden_attack:
        return Match(
            ENCODED_ID,
            ENCODED_NAME,
            0.85,
            f"{kind} esconde instrução",
            _evidence(decoded),
            span,
        )
    return Match(ENCODED_ID, ENCODED_NAME, 0.2, f"{kind} decodificável", _evidence(decoded))


def _encoded_matches(text: str, norm: Normalized, depth: int) -> list[Match]:
    matches = []

    if norm.hidden_ascii.strip():
        if depth < MAX_DEPTH:
            match = _payload_match("caracteres Unicode Tag", norm.hidden_ascii, depth, None)
            weight = max(match.weight, 0.6)  # Tag não tem uso legítimo em texto de aluno
            matches.append(Match(ENCODED_ID, ENCODED_NAME, weight, match.label, match.evidence))
    elif norm.invisible:
        matches.append(
            Match(
                ENCODED_ID,
                ENCODED_NAME,
                0.35,
                f"{len(norm.invisible)} caractere(s) invisível(is)",
            )
        )

    if norm.mixed_script_words:
        words = ", ".join(norm.mixed_script_words[:3])
        matches.append(Match(ENCODED_ID, ENCODED_NAME, 0.4, "homoglifos", _evidence(words)))

    if depth < MAX_DEPTH:
        for regex, kind, decoder in (
            (BASE64_CANDIDATE, "base64", _decode_base64),
            (HEX_CANDIDATE, "hexadecimal", _decode_hex),
        ):
            for found in regex.finditer(text):
                decoded = decoder(found.group(0).strip())
                if decoded:
                    matches.append(_payload_match(kind, decoded, depth, found.span()))
    return matches


def _shape_matches(text: str, norm: Normalized) -> list[Match]:
    matches = []
    letters = [ch for ch in text if ch.isalpha()]
    if len(letters) >= 40:
        upper = sum(1 for ch in letters if ch.isupper()) / len(letters)
        if upper >= 0.7:
            matches.append(
                Match(SHAPE_ID, SHAPE_NAME, 0.15, f"caixa alta em {upper:.0%} das letras")
            )

    words = [w for w in re.findall(r"\w+", norm.text) if len(w) >= 3]
    if len(words) >= 20:
        word, count = Counter(words).most_common(1)[0]
        if count >= 10 and count / len(words) >= 0.3:
            matches.append(Match(SHAPE_ID, SHAPE_NAME, 0.2, f"'{word}' repetido {count} vezes"))

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        line, count = Counter(lines).most_common(1)[0]
        if count >= 5:
            matches.append(
                Match(SHAPE_ID, SHAPE_NAME, 0.2, f"linha repetida {count} vezes", _evidence(line))
            )

    if re.search(r"(.)\1{59,}", text):
        matches.append(Match(SHAPE_ID, SHAPE_NAME, 0.1, "caractere repetido 60+ vezes"))
    return matches


def _analyze(text: str, depth: int = 0) -> list[Match]:
    norm = normalize(text)
    return (
        _semantic_matches(text, norm)
        + _encoded_matches(text, norm, depth)
        + _shape_matches(text, norm)
    )


def risk(matches: list[Match]) -> float:
    """Combina os sinais como eventos independentes (noisy-OR)."""
    strongest: dict[tuple[str, str], float] = {}
    for match in matches:
        key = (match.rule_id, match.label)
        strongest[key] = max(strongest.get(key, 0.0), match.weight)
    remaining = 1.0
    for weight in strongest.values():
        remaining *= 1 - weight
    return round(1 - remaining, 3)


REPLACEMENT = "[removido]"


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _fix_homoglyphs(text: str) -> str:
    mixed = set(mixed_script_words(text))
    if not mixed:
        return text
    out = []
    for word in re.split(r"(\s+)", text):
        if word in mixed:
            word = "".join(
                HOMOGLYPHS.get(ch.lower(), ch).upper() if ch.isupper() else HOMOGLYPHS.get(ch, ch)
                for ch in word
            )
        out.append(word)
    return "".join(out)


def sanitize(text: str, matches: list[Match]) -> tuple[str, list[tuple[int, int]]]:
    """Remove os trechos de ataque, os invisíveis e corrige homoglifos."""
    spans = _merge([m.span for m in matches if m.span and m.weight >= 0.3])
    norm = normalize(text)
    invisible = set(norm.invisible)

    out: list[str] = []
    position = 0
    for start, end in spans:
        out.append(_strip_invisible(text[position:start], invisible, position))
        out.append(REPLACEMENT)
        position = end
    out.append(_strip_invisible(text[position:], invisible, position))
    return _fix_homoglyphs("".join(out)), spans


def _strip_invisible(chunk: str, invisible: set[int], offset: int) -> str:
    if not invisible:
        return chunk
    return "".join(ch for i, ch in enumerate(chunk, offset) if i not in invisible)


def scan(text: str, policy: Policy | str = Policy.BALANCED) -> Verdict:
    """Analisa um texto de usuário antes de enviá-lo ao LLM."""
    policy = Policy(policy)
    matches = sorted(_analyze(text), key=lambda m: (-m.weight, m.rule_id))
    sanitized, removed = sanitize(text, matches)
    return Verdict(
        risk_score=risk(matches),
        matched_rules=matches,
        sanitized_text=sanitized,
        policy=policy,
        removed=removed,
    )
