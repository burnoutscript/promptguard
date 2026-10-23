"""Regras de detecção."""

from __future__ import annotations

import re
from dataclasses import dataclass

# só imperativo: "ignorar as instruções" é alguém falando sobre o ataque
_IGNORE_PT = r"(?:ignore|ignora|ignorem|desconsidere|desconsidera|despreze|descarte|abandone)"
_FORGET_PT = r"(?:esqueca|esquece|esquecam)"
_TARGET_PT = (
    r"(?:instruc\w*|orientac\w*|regras?|diretrizes?|comandos?|prompts?|mensagens?|"
    r"restricoes|limitacoes|configurac\w*)"
)
_PREVIOUS_PT = (
    r"(?:anterior\w*|acima|previa\w*|originais|iniciais|de sistema|do sistema|"
    r"dadas|recebidas|que (?:voce )?recebeu|que te (?:deram|passaram))"
)
_TARGET_EN = r"(?:instructions?|prompts?|rules|directives|guidelines|context|messages?|commands)"
_PREVIOUS_EN = r"(?:previous|prior|above|earlier|preceding|initial|original|system|all|any)"
_GAP = r"[^.\n?!]{0,40}?"


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern
    weight: float
    label: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    patterns: tuple[Pattern, ...]
    semantic: bool = True


def _p(regex: str, weight: float, label: str) -> Pattern:
    return Pattern(re.compile(regex), weight, label)


OVERRIDE = Rule(
    "PG001",
    "Sobrescrita de instruções",
    (
        _p(
            rf"\b{_IGNORE_PT}\b{_GAP}\b{_TARGET_PT}\b{_GAP}\b{_PREVIOUS_PT}\b",
            0.75,
            "ignorar instruções anteriores (pt)",
        ),
        _p(
            rf"\b{_IGNORE_PT} (?:tudo|todo o resto) (?:o que )?(?:esta |foi dito )?"
            r"(?:acima|antes)\b",
            0.7,
            "ignorar tudo acima (pt)",
        ),
        _p(
            rf"\b{_FORGET_PT} (?:tudo|todas as {_TARGET_PT}|suas {_TARGET_PT}|as {_TARGET_PT})"
            r"[^.\n?!]{0,30}?(?:acima|anterior\w*|ate aqui|(?:que|o que) (?:te |lhe )?"
            r"(?:foi |foram )?(?:dito|ditas|instruido|pedido|passad[oa]s?|mandad[oa]s?))",
            0.75,
            "esquecer tudo acima (pt)",
        ),
        _p(
            rf"\b{_FORGET_PT} (?:suas|as|todas as) {_TARGET_PT}\b",
            0.6,
            "esquecer as instruções (pt)",
        ),
        _p(r"\bnovas instrucoes(?: do sistema)?\s*:", 0.5, "novas instruções: (pt)"),
        _p(
            rf"\b(?:ignore|disregard|forget|override|bypass|skip)\b{_GAP}\b{_PREVIOUS_EN}\b"
            rf"{_GAP}\b{_TARGET_EN}\b",
            0.75,
            "ignore previous instructions (en)",
        ),
        _p(
            r"\bforget (?:everything|all)(?: you (?:were|have been) told| above| before| so far)",
            0.7,
            "forget everything (en)",
        ),
        _p(r"\bnew instructions\s*:", 0.5, "new instructions: (en)"),
    ),
)

EXTRACTION = Rule(
    "PG002",
    "Extração do prompt de sistema",
    (
        _p(
            r"\b(?:mostre|mostra|revele|revela|exiba|exibe|imprima|imprime|repita|repete|diga|"
            r"diz|escreva|escreve|copie|liste|cole|transcreva|me (?:de|da|passe|passa|mande|"
            r"manda|mostre|mostra|diga|diz))\b[^.\n?!]{0,40}?"
            r"(?:prompt (?:de|do) sistema|system prompt|prompt (?:inicial|original|oculto|"
            r"secreto|completo)|(?:instrucoes|regras|diretrizes) (?:iniciais|originais|"
            r"internas|ocultas|secretas|de sistema|do sistema|que (?:voce )?recebeu)|"
            r"(?:suas|tuas) (?:instrucoes|diretrizes|regras internas)|(?:seu|teu) prompt)",
            0.65,
            "revelar o prompt de sistema (pt)",
        ),
        _p(
            r"\bqual (?:e|eh|era) (?:o )?(?:seu|teu) (?:prompt|system prompt)"
            r"|\bquais (?:sao|eram) (?:as )?(?:suas|tuas) (?:instrucoes|diretrizes)",
            0.6,
            "pergunta pelo prompt (pt)",
        ),
        _p(
            r"\b(?:repita|repete|reproduza|copie) (?:tudo|todo o texto|o texto|as mensagens) "
            r"(?:acima|anterior|que veio antes)|\bpalavra por palavra\b.{0,40}(?:acima|instruc)",
            0.6,
            "repetir o texto acima (pt)",
        ),
        _p(
            r"\b(?:show|reveal|print|repeat|output|display|tell me|give me|what (?:is|are|were)|"
            r"leak|dump)\b[^.\n?!]{0,40}?(?:system prompt|(?:initial|original|hidden|secret|"
            r"internal) (?:prompt|instructions|rules)|your (?:prompt|instructions|rules|"
            r"guidelines|directives))",
            0.65,
            "reveal system prompt (en)",
        ),
        _p(
            r"\brepeat (?:the |all )?(?:text|words|everything) above\b|\bverbatim\b"
            r".{0,40}(?:above|instructions|prompt)|\bstarting with ['\"]?you are",
            0.6,
            "repeat the text above (en)",
        ),
    ),
)

DELIMITER = Rule(
    "PG003",
    "Delimitador ou papel falso",
    (
        _p(
            r"<\|(?:im_start|im_end|system|assistant|user|endoftext|eot_id|start_header_id|"
            r"end_header_id|begin_of_text)\|>|\[/?inst\]|<</?sys>>|</?(?:system|sistema)>",
            0.7,
            "token especial de modelo",
        ),
        _p(
            r"(?:^|\n)[ \t]*(?:#{1,6}[ \t]*|\*\*|\[)(?:system|assistant|sistema|assistente|"
            r"developer|desenvolvedor)(?:\*\*|\])?[ \t]*:",
            0.55,
            "cabeçalho de papel forjado (### System:)",
        ),
        _p(
            r"(?:^|\n)[ \t]*(?:system|assistant|sistema|assistente|developer|desenvolvedor)"
            r"[ \t]*:",
            0.45,
            "marcação de papel no início da linha",
        ),
        _p(
            r"(?:^|\n)[ \t]*(?:#{1,6}[ \t]*|\*\*)?(?:user|human|usuario|humano)(?:\*\*)?[ \t]*:",
            0.3,
            "marcação de usuário no início da linha",
        ),
        _p(
            r"\b(?:end of (?:user )?(?:input|prompt|message)|fim (?:da|do) "
            r"(?:entrada|prompt|mensagem|texto) (?:do usuario)?)\b",
            0.45,
            "fim de entrada forjado",
        ),
    ),
)

PERSONA = Rule(
    "PG006",
    "Troca de persona",
    (
        _p(
            r"\b(?:a partir de agora|de agora em diante|daqui (?:pra|para) frente)\b"
            r"[^.\n?!]{0,30}?\b(?:voce|vc|tu)\s+(?:e|eh|sera|vai ser|agira|age|atuara|"
            r"responde|respondera|deve agir)\b",
            0.4,
            "a partir de agora você é (pt)",
        ),
        _p(
            r"\b(?:finja|finge|faca de conta) (?:que )?(?:voce|vc) (?:e|eh|seja|fosse)\b",
            0.35,
            "finja que você é (pt)",
        ),
        _p(
            r"\b(?:from now on|henceforth|starting now)\b[^.\n?!]{0,30}?\byou (?:are|will be|"
            r"will act|act|must act|respond)\b|\byou are now\b",
            0.4,
            "from now on you are (en)",
        ),
        _p(r"\b(?:pretend (?:to be|you are)|roleplay as)\b", 0.35, "pretend to be (en)"),
        _p(
            r"\b(?:responda|responde|fale|aja|atue|escreva|opere|funcione)\b[^.\n?!]{0,25}?"
            r"\bsem (?:nenhuma |qualquer )?(?:restricoes|restricao|filtros?|limites|regras|"
            r"censura|diretrizes)\b"
            r"|\b(?:voce|vc) (?:nao tem|nao possui|esta livre de|agora nao tem) (?:mais )?"
            r"(?:nenhuma )?(?:restricoes|regras|limites|filtros|diretrizes)\b",
            0.7,
            "persona sem restrições (pt)",
        ),
        _p(
            r"\b(?:voce|vc|seja|sendo|como)\s+(?:e\s+|eh\s+|sera\s+|fosse\s+)?(?:uma?|o|a)\s+"
            r"(?:ia|ai|inteligencia artificial|assistente|chatbot|modelo|bot)\s+(?:sem|livre de|"
            r"que nao tem|que nao possui)\s+(?:nenhuma\s+|qualquer\s+)?(?:censura|restricoes|"
            r"restricao|filtros?|limites|regras|diretrizes)\b",
            0.7,
            "persona de IA sem restrições (pt)",
        ),
        _p(
            r"\b(?:do anything now|jailbreak\w*|jailbroken|developer mode|god mode|unfiltered "
            r"(?:ai|mode|assistant)|uncensored (?:ai|mode|assistant))\b|\b(?:you are|as|act as"
            r"|voce e|modo) (?:o )?dan\b|\bmodo (?:deus|irrestrito|sem censura)\b"
            r"|\bno (?:restrictions|filters|rules|limits) (?:apply|at all)\b"
            r"|\bwithout (?:any )?(?:restrictions|filters|censorship)\b",
            0.7,
            "persona de jailbreak",
        ),
    ),
)

SEMANTIC_RULES = (OVERRIDE, EXTRACTION, DELIMITER, PERSONA)

ENCODED_ID, ENCODED_NAME = "PG004", "Payload codificado ou ofuscado"
SHAPE_ID, SHAPE_NAME = "PG005", "Forma anômala do texto"

RULE_NAMES = {rule.rule_id: rule.name for rule in SEMANTIC_RULES} | {
    ENCODED_ID: ENCODED_NAME,
    SHAPE_ID: SHAPE_NAME,
}
