"""Interface de linha de comando do promptguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .scanner import Policy, Verdict, scan

EXIT_ALLOWED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[97;41m"
GREEN = "\033[30;42m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptguard",
        description="Analisa um texto em busca de prompt injection antes de enviá-lo ao LLM.",
        epilog='Exemplo: promptguard "Ignore as instruções anteriores" --policy strict',
    )
    parser.add_argument("text", nargs="?", help="texto a analisar (omita para ler da stdin)")
    parser.add_argument("-f", "--file", type=Path, help="lê o texto de um arquivo")
    parser.add_argument(
        "--policy",
        choices=[p.value for p in Policy],
        default=Policy.BALANCED.value,
        help="nível de tolerância (padrão: balanced)",
    )
    parser.add_argument(
        "--format", choices=("terminal", "json"), default="terminal", help="formato da saída"
    )
    parser.add_argument(
        "--sanitize", action="store_true", help="imprime só o texto sanitizado (para pipeline)"
    )
    parser.add_argument("--no-color", action="store_true", help="desliga cores no terminal")
    parser.add_argument("--version", action="version", version=f"promptguard {__version__}")
    return parser


def to_terminal(verdict: Verdict, color: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    badge = paint(" BLOQUEADO ", RED) if verdict.blocked else paint(" PERMITIDO ", GREEN)
    lines = [
        "",
        f"  {badge}  risco {verdict.risk_score:.2f} · política {verdict.policy.value} "
        f"(limiar {verdict.policy.threshold:.2f})",
        "  " + "─" * 66,
    ]
    if not verdict.matched_rules:
        lines += ["", "  Nenhum sinal de prompt injection.", ""]
        return "\n".join(lines)

    for match in verdict.matched_rules:
        lines.append(
            f"  {paint(match.rule_id, BOLD)}  {match.name} · {match.label}  "
            f"{paint(f'peso {match.weight:.2f}', DIM)}"
        )
        if match.evidence:
            lines.append(paint(f"         “{match.evidence}”", DIM))
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    # console do Windows usa cp1252 e quebra os acentos
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)

    try:
        if args.file:
            text = args.file.read_text(encoding="utf-8")
        elif args.text is not None and args.text != "-":
            text = args.text
        else:
            text = sys.stdin.read()
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR

    verdict = scan(text, args.policy)

    if args.sanitize:
        print(verdict.sanitized_text)
    elif args.format == "json":
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(to_terminal(verdict, color=not args.no_color))

    return EXIT_BLOCKED if verdict.blocked else EXIT_ALLOWED


if __name__ == "__main__":
    raise SystemExit(main())
