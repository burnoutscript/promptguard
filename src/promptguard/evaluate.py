"""Mede precisão e recall do scanner sobre o corpus rotulado."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .scanner import Policy, scan


@dataclass(frozen=True)
class Sample:
    text: str
    malicious: bool
    category: str


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0


def load(directory: Path, subset: str) -> list[Sample]:
    samples = []
    for label, malicious in (("maliciosos", True), ("legitimos", False)):
        path = directory / f"{subset}_{label}.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                samples.append(Sample(row["texto"], malicious, row.get("categoria", "")))
    return samples


def evaluate(samples: list[Sample], policy: Policy) -> tuple[Metrics, list[tuple[Sample, float]]]:
    metrics = Metrics()
    errors = []
    for sample in samples:
        verdict = scan(sample.text, policy)
        if sample.malicious and verdict.blocked:
            metrics.tp += 1
        elif sample.malicious:
            metrics.fn += 1
            errors.append((sample, verdict.risk_score))
        elif verdict.blocked:
            metrics.fp += 1
            errors.append((sample, verdict.risk_score))
        else:
            metrics.tn += 1
    return metrics, errors


def recall_by_category(samples: list[Sample], policy: Policy) -> dict[str, tuple[int, int]]:
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for sample in samples:
        if sample.malicious:
            totals[sample.category][1] += 1
            if scan(sample.text, policy).blocked:
                totals[sample.category][0] += 1
    return {category: (hit, total) for category, (hit, total) in sorted(totals.items())}


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="python -m promptguard.evaluate")
    parser.add_argument("corpus", type=Path, help="diretório com os arquivos .jsonl")
    parser.add_argument("--conjunto", choices=("dev", "validacao"), action="append")
    parser.add_argument("--erros", action="store_true", help="lista falsos positivos e negativos")
    args = parser.parse_args(argv)

    for subset in args.conjunto or ["dev", "validacao"]:
        samples = load(args.corpus, subset)
        malicious = sum(s.malicious for s in samples)
        print(
            f"\n## Conjunto {subset}: {malicious} maliciosos, "
            f"{len(samples) - malicious} legítimos\n"
        )
        print("| Política | Precisão | Recall | Falsos positivos | Falsos negativos |")
        print("|---|---|---|---|---|")
        for policy in Policy:
            metrics, errors = evaluate(samples, policy)
            print(
                f"| {policy.value} | {metrics.precision:.1%} | {metrics.recall:.1%} "
                f"| {metrics.fp} de {metrics.fp + metrics.tn} | {metrics.fn} de {malicious} |"
            )
            if args.erros:
                for sample, score in errors:
                    kind = "FN" if sample.malicious else "FP"
                    preview = " ".join(sample.text.split())[:90]
                    print(f"    {kind} {score:.2f} [{sample.category}] {preview}")

        print("\nRecall por categoria (balanced):\n")
        for category, (hit, total) in recall_by_category(samples, Policy.BALANCED).items():
            print(f"- {category}: {hit}/{total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
