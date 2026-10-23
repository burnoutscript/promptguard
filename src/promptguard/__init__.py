"""promptguard — detecção e sanitização de prompt injection antes do texto chegar ao LLM."""

__version__ = "0.1.0"

from .scanner import Match, Policy, Verdict, scan

__all__ = ["Match", "Policy", "Verdict", "scan", "__version__"]
