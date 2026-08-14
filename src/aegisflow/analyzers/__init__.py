"""Stable, failure-isolated entry point for deterministic source analysis."""

from __future__ import annotations

from collections.abc import Sequence

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import Candidate, Language, SourceFile

from .base import RULES, candidate_sort_key
from .javascript import analyze_javascript
from .python import analyze_python


def analyze_sources(sources: Sequence[SourceFile], config: AnalysisConfig) -> list[Candidate]:
    """Analyze supported sources without allowing one malformed file to abort the run."""

    candidates: list[Candidate] = []
    enabled_languages = set(config.languages)
    for source in sorted(sources, key=lambda item: (item.path, item.language.value)):
        if source.language not in enabled_languages:
            continue
        try:
            if source.language == Language.PYTHON:
                candidates.extend(analyze_python(source, config))
            elif source.language in {Language.JAVASCRIPT, Language.TYPESCRIPT}:
                candidates.extend(analyze_javascript(source, config))
        except (SyntaxError, UnicodeError, ValueError):
            continue
    unique = {candidate.candidate_id: candidate for candidate in candidates}
    return sorted(unique.values(), key=candidate_sort_key)


__all__ = ["RULES", "analyze_sources"]
