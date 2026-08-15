"""Stable, failure-isolated entry point for deterministic source analysis."""

from __future__ import annotations

from collections.abc import Sequence

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import (
    AnalysisResult,
    Candidate,
    Diagnostic,
    DiagnosticLevel,
    Language,
    SourceFile,
)

from .base import RULES, candidate_sort_key
from .javascript import analyze_javascript
from .python import analyze_python


def analyze_sources(sources: Sequence[SourceFile], config: AnalysisConfig) -> AnalysisResult:
    """Analyze supported sources and report every failure that affects completeness."""

    candidates: list[Candidate] = []
    diagnostics: list[Diagnostic] = []
    enabled_languages = set(config.languages)
    for source in sorted(sources, key=lambda item: (item.path, item.language.value)):
        if source.language not in enabled_languages:
            continue
        try:
            if source.language == Language.PYTHON:
                candidates.extend(analyze_python(source, config))
            elif source.language in {Language.JAVASCRIPT, Language.TYPESCRIPT}:
                candidates.extend(analyze_javascript(source, config))
        except SyntaxError as exc:
            line = getattr(exc, "lineno", None)
            diagnostics.append(
                Diagnostic(
                    code="analysis_parse_error",
                    level=DiagnosticLevel.ERROR,
                    message=f"{source.language.value} source could not be parsed",
                    path=source.path,
                    line=line if isinstance(line, int) and line >= 1 else None,
                )
            )
        except Exception:
            diagnostics.append(
                Diagnostic(
                    code="analysis_internal_error",
                    level=DiagnosticLevel.ERROR,
                    message=f"{source.language.value} analyzer did not complete",
                    path=source.path,
                )
            )
    unique = {candidate.candidate_id: candidate for candidate in candidates}
    return AnalysisResult(
        candidates=sorted(unique.values(), key=candidate_sort_key),
        diagnostics=diagnostics,
        complete=not diagnostics,
    )


__all__ = ["RULES", "analyze_sources"]
