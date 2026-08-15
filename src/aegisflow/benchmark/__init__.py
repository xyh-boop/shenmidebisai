"""Ground-truth loading and deterministic benchmark scoring."""

from __future__ import annotations

import json
from pathlib import Path

from aegisflow.contracts import (
    BenchmarkResult,
    Disposition,
    Finding,
    GroundTruth,
    GroundTruthFinding,
    ReportEnvelope,
)

MAX_GROUND_TRUTH_BYTES = 8 * 1024 * 1024


class GroundTruthLoadError(ValueError):
    """Raised when a ground-truth manifest cannot be safely loaded."""


def load_ground_truth(path: Path) -> GroundTruth:
    """Load and validate a UTF-8 ground-truth manifest."""

    with path.open("rb") as handle:
        raw = handle.read(MAX_GROUND_TRUTH_BYTES + 1)
    if len(raw) > MAX_GROUND_TRUTH_BYTES:
        raise GroundTruthLoadError("ground-truth manifest exceeds the configured byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GroundTruthLoadError("ground-truth manifest is not valid UTF-8") from exc
    payload = json.loads(text)
    return GroundTruth.model_validate(payload)


def _overlaps(finding: Finding, truth: GroundTruthFinding) -> bool:
    return (
        finding.rule_id == truth.rule_id
        and finding.path == truth.path
        and finding.start_line <= truth.end_line
        and truth.start_line <= finding.end_line
    )


def _scored_findings(report: ReportEnvelope) -> list[Finding]:
    """Return unique user-visible predictions in stable report order."""

    unique: dict[str, Finding] = {}
    for finding in report.findings:
        if finding.disposition != Disposition.REJECTED:
            unique.setdefault(finding.finding_id, finding)
    return list(unique.values())


def _maximum_matching(
    findings: list[Finding], expected: list[GroundTruthFinding]
) -> dict[int, int]:
    """Return truth-index to finding-index matches using deterministic augmentation."""

    adjacency = [
        [truth_index for truth_index, truth in enumerate(expected) if _overlaps(finding, truth)]
        for finding in findings
    ]
    truth_to_finding: dict[int, int] = {}

    def augment(finding_index: int, visited: set[int]) -> bool:
        for truth_index in adjacency[finding_index]:
            if truth_index in visited:
                continue
            visited.add(truth_index)
            incumbent = truth_to_finding.get(truth_index)
            if incumbent is None or augment(incumbent, visited):
                truth_to_finding[truth_index] = finding_index
                return True
        return False

    for finding_index in range(len(findings)):
        augment(finding_index, set())
    return truth_to_finding


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def score_benchmark(report: ReportEnvelope, truth: GroundTruth) -> BenchmarkResult:
    """Score location-overlapping, rule-matched predictions one-to-one."""

    findings = _scored_findings(report)
    expected = list(truth.expected)
    truth_to_finding = _maximum_matching(findings, expected)
    matched_finding_indexes = set(truth_to_finding.values())
    matched_truth_indexes = set(truth_to_finding)

    true_positives = len(truth_to_finding)
    false_positives = len(findings) - true_positives
    false_negatives = len(expected) - true_positives
    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(true_positives, true_positives + false_negatives)
    f1 = _ratio(2 * precision * recall, precision + recall)

    return BenchmarkResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        false_discovery_rate=_ratio(false_positives, true_positives + false_positives),
        matched_finding_ids=[
            finding.finding_id
            for index, finding in enumerate(findings)
            if index in matched_finding_indexes
        ],
        missed_truth_ids=[
            item.truth_id
            for index, item in enumerate(expected)
            if index not in matched_truth_indexes
        ],
    )


__all__ = [
    "MAX_GROUND_TRUTH_BYTES",
    "GroundTruthLoadError",
    "load_ground_truth",
    "score_benchmark",
]
