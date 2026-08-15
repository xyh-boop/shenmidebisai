import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

import aegisflow.benchmark as benchmark_module
from aegisflow.benchmark import load_ground_truth, score_benchmark
from aegisflow.contracts import (
    EvidenceEdge,
    EvidenceNode,
    Finding,
    GroundTruth,
    ReportEnvelope,
    RunMetadata,
    RunMetrics,
    build_finding_id,
)


def make_finding(
    *,
    path: str,
    start: int,
    end: int,
    rule_id: str = "AF-CMD-001",
    disposition: str = "confirmed",
) -> Finding:
    nodes = [
        EvidenceNode(
            node_id=f"source-{start}-{end}",
            kind="source",
            path=path,
            line=start,
            symbol="input",
            snippet="user_input",
            description="Untrusted input",
        ),
        EvidenceNode(
            node_id=f"sink-{start}-{end}",
            kind="sink",
            path=path,
            line=end,
            symbol="run",
            snippet="run(user_input)",
            description="Dangerous sink",
        ),
    ]
    return Finding(
        finding_id=build_finding_id(rule_id, path, start, end, nodes),
        rule_id=rule_id,
        cwe="CWE-78",
        title="Command injection",
        severity="high",
        confidence=0.9,
        disposition=disposition,
        language="python",
        path=path,
        start_line=start,
        end_line=end,
        nodes=nodes,
        edges=[
            EvidenceEdge(
                source_id=f"source-{start}-{end}",
                target_id=f"sink-{start}-{end}",
                relation="flows_to",
            )
        ],
        decisions=[],
        remediation="Avoid shell execution.",
    )


def make_report(findings: list[Finding]) -> ReportEnvelope:
    now = datetime(2026, 8, 14, tzinfo=UTC)
    return ReportEnvelope(
        schema_version="1.0",
        tool_version="0.1.0",
        run=RunMetadata(
            run_id="benchmark",
            mode="offline",
            root=".",
            started_at=now,
            completed_at=now,
            configuration_digest="0" * 64,
        ),
        metrics=RunMetrics(
            files_scanned=1,
            lines_scanned=100,
            elapsed_ms=1,
            time_to_first_high_ms=None,
            candidates_total=len(findings),
            findings_confirmed=sum(item.disposition == "confirmed" for item in findings),
            findings_rejected=sum(item.disposition == "rejected" for item in findings),
            human_review_required=0,
            model_requests=0,
            prompt_tokens=0,
            completion_tokens=0,
            estimated_cost_usd=0,
        ),
        findings=findings,
        diagnostics=[],
    )


def truth_fixture() -> GroundTruth:
    return GroundTruth.model_validate(
        {
            "schema_version": "1.0",
            "expected": [
                {
                    "truth_id": "truth-a",
                    "rule_id": "AF-CMD-001",
                    "path": "src/app.py",
                    "start_line": 10,
                    "end_line": 10,
                },
                {
                    "truth_id": "truth-b",
                    "rule_id": "AF-CMD-001",
                    "path": "src/app.py",
                    "start_line": 20,
                    "end_line": 20,
                },
            ],
        }
    )


def test_load_ground_truth_validates_and_stably_orders(tmp_path) -> None:
    path = tmp_path / "truth.json"
    payload = {
        "schema_version": "1.0",
        "expected": [
            {
                "truth_id": "later",
                "rule_id": "AF-CMD-001",
                "path": "z.py",
                "start_line": 9,
                "end_line": 9,
            },
            {
                "truth_id": "first",
                "rule_id": "AF-CMD-001",
                "path": "a.py",
                "start_line": 2,
                "end_line": 3,
            },
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_ground_truth(path)

    assert [item.truth_id for item in loaded.expected] == ["first", "later"]


def test_load_ground_truth_rejects_invalid_manifest(tmp_path) -> None:
    path = tmp_path / "truth.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "expected": [
                    {
                        "truth_id": "bad",
                        "rule_id": "AF-CMD-001",
                        "path": "../escape.py",
                        "start_line": 1,
                        "end_line": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_ground_truth(path)


def test_load_ground_truth_rejects_oversized_control_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(benchmark_module, "MAX_GROUND_TRUTH_BYTES", 64)
    path = tmp_path / "oversized-truth.json"
    path.write_bytes(b'{"schema_version":"1.0","expected":[]}' + b" " * 64)

    with pytest.raises(ValueError, match="exceeds the configured byte limit"):
        load_ground_truth(path)


def test_scoring_uses_maximum_one_to_one_location_matching() -> None:
    broad = make_finding(path="src/app.py", start=5, end=25)
    narrow = make_finding(path="src/app.py", start=9, end=11)

    result = score_benchmark(make_report([broad, narrow]), truth_fixture())

    assert result.true_positives == 2
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert result.false_discovery_rate == 0.0
    assert result.missed_truth_ids == []


def test_scoring_requires_matching_rule_path_and_overlap() -> None:
    findings = [
        make_finding(path="other.py", start=10, end=10),
        make_finding(path="src/app.py", start=30, end=31),
        make_finding(path="src/app.py", start=10, end=10, rule_id="AF-OTHER-001"),
    ]

    result = score_benchmark(make_report(findings), truth_fixture())

    assert result.true_positives == 0
    assert result.false_positives == 3
    assert result.false_negatives == 2
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0
    assert result.false_discovery_rate == 1.0


def test_scoring_deduplicates_fingerprints_and_ignores_rejected() -> None:
    match = make_finding(path="src/app.py", start=10, end=10)
    rejected = make_finding(path="false.py", start=1, end=1, disposition="rejected")

    result = score_benchmark(make_report([match, match, rejected]), truth_fixture())

    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 1
    assert result.precision == 1.0
    assert result.recall == 0.5
    assert result.f1 == pytest.approx(2 / 3)
    assert result.matched_finding_ids == [match.finding_id]
    assert result.missed_truth_ids == ["truth-b"]


def test_false_discovery_rate_uses_predicted_positives_as_denominator() -> None:
    findings = [
        make_finding(path="src/app.py", start=10, end=10),
        make_finding(path="false.py", start=1, end=1),
    ]

    result = score_benchmark(make_report(findings), truth_fixture())

    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_discovery_rate == 0.5


def test_zero_safe_metrics_for_empty_report_and_truth() -> None:
    result = score_benchmark(make_report([]), GroundTruth(schema_version="1.0", expected=[]))

    assert result.true_positives == 0
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0
    assert result.false_discovery_rate == 0.0
