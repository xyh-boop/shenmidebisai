from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegisflow.config import (
    AnalysisConfig,
    AppConfig,
    ProviderConfig,
    RoutingPolicy,
    ScanLimits,
)
from aegisflow.contracts import (
    AgentDecision,
    AnalysisResult,
    BenchmarkResult,
    BudgetState,
    Candidate,
    Diagnostic,
    Disposition,
    EvidenceEdge,
    EvidenceNode,
    Finding,
    ReportEnvelope,
    RunMetadata,
    RunMetrics,
    build_finding_id,
    normalize_repo_path,
)


def node(node_id: str, kind: str, line: int) -> EvidenceNode:
    return EvidenceNode(
        node_id=node_id,
        kind=kind,
        path="src/app.py",
        line=line,
        symbol="handler",
        snippet=f"line {line}",
        description=f"{kind} evidence",
    )


def valid_finding(**changes: object) -> Finding:
    nodes = [node("sink", "sink", 9), node("source", "source", 3)]
    values: dict[str, object] = {
        "finding_id": build_finding_id("PY-CMD-001", "src/app.py", 3, 9, nodes),
        "rule_id": "PY-CMD-001",
        "cwe": "CWE-78",
        "title": "User input reaches a shell",
        "severity": "high",
        "confidence": 0.94,
        "disposition": "confirmed",
        "language": "python",
        "path": "src/app.py",
        "start_line": 3,
        "end_line": 9,
        "nodes": nodes,
        "edges": [EvidenceEdge(source_id="source", target_id="sink", relation="flows_to")],
        "decisions": [
            AgentDecision(
                agent="scout",
                verdict="confirm",
                confidence=0.94,
                reason_codes=["TAINT_PATH", "DANGEROUS_SINK"],
                supporting_node_ids=["source", "sink"],
                counterevidence_node_ids=[],
                rationale="A complete local source-to-sink path exists.",
                latency_ms=2,
            )
        ],
        "remediation": "Avoid the shell and pass a fixed argument vector.",
    }
    values.update(changes)
    return Finding.model_validate(values)


def valid_candidate(**changes: object) -> Candidate:
    finding = valid_finding()
    values = {
        "candidate_id": "candidate-python-command",
        "rule_id": finding.rule_id,
        "cwe": finding.cwe,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "language": finding.language,
        "path": finding.path,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "nodes": finding.nodes,
        "edges": finding.edges,
        "remediation": finding.remediation,
    }
    values.update(changes)
    return Candidate.model_validate(values)


def metrics() -> RunMetrics:
    return RunMetrics(
        files_scanned=1,
        lines_scanned=12,
        elapsed_ms=20,
        time_to_first_high_ms=10,
        candidates_total=1,
        findings_confirmed=1,
        findings_rejected=0,
        human_review_required=0,
        model_requests=0,
        prompt_tokens=0,
        completion_tokens=0,
        estimated_cost_usd=0.0,
    )


def test_public_enum_values_and_confidence_bounds_are_enforced() -> None:
    assert valid_finding().severity.value == "high"
    assert valid_finding().disposition == Disposition.CONFIRMED

    with pytest.raises(ValidationError, match="less than or equal to 1"):
        valid_finding(confidence=1.01)

    with pytest.raises(ValidationError, match="Input should be"):
        valid_finding(severity="urgent")


def test_graph_edges_and_agent_decisions_must_reference_known_nodes() -> None:
    with pytest.raises(ValidationError, match="edge references unknown evidence nodes"):
        valid_finding(
            edges=[EvidenceEdge(source_id="source", target_id="missing", relation="flows_to")]
        )

    bad_decision = AgentDecision(
        agent="critic",
        verdict="reject",
        confidence=0.7,
        reason_codes=["SAFE_GUARD"],
        supporting_node_ids=[],
        counterevidence_node_ids=["missing"],
        rationale="A guard may reject hostile input.",
        latency_ms=1,
    )
    with pytest.raises(ValidationError, match="decision references unknown evidence nodes"):
        valid_finding(decisions=[bad_decision])


def test_confirmed_injection_requires_source_to_sink_path() -> None:
    with pytest.raises(ValidationError, match="source-to-sink evidence path"):
        valid_finding(edges=[])


@pytest.mark.parametrize(
    "unsafe_path",
    ["../secret.py", "/tmp/app.py", "src\\app.py", "C:/repo/app.py", "src//app.py"],
)
def test_repository_paths_must_be_normalized_posix_relative(unsafe_path: str) -> None:
    with pytest.raises(ValueError):
        normalize_repo_path(unsafe_path)


def test_canonical_serialization_and_report_order_are_stable() -> None:
    first = valid_finding()
    other_nodes = [node("sink-2", "sink", 20), node("source-2", "source", 15)]
    other_nodes = [EvidenceNode(**{**item.model_dump(), "path": "a.py"}) for item in other_nodes]
    second = valid_finding(
        finding_id=build_finding_id("PY-CMD-002", "a.py", 15, 20, other_nodes),
        rule_id="PY-CMD-002",
        path="a.py",
        start_line=15,
        end_line=20,
        nodes=other_nodes,
        edges=[EvidenceEdge(source_id="source-2", target_id="sink-2", relation="flows_to")],
        decisions=[],
    )
    run = RunMetadata(
        run_id="offline-test",
        mode="offline",
        root=".",
        started_at=datetime(2026, 8, 14, tzinfo=UTC),
        completed_at=datetime(2026, 8, 14, tzinfo=UTC),
        configuration_digest="0" * 64,
    )
    report_a = ReportEnvelope(
        schema_version="1.0",
        tool_version="0.1.0",
        run=run,
        metrics=metrics(),
        findings=[first, second],
        diagnostics=[],
    )
    report_b = ReportEnvelope(
        schema_version="1.0",
        tool_version="0.1.0",
        run=run,
        metrics=metrics(),
        findings=[second, first],
        diagnostics=[],
    )

    assert [finding.path for finding in report_a.findings] == ["a.py", "src/app.py"]
    assert report_a.canonical_json() == report_b.canonical_json()


def test_finding_id_is_stable_across_node_input_order() -> None:
    nodes = [node("source", "source", 3), node("sink", "sink", 9)]
    assert build_finding_id("PY-CMD-001", "src/app.py", 3, 9, nodes) == build_finding_id(
        "PY-CMD-001", "src/app.py", 3, 9, list(reversed(nodes))
    )


def test_finding_id_must_match_the_validated_evidence() -> None:
    with pytest.raises(ValidationError, match="does not match"):
        valid_finding(finding_id="f" * 64)


def test_analysis_result_is_stable_and_rejects_inconsistent_completeness() -> None:
    later = valid_candidate()
    earlier_nodes = [EvidenceNode(**{**item.model_dump(), "path": "a.py"}) for item in later.nodes]
    earlier = valid_candidate(
        candidate_id="candidate-earlier",
        path="a.py",
        nodes=earlier_nodes,
    )
    warning = Diagnostic(code="warning", level="warning", message="warning", path="z.py")
    error = Diagnostic(code="parse_error", level="error", message="parse failed", path="a.py")

    first = AnalysisResult(
        candidates=[later, earlier], diagnostics=[warning, error], complete=False
    )
    second = AnalysisResult(
        candidates=[earlier, later], diagnostics=[error, warning], complete=False
    )

    assert [item.candidate_id for item in first.candidates] == [
        "candidate-earlier",
        "candidate-python-command",
    ]
    assert [item.code for item in first.diagnostics] == ["parse_error", "warning"]
    assert first.canonical_json() == second.canonical_json()

    with pytest.raises(ValidationError, match="complete analysis may not contain error"):
        AnalysisResult(candidates=[], diagnostics=[error], complete=True)
    with pytest.raises(ValidationError, match="incomplete analysis requires an error"):
        AnalysisResult(candidates=[], diagnostics=[warning], complete=False)
    with pytest.raises(ValidationError, match="candidate_id values must be unique"):
        AnalysisResult(candidates=[later, later], diagnostics=[], complete=True)


def test_benchmark_contract_uses_false_discovery_rate() -> None:
    values = {
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 0,
        "precision": 0.5,
        "recall": 1.0,
        "f1": 2 / 3,
        "false_discovery_rate": 0.5,
    }
    result = BenchmarkResult.model_validate(values)

    assert result.false_discovery_rate == 0.5
    assert not hasattr(result, "false_positive_rate")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        BenchmarkResult.model_validate(
            {**values, "false_positive_rate": values["false_discovery_rate"]}
        )

    assert metrics().false_discovery_rate is None
    with pytest.raises(ValidationError, match="less than or equal to 1"):
        RunMetrics(**{**metrics().model_dump(), "false_discovery_rate": 1.01})


def test_scan_and_analysis_configuration_reject_unsafe_values() -> None:
    with pytest.raises(ValidationError, match="max_file_bytes"):
        ScanLimits(max_total_bytes=10, max_file_bytes=11)

    with pytest.raises(ValidationError, match="duplicates"):
        AnalysisConfig(languages=["python", "python"])

    with pytest.raises(ValidationError, match="absolute HTTPS or loopback HTTP"):
        ProviderConfig(base_url="file:///tmp/provider", model="test")

    with pytest.raises(ValidationError, match="must not contain credentials"):
        ProviderConfig(base_url="https://user:secret@example.test/v1", model="test")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_files", 10**12),
        ("max_total_bytes", 10**15),
        ("max_file_bytes", 10**12),
        ("max_depth", 10**6),
        ("max_entries", 10**12),
        ("max_directories", 10**12),
        ("max_path_bytes", 10**12),
    ],
)
def test_scan_limits_have_absolute_hard_caps(field: str, value: int) -> None:
    with pytest.raises(ValidationError, match="less than or equal to"):
        ScanLimits.model_validate({field: value})


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000/v1",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
    ],
)
def test_provider_allows_only_explicit_loopback_http(base_url: str) -> None:
    with pytest.raises(ValidationError, match="allow_insecure_http=true"):
        ProviderConfig(base_url=base_url, model="test")

    config = ProviderConfig(
        base_url=base_url,
        model="test",
        allow_insecure_http=True,
    )
    assert config.uses_insecure_http


def test_provider_rejects_public_http_and_limits_response_bytes() -> None:
    with pytest.raises(ValidationError, match="loopback host"):
        ProviderConfig(
            base_url="http://api.example.test/v1",
            model="test",
            allow_insecure_http=True,
        )

    secure = ProviderConfig(base_url="https://api.example.test/v1", model="test")
    assert not secure.uses_insecure_http
    assert (
        ProviderConfig(base_url="https://api.example.test/v1/", model="test").base_url
        == secure.base_url
    )
    assert secure.max_response_bytes > 0
    with pytest.raises(ValidationError, match="less than or equal to"):
        ProviderConfig(
            base_url="https://api.example.test/v1",
            model="test",
            max_response_bytes=10**12,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://alice:hunter2@example.test/v1",
        "https://example.test/v1?token=hunter2",
    ],
)
def test_provider_validation_errors_do_not_echo_url_secrets(base_url: str) -> None:
    with pytest.raises(ValidationError) as captured:
        ProviderConfig(base_url=base_url, model="test")

    rendered = str(captured.value)
    assert "alice" not in rendered
    assert "hunter2" not in rendered
    assert "token=" not in rendered


def test_strict_agent_policy_and_removed_dead_routing_field_are_validated() -> None:
    with pytest.raises(ValidationError, match="provider configuration"):
        AppConfig(require_agent_success=True)

    provider = ProviderConfig(base_url="https://api.example.test/v1", model="test")
    strict = AppConfig(provider=provider, require_agent_success=True)
    assert strict.require_agent_success

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RoutingPolicy(auto_reject_confidence=0.95)


def test_budget_state_checks_all_limits_before_review() -> None:
    budget = BudgetState(
        max_requests=2,
        max_prompt_tokens=100,
        max_completion_tokens=50,
        max_cost_usd=0.25,
        requests_used=1,
        prompt_tokens_used=80,
        completion_tokens_used=10,
        cost_usd_used=0.10,
    )

    assert budget.can_review(prompt_tokens=20, completion_tokens=40, estimated_cost_usd=0.15)
    assert not budget.can_review(prompt_tokens=21)
    assert not budget.can_review(estimated_cost_usd=0.151)


def test_contracts_forbid_unrecognized_fields() -> None:
    values = valid_finding().model_dump()
    values["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Finding.model_validate(values)
