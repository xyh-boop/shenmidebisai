import json
from datetime import UTC, datetime

from aegisflow.contracts import (
    AgentDecision,
    Diagnostic,
    EvidenceEdge,
    EvidenceNode,
    Finding,
    ReportEnvelope,
    RunMetadata,
    RunMetrics,
    build_finding_id,
)
from aegisflow.reporting import render_html, render_json, write_report


def report_fixture(*, hostile: bool = False) -> ReportEnvelope:
    payload = "<script>alert('owned')</script>" if hostile else "request.args['cmd']"
    nodes = [
        EvidenceNode(
            node_id="source",
            kind="source",
            path="src/app.py",
            line=3,
            symbol="handler",
            snippet=payload,
            description=f"Untrusted input {payload}",
        ),
        EvidenceNode(
            node_id="sink",
            kind="sink",
            path="src/app.py",
            line=9,
            symbol="run",
            snippet=f"subprocess.run({payload}, shell=True)",
            description="Shell execution sink",
        ),
    ]
    finding = Finding(
        finding_id=build_finding_id("AF-CMD-001", "src/app.py", 3, 9, nodes),
        rule_id="AF-CMD-001",
        cwe="CWE-78",
        title=f"Command injection {payload}",
        severity="high",
        confidence=0.94,
        disposition="confirmed",
        language="python",
        path="src/app.py",
        start_line=3,
        end_line=9,
        nodes=nodes,
        edges=[EvidenceEdge(source_id="source", target_id="sink", relation="flows_to")],
        decisions=[
            AgentDecision(
                agent="scout",
                verdict="confirm",
                confidence=0.94,
                reason_codes=["COMPLETE_PATH"],
                supporting_node_ids=["source", "sink"],
                counterevidence_node_ids=[],
                rationale=f"The tainted path is complete. {payload}",
                latency_ms=2,
            ),
            AgentDecision(
                agent="critic",
                verdict="needs_review",
                confidence=0.30,
                reason_codes=["NO_GUARD"],
                supporting_node_ids=[],
                counterevidence_node_ids=["source"],
                rationale="No recognized guard was found.",
                latency_ms=3,
            ),
        ],
        remediation=f"Use an argument vector. {payload}",
    )
    now = datetime(2026, 8, 14, 12, tzinfo=UTC)
    return ReportEnvelope(
        schema_version="1.0",
        tool_version="0.1.0",
        run=RunMetadata(
            run_id="test-run",
            mode="offline",
            root=f"repo {payload}" if hostile else "repo",
            started_at=now,
            completed_at=now,
            configuration_digest="0" * 64,
        ),
        metrics=RunMetrics(
            files_scanned=1,
            lines_scanned=12,
            elapsed_ms=20,
            time_to_first_high_ms=10,
            candidates_total=1,
            findings_confirmed=1,
            findings_rejected=0,
            human_review_required=0,
            model_requests=1,
            prompt_tokens=120,
            completion_tokens=30,
            estimated_cost_usd=0.0012,
        ),
        findings=[finding],
        diagnostics=[
            Diagnostic(
                code="PARSE_NOTE",
                level="warning",
                message=f"Diagnostic {payload}",
                path="src/app.py",
                line=11,
            )
        ],
    )


def test_render_json_is_canonical_and_stable() -> None:
    report = report_fixture()

    rendered = render_json(report)

    assert rendered == report.canonical_json()
    assert json.loads(rendered) == report.model_dump(mode="json")
    assert rendered == render_json(ReportEnvelope.model_validate_json(rendered))


def test_html_is_self_contained_responsive_and_complete() -> None:
    rendered = render_html(report_fixture())

    assert 'lang="zh-CN"' in rendered
    assert "安全态势" in rendered
    assert "运行指标" in rendered
    assert "路由与决策时间线" in rendered
    assert "证据图" in rendered
    assert "支持证据与反证" in rendered
    assert "修复建议" in rendered
    assert "输入 Token" in rendered
    assert "诊断信息" in rendered
    assert "高危" in rendered
    assert "已确认" in rendered
    assert "发现 Agent" in rendered
    assert "@media (max-width: 430px)" in rendered
    assert ".subtitle" in rendered and "overflow-wrap: anywhere" in rendered
    assert ".datum dd" in rendered and "word-break: break-word" in rendered
    assert "html, body { max-width: 100%; overflow-x: hidden; }" in rendered
    assert ".shell { min-width: 0;" in rendered
    assert "max-width: 100%;" in rendered
    assert ".run-grid { grid-template-columns: minmax(0, 1fr); }" in rendered
    assert ".metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }" in rendered
    assert (
        ".severity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); overflow-x: hidden; }"
    ) in rendered
    assert 'src="http' not in rendered
    assert 'href="http' not in rendered
    assert "<script" not in rendered


def test_html_escapes_all_repository_controlled_content() -> None:
    rendered = render_html(report_fixture(hostile=True))

    assert "<script>alert('owned')</script>" not in rendered
    assert "&lt;script&gt;alert" in rendered
    assert rendered.count("&lt;script&gt;") >= 5


def test_write_report_writes_requested_format(tmp_path) -> None:
    report = report_fixture()
    json_path = tmp_path / "nested" / "report.json"
    html_path = tmp_path / "report.html"

    write_report(report, json_path, "json")
    write_report(report, html_path, "html")

    assert json_path.read_text(encoding="utf-8") == render_json(report)
    assert html_path.read_text(encoding="utf-8") == render_html(report)


def test_empty_report_has_explicit_empty_states() -> None:
    values = report_fixture().model_dump()
    values["findings"] = []
    values["diagnostics"] = []

    rendered = render_html(ReportEnvelope.model_validate(values))

    assert "本次运行未记录漏洞发现" in rendered
    assert "未输出诊断信息" in rendered
