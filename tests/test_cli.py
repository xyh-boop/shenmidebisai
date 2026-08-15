from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from aegisflow import cli as cli_module
from aegisflow.cli import app
from aegisflow.contracts import AnalysisResult, BenchmarkResult, Diagnostic

runner = CliRunner()


def write_source(root: Path, content: str = "print('ok')\n") -> Path:
    source = root / "app.py"
    source.write_text(content, encoding="utf-8")
    return source


def artifact_output(root: Path, name: str) -> Path:
    directory = root / "artifacts"
    directory.mkdir(exist_ok=True)
    return directory / name


def write_model_config(
    path: Path,
    *,
    base_url: str = "https://api.example.test/v1",
    require_agent_success: bool = False,
    max_entries: int = 100,
) -> None:
    path.write_text(
        f"""require_agent_success = {str(require_agent_success).lower()}

[scan]
max_files = 20
max_total_bytes = 100000
max_file_bytes = 10000
max_depth = 8
max_entries = {max_entries}
max_directories = 20
max_path_bytes = 1024

[analysis]
languages = ["python"]
enabled_rule_ids = []
max_snippet_bytes = 4096

[routing]
auto_confirm_confidence = 0.90
agent_review_severities = ["critical", "high"]

[provider]
base_url = "{base_url}"
model = "test-model"
api_key_env = "AEGISFLOW_TEST_KEY"
allow_insecure_http = {str(base_url.startswith("http://")).lower()}
timeout_seconds = 5.0
max_context_bytes = 4096
max_response_bytes = 4096
input_cost_per_million_tokens = 0.0
output_cost_per_million_tokens = 0.0
""",
        encoding="utf-8",
    )


class DummyProvider:
    def __init__(self, _config: object) -> None:
        pass

    def close(self) -> None:
        pass


def test_rules_json_and_doctor() -> None:
    rules = runner.invoke(app, ["rules", "--format", "json"])
    assert rules.exit_code == 0
    assert {item["rule_id"] for item in json.loads(rules.stdout)} == {
        "AF-CMD-001",
        "AF-SQL-001",
        "AF-PATH-001",
        "AF-DESER-001",
    }
    doctor = runner.invoke(app, ["doctor"])
    assert doctor.exit_code == 0
    assert "parsers" in doctor.stdout


def test_scan_json_and_source_output_guard(tmp_path: Path) -> None:
    source = write_source(tmp_path, "import os\nvalue = input()\nos.system(value)\n")
    output = artifact_output(tmp_path, "report.json")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"]
    )
    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metrics"]["files_scanned"] == 1
    assert payload["run"]["configuration_digest"]
    if cli_module._uses_path_output_fallback():
        assert "cannot fully prevent a concurrent Windows junction replacement" in result.output
    blocked = runner.invoke(app, ["scan", str(tmp_path), "--output", str(source)])
    assert blocked.exit_code == 3


def test_scan_returns_one_for_finding_threshold(tmp_path: Path) -> None:
    write_source(tmp_path, "import os\nvalue = input()\nos.system(value)\n")
    output = artifact_output(tmp_path, "report.json")

    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(output)])

    assert result.exit_code == 1
    assert output.exists()


def test_first_high_time_is_sampled_before_later_files_and_workflow_finish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path, "import os\nvalue = input()\nos.system(value)\n")
    (tmp_path / "z.py").write_text("value = 1\n", encoding="utf-8")
    clock = {"value": 10.0}
    analyzed_paths: list[str] = []
    original_analyze = cli_module.analyze_sources

    def timed_analyze(sources: object, config: object) -> AnalysisResult:
        source_items = tuple(sources)  # type: ignore[arg-type]
        assert len(source_items) == 1
        analyzed_paths.append(source_items[0].path)
        result = original_analyze(source_items, config)  # type: ignore[arg-type]
        clock["value"] = 11.0 if source_items[0].path == "app.py" else 20.0
        return result

    monkeypatch.setattr(cli_module, "analyze_sources", timed_analyze)
    monkeypatch.setattr(cli_module.time, "perf_counter", lambda: clock["value"])
    output = artifact_output(tmp_path, "report.json")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"],
    )

    assert result.exit_code == 0
    metrics = json.loads(output.read_text(encoding="utf-8"))["metrics"]
    assert analyzed_paths == ["app.py", "z.py"]
    assert metrics["time_to_first_high_ms"] == 1_000
    assert metrics["elapsed_ms"] == 10_000


def test_scan_html(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nvalue = input()\nos.system(value)\n", encoding="utf-8"
    )
    output = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "html", "--output", str(output), "--fail-on", "none"],
    )
    assert result.exit_code == 0
    assert "安全态势" in output.read_text(encoding="utf-8")


def test_benchmark_bundled_fixtures(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            str(root / "benchmarks" / "fixtures"),
            "--ground-truth",
            str(root / "benchmarks" / "ground_truth.json"),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["true_positives"] == 8
    assert data["false_positives"] == 0
    assert data["false_discovery_rate"] == 0.0
    assert "false_positive_rate" not in data
    assert "precision=1.000" in result.stdout
    assert "false_discovery_rate=0.000" in result.stdout


def test_benchmark_missing_ground_truth_exits_three(tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    missing_truth = tmp_path / "missing-ground-truth.json"
    output = tmp_path / "benchmark.json"

    result = runner.invoke(
        app,
        [
            "benchmark",
            str(fixture_root),
            "--ground-truth",
            str(missing_truth),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 3
    assert "ground-truth file does not exist" in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


def test_agent_requires_model_config_and_key(tmp_path: Path) -> None:
    write_source(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--mode", "agent"])
    assert result.exit_code == 2


def test_incomplete_analysis_writes_audit_report_then_exits_three(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path, "this is not valid python")
    diagnostic = Diagnostic(
        code="python_parse_error",
        level="error",
        message="could not parse source",
        path="app.py",
    )
    monkeypatch.setattr(
        cli_module,
        "analyze_sources",
        lambda _sources, _config: AnalysisResult(
            candidates=[], diagnostics=[diagnostic], complete=False
        ),
    )
    output = artifact_output(tmp_path, "report.json")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"],
    )

    assert result.exit_code == 3
    assert "Traceback" not in result.output
    assert json.loads(output.read_text(encoding="utf-8"))["diagnostics"][0]["code"] == (
        "python_parse_error"
    )


def test_real_malformed_source_exits_three_with_audit_diagnostic(tmp_path: Path) -> None:
    write_source(tmp_path, "def broken(:\n")
    output = artifact_output(tmp_path, "report.json")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"],
    )

    assert result.exit_code == 3
    diagnostics = json.loads(output.read_text(encoding="utf-8"))["diagnostics"]
    assert diagnostics and diagnostics[0]["level"] == "error"
    assert "Traceback" not in result.output


def test_configured_ingest_limit_writes_report_and_exits_three(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    write_source(repository)
    (repository / "extra.txt").write_text("extra", encoding="utf-8")
    config = tmp_path / "model.toml"
    write_model_config(config, max_entries=1)
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            str(repository),
            "--model-config",
            str(config),
            "--output",
            str(output),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 3
    diagnostics = json.loads(output.read_text(encoding="utf-8"))["diagnostics"]
    assert [item["code"] for item in diagnostics] == ["max_entries_exceeded"]


def test_unknown_config_is_rejected_without_echoing_a_traceback(tmp_path: Path) -> None:
    write_source(tmp_path)
    config = tmp_path / "invalid.toml"
    config.write_text("[unknown]\nenabled = true\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--model-config", str(config), "--fail-on", "none"],
    )

    assert result.exit_code == 2
    assert "Extra inputs are not permitted" in result.output
    assert "Traceback" not in result.output


def test_full_config_and_budget_change_configuration_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path)
    config = tmp_path / "model.toml"
    write_model_config(config)
    monkeypatch.setenv("AEGISFLOW_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr(cli_module, "OpenAICompatibleProvider", DummyProvider)
    monkeypatch.setattr(
        cli_module,
        "process_candidates",
        lambda _candidates, _policy, *, mode, provider, budget: SimpleNamespace(
            findings=[], budget=budget, agent_failures=()
        ),
    )
    first_output = artifact_output(tmp_path, "first.json")
    second_output = artifact_output(tmp_path, "second.json")

    first = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--mode",
            "agent",
            "--model-config",
            str(config),
            "--max-requests",
            "1",
            "--output",
            str(first_output),
            "--fail-on",
            "none",
        ],
    )
    second = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--mode",
            "agent",
            "--model-config",
            str(config),
            "--max-requests",
            "2",
            "--output",
            str(second_output),
            "--fail-on",
            "none",
        ],
    )

    assert first.exit_code == second.exit_code == 0
    first_digest = json.loads(first_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    second_digest = json.loads(second_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    assert first_digest != second_digest


def test_effective_scan_configuration_changes_digest(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    write_source(repository)
    first_config = tmp_path / "first.toml"
    second_config = tmp_path / "second.toml"
    write_model_config(first_config, max_entries=100)
    write_model_config(second_config, max_entries=101)
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    first = runner.invoke(
        app,
        [
            "scan",
            str(repository),
            "--model-config",
            str(first_config),
            "--output",
            str(first_output),
            "--fail-on",
            "none",
        ],
    )
    second = runner.invoke(
        app,
        [
            "scan",
            str(repository),
            "--model-config",
            str(second_config),
            "--output",
            str(second_output),
            "--fail-on",
            "none",
        ],
    )

    assert first.exit_code == second.exit_code == 0
    first_digest = json.loads(first_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    second_digest = json.loads(second_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    assert first_digest != second_digest


def test_require_agent_success_maps_failures_to_exit_four_and_can_be_overridden(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path)
    config = tmp_path / "model.toml"
    write_model_config(config)
    monkeypatch.setenv("AEGISFLOW_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr(cli_module, "OpenAICompatibleProvider", DummyProvider)
    monkeypatch.setattr(
        cli_module,
        "process_candidates",
        lambda _candidates, _policy, *, mode, provider, budget: SimpleNamespace(
            findings=[], budget=budget, agent_failures=("provider_timeout",)
        ),
    )
    strict_output = artifact_output(tmp_path, "strict.json")
    relaxed_output = artifact_output(tmp_path, "relaxed.json")
    common = ["scan", str(tmp_path), "--mode", "agent", "--model-config", str(config)]

    strict = runner.invoke(
        app,
        [*common, "--require-agent-success", "--output", str(strict_output), "--fail-on", "none"],
    )
    relaxed = runner.invoke(
        app,
        [
            *common,
            "--no-require-agent-success",
            "--output",
            str(relaxed_output),
            "--fail-on",
            "none",
        ],
    )

    assert strict.exit_code == 4
    assert relaxed.exit_code == 0
    assert strict_output.exists() and relaxed_output.exists()
    assert "Traceback" not in strict.output
    strict_digest = json.loads(strict_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    relaxed_digest = json.loads(relaxed_output.read_text(encoding="utf-8"))["run"][
        "configuration_digest"
    ]
    assert strict_digest != relaxed_digest


def test_loopback_http_emits_warning_without_network_access(tmp_path: Path) -> None:
    write_source(tmp_path)
    config = tmp_path / "loopback.toml"
    write_model_config(config, base_url="http://127.0.0.1:8000/v1")
    output = artifact_output(tmp_path, "report.json")

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--model-config",
            str(config),
            "--output",
            str(output),
            "--fail-on",
            "none",
        ],
    )

    assert result.exit_code == 0
    assert "loopback HTTP" in result.output
    assert "127.0.0.1" not in result.output


def test_public_http_provider_is_rejected_without_network_access(tmp_path: Path) -> None:
    write_source(tmp_path)
    config = tmp_path / "public-http.toml"
    write_model_config(config, base_url="http://api.example.test/v1")

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--model-config", str(config), "--fail-on", "none"],
    )

    assert result.exit_code == 2
    assert "loopback host" in result.output
    assert "Traceback" not in result.output


def test_missing_agent_key_degrades_relaxed_and_is_strict_exit_four(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path, "import os\ndef run(command):\n    os.system(command)\n")
    config = tmp_path / "model.toml"
    write_model_config(config)
    monkeypatch.delenv("AEGISFLOW_TEST_KEY", raising=False)
    relaxed_output = tmp_path / "relaxed.json"
    strict_output = tmp_path / "strict.json"
    common = ["scan", str(tmp_path), "--mode", "agent", "--model-config", str(config)]

    relaxed = runner.invoke(
        app,
        [
            *common,
            "--no-require-agent-success",
            "--output",
            str(relaxed_output),
            "--fail-on",
            "none",
        ],
    )
    strict = runner.invoke(
        app,
        [*common, "--require-agent-success", "--output", str(strict_output), "--fail-on", "none"],
    )

    assert relaxed.exit_code == 0
    assert strict.exit_code == 4
    relaxed_payload = json.loads(relaxed_output.read_text(encoding="utf-8"))
    strict_payload = json.loads(strict_output.read_text(encoding="utf-8"))
    assert relaxed_payload["diagnostics"][0]["code"] == ("agent_provider_credential_unavailable")
    assert relaxed_payload["findings"][0]["disposition"] == "needs_review"
    assert strict_payload["findings"][0]["disposition"] == "needs_review"
    assert "Traceback" not in relaxed.output + strict.output


def test_windows_path_fallback_requires_existing_parent_directory(
    tmp_path: Path,
) -> None:
    if os.name != "nt" or not cli_module._uses_path_output_fallback():
        pytest.skip("directory-handle atomic replacement is available on this platform")
    write_source(tmp_path)
    output = tmp_path / "missing-parent" / "report.json"

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"],
    )

    assert result.exit_code == 3
    assert "pre-existing" in result.output
    assert "Traceback" not in result.output


def test_path_fallback_rechecks_parent_after_temporary_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not cli_module._uses_path_output_fallback():
        pytest.skip("directory-handle atomic replacement is available on this platform")
    parent = tmp_path / "existing"
    parent.mkdir()
    output = parent / "report.json"
    original_validate = cli_module._validate_path_component
    parent_checks = 0

    def simulate_parent_replacement(path: Path, *, directory: bool) -> object:
        nonlocal parent_checks
        result = original_validate(path, directory=directory)
        if path == parent:
            parent_checks += 1
            if parent_checks == 3:
                return SimpleNamespace(st_dev=result.st_dev, st_ino=result.st_ino + 1)
        return result

    monkeypatch.setattr(cli_module, "_validate_path_component", simulate_parent_replacement)

    with pytest.raises(OSError, match="changed after temporary file creation"):
        cli_module._safe_write_text(output, "content")

    assert not output.exists()
    assert not list(parent.glob(".aegisflow-*.tmp"))


def test_strict_agent_requires_agent_mode(tmp_path: Path) -> None:
    write_source(tmp_path)
    config = tmp_path / "model.toml"
    write_model_config(config)

    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--model-config",
            str(config),
            "--require-agent-success",
        ],
    )

    assert result.exit_code == 2
    assert "requires --mode agent" in result.output


def test_outputs_may_not_overwrite_control_files(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    write_source(repository)
    config = tmp_path / "model.toml"
    write_model_config(config)
    scan_result = runner.invoke(
        app,
        [
            "scan",
            str(repository),
            "--model-config",
            str(config),
            "--output",
            str(config),
        ],
    )

    ground_truth = tmp_path / "truth.json"
    ground_truth.write_text('{"schema_version":"1.0","expected":[]}', encoding="utf-8")
    benchmark_result = runner.invoke(
        app,
        [
            "benchmark",
            str(repository),
            "--ground-truth",
            str(ground_truth),
            "--output",
            str(ground_truth),
        ],
    )

    assert scan_result.exit_code == benchmark_result.exit_code == 3
    assert "require_agent_success" in config.read_text(encoding="utf-8")
    assert json.loads(ground_truth.read_text(encoding="utf-8"))["expected"] == []


@pytest.mark.parametrize("link_kind", ["parent", "target"])
def test_report_output_rejects_symlink_escape(
    link_kind: str,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    write_source(repository)
    sentinel = outside / "sentinel.json"
    sentinel.write_text("unchanged", encoding="utf-8")
    artifacts = repository / "artifacts"
    if link_kind == "parent":
        try:
            artifacts.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symbolic links are not available: {exc}")
        output = artifacts / "escaped.json"
    else:
        artifacts.mkdir()
        output = artifacts / "report.json"
        try:
            output.symlink_to(sentinel)
        except (NotImplementedError, OSError) as exc:
            pytest.skip(f"symbolic links are not available: {exc}")

    result = runner.invoke(
        app,
        ["scan", str(repository), "--output", str(output), "--fail-on", "none"],
    )

    assert result.exit_code == 3
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert not (outside / "escaped.json").exists()
    assert "Traceback" not in result.output


def test_report_write_failure_exits_three_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path)
    output = artifact_output(tmp_path, "report.json")

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(cli_module.os, "replace", fail_replace)

    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", str(output)],
    )

    assert result.exit_code == 3
    assert "simulated write failure" in result.output
    assert "Traceback" not in result.output
    assert not output.exists()
    assert not list(output.parent.glob(".aegisflow-*.tmp"))


def test_benchmark_write_failure_exits_three_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    ground_truth = tmp_path / "truth.json"
    ground_truth.write_text('{"schema_version":"1.0","expected":[]}', encoding="utf-8")
    monkeypatch.setattr(
        cli_module,
        "_run_scan",
        lambda *args, **kwargs: SimpleNamespace(complete=True, report=object()),
    )
    monkeypatch.setattr(
        cli_module,
        "score_benchmark",
        lambda _report, _truth: BenchmarkResult(
            true_positives=0,
            false_positives=0,
            false_negatives=0,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            false_discovery_rate=0.0,
        ),
    )
    output = tmp_path / "benchmark.json"

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(cli_module.os, "replace", fail_replace)

    result = runner.invoke(
        app,
        [
            "benchmark",
            str(fixture_root),
            "--ground-truth",
            str(ground_truth),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 3
    assert "simulated write failure" in result.output
    assert "Traceback" not in result.output
    assert not output.exists()
    assert not list(tmp_path.glob(".aegisflow-*.tmp"))


def test_control_file_size_limits_map_to_cli_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    write_source(tmp_path)
    oversized_config = tmp_path / "oversized.toml"
    oversized_config.write_text("x" * 32, encoding="utf-8")
    monkeypatch.setattr(cli_module, "_MAX_TOML_BYTES", 16)
    config_result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--model-config", str(oversized_config)],
    )

    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    oversized_truth = tmp_path / "oversized.json"
    oversized_truth.write_text("{" + " " * 32 + "}", encoding="utf-8")
    monkeypatch.setattr(cli_module, "_MAX_GROUND_TRUTH_BYTES", 16)
    truth_result = runner.invoke(
        app,
        [
            "benchmark",
            str(fixture_root),
            "--ground-truth",
            str(oversized_truth),
            "--output",
            str(tmp_path / "benchmark.json"),
        ],
    )

    assert config_result.exit_code == 2
    assert truth_result.exit_code == 3
    assert "Traceback" not in config_result.output + truth_result.output
