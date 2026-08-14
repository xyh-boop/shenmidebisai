from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegisflow.cli import app

runner = CliRunner()


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
    source = tmp_path / "app.py"
    source.write_text("import os\nvalue = input()\nos.system(value)\n", encoding="utf-8")
    output = tmp_path / "artifacts" / "report.json"
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--output", str(output), "--fail-on", "none"]
    )
    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["metrics"]["files_scanned"] == 1
    assert payload["run"]["configuration_digest"]
    blocked = runner.invoke(app, ["scan", str(tmp_path), "--output", str(source)])
    assert blocked.exit_code == 2


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
    assert "precision=1.000" in result.stdout


def test_agent_requires_model_config_and_key(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--mode", "agent"])
    assert result.exit_code == 2
