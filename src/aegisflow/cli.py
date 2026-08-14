"""Typer entry points for safe, deterministic AegisFlow scans."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from aegisflow import __version__
from aegisflow.analyzers import RULES, analyze_sources
from aegisflow.benchmark import load_ground_truth, score_benchmark
from aegisflow.config import AppConfig, ProviderConfig, RoutingPolicy
from aegisflow.contracts import (
    BudgetState,
    ReportEnvelope,
    RunMetadata,
    RunMetrics,
    ScanMode,
)
from aegisflow.ingest import discover_repository
from aegisflow.providers import OpenAICompatibleProvider
from aegisflow.reporting import write_report
from aegisflow.workflow import process_candidates

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}


def _fail(message: str, code: int) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code)


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _fail(f"could not load model configuration: {exc}", 2)
    return payload


def _app_config(
    *,
    mode: ScanMode,
    model_config: Path | None,
    max_requests: int,
    max_prompt_tokens: int,
    max_completion_tokens: int,
    max_cost_usd: float,
) -> tuple[AppConfig, ProviderConfig | None, BudgetState | None]:
    provider = None
    payload: dict[str, Any] = {}
    if model_config is not None:
        payload = _load_toml(model_config)
        try:
            provider = ProviderConfig.model_validate(payload.get("provider", {}))
        except Exception as exc:
            _fail(f"invalid provider configuration: {exc}", 2)
    if mode == ScanMode.AGENT:
        if provider is None:
            _fail("agent mode requires --model-config", 2)
        if not os.environ.get(provider.api_key_env):
            _fail(f"missing provider credential environment variable: {provider.api_key_env}", 2)
        routing_payload = payload.get("routing", {})
    else:
        routing_payload = payload.get("routing", {}) if payload else {}
    try:
        routing = RoutingPolicy.model_validate(routing_payload)
        config = AppConfig(routing=routing, provider=provider)
        budget = (
            BudgetState(
                max_requests=max_requests,
                max_prompt_tokens=max_prompt_tokens,
                max_completion_tokens=max_completion_tokens,
                max_cost_usd=max_cost_usd,
            )
            if mode == ScanMode.AGENT
            else None
        )
    except Exception as exc:
        _fail(f"invalid scan configuration: {exc}", 2)
    return config, provider, budget


def _guard_output(root: Path, output: Path) -> None:
    if not root.exists():
        return
    root_resolved = root.resolve(strict=True)
    output_resolved = output.resolve(strict=False)
    try:
        relative = output_resolved.relative_to(root_resolved)
    except ValueError:
        return
    if output_resolved.suffix.casefold() in _SUPPORTED_SUFFIXES:
        _fail("output may not overwrite a supported source file under the scanned root", 2)
    if (
        relative.parts
        and relative.parts[0].casefold() not in {"artifacts", ".artifacts"}
        and output_resolved.exists()
        and output_resolved.is_file()
    ):
        _fail("output may not overwrite an existing file under the scanned root", 2)


def _timestamp() -> datetime:
    return datetime.now(UTC)


def _make_report(
    root: Path,
    mode: ScanMode,
    config: AppConfig,
    started: datetime,
    monotonic_start: float,
    ingest: Any,
    candidates: list[Any],
    workflow: Any,
) -> ReportEnvelope:
    completed = _timestamp()
    elapsed_ms = max(0, round((time.perf_counter() - monotonic_start) * 1000))
    findings = workflow.findings
    high_times = [
        max(0, round((time.perf_counter() - monotonic_start) * 1000))
        for finding in findings
        if finding.severity.value in {"critical", "high"}
    ]
    budget = workflow.budget
    diagnostics = list(ingest.diagnostics)
    metrics = RunMetrics(
        files_scanned=ingest.files_scanned,
        lines_scanned=ingest.lines_scanned,
        elapsed_ms=elapsed_ms,
        time_to_first_high_ms=min(high_times) if high_times else None,
        candidates_total=len(candidates),
        findings_confirmed=sum(item.disposition.value == "confirmed" for item in findings),
        findings_rejected=sum(item.disposition.value == "rejected" for item in findings),
        human_review_required=sum(item.disposition.value == "needs_review" for item in findings),
        model_requests=budget.requests_used if budget else 0,
        prompt_tokens=budget.prompt_tokens_used if budget else 0,
        completion_tokens=budget.completion_tokens_used if budget else 0,
        estimated_cost_usd=budget.cost_usd_used if budget else 0.0,
    )
    config_digest = _digest(config.canonical_data())
    return ReportEnvelope(
        schema_version="1.0",
        tool_version=__version__,
        run=RunMetadata(
            run_id=_digest([root.as_posix(), started.isoformat(), mode.value])[:24],
            mode=mode,
            root=root.as_posix(),
            started_at=started,
            completed_at=completed,
            configuration_digest=config_digest,
        ),
        metrics=metrics,
        findings=findings,
        diagnostics=diagnostics,
    )


def _run_scan(
    root: Path,
    *,
    mode: ScanMode,
    model_config: Path | None,
    max_requests: int,
    max_prompt_tokens: int,
    max_completion_tokens: int,
    max_cost_usd: float,
) -> ReportEnvelope:
    if not root.exists() or not root.is_dir():
        _fail(f"scan root is not a directory: {root}", 3)
    config, provider_config, budget = _app_config(
        mode=mode,
        model_config=model_config,
        max_requests=max_requests,
        max_prompt_tokens=max_prompt_tokens,
        max_completion_tokens=max_completion_tokens,
        max_cost_usd=max_cost_usd,
    )
    started = _timestamp()
    monotonic_start = time.perf_counter()
    try:
        ingest = discover_repository(root, config.scan)
        candidates = analyze_sources(ingest.sources, config.analysis)
        provider = OpenAICompatibleProvider(provider_config) if provider_config else None
        try:
            workflow = process_candidates(
                candidates,
                config.routing,
                mode=mode,
                provider=provider,
                budget=budget,
            )
        finally:
            if provider is not None:
                provider.close()
        return _make_report(
            root, mode, config, started, monotonic_start, ingest, candidates, workflow
        )
    except (OSError, ValueError, UnicodeError) as exc:
        _fail(f"scan could not produce a trustworthy result: {exc}", 3)
    raise AssertionError("unreachable")


def _format_path(path: Path | None, default: str) -> Path:
    return path if path is not None else Path(default)


@app.command()
def doctor() -> None:
    """Validate runtime and parser availability without network access."""
    checks = {"python": sys.version.split()[0], "platform": platform.system()}
    try:
        import tree_sitter_javascript  # noqa: F401
        import tree_sitter_python  # noqa: F401
        import tree_sitter_typescript  # noqa: F401

        checks["parsers"] = "available"
    except ImportError as exc:
        checks["parsers"] = f"unavailable: {exc}"
    console.print_json(json.dumps(checks, ensure_ascii=False))
    if checks["parsers"] != "available":
        raise typer.Exit(3)


@app.command()
def rules(
    format: Annotated[str, typer.Option("--format", help="Output format: table or json")] = "table",
) -> None:
    """List the four locked vulnerability rules."""
    if format not in {"table", "json"}:
        _fail("--format must be table or json", 2)
    items = [meta.__dict__ | {"severity": meta.severity.value} for meta in RULES.values()]
    items.sort(key=lambda item: item["rule_id"])
    if format == "json":
        typer.echo(json.dumps(items, ensure_ascii=False, sort_keys=True, indent=2))
        return
    table = Table("Rule", "CWE", "Severity", "Title")
    for item in items:
        table.add_row(item["rule_id"], item["cwe"], item["severity"], item["title"])
    console.print(table)


@app.command()
def scan(
    root: Annotated[Path, typer.Argument(help="Repository root to scan")],
    mode: Annotated[str, typer.Option("--mode")] = "offline",
    format: Annotated[str, typer.Option("--format")] = "json",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    model_config: Annotated[Path | None, typer.Option("--model-config")] = None,
    max_requests: Annotated[int, typer.Option("--max-requests", min=0)] = 8,
    max_prompt_tokens: Annotated[int, typer.Option("--max-prompt-tokens", min=0)] = 100_000,
    max_completion_tokens: Annotated[int, typer.Option("--max-completion-tokens", min=0)] = 10_000,
    max_cost_usd: Annotated[float, typer.Option("--max-cost-usd", min=0.0)] = 0.50,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "high",
) -> None:
    """Scan a repository offline or with optional adversarial Agent review."""
    if mode not in {item.value for item in ScanMode} or format not in {"json", "html"}:
        _fail("--mode must be offline or agent; --format must be json or html", 2)
    if fail_on not in {"none", "critical", "high", "medium", "low", "info"}:
        _fail("--fail-on must be none, critical, high, medium, low, or info", 2)
    target = _format_path(
        output, "aegisflow-report.html" if format == "html" else "aegisflow-report.json"
    )
    _guard_output(root, target)
    report = _run_scan(
        root,
        mode=ScanMode(mode),
        model_config=model_config,
        max_requests=max_requests,
        max_prompt_tokens=max_prompt_tokens,
        max_completion_tokens=max_completion_tokens,
        max_cost_usd=max_cost_usd,
    )
    write_report(report, target, format)  # type: ignore[arg-type]
    typer.echo(f"Wrote {format} report to {target}")
    if fail_on != "none":
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[fail_on]
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if any(
            severity_rank[item.severity.value] <= threshold
            for item in report.findings
            if item.disposition.value != "rejected"
        ):
            raise typer.Exit(1)


@app.command()
def benchmark(
    fixture_root: Annotated[Path, typer.Argument(help="Benchmark fixture root")],
    ground_truth: Annotated[Path, typer.Option("--ground-truth")],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Scan fixtures offline and write deterministic benchmark metrics."""
    _guard_output(fixture_root, output)
    truth_path = ground_truth
    if not truth_path.exists():
        _fail(f"ground-truth file does not exist: {truth_path}", 2)
    try:
        truth = load_ground_truth(truth_path)
        report = _run_scan(
            fixture_root,
            mode=ScanMode.OFFLINE,
            model_config=None,
            max_requests=0,
            max_prompt_tokens=0,
            max_completion_tokens=0,
            max_cost_usd=0.0,
        )
        result = score_benchmark(report, truth)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.canonical_json(), encoding="utf-8", newline="\n")
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"benchmark failed: {exc}", 3)
    typer.echo(
        f"precision={result.precision:.3f} recall={result.recall:.3f} "
        f"f1={result.f1:.3f} false_positive_rate={result.false_positive_rate:.3f}"
    )


if __name__ == "__main__":
    app()
