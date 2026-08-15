"""Typer entry points for safe, deterministic AegisFlow scans."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import stat
import sys
import tempfile
import time
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from aegisflow import __version__
from aegisflow.analyzers import RULES, analyze_sources
from aegisflow.benchmark import score_benchmark
from aegisflow.config import AppConfig, ProviderConfig
from aegisflow.contracts import (
    AnalysisResult,
    BudgetState,
    Diagnostic,
    DiagnosticLevel,
    GroundTruth,
    ReportEnvelope,
    RunMetadata,
    RunMetrics,
    ScanMode,
)
from aegisflow.ingest import discover_repository
from aegisflow.providers import OpenAICompatibleProvider
from aegisflow.reporting import render_html, render_json
from aegisflow.workflow import process_candidates

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
_SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_MAX_TOML_BYTES = 1 * 1024 * 1024
_MAX_GROUND_TRUTH_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _ScanExecution:
    report: ReportEnvelope
    complete: bool
    require_agent_success: bool
    agent_failures: tuple[str, ...]


def _fail(message: str, code: int) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code)


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _supports_directory_handle_io() -> bool:
    return (
        os.open in os.supports_dir_fd
        and os.replace in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
    )


def _uses_path_output_fallback() -> bool:
    return not _supports_directory_handle_io()


def _path_output_fallback_warning() -> str:
    return (
        "Warning: path-based output replacement fallback is active; lstat and final rechecks "
        "cannot fully prevent a concurrent Windows junction replacement on this platform."
    )


def _read_bounded_control_file(path: Path, limit: int, label: str) -> bytes:
    expected = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(expected.st_mode) or _is_reparse_point(expected):
        raise OSError(f"{label} must not be a symbolic link or reparse point")
    if not stat.S_ISREG(expected.st_mode):
        raise OSError(f"{label} must be a regular file")
    if expected.st_size > limit:
        raise OSError(f"{label} exceeds the {limit}-byte limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not _same_file(expected, opened) or not stat.S_ISREG(opened.st_mode):
            raise OSError(f"{label} changed before it was opened")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(limit + 1)
        final = os.fstat(descriptor)
        if not _same_file(opened, final) or final.st_size != len(content):
            raise OSError(f"{label} changed while it was read")
        if len(content) > limit:
            raise OSError(f"{label} exceeds the {limit}-byte limit")
        return content
    finally:
        os.close(descriptor)


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        raw = _read_bounded_control_file(path, _MAX_TOML_BYTES, "model configuration")
        payload = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        _fail(f"could not load model configuration: {exc}", 2)
    return payload


def _load_ground_truth(path: Path) -> GroundTruth:
    raw = _read_bounded_control_file(path, _MAX_GROUND_TRUTH_BYTES, "ground truth")
    return GroundTruth.model_validate_json(raw)


def _app_config(
    *,
    mode: ScanMode,
    model_config: Path | None,
    max_requests: int,
    max_prompt_tokens: int,
    max_completion_tokens: int,
    max_cost_usd: float,
    require_agent_success: bool | None,
) -> tuple[AppConfig, ProviderConfig | None, BudgetState | None]:
    payload: dict[str, Any] = {}
    if model_config is not None:
        payload = _load_toml(model_config)
    if require_agent_success is not None:
        payload = {**payload, "require_agent_success": require_agent_success}
    try:
        config = AppConfig.model_validate(payload)
    except Exception as exc:
        _fail(f"invalid scan configuration: {exc}", 2)
    provider = config.provider
    if config.require_agent_success and mode != ScanMode.AGENT:
        _fail("--require-agent-success requires --mode agent", 2)
    if mode == ScanMode.AGENT and provider is None:
        _fail("agent mode requires --model-config", 2)
    if provider is not None and provider.uses_insecure_http:
        typer.echo(
            "Warning: provider uses explicitly enabled loopback HTTP; transport is not encrypted",
            err=True,
        )
    try:
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


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _validate_path_component(path: Path, *, directory: bool) -> os.stat_result:
    current = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(current.st_mode) or _is_reparse_point(current):
        raise OSError("output path contains a symbolic link or reparse point")
    if directory and not stat.S_ISDIR(current.st_mode):
        raise OSError("output parent component is not a directory")
    return current


def _validate_existing_output_chain(output: Path) -> Path:
    absolute = _absolute_lexical(output)
    if not absolute.name:
        raise OSError("output target must be a file path")
    current = Path(absolute.anchor)
    _validate_path_component(current, directory=True)
    for index, part in enumerate(absolute.parts[1:]):
        current /= part
        try:
            _validate_path_component(
                current,
                directory=index < len(absolute.parts[1:]) - 1,
            )
        except FileNotFoundError:
            break
    return absolute


def _create_output_directory(path: Path) -> None:
    parent_before = _validate_path_component(path.parent, directory=True)
    use_directory_handle = os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd
    if use_directory_handle:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path.parent, flags)
        try:
            if not _same_file(parent_before, os.fstat(descriptor)):
                raise OSError("output parent changed before directory creation")
            os.mkdir(path.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
    else:
        os.mkdir(path)
    parent_after = _validate_path_component(path.parent, directory=True)
    if not _same_file(parent_before, parent_after):
        raise OSError("output parent changed during directory creation")
    _validate_path_component(path, directory=True)


def _prepare_output_parent(
    output: Path,
    *,
    allow_create: bool = True,
) -> tuple[Path, os.stat_result]:
    absolute = _absolute_lexical(output)
    if not absolute.name:
        raise OSError("output target must be a file path")
    current = Path(absolute.anchor)
    _validate_path_component(current, directory=True)
    for part in absolute.parts[1:-1]:
        current /= part
        try:
            _validate_path_component(current, directory=True)
        except FileNotFoundError as exc:
            if not allow_create:
                raise OSError(
                    "path-based output fallback requires pre-existing parent directories"
                ) from exc
            _create_output_directory(current)
    try:
        parent_stat = _validate_path_component(absolute.parent, directory=True)
    except FileNotFoundError as exc:
        if not allow_create:
            raise OSError(
                "path-based output fallback requires a pre-existing output parent directory"
            ) from exc
        raise
    try:
        target_stat = _validate_path_component(absolute, directory=False)
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
        raise OSError("output target must be a regular file")
    return absolute, parent_stat


def _safe_write_text(output: Path, content: str) -> bool:
    use_directory_handle = _supports_directory_handle_io()
    absolute, parent_before = _prepare_output_parent(
        output,
        allow_create=use_directory_handle or os.name != "nt",
    )
    descriptor = -1
    parent_descriptor = -1
    temporary_name: str | None = None
    temporary_path: Path | None = None
    try:
        if use_directory_handle:
            directory_flags = (
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            parent_descriptor = os.open(absolute.parent, directory_flags)
            if not _same_file(parent_before, os.fstat(parent_descriptor)):
                raise OSError("output parent changed before temporary file creation")
            temporary_name = f".aegisflow-{secrets.token_hex(16)}.tmp"
            temporary_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                temporary_name,
                temporary_flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        else:
            descriptor, temporary_file = tempfile.mkstemp(
                prefix=".aegisflow-",
                suffix=".tmp",
                dir=absolute.parent,
            )
            temporary_path = Path(temporary_file)
        if not use_directory_handle:
            parent_after_temp = _validate_path_component(absolute.parent, directory=True)
            if not _same_file(parent_before, parent_after_temp):
                raise OSError("output parent changed after temporary file creation")
        temporary_stat = os.fstat(descriptor)
        if not stat.S_ISREG(temporary_stat.st_mode) or _is_reparse_point(temporary_stat):
            raise OSError("temporary output is not a regular file")
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())

        _validate_existing_output_chain(absolute)
        parent_after = _validate_path_component(absolute.parent, directory=True)
        if not _same_file(parent_before, parent_after):
            raise OSError("output parent changed during report generation")
        try:
            target_stat = _validate_path_component(absolute, directory=False)
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and not stat.S_ISREG(target_stat.st_mode):
            raise OSError("output target changed to a non-regular file")

        if parent_descriptor >= 0:
            if not _same_file(parent_before, os.fstat(parent_descriptor)):
                raise OSError("output directory handle changed before atomic replacement")
            if temporary_name is None:
                raise OSError("temporary output name is unavailable")
            os.replace(
                temporary_name,
                absolute.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            temporary_name = None
        else:
            if temporary_path is None:
                raise OSError("temporary output path is unavailable")
            os.replace(temporary_path, absolute)
            temporary_path = None
        final = _validate_path_component(absolute, directory=False)
        if not stat.S_ISREG(final.st_mode):
            raise OSError("output replacement did not produce a regular file")
        parent_final = _validate_path_component(absolute.parent, directory=True)
        if not _same_file(parent_before, parent_final):
            raise OSError("output parent changed during atomic replacement")
        return not use_directory_handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None and parent_descriptor >= 0:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        if temporary_path is not None:
            current_parent: os.stat_result | None = None
            with suppress(OSError):
                current_parent = _validate_path_component(absolute.parent, directory=True)
            if current_parent is not None and _same_file(parent_before, current_parent):
                with suppress(FileNotFoundError):
                    os.unlink(temporary_path)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _safe_write_report(report: ReportEnvelope, output: Path, format: str) -> bool:
    renderers = {"json": render_json, "html": render_html}
    try:
        renderer = renderers[format]
    except KeyError as exc:
        raise ValueError("format must be json or html") from exc
    return _safe_write_text(output, renderer(report))


def _guard_output(root: Path, output: Path) -> None:
    output_absolute = _validate_existing_output_chain(output)
    if not root.exists():
        return
    root_absolute = _absolute_lexical(root)
    try:
        relative = output_absolute.relative_to(root_absolute)
    except ValueError:
        return
    if output_absolute.suffix.casefold() in _SUPPORTED_SUFFIXES:
        raise OSError("output may not overwrite a supported source file under the scanned root")
    if (
        relative.parts
        and relative.parts[0].casefold() not in {"artifacts", ".artifacts"}
        and output_absolute.exists()
        and output_absolute.is_file()
    ):
        raise OSError("output may not overwrite an existing file under the scanned root")


def _timestamp() -> datetime:
    return datetime.now(UTC)


def _make_report(
    root: Path,
    mode: ScanMode,
    started: datetime,
    monotonic_start: float,
    ingest: Any,
    candidates: list[Any],
    workflow: Any,
    diagnostics: list[Any],
    time_to_first_high_ms: int | None,
    configuration_digest: str,
) -> ReportEnvelope:
    completed = _timestamp()
    elapsed_ms = max(0, round((time.perf_counter() - monotonic_start) * 1000))
    findings = workflow.findings
    budget = workflow.budget
    metrics = RunMetrics(
        files_scanned=ingest.files_scanned,
        lines_scanned=ingest.lines_scanned,
        elapsed_ms=elapsed_ms,
        time_to_first_high_ms=time_to_first_high_ms,
        candidates_total=len(candidates),
        findings_confirmed=sum(item.disposition.value == "confirmed" for item in findings),
        findings_rejected=sum(item.disposition.value == "rejected" for item in findings),
        human_review_required=sum(item.disposition.value == "needs_review" for item in findings),
        model_requests=budget.requests_used if budget else 0,
        prompt_tokens=budget.prompt_tokens_used if budget else 0,
        completion_tokens=budget.completion_tokens_used if budget else 0,
        estimated_cost_usd=budget.cost_usd_used if budget else 0.0,
    )
    return ReportEnvelope(
        schema_version="1.0",
        tool_version=__version__,
        run=RunMetadata(
            run_id=_digest([root.as_posix(), started.isoformat(), mode.value])[:24],
            mode=mode,
            root=root.as_posix(),
            started_at=started,
            completed_at=completed,
            configuration_digest=configuration_digest,
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
    require_agent_success: bool | None,
) -> _ScanExecution:
    if not root.exists() or not root.is_dir():
        _fail(f"scan root is not a directory: {root}", 3)
    config, provider_config, budget = _app_config(
        mode=mode,
        model_config=model_config,
        max_requests=max_requests,
        max_prompt_tokens=max_prompt_tokens,
        max_completion_tokens=max_completion_tokens,
        max_cost_usd=max_cost_usd,
        require_agent_success=require_agent_success,
    )
    agent_failures: set[str] = set()
    agent_diagnostics: list[Diagnostic] = []
    if (
        mode == ScanMode.AGENT
        and provider_config is not None
        and not os.environ.get(provider_config.api_key_env)
    ):
        agent_failures.add("AGENT_PROVIDER_CREDENTIAL_UNAVAILABLE")
        agent_diagnostics.append(
            Diagnostic(
                code="agent_provider_credential_unavailable",
                level=DiagnosticLevel.WARNING,
                message="Agent provider credential is unavailable; local findings require review.",
            )
        )
    started = _timestamp()
    monotonic_start = time.perf_counter()
    try:
        ingest = discover_repository(root, config.scan)
        analysis_candidates: list[Any] = []
        analysis_diagnostics: list[Any] = []
        analysis_complete = True
        time_to_first_high_ms: int | None = None
        ordered_sources = sorted(
            ingest.sources,
            key=lambda item: (item.path, item.language.value),
        )
        for source in ordered_sources:
            source_result = analyze_sources((source,), config.analysis)
            if not isinstance(source_result, AnalysisResult):
                raise ValueError("analyzer returned an invalid result contract")
            analysis_candidates.extend(source_result.candidates)
            analysis_diagnostics.extend(source_result.diagnostics)
            analysis_complete = analysis_complete and source_result.complete
            if time_to_first_high_ms is None and any(
                item.severity.value in {"critical", "high"} for item in source_result.candidates
            ):
                time_to_first_high_ms = max(
                    0,
                    round((time.perf_counter() - monotonic_start) * 1000),
                )
        analysis = AnalysisResult(
            candidates=analysis_candidates,
            diagnostics=analysis_diagnostics,
            complete=analysis_complete,
        )
        candidates = list(analysis.candidates)
        configuration_digest = _digest(
            {
                "mode": mode.value,
                "config": config.canonical_data(),
                "budget": (
                    {
                        "max_requests": budget.max_requests,
                        "max_prompt_tokens": budget.max_prompt_tokens,
                        "max_completion_tokens": budget.max_completion_tokens,
                        "max_cost_usd": budget.max_cost_usd,
                    }
                    if budget is not None
                    else None
                ),
            }
        )
        provider = (
            OpenAICompatibleProvider(provider_config)
            if mode == ScanMode.AGENT and provider_config is not None
            else None
        )
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
        agent_failures.update(getattr(workflow, "agent_failures", ()))
        diagnostics = [*ingest.diagnostics, *analysis.diagnostics, *agent_diagnostics]
        complete = analysis.complete and not any(
            item.level == DiagnosticLevel.ERROR for item in diagnostics
        )
        report = _make_report(
            root,
            mode,
            started,
            monotonic_start,
            ingest,
            candidates,
            workflow,
            diagnostics,
            time_to_first_high_ms,
            configuration_digest,
        )
        return _ScanExecution(
            report=report,
            complete=complete,
            require_agent_success=config.require_agent_success,
            agent_failures=tuple(sorted(agent_failures)),
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
    require_agent_success: Annotated[
        bool | None,
        typer.Option("--require-agent-success/--no-require-agent-success"),
    ] = None,
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
    if model_config is not None and _absolute_lexical(target) == _absolute_lexical(model_config):
        _fail("report output may not overwrite the model configuration", 3)
    try:
        _guard_output(root, target)
    except (OSError, ValueError) as exc:
        _fail(f"unsafe report output: {exc}", 3)
    execution = _run_scan(
        root,
        mode=ScanMode(mode),
        model_config=model_config,
        max_requests=max_requests,
        max_prompt_tokens=max_prompt_tokens,
        max_completion_tokens=max_completion_tokens,
        max_cost_usd=max_cost_usd,
        require_agent_success=require_agent_success,
    )
    try:
        used_path_fallback = _safe_write_report(execution.report, target, format)
    except (OSError, ValueError, UnicodeError) as exc:
        _fail(f"could not safely write report: {exc}", 3)
    if used_path_fallback:
        typer.echo(_path_output_fallback_warning(), err=True)
    typer.echo(f"Wrote {format} report to {target}")
    if not execution.complete:
        _fail("scan is incomplete; inspect report diagnostics", 3)
    if execution.require_agent_success and execution.agent_failures:
        _fail("required Agent review did not complete successfully", 4)
    if fail_on != "none":
        threshold = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[fail_on]
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if any(
            severity_rank[item.severity.value] <= threshold
            for item in execution.report.findings
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
    try:
        _guard_output(fixture_root, output)
    except (OSError, ValueError) as exc:
        _fail(f"unsafe benchmark output: {exc}", 3)
    truth_path = ground_truth
    if _absolute_lexical(output) == _absolute_lexical(truth_path):
        _fail("benchmark output may not overwrite the ground-truth file", 3)
    if not truth_path.exists():
        _fail(f"ground-truth file does not exist: {truth_path}", 3)
    try:
        truth = _load_ground_truth(truth_path)
        execution = _run_scan(
            fixture_root,
            mode=ScanMode.OFFLINE,
            model_config=None,
            max_requests=0,
            max_prompt_tokens=0,
            max_completion_tokens=0,
            max_cost_usd=0.0,
            require_agent_success=False,
        )
        if not execution.complete:
            raise ValueError("fixture scan is incomplete; inspect source diagnostics")
        result = score_benchmark(execution.report, truth)
        used_path_fallback = _safe_write_text(output, result.canonical_json())
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"benchmark failed: {exc}", 3)
    if used_path_fallback:
        typer.echo(_path_output_fallback_warning(), err=True)
    typer.echo(
        f"precision={result.precision:.3f} recall={result.recall:.3f} "
        f"f1={result.f1:.3f} false_discovery_rate={result.false_discovery_rate:.3f}"
    )


if __name__ == "__main__":
    app()
