from __future__ import annotations

import os
from pathlib import Path

import pytest

from aegisflow.config import ScanLimits
from aegisflow.contracts import DiagnosticLevel, Language
from aegisflow.ingest import discover_repository


def limits(**overrides: int) -> ScanLimits:
    values = {
        "max_files": 100,
        "max_total_bytes": 100_000,
        "max_file_bytes": 10_000,
        "max_depth": 8,
    }
    values.update(overrides)
    return ScanLimits(**values)


def test_discovers_supported_languages_with_stable_paths_and_metrics(tmp_path: Path) -> None:
    (tmp_path / "z.tsx").write_text("const z = 1;\n", encoding="utf-8")
    (tmp_path / "A.py").write_text("one\ntwo\n", encoding="utf-8")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "client.JSX").write_text("export default 1;", encoding="utf-8")
    (nested / "ignored.txt").write_text("not source", encoding="utf-8")

    result = discover_repository(tmp_path, limits())

    assert [source.path for source in result.sources] == ["A.py", "nested/client.JSX", "z.tsx"]
    assert [source.language for source in result.sources] == [
        Language.PYTHON,
        Language.JAVASCRIPT,
        Language.TYPESCRIPT,
    ]
    assert result.files_scanned == 3
    assert result.lines_scanned == 4
    assert result.bytes_scanned == sum(source.size_bytes for source in result.sources)
    assert result.diagnostics == ()


def test_supports_utf8_sig_without_exposing_the_bom(tmp_path: Path) -> None:
    path = tmp_path / "bom.py"
    path.write_text("print('ok')\n", encoding="utf-8-sig")

    source = discover_repository(tmp_path, limits()).sources[0]

    assert source.encoding == "utf-8-sig"
    assert source.content == path.read_bytes()[3:].decode("utf-8")
    assert source.size_bytes == path.stat().st_size
    assert source.line_count == 1


def test_stable_ordering_is_independent_of_creation_order(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "B.py"):
        (tmp_path / name).write_text(name, encoding="utf-8")

    first = discover_repository(tmp_path, limits())
    second = discover_repository(tmp_path, limits())

    assert [source.path for source in first.sources] == ["B.py", "a.py", "c.py"]
    assert first == second


def test_ignores_vcs_dependencies_caches_builds_and_artifacts(tmp_path: Path) -> None:
    ignored_names = [".git", "node_modules", "__pycache__", "build", "dist", "artifacts"]
    for name in ignored_names:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "hidden.py").write_text("raise RuntimeError", encoding="utf-8")
    (tmp_path / "visible.py").write_text("value = 1", encoding="utf-8")

    result = discover_repository(tmp_path, limits())

    assert [source.path for source in result.sources] == ["visible.py"]
    assert result.diagnostics == ()


def test_skips_binary_and_malformed_utf8_with_diagnostics(tmp_path: Path) -> None:
    (tmp_path / "binary.py").write_bytes(b"print(1)\x00junk")
    (tmp_path / "malformed.ts").write_bytes(b"const x = '\xff';")

    result = discover_repository(tmp_path, limits())

    assert result.sources == ()
    assert [(item.path, item.code, item.level) for item in result.diagnostics] == [
        ("binary.py", "binary_file", DiagnosticLevel.WARNING),
        ("malformed.ts", "invalid_utf8", DiagnosticLevel.WARNING),
    ]


def test_skips_oversized_files_and_enforces_total_byte_budget(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"a" * 8)
    (tmp_path / "b.py").write_bytes(b"b" * 8)
    (tmp_path / "huge.py").write_bytes(b"h" * 20)

    result = discover_repository(
        tmp_path,
        limits(max_file_bytes=10, max_total_bytes=12),
    )

    assert [source.path for source in result.sources] == ["a.py"]
    assert [(item.path, item.code) for item in result.diagnostics] == [
        ("b.py", "max_total_bytes_exceeded"),
        ("huge.py", "max_file_bytes_exceeded"),
    ]


def test_binary_files_consume_the_total_read_budget(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"a\x00" + b"x" * 6)
    (tmp_path / "b.py").write_bytes(b"value=1\n")

    result = discover_repository(tmp_path, limits(max_file_bytes=10, max_total_bytes=12))

    assert result.sources == ()
    assert [(item.path, item.code) for item in result.diagnostics] == [
        ("a.py", "binary_file"),
        ("b.py", "max_total_bytes_exceeded"),
    ]


def test_file_count_limit_stops_at_stable_boundary(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_text(name, encoding="utf-8")

    result = discover_repository(tmp_path, limits(max_files=2))

    assert [source.path for source in result.sources] == ["a.py", "b.py"]
    assert [(item.path, item.code) for item in result.diagnostics] == [
        ("c.py", "max_files_exceeded")
    ]


def test_depth_limit_skips_deeper_directories(tmp_path: Path) -> None:
    level_one = tmp_path / "one"
    level_two = level_one / "two"
    level_two.mkdir(parents=True)
    (level_one / "kept.py").write_text("kept = True", encoding="utf-8")
    (level_two / "skipped.py").write_text("skipped = True", encoding="utf-8")

    result = discover_repository(tmp_path, limits(max_depth=1))

    assert [source.path for source in result.sources] == ["one/kept.py"]
    assert [(item.path, item.code) for item in result.diagnostics] == [
        ("one/two", "max_depth_exceeded")
    ]


def test_symlink_escape_is_never_followed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    outside = tmp_path / "outside"
    repository.mkdir()
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = 'outside'", encoding="utf-8")
    link = repository / "escape.py"
    try:
        link.symlink_to(secret)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are not available: {exc}")

    result = discover_repository(repository, limits())

    assert result.sources == ()
    assert [(item.path, item.code) for item in result.diagnostics] == [
        ("escape.py", "symlink_skipped")
    ]


def test_symlinked_root_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    link = tmp_path / "repository-link"
    try:
        link.symlink_to(repository, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are not available: {exc}")

    with pytest.raises(ValueError, match="symbolic link"):
        discover_repository(link, limits())


def test_invalid_roots_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover_repository(tmp_path / "missing", limits())

    regular_file = tmp_path / "file.py"
    regular_file.write_text("pass", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        discover_repository(regular_file, limits())


def test_discovery_does_not_write_into_repository(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("value = 1", encoding="utf-8")
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    discover_repository(tmp_path, limits())

    after = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}
    assert after == before
    assert os.fspath(source.relative_to(tmp_path)) == "source.py"
