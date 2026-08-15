"""Read supported source files from an untrusted repository without executing it."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from aegisflow.config import ScanLimits
from aegisflow.contracts import Diagnostic, DiagnosticLevel, Language, SourceFile

_SOURCE_LANGUAGES = {
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".py": Language.PYTHON,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
}

_IGNORED_DIRECTORIES = frozenset(
    {
        ".artifacts",
        ".cache",
        ".coverage",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".nox",
        ".npm",
        ".nyc_output",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        ".yarn",
        "__pycache__",
        "artifacts",
        "bower_components",
        "build",
        "coverage",
        "dist",
        "generated",
        "htmlcov",
        "node_modules",
        "out",
        "target",
        "vendor",
        "venv",
    }
)

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Immutable result kept local to ingestion until the shared contract needs it."""

    sources: tuple[SourceFile, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def files_scanned(self) -> int:
        return len(self.sources)

    @property
    def bytes_scanned(self) -> int:
        return sum(source.size_bytes for source in self.sources)

    @property
    def lines_scanned(self) -> int:
        return sum(source.line_count for source in self.sources)

    @property
    def complete(self) -> bool:
        return not any(item.level == DiagnosticLevel.ERROR for item in self.diagnostics)


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_contained(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _diagnostic(
    code: str,
    level: DiagnosticLevel,
    message: str,
    path: str | None = None,
) -> Diagnostic:
    return Diagnostic(code=code, level=level, message=message, path=path)


def _read_bounded_file(path: Path, expected: os.stat_result, limit: int) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        same_file = (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
        if not same_file or not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise OSError("file changed or became a link before it was opened")

        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)

        final = os.fstat(descriptor)
        unchanged = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) == (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        actual_size = final.st_size
        if actual_size > limit or len(data) > limit:
            return data, actual_size
        if not unchanged or len(data) != final.st_size:
            raise OSError("file changed while it was being read")
        return data, actual_size
    finally:
        os.close(descriptor)


def _diagnostic_sort_key(item: Diagnostic) -> tuple[str, int, str, str, str]:
    return (item.path or "", item.line or 0, item.level.value, item.code, item.message)


def discover_repository(root: Path, limits: ScanLimits) -> IngestResult:
    """Discover and decode supported files beneath *root* using bounded, read-only I/O."""

    requested_root = Path(root)
    if requested_root.is_symlink():
        raise ValueError("repository root must not be a symbolic link")
    if not requested_root.exists():
        raise FileNotFoundError(f"repository root does not exist: {requested_root}")
    if not requested_root.is_dir():
        raise NotADirectoryError(f"repository root is not a directory: {requested_root}")
    root_stat = requested_root.stat(follow_symlinks=False)
    if _is_reparse_point(root_stat):
        raise ValueError("repository root must not be a reparse point")

    resolved_root = requested_root.resolve(strict=True)
    sources: list[SourceFile] = []
    diagnostics: list[Diagnostic] = []
    candidate_count = 0
    entries_seen = 0
    directories_seen = 1
    processed_bytes = 0
    entry_limit_reached = False
    directory_limit_reached = False
    file_limit_reached = False

    def add_skip(code: str, message: str, path: Path, *, error: bool = False) -> None:
        diagnostics.append(
            _diagnostic(
                code,
                DiagnosticLevel.ERROR if error else DiagnosticLevel.WARNING,
                message,
                _relative_path(path, resolved_root),
            )
        )

    def bounded_entries(directory: Path) -> list[Path]:
        nonlocal entries_seen, entry_limit_reached
        entries: list[Path] = []
        try:
            with os.scandir(directory) as iterator:
                for raw_entry in iterator:
                    if entries_seen >= limits.max_entries:
                        if not entry_limit_reached:
                            relative = (
                                None
                                if directory == resolved_root
                                else _relative_path(directory, resolved_root)
                            )
                            diagnostics.append(
                                _diagnostic(
                                    "max_entries_exceeded",
                                    DiagnosticLevel.ERROR,
                                    (
                                        "repository entry count exceeds maximum of "
                                        f"{limits.max_entries}"
                                    ),
                                    relative,
                                )
                            )
                        entry_limit_reached = True
                        break
                    entries_seen += 1
                    entries.append(Path(raw_entry.path))
        except OSError as exc:
            relative = (
                None if directory == resolved_root else _relative_path(directory, resolved_root)
            )
            diagnostics.append(
                _diagnostic(
                    "directory_read_error",
                    DiagnosticLevel.ERROR,
                    f"could not enumerate directory: {exc}",
                    relative,
                )
            )
        return sorted(entries, key=lambda item: (item.name.casefold(), item.name))

    def visit(directory: Path, depth: int) -> None:
        nonlocal candidate_count, directories_seen
        nonlocal directory_limit_reached, file_limit_reached, processed_bytes
        entries = bounded_entries(directory)

        for entry in entries:
            if file_limit_reached:
                return

            lexical_path = _relative_path(entry, resolved_root)
            try:
                path_bytes = len(lexical_path.encode("utf-8"))
            except UnicodeEncodeError:
                diagnostics.append(
                    _diagnostic(
                        "invalid_path_encoding",
                        DiagnosticLevel.ERROR,
                        "repository path cannot be represented as UTF-8",
                    )
                )
                continue
            if path_bytes > limits.max_path_bytes:
                add_skip(
                    "max_path_bytes_exceeded",
                    f"path length exceeds byte limit {limits.max_path_bytes}",
                    entry,
                    error=True,
                )
                continue
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                add_skip("stat_error", f"could not inspect path: {exc}", entry, error=True)
                continue

            if stat.S_ISLNK(entry_stat.st_mode) or _is_reparse_point(entry_stat):
                add_skip(
                    "symlink_skipped", "symbolic links and reparse points are not followed", entry
                )
                continue

            try:
                resolved_entry = entry.resolve(strict=True)
            except OSError as exc:
                add_skip("resolve_error", f"could not resolve path: {exc}", entry, error=True)
                continue
            if not _is_contained(resolved_entry, resolved_root):
                add_skip(
                    "outside_root", "resolved path escapes the repository root", entry, error=True
                )
                continue

            if stat.S_ISDIR(entry_stat.st_mode):
                if entry.name.casefold() in _IGNORED_DIRECTORIES:
                    continue
                if depth >= limits.max_depth:
                    add_skip(
                        "max_depth_exceeded",
                        f"directory exceeds maximum depth of {limits.max_depth}",
                        entry,
                        error=True,
                    )
                    continue
                if entry_limit_reached:
                    continue
                if directories_seen >= limits.max_directories:
                    if not directory_limit_reached:
                        add_skip(
                            "max_directories_exceeded",
                            (
                                "repository directory count exceeds maximum of "
                                f"{limits.max_directories}"
                            ),
                            entry,
                            error=True,
                        )
                    directory_limit_reached = True
                    continue
                directories_seen += 1
                visit(entry, depth + 1)
                continue

            if not stat.S_ISREG(entry_stat.st_mode):
                continue

            language = _SOURCE_LANGUAGES.get(entry.suffix.casefold())
            if language is None:
                continue

            candidate_count += 1
            if candidate_count > limits.max_files:
                diagnostics.append(
                    _diagnostic(
                        "max_files_exceeded",
                        DiagnosticLevel.ERROR,
                        f"source file count exceeds maximum of {limits.max_files}",
                        lexical_path,
                    )
                )
                file_limit_reached = True
                return

            try:
                raw, actual_size = _read_bounded_file(entry, entry_stat, limits.max_file_bytes)
            except OSError as exc:
                add_skip("file_read_error", f"could not safely read file: {exc}", entry, error=True)
                continue
            if actual_size > limits.max_file_bytes or len(raw) > limits.max_file_bytes:
                add_skip(
                    "max_file_bytes_exceeded",
                    f"actual file size {actual_size} exceeds limit {limits.max_file_bytes}",
                    entry,
                    error=True,
                )
                continue
            if processed_bytes + actual_size > limits.max_total_bytes:
                add_skip(
                    "max_total_bytes_exceeded",
                    f"actual read bytes would exceed total limit {limits.max_total_bytes}",
                    entry,
                    error=True,
                )
                continue
            processed_bytes += actual_size
            if b"\x00" in raw:
                add_skip(
                    "binary_file",
                    "file contains NUL bytes and is treated as binary",
                    entry,
                    error=True,
                )
                continue

            encoding = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
            try:
                content = raw.decode(encoding)
            except UnicodeDecodeError as exc:
                add_skip(
                    "invalid_utf8",
                    f"file is not valid UTF-8: byte offset {exc.start}",
                    entry,
                    error=True,
                )
                continue

            sources.append(
                SourceFile(
                    path=lexical_path,
                    language=language,
                    content=content,
                    size_bytes=len(raw),
                    encoding=encoding,
                )
            )

    visit(resolved_root, 0)
    return IngestResult(
        sources=tuple(sorted(sources, key=lambda source: source.path)),
        diagnostics=tuple(sorted(diagnostics, key=_diagnostic_sort_key)),
    )
