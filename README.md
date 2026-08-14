# AegisFlow

AegisFlow is an evidence-driven, local-first source security audit Agent for Python and JavaScript/TypeScript. It combines deterministic candidate discovery, local source-to-sink evidence graphs, cost-aware routing, and optional adversarial model review. The MVP focuses on command injection, SQL injection, path traversal, and unsafe deserialization.

The scanner treats a repository as hostile data. It does not import, execute, build, install, or test target code. Offline mode is the deterministic default and requires no credentials or network access.

## Quick start

Requirements: Python 3.11 or newer.

```powershell
python -m pip install ".[dev]"
aegisflow doctor
aegisflow rules --format table
aegisflow scan . --mode offline --format html --output .\artifacts\report.html --fail-on none
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

`scan` returns exit code `1` when a finding meets `--fail-on`; use `--fail-on none` for an informational run. Reports may be written outside the scanned root or under its ignored `artifacts/` or `.artifacts/` directory. A report path inside scanned source is rejected.

## Agent mode

Copy the non-secret settings in `config/model.example.toml`, select an OpenAI-compatible endpoint, and set the environment variable named by `api_key_env`. Credentials belong only in the environment and are never written to a report.

```powershell
$env:AEGISFLOW_API_KEY = "..."
aegisflow scan . --mode agent --model-config .\config\model.example.toml --max-requests 8 --max-cost-usd 0.50 --output .\artifacts\agent-report.html --fail-on none
```

Agent mode reviews only bounded evidence for ambiguous high-risk candidates. Invalid responses, unknown evidence references, timeouts, or exhausted budget become `needs_review`; they are not silently confirmed. Offline benchmark results remain the canonical reproducible score.

## Commands and exit codes

- `doctor`: validate runtime and parser availability without network access.
- `rules`: list the four locked rules as a table or JSON.
- `scan`: produce canonical JSON or self-contained HTML.
- `benchmark`: scan a fixture corpus and score it against an independent manifest.

Exit codes are `0` for success without a threshold finding, `1` for a completed scan with a threshold finding, `2` for invalid arguments/configuration, `3` for an untrustworthy input/parse failure, and `4` for a required Agent-mode failure.

## Scope and limitations

AegisFlow performs bounded, local, mostly intraprocedural tracking. It does not claim complete cross-file or whole-program taint analysis, runtime reachability, framework-specific authentication analysis, binary analysis, active exploitation, or automated remediation. Benchmark scores describe only the versioned bundled corpus and recorded configuration; they are not claims of universal accuracy.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [benchmark methodology](docs/benchmark.md), and the [five-minute demo script](docs/demo-script.md).

## Verification

```powershell
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```
