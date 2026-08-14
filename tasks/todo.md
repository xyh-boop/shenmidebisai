# AegisFlow Task Checklist

- [ ] T01: Create package foundation and locked contracts
  - Acceptance: DTOs, enums, graph validation, config, and stable serialization match `docs/spec.md`.
  - Verify: `python -m pytest -q tests/test_contracts.py`
  - Files: `pyproject.toml`, `.gitignore`, `src/aegisflow/__init__.py`, `src/aegisflow/contracts.py`, `src/aegisflow/config.py`, `tests/test_contracts.py`

- [ ] T02: Implement safe repository ingestion
  - Acceptance: containment, ignore lists, limits, binary/encoding handling, and structured diagnostics work without following symlinks.
  - Verify: `python -m pytest -q tests/test_ingest.py`
  - Files: `src/aegisflow/ingest/**`, `tests/test_ingest.py`

- [ ] T03: Implement four-class Python and JS/TS candidate analysis
  - Acceptance: analyzers emit typed candidates and evidence for command injection, SQL injection, path traversal, and unsafe deserialization, including near-miss suppression.
  - Verify: `python -m pytest -q tests/test_analyzers.py`
  - Files: `src/aegisflow/analyzers/**`, `tests/test_analyzers.py`

- [ ] T04: Implement scoring, routing, budgets, and adversarial review
  - Acceptance: deterministic routing handles confirm/reject/review paths; provider output and graph references are validated; budgets cannot be exceeded.
  - Verify: `python -m pytest -q tests/test_workflow.py tests/test_providers.py`
  - Files: `src/aegisflow/workflow/**`, `src/aegisflow/providers/**`, `tests/test_workflow.py`, `tests/test_providers.py`

- [ ] T05: Implement canonical reports and benchmark scorer
  - Acceptance: stable JSON, escaped responsive HTML, location-based deduped scoring, and all required metrics are generated.
  - Verify: `python -m pytest -q tests/test_reporting.py tests/test_benchmark.py`
  - Files: `src/aegisflow/reporting/**`, `src/aegisflow/benchmark/**`, `tests/test_reporting.py`, `tests/test_benchmark.py`

- [ ] T06: Integrate CLI, benchmark corpus, and delivery documentation
  - Acceptance: `doctor`, `rules`, `scan`, and `benchmark` work; at least 16 cases exist; all required documentation is present.
  - Verify: `python -m pytest -q tests/test_cli.py`; run documented CLI commands.
  - Files: `src/aegisflow/cli.py`, `benchmarks/**`, `config/**`, `README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/benchmark.md`, `docs/demo-script.md`, `tests/test_cli.py`

- [ ] T07: Integration and competition acceptance
  - Acceptance: full pytest and Ruff gates pass; normalized offline output is repeatable; benchmark meets declared targets; HTML passes desktop/mobile inspection.
  - Verify: commands in `tasks/plan.md` plus report screenshots.
  - Files: fixes limited to the owning module for each defect; `artifacts/**` for generated outputs.

