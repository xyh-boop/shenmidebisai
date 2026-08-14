# AegisFlow Implementation Plan

## Goal

Deliver the approved AegisFlow MVP from `docs/spec.md`: safe local ingestion, four deep vulnerability classes, evidence graphs, cost-aware routing, adversarial review contracts, deterministic JSON/HTML reporting, and a reproducible benchmark.

## Dependency Graph

```text
P0 Shared package + contracts + config
  |-- P1 Safe repository ingestion
  |-- P2 Python and JS/TS candidate analysis
  |     `-- P3 Evidence scoring and cost-aware workflow
  |            `-- P4 Optional provider and adversarial review
  |-- P5 Reporting and benchmark scoring
  `-- P6 CLI integration
         `-- P7 Fixtures, docs, end-to-end verification
```

## Locked Contracts

The DTOs and enum values in `docs/spec.md` are authoritative. Implementation may add internal models (`SourceFile`, `Candidate`, `RoutingDecision`, `Diagnostic`, `ReportEnvelope`, `BenchmarkResult`, `BudgetState`) only in `src/aegisflow/contracts.py`. Existing public field names and enum values may not change.

Required callable boundaries:

```python
discover_repository(root: Path, limits: ScanLimits) -> IngestResult
analyze_sources(sources: Sequence[SourceFile], config: AnalysisConfig) -> list[Candidate]
build_finding(candidate: Candidate, policy: RoutingPolicy) -> Finding
review_candidate(candidate: Candidate, provider: ReviewProvider, budget: BudgetState) -> list[AgentDecision]
render_json(report: ReportEnvelope) -> str
render_html(report: ReportEnvelope) -> str
score_benchmark(report: ReportEnvelope, truth: GroundTruth) -> BenchmarkResult
```

All paths crossing module boundaries are normalized repository-relative POSIX strings. Lists returned from public boundaries are stably sorted.

## Implementation Phases

### Phase 0: Foundation

- Create the package manifest, dependency pins, package metadata, shared DTOs, limits, and configuration.
- Verify strict DTO validation, graph reference validation, confidence bounds, and deterministic serialization.

Checkpoint: contract tests pass before dependent workers begin.

### Phase 1: Safe Input and Analysis

- Implement safe repository discovery with ignore policies, containment checks, file/byte limits, binary detection, and diagnostics.
- Implement Python AST candidate discovery and lightweight source-to-sink tracing.
- Implement JS/TS Tree-sitter candidate discovery with the same four rule IDs and common evidence semantics.
- Add positive and near-miss negative unit fixtures.

Checkpoint: analyzer and ingestion tests pass without executing target code.

### Phase 2: Agent Workflow and Outputs

- Implement evidence completeness scoring, local confirmation/rejection, routing, budget accounting, and adversarial decision validation.
- Implement OpenAI-compatible review transport behind a protocol and fake transport tests.
- Implement canonical JSON, escaped self-contained HTML, benchmark math, and stable fingerprints.
- Integrate CLI commands and exit-code mapping.

Checkpoint: end-to-end offline scan produces valid JSON and HTML.

### Phase 3: Competition Package

- Build at least 16 vulnerable/safe benchmark cases and independent ground truth.
- Generate benchmark artifacts and confirm declared recall/false-positive thresholds.
- Add README, architecture, threat model, benchmark methodology, and five-minute demo script.
- Perform Ruff, pytest, repeatability, malicious HTML, and mobile/desktop report checks.

Checkpoint: all success criteria have command or artifact evidence.

## Parallel Work and Ownership

### Wave 1

- Worker Foundation owns: `pyproject.toml`, `.gitignore`, `src/aegisflow/__init__.py`, `src/aegisflow/contracts.py`, `src/aegisflow/config.py`, `tests/test_contracts.py`.
- Worker Ingestion owns: `src/aegisflow/ingest/**`, `tests/test_ingest.py`.
- Worker Analysis owns: `src/aegisflow/analyzers/**`, `tests/test_analyzers.py`.

Ingestion and Analysis may read the locked spec but begin final integration only after Foundation exposes contracts. They may not edit shared files.

### Wave 2

- Worker Workflow owns: `src/aegisflow/workflow/**`, `src/aegisflow/providers/**`, `tests/test_workflow.py`, `tests/test_providers.py`.
- Worker Reporting owns: `src/aegisflow/reporting/**`, `src/aegisflow/benchmark/**`, `tests/test_reporting.py`, `tests/test_benchmark.py`.
- Worker Delivery owns: `src/aegisflow/cli.py`, `benchmarks/**`, `config/**`, `README.md`, `docs/architecture.md`, `docs/threat-model.md`, `docs/benchmark.md`, `docs/demo-script.md`, `tests/test_cli.py`.

No worker may edit another worker's owned path. Shared-contract changes must be reported to the orchestrator and handled as a spec update before code changes.

## Risks and Mitigations

- Tree-sitter installation: pin wheel-backed packages; `doctor` reports unavailable JS/TS support explicitly.
- Lightweight JS/TS tracing: limit claims to local syntax and assignment flows; use near-miss negatives.
- Model nondeterminism: offline benchmark is canonical; model output is schema validated and separately reported.
- Fixture overfitting: separate demo and regression sets and include structurally similar safe cases.
- HTML injection: use Jinja autoescape plus tests containing hostile paths/snippets.
- Deadline pressure: four vulnerability classes and complete evidence/reporting take precedence over additional rules or UI features.

## Verification Commands

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
aegisflow doctor
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json
```

