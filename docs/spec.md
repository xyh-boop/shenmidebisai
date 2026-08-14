# Spec: AegisFlow Evidence-Driven Audit Agent

## Status

- Phase: IMPLEMENT
- State: implemented and verified
- Approved direction: 2026-08-14

## Objective

AegisFlow is a local-first source-code security audit Agent for Python and JavaScript/TypeScript repositories. It combines deterministic candidate discovery, lightweight taint evidence graphs, adversarial Agent review, and cost-aware routing to find high-risk vulnerabilities without turning every source file into an opaque model prompt.

The product is designed for security researchers, SRC teams, and competition judges who need three things at once:

1. exact and reviewable vulnerability evidence;
2. measurable improvements over raw static candidates;
3. reproducible latency, accuracy, model-cost, and human-review metrics.

The MVP goes deep on four vulnerability classes:

- command injection (`CWE-78`);
- SQL injection (`CWE-89`);
- path traversal (`CWE-22`);
- unsafe deserialization (`CWE-502`).

## Assumptions

1. Target repositories are hostile, read-only data. AegisFlow never imports, executes, builds, installs, or tests target code.
2. Python and JavaScript/TypeScript are the only MVP languages.
3. The primary interface is a CLI with JSON and self-contained HTML reports.
4. Offline mode is deterministic and requires no model credentials or network.
5. Agent mode uses an explicitly enabled OpenAI-compatible endpoint and sends only bounded, redacted evidence snippets.
6. Benchmark claims apply only to the versioned benchmark, recorded configuration, and recorded machine.
7. The four vulnerability classes take priority over adding more shallow rules.
8. Generated remediation is advisory; AegisFlow does not modify scanned source code.

## Agent Workflow

```text
Safe repository ingestion
  -> deterministic candidate discovery
  -> local evidence graph construction
  -> confidence and risk scoring
  -> cost-aware routing
       -> auto-confirm when evidence is complete
       -> needs-review when risk is low or evidence is ambiguous
       -> adversarial review for high-risk ambiguous candidates
            -> Verifier: supporting evidence
            -> Critic: sanitizers, constraints, constants, unreachable paths
            -> Arbiter: structured final decision
  -> stable finding fingerprint
  -> JSON / HTML / benchmark metrics
```

Agent roles are contract-bound stages, not free-form personas. Invalid model output is rejected and cannot affect a finding.

## User Stories

- A researcher can scan a repository with one command and receive prioritized findings with exact paths, line ranges, CWE labels, evidence graphs, and remediation.
- A reviewer can inspect source, propagation, sanitizer, constraint, and sink nodes instead of accepting an unsupported model assertion.
- A judge can compare raw candidates with final findings and see recall, false-positive rate, time-to-first-high, cost per confirmed finding, and human-review ratio.
- An operator can run entirely offline or set hard request, token, and USD limits for Agent mode.
- A tester can reproduce benchmark scores from an independent ground-truth manifest and stable finding fingerprints.

## Functional Requirements

### Safe ingestion

- Discover `.py`, `.js`, `.jsx`, `.ts`, and `.tsx` files under an explicit root.
- Ignore dependency, VCS, cache, build, coverage, generated, and artifact directories by default.
- Never follow symlinks; reject resolved paths outside the root.
- Enforce configurable file count, total byte, and per-file byte limits.
- Skip binary or undecodable files with structured diagnostics.
- Count scanned files and logical source lines without inflating metrics from ignored content.

### Candidate discovery

- Python parsing uses the standard-library AST.
- JavaScript/TypeScript parsing uses Tree-sitter and never evaluates code.
- Each rule produces typed `Candidate` objects with stable locations and initial evidence.
- Rules include positive signals and explicit suppressors for constants, parameterized queries, safe path containment, and safe deserializers.

### Evidence graph

- Model each finding as nodes and directed edges.
- Node kinds: `source`, `propagation`, `sanitizer`, `constraint`, `sink`, `context`.
- Edge kinds: `flows_to`, `sanitized_by`, `guarded_by`, `derived_from`.
- Every confirmed or likely finding must contain at least one sink and one supporting evidence node.
- Injection and traversal findings require a source-to-sink path unless the sink is independently dangerous by construction.

### Cost-aware routing

- Compute deterministic evidence completeness, exploitability, and initial confidence.
- Auto-confirm complete high-confidence evidence without a model call.
- Auto-reject candidates with proven safe constants or recognized sanitizers.
- Route only high-risk ambiguous candidates to adversarial review.
- Enforce model request, prompt token, completion token, context byte, and estimated USD budgets before every request.
- Record why each candidate was routed, skipped, confirmed, rejected, or left for human review.

### Adversarial review

- `Verifier` returns a verdict, supporting node IDs, reason codes, and concise rationale.
- `Critic` independently returns counterevidence node IDs, reason codes, and concise rationale.
- `Arbiter` may use only validated graph nodes and prior structured decisions.
- Source comments that instruct the model are quoted as untrusted evidence and cannot alter system instructions.
- Invalid JSON, unknown node references, timeout, or exhausted budget results in `needs_review`, never silent confirmation.

### Reporting

- JSON is the canonical report; HTML is rendered from the same validated envelope.
- HTML is self-contained, responsive, and escapes all repository-controlled content.
- The report shows severity totals, confidence, evidence graph, Agent decision timeline, supporting evidence versus counterevidence, routing reason, latency, token usage, estimated cost, and human-review state.
- Stable content ordering and fingerprints make repeat runs comparable.

### Benchmarking

- Maintain separate demonstration and regression fixture sets.
- Each vulnerability class contains vulnerable samples and near-miss safe samples in both supported language families where feasible.
- Ground truth lives in a separate manifest; expected findings are not embedded in source comments.
- Scoring is location based. A true positive requires the expected rule ID, normalized path, and overlapping line range.
- Duplicate fingerprints count once.
- Offline metrics are the primary reproducible score. Agent-assisted before/after metrics are reported separately.

## Public Contracts

Shared fields and enum values are locked. Worker Agents may not rename or extend them without an approved spec update.

```python
class EvidenceNode(BaseModel):
    node_id: str
    kind: Literal["source", "propagation", "sanitizer", "constraint", "sink", "context"]
    path: str
    line: int
    symbol: str | None
    snippet: str
    description: str

class EvidenceEdge(BaseModel):
    source_id: str
    target_id: str
    relation: Literal["flows_to", "sanitized_by", "guarded_by", "derived_from"]

class AgentDecision(BaseModel):
    agent: Literal["scout", "tracer", "verifier", "critic", "arbiter"]
    verdict: Literal["confirm", "reject", "needs_review"]
    confidence: float
    reason_codes: list[str]
    supporting_node_ids: list[str]
    counterevidence_node_ids: list[str]
    rationale: str
    latency_ms: int

class Finding(BaseModel):
    finding_id: str
    rule_id: str
    cwe: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    disposition: Literal["confirmed", "likely", "rejected", "needs_review"]
    language: Literal["python", "javascript", "typescript"]
    path: str
    start_line: int
    end_line: int
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    decisions: list[AgentDecision]
    remediation: str

class RunMetrics(BaseModel):
    files_scanned: int
    lines_scanned: int
    elapsed_ms: int
    time_to_first_high_ms: int | None
    candidates_total: int
    findings_confirmed: int
    findings_rejected: int
    human_review_required: int
    model_requests: int
    prompt_tokens: int
    completion_tokens: int
    estimated_cost_usd: float
```

Every report envelope contains `schema_version`, `tool_version`, `run`, `metrics`, `findings`, and `diagnostics`. Repository paths use `/` separators. `finding_id` is a stable SHA-256 digest of rule ID, normalized path, vulnerable line range, and normalized evidence identity.

## CLI Contract

```powershell
# Install
python -m pip install ".[dev]"

# Environment validation
aegisflow doctor

# Inspect rule coverage
aegisflow rules --format table

# Deterministic offline scan
aegisflow scan . --mode offline --format html --output .\artifacts\report.html

# Cost-bounded Agent scan
aegisflow scan . --mode agent --model-config .\config\model.example.toml --max-requests 8 --max-cost-usd 0.50 --output .\artifacts\report.html

# Reproducible benchmark
aegisflow benchmark .\benchmarks\fixtures --ground-truth .\benchmarks\ground_truth.json --output .\artifacts\benchmark.json

# Verification
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

Exit codes:

- `0`: completed and no finding met the configured fail threshold;
- `1`: completed and at least one finding met the threshold;
- `2`: invalid arguments or configuration;
- `3`: input or parsing failure preventing a trustworthy scan;
- `4`: required Agent mode failed or exhausted its mandatory budget.

## Tech Stack

- Python 3.11+
- Pydantic 2.x for shared contracts
- Typer and Rich for CLI output
- Python AST plus Tree-sitter language packages for parsing
- Jinja2 for the self-contained report
- HTTPX for the optional OpenAI-compatible provider
- pytest and Ruff for verification

Default tests use fake provider transports and require neither credentials nor network.

## Project Structure

```text
src/aegisflow/
  cli.py                  CLI and exit-code mapping
  contracts.py            Locked DTOs and enums
  config.py               Limits, routing, and provider configuration
  ingest/                 Safe repository discovery and loading
  analyzers/              Parsers, rules, and local evidence tracing
  workflow/               Scoring, routing, review, and arbitration
  providers/              OpenAI-compatible adapter and budget accounting
  reporting/              JSON, HTML, and metrics
  benchmark/              Ground-truth loading and scoring
tests/                    Unit, contract, integration, and safety tests
benchmarks/               Demo/regression fixtures and ground truth
docs/                     Spec, architecture, threat model, and demo script
tasks/                    SDD plan and task checklist
config/                   Non-secret examples
artifacts/                Generated output, excluded from version control
```

## Code Style

- Typed public boundaries and Pydantic validation between workflow stages.
- Small deterministic functions; side effects are isolated in ingestion, provider, and report adapters.
- Stable ordering for files, candidates, graph nodes, decisions, and findings.
- Structured diagnostics for expected failures; exceptions for unrecoverable faults.
- Comments document security invariants and non-obvious analysis tradeoffs.

```python
def route_candidate(candidate: Candidate, budget: BudgetState) -> RoutingDecision:
    if candidate.proven_safe:
        return RoutingDecision(action="reject", reason="recognized_sanitizer")
    if candidate.evidence_complete and candidate.confidence >= 0.90:
        return RoutingDecision(action="confirm", reason="complete_local_evidence")
    if candidate.severity in {Severity.CRITICAL, Severity.HIGH} and budget.can_review():
        return RoutingDecision(action="agent_review", reason="high_risk_ambiguity")
    return RoutingDecision(action="needs_review", reason="insufficient_evidence")
```

## Testing Strategy

- Unit tests for path containment, limits, redaction, AST matching, evidence graphs, confidence calibration, routing, budget accounting, stable fingerprints, escaping, and benchmark math.
- Positive and near-miss negative fixtures for every rule.
- Contract tests for all Agent stage outputs and unknown graph-node references.
- Golden JSON tests with injected clocks and normalized volatile fields.
- CLI integration tests from repository scan through JSON and HTML generation.
- Safety tests for symlink escape, malformed syntax, binary files, oversized inputs, HTML injection, prompt injection in comments, and secret leakage.
- Provider tests use fake HTTP transports for timeout, malformed response, retries, and budget exhaustion.
- Repeatability test requires two offline scans of identical input/configuration to produce identical normalized findings.

## Boundaries

### Always

- Treat repository content and model output as hostile input.
- Verify every resolved path remains within the selected root.
- Escape all repository content in HTML.
- Validate every workflow transition against the locked contracts.
- Enforce model budgets before calls and redact bounded context.
- Record the benchmark configuration, runtime versions, and raw metrics.
- Run tests, Ruff checks, and the benchmark before delivery.

### Ask first

- Change shared contract fields, enums, CLI commands, or report schema.
- Add runtime dependencies beyond the approved stack.
- Send a real repository snippet to an external provider.
- Add languages, vulnerability classes, hosted services, databases, or active scanning.

### Never

- Execute, import, build, install, or test scanned repositories.
- Generate or run exploitation payloads or PoCs.
- Persist secrets, raw environment variables, API keys, or session data.
- Follow symlinks outside the scan root.
- Claim benchmark scores as universal real-world accuracy.
- weaken tests or ground truth to improve metrics.

## Success Criteria

1. `aegisflow doctor`, `rules`, `scan`, and `benchmark` run with documented output.
2. Offline mode scans Python and JavaScript/TypeScript fixtures without credentials or network.
3. All confirmed findings include a sink, evidence nodes, valid graph edges, Agent decisions, exact location, CWE, confidence, and remediation.
4. The benchmark contains at least 16 vulnerable/safe cases across the four vulnerability classes and reaches at least 85% recall with no more than 15% false-positive rate on its declared corpus.
5. Offline scan of the bundled corpus completes in under 10 seconds on the recorded development machine and records time-to-first-high.
6. Two offline runs produce identical normalized findings and fingerprints.
7. Agent mode never exceeds configured request or cost budgets and degrades invalid responses to `needs_review`.
8. Reports expose audit volume, precision, recall, false-positive rate, F1, elapsed time, time-to-first-high, review reduction, tokens, and estimated cost.
9. HTML reports safely render malicious snippets and fit desktop and mobile viewports without overlapping controls or text.
10. The default pytest suite and Ruff checks pass; core safety, routing, benchmark, and reporting paths are covered.
11. README, architecture notes, threat model, benchmark methodology, and a five-minute demo script are included.
12. No operation writes into or executes code from the scanned repository.

## Open Questions

None blocking. The user approved this optimized direction on 2026-08-14. A live model provider remains optional and can be selected at demonstration time through the OpenAI-compatible configuration.
