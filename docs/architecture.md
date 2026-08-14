# Architecture

## System flow

```text
Typer CLI
  -> safe repository ingestion
  -> Python AST / JS-TS Tree-sitter analysis
  -> typed Candidate and evidence graph
  -> confidence scoring and cost-aware routing
  -> optional Verifier / Critic / Arbiter review
  -> validated Finding objects
  -> canonical ReportEnvelope
  -> JSON or escaped self-contained HTML
  -> optional location-based benchmark scorer
```

JSON is the canonical representation; HTML is a rendering of the same validated envelope. Repository-relative paths, stable ordering, and content-based finding identifiers make offline results comparable between runs.

## Component boundaries

- `ingest` discovers only supported source files, rejects links and reparse points, enforces byte/file/depth limits, and emits structured diagnostics.
- `analyzers` parse code without execution and produce candidates for four locked rules. Evidence nodes represent sources, propagation, constraints, sanitizers, and sinks.
- `workflow` calibrates confidence, applies deterministic confirm/reject/review routes, and invokes adversarial review only for eligible ambiguous findings.
- `providers` bounds, redacts, sends, and validates OpenAI-compatible review requests while enforcing request/token/cost budgets.
- `reporting` computes run metrics and serializes escaped output from validated DTOs.
- `benchmark` loads independent truth and scores unique findings by rule, normalized path, and overlapping line range.
- `cli` is a thin orchestration layer. It does not reimplement analysis or scoring.

## Agent semantics

The Agent roles are contract-bound stages rather than unrestricted personas. Verifier argues from graph nodes that support exploitability; Critic searches for sanitizers, constraints, constants, and reachability counterevidence; Arbiter may cite only validated graph nodes and structured prior decisions. A malformed or budget-blocked review cannot increase confidence.

## Determinism and budgets

Offline mode makes no provider call. Files, candidates, nodes, decisions, and findings are stably sorted. Model-assisted decisions are recorded separately with requests, token usage, estimated cost, route reason, and latency. Hard limits are checked before each provider request.

## Deliberate limits

The MVP uses local, bounded data-flow. It does not implement complete interprocedural aliases, cross-file framework resolution, dynamic-language runtime semantics, or runtime exploitability. Those limits preserve predictable latency and make evidence reviewable, but they can cause both false negatives and conservative `needs_review` outcomes.

