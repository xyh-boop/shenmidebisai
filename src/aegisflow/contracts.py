"""Validated data contracts shared by all AegisFlow workflow stages."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class StringEnum(StrEnum):
    """String enum whose values serialize without custom encoders."""


class EvidenceNodeKind(StringEnum):
    SOURCE = "source"
    PROPAGATION = "propagation"
    SANITIZER = "sanitizer"
    CONSTRAINT = "constraint"
    SINK = "sink"
    CONTEXT = "context"


class EvidenceRelation(StringEnum):
    FLOWS_TO = "flows_to"
    SANITIZED_BY = "sanitized_by"
    GUARDED_BY = "guarded_by"
    DERIVED_FROM = "derived_from"


class AgentRole(StringEnum):
    SCOUT = "scout"
    TRACER = "tracer"
    VERIFIER = "verifier"
    CRITIC = "critic"
    ARBITER = "arbiter"


class DecisionVerdict(StringEnum):
    CONFIRM = "confirm"
    REJECT = "reject"
    NEEDS_REVIEW = "needs_review"


class Severity(StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Disposition(StringEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    REJECTED = "rejected"
    NEEDS_REVIEW = "needs_review"


class Language(StringEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


class RoutingAction(StringEnum):
    CONFIRM = "confirm"
    REJECT = "reject"
    AGENT_REVIEW = "agent_review"
    NEEDS_REVIEW = "needs_review"


class DiagnosticLevel(StringEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ScanMode(StringEnum):
    OFFLINE = "offline"
    AGENT = "agent"


def normalize_repo_path(value: str) -> str:
    """Validate a normalized repository-relative POSIX path."""

    if not value or value != value.strip():
        raise ValueError("path must be a non-empty trimmed string")
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("path must be repository-relative and use '/' separators")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must be normalized and may not traverse parents")
    normalized = PurePosixPath(value).as_posix()
    if normalized != value:
        raise ValueError("path must already be normalized")
    return normalized


def _non_empty(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("value must not be empty")
    return value.strip()


def _stable_unique(values: list[str], *, field_name: str) -> list[str]:
    normalized = [_non_empty(value) for value in values]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return sorted(normalized)


class ContractModel(BaseModel):
    """Base contract with forbidden extras and canonical serialization."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        allow_inf_nan=False,
    )

    def canonical_data(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


class EvidenceNode(ContractModel):
    node_id: str
    kind: EvidenceNodeKind
    path: str
    line: int = Field(ge=1)
    symbol: str | None
    snippet: str
    description: str

    _validate_node_id = field_validator("node_id")(_non_empty)
    _validate_path = field_validator("path")(normalize_repo_path)
    _validate_description = field_validator("description")(_non_empty)

    @field_validator("symbol")
    @classmethod
    def normalize_symbol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class EvidenceEdge(ContractModel):
    source_id: str
    target_id: str
    relation: EvidenceRelation

    _validate_source = field_validator("source_id")(_non_empty)
    _validate_target = field_validator("target_id")(_non_empty)


class AgentDecision(ContractModel):
    agent: AgentRole
    verdict: DecisionVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list)
    supporting_node_ids: list[str] = Field(default_factory=list)
    counterevidence_node_ids: list[str] = Field(default_factory=list)
    rationale: str
    latency_ms: int = Field(ge=0)

    _validate_rationale = field_validator("rationale")(_non_empty)

    @field_validator("reason_codes", "supporting_node_ids", "counterevidence_node_ids")
    @classmethod
    def sort_unique_values(cls, value: list[str], info: Any) -> list[str]:
        return _stable_unique(value, field_name=info.field_name)


def _validate_graph(
    nodes: list[EvidenceNode],
    edges: list[EvidenceEdge],
    decisions: list[AgentDecision] | None = None,
) -> None:
    node_ids = [node.node_id for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("evidence node IDs must be unique")
    known_ids = set(node_ids)
    for edge in edges:
        unknown = {edge.source_id, edge.target_id} - known_ids
        if unknown:
            raise ValueError(f"edge references unknown evidence nodes: {sorted(unknown)}")
    for decision in decisions or []:
        referenced = set(decision.supporting_node_ids + decision.counterevidence_node_ids)
        unknown = referenced - known_ids
        if unknown:
            raise ValueError(f"decision references unknown evidence nodes: {sorted(unknown)}")


def _has_source_to_sink_path(nodes: list[EvidenceNode], edges: list[EvidenceEdge]) -> bool:
    sources = {node.node_id for node in nodes if node.kind == EvidenceNodeKind.SOURCE}
    sinks = {node.node_id for node in nodes if node.kind == EvidenceNodeKind.SINK}
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        if edge.relation in {EvidenceRelation.FLOWS_TO, EvidenceRelation.DERIVED_FROM}:
            adjacency.setdefault(edge.source_id, set()).add(edge.target_id)
    pending = list(sources)
    visited = set(sources)
    while pending:
        current = pending.pop()
        if current in sinks:
            return True
        for target in adjacency.get(current, set()):
            if target not in visited:
                visited.add(target)
                pending.append(target)
    return False


def _sort_nodes(nodes: list[EvidenceNode]) -> list[EvidenceNode]:
    return sorted(nodes, key=lambda node: (node.path, node.line, node.kind.value, node.node_id))


def _sort_edges(edges: list[EvidenceEdge]) -> list[EvidenceEdge]:
    return sorted(edges, key=lambda edge: (edge.source_id, edge.target_id, edge.relation.value))


def _sort_decisions(decisions: list[AgentDecision]) -> list[AgentDecision]:
    role_order = {role: index for index, role in enumerate(AgentRole)}
    return sorted(
        decisions,
        key=lambda decision: (
            role_order[decision.agent],
            decision.verdict.value,
            decision.rationale,
        ),
    )


def build_finding_id(
    rule_id: str,
    path: str,
    start_line: int,
    end_line: int,
    nodes: list[EvidenceNode],
) -> str:
    """Build the spec-defined stable finding fingerprint."""

    normalized_path = normalize_repo_path(path)
    evidence_identity = [
        [node.node_id, node.kind.value, node.path, node.line, node.symbol]
        for node in _sort_nodes(nodes)
    ]
    payload = json.dumps(
        [rule_id.strip(), normalized_path, start_line, end_line, evidence_identity],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Finding(ContractModel):
    finding_id: str
    rule_id: str
    cwe: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    disposition: Disposition
    language: Language
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    decisions: list[AgentDecision]
    remediation: str

    _validate_finding_id = field_validator("finding_id")(_non_empty)
    _validate_rule_id = field_validator("rule_id")(_non_empty)
    _validate_cwe = field_validator("cwe")(_non_empty)
    _validate_title = field_validator("title")(_non_empty)
    _validate_path = field_validator("path")(normalize_repo_path)
    _validate_remediation = field_validator("remediation")(_non_empty)
    _stable_nodes = field_validator("nodes")(_sort_nodes)
    _stable_edges = field_validator("edges")(_sort_edges)
    _stable_decisions = field_validator("decisions")(_sort_decisions)

    @model_validator(mode="after")
    def validate_finding(self) -> Self:
        if self.start_line > self.end_line:
            raise ValueError("start_line must not exceed end_line")
        if not _SHA256_RE.fullmatch(self.finding_id):
            raise ValueError("finding_id must be a lowercase SHA-256 digest")
        _validate_graph(self.nodes, self.edges, self.decisions)
        expected_finding_id = build_finding_id(
            self.rule_id,
            self.path,
            self.start_line,
            self.end_line,
            self.nodes,
        )
        if self.finding_id != expected_finding_id:
            raise ValueError("finding_id does not match the finding evidence identity")
        if self.disposition in {Disposition.CONFIRMED, Disposition.LIKELY}:
            if not any(node.kind == EvidenceNodeKind.SINK for node in self.nodes):
                raise ValueError("confirmed or likely findings require a sink node")
            if not any(node.kind != EvidenceNodeKind.SINK for node in self.nodes):
                raise ValueError("confirmed or likely findings require supporting evidence")
            if self.cwe in {"CWE-22", "CWE-78", "CWE-89"} and not _has_source_to_sink_path(
                self.nodes, self.edges
            ):
                raise ValueError(f"{self.cwe} findings require a source-to-sink evidence path")
        return self


class RunMetrics(ContractModel):
    files_scanned: int = Field(ge=0)
    lines_scanned: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    time_to_first_high_ms: int | None = Field(default=None, ge=0)
    candidates_total: int = Field(ge=0)
    findings_confirmed: int = Field(ge=0)
    findings_rejected: int = Field(ge=0)
    human_review_required: int = Field(ge=0)
    model_requests: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0.0)


class SourceFile(ContractModel):
    path: str
    language: Language
    content: str
    size_bytes: int = Field(ge=0)
    encoding: str = "utf-8"

    _validate_path = field_validator("path")(normalize_repo_path)
    _validate_encoding = field_validator("encoding")(_non_empty)

    @model_validator(mode="after")
    def validate_size(self) -> Self:
        if len(self.content.encode(self.encoding)) != self.size_bytes:
            raise ValueError("size_bytes must match the encoded content length")
        return self

    @property
    def line_count(self) -> int:
        return len(self.content.splitlines())

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode(self.encoding)).hexdigest()


class Candidate(ContractModel):
    candidate_id: str
    rule_id: str
    cwe: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    language: Language
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    remediation: str
    proven_safe: bool = False
    evidence_complete: bool = False
    suppressors: list[str] = Field(default_factory=list)
    decisions: list[AgentDecision] = Field(default_factory=list)

    _validate_candidate_id = field_validator("candidate_id")(_non_empty)
    _validate_rule_id = field_validator("rule_id")(_non_empty)
    _validate_cwe = field_validator("cwe")(_non_empty)
    _validate_title = field_validator("title")(_non_empty)
    _validate_path = field_validator("path")(normalize_repo_path)
    _validate_remediation = field_validator("remediation")(_non_empty)
    _stable_nodes = field_validator("nodes")(_sort_nodes)
    _stable_edges = field_validator("edges")(_sort_edges)
    _stable_decisions = field_validator("decisions")(_sort_decisions)

    @field_validator("suppressors")
    @classmethod
    def sort_suppressors(cls, value: list[str]) -> list[str]:
        return _stable_unique(value, field_name="suppressors")

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if self.start_line > self.end_line:
            raise ValueError("start_line must not exceed end_line")
        _validate_graph(self.nodes, self.edges, self.decisions)
        return self


class RoutingDecision(ContractModel):
    action: RoutingAction
    reason: str

    _validate_reason = field_validator("reason")(_non_empty)


class Diagnostic(ContractModel):
    code: str
    level: DiagnosticLevel
    message: str
    path: str | None = None
    line: int | None = Field(default=None, ge=1)

    _validate_code = field_validator("code")(_non_empty)
    _validate_message = field_validator("message")(_non_empty)

    @field_validator("path")
    @classmethod
    def validate_optional_path(cls, value: str | None) -> str | None:
        return normalize_repo_path(value) if value is not None else None


class RunMetadata(ContractModel):
    run_id: str
    mode: ScanMode
    root: str
    started_at: datetime
    completed_at: datetime
    configuration_digest: str

    _validate_run_id = field_validator("run_id")(_non_empty)
    _validate_root = field_validator("root")(_non_empty)

    @field_validator("configuration_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("configuration_digest must be a lowercase SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_timestamps(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class ReportEnvelope(ContractModel):
    schema_version: str
    tool_version: str
    run: RunMetadata
    metrics: RunMetrics
    findings: list[Finding]
    diagnostics: list[Diagnostic]

    _validate_schema_version = field_validator("schema_version")(_non_empty)
    _validate_tool_version = field_validator("tool_version")(_non_empty)

    @field_validator("findings")
    @classmethod
    def sort_findings(cls, value: list[Finding]) -> list[Finding]:
        return sorted(
            value,
            key=lambda finding: (
                finding.path,
                finding.start_line,
                finding.rule_id,
                finding.finding_id,
            ),
        )

    @field_validator("diagnostics")
    @classmethod
    def sort_diagnostics(cls, value: list[Diagnostic]) -> list[Diagnostic]:
        return sorted(
            value,
            key=lambda diagnostic: (
                diagnostic.path or "",
                diagnostic.line or 0,
                diagnostic.level.value,
                diagnostic.code,
            ),
        )


class GroundTruthFinding(ContractModel):
    truth_id: str
    rule_id: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    _validate_truth_id = field_validator("truth_id")(_non_empty)
    _validate_rule_id = field_validator("rule_id")(_non_empty)
    _validate_path = field_validator("path")(normalize_repo_path)

    @model_validator(mode="after")
    def validate_lines(self) -> Self:
        if self.start_line > self.end_line:
            raise ValueError("start_line must not exceed end_line")
        return self


class GroundTruth(ContractModel):
    schema_version: str
    expected: list[GroundTruthFinding]

    _validate_schema_version = field_validator("schema_version")(_non_empty)

    @field_validator("expected")
    @classmethod
    def sort_expected(cls, value: list[GroundTruthFinding]) -> list[GroundTruthFinding]:
        truth_ids = [item.truth_id for item in value]
        if len(set(truth_ids)) != len(truth_ids):
            raise ValueError("truth_id values must be unique")
        return sorted(
            value,
            key=lambda item: (item.path, item.start_line, item.rule_id, item.truth_id),
        )


class BenchmarkResult(ContractModel):
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)
    matched_finding_ids: list[str] = Field(default_factory=list)
    missed_truth_ids: list[str] = Field(default_factory=list)

    @field_validator("matched_finding_ids", "missed_truth_ids")
    @classmethod
    def sort_result_ids(cls, value: list[str], info: Any) -> list[str]:
        return _stable_unique(value, field_name=info.field_name)


class BudgetState(ContractModel):
    max_requests: int = Field(ge=0)
    max_prompt_tokens: int = Field(ge=0)
    max_completion_tokens: int = Field(ge=0)
    max_cost_usd: float = Field(ge=0.0)
    requests_used: int = Field(default=0, ge=0)
    prompt_tokens_used: int = Field(default=0, ge=0)
    completion_tokens_used: int = Field(default=0, ge=0)
    cost_usd_used: float = Field(default=0.0, ge=0.0)

    @model_validator(mode="after")
    def validate_usage(self) -> Self:
        limits_and_usage = (
            (self.requests_used, self.max_requests, "requests"),
            (self.prompt_tokens_used, self.max_prompt_tokens, "prompt tokens"),
            (self.completion_tokens_used, self.max_completion_tokens, "completion tokens"),
            (self.cost_usd_used, self.max_cost_usd, "cost"),
        )
        for used, maximum, label in limits_and_usage:
            if used > maximum:
                raise ValueError(f"used {label} may not exceed its configured maximum")
        return self

    def can_review(
        self,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> bool:
        if prompt_tokens < 0 or completion_tokens < 0 or estimated_cost_usd < 0:
            return False
        return (
            self.requests_used + 1 <= self.max_requests
            and self.prompt_tokens_used + prompt_tokens <= self.max_prompt_tokens
            and self.completion_tokens_used + completion_tokens <= self.max_completion_tokens
            and self.cost_usd_used + estimated_cost_usd <= self.max_cost_usd
        )


__all__ = [
    "AgentDecision",
    "AgentRole",
    "BenchmarkResult",
    "BudgetState",
    "Candidate",
    "DecisionVerdict",
    "Diagnostic",
    "DiagnosticLevel",
    "Disposition",
    "EvidenceEdge",
    "EvidenceNode",
    "EvidenceNodeKind",
    "EvidenceRelation",
    "Finding",
    "GroundTruth",
    "GroundTruthFinding",
    "Language",
    "ReportEnvelope",
    "RoutingAction",
    "RoutingDecision",
    "RunMetadata",
    "RunMetrics",
    "ScanMode",
    "Severity",
    "SourceFile",
    "build_finding_id",
    "normalize_repo_path",
]
