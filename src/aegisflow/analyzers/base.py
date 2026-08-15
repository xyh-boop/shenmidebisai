"""Shared deterministic primitives for language-specific source analyzers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from aegisflow.config import AnalysisConfig
from aegisflow.contracts import (
    Candidate,
    EvidenceEdge,
    EvidenceNode,
    EvidenceNodeKind,
    EvidenceRelation,
    Severity,
    SourceFile,
)


class RiskDomain(StrEnum):
    COMMAND = "command"
    SQL = "sql"
    PATH = "path"
    DESERIALIZATION = "deserialization"


ALL_RISK_DOMAINS: Final[frozenset[RiskDomain]] = frozenset(RiskDomain)


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    cwe: str
    title: str
    severity: Severity
    remediation: str
    domain: RiskDomain


RULES: Final[dict[str, RuleMetadata]] = {
    "AF-CMD-001": RuleMetadata(
        rule_id="AF-CMD-001",
        cwe="CWE-78",
        title="User-controlled data reaches an operating system command",
        severity=Severity.HIGH,
        remediation=(
            "Avoid shell command construction. Use an argument-vector API, disable shell mode, "
            "and validate inputs against a strict allowlist."
        ),
        domain=RiskDomain.COMMAND,
    ),
    "AF-SQL-001": RuleMetadata(
        rule_id="AF-SQL-001",
        cwe="CWE-89",
        title="User-controlled data is interpolated into a SQL statement",
        severity=Severity.HIGH,
        remediation=(
            "Use parameterized queries or prepared statements and keep untrusted values out of "
            "the SQL text."
        ),
        domain=RiskDomain.SQL,
    ),
    "AF-PATH-001": RuleMetadata(
        rule_id="AF-PATH-001",
        cwe="CWE-22",
        title="User-controlled data reaches a filesystem path",
        severity=Severity.HIGH,
        remediation=(
            "Resolve the requested path under a fixed base directory and reject paths outside it; "
            "use an allowlist or a safe basename where appropriate."
        ),
        domain=RiskDomain.PATH,
    ),
    "AF-DESER-001": RuleMetadata(
        rule_id="AF-DESER-001",
        cwe="CWE-502",
        title="Untrusted data reaches an unsafe deserializer",
        severity=Severity.HIGH,
        remediation=(
            "Use a data-only format such as JSON or a safe loader, authenticate serialized data, "
            "and never deserialize attacker-controlled objects."
        ),
        domain=RiskDomain.DESERIALIZATION,
    ),
}


def stable_digest(*parts: object) -> str:
    payload = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def stable_node_id(
    path: str,
    kind: EvidenceNodeKind,
    line: int,
    symbol: str | None,
    snippet: str,
    description: str,
) -> str:
    return f"node-{stable_digest(path, kind.value, line, symbol, snippet, description)[:24]}"


@dataclass
class DomainTrace:
    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)
    tail_id: str | None = None
    tainted: bool = False
    suppressors: set[str] = field(default_factory=set)
    source_confidence: float = 0.0

    def clone(self) -> DomainTrace:
        return DomainTrace(
            nodes=list(self.nodes),
            edges=list(self.edges),
            tail_id=self.tail_id,
            tainted=self.tainted,
            suppressors=set(self.suppressors),
            source_confidence=self.source_confidence,
        )


@dataclass(frozen=True)
class PathResolution:
    resolved: bool
    base_symbol: str | None = None


@dataclass
class Trace:
    """Bounded local flows separated by vulnerability risk domain."""

    flows: dict[RiskDomain, DomainTrace] = field(default_factory=dict)
    constant: bool = False
    path_resolution: PathResolution | None = None

    @property
    def tainted(self) -> bool:
        return any(flow.tainted for flow in self.flows.values())

    @property
    def suppressors(self) -> set[str]:
        return (
            set().union(*(flow.suppressors for flow in self.flows.values()))
            if self.flows
            else set()
        )

    @property
    def active(self) -> bool:
        return self.tainted or bool(self.suppressors)

    def clone(self) -> Trace:
        return Trace(
            flows={domain: flow.clone() for domain, flow in self.flows.items()},
            constant=self.constant,
            path_resolution=self.path_resolution,
        )


class CandidateBuilder:
    def __init__(self, source: SourceFile, config: AnalysisConfig) -> None:
        self.source = source
        self.config = config
        self._lines = source.content.splitlines()

    def snippet(self, line: int, fallback: str = "") -> str:
        text = self._lines[line - 1].strip() if 1 <= line <= len(self._lines) else fallback.strip()
        encoded = text.encode("utf-8")
        if len(encoded) <= self.config.max_snippet_bytes:
            return text
        return encoded[: self.config.max_snippet_bytes].decode("utf-8", errors="ignore")

    def node(
        self,
        kind: EvidenceNodeKind,
        line: int,
        symbol: str | None,
        description: str,
        *,
        snippet: str | None = None,
    ) -> EvidenceNode:
        evidence = self.snippet(line) if snippet is None else snippet
        return EvidenceNode(
            node_id=stable_node_id(
                self.source.path,
                kind,
                line,
                symbol,
                evidence,
                description,
            ),
            kind=kind,
            path=self.source.path,
            line=max(line, 1),
            symbol=symbol,
            snippet=evidence,
            description=description,
        )

    def source_trace(
        self,
        line: int,
        symbol: str | None,
        description: str,
        *,
        confidence: float = 1.0,
        domains: frozenset[RiskDomain] = ALL_RISK_DOMAINS,
    ) -> Trace:
        node = self.node(EvidenceNodeKind.SOURCE, line, symbol, description)
        return Trace(
            flows={
                domain: DomainTrace(
                    nodes=[node],
                    tail_id=node.node_id,
                    tainted=True,
                    source_confidence=confidence,
                )
                for domain in domains
            }
        )

    def constant_trace(self) -> Trace:
        return Trace(constant=True)

    def propagate(
        self,
        traces: list[Trace],
        line: int,
        symbol: str | None,
        description: str,
    ) -> Trace:
        result = Trace(constant=bool(traces) and all(trace.constant for trace in traces))
        for domain in RiskDomain:
            domain_flows = [trace.flows[domain] for trace in traces if domain in trace.flows]
            tainted_flows = [flow for flow in domain_flows if flow.tainted]
            selected = tainted_flows or [flow for flow in domain_flows if flow.suppressors]
            if not selected:
                continue
            node = self.node(EvidenceNodeKind.PROPAGATION, line, symbol, description)
            nodes = [item for flow in selected for item in flow.nodes]
            edges = [item for flow in selected for item in flow.edges]
            for flow in selected:
                if flow.tail_id:
                    edges.append(
                        EvidenceEdge(
                            source_id=flow.tail_id,
                            target_id=node.node_id,
                            relation=EvidenceRelation.FLOWS_TO,
                        )
                    )
            nodes.append(node)
            result.flows[domain] = DomainTrace(
                nodes=self._unique_nodes(nodes),
                edges=self._unique_edges(edges),
                tail_id=node.node_id,
                tainted=bool(tainted_flows),
                suppressors=(
                    set()
                    if tainted_flows
                    else set().union(*(flow.suppressors for flow in selected))
                ),
                source_confidence=max(flow.source_confidence for flow in selected),
            )
        return result

    def sanitize(
        self,
        trace: Trace,
        line: int,
        symbol: str | None,
        description: str,
        reason: str,
        domain: RiskDomain,
    ) -> Trace:
        return self._suppress(
            trace,
            line,
            symbol,
            description,
            reason,
            domain,
            EvidenceNodeKind.SANITIZER,
            EvidenceRelation.SANITIZED_BY,
        )

    def constrain(
        self,
        trace: Trace,
        line: int,
        symbol: str | None,
        description: str,
        reason: str,
        domain: RiskDomain,
    ) -> Trace:
        return self._suppress(
            trace,
            line,
            symbol,
            description,
            reason,
            domain,
            EvidenceNodeKind.CONSTRAINT,
            EvidenceRelation.GUARDED_BY,
        )

    def _suppress(
        self,
        trace: Trace,
        line: int,
        symbol: str | None,
        description: str,
        reason: str,
        domain: RiskDomain,
        kind: EvidenceNodeKind,
        relation: EvidenceRelation,
    ) -> Trace:
        result = trace.clone()
        flow = result.flows.get(domain)
        if flow is None or (not flow.tainted and not flow.suppressors):
            return result
        node = self.node(kind, line, symbol, description)
        flow.nodes = self._unique_nodes([*flow.nodes, node])
        if flow.tail_id:
            flow.edges = self._unique_edges(
                [
                    *flow.edges,
                    EvidenceEdge(
                        source_id=flow.tail_id,
                        target_id=node.node_id,
                        relation=relation,
                    ),
                ]
            )
        flow.tail_id = node.node_id
        flow.tainted = False
        flow.suppressors.add(reason)
        return result

    def candidate(
        self,
        rule_id: str,
        trace: Trace,
        line: int,
        end_line: int,
        sink_symbol: str,
        sink_description: str,
        *,
        confidence: float,
    ) -> Candidate | None:
        if rule_id not in RULES or not self.rule_enabled(rule_id):
            return None
        metadata = RULES[rule_id]
        flow = trace.flows.get(metadata.domain)
        if flow is None or not flow.tainted:
            return None
        sink = self.node(EvidenceNodeKind.SINK, line, sink_symbol, sink_description)
        nodes = self._unique_nodes([*flow.nodes, sink])
        edges = list(flow.edges)
        if flow.tail_id:
            edges.append(
                EvidenceEdge(
                    source_id=flow.tail_id,
                    target_id=sink.node_id,
                    relation=EvidenceRelation.FLOWS_TO,
                )
            )
        edges = self._unique_edges(edges)
        candidate_id = stable_digest(
            rule_id,
            self.source.path,
            line,
            end_line,
            [node.node_id for node in nodes],
        )
        return Candidate(
            candidate_id=candidate_id,
            rule_id=metadata.rule_id,
            cwe=metadata.cwe,
            title=metadata.title,
            severity=metadata.severity,
            confidence=min(confidence, flow.source_confidence),
            language=self.source.language,
            path=self.source.path,
            start_line=max(line, 1),
            end_line=max(end_line, line, 1),
            nodes=nodes,
            edges=edges,
            remediation=metadata.remediation,
            proven_safe=False,
            evidence_complete=any(node.kind == EvidenceNodeKind.SOURCE for node in nodes),
            suppressors=sorted(flow.suppressors),
        )

    def rule_enabled(self, rule_id: str) -> bool:
        return not self.config.enabled_rule_ids or rule_id in self.config.enabled_rule_ids

    @staticmethod
    def _unique_nodes(nodes: list[EvidenceNode]) -> list[EvidenceNode]:
        by_id = {node.node_id: node for node in nodes}
        return sorted(
            by_id.values(),
            key=lambda node: (node.path, node.line, node.kind.value, node.node_id),
        )

    @staticmethod
    def _unique_edges(edges: list[EvidenceEdge]) -> list[EvidenceEdge]:
        by_key = {(edge.source_id, edge.target_id, edge.relation.value): edge for edge in edges}
        return sorted(
            by_key.values(),
            key=lambda edge: (edge.source_id, edge.target_id, edge.relation.value),
        )


def candidate_sort_key(candidate: Candidate) -> tuple[str, int, int, str, str]:
    return (
        candidate.path,
        candidate.start_line,
        candidate.end_line,
        candidate.rule_id,
        candidate.candidate_id,
    )


__all__ = [
    "ALL_RISK_DOMAINS",
    "RULES",
    "CandidateBuilder",
    "PathResolution",
    "RiskDomain",
    "RuleMetadata",
    "Trace",
    "candidate_sort_key",
]
