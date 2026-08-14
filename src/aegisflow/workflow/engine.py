"""Deterministic routing and finding construction for audit candidates."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from aegisflow.config import RoutingPolicy
from aegisflow.contracts import (
    AgentDecision,
    AgentRole,
    BudgetState,
    Candidate,
    DecisionVerdict,
    Disposition,
    EvidenceNodeKind,
    EvidenceRelation,
    Finding,
    RoutingAction,
    RoutingDecision,
    ScanMode,
    build_finding_id,
)
from aegisflow.providers import ReviewProvider, review_candidate


@dataclass(frozen=True)
class WorkflowResult:
    """Local workflow output with the caller-owned budget after processing."""

    findings: list[Finding]
    budget: BudgetState | None


def _has_complete_evidence(candidate: Candidate) -> bool:
    sources = {node.node_id for node in candidate.nodes if node.kind == EvidenceNodeKind.SOURCE}
    sinks = {node.node_id for node in candidate.nodes if node.kind == EvidenceNodeKind.SINK}
    if not sources or not sinks:
        return False

    adjacency: dict[str, set[str]] = {}
    for edge in candidate.edges:
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


def route_candidate(
    candidate: Candidate,
    policy: RoutingPolicy,
    budget: BudgetState | None = None,
) -> RoutingDecision:
    """Choose the next stage using only validated, deterministic evidence."""

    if candidate.proven_safe:
        return RoutingDecision(action=RoutingAction.REJECT, reason="proven_safe")
    if _has_complete_evidence(candidate) and candidate.confidence >= policy.auto_confirm_confidence:
        return RoutingDecision(
            action=RoutingAction.CONFIRM,
            reason="complete_local_evidence",
        )
    if candidate.severity in policy.agent_review_severities:
        if budget is not None and not budget.can_review():
            return RoutingDecision(
                action=RoutingAction.NEEDS_REVIEW,
                reason="agent_budget_unavailable",
            )
        return RoutingDecision(
            action=RoutingAction.AGENT_REVIEW,
            reason="high_risk_ambiguous",
        )
    return RoutingDecision(
        action=RoutingAction.NEEDS_REVIEW,
        reason="insufficient_local_evidence",
    )


def _reason_code(reason: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", reason.upper()).strip("_")


def _local_decision(candidate: Candidate, route: RoutingDecision) -> AgentDecision:
    supporting = [
        node.node_id
        for node in candidate.nodes
        if node.kind
        in {EvidenceNodeKind.SOURCE, EvidenceNodeKind.PROPAGATION, EvidenceNodeKind.SINK}
    ]
    counterevidence = [
        node.node_id
        for node in candidate.nodes
        if node.kind in {EvidenceNodeKind.SANITIZER, EvidenceNodeKind.CONSTRAINT}
    ]
    verdict_by_action = {
        RoutingAction.CONFIRM: DecisionVerdict.CONFIRM,
        RoutingAction.REJECT: DecisionVerdict.REJECT,
        RoutingAction.AGENT_REVIEW: DecisionVerdict.NEEDS_REVIEW,
        RoutingAction.NEEDS_REVIEW: DecisionVerdict.NEEDS_REVIEW,
    }
    rationale_by_action = {
        RoutingAction.CONFIRM: (
            "Validated local evidence contains a high-confidence source-to-sink path."
        ),
        RoutingAction.REJECT: "Deterministic analysis proved that the candidate is safe.",
        RoutingAction.AGENT_REVIEW: (
            "High-risk evidence is ambiguous and requires structured review."
        ),
        RoutingAction.NEEDS_REVIEW: "Local evidence is insufficient for an automatic disposition.",
    }
    return AgentDecision(
        agent=AgentRole.SCOUT,
        verdict=verdict_by_action[route.action],
        confidence=candidate.confidence,
        reason_codes=[_reason_code(route.reason)],
        supporting_node_ids=supporting,
        counterevidence_node_ids=counterevidence,
        rationale=rationale_by_action[route.action],
        latency_ms=0,
    )


def _make_finding(
    candidate: Candidate,
    disposition: Disposition,
    confidence: float,
    decisions: list[AgentDecision],
) -> Finding:
    return Finding(
        finding_id=build_finding_id(
            candidate.rule_id,
            candidate.path,
            candidate.start_line,
            candidate.end_line,
            candidate.nodes,
        ),
        rule_id=candidate.rule_id,
        cwe=candidate.cwe,
        title=candidate.title,
        severity=candidate.severity,
        confidence=confidence,
        disposition=disposition,
        language=candidate.language,
        path=candidate.path,
        start_line=candidate.start_line,
        end_line=candidate.end_line,
        nodes=candidate.nodes,
        edges=candidate.edges,
        decisions=[*candidate.decisions, *decisions],
        remediation=candidate.remediation,
    )


def build_finding(candidate: Candidate, policy: RoutingPolicy) -> Finding:
    """Build a deterministic local finding without invoking an external provider."""

    route = route_candidate(candidate, policy)
    disposition_by_action = {
        RoutingAction.CONFIRM: Disposition.CONFIRMED,
        RoutingAction.REJECT: Disposition.REJECTED,
        RoutingAction.AGENT_REVIEW: Disposition.NEEDS_REVIEW,
        RoutingAction.NEEDS_REVIEW: Disposition.NEEDS_REVIEW,
    }
    return _make_finding(
        candidate,
        disposition_by_action[route.action],
        candidate.confidence,
        [_local_decision(candidate, route)],
    )


def _reviewed_finding(
    candidate: Candidate,
    policy: RoutingPolicy,
    decisions: list[AgentDecision],
) -> Finding:
    arbiter = next(
        (decision for decision in reversed(decisions) if decision.agent == AgentRole.ARBITER),
        None,
    )
    if arbiter is None:
        disposition = Disposition.NEEDS_REVIEW
        confidence = candidate.confidence
    elif arbiter.verdict == DecisionVerdict.CONFIRM and _has_complete_evidence(candidate):
        disposition = Disposition.CONFIRMED
        confidence = arbiter.confidence
    elif arbiter.verdict == DecisionVerdict.REJECT:
        disposition = Disposition.REJECTED
        confidence = arbiter.confidence
    else:
        disposition = Disposition.NEEDS_REVIEW
        confidence = arbiter.confidence

    route = RoutingDecision(action=RoutingAction.AGENT_REVIEW, reason="high_risk_ambiguous")
    return _make_finding(
        candidate,
        disposition,
        confidence,
        [_local_decision(candidate, route), *decisions],
    )


def process_candidates(
    candidates: Sequence[Candidate],
    policy: RoutingPolicy,
    mode: ScanMode = ScanMode.OFFLINE,
    provider: ReviewProvider | None = None,
    budget: BudgetState | None = None,
) -> WorkflowResult:
    """Process candidates in stable order and degrade unavailable review safely."""

    ordered = sorted(
        candidates,
        key=lambda item: (
            item.path,
            item.start_line,
            item.end_line,
            item.rule_id,
            item.candidate_id,
        ),
    )
    findings: list[Finding] = []
    for candidate in ordered:
        route = route_candidate(candidate, policy, budget)
        can_run_review = (
            route.action == RoutingAction.AGENT_REVIEW
            and mode == ScanMode.AGENT
            and provider is not None
            and budget is not None
        )
        if can_run_review:
            findings.append(
                _reviewed_finding(
                    candidate,
                    policy,
                    review_candidate(candidate, provider, budget),
                )
            )
            continue
        findings.append(build_finding(candidate, policy))

    return WorkflowResult(findings=findings, budget=budget)


__all__ = [
    "WorkflowResult",
    "build_finding",
    "process_candidates",
    "route_candidate",
]
