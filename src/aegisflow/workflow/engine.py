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
    agent_failures: tuple[str, ...] = ()


_PROVIDER_FAILURE_CODES = frozenset(
    {
        "AGENT_BUDGET_EXHAUSTED",
        "AGENT_PROVIDER_CREDENTIAL_UNAVAILABLE",
        "AGENT_PROVIDER_TIMEOUT",
        "AGENT_PROVIDER_TRANSPORT_FAILURE",
        "AGENT_PROVIDER_FAILURE",
        "AGENT_PROVIDER_UNACCOUNTED_USAGE",
        "AGENT_RESPONSE_INVALID",
        "AGENT_RESPONSE_TOO_LARGE",
    }
)


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
    verifier = next(
        (decision for decision in decisions if decision.agent == AgentRole.VERIFIER),
        None,
    )
    critic = next(
        (decision for decision in decisions if decision.agent == AgentRole.CRITIC),
        None,
    )
    arbiter = next(
        (decision for decision in reversed(decisions) if decision.agent == AgentRole.ARBITER),
        None,
    )
    rejection_is_evidence_backed = _rejection_is_evidence_backed(
        candidate,
        verifier,
        critic,
        arbiter,
    )
    if arbiter is None:
        disposition = Disposition.NEEDS_REVIEW
        confidence = candidate.confidence
    elif arbiter.verdict == DecisionVerdict.CONFIRM and _has_complete_evidence(candidate):
        disposition = Disposition.CONFIRMED
        confidence = max(candidate.confidence, arbiter.confidence)
    elif arbiter.verdict == DecisionVerdict.REJECT and rejection_is_evidence_backed:
        disposition = Disposition.REJECTED
        confidence = max(candidate.confidence, arbiter.confidence)
    else:
        disposition = Disposition.NEEDS_REVIEW
        confidence = max(candidate.confidence, arbiter.confidence)

    route = RoutingDecision(action=RoutingAction.AGENT_REVIEW, reason="high_risk_ambiguous")
    return _make_finding(
        candidate,
        disposition,
        confidence,
        [_local_decision(candidate, route), *decisions],
    )


def _rejection_is_evidence_backed(
    candidate: Candidate,
    verifier: AgentDecision | None,
    critic: AgentDecision | None,
    arbiter: AgentDecision | None,
) -> bool:
    if verifier is None or verifier.verdict != DecisionVerdict.NEEDS_REVIEW:
        return False
    if critic is None or critic.verdict != DecisionVerdict.REJECT:
        return False
    if arbiter is None or arbiter.verdict != DecisionVerdict.REJECT:
        return False
    shared_counterevidence = set(critic.counterevidence_node_ids).intersection(
        arbiter.counterevidence_node_ids
    )
    return any(
        _counterevidence_is_connected(candidate, node_id) for node_id in shared_counterevidence
    )


_COUNTEREVIDENCE_MARKERS = {
    "AF-CMD-001": frozenset({"shell_argument_quoted", "shlex.quote"}),
    "AF-PATH-001": frozenset({"safe_basename", "path_containment_check"}),
    "AF-DESER-001": frozenset({"safe_data_deserializer"}),
}


def _counterevidence_matches_risk_domain(candidate: Candidate, node_id: str) -> bool:
    node = next((item for item in candidate.nodes if item.node_id == node_id), None)
    if node is None:
        return False
    text = " ".join((node.symbol or "", node.snippet, node.description)).lower()
    matched_domains = {
        rule_id
        for rule_id, markers in _COUNTEREVIDENCE_MARKERS.items()
        if any(marker in text for marker in markers)
    }
    # An unmarked counterexample has no auditable risk-domain binding.  Keep
    # rejection fail-closed even when its graph edges happen to be valid.
    return matched_domains == {candidate.rule_id}


def _counterevidence_is_connected(candidate: Candidate, node_id: str) -> bool:
    node_by_id = {node.node_id: node for node in candidate.nodes}
    counter = node_by_id.get(node_id)
    if counter is None or counter.kind not in {
        EvidenceNodeKind.SANITIZER,
        EvidenceNodeKind.CONSTRAINT,
    }:
        return False
    if counter.path != candidate.path:
        return False
    if not _counterevidence_matches_risk_domain(candidate, node_id):
        return False

    sources = {
        node.node_id
        for node in candidate.nodes
        if node.kind == EvidenceNodeKind.SOURCE and node.path == candidate.path
    }
    sinks = {
        node.node_id
        for node in candidate.nodes
        if node.kind == EvidenceNodeKind.SINK
        and node.path == candidate.path
        and candidate.start_line <= node.line <= candidate.end_line
    }
    all_sinks = {node.node_id for node in candidate.nodes if node.kind == EvidenceNodeKind.SINK}
    flow_edges = {
        EvidenceRelation.FLOWS_TO,
        EvidenceRelation.DERIVED_FROM,
    }
    forward: dict[str, set[str]] = {}
    for edge in candidate.edges:
        if edge.relation in flow_edges:
            forward.setdefault(edge.source_id, set()).add(edge.target_id)

    reachable = set(sources)
    pending = list(sources)
    while pending:
        current = pending.pop()
        if current in all_sinks:
            continue
        for target in forward.get(current, set()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)

    required_relation = (
        EvidenceRelation.SANITIZED_BY
        if counter.kind == EvidenceNodeKind.SANITIZER
        else EvidenceRelation.GUARDED_BY
    )
    connected_before = any(
        edge.target_id == node_id
        and edge.relation == required_relation
        and edge.source_id in reachable
        for edge in candidate.edges
    )
    if not connected_before:
        return False

    after = {node_id}
    pending = [node_id]
    while pending:
        current = pending.pop()
        if current in sinks:
            return True
        for target in forward.get(current, set()):
            if target not in after:
                after.add(target)
                pending.append(target)
    return bool(after.intersection(sinks))


def _review_failure_codes(
    candidate: Candidate,
    decisions: Sequence[AgentDecision],
) -> set[str]:
    failures = {
        code
        for decision in decisions
        for code in decision.reason_codes
        if code in _PROVIDER_FAILURE_CODES
    }
    arbiter = next(
        (decision for decision in reversed(decisions) if decision.agent == AgentRole.ARBITER),
        None,
    )
    if arbiter is not None and arbiter.verdict == DecisionVerdict.REJECT:
        verifier = next(
            (decision for decision in decisions if decision.agent == AgentRole.VERIFIER),
            None,
        )
        critic = next(
            (decision for decision in decisions if decision.agent == AgentRole.CRITIC),
            None,
        )
        if not _rejection_is_evidence_backed(candidate, verifier, critic, arbiter):
            failures.add("AGENT_REJECTION_EVIDENCE_INVALID")
    return failures


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
    agent_failures: set[str] = set()
    for candidate in ordered:
        route = route_candidate(candidate, policy, budget)
        agent_routed = route.action == RoutingAction.AGENT_REVIEW or (
            route.action == RoutingAction.NEEDS_REVIEW
            and route.reason == "agent_budget_unavailable"
        )
        if mode == ScanMode.AGENT and agent_routed:
            if provider is None:
                agent_failures.add("AGENT_PROVIDER_UNAVAILABLE")
            if budget is None:
                agent_failures.add("AGENT_BUDGET_UNAVAILABLE")
            elif route.reason == "agent_budget_unavailable":
                agent_failures.add("AGENT_BUDGET_EXHAUSTED")
        can_run_review = (
            route.action == RoutingAction.AGENT_REVIEW
            and mode == ScanMode.AGENT
            and provider is not None
            and budget is not None
        )
        if can_run_review:
            try:
                decisions = review_candidate(candidate, provider, budget)
            except Exception:
                decisions = []
                agent_failures.add("AGENT_PROVIDER_FAILURE")
            agent_failures.update(_review_failure_codes(candidate, decisions))
            findings.append(
                _reviewed_finding(
                    candidate,
                    policy,
                    decisions,
                )
            )
            continue
        findings.append(build_finding(candidate, policy))

    return WorkflowResult(
        findings=findings,
        budget=budget,
        agent_failures=tuple(sorted(agent_failures)),
    )


__all__ = [
    "WorkflowResult",
    "build_finding",
    "process_candidates",
    "route_candidate",
]
