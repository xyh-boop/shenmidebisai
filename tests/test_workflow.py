from __future__ import annotations

from collections.abc import Sequence

from aegisflow.config import RoutingPolicy
from aegisflow.contracts import (
    AgentDecision,
    AgentRole,
    BudgetState,
    Candidate,
    DecisionVerdict,
    Disposition,
    EvidenceEdge,
    EvidenceNode,
    ScanMode,
)
from aegisflow.workflow import build_finding, process_candidates, route_candidate


def make_candidate(
    *,
    confidence: float = 0.94,
    complete: bool = True,
    proven_safe: bool = False,
    severity: str = "high",
    path: str = "src/app.py",
) -> Candidate:
    source = EvidenceNode(
        node_id="source",
        kind="source",
        path=path,
        line=3,
        symbol="request.args['command']",
        snippet="command = request.args['command']",
        description="Request-controlled command",
    )
    sink = EvidenceNode(
        node_id="sink",
        kind="sink",
        path=path,
        line=8,
        symbol="os.system",
        snippet="os.system(command)",
        description="Shell command execution",
    )
    nodes = [source, sink] if complete else [sink]
    edges = (
        [EvidenceEdge(source_id="source", target_id="sink", relation="flows_to")]
        if complete
        else []
    )
    return Candidate(
        candidate_id=f"candidate-{path}",
        rule_id="AF-CMD-001",
        cwe="CWE-78",
        title="User-controlled command reaches a shell",
        severity=severity,
        confidence=confidence,
        language="python",
        path=path,
        start_line=8,
        end_line=8,
        nodes=nodes,
        edges=edges,
        remediation="Use a fixed executable and an argument vector.",
        proven_safe=proven_safe,
        evidence_complete=complete,
        suppressors=["allowlist"] if proven_safe else [],
    )


def decision(
    role: AgentRole,
    verdict: DecisionVerdict,
    *,
    confidence: float = 0.8,
) -> AgentDecision:
    return AgentDecision(
        agent=role,
        verdict=verdict,
        confidence=confidence,
        reason_codes=[f"{role.value.upper()}_RESULT"],
        supporting_node_ids=["source", "sink"] if verdict == DecisionVerdict.CONFIRM else [],
        counterevidence_node_ids=["source"] if verdict == DecisionVerdict.REJECT else [],
        rationale=f"Structured {role.value} decision.",
        latency_ms=1,
    )


class SequenceProvider:
    def __init__(self, decisions: Sequence[AgentDecision]) -> None:
        self.decisions = list(decisions)
        self.roles: list[AgentRole] = []

    def review(
        self,
        role: AgentRole,
        candidate: Candidate,
        prior_decisions: Sequence[AgentDecision],
        budget: BudgetState,
    ) -> AgentDecision:
        del candidate, prior_decisions, budget
        self.roles.append(role)
        return self.decisions[len(self.roles) - 1]


def budget() -> BudgetState:
    return BudgetState(
        max_requests=3,
        max_prompt_tokens=100_000,
        max_completion_tokens=10_000,
        max_cost_usd=10.0,
    )


def test_complete_high_confidence_candidate_is_auto_confirmed() -> None:
    candidate = make_candidate()

    route = route_candidate(candidate, RoutingPolicy())
    finding = build_finding(candidate, RoutingPolicy())

    assert route.action.value == "confirm"
    assert route.reason == "complete_local_evidence"
    assert finding.disposition == Disposition.CONFIRMED
    assert finding.finding_id
    assert finding.decisions[0].agent == AgentRole.SCOUT


def test_proven_safe_candidate_is_rejected_before_confidence_routing() -> None:
    candidate = make_candidate(proven_safe=True, confidence=0.99)

    finding = build_finding(candidate, RoutingPolicy())

    assert finding.disposition == Disposition.REJECTED
    assert finding.decisions[0].reason_codes == ["PROVEN_SAFE"]


def test_evidence_completeness_is_derived_from_graph_not_boolean_flag() -> None:
    candidate = make_candidate(complete=False)
    candidate.evidence_complete = True

    route = route_candidate(candidate, RoutingPolicy())

    assert route.action.value == "agent_review"


def test_low_risk_ambiguous_candidate_requires_human_review() -> None:
    candidate = make_candidate(complete=False, severity="medium")

    finding = build_finding(candidate, RoutingPolicy())

    assert finding.disposition == Disposition.NEEDS_REVIEW
    assert finding.decisions[0].verdict == DecisionVerdict.NEEDS_REVIEW


def test_offline_ambiguous_candidate_never_invokes_provider() -> None:
    provider = SequenceProvider([])

    result = process_candidates(
        [make_candidate(confidence=0.5)],
        RoutingPolicy(),
        mode=ScanMode.OFFLINE,
        provider=provider,
        budget=budget(),
    )

    assert result.findings[0].disposition == Disposition.NEEDS_REVIEW
    assert provider.roles == []


def test_agent_review_runs_strict_role_order_and_applies_arbiter() -> None:
    provider = SequenceProvider(
        [
            decision(AgentRole.VERIFIER, DecisionVerdict.CONFIRM),
            decision(AgentRole.CRITIC, DecisionVerdict.NEEDS_REVIEW),
            decision(AgentRole.ARBITER, DecisionVerdict.CONFIRM, confidence=0.91),
        ]
    )

    result = process_candidates(
        [make_candidate(confidence=0.7)],
        RoutingPolicy(),
        mode=ScanMode.AGENT,
        provider=provider,
        budget=budget(),
    )

    assert provider.roles == [AgentRole.VERIFIER, AgentRole.CRITIC, AgentRole.ARBITER]
    assert result.findings[0].disposition == Disposition.CONFIRMED
    assert result.findings[0].confidence == 0.91


def test_agent_rejection_and_stable_candidate_order() -> None:
    first = make_candidate(confidence=0.7, path="z.py")
    second = make_candidate(confidence=0.7, path="a.py")
    provider = SequenceProvider(
        [
            decision(AgentRole.VERIFIER, DecisionVerdict.NEEDS_REVIEW),
            decision(AgentRole.CRITIC, DecisionVerdict.REJECT),
            decision(AgentRole.ARBITER, DecisionVerdict.REJECT, confidence=0.96),
        ]
        * 2
    )

    result = process_candidates(
        [first, second],
        RoutingPolicy(),
        mode=ScanMode.AGENT,
        provider=provider,
        budget=budget(),
    )

    assert [item.path for item in result.findings] == ["a.py", "z.py"]
    assert all(item.disposition == Disposition.REJECTED for item in result.findings)


def test_unavailable_budget_leaves_ambiguous_candidate_for_review() -> None:
    exhausted = BudgetState(
        max_requests=0,
        max_prompt_tokens=0,
        max_completion_tokens=0,
        max_cost_usd=0,
    )
    provider = SequenceProvider([])

    result = process_candidates(
        [make_candidate(confidence=0.7)],
        RoutingPolicy(),
        mode=ScanMode.AGENT,
        provider=provider,
        budget=exhausted,
    )

    assert result.findings[0].disposition == Disposition.NEEDS_REVIEW
    assert provider.roles == []
    assert result.budget == exhausted
