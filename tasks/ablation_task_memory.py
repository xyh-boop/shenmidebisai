"""Deterministic ablation experiment for task-memory lifecycle semantics.

Run from the repository root with:
    python tasks/ablation_task_memory.py

The script intentionally models only the lifecycle operations under study:
preflight, finalize, supersede, and their invalid-state guards.  It has no
dependency on the Codex application or project packages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


ARTIFACT_PATH = Path(__file__).resolve().parents[1] / "artifacts" / "task_memory_ablation_results.json"


@dataclass(frozen=True)
class Policy:
    """Switches for the full model and one-factor ablations."""

    preflight: bool = True
    finalize: bool = True
    supersede: bool = True
    edge_guards: bool = True


@dataclass
class Task:
    task_id: str
    status: str = "active"
    successor: str | None = None


@dataclass
class TaskMemory:
    policy: Policy
    tasks: dict[str, Task] = field(default_factory=dict)
    sequence: int = 0

    def preflight(self, task_id: str) -> tuple[bool, str]:
        if self.policy.edge_guards and not task_id:
            return False, "invalid_task_id"
        if self.policy.preflight and task_id in self.tasks:
            return True, "existing"
        if not task_id:
            task_id = "unnamed"
        self.tasks[task_id] = Task(task_id=task_id)
        return True, "created"

    def finalize(self, task_id: str) -> tuple[bool, str]:
        task = self.tasks.get(task_id)
        if task is None:
            return (False, "unknown_task") if self.policy.edge_guards else (True, "ignored")
        if not self.policy.finalize:
            return True, "disabled"
        if task.status == "completed":
            return True, "already_completed"
        if task.status == "superseded" and self.policy.edge_guards:
            return False, "superseded_task"
        task.status = "completed"
        return True, "completed"

    def supersede(self, task_id: str) -> tuple[bool, str | None]:
        task = self.tasks.get(task_id)
        if task is None:
            return (False, None) if self.policy.edge_guards else (True, None)
        if not self.policy.supersede:
            return True, None
        if task.status != "active" and self.policy.edge_guards:
            return False, None
        self.sequence += 1
        successor_id = f"{task_id}#replacement-{self.sequence}"
        self.tasks[successor_id] = Task(task_id=successor_id)
        task.status = "superseded"
        task.successor = successor_id
        return True, successor_id


@dataclass(frozen=True)
class Claim:
    task_id: str
    text: str
    evidence: tuple[str, ...] = ()
    supersedes: int | None = None
    active: bool = True


@dataclass(frozen=True)
class LedgerPolicy:
    retrieve: bool = True
    evidence: bool = True
    supersede: bool = True
    guards: bool = True


@dataclass
class EvidenceLedger:
    policy: LedgerPolicy
    claims: list[Claim] = field(default_factory=list)

    def append(self, task_id: str, text: str, evidence: tuple[str, ...] = ()) -> tuple[bool, str]:
        if self.policy.guards and (not task_id or not text):
            return False, "invalid_claim"
        if self.policy.evidence and not evidence:
            return False, "missing_evidence"
        self.claims.append(Claim(task_id, text, evidence))
        return True, "appended"

    def retrieve(self, task_id: str, query: str) -> tuple[bool, object]:
        if self.policy.guards and (not task_id or not query):
            return False, "invalid_query"
        if not self.policy.retrieve:
            return True, []
        hits = [
            (i, c) for i, c in enumerate(self.claims)
            if c.active and c.task_id == task_id and query.lower() in c.text.lower()
        ]
        if len(hits) > 1 and self.policy.guards:
            return False, "conflict"
        return True, [i for i, _ in hits]

    def supersede(self, index: int, text: str, evidence: tuple[str, ...]) -> tuple[bool, str]:
        if not self.policy.supersede:
            return False, "disabled"
        if self.policy.guards and (index < 0 or index >= len(self.claims) or not self.claims[index].active):
            return False, "invalid_predecessor"
        if self.policy.evidence and not evidence:
            return False, "missing_evidence"
        old = self.claims[index]
        self.claims[index] = Claim(old.task_id, old.text, old.evidence, old.supersedes, False)
        self.claims.append(Claim(old.task_id, text, evidence, index))
        return True, "superseded"


LEDGER_SCENARIOS = (
    ("ledger_append_verified", lambda l: l.append("review", "scan passed", ("test:T1",)), lambda l, r: r == (True, "appended")),
    ("ledger_retrieves_exact_claim", lambda l: (l.append("review", "scan passed", ("test:T1",)), l.retrieve("review", "scan"))[1], lambda l, r: r == (True, [0])),
    ("ledger_rejects_missing_evidence", lambda l: l.append("review", "unverified claim"), lambda l, r: r == (False, "missing_evidence")),
    ("ledger_supersedes_with_provenance", lambda l: (l.append("review", "old decision", ("file:A",)), l.supersede(0, "new decision", ("file:B",)))[1], lambda l, r: r == (True, "superseded") and l.claims[1].supersedes == 0 and not l.claims[0].active),
    ("ledger_hides_old_claim", lambda l: (l.append("review", "old decision", ("file:A",)), l.supersede(0, "new decision", ("file:B",)), l.retrieve("review", "decision"))[2], lambda l, r: r == (True, [1])),
    ("ledger_surfaces_conflict", lambda l: (l.append("review", "decision A", ("file:A",)), l.append("review", "decision B", ("file:B",)), l.retrieve("review", "decision"))[2], lambda l, r: r == (False, "conflict")),
    ("ledger_excludes_irrelevant_query", lambda l: (l.append("review", "scan passed", ("test:T1",)), l.retrieve("review", "billing"))[1], lambda l, r: r == (True, [])),
    ("ledger_rejects_invalid_query", lambda l: l.retrieve("", "scan"), lambda l, r: r == (False, "invalid_query")),
    ("ledger_read_does_not_mutate", lambda l: (l.append("review", "scan passed", ("test:T1",)), l.retrieve("review", "scan"))[1], lambda l, r: r == (True, [0]) and len(l.claims) == 1),
)


LEDGER_VARIANTS = {
    "ledger_full": LedgerPolicy(),
    "ledger_without_retrieve": LedgerPolicy(retrieve=False),
    "ledger_without_evidence": LedgerPolicy(evidence=False),
    "ledger_without_supersede": LedgerPolicy(supersede=False),
    "ledger_without_guards": LedgerPolicy(guards=False),
}


def run_ledger_variant(name: str, policy: LedgerPolicy) -> dict[str, object]:
    outcomes = []
    for scenario, operation, expected in LEDGER_SCENARIOS:
        ledger = EvidenceLedger(policy)
        result = operation(ledger)
        outcomes.append({"scenario": scenario, "passed": expected(ledger, result), "actual_result": result})
    passed = sum(item["passed"] for item in outcomes)
    return {"variant": name, "passed": passed, "total": len(outcomes), "pass_rate": round(passed / len(outcomes), 3), "outcomes": outcomes}


Expectation = Callable[[TaskMemory, tuple[bool, object]], bool]


@dataclass(frozen=True)
class Scenario:
    name: str
    operation: Callable[[TaskMemory], tuple[bool, object]]
    expected: Expectation
    purpose: str


def _has_task(task_id: str) -> Expectation:
    return lambda memory, result: result == (True, "created") and task_id in memory.tasks


SCENARIOS = (
    Scenario(
        "preflight_creates_active_record",
        lambda memory: memory.preflight("review"),
        lambda memory, result: _has_task("review")(memory, result) and memory.tasks["review"].status == "active",
        "A new task is recorded as active before work begins.",
    ),
    Scenario(
        "preflight_is_idempotent",
        lambda memory: (memory.preflight("review"), memory.preflight("review"))[1],
        lambda memory, result: result == (True, "existing") and len(memory.tasks) == 1,
        "Repeated preparation reuses the active record instead of replacing it.",
    ),
    Scenario(
        "finalize_completes_active_task",
        lambda memory: (memory.preflight("review"), memory.finalize("review"))[1],
        lambda memory, result: result == (True, "completed") and memory.tasks["review"].status == "completed",
        "A successful task is durably marked completed.",
    ),
    Scenario(
        "finalize_is_idempotent",
        lambda memory: (memory.preflight("review"), memory.finalize("review"), memory.finalize("review"))[2],
        lambda memory, result: result == (True, "already_completed") and memory.tasks["review"].status == "completed",
        "A retry cannot reopen or duplicate a completed task.",
    ),
    Scenario(
        "supersede_links_replacement",
        lambda memory: (memory.preflight("review"), memory.supersede("review"))[1],
        lambda memory, result: bool(result[0])
        and isinstance(result[1], str)
        and memory.tasks["review"].status == "superseded"
        and memory.tasks["review"].successor == result[1]
        and memory.tasks[result[1]].status == "active",
        "Changed work preserves provenance and starts one replacement task.",
    ),
    Scenario(
        "supersede_rejects_non_active_task",
        lambda memory: (memory.preflight("review"), memory.finalize("review"), memory.supersede("review"))[2],
        lambda memory, result: result == (False, None) and len(memory.tasks) == 1,
        "Completed work cannot be silently replaced.",
    ),
    Scenario(
        "finalize_rejects_superseded_task",
        lambda memory: (memory.preflight("review"), memory.supersede("review"), memory.finalize("review"))[2],
        lambda memory, result: result == (False, "superseded_task"),
        "The obsolete task cannot overwrite the replacement lifecycle.",
    ),
    Scenario(
        "unknown_task_is_rejected",
        lambda memory: memory.finalize("missing"),
        lambda memory, result: result == (False, "unknown_task"),
        "Finalization requires a preflighted task.",
    ),
    Scenario(
        "empty_task_id_is_rejected",
        lambda memory: memory.preflight(""),
        lambda memory, result: result == (False, "invalid_task_id") and not memory.tasks,
        "Invalid identifiers do not create ambiguous records.",
    ),
)


VARIANTS = {
    "full": Policy(),
    "without_preflight": Policy(preflight=False),
    "without_finalize": Policy(finalize=False),
    "without_supersede": Policy(supersede=False),
    "without_edge_guards": Policy(edge_guards=False),
}


def run_variant(name: str, policy: Policy) -> dict[str, object]:
    outcomes = []
    for scenario in SCENARIOS:
        memory = TaskMemory(policy=policy)
        result = scenario.operation(memory)
        passed = scenario.expected(memory, result)
        outcomes.append(
            {
                "scenario": scenario.name,
                "purpose": scenario.purpose,
                "passed": passed,
                "actual_result": list(result),
                "final_tasks": {
                    task_id: {"status": task.status, "successor": task.successor}
                    for task_id, task in sorted(memory.tasks.items())
                },
            }
        )
    passed_count = sum(outcome["passed"] for outcome in outcomes)
    return {
        "variant": name,
        "policy": {
            "preflight": policy.preflight,
            "finalize": policy.finalize,
            "supersede": policy.supersede,
            "edge_guards": policy.edge_guards,
        },
        "passed": passed_count,
        "total": len(outcomes),
        "pass_rate": round(passed_count / len(outcomes), 3),
        "outcomes": outcomes,
    }


def build_report() -> dict[str, object]:
    results = [run_variant(name, policy) for name, policy in VARIANTS.items()]
    full = next(result for result in results if result["variant"] == "full")
    ledger_results = [run_ledger_variant(name, policy) for name, policy in LEDGER_VARIANTS.items()]
    ledger_full = next(result for result in ledger_results if result["variant"] == "ledger_full")
    return {
        "schema_version": 2,
        "experiment": "task_memory_two_framework_ablation",
        "deterministic": True,
        "frameworks": {
            "lifecycle_state_machine": {"design": "legal task-state transitions", "results": results},
            "evidence_ledger_retrieval": {"design": "append-only claims, evidence, retrieval and conflict resolution", "results": ledger_results},
        },
        "common_scenarios": [item.name for item in SCENARIOS] + [item[0] for item in LEDGER_SCENARIOS],
        "ablations": [
            {
                "framework": "lifecycle_state_machine",
                "variant": result["variant"],
                "pass_rate_delta_from_full": round(result["pass_rate"] - full["pass_rate"], 3),
            }
            for result in results
            if result["variant"] != "full"
        ] + [
            {"framework": "evidence_ledger_retrieval", "variant": result["variant"], "pass_rate_delta_from_full": round(result["pass_rate"] - ledger_full["pass_rate"], 3)}
            for result in ledger_results if result["variant"] != "ledger_full"
        ],
    }


def main() -> int:
    report = build_report()
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"artifact": str(ARTIFACT_PATH), "frameworks": list(report["frameworks"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
