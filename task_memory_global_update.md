---
name: task-memory
description: Maintain durable, evidence-backed, conflict-aware memory for a task across turns, with validated retrieval, atomic append-only writes, recovery, and measurable quality/performance checks. Automatically use for long conversations, multi-step implementation, debugging, deployment, agent workflows, handoffs, explicit decisions, and meaningful checkpoints; also use on short tasks when the user asks for a summary or continuity.
---

# Task Memory

Use this skill to preserve only useful, verifiable task context. Memory is a working record, not a transcript: it must help a later turn act correctly without requiring the full conversation.

## Scope and storage

- Default store: `<workspace>/.codex/task-memory/`.
- A caller may provide another project-local store with `memory_root`; never write outside the workspace unless explicitly authorized.
- Use one Markdown record per task: `<memory_root>/<task_id>.md`.
- Use a stable `task_id` supplied by the caller. If absent, derive a short slug from the task title and append a collision-resistant date/time suffix. Do not use secrets, full prompts, or personal data in the filename.
- Create the directory only when a write is required. Do not create a record during a read-only preflight.
- Preserve unrelated existing files. Never replace an entire memory store to update one task.
- Do not store credentials, tokens, private keys, passwords, session cookies, raw `.env` values, or unrelated personal data. Redact them as `[REDACTED]`.

## Automatic activation

Use this skill without waiting for the user to name it when any of these conditions is true:

- The task has 3 or more implementation, diagnosis, review, deployment, or agent steps.
- The conversation has 8 or more substantive turns, or the context has been compacted or resumed.
- A key decision, changed file, test result, deployment result, blocker, user approval, or handoff occurs.
- The user asks to continue, retry, summarize, hand off, or restore prior context.

For an automatically activated task, derive a stable `task_id` from the objective, use the project-local `.codex/task-memory/` store, and run `preflight` before meaningful work if the record exists. Run `finalize` at a stage boundary, before a long pause, after a blocker, or when the task is complete. A long task may receive multiple concise checkpoint entries; do not wait until the final turn.

Do not write memory for simple one-off questions, casual conversation, or fewer than 3 substantive turns unless the user explicitly asks. Keep automatic summaries concise and actionable, not transcripts.

## Activation contract

The skill accepts an operation and a task context. The operation is one of:

- `preflight`: retrieve relevant prior memory before implementation or a meaningful decision.
- `finalize`: record the verified result after implementation, diagnosis, review, or handoff.
- `retrieve`: search memory without changing it.
- `supersede`: explicitly mark a prior fact or decision obsolete and record its replacement.

Required input fields:

```text
operation: preflight | finalize | retrieve | supersede
task_id: stable task identifier
task: concise statement of the current objective
```

Optional input fields:

```text
memory_root: project-local memory directory
query: terms, paths, symbols, or decisions to retrieve
scope: task | workspace | explicit list of task_ids (default: task)
status: planned | in_progress | blocked | completed | abandoned
files_changed: paths actually changed
commands_run: commands used for verification, excluding secrets
tests: test/check name, result, and relevant output
decisions: decision, alternatives considered, and rationale
risks: unresolved risks or follow-up work
user_constraints: constraints that must survive a handoff
supersedes: memory entry identifier or statement being replaced
```

If `task_id` or `task` is missing, stop and return `invalid_input`; do not guess. If an operation-specific field is missing, apply the operation rules below and report the omission.

## Preflight

Run before making a change when prior decisions, constraints, failed attempts, or ownership boundaries may affect the work.

1. Resolve and validate `memory_root` as workspace-local. If it does not exist, return an empty result with `store_status: absent`; this is not an error.
2. Read the current task record if present.
3. Retrieve matching records using the task id first, then exact paths, symbols, endpoint names, error strings, and distinctive query terms. Prefer structured search (`rg` or an equivalent indexed search) over broad transcript scanning.
4. Ignore entries explicitly marked `superseded`, `invalid`, `unverified`, or `redacted` unless needed to explain history.
5. Rank results in this order: current task and active constraints; verified decisions; unresolved risks; recent related outcomes; older background.
6. Detect conflicts. A newer entry supersedes an older one only when it names the old entry or clearly records a replacement. Otherwise report both claims as a conflict and do not choose silently.
7. Return the preflight report before implementation.

Preflight output:

```yaml
operation: preflight
task_id: <id>
store_status: found | absent | unreadable
relevant_memory:
  - id: <entry-id>
    fact: <concise claim>
    source: <record path and section>
    confidence: verified | reported | inferred
    evidence: [<evidence ids>]
active_constraints: [<constraints>]
unresolved_risks: [<risks>]
conflicts: [<conflicts, or []>]
recommended_next_checks: [<checks, or []>]
```

If the store is unreadable, return `store_status: unreadable` and continue only if the caller can safely proceed without memory. Do not silently treat an unreadable store as empty.

## Retrieval

For `retrieve`, do the same search and ranking as preflight but do not create, modify, or update records. Return matching entry ids, concise claims, source locations, timestamps when present, confidence, and evidence. An empty match is a successful result (`matches: []`).

Use exact matching before fuzzy matching. For fuzzy matching, require at least one shared task concept, path, symbol, error, or decision term. Do not infer that two tasks are related merely because they share a generic word such as `fix`, `test`, or `app`.

## Finalize

Run after the task reaches a meaningful stopping point, including a completed change, a blocked attempt, a review, or a handoff.

1. Re-read the current record immediately before writing to avoid clobbering a concurrent update.
2. Append a new dated entry; do not rewrite history. If an earlier claim is wrong, mark it `superseded` and explain why in the new entry.
3. Record facts separately from decisions, observations, and hypotheses.
4. Record only files actually changed and verification actually performed. A command that was planned but not run must be labeled `not_run`.
5. Record the exact failure and current blocker when status is `blocked`; include the next actionable attempt.
6. Add a handoff summary that is sufficient for another agent to continue without rereading the full task.
7. Validate the written record: required fields exist, evidence references resolve within the entry, secrets are absent, and the status agrees with the outcome.

Finalize input requirements:

- `status` is required for `finalize`.
- `evidence` is required for any claim of `completed` or `verified`; if no evidence exists, downgrade the claim to `reported` and return `insufficient_evidence`.
- `files_changed`, `commands_run`, and `tests` are optional, but omitted verification must be stated as `not provided`, never implied to have passed.

Memory record format:

```markdown
# Task: <task>

- task_id: <stable id>
- status: <planned|in_progress|blocked|completed|abandoned>
- created_at: <ISO 8601 timestamp>
- updated_at: <ISO 8601 timestamp>

## Handoff

<what was done, what remains, and the next safe action>

## Constraints

- [C1] <constraint>

## Entries

### <entry-id> | <ISO 8601 timestamp> | <fact|decision|observation|hypothesis|risk>

- state: active | superseded | unverified
- claim: <one concise claim>
- rationale: <why it matters or why the decision was made>
- evidence: [E1, E2]
- supersedes: <entry-id or none>

#### Evidence

- E1: command/test/file/user report; result: <observable result>; captured_at: <timestamp>
```

Use opaque, local entry ids such as `E-20260813-001` and `M-20260813-001`. Evidence must be auditable from the record: cite a command plus its relevant result, a file path plus line/section, a test name plus pass/fail output, or an explicit user statement. “It works” and model inference are not evidence.

Finalize output:

```yaml
operation: finalize
task_id: <id>
write_status: written | unchanged | failed
record_path: <path or null>
record_status: <status>
entry_ids: [<ids>]
evidence_ids: [<ids>]
warnings: [<warnings, or []>]
next_action: <action or none>
```

## Superseding and conflict handling

Use `supersede` only for an intentional correction or replacement. Preserve the old entry, set its state to `superseded`, link `supersedes` from the replacement, and include evidence for the correction. If two active entries conflict and neither explicitly supersedes the other, return `conflict` and require a human or current task result to resolve it.

Never convert an inference into a fact merely because it is repeated. Mark it `inferred` or `unverified` until observable evidence is recorded.

## Failure handling

Return a structured failure without pretending the operation succeeded:

```yaml
operation: <operation>
task_id: <id or null>
result: failed
code: invalid_input | unreadable_store | unsafe_path | permission_denied | conflict | insufficient_evidence | write_failed
message: <specific problem>
recovery: <one or more concrete next actions>
```

- `invalid_input`: required input is missing or malformed; ask for the missing field.
- `unsafe_path`: `memory_root` escapes the workspace or targets a protected path; refuse the write and request a project-local path.
- `unreadable_store` / `permission_denied`: report the path and continue read-only only when safe.
- `conflict`: show the competing entry ids and do not silently merge them.
- `insufficient_evidence`: record the outcome as unverified or reported, list the missing proof, and suggest a check.
- `write_failed`: preserve the prior record, report the write error, and provide the retry action. Never claim finalization succeeded.

## Safety and quality gates

Before every write, check:

- The target is inside the declared workspace-local `memory_root`.
- Only the requested task record is being changed.
- The content contains no apparent secret or credential.
- Every verified claim has at least one concrete evidence item.
- The record is append-oriented and retains prior history.
- The final response names the record path, status, evidence ids, and any unresolved risk.

Keep entries concise and actionable. Prefer one claim per entry. Do not copy the entire prompt, terminal output, chat transcript, or generated code into memory.

## Operational hardening

Apply the following controls whenever a record is read or written. These controls are part of the skill contract, not optional suggestions.

### Atomic and concurrent writes

- Resolve and validate the target record and its parent directory before opening it. Refuse paths outside the workspace-local `memory_root` unless the user explicitly authorizes another project-local path.
- Serialize writers with a per-record lock file. Acquire the lock with an exclusive create operation, include the process id and timestamp, and release it in a `finally`/cleanup path.
- Treat a lock older than the configured stale-lock threshold as recoverable only after checking that its owner is no longer active; record the recovery as an observation.
- Write updates to a sibling temporary file, flush and close it, then atomically replace the target. Never truncate the live record before the replacement is ready.
- Before replacing, re-read the record and preserve any entries added since the initial read. If the record changed concurrently and cannot be merged safely, return `conflict` instead of overwriting.

### Corruption and recovery

- Validate front matter, required headings, entry ids, evidence references, and status before trusting a record. Malformed records are `unreadable`, not empty.
- Keep at most one bounded backup or checksum sidecar when the host supports it. Recovery may restore the last valid version, but must never silently discard newer entries.
- On partial writes, preserve the damaged file, create a recovery diagnostic, and stop with `write_failed` or `unreadable`; do not claim finalization succeeded.

### Retrieval quality gates

- Normalize queries without deleting path, symbol, rule-id, or error tokens. Run exact matching before fuzzy matching.
- Exclude `superseded`, `invalid`, `redacted`, and `unverified` entries from default answers. Include them only when the user requests history or the conflict explanation requires them.
- Return citations for every returned verified claim. A citation must resolve to an evidence item in the same record or an explicitly allowed source record.
- Track retrieval metrics when the harness is available: `precision_at_k`, `recall_at_k`, irrelevant-hit rate, conflict-detection recall, citation completeness, and mutation-on-read violations. If no gold set exists, report the metric as `not measured` rather than estimating it.
- Never collapse two active claims with incompatible values. Return `conflict`, list both claim ids and evidence, and ask for a current decision.

### Evidence and state validation

- A claim may be labeled `verified` only when at least one evidence item resolves to a concrete file, command, test result, or explicit user statement.
- A `completed` task must have a handoff plus verification evidence. Otherwise downgrade it to `reported` or `unverified`.
- `supersede` must append a replacement and preserve the predecessor link. It must not mutate history in place or mark a replacement completed automatically.
- Read operations, including `preflight` and `retrieve`, must be side-effect free. Verify the record hash/entry count before and after when practical; record any mutation-on-read violation.

### Performance and observability

- For deterministic local tests, collect `wall_time_ms`, storage bytes before/after, returned-context characters, and sample count. Use `perf_counter_ns`; report P50/P95 for at least 30 repetitions when performance is material.
- Report model `prompt_tokens`, `completion_tokens`, context-window usage, and cost only from an instrumented provider or declared tokenizer. Do not infer them from character counts or local script runtime.
- Include a stable run id, skill version/hash, task id, scenario id, seed (if any), and failure reason codes in experiment artifacts. Redact credentials and raw environment values.

### Failure contract

Return one of the structured failure codes (`invalid_input`, `unreadable_store`, `unsafe_path`, `permission_denied`, `conflict`, `insufficient_evidence`, `write_failed`) with the exact path/scope and one recovery action. Do not silently fall back from an unreadable store to an empty store, and do not turn a failed write into a successful handoff.
